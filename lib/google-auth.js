'use strict';

const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const NestEndpoints = require('./nest-endpoints');

function cookiePair(pair) {
    const separator = pair.indexOf('=');
    return separator < 0 ? ['', ''] : [pair.slice(0, separator).trim(), pair.slice(separator + 1).trim()];
}

function isDeletion(attributes) {
    const options = new Map(attributes.map(cookiePair).map(([key, value]) => [key.toLowerCase(), value]));
    const maxAge = options.get('max-age');
    if (maxAge !== undefined && /^-?\d+$/.test(maxAge)) {
        return Number(maxAge) <= 0;
    }
    return Date.parse(options.get('expires')) <= Date.now();
}

class GoogleAuth {
    constructor(config, storagePath, log) {
        this.issueToken = config.issueToken;
        this.cookies = config.cookies;
        this.log = log;

        if (storagePath) {
            // Recapturing credentials must start a new session instead of reusing the cache.
            const sessionKey = crypto.createHash('sha256').update(JSON.stringify([config.issueToken, config.cookies])).digest('hex');
            this.cookieFile = path.join(storagePath, 'nest-google-cookies-' + sessionKey);
            try {
                this.cookies = fs.readFileSync(this.cookieFile, 'utf8');
                this.log.debug('Restored saved Google cookies.');
            } catch (error) {
                if (error.code !== 'ENOENT') {
                    this.log.error('Could not read saved Google cookies (' + error.code + ').');
                }
            }
        }
        this.savedCookies = this.cookies;
    }

    async exchange(timeout) {
        const response = await axios.get(this.issueToken, {
            timeout,
            headers: {
                'Sec-Fetch-Mode': 'cors',
                'User-Agent': NestEndpoints.USER_AGENT_STRING,
                'X-Requested-With': 'XmlHttpRequest',
                'Referer': 'https://accounts.google.com/o/oauth2/iframe',
                'Cookie': this.cookies
            }
        });
        const setCookies = response.headers['set-cookie'];
        if (response.data && response.data.access_token && !response.data.error) {
            if (setCookies) {
                this.applyCookieUpdates(setCookies);
            }
            this.saveCookies();
        }
        return response.data;
    }

    applyCookieUpdates(setCookies) {
        // All of these cookies are for the same issueToken request URL.
        const cookies = new Map(this.cookies.split(';').map(cookiePair).filter(([name]) => name));
        for (const header of setCookies) {
            const [pair, ...attributes] = header.split(';');
            const [name, value] = cookiePair(pair);
            if (name) {
                if (isDeletion(attributes)) {
                    cookies.delete(name);
                } else {
                    cookies.set(name, value);
                }
            }
        }

        this.cookies = Array.from(cookies, ([name, value]) => name + '=' + value).join('; ');
    }

    saveCookies() {
        if (!this.cookieFile || this.cookies === this.savedCookies) {
            return;
        }
        const temporaryFile = this.cookieFile + '.' + crypto.randomBytes(8).toString('hex');
        try {
            fs.writeFileSync(temporaryFile, this.cookies, { mode: 0o600, flag: 'wx' });
            fs.renameSync(temporaryFile, this.cookieFile);
            this.savedCookies = this.cookies;
            this.log.debug('Saved rotated Google cookies.');
        } catch (error) {
            this.log.error('Could not save rotated Google cookies (' + error.code + ').');
            try {
                fs.unlinkSync(temporaryFile);
            } catch (cleanupError) {
                // A failed write may not have created the file.
            }
        }
    }
}

module.exports = GoogleAuth;
