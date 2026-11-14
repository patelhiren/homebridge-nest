'use strict';

const axios = require('axios');
const path = require('path');
const { Cookie, CookieJar, domainMatch, pathMatch } = require('tough-cookie');
const cache = require('./google-cookie-cache');
const NestEndpoints = require('./nest-endpoints');

function newJar() {
    return new CookieJar(undefined, { prefixSecurity: 'strict', allowSecureOnLocal: false });
}

function invalidCache() {
    const error = new Error('Invalid Google cookie cache');
    error.code = 'EINVALIDCACHE';
    return error;
}

class GoogleAuth {
    constructor(config, storagePath, log, configPath) {
        this.issueToken = config.issueToken;
        this.url = new URL(this.issueToken);
        this.log = log;
        this.storagePath = storagePath;
        this.configPath = configPath;
        this.sessionKey = cache.sessionKey(config);
        this.seed(config.cookies);

        if (storagePath) {
            // Keep the original filename so existing deployments migrate without
            // recapturing credentials. Fresh config still selects a new session.
            this.cookieFile = path.join(storagePath, 'nest-google-cookies-' + this.sessionKey);
            try {
                const saved = cache.read(this.cookieFile);
                this.restore(saved);
                this.savedData = saved;
                this.log.debug('Restored saved Google cookies.');
            } catch (error) {
                // Never partially use a malformed cache or log its contents.
                this.seed(config.cookies);
                if (error.code !== 'ENOENT') {
                    this.log.error('Could not read saved Google cookies (' + (error.code || 'EINVALIDCACHE') + ').');
                }
            }
        }
    }

    seed(header) {
        this.jar = newJar();
        this.seededNames = new Set();
        // A copied Cookie header has no scope/expiry metadata. Bind it to this
        // host, with HTTPS protection where applicable; never follow redirects.
        for (const pair of header.split(';')) {
            const cookie = Cookie.parse(pair.trim());
            if (!cookie || this.seededNames.has(cookie.key)) {
                continue;
            }
            cookie.path = '/';
            cookie.secure = this.url.protocol === 'https:';
            cookie.httpOnly = true;
            const accepted = this.jar.setCookieSync(cookie, this.issueToken, { ignoreError: true });
            if (accepted) {
                this.seededNames.add(cookie.key);
            }
        }
    }

    restore(saved) {
        if (!saved.trimStart().startsWith('{')) {
            // v1 caches stored only a header. Treat them like copied credentials
            // and migrate to scoped JSON after a successful Google exchange.
            if (!saved.trim() || /[\r\n\0]/.test(saved)) {
                throw invalidCache();
            }
            this.seed(saved);
            return;
        }
        const data = JSON.parse(saved);
        if (data.version !== 2 || !Array.isArray(data.cookies) || !Array.isArray(data.seededNames) ||
            data.seededNames.some(name => typeof name !== 'string')) {
            throw invalidCache();
        }
        const jar = newJar();
        for (const entry of data.cookies) {
            const cookie = Cookie.fromJSON(entry);
            // All Max-Age values are converted to absolute expiry on receipt.
            // Restoring them as relative lifetimes could extend expired cookies.
            if (!cookie || cookie.maxAge !== null) {
                throw invalidCache();
            }
            jar.setCookieSync(cookie, this.issueToken);
        }
        this.jar = jar;
        this.seededNames = new Set(data.seededNames);
    }

    get cookies() {
        return this.jar.getCookieStringSync(this.issueToken);
    }

    async exchange(timeout) {
        const response = await axios.get(this.issueToken, {
            timeout,
            maxRedirects: 0,
            headers: {
                'Sec-Fetch-Mode': 'cors',
                'User-Agent': NestEndpoints.USER_AGENT_STRING,
                'X-Requested-With': 'XmlHttpRequest',
                'Referer': 'https://accounts.google.com/o/oauth2/iframe',
                'Cookie': this.cookies
            }
        });
        if (response.data && response.data.access_token && !response.data.error) {
            this.applyCookieUpdates(response.headers['set-cookie'] || []);
            this.saveCookies();
        }
        return response.data;
    }

    applyCookieUpdates(setCookies) {
        for (const header of setCookies) {
            const cookie = Cookie.parse(header);
            if (!cookie) {
                continue;
            }
            if (cookie.maxAge !== null) {
                // Absolute expiry must survive both access and restarts. Max-Age
                // takes precedence over an inconsistent Expires attribute.
                const expires = cookie.maxAge <= 0 ? 0 : Math.min(Date.now() + Number(cookie.maxAge) * 1000, 8640000000000000);
                cookie.expires = new Date(expires);
                cookie.maxAge = null;
            }
            const accepted = this.jar.setCookieSync(cookie, this.issueToken, { ignoreError: true });
            if (!accepted || !this.seededNames.has(cookie.key) ||
                !domainMatch(this.url.hostname, cookie.domain) || !pathMatch(this.url.pathname, cookie.path)) {
                continue;
            }
            // The original header did not tell us whether SIDCC (for example)
            // belonged to accounts.google.com or .google.com. Once an applicable
            // update supplies that metadata, replace its synthetic seed rather
            // than sending the stale seed alongside the rotated cookie.
            if (cookie.domain !== this.url.hostname || cookie.path !== '/') {
                this.jar.store.removeCookie(this.url.hostname, '/', cookie.key, error => {
                    if (error) {
                        throw error;
                    }
                });
            }
            this.seededNames.delete(cookie.key);
        }
    }

    saveCookies() {
        if (!this.cookieFile) {
            return;
        }
        // Purge expired cookies at all stored paths before writing metadata.
        this.jar.getCookiesSync(this.issueToken, { allPaths: true });
        const data = JSON.stringify({ version: 2, cookies: this.jar.serializeSync().cookies, seededNames: Array.from(this.seededNames) });
        try {
            if (data !== this.savedData) {
                cache.write(this.cookieFile, data);
                this.savedData = data;
                this.log.debug('Saved rotated Google cookies.');
            }
        } catch (error) {
            this.log.error('Could not save rotated Google cookies (' + error.code + ').');
            return;
        }
        try {
            cache.prune(this.storagePath, this.configPath, this.sessionKey);
        } catch (error) {
            this.log.error('Could not retire unused Google cookie caches (' + (error.code || 'INVALID_CONFIG') + ').');
        }
    }
}

module.exports = GoogleAuth;
