'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const GoogleAuth = require('../lib/google-auth');
const cache = require('../lib/google-cookie-cache');
const { Console } = require('node:console');
const { PassThrough } = require('node:stream');

function logger() {
    const output = new PassThrough();
    return { output, log: new Console({ stdout: output, stderr: output }) };
}

function directory(t) {
    const storage = fs.mkdtempSync(path.join(os.tmpdir(), 'nest-cookie-scope-'));
    t.after(() => fs.rmSync(storage, { recursive: true, force: true }));
    return storage;
}

async function listen(t, handler) {
    const server = http.createServer(handler);
    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolve);
    });
    t.after(() => new Promise(resolve => server.close(resolve)));
    return 'http://127.0.0.1:' + server.address().port + '/o/oauth2/iframerpc';
}

function token(response, cookies = []) {
    response.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': cookies });
    response.end(JSON.stringify({ access_token: 'fixture-token' }));
}

test('real requests withhold foreign-domain, mismatched-path and insecurely set Secure cookies after restart', async t => {
    const requests = [];
    const issueToken = await listen(t, (request, response) => {
        requests.push(request.headers.cookie);
        token(response, requests.length === 1 ? [
            'foreign=fixture; Domain=unrelated.invalid; Path=/',
            'differentPath=fixture; Path=/unrelated',
            'secureOnly=fixture; Secure; Path=/',
            'applicable=fixture; Path=/o/oauth2',
            'malformed cookie'
        ] : []);
    });
    const storage = directory(t);
    const config = { issueToken, cookies: 'SID=seed-fixture' };
    const { log } = logger();
    await new GoogleAuth(config, storage, log).exchange(2000);
    const restarted = new GoogleAuth(config, storage, log);
    await restarted.exchange(2000);
    assert.match(requests[1], /SID=seed-fixture/);
    assert.match(requests[1], /applicable=fixture/);
    assert.doesNotMatch(requests[1], /foreign|differentPath|secureOnly/);
    const data = JSON.parse(fs.readFileSync(restarted.cookieFile, 'utf8'));
    assert.equal(data.version, 2);
    assert.ok(data.cookies.some(cookie => cookie.key === 'differentPath' && cookie.path === '/unrelated'));
});

test('Max-Age is absolute, takes precedence over Expires and does not restart on access or process restart', async t => {
    const requests = [];
    const issueToken = await listen(t, (request, response) => {
        requests.push(request.headers.cookie);
        token(response, requests.length === 1 ? [
            'brief=fixture; Max-Age=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/',
            'alreadyExpired=fixture; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/'
        ] : []);
    });
    const config = { issueToken, cookies: 'SID=seed-fixture' };
    const storage = directory(t);
    const { log } = logger();
    const auth = new GoogleAuth(config, storage, log);
    await auth.exchange(2000);
    assert.match(auth.cookies, /brief=fixture/);
    assert.doesNotMatch(auth.cookies, /alreadyExpired/);
    const persistedExpiry = JSON.parse(fs.readFileSync(auth.cookieFile, 'utf8')).cookies.find(cookie => cookie.key === 'brief').expires;
    // Access midway through its lifetime must not extend that lifetime.
    await new Promise(resolve => setTimeout(resolve, 600));
    await auth.exchange(2000);
    assert.equal(JSON.parse(fs.readFileSync(auth.cookieFile, 'utf8')).cookies.find(cookie => cookie.key === 'brief').expires, persistedExpiry);
    await new Promise(resolve => setTimeout(resolve, 600));
    await new GoogleAuth(config, storage, log).exchange(2000);
    assert.doesNotMatch(requests[2], /brief|alreadyExpired/);
    assert.match(requests[2], /SID=seed-fixture/);
});

test('Google parent-domain updates replace metadata-free seeds and preserve scope after restart', t => {
    const config = {
        issueToken: 'https://accounts.google.com/o/oauth2/iframerpc?action=issueToken',
        cookies: 'SID=initial-fixture; SIDCC=old-fixture; __Secure-3PSID=secure-fixture; __Host-GAPS=host-fixture'
    };
    const storage = directory(t);
    const { log } = logger();
    const auth = new GoogleAuth(config, storage, log);
    auth.applyCookieUpdates(['SIDCC=rotated==; Domain=.google.com; Path=/; Secure; HttpOnly']);
    assert.match(auth.cookies, /SIDCC=rotated==/);
    assert.doesNotMatch(auth.cookies, /old-fixture/);
    assert.equal(auth.cookies.split('SIDCC=').length, 2);
    auth.saveCookies();
    const restarted = new GoogleAuth(config, storage, log);
    assert.match(restarted.cookies, /SIDCC=rotated==/);
    assert.match(restarted.cookies, /__Secure-3PSID=secure-fixture/);
    assert.match(restarted.cookies, /__Host-GAPS=host-fixture/);
    assert.equal(restarted.cookies.split('SIDCC=').length, 2);
    const stored = JSON.parse(fs.readFileSync(auth.cookieFile, 'utf8')).cookies.find(cookie => cookie.key === 'SIDCC');
    assert.equal(stored.domain, 'google.com');
    assert.equal(stored.secure, true);
    assert.equal(stored.httpOnly, true);
    restarted.applyCookieUpdates(['SIDCC=; Domain=.google.com; Path=/; Max-Age=0; Secure']);
    assert.doesNotMatch(restarted.cookies, /SIDCC=/);
});

test('same-name scoped cookies remain distinct and wrong-path updates do not erase the legacy seed', () => {
    const { log } = logger();
    const auth = new GoogleAuth({ issueToken: 'https://accounts.google.com/o/oauth2/iframerpc', cookies: 'SIDCC=seed-fixture' }, undefined, log);
    auth.applyCookieUpdates(['SIDCC=other-path; Path=/unrelated; Secure']);
    assert.equal(auth.cookies, 'SIDCC=seed-fixture');
    auth.applyCookieUpdates(['SIDCC=parent; Domain=.google.com; Path=/; Secure']);
    assert.equal(auth.cookies, 'SIDCC=parent');
    auth.applyCookieUpdates(['SIDCC=exact-path; Path=/o/oauth2; Secure']);
    assert.equal(auth.cookies, 'SIDCC=exact-path; SIDCC=parent');
    // Prefix-invalid updates are rejected by the actual cookie jar.
    auth.applyCookieUpdates(['__Host-invalid=fixture; Domain=.google.com; Path=/; Secure']);
    assert.doesNotMatch(auth.cookies, /__Host-invalid/);
});

test('metadata-free duplicate names keep the first browser-ordered value until rotation supplies scope', () => {
    const { log } = logger();
    const auth = new GoogleAuth({ issueToken: 'https://accounts.google.com/o/oauth2/iframerpc', cookies: 'SID=first-fixture; SID=second-fixture' }, undefined, log);
    assert.equal(auth.cookies, 'SID=first-fixture');
    auth.applyCookieUpdates(['SID=rotated-fixture; Domain=.google.com; Path=/; Secure']);
    assert.equal(auth.cookies, 'SID=rotated-fixture');
});

test('legacy plaintext caches migrate after successful exchange without fresh credentials', async t => {
    const requests = [];
    const issueToken = await listen(t, (request, response) => {
        requests.push(request.headers.cookie);
        token(response);
    });
    const config = { issueToken, cookies: 'SID=original-config-fixture' };
    const storage = directory(t);
    const file = path.join(storage, 'nest-google-cookies-' + cache.sessionKey(config));
    fs.writeFileSync(file, 'SID=legacy-rotated-fixture', { mode: 0o644 });
    const { log } = logger();
    const auth = new GoogleAuth(config, storage, log);
    await auth.exchange(2000);
    assert.equal(requests[0], 'SID=legacy-rotated-fixture');
    assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).version, 2);
    if (process.platform !== 'win32') {
        assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    }
    await new GoogleAuth(config, storage, log).exchange(2000);
    assert.equal(requests[1], 'SID=legacy-rotated-fixture');
});

test('malformed or linked caches fall back to configured cookies without exposing cache contents', async t => {
    const issueToken = await listen(t, (request, response) => {
        assert.equal(request.headers.cookie, 'SID=configured-fixture');
        token(response);
    });
    const config = { issueToken, cookies: 'SID=configured-fixture' };
    const storage = directory(t);
    const file = path.join(storage, 'nest-google-cookies-' + cache.sessionKey(config));
    const { log, output } = logger();
    fs.writeFileSync(file, '{invalid-private-cache-fixture', { mode: 0o600 });
    await new GoogleAuth(config, storage, log).exchange(2000);
    if (process.platform !== 'win32') {
        fs.unlinkSync(file);
        const target = path.join(storage, 'unrelated');
        fs.writeFileSync(target, 'SID=private-target-fixture');
        fs.symlinkSync(target, file);
        await new GoogleAuth(config, storage, log).exchange(2000);
        assert.equal(fs.readFileSync(target, 'utf8'), 'SID=private-target-fixture');
    }
    const text = output.read(output.readableLength).toString();
    assert.doesNotMatch(text, /configured-fixture|private-cache-fixture|private-target-fixture/);
    assert.match(text, /Could not read saved Google cookies/);
});

test('successful new credentials retire old caches only after saving and preserve another configured account', async t => {
    const issueToken = await listen(t, (_request, response) => token(response));
    const storage = directory(t);
    const configPath = path.join(storage, 'config.json');
    const previous = { issueToken, cookies: 'SID=previous-fixture' };
    const current = { issueToken, cookies: 'SID=current-fixture' };
    const other = { issueToken, cookies: 'SID=other-fixture' };
    const previousFile = path.join(storage, 'nest-google-cookies-' + cache.sessionKey(previous));
    const otherFile = path.join(storage, 'nest-google-cookies-' + cache.sessionKey(other));
    cache.write(previousFile, previous.cookies);
    cache.write(otherFile, other.cookies);
    fs.writeFileSync(configPath, JSON.stringify({ platforms: [current, other].map(googleAuth => ({ platform: 'Nest', googleAuth })) }));
    const { log } = logger();
    const auth = new GoogleAuth(current, storage, log, configPath);
    assert.ok(fs.existsSync(previousFile));
    await auth.exchange(2000);
    assert.ok(fs.existsSync(auth.cookieFile));
    assert.ok(!fs.existsSync(previousFile));
    assert.ok(fs.existsSync(otherFile));
});

test('redirects are rejected rather than forwarding credentials or importing redirect cookies', async t => {
    let redirectedRequests = 0;
    const destination = await listen(t, (_request, response) => {
        redirectedRequests++;
        token(response);
    });
    const issueToken = await listen(t, (_request, response) => {
        response.writeHead(302, { Location: destination, 'Set-Cookie': 'SID=redirect-fixture' });
        response.end();
    });
    const { log } = logger();
    const auth = new GoogleAuth({ issueToken, cookies: 'SID=initial-fixture' }, directory(t), log);
    await assert.rejects(auth.exchange(2000), { status: 302 });
    assert.equal(redirectedRequests, 0);
    assert.equal(auth.cookies, 'SID=initial-fixture');
    assert.ok(!fs.existsSync(auth.cookieFile));
});
