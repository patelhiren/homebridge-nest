'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

const GoogleAuth = require('../lib/google-auth');
const NestConnection = require('../lib/nest-connection');
const log = {
    info: console.info,
    debug: console.debug,
    error: console.error
};

async function listen(t, handler) {
    const server = http.createServer(handler);
    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolve);
    });
    t.after(() => new Promise(resolve => server.close(resolve)));
    return 'http://127.0.0.1:' + server.address().port + '/issueToken';
}

test('uses rotated Google cookies on renewal and after restart', async t => {
    const storagePath = fs.mkdtempSync(path.join(os.tmpdir(), 'homebridge-nest-test-'));
    t.after(() => fs.rmSync(storagePath, { recursive: true, force: true }));
    const requests = [];
    const issueToken = await listen(t, (request, response) => {
        requests.push(request.headers.cookie);
        if (requests.length === 2) {
            response.writeHead(429, { 'Set-Cookie': 'SIDCC=; Max-Age=0' });
            response.end();
            return;
        }
        const setCookies = requests.length === 1 ? [
            'SIDCC=rotated==; Priority=High; Secure',
            'deleteMe=; Max-Age=0',
            'expired=; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
            'keep=latest; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT'
        ] : ['SIDCC=second; Secure'];
        response.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': setCookies });
        response.end(JSON.stringify({ access_token: 'local-test-token' }));
    });

    const config = { issueToken, cookies: 'SID=original; SIDCC=first; deleteMe=old; expired=old; keep=old' };
    const first = new GoogleAuth(config, storagePath, log);
    assert.equal((await first.exchange(2000)).access_token, 'local-test-token');
    await assert.rejects(first.exchange(2000), { status: 429 });

    const restarted = new GoogleAuth(config, storagePath, log);
    await restarted.exchange(2000);
    await restarted.exchange(2000);
    assert.deepEqual(requests, [
        config.cookies,
        'SID=original; SIDCC=rotated==; keep=latest',
        'SID=original; SIDCC=rotated==; keep=latest',
        'SID=original; SIDCC=second; keep=latest'
    ]);

    const recaptured = new GoogleAuth({ issueToken, cookies: 'SID=fresh' }, storagePath, log);
    await recaptured.exchange(2000);
    assert.equal(requests[4], 'SID=fresh');
    if (process.platform !== 'win32') {
        for (const file of fs.readdirSync(storagePath)) {
            assert.equal(fs.statSync(path.join(storagePath, file)).mode & 0o777, 0o600);
        }
    }
});

test('concurrent Nest authentication calls share one Google exchange', async t => {
    let requests = 0;
    const issueToken = await listen(t, (_request, response) => {
        requests++;
        response.writeHead(400);
        response.end();
    });
    const connection = new NestConnection({ googleAuth: { issueToken, cookies: 'SID=local' } }, log, false, false);

    assert.deepEqual(await Promise.all([connection.auth(true), connection.auth()]), [false, false]);
    assert.equal(requests, 1);
    assert.equal(await connection.auth(), false);
    assert.equal(requests, 2);
});
