'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const cache = require('../lib/google-cookie-cache');

function directory(t) {
    const storage = fs.mkdtempSync(path.join(os.tmpdir(), 'nest-cache-security-'));
    t.after(() => fs.rmSync(storage, { recursive: true, force: true }));
    return storage;
}

test('repairs restored cache permissions and atomically writes owner-only files', t => {
    const storage = directory(t);
    const file = path.join(storage, 'cookies');
    fs.writeFileSync(file, 'SID=restored-fixture', { mode: 0o644 });
    assert.equal(cache.read(file), 'SID=restored-fixture');
    if (process.platform !== 'win32') {
        assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    }
    cache.write(file, 'SID=rotated-fixture');
    assert.equal(cache.read(file), 'SID=rotated-fixture');
    assert.deepEqual(fs.readdirSync(storage), ['cookies']);
    if (process.platform !== 'win32') {
        assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    }
});

test('rejects symlinks, hardlinks, nonregular files and oversized caches', { skip: process.platform === 'win32' }, t => {
    const storage = directory(t);
    const target = path.join(storage, 'target');
    fs.writeFileSync(target, 'SID=unrelated-fixture', { mode: 0o644 });
    const link = path.join(storage, 'link');
    fs.symlinkSync(target, link);
    assert.throws(() => cache.read(link), { code: 'EUNSAFECACHE' });
    assert.equal(fs.statSync(target).mode & 0o777, 0o644);
    fs.unlinkSync(link);
    fs.linkSync(target, link);
    assert.throws(() => cache.read(link), { code: 'EUNSAFECACHE' });
    assert.throws(() => cache.read(storage), { code: 'EUNSAFECACHE' });
    const oversized = path.join(storage, 'oversized');
    fs.writeFileSync(oversized, Buffer.alloc(128 * 1024 + 1));
    assert.throws(() => cache.read(oversized), { code: 'EUNSAFECACHE' });
    assert.throws(() => cache.write(path.join(storage, 'too-big'), 'x'.repeat(128 * 1024 + 1)), { code: 'EUNSAFECACHE' });
});

test('retirement preserves every configured Nest session and unrelated files', t => {
    const storage = directory(t);
    const configPath = path.join(storage, 'config.json');
    const configs = ['current', 'other-account', 'retired'].map(name => ({ issueToken: 'https://accounts.google.com/token', cookies: 'SID=' + name }));
    const files = configs.map(config => path.join(storage, 'nest-google-cookies-' + cache.sessionKey(config)));
    files.forEach(file => cache.write(file, 'SID=fixture'));
    fs.writeFileSync(path.join(storage, 'unrelated'), 'keep');
    fs.writeFileSync(configPath, JSON.stringify({ platforms: configs.slice(0, 2).map(googleAuth => ({ platform: 'Nest', googleAuth })) }));
    cache.prune(storage, configPath, cache.sessionKey(configs[0]));
    assert.ok(fs.existsSync(files[0]));
    assert.ok(fs.existsSync(files[1]));
    assert.ok(!fs.existsSync(files[2]));
    assert.ok(fs.existsSync(path.join(storage, 'unrelated')));
    // A stale Connection cannot delete credentials from the new configuration.
    cache.write(files[2], 'SID=retired-fixture');
    cache.prune(storage, configPath, cache.sessionKey(configs[2]));
    assert.ok(fs.existsSync(files[0]));
    assert.ok(fs.existsSync(files[1]));
});

test('retirement requires complete readable configuration and skips fresh temporary files', t => {
    const storage = directory(t);
    const configPath = path.join(storage, 'config.json');
    const config = { issueToken: 'https://accounts.google.com/token', cookies: 'SID=fixture' };
    const key = cache.sessionKey(config);
    const base = path.join(storage, 'nest-google-cookies-' + key);
    cache.write(base, 'SID=fixture');
    const fresh = base + '.0123456789abcdef';
    const stale = base + '.fedcba9876543210';
    fs.writeFileSync(fresh, 'SID=temporary-fixture');
    fs.writeFileSync(stale, 'SID=old-temporary-fixture');
    fs.utimesSync(stale, new Date(0), new Date(0));
    cache.prune(storage, undefined, key);
    assert.ok(fs.existsSync(stale));
    fs.writeFileSync(configPath, '{invalid');
    assert.throws(() => cache.prune(storage, configPath, key));
    assert.ok(fs.existsSync(stale));
    fs.writeFileSync(configPath, JSON.stringify({}));
    assert.throws(() => cache.prune(storage, configPath, key), { code: 'EINVALIDCONFIG' });
    assert.ok(fs.existsSync(stale));
    fs.writeFileSync(configPath, JSON.stringify({ platforms: [{ platform: 'Nest', googleAuth: config }] }));
    cache.prune(storage, configPath, key);
    assert.ok(fs.existsSync(base));
    assert.ok(fs.existsSync(fresh));
    assert.ok(!fs.existsSync(stale));
});
