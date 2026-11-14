'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MAX_CACHE_BYTES = 128 * 1024;
const CACHE_NAME = /^nest-google-cookies-([a-f0-9]{64})(?:\.([a-f0-9]{16}))?$/;

function unsafeCache() {
    const error = new Error('Unsafe Google cookie cache');
    error.code = 'EUNSAFECACHE';
    return error;
}

function sessionKey(config) {
    return crypto.createHash('sha256').update(JSON.stringify([config.issueToken, config.cookies])).digest('hex');
}

function ownedRegularFile(stat) {
    return stat.isFile() && stat.nlink === 1 &&
        (typeof process.getuid !== 'function' || stat.uid === process.getuid());
}

function read(file) {
    // O_NONBLOCK prevents a replaced FIFO from blocking Homebridge on open.
    const before = fs.lstatSync(file);
    if (!ownedRegularFile(before) || before.size > MAX_CACHE_BYTES) {
        throw unsafeCache();
    }
    const descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
    try {
        const stat = fs.fstatSync(descriptor);
        if (!ownedRegularFile(stat) || stat.dev !== before.dev || stat.ino !== before.ino || stat.size > MAX_CACHE_BYTES) {
            throw unsafeCache();
        }
        if (process.platform !== 'win32' && (stat.mode & 0o777) !== 0o600) {
            // Repair restored permissions on the verified descriptor, not a path
            // that could have been replaced with a symlink.
            fs.fchmodSync(descriptor, 0o600);
            if ((fs.fstatSync(descriptor).mode & 0o777) !== 0o600) {
                throw unsafeCache();
            }
        }
        const buffer = Buffer.alloc(MAX_CACHE_BYTES + 1);
        let length = 0;
        let count;
        do {
            count = fs.readSync(descriptor, buffer, length, buffer.length - length, null);
            length += count;
        } while (count && length < buffer.length);
        if (length > MAX_CACHE_BYTES) {
            throw unsafeCache();
        }
        return buffer.toString('utf8', 0, length);
    } finally {
        fs.closeSync(descriptor);
    }
}

function write(file, contents) {
    if (Buffer.byteLength(contents) > MAX_CACHE_BYTES) {
        throw unsafeCache();
    }
    const temporary = file + '.' + crypto.randomBytes(8).toString('hex');
    let descriptor;
    let created = false;
    try {
        descriptor = fs.openSync(temporary, 'wx', 0o600);
        created = true;
        fs.writeFileSync(descriptor, contents);
        fs.fsyncSync(descriptor);
        fs.closeSync(descriptor);
        descriptor = undefined;
        fs.renameSync(temporary, file);
    } finally {
        if (descriptor !== undefined) {
            fs.closeSync(descriptor);
        }
        if (created) {
            try {
                fs.unlinkSync(temporary);
            } catch (error) {
                // Do not mask the write/rename error. Any leftover remains
                // owner-only and becomes eligible for stale-temp cleanup.
            }
        }
    }
}

function prune(storagePath, configPath, currentKey) {
    // Homebridge's complete configuration is authoritative for this storage
    // directory. Never infer unused sessions from only the current platform.
    if (!configPath) {
        return;
    }
    const original = fs.readFileSync(configPath, 'utf8');
    const config = JSON.parse(original);
    if (!config || !Array.isArray(config.platforms)) {
        const error = new Error('Complete Homebridge platforms configuration required');
        error.code = 'EINVALIDCONFIG';
        throw error;
    }
    const active = new Set(config.platforms.filter(platform => platform.platform === 'Nest' &&
        platform.googleAuth && typeof platform.googleAuth.issueToken === 'string' &&
        typeof platform.googleAuth.cookies === 'string').map(platform => sessionKey(platform.googleAuth)));
    // An old Connection still running during a config update must not prune
    // credentials belonging to the replacement Connection.
    if (!active.has(currentKey)) {
        return;
    }
    for (const name of fs.readdirSync(storagePath)) {
        const match = CACHE_NAME.exec(name);
        if (!match) {
            continue;
        }
        const file = path.join(storagePath, name);
        const stat = fs.lstatSync(file);
        if (!ownedRegularFile(stat)) {
            continue;
        }
        // In-progress temporary writes are never collected. Crash leftovers
        // become eligible after a day, including those for an active session.
        const retired = match[2] ? stat.mtimeMs < Date.now() - 24 * 60 * 60 * 1000 : !active.has(match[1]);
        if (retired) {
            if (fs.readFileSync(configPath, 'utf8') !== original) {
                return;
            }
            fs.unlinkSync(file);
        }
    }
}

module.exports = { read, write, prune, sessionKey };
