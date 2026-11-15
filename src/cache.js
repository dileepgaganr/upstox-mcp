// Shared TTL cache: in-memory layer (zero I/O on hot path) + file layer
// (~/.cache/mcp-servers/) so multiple bot processes and scheduled runs can
// reuse the same data without hammering the Upstox API.

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import os from 'os';

const CACHE_DIR = path.join(os.homedir(), '.cache', 'mcp-servers');
const _mem = new Map(); // key -> { data, expires }

try { fs.mkdirSync(CACHE_DIR, { recursive: true }); } catch (_) {}

function _fileKey(prefix, args) {
  const h = crypto.createHash('sha1').update(JSON.stringify(args)).digest('hex').slice(0, 16);
  return `${prefix}-${h}`;
}

/**
 * cached(prefix, args, ttlMs, fn)
 *
 * Returns cached data if still fresh, otherwise calls fn() and stores result.
 * Errors from fn() are never cached — they propagate normally.
 *
 * @param {string}   prefix  - namespace, e.g. 'upstox-ltp'
 * @param {any}      args    - serialisable arguments used as the cache key
 * @param {number}   ttlMs   - lifetime in milliseconds (0 = bypass cache)
 * @param {Function} fn      - async thunk that fetches fresh data
 */
export async function cached(prefix, args, ttlMs, fn) {
  if (!ttlMs || ttlMs <= 0) return fn();

  const key = _fileKey(prefix, args);
  const now = Date.now();

  // 1. In-memory hit
  const mem = _mem.get(key);
  if (mem && mem.expires > now) return mem.data;

  // 2. File hit (shared across processes / restarts)
  const fp = path.join(CACHE_DIR, `${key}.json`);
  try {
    const e = JSON.parse(fs.readFileSync(fp, 'utf-8'));
    if (e.expires > now) {
      _mem.set(key, e); // promote to memory
      return e.data;
    }
  } catch (_) { /* miss or corrupt */ }

  // 3. Fetch and store
  const data = await fn();
  const entry = { data, expires: now + ttlMs };
  _mem.set(key, entry);
  fs.writeFile(fp, JSON.stringify(entry), () => {}); // non-blocking write
  return data;
}
