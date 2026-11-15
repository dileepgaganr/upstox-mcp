// Tests for the shared TTL cache module (ESM).
// Run with: node --test src/cache.test.js
// Also covers Upstox and Breeze since they share the same cache.js.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';

import { cached } from './cache.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let _seq = 0;
function uid() { return `test-upstox-${process.pid}-${++_seq}`; }

// ── Core cache behaviour ─────────────────────────────────────────────

test('cache miss: fn is called and result is returned', async () => {
  let calls = 0;
  const result = await cached(uid(), ['a'], 5_000, () => { calls++; return Promise.resolve({ v: 1 }); });
  assert.deepEqual(result, { v: 1 });
  assert.equal(calls, 1);
});

test('cache hit: fn is NOT called again within TTL', async () => {
  let calls = 0;
  const prefix = uid();
  const args = ['same'];
  const fn = () => { calls++; return Promise.resolve(calls); };
  const r1 = await cached(prefix, args, 5_000, fn);
  const r2 = await cached(prefix, args, 5_000, fn);
  assert.equal(r1, 1);
  assert.equal(r2, 1);   // still 1 — served from cache
  assert.equal(calls, 1);
});

test('ttl=0: cache is bypassed every call', async () => {
  let calls = 0;
  const prefix = uid();
  const args = ['x'];
  const fn = () => { calls++; return Promise.resolve(calls); };
  const r1 = await cached(prefix, args, 0, fn);
  const r2 = await cached(prefix, args, 0, fn);
  assert.equal(r1, 1);
  assert.equal(r2, 2);
  assert.equal(calls, 2);
});

test('different args produce independent cache entries', async () => {
  let calls = 0;
  const prefix = uid();
  const fn = (v) => { calls++; return Promise.resolve({ v }); };
  const r1 = await cached(prefix, ['NSE_EQ|RELIANCE'], 5_000, () => fn('RELIANCE'));
  const r2 = await cached(prefix, ['NSE_EQ|INFY'],     5_000, () => fn('INFY'));
  assert.deepEqual(r1, { v: 'RELIANCE' });
  assert.deepEqual(r2, { v: 'INFY' });
  assert.equal(calls, 2);
  // Both should hit now
  await cached(prefix, ['NSE_EQ|RELIANCE'], 5_000, () => fn('RELIANCE'));
  await cached(prefix, ['NSE_EQ|INFY'],     5_000, () => fn('INFY'));
  assert.equal(calls, 2);
});

test('errors propagate and are NOT cached', async () => {
  let calls = 0;
  const prefix = uid();
  const args = ['err'];
  const fn = () => { calls++; return Promise.reject(new Error('upstox 429')); };
  await assert.rejects(() => cached(prefix, args, 5_000, fn), /upstox 429/);
  await assert.rejects(() => cached(prefix, args, 5_000, fn), /upstox 429/);
  assert.equal(calls, 2);
});

test('file was written to ~/.cache/mcp-servers/', async () => {
  const prefix = uid();
  await cached(prefix, ['filecheck'], 60_000, () => Promise.resolve({ ok: true }));
  await new Promise(r => setTimeout(r, 50)); // let the fire-and-forget write flush
  const CACHE_DIR = path.join(os.homedir(), '.cache', 'mcp-servers');
  const files = fs.readdirSync(CACHE_DIR);
  const match = files.some(f => f.startsWith(`${prefix}-`));
  assert.ok(match, `No cache file found for prefix "${prefix}" in ${CACHE_DIR}`);
});

test('cache file contains correct structure', async () => {
  const prefix = uid();
  const data = { price: 2500, symbol: 'RELIANCE' };
  await cached(prefix, ['struct'], 60_000, () => Promise.resolve(data));
  // The cache write is fire-and-forget; give the event loop a tick to flush it.
  await new Promise(r => setTimeout(r, 50));
  const CACHE_DIR = path.join(os.homedir(), '.cache', 'mcp-servers');
  const files = fs.readdirSync(CACHE_DIR);
  const file = files.find(f => f.startsWith(`${prefix}-`));
  assert.ok(file, `Cache file for prefix "${prefix}" not found`);
  const entry = JSON.parse(fs.readFileSync(path.join(CACHE_DIR, file), 'utf-8'));
  assert.ok(typeof entry.expires === 'number', 'expires should be a number');
  assert.ok(entry.expires > Date.now(), 'expires should be in the future');
  assert.deepEqual(entry.data, data);
});

// Extract the source block for one server.tool() registration.
// Bounded by the next server.tool( call so we never bleed into an adjacent tool.
function toolBlock(src, toolName) {
  const start = src.indexOf(`"${toolName}"`);
  if (start === -1) return null;
  const nextTool = src.indexOf('server.tool(', start + toolName.length);
  return nextTool === -1 ? src.slice(start) : src.slice(start, nextTool);
}

// ── Upstox-specific: verify TTL map and server wiring ─────────────────

test('Upstox TTL map: all read-only endpoints have TTLs > 0', () => {
  const src = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf-8');
  const match = src.match(/const TTL\s*=\s*\{([^}]+)\}/s);
  assert.ok(match, 'TTL object not found in server.js');
  const block = match[1];
  const entries = [...block.matchAll(/(\w+)\s*:\s*([\d_]+)/g)];
  assert.ok(entries.length > 10, `Expected >10 TTL entries, got ${entries.length}`);
  for (const [, name, rawVal] of entries) {
    const ms = Number(rawVal.replace(/_/g, ''));
    assert.ok(ms > 0, `TTL for "${name}" is not positive: ${ms}`);
  }
});

test('Upstox server: mutating tools do NOT use cachedGet', () => {
  const src = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf-8');
  const mutatingTools = ['place_order', 'modify_order', 'cancel_order', 'exit_positions', 'convert_position'];
  for (const tool of mutatingTools) {
    const block = toolBlock(src, tool);
    assert.ok(block !== null, `Tool "${tool}" not found in server.js`);
    const usesCached = /cachedGet|cached\(/.test(block);
    assert.ok(!usesCached, `Mutating tool "${tool}" should NOT use cache`);
  }
});

test('Upstox server: read-only GET tools use cachedGet', () => {
  const src = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf-8');
  const readTools = [
    'get_profile', 'get_holdings', 'get_positions', 'get_market_quote',
    'get_ltp_quotes', 'get_historical_candles', 'get_market_holidays',
  ];
  for (const tool of readTools) {
    const block = toolBlock(src, tool);
    assert.ok(block !== null, `Tool "${tool}" not found in server.js`);
    const usesCached = /cachedGet|cached\(/.test(block);
    assert.ok(usesCached, `Read tool "${tool}" should use cachedGet or cached()`);
  }
});

// ── Breeze-specific: verify TTL map and server wiring ─────────────────

test('Breeze TTL map: all read-only calls have TTLs > 0', () => {
  const breezeSrc = fs.readFileSync(
    path.join(__dirname, '../../icici breeze/js-api/src/server.js'), 'utf-8'
  );
  const match = breezeSrc.match(/const TTL\s*=\s*\{([^}]+)\}/s);
  assert.ok(match, 'TTL object not found in Breeze server.js');
  const block = match[1];
  const entries = [...block.matchAll(/(\w+)\s*:\s*([\d_]+)/g)];
  assert.ok(entries.length >= 8, `Expected >=8 TTL entries, got ${entries.length}`);
  for (const [, name, rawVal] of entries) {
    const ms = Number(rawVal.replace(/_/g, ''));
    assert.ok(ms > 0, `Breeze TTL for "${name}" is not positive: ${ms}`);
  }
});

test('Breeze server: mutating tools do NOT use cachedBreeze', () => {
  const src = fs.readFileSync(
    path.join(__dirname, '../../icici breeze/js-api/src/server.js'), 'utf-8'
  );
  const mutating = ['place_order', 'modify_order', 'cancel_order', 'square_off'];
  for (const tool of mutating) {
    const block = toolBlock(src, tool);
    assert.ok(block !== null, `Breeze tool "${tool}" not found`);
    const usesCached = /cachedBreeze/.test(block);
    assert.ok(!usesCached, `Breeze mutating tool "${tool}" should NOT use cachedBreeze`);
  }
});

test('Breeze server: read-only tools use cachedBreeze', () => {
  const src = fs.readFileSync(
    path.join(__dirname, '../../icici breeze/js-api/src/server.js'), 'utf-8'
  );
  const readTools = [
    'get_funds', 'get_margins', 'get_quotes', 'get_option_chain_quotes',
    'get_historical_data', 'get_names', 'get_demat_holdings',
  ];
  for (const tool of readTools) {
    const block = toolBlock(src, tool);
    assert.ok(block !== null, `Breeze tool "${tool}" not found`);
    const usesCached = /cachedBreeze/.test(block);
    assert.ok(usesCached, `Breeze read tool "${tool}" should use cachedBreeze`);
  }
});
