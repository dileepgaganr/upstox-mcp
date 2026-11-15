import test from "node:test";
import assert from "node:assert/strict";
import { nextExpiry0330Ist, nextIstTimeMs, parseHHMM, jwtExpMs, resolveTokenExpiry, updateEnvText, formatIst, todayIst } from "./token.js";

const utc = (s) => Date.parse(s);

test("next 03:30 IST: before cutoff same IST day", () => {
  // 2026-11-14 20:00Z = 01:30 IST Nov 15 -> next 03:30 IST Nov 15 = 22:00Z Nov 14
  assert.equal(nextExpiry0330Ist(utc("2026-11-14T20:00:00Z")), utc("2026-11-14T22:00:00Z"));
});
test("next 03:30 IST: after cutoff rolls to next day", () => {
  // 2026-11-14 04:00Z = 09:30 IST -> next is Nov 15 03:30 IST = Nov 14 22:00Z
  assert.equal(nextExpiry0330Ist(utc("2026-11-14T04:00:00Z")), utc("2026-11-14T22:00:00Z"));
});
test("next 03:30 IST: exactly at cutoff is strictly after", () => {
  const at = utc("2026-11-14T22:00:00Z");
  assert.equal(nextExpiry0330Ist(at), at + 86400e3);
});
test("daily 08:00 IST = 02:30Z", () => {
  assert.equal(nextIstTimeMs(utc("2026-11-14T00:00:00Z"), 8, 0), utc("2026-11-14T02:30:00Z"));
  assert.equal(nextIstTimeMs(utc("2026-11-14T03:00:00Z"), 8, 0), utc("2026-11-15T02:30:00Z"));
});
test("IST date rollover across UTC midnight", () => {
  // 19:00Z Nov 14 = 00:30 IST Nov 15 -> next 08:00 IST is Nov 15 02:30Z
  assert.equal(nextIstTimeMs(utc("2026-11-14T19:00:00Z"), 8, 0), utc("2026-11-15T02:30:00Z"));
  assert.equal(todayIst(utc("2026-11-14T19:00:00Z")), "2026-11-15");
});
test("parseHHMM", () => {
  assert.deepEqual(parseHHMM("8:05"), { hour: 8, minute: 5 });
  assert.deepEqual(parseHHMM("25:00"), { hour: 8, minute: 0 });
  assert.deepEqual(parseHHMM(undefined), { hour: 8, minute: 0 });
});
const mkJwt = (p) => "h." + Buffer.from(JSON.stringify(p)).toString("base64url") + ".s";
test("jwtExpMs decodes base64url", () => {
  assert.equal(jwtExpMs(mkJwt({ exp: 1700000000 })), 1700000000000);
  assert.equal(jwtExpMs("garbage"), null);
  assert.equal(jwtExpMs(mkJwt({ sub: "x" })), null);
});
test("resolveTokenExpiry precedence", () => {
  const now = utc("2026-11-14T04:00:00Z");
  assert.deepEqual(resolveTokenExpiry({ envExpiresAt: "123456", token: mkJwt({ exp: 9 }), now }), { ms: 123456, source: "env" });
  assert.deepEqual(resolveTokenExpiry({ envExpiresAt: "", token: mkJwt({ exp: 9 }), now }), { ms: 9000, source: "jwt" });
  const f = resolveTokenExpiry({ token: "opaque", now });
  assert.equal(f.source, "fallback_0330_ist");
  assert.equal(f.ms, utc("2026-11-14T22:00:00Z"));
});
test("formatIst", () => {
  assert.equal(formatIst(utc("2026-11-14T22:00:00Z")), "2026-11-15 03:30:00 IST");
});
test("updateEnvText replaces anchored, appends missing, keeps other lines", () => {
  const src = "A=1\nUPSTOX_ACCESS_TOKEN=old\nXUPSTOX_ACCESS_TOKEN=keep\n";
  const out = updateEnvText(src, { UPSTOX_ACCESS_TOKEN: "n$&ew", NEW_KEY: "9" });
  assert.equal(out, "A=1\nUPSTOX_ACCESS_TOKEN=n$&ew\nXUPSTOX_ACCESS_TOKEN=keep\nNEW_KEY=9\n");
});
test("updateEnvText appends newline when file lacks trailing one, strips newlines in values", () => {
  assert.equal(updateEnvText("A=1", { B: "x\ny" }), "A=1\nB=xy\n");
});

import { totp, base32Decode, base32Encode } from "./token.js";
const RFC_SECRET = base32Encode(Buffer.from("12345678901234567890", "ascii"));
test("TOTP matches RFC 6238 SHA1 vectors (8 digits)", () => {
  const v = [[59, "94287082"], [1111111109, "07081804"], [1111111111, "14050471"],
             [1234567890, "89005924"], [2000000000, "69279037"], [20000000000, "65353130"]];
  for (const [t, code] of v) assert.equal(totp(RFC_SECRET, { timeMs: t * 1000, digits: 8 }), code);
});
test("TOTP 6 digits = last 6 of 8-digit vector", () => {
  assert.equal(totp(RFC_SECRET, { timeMs: 59000 }), "287082");
});
test("base32 tolerant of spaces, lowercase, padding", () => {
  const a = base32Decode(RFC_SECRET);
  assert.deepEqual(base32Decode(RFC_SECRET.toLowerCase().replace(/(.{4})/g, "$1 ") + "===="), a);
  assert.equal(a.toString("ascii"), "12345678901234567890");
  assert.throws(() => base32Decode("1!"));
});
