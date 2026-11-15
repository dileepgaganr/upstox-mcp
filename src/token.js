import crypto from "node:crypto";
// Pure helpers for Upstox token lifetime + .env editing. No I/O, easy to unit test.
// IST is UTC+5:30 with no DST, so all timezone math is explicit (never uses process TZ).

export const IST_OFFSET_MS = 5.5 * 3600e3;
const DAY_MS = 86400e3;

/** Next occurrence (strictly after nowMs) of hh:mm IST, as epoch ms. */
export function nextIstTimeMs(nowMs, hour, minute) {
  const istNow = nowMs + IST_OFFSET_MS; // "IST wall clock" expressed as a UTC date
  const d = new Date(istNow);
  let target = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), hour, minute, 0, 0);
  if (target <= istNow) target += DAY_MS;
  return target - IST_OFFSET_MS;
}

/** Upstox access tokens always expire at 03:30 IST. Next one after nowMs. */
export function nextExpiry0330Ist(nowMs = Date.now()) {
  return nextIstTimeMs(nowMs, 3, 30);
}

/** Parse "HH:MM" -> {hour, minute}; falls back to fallback ("08:00") when invalid. */
export function parseHHMM(str, fallback = "08:00") {
  const m = /^\s*(\d{1,2}):(\d{2})\s*$/.exec(String(str ?? ""));
  if (m) {
    const h = +m[1], mi = +m[2];
    if (h >= 0 && h <= 23 && mi >= 0 && mi <= 59) return { hour: h, minute: mi };
  }
  return parseHHMM(fallback, "08:00");
}

/** Decode JWT exp claim (seconds) -> ms, no signature verification. null if unavailable. */
export function jwtExpMs(token) {
  try {
    const part = String(token).split(".")[1];
    if (!part) return null;
    const json = Buffer.from(part.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    const exp = JSON.parse(json).exp;
    return typeof exp === "number" && isFinite(exp) ? exp * 1000 : null;
  } catch {
    return null;
  }
}

/**
 * Token expiry: explicit UPSTOX_TOKEN_EXPIRES_AT -> JWT exp -> next 03:30 IST.
 * Returns { ms, source }.
 */
export function resolveTokenExpiry({ envExpiresAt, token, now = Date.now() }) {
  const env = Number(envExpiresAt);
  if (envExpiresAt !== undefined && envExpiresAt !== null && envExpiresAt !== "" && isFinite(env) && env > 0) {
    return { ms: env, source: "env" };
  }
  const j = token ? jwtExpMs(token) : null;
  if (j) return { ms: j, source: "jwt" };
  return { ms: nextExpiry0330Ist(now), source: "fallback_0330_ist" };
}

/** Format epoch ms as "YYYY-MM-DD HH:mm:ss IST". */
export function formatIst(ms) {
  return new Date(ms + IST_OFFSET_MS).toISOString().replace("T", " ").slice(0, 19) + " IST";
}

/** Today's date (YYYY-MM-DD) in IST. */
export function todayIst(nowMs = Date.now()) {
  return new Date(nowMs + IST_OFFSET_MS).toISOString().slice(0, 10);
}

/** Replace KEY=... lines (anchored, multiline) or append missing keys. Pure. */
export function updateEnvText(text, vars) {
  let out = text || "";
  for (const [key, value] of Object.entries(vars)) {
    if (!/^[A-Z0-9_]+$/.test(key)) throw new Error(`bad env key ${key}`);
    const v = String(value ?? "").replace(/[\r\n]/g, "");
    const re = new RegExp(`^${key}=.*$`, "m");
    if (re.test(out)) {
      out = out.replace(re, () => `${key}=${v}`);
    } else {
      out += (out === "" || out.endsWith("\n") ? "" : "\n") + `${key}=${v}\n`;
    }
  }
  return out;
}

// ── RFC 6238 TOTP (node:crypto only) ─────────────────────────────────

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** RFC 4648 base32 decode; tolerates spaces/dashes, lowercase, missing padding. */
export function base32Decode(str) {
  const clean = String(str ?? "").toUpperCase().replace(/[\s-]/g, "").replace(/=+$/, "");
  if (!clean) throw new Error("empty base32 secret");
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error("invalid base32 secret");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** base32 encode (used by tests / tooling). */
export function base32Encode(buf) {
  let bits = 0, value = 0, out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}


/** TOTP code for a base32 secret. Defaults: HMAC-SHA1, 30 s step, 6 digits. */
export function totp(secretBase32, { timeMs = Date.now(), digits = 6, step = 30, algorithm = "sha1" } = {}) {
  const key = base32Decode(secretBase32);
  const counter = Math.floor(timeMs / 1000 / step);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac(algorithm, key).update(msg).digest();
  const off = h[h.length - 1] & 0x0f;
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(bin % 10 ** digits).padStart(digits, "0");
}
