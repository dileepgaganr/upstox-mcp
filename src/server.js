import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import axios from "axios";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import http from "http";
import https from "https";
import { fileURLToPath } from "url";
import express from "express";
import crypto from "crypto";
import { cached } from "./cache.js";
import {
  nextExpiry0330Ist, nextIstTimeMs, parseHHMM, resolveTokenExpiry,
  formatIst, todayIst, updateEnvText, totp, jwtExpMs,
} from "./token.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Overridable so tests never touch the real .env.
const ENV_PATH = process.env.UPSTOX_ENV_PATH || path.resolve(__dirname, "../.env");

dotenv.config({ path: ENV_PATH });

// UPSTOX_BASE_URL is overridable (tests point it at a local stub). Production default below.
const UPSTOX_BASE_URL = (process.env.UPSTOX_BASE_URL || "https://api.upstox.com").replace(/\/+$/, "");
const UPSTOX_HFT_URL = "https://api-hft.upstox.com"; // order placement/modify/cancel ONLY
const UPSTOX_AUTH_URL = `${UPSTOX_BASE_URL}/v2/login/authorization/dialog`;
const UPSTOX_TOKEN_URL = `${UPSTOX_BASE_URL}/v2/login/authorization/token`;
const UPSTOX_TOTP_URL = `${UPSTOX_BASE_URL}/v2/totp-login/authorization/token`;
const UPSTOX_TOKEN_REQUEST_URL = `${UPSTOX_BASE_URL}/v3/login/auth/token/request`;

let ACCESS_TOKEN = process.env.UPSTOX_ACCESS_TOKEN || null;
// Token lifetime + pending-request state, mirrored from .env (shared across processes).
let TOKEN_EXPIRES_AT = process.env.UPSTOX_TOKEN_EXPIRES_AT || "";
let TOKEN_SIG = process.env.UPSTOX_TOKEN_SIG || "";
let TOKEN_REQUEST_EXPIRY = process.env.UPSTOX_TOKEN_REQUEST_EXPIRY || "";
let TOKEN_REQUESTED_AT = process.env.UPSTOX_TOKEN_REQUESTED_AT || "";
// TOTP-login bookkeeping (shared across processes via .env). Never contains secrets.
const envState = {
  UPSTOX_RENEW_LOCK_UNTIL: process.env.UPSTOX_RENEW_LOCK_UNTIL || "",
  UPSTOX_TOTP_LAST_ATTEMPT_AT: process.env.UPSTOX_TOTP_LAST_ATTEMPT_AT || "",
  UPSTOX_TOTP_FAILS: process.env.UPSTOX_TOTP_FAILS || "",
  UPSTOX_TOTP_BLOCKED_UNTIL: process.env.UPSTOX_TOTP_BLOCKED_UNTIL || "",
};

const API_KEY = process.env.UPSTOX_API_KEY;
const API_SECRET = process.env.UPSTOX_API_SECRET;
const AUTH_PORT = parseInt(process.env.AUTH_PORT || "9080", 10);
const REDIRECT_URI = process.env.UPSTOX_REDIRECT_URI || `http://localhost:${AUTH_PORT}/callback`;
const NOTIFIER_SECRET = process.env.UPSTOX_NOTIFIER_SECRET || "";
const REQUEST_COOLDOWN_MIN = Math.max(1, parseFloat(process.env.UPSTOX_TOKEN_REQUEST_COOLDOWN_MIN || "30") || 30);
const REQUEST_TIME = parseHHMM(process.env.UPSTOX_TOKEN_REQUEST_TIME_IST || "08:00");
// Credentials for TOTP login (primary renewal). Never logged or returned by any tool/endpoint.
const TOTP_SECRET = process.env.UPSTOX_TOTP_SECRET || "";
const UPSTOX_PIN = process.env.UPSTOX_PIN || "";
const TOTP_CONFIGURED = !!(API_KEY && TOTP_SECRET && UPSTOX_PIN);
const NOTIFIER_ENABLED = ["1", "true", "on", "yes"].includes(String(process.env.UPSTOX_NOTIFIER_ENABLED ?? "").toLowerCase());
const RENEW_STRATEGY = TOTP_CONFIGURED ? "totp" : NOTIFIER_ENABLED ? "access_token_request" : "oauth_login";
const TOTP_MIN_GAP_MS = 2 * 60_000;
const TOTP_MAX_FAILS = 3;
const AUTO_TOKEN_REQUEST =
  !["0", "false", "off", "no"].includes(String(process.env.UPSTOX_AUTO_TOKEN_REQUEST ?? "").toLowerCase()) &&
  (TOTP_CONFIGURED || !!(NOTIFIER_ENABLED && API_KEY && API_SECRET));
const NOTIFIER_PATH = NOTIFIER_SECRET ? "/notifier/<UPSTOX_NOTIFIER_SECRET>" : "/notifier";

// ── HTTP keep-alive client ───────────────────────────────────────────
// Reuses TCP + TLS across calls so each tool invocation isn't a fresh handshake.

const httpsAgent = new https.Agent({
  keepAlive: true,
  maxSockets: 25,
  maxFreeSockets: 10,
  timeout: 60_000,
});
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 25, maxFreeSockets: 10 });
const httpClient = axios.create({
  httpsAgent,
  httpAgent,
  timeout: 30_000,
});

// ── In-memory token cache + .env file watcher ────────────────────────
// getLatestToken() is called on every API request. Doing fs.readFileSync on the
// hot path was blocking the event loop, so we cache in memory and only re-read
// when the file actually changes (watcher fires every 2s).

function parseEnvFileSync(text) {
  const out = {};
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (!m) continue;
    out[m[1]] = m[2].trim();
  }
  return out;
}

function loadTokensFromEnvFile() {
  try {
    const text = fs.readFileSync(ENV_PATH, "utf-8");
    const p = parseEnvFileSync(text);
    if ("UPSTOX_ACCESS_TOKEN" in p) {
      const fresh = p.UPSTOX_ACCESS_TOKEN || null;
      if (fresh !== ACCESS_TOKEN) {
        ACCESS_TOKEN = fresh;
        console.error(fresh ? "🔄 Loaded updated access token from .env" : "🔄 Access token cleared in .env");
      }
    }
    TOKEN_EXPIRES_AT = p.UPSTOX_TOKEN_EXPIRES_AT || "";
    TOKEN_SIG = p.UPSTOX_TOKEN_SIG || "";
    TOKEN_REQUEST_EXPIRY = p.UPSTOX_TOKEN_REQUEST_EXPIRY || "";
    TOKEN_REQUESTED_AT = p.UPSTOX_TOKEN_REQUESTED_AT || "";
    for (const k of Object.keys(envState)) envState[k] = p[k] || "";
  } catch (e) {
    // .env may not exist on first boot — that's fine, env vars still apply.
  }
}

// Prime the cache once at startup
loadTokensFromEnvFile();

fs.watchFile(ENV_PATH, { interval: 2000 }, (curr, prev) => {
  if (curr.mtimeMs !== prev.mtimeMs) loadTokensFromEnvFile();
});

function getLatestToken() {
  // Pure in-memory read — zero I/O on the hot path.
  return ACCESS_TOKEN;
}

const maskToken = (t) => (t ? `${String(t).slice(0, 6)}…(${String(t).length} chars)` : null);
const tokenSig = (t) => crypto.createHash("sha256").update(String(t)).digest("hex").slice(0, 12);

// ── Token expiry helpers ─────────────────────────────────────────────
// UPSTOX_TOKEN_EXPIRES_AT is trusted only if UPSTOX_TOKEN_SIG matches the current token
// (so a token pasted into .env by hand doesn't inherit a stale expiry).

function getTokenExpiry() {
  const sigOk = !TOKEN_SIG || (ACCESS_TOKEN && TOKEN_SIG === tokenSig(ACCESS_TOKEN));
  return resolveTokenExpiry({
    envExpiresAt: sigOk ? TOKEN_EXPIRES_AT : "",
    token: ACCESS_TOKEN,
    now: Date.now(),
  });
}
function getTokenExpiryMs() {
  return getTokenExpiry().ms;
}
function tokenIsExpired(marginMs = 0) {
  return getTokenExpiryMs() <= Date.now() + marginMs;
}

// ── Atomic .env persistence ──────────────────────────────────────────
// Writes are serialized within a process; file is replaced via temp+rename. A
// single-file Docker bind mount can't be renamed over (EBUSY), so fall back to
// an in-place write in that case.

let envWriteChain = Promise.resolve();

function applyEnvVarsToMemory(vars) {
  for (const [k, v] of Object.entries(vars)) {
    const val = v === null || v === undefined ? "" : String(v);
    if (k === "UPSTOX_ACCESS_TOKEN") ACCESS_TOKEN = val || null;
    else if (k === "UPSTOX_TOKEN_EXPIRES_AT") TOKEN_EXPIRES_AT = val;
    else if (k === "UPSTOX_TOKEN_SIG") TOKEN_SIG = val;
    else if (k === "UPSTOX_TOKEN_REQUEST_EXPIRY") TOKEN_REQUEST_EXPIRY = val;
    else if (k === "UPSTOX_TOKEN_REQUESTED_AT") TOKEN_REQUESTED_AT = val;
    else if (k in envState) envState[k] = val;
  }
}

function updateEnvVars(vars) {
  applyEnvVarsToMemory(vars);
  const job = envWriteChain.then(async () => {
    let env = "";
    try { env = await fs.promises.readFile(ENV_PATH, "utf-8"); } catch (_) { env = ""; }
    const next = updateEnvText(env, vars);
    const tmp = `${ENV_PATH}.${process.pid}.${Date.now()}.tmp`;
    try {
      await fs.promises.writeFile(tmp, next, { mode: 0o600 });
      await fs.promises.rename(tmp, ENV_PATH);
    } catch (e) {
      try { await fs.promises.unlink(tmp); } catch (_) {}
      if (["EBUSY", "EXDEV", "EPERM", "EACCES"].includes(e.code)) {
        await fs.promises.writeFile(ENV_PATH, next); // bind-mounted file: in-place
      } else {
        throw e;
      }
    }
  });
  envWriteChain = job.catch(() => {});
  return job.catch((e) => {
    console.error("⚠️  Could not update .env:", e.message);
    return false;
  }).then((r) => r !== false);
}

async function persistToken(token, expiresAtMs) {
  const good = await updateEnvVars({
    UPSTOX_ACCESS_TOKEN: token,
    UPSTOX_TOKEN_EXPIRES_AT: String(expiresAtMs),
    UPSTOX_TOKEN_SIG: tokenSig(token),
    UPSTOX_TOKEN_REQUEST_EXPIRY: "",
    UPSTOX_TOKEN_REQUESTED_AT: "",
  });
  if (good) console.error(`✅ Token ${maskToken(token)} saved to .env (expires ${formatIst(expiresAtMs)})`);
  return good;
}

// ── Access Token Request (v3) — official daily renewal path ──────────
// POST /v3/login/auth/token/request/{client_id} with {client_secret}. The user approves in the
// Upstox app / WhatsApp; Upstox then POSTs the token to our Notifier Webhook (POST /notifier).

const TOKEN_REQUEST_ERRORS = {
  UDAPI1124: "This app is not an individual-user app; Access Token Request is only available for individual apps.",
  UDAPI100069: "Bad credentials: check UPSTOX_API_KEY / UPSTOX_API_SECRET.",
  UDAPI1123: "No Notifier Webhook URL configured for this app: set it in the Upstox developer app settings.",
  UDAPI1155: "The app is still under review by Upstox.",
  UDAPI1157: "The app has expired; renew/recreate it in the Upstox developer portal.",
};

let tokenRequestInflight = null;

function approvalHint(expiryMs) {
  return `Approve the access-token request in your Upstox app or WhatsApp${expiryMs ? ` before ${formatIst(Number(expiryMs))}` : ""}. The token is delivered to the Notifier Webhook (${NOTIFIER_PATH}) automatically.`;
}

async function requestAccessToken({ force = false } = {}) {
  if (!API_KEY || !API_SECRET) {
    return { status: "error", code: "MISSING_CREDENTIALS", message: "UPSTOX_API_KEY / UPSTOX_API_SECRET not set" };
  }
  if (tokenRequestInflight) return tokenRequestInflight;
  tokenRequestInflight = (async () => {
    loadTokensFromEnvFile(); // pick up requests made by other processes sharing .env
    const now = Date.now();
    const pendingUntil = Number(TOKEN_REQUEST_EXPIRY) || 0;
    const sentAt = Number(TOKEN_REQUESTED_AT) || 0;
    if (!force && now < pendingUntil && now - sentAt < REQUEST_COOLDOWN_MIN * 60_000) {
      return {
        status: "pending",
        skipped: true,
        requested_at: new Date(sentAt).toISOString(),
        authorization_expiry: new Date(pendingUntil).toISOString(),
        authorization_expiry_ist: formatIst(pendingUntil),
        hint: `A request is already pending (cooldown ${REQUEST_COOLDOWN_MIN} min). ${approvalHint(pendingUntil)} Use force=true to resend.`,
      };
    }
    // Claim before the HTTP call so other processes dedupe against us.
    await updateEnvVars({
      UPSTOX_TOKEN_REQUESTED_AT: String(now),
      UPSTOX_TOKEN_REQUEST_EXPIRY: String(now + 5 * 60_000),
    });
    try {
      const res = await httpClient.post(
        `${UPSTOX_TOKEN_REQUEST_URL}/${encodeURIComponent(API_KEY)}`,
        { client_secret: API_SECRET },
        { headers: { accept: "application/json", "Content-Type": "application/json" } }
      );
      const exp = Number(res.data?.data?.authorization_expiry) || now + 10 * 60_000;
      await updateEnvVars({
        UPSTOX_TOKEN_REQUESTED_AT: String(now),
        UPSTOX_TOKEN_REQUEST_EXPIRY: String(exp),
      });
      console.error(`📲 Access token request sent (valid until ${formatIst(exp)})`);
      return {
        status: "requested",
        requested_at: new Date(now).toISOString(),
        authorization_expiry: new Date(exp).toISOString(),
        authorization_expiry_ist: formatIst(exp),
        notifier_url: res.data?.data?.notifier_url,
        hint: approvalHint(exp),
      };
    } catch (e) {
      await updateEnvVars({ UPSTOX_TOKEN_REQUESTED_AT: "", UPSTOX_TOKEN_REQUEST_EXPIRY: "" });
      const first = e.response?.data?.errors?.[0];
      const code = first?.errorCode || first?.error_code;
      const message = first?.message || e.response?.data?.message || e.message;
      console.error(`❌ Access token request failed: ${code || ""} ${message}`);
      return {
        status: "error",
        code: code || (e.response?.status ? `HTTP_${e.response.status}` : "NETWORK"),
        message,
        hint: TOKEN_REQUEST_ERRORS[code] || "Request failed; fall back to the OAuth login URL.",
      };
    }
  })().finally(() => { tokenRequestInflight = null; });
  return tokenRequestInflight;
}

// ── API Helper ───────────────────────────────────────────────────────

// ── TOTP login (primary renewal) ─────────────────────────────────────
// POST /v2/totp-login/authorization/token {totp, pin} with x-api-key. NOTE: this revokes any
// currently active token for the app, so it is only called when the token is missing/expired/rejected.
// Rate limits: 1/s, 10/min, 60/30min -> max 1 auto attempt per 2 min, stop after 3 consecutive
// failures until the next IST day (or a manual force=true call).

const TOTP_ERRORS = {
  UDAPI100098: "TOTP is not enabled on this Upstox account: enable it in Upstox account security settings.",
  UDAPI100101: "This app is not an individual-user app; TOTP login is only available for individual apps.",
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitForNewToken(prevToken, maxMs = 10_000) {
  const end = Date.now() + maxMs;
  while (Date.now() < end) {
    loadTokensFromEnvFile();
    if (ACCESS_TOKEN && ACCESS_TOKEN !== prevToken && !tokenIsExpired(0)) return true;
    await sleep(500);
  }
  return false;
}

async function totpLogin({ force = false } = {}) {
  const prevToken = ACCESS_TOKEN;
  loadTokensFromEnvFile();
  const now = Date.now();
  // Cross-process lock: someone else is mid-login -> wait for their token to land via .env.
  const lockUntil = Number(envState.UPSTOX_RENEW_LOCK_UNTIL) || 0;
  if (lockUntil > now) {
    const got = await waitForNewToken(prevToken);
    return got
      ? { status: "skipped_locked", method: "totp", token_changed: true, hint: "Another process renewed the token." }
      : { status: "skipped_locked", method: "totp", token_changed: false, hint: "Another process is renewing the token; retry in a few seconds." };
  }
  if (!force) {
    const blockedUntil = Number(envState.UPSTOX_TOTP_BLOCKED_UNTIL) || 0;
    if (blockedUntil > now) {
      return { status: "blocked", method: "totp", message: `Auto TOTP login paused after ${TOTP_MAX_FAILS} consecutive failures until ${formatIst(blockedUntil)}. Fix the cause, then call renew_token with force=true.` };
    }
    const last = Number(envState.UPSTOX_TOTP_LAST_ATTEMPT_AT) || 0;
    if (now - last < TOTP_MIN_GAP_MS) {
      return { status: "throttled", method: "totp", message: `Last TOTP attempt was ${Math.round((now - last) / 1000)}s ago; waiting (min gap 2 min).` };
    }
  }
  let code;
  try {
    code = totp(TOTP_SECRET);
  } catch (e) {
    return { status: "error", method: "totp", code: "CONFIG", message: "UPSTOX_TOTP_SECRET is not valid base32", hint: "Re-copy the base32 key shown when enabling TOTP." };
  }
  await updateEnvVars({
    UPSTOX_RENEW_LOCK_UNTIL: String(now + 60_000),
    UPSTOX_TOTP_LAST_ATTEMPT_AT: String(now),
  });
  try {
    const res = await httpClient.post(UPSTOX_TOTP_URL, { totp: code, pin: UPSTOX_PIN }, {
      headers: { "x-api-key": API_KEY, "Content-Type": "application/json", accept: "application/json" },
    });
    const d = res.data?.data && typeof res.data.data === "object" ? res.data.data : res.data;
    const token = d?.access_token;
    if (typeof token !== "string" || !token) throw Object.assign(new Error("response had no access_token"), { noToken: true });
    const expiresAt = jwtExpMs(token) || nextExpiry0330Ist(Date.now());
    await persistToken(token, expiresAt);
    await updateEnvVars({ UPSTOX_TOTP_FAILS: "", UPSTOX_TOTP_BLOCKED_UNTIL: "" });
    console.error("🔐 TOTP login succeeded");
    return { status: "renewed", method: "totp", expires_at_ist: formatIst(expiresAt) };
  } catch (e) {
    const first = e.response?.data?.errors?.[0];
    const errCode = first?.errorCode || first?.error_code;
    const message = first?.message || e.response?.data?.message || (e.response?.status ? `HTTP ${e.response.status}` : e.message);
    const fails = (Number(envState.UPSTOX_TOTP_FAILS) || 0) + 1;
    const vars = { UPSTOX_TOTP_FAILS: String(fails) };
    if (fails >= TOTP_MAX_FAILS) vars.UPSTOX_TOTP_BLOCKED_UNTIL = String(nextIstTimeMs(Date.now(), 0, 0));
    await updateEnvVars(vars);
    console.error(`❌ TOTP login failed (${fails}/${TOTP_MAX_FAILS}): ${errCode || ""} ${message}`);
    return {
      status: "error", method: "totp",
      code: errCode || (e.response?.status ? `HTTP_${e.response.status}` : "NETWORK"),
      message,
      hint: TOTP_ERRORS[errCode] || "TOTP login failed; check UPSTOX_TOTP_SECRET / UPSTOX_PIN.",
      consecutive_failures: fails,
    };
  } finally {
    await updateEnvVars({ UPSTOX_RENEW_LOCK_UNTIL: "" });
  }
}

// Strategy chain: TOTP login -> Access Token Request (opt-in) -> OAuth login URL.
let renewInflight = null;
function renewToken({ force = false } = {}) {
  if (renewInflight) return renewInflight;
  renewInflight = (async () => {
    if (TOTP_CONFIGURED) return totpLogin({ force });
    if (NOTIFIER_ENABLED && API_SECRET) return { method: "access_token_request", ...(await requestAccessToken({ force })) };
    return {
      status: "manual", method: "oauth_login",
      login_url: `http://localhost:${AUTH_PORT}/login`,
      hint: "No automatic renewal configured (set UPSTOX_TOTP_SECRET + UPSTOX_PIN, or UPSTOX_NOTIFIER_ENABLED=1). Log in via the OAuth URL.",
    };
  })().finally(() => { renewInflight = null; });
  return renewInflight;
}

// Called when the token is missing/expired/rejected. Returns normally ONLY if a
// newer, non-expired token is now available (caller should retry once); otherwise throws.
async function recoverToken(prevToken) {
  loadTokensFromEnvFile();
  const fresh = getLatestToken();
  if (fresh && fresh !== prevToken && !tokenIsExpired(0)) {
    console.error("🔄 Found newer token, retrying...");
    return;
  }
  const r = await renewToken();
  if (r.status === "renewed") return;
  if (r.status === "skipped_locked" && r.token_changed) return;
  const loginUrl = ensureAuthServerStarted();
  if (r.method === "access_token_request" && (r.status === "requested" || r.status === "pending")) {
    throw new Error(
      `Upstox token expired — approval request sent to your Upstox app/WhatsApp; approve it and retry. Fallback: login at ${loginUrl}`
    );
  }
  throw new Error(
    `Upstox token expired — automatic renewal (${r.method}) ${r.status}: ${[r.code, r.message, r.hint].filter(Boolean).join(" ")}. Fallback: login at ${loginUrl}`.replace(/\s+/g, " ")
  );
}

async function callAPI(endpoint, method = "GET", data = null, retried = false, hft = false, extraHeaders = null) {
  const token = getLatestToken();
  if (!token || tokenIsExpired(0)) {
    // Skip the doomed HTTP call and go straight to recovery (renews inline with TOTP).
    if (retried) throw new Error("Upstox token still missing/expired after renewal attempt");
    await recoverToken(token);
    return callAPI(endpoint, method, data, true, hft, extraHeaders);
  }
  const base = hft ? UPSTOX_HFT_URL : UPSTOX_BASE_URL;
  try {
    const cfg = {
      method,
      url: `${base}${endpoint}`,
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        Accept: "application/json",
        ...(extraHeaders || {}),
      },
    };
    if (data) cfg.data = data;
    return (await httpClient(cfg)).data;
  } catch (err) {
    if (err.response?.status === 401 && !retried) {
      console.error("🔑 Token rejected (401), attempting recovery...");
      await recoverToken(token);
      return callAPI(endpoint, method, data, true, hft, extraHeaders);
    }
    const first = err.response?.data?.errors?.[0];
    throw new Error(`Upstox API Error: ${first?.message || err.response?.data?.message || err.message}`);
  }
}

// ── Lazy embedded auth server (OAuth helper + Notifier webhook) ──────
// All processes sharing /app/.env try to bind AUTH_PORT; only one wins. `authPortOwned`
// is true only in the process whose listen() succeeded — that process also runs the
// token-renewal scheduler.

let authServerInstance = null; // { app, httpServer, loginUrl, callbackUrl, startedAt, ready }
let authPortOwned = false;

function safeEqual(a, b) {
  const ba = Buffer.from(String(a)), bb = Buffer.from(String(b));
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

function buildAuthApp() {
  const app = express();
  app.use(express.json({ limit: "64kb" }));

  app.get("/", (_, res) => {
    res.json({
      status: "running",
      token_set: !!ACCESS_TOKEN,
      expires_at_ist: ACCESS_TOKEN ? formatIst(getTokenExpiryMs()) : null,
      login: `/login`,
      notifier: NOTIFIER_PATH,
      docs: "GET /login → Upstox OAuth → token saved to .env. POST /notifier → Access Token Request webhook (daily auto-renewal).",
    });
  });

  app.get("/login", (_, res) => {
    if (!API_KEY) {
      return res.status(500).send("UPSTOX_API_KEY not set in environment");
    }
    const state = crypto.randomBytes(16).toString("hex");
    const params = new URLSearchParams({
      client_id: API_KEY,
      redirect_uri: REDIRECT_URI,
      response_type: "code",
      state,
    });
    const url = `${UPSTOX_AUTH_URL}?${params}`;
    console.error(`🔑 OAuth login initiated`);
    res.redirect(url);
  });

  // Auto-capture: exchange code immediately and write the token to .env
  app.get("/callback", async (req, res) => {
    const { code } = req.query;
    if (!code) {
      return res.status(400).json({ error: "No authorization code received" });
    }
    console.error(`✅ Auth code received`);
    try {
      const response = await httpClient.post(UPSTOX_TOKEN_URL, null, {
        params: {
          code,
          client_id: API_KEY,
          client_secret: API_SECRET,
          redirect_uri: REDIRECT_URI,
          grant_type: "authorization_code",
        },
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      });
      const { access_token } = response.data;
      // The response has no expiry; Upstox tokens always expire at 03:30 IST.
      await persistToken(access_token, nextExpiry0330Ist(Date.now()));
      res.send(`
        <html><body style="font-family:sans-serif;text-align:center;padding:60px">
          <h1 style="color:green">✅ Token Captured!</h1>
          <p>Access token saved to <code>.env</code> (valid until 03:30 IST tomorrow).</p>
          <p>You can close this tab and call <code>stop_auth_server</code> to release port ${AUTH_PORT}.</p>
        </body></html>
      `);
    } catch (e) {
      const msg = e.response?.data?.message || e.message;
      const details = JSON.stringify(e.response?.data || {}, null, 2);
      console.error(`❌ Token exchange failed: ${msg}`);
      res.status(500).send(`
        <html><body style="font-family:sans-serif;text-align:center;padding:60px">
          <h1 style="color:red">❌ Token Exchange Failed</h1>
          <p>${msg}</p>
          <pre style="text-align:left;background:#f5f5f5;padding:20px;max-width:600px;margin:auto">${details}</pre>
          <p><a href="/login">Try again</a></p>
        </body></html>
      `);
    }
  });

  // Upstox Notifier Webhook: must be unauthenticated and return 2xx. If UPSTOX_NOTIFIER_SECRET
  // is set, the secret path segment stands in for auth; otherwise /notifier/:secret is a 404.
  app.post(["/notifier", "/notifier/:secret"], async (req, res) => {
    if (!NOTIFIER_ENABLED) return res.status(404).json({ error: "notifier disabled (set UPSTOX_NOTIFIER_ENABLED=1)" });
    const given = req.params.secret;
    if (NOTIFIER_SECRET) {
      if (given === undefined || !safeEqual(given, NOTIFIER_SECRET)) return res.status(404).json({ error: "not found" });
    } else if (given !== undefined) {
      return res.status(404).json({ error: "not found" });
    }
    const b = req.body || {};
    if (b.message_type !== "access_token") {
      return res.status(400).json({ status: "error", error: "message_type must be access_token" });
    }
    if (!API_KEY || b.client_id !== API_KEY) {
      return res.status(400).json({ status: "error", error: "client_id mismatch" });
    }
    if (typeof b.access_token !== "string" || !b.access_token.trim()) {
      return res.status(400).json({ status: "error", error: "access_token missing" });
    }
    const token = b.access_token.trim();
    const exp = Number(b.expires_at);
    const expiresAt = isFinite(exp) && exp > Date.now() ? exp : nextExpiry0330Ist(Date.now());
    const saved = await persistToken(token, expiresAt);
    if (!saved) return res.status(500).json({ status: "error", error: "could not persist token" });
    console.error(`📨 Notifier delivered token ${maskToken(token)}`);
    res.json({ status: "ok" });
  });

  app.get("/status", (_, res) => {
    res.json({
      token_set: !!ACCESS_TOKEN,
      token_preview: maskToken(ACCESS_TOKEN),
      expires_at_ist: ACCESS_TOKEN ? formatIst(getTokenExpiryMs()) : null,
      expired: ACCESS_TOKEN ? tokenIsExpired(0) : null,
      auto_token_request: AUTO_TOKEN_REQUEST,
      scheduler_running: schedulerState.running,
      notifier: NOTIFIER_PATH,
      redirect_uri: REDIRECT_URI,
      api_key: API_KEY ? API_KEY.substring(0, 10) + "..." : "NOT SET",
    });
  });

  // Malformed JSON etc. → 400 JSON rather than Express' HTML error page.
  app.use((e, _req, res, _next) => {
    res.status(e.status && e.status < 500 ? e.status : 500).json({ status: "error", error: "bad request" });
  });

  return app;
}

function startAuthServer() {
  if (authServerInstance) return authServerInstance;

  const app = buildAuthApp();
  let resolveReady;
  const ready = new Promise((r) => { resolveReady = r; });
  const httpServer = app.listen(AUTH_PORT, () => {
    authPortOwned = true;
    console.error(`🔐 Auth server listening on http://localhost:${AUTH_PORT} (this process owns the port)`);
    startScheduler();
    resolveReady(true);
  });
  const inst = {
    app,
    httpServer,
    loginUrl: `http://localhost:${AUTH_PORT}/login`,
    callbackUrl: `http://localhost:${AUTH_PORT}/callback`,
    startedAt: new Date().toISOString(),
    ready,
  };
  httpServer.on("error", (err) => {
    // We do NOT own the port: forget this instance so a later start can retry.
    if (authServerInstance === inst) authServerInstance = null;
    authPortOwned = false;
    if (err.code === "EADDRINUSE") {
      console.error(`ℹ️  Port ${AUTH_PORT} already in use; another process owns the auth server`);
    } else {
      console.error(`⚠️  Auth server error: ${err.message}`);
    }
    resolveReady(false);
  });

  authServerInstance = inst;
  return inst;
}

function ensureAuthServerStarted() {
  return startAuthServer().loginUrl;
}

function stopAuthServer() {
  if (!authServerInstance) return false;
  const { httpServer } = authServerInstance;
  authServerInstance = null;
  authPortOwned = false;
  stopScheduler();
  try {
    if (typeof httpServer.closeAllConnections === "function") httpServer.closeAllConnections();
  } catch (_) {}
  try {
    httpServer.close();
  } catch (_) {}
  return true;
}

// ── Token renewal scheduler (runs ONLY in the process that owns the auth port) ──

const schedulerState = { running: false, interval: null, daily: null, nextDailyAt: null, lastCheckAt: null, lastResult: null };

async function schedulerCheck(minRemainingMs, reason) {
  schedulerState.lastCheckAt = new Date().toISOString();
  try {
    loadTokensFromEnvFile();
    if (ACCESS_TOKEN && !tokenIsExpired(minRemainingMs)) {
      schedulerState.lastResult = `${reason}: token ok`;
      return;
    }
    const r = await renewToken();
    schedulerState.lastResult = `${reason}: ${r.method} ${r.status}${r.code ? " " + r.code : ""}`;
  } catch (e) {
    schedulerState.lastResult = `${reason}: error ${e.message}`;
    console.error("⚠️  Scheduler check failed:", e.message);
  }
}

function scheduleDaily() {
  const next = nextIstTimeMs(Date.now(), REQUEST_TIME.hour, REQUEST_TIME.minute);
  schedulerState.nextDailyAt = new Date(next).toISOString();
  // setTimeout caps at ~24.8 days; our max delay is 24h. Add 1s so we land after the boundary.
  schedulerState.daily = setTimeout(async () => {
    // Daily pre-open renewal: skip if a fresh token (>12h left) is already in place.
    await schedulerCheck(12 * 3600e3, "daily");
    if (schedulerState.running) scheduleDaily();
  }, Math.max(1000, next - Date.now() + 1000));
  schedulerState.daily.unref?.();
}

function startScheduler() {
  if (!AUTO_TOKEN_REQUEST || schedulerState.running || isShuttingDown) return;
  schedulerState.running = true;
  schedulerCheck(10 * 60_000, "startup");
  schedulerState.interval = setInterval(() => schedulerCheck(10 * 60_000, "periodic"), 5 * 60_000);
  schedulerState.interval.unref?.();
  scheduleDaily();
  console.error(`⏰ Token scheduler started (every 5 min + daily ${String(REQUEST_TIME.hour).padStart(2, "0")}:${String(REQUEST_TIME.minute).padStart(2, "0")} IST)`);
}

function stopScheduler() {
  if (schedulerState.interval) clearInterval(schedulerState.interval);
  if (schedulerState.daily) clearTimeout(schedulerState.daily);
  schedulerState.interval = null;
  schedulerState.daily = null;
  schedulerState.nextDailyAt = null;
  schedulerState.running = false;
}

// ── Cache TTLs (ms). Shared via ~/.cache/mcp-servers/ across bots/runs. ──
const TTL = {
  // Live market data — brief TTL prevents throttling without stale risk
  market_quote:    30_000,   // 30 s
  ltp:             30_000,
  intraday:        30_000,
  ohlc:            60_000,   // 1 min
  option_chain:    60_000,
  greeks:          30_000,
  exchange_status: 60_000,
  // Account snapshot
  funds:          300_000,   // 5 min
  positions:      300_000,
  mtf_positions:  300_000,
  orders:         120_000,   // 2 min
  order_details:  120_000,
  order_history:  120_000,
  trades:         120_000,
  order_trades:   120_000,
  margin_calc:     60_000,   // 1 min (price-dependent)
  gtt:             60_000,
  kill_switch:     60_000,
  news:           300_000,   // 5 min
  analytics:      300_000,   // OI / PCR / max pain / FII / DII
  // Historical / semi-static
  historical:  21_600_000,   // 6 h (completed bars don't change)
  expired:     21_600_000,   // expired contracts/candles never change
  option_contracts: 3_600_000, // 1 h (new strikes rarely added intraday)
  holdings:     3_600_000,   // 1 h (demat changes on T+1 settlement)
  profile:      3_600_000,
  brokerage:    3_600_000,   // broker schedule rarely changes
  trade_pnl:    3_600_000,
  pnl_meta:     3_600_000,
  pnl_charges:  3_600_000,
  hist_trades:  3_600_000,
  static_ips:   3_600_000,
  mf_holdings:  3_600_000,
  ipos:         3_600_000,
  search:       3_600_000,
  fundamentals: 21_600_000,
  // Very stable
  holidays:   86_400_000,    // 24 h
  timings:    86_400_000,
};

// Convenience wrapper for cacheable GET calls.
// endpoint must already include query-string params as part of the cache key.
function cachedGet(endpoint, ttlKey, hft = false, headers = null) {
  const ttlMs = TTL[ttlKey] || 0;
  return cached("upstox", [hft ? "hft" : "std", endpoint, headers || null], ttlMs, () =>
    callAPI(endpoint, "GET", null, false, hft, headers)
  );
}

// Query-string helpers. Skips undefined/null/""; keys lists keep literal commas.
const enc = encodeURIComponent;
const keysParam = (arr) => arr.map(enc).join(",");
function qs(obj) {
  const parts = [];
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null || v === "") continue;
    parts.push(`${k}=${k === "instrument_key" && Array.isArray(v) ? keysParam(v) : enc(String(v))}`);
  }
  return parts.length ? `?${parts.join("&")}` : "";
}

// ── MCP Server + tool definitions ────────────────────────────────────

const server = new McpServer({
  name: "upstox-trading-server",
  version: "2.1.0",
});

// Compact-JSON helper used by every tool. We deliberately do NOT pretty-print —
// MCP transports the text fine and pretty-printing was a measurable heap waste
// on large market-quote / option-chain responses.
function ok(data) {
  return { content: [{ type: "text", text: JSON.stringify(data) }] };
}
function err(message) {
  return { content: [{ type: "text", text: `Error: ${message}` }], isError: true };
}

// ── User ──
server.tool(
  "get_profile",
  "Get user profile information.",
  {},
  async () => {
    try { return ok(await cachedGet("/v2/user/profile", "profile")); }
    catch (e) { return err(e.message); }
  }
);

server.tool(
  "get_funds_margin",
  "Get available funds and margin. version v3 (default) = GET /v3/user/get-funds-and-margin (Api-Version 3.0); v2 supports the optional segment SEC (equity) or COM (commodity).",
  {
    version: z.enum(["v2", "v3"]).default("v3").optional(),
    segment: z.enum(["SEC", "COM"]).optional().describe("v2 only"),
  },
  async ({ version, segment }) => {
    try {
      if ((version || "v3") === "v2") {
        return ok(await cachedGet(`/v2/user/get-funds-and-margin${qs({ segment })}`, "funds"));
      }
      return ok(await cachedGet("/v3/user/get-funds-and-margin", "funds", false, { "Api-Version": "3.0" }));
    } catch (e) { return err(e.message); }
  }
);

// ── Portfolio ──
server.tool(
  "get_holdings",
  "Retrieve long-term DEMAT holdings.",
  {},
  async () => {
    try { return ok(await cachedGet("/v2/portfolio/long-term-holdings", "holdings")); }
    catch (e) { return err(e.message); }
  }
);

server.tool(
  "get_positions",
  "Get current intraday and delivery positions with P/L.",
  {},
  async () => {
    try { return ok(await cachedGet("/v3/portfolio/short-term-positions", "positions")); }
    catch (e) { return err(e.message); }
  }
);

server.tool(
  "get_mtf_positions",
  "Get Margin Trade Funding positions.",
  {},
  async () => {
    try { return ok(await cachedGet("/v3/portfolio/mtf-positions", "mtf_positions")); }
    catch (e) { return err(e.message); }
  }
);

server.tool(
  "convert_position",
  "Convert position product type (e.g., intraday to delivery).",
  {
    instrument_token: z.string(),
    new_product: z.enum(["D", "I", "CO", "MTF"]),
    old_product: z.enum(["D", "I", "CO", "MTF"]),
    quantity: z.number(),
    transaction_type: z.enum(["BUY", "SELL"]),
  },
  async (input) => {
    try {
      return ok(await callAPI("/v2/portfolio/convert-position", "PUT", {
        instrument_token: input.instrument_token,
        new_product: input.new_product,
        old_product: input.old_product,
        quantity: input.quantity,
        transaction_type: input.transaction_type,
      }));
    } catch (e) { return err(e.message); }
  }
);

// ── Orders ──
server.tool(
  "place_order",
  "Place a new order (market, limit, stop-loss, bracket).",
  {
    instrument_token: z.string(),
    quantity: z.number(),
    order_type: z.enum(["MARKET", "LIMIT", "SL", "SL-M"]),
    transaction_type: z.enum(["BUY", "SELL"]),
    product: z.enum(["D", "I", "CO", "MTF"]),
    price: z.number(),
    trigger_price: z.number(),
    validity: z.enum(["DAY", "IOC"]),
    disclosed_quantity: z.number().optional(),
    is_amo: z.boolean().optional(),
    tag: z.string().optional(),
  },
  async (input) => {
    try {
      return ok(await callAPI("/v2/order/place", "POST", {
        quantity: input.quantity,
        product: input.product,
        validity: input.validity,
        price: input.price,
        instrument_token: input.instrument_token,
        order_type: input.order_type,
        transaction_type: input.transaction_type,
        disclosed_quantity: input.disclosed_quantity || 0,
        trigger_price: input.trigger_price || 0,
        is_amo: input.is_amo || false,
        tag: input.tag || "",
      }, false, true));
    } catch (e) { return err(e.message); }
  }
);

server.tool(
  "modify_order",
  "Modify an existing open order.",
  {
    order_id: z.string(),
    quantity: z.number().optional(),
    order_type: z.enum(["MARKET", "LIMIT", "SL", "SL-M"]).optional(),
    price: z.number().optional(),
    trigger_price: z.number().optional(),
    validity: z.enum(["DAY", "IOC"]).optional(),
    disclosed_quantity: z.number().optional(),
  },
  async (input) => {
    try {
      return ok(await callAPI("/v2/order/modify", "PUT", {
        order_id: input.order_id,
        quantity: input.quantity,
        order_type: input.order_type,
        price: input.price,
        trigger_price: input.trigger_price,
        validity: input.validity,
        disclosed_quantity: input.disclosed_quantity,
      }, false, true));
    } catch (e) { return err(e.message); }
  }
);

server.tool(
  "cancel_order",
  "Cancel a pending order.",
  { order_id: z.string() },
  async ({ order_id }) => {
    try {
      return ok(await callAPI(`/v3/order/cancel?order_id=${order_id}`, "DELETE", null, false, true));
    } catch (e) { return err(e.message); }
  }
);

server.tool(
  "get_order_book",
  "Get all orders for the day (open, pending, filled, cancelled).",
  {},
  async () => {
    try { return ok(await cachedGet("/v2/order/retrieve-all", "orders")); }
    catch (e) { return err(e.message); }
  }
);

server.tool(
  "get_order_details",
  "Get details of a specific order by order_id.",
  { order_id: z.string() },
  async ({ order_id }) => {
    try { return ok(await cachedGet(`/v2/order/details?order_id=${order_id}`, "order_details")); }
    catch (e) { return err(e.message); }
  }
);

server.tool(
  "get_order_history",
  "Get order state history by order_id or tag.",
  {
    order_id: z.string().optional(),
    tag: z.string().optional(),
  },
  async ({ order_id, tag }) => {
    try {
      const params = [];
      if (order_id) params.push(`order_id=${order_id}`);
      if (tag) params.push(`tag=${tag}`);
      return ok(await cachedGet(`/v2/order/history?${params.join("&")}`, "order_history"));
    } catch (e) { return err(e.message); }
  }
);

server.tool(
  "get_trades",
  "Get all executed trades for the day.",
  {},
  async () => {
    try { return ok(await cachedGet("/v2/order/trades/get-trades-for-day", "trades")); }
    catch (e) { return err(e.message); }
  }
);

server.tool(
  "get_order_trades",
  "Get trades for a specific order.",
  { order_id: z.string() },
  async ({ order_id }) => {
    try { return ok(await cachedGet(`/v2/order/trades?order_id=${order_id}`, "order_trades")); }
    catch (e) { return err(e.message); }
  }
);

server.tool(
  "exit_positions",
  "Exit all open positions (square off).",
  {},
  async () => {
    try { return ok(await callAPI("/v2/order/positions/exit", "POST")); }
    catch (e) { return err(e.message); }
  }
);

// ── Market Quotes ──
server.tool(
  "get_market_quote",
  "Full market quote with OHLC, depth, volume. Up to 500 instruments.",
  { instrument_keys: z.array(z.string()).describe("e.g. NSE_EQ|INE002A01018") },
  async ({ instrument_keys }) => {
    try {
      const keys = instrument_keys.join(",");
      return ok(await cachedGet(`/v2/market-quote/quotes?instrument_key=${keys}`, "market_quote"));
    } catch (e) { return err(e.message); }
  }
);

server.tool(
  "get_ltp_quotes",
  "Last Traded Price for up to 1000 instruments (v3).",
  { instrument_keys: z.array(z.string()).min(1).max(1000) },
  async ({ instrument_keys }) => {
    try {
      return ok(await cachedGet(`/v3/market-quote/ltp?instrument_key=${keysParam(instrument_keys)}`, "ltp"));
    } catch (e) { return err(e.message); }
  }
);

server.tool(
  "get_ohlc_quotes",
  "OHLC quotes for up to 1000 instruments (v3). interval: 1d (default), I1 (1-minute) or I30 (30-minute).",
  {
    instrument_keys: z.array(z.string()).min(1).max(1000),
    interval: z.enum(["1d", "I1", "I30"]).default("1d").describe("OHLC interval"),
  },
  async ({ instrument_keys, interval }) => {
    try {
      return ok(await cachedGet(`/v3/market-quote/ohlc?instrument_key=${keysParam(instrument_keys)}&interval=${interval || "1d"}`, "ohlc"));
    } catch (e) { return err(e.message); }
  }
);

// ── Candles (Upstox v3) ──
// Path: /v3/historical-candle/{key}/{unit}/{interval}/{to_date}/{from_date?}
//       /v3/historical-candle/intraday/{key}/{unit}/{interval}
// Units/intervals: minutes 1-300, hours 1-5, days/weeks/months 1.
// Range limits: minutes 1-15 -> 1 month; minutes >15 and hours -> 1 quarter; days -> 1 decade.
// Legacy `interval` names map onto (unit, n); v2 is used only as a fallback for the names v2 supports.
const V3_UNIT = {
  "1minute": ["minutes", 1], "5minute": ["minutes", 5], "15minute": ["minutes", 15],
  "30minute": ["minutes", 30], "60minute": ["hours", 1],
  "day": ["days", 1], "week": ["weeks", 1], "month": ["months", 1],
};
const V2_OK = new Set(["1minute", "30minute", "day", "week", "month"]);
const UNIT_MAX = { minutes: 300, hours: 5, days: 1, weeks: 1, months: 1 };
function resolveUnit(interval, unit, n) {
  if (unit) {
    const max = UNIT_MAX[unit];
    const v = n ?? 1;
    if (!Number.isInteger(v) || v < 1 || v > max) throw new Error(`interval_value for ${unit} must be an integer 1-${max}`);
    return [unit, v, null];
  }
  const m = V3_UNIT[interval || "day"];
  if (!m) throw new Error(`unknown interval ${interval}`);
  return [m[0], m[1], interval];
}
async function candlesV3(keyEnc, [unit, n, legacy], tail, ttlKey) {
  const v3 = `/v3/historical-candle/${tail.intraday ? "intraday/" : ""}${keyEnc}/${unit}/${n}${tail.dates || ""}`;
  try {
    return await cachedGet(v3, ttlKey);
  } catch (e) {
    if (!legacy || !V2_OK.has(legacy)) throw e;     // v2 cannot serve it either
    return await cachedGet(`/v2/historical-candle/${tail.intraday ? "intraday/" : ""}${keyEnc}/${legacy}${tail.dates || ""}`, ttlKey);
  }
}
const UNIT_ENUM = z.enum(["minutes", "hours", "days", "weeks", "months"]);

// ── Historical Candles ──
server.tool(
  "get_historical_candles",
  "Get historical OHLCV candles (Upstox v3). Returns [timestamp, open, high, low, close, volume]. Use `interval` (legacy names) OR `unit`+`interval_value`. Units: minutes 1-300, hours 1-5, days/weeks/months 1. Max range per request: 1 month for minutes 1-15; 1 quarter for minutes >15 and hours; 1 decade for days. from_date is optional (defaults to to_date).",
  {
    instrument_key: z.string().describe("e.g. NSE_EQ|INE002A01018"),
    interval: z.enum(["1minute", "5minute", "15minute", "30minute", "60minute", "day", "week", "month"]).optional(),
    unit: UNIT_ENUM.optional(),
    interval_value: z.number().int().optional().describe("with unit: minutes 1-300, hours 1-5, others 1"),
    from_date: z.string().optional().describe("YYYY-MM-DD"),
    to_date: z.string().describe("YYYY-MM-DD"),
  },
  async ({ instrument_key, interval, unit, interval_value, from_date, to_date }) => {
    try {
      const r = resolveUnit(interval, unit, interval_value);
      return ok(await candlesV3(enc(instrument_key), r, { dates: `/${to_date}${from_date ? `/${from_date}` : ""}` }, "historical"));
    } catch (e) { return err(e.message); }
  }
);

server.tool(
  "get_intraday_candles",
  "Get today's intraday candles (Upstox v3). Use `interval` (legacy names) OR `unit`+`interval_value` (minutes 1-300, hours 1-5, days 1).",
  {
    instrument_key: z.string(),
    interval: z.enum(["1minute", "5minute", "15minute", "30minute", "60minute"]).optional(),
    unit: z.enum(["minutes", "hours", "days"]).optional(),
    interval_value: z.number().int().optional(),
  },
  async ({ instrument_key, interval, unit, interval_value }) => {
    try {
      const r = resolveUnit(interval || (unit ? undefined : "1minute"), unit, interval_value);
      return ok(await candlesV3(enc(instrument_key), r, { intraday: true }, "intraday"));
    } catch (e) { return err(e.message); }
  }
);

// ── Options ──
server.tool(
  "get_option_contracts",
  "Get option contracts for an underlying instrument.",
  {
    instrument_key: z.string().describe("Underlying instrument key"),
    expiry_date: z.string().describe("YYYY-MM-DD (optional)").optional(),
  },
  async ({ instrument_key, expiry_date }) => {
    try {
      let url = `/v2/option/contract?instrument_key=${encodeURIComponent(instrument_key)}`;
      if (expiry_date) url += `&expiry_date=${expiry_date}`;
      return ok(await cachedGet(url, "option_contracts"));
    } catch (e) { return err(e.message); }
  }
);

server.tool(
  "get_option_chain",
  "Get put/call option chain.",
  {
    instrument_key: z.string(),
    expiry_date: z.string().describe("YYYY-MM-DD"),
  },
  async ({ instrument_key, expiry_date }) => {
    try {
      return ok(await cachedGet(
        `/v2/option/chain?instrument_key=${encodeURIComponent(instrument_key)}&expiry_date=${expiry_date}`,
        "option_chain"
      ));
    } catch (e) { return err(e.message); }
  }
);

// ── Charges ──
server.tool(
  "calculate_margin",
  "Calculate required margin for instruments (max 20).",
  {
    instruments: z.array(z.object({
      instrument_token: z.string(),
      quantity: z.number(),
      product: z.enum(["D", "I", "CO", "MTF"]),
      transaction_type: z.enum(["BUY", "SELL"]),
    })),
  },
  async ({ instruments }) => {
    try {
      // POST but idempotent — cache briefly so parallel bots with the same basket skip re-fetching
      return ok(await cached("upstox-margin", { instruments }, TTL.margin_calc, () =>
        callAPI("/v2/charges/margin", "POST", { instruments })
      ));
    } catch (e) { return err(e.message); }
  }
);

server.tool(
  "get_brokerage",
  "Get brokerage charges for a trade.",
  {
    instrument_token: z.string(),
    quantity: z.number(),
    product: z.enum(["D", "I", "CO", "MTF"]),
    transaction_type: z.enum(["BUY", "SELL"]),
    price: z.number(),
  },
  async (input) => {
    try {
      // Docs: GET /v2/charges/brokerage with query params
      const body = {
        instrument_token: input.instrument_token,
        quantity: input.quantity,
        product: input.product,
        transaction_type: input.transaction_type,
        price: input.price,
      };
      return ok(await cached("upstox-brokerage", body, TTL.brokerage, () =>
        callAPI(`/v2/charges/brokerage?${new URLSearchParams(Object.entries(body).map(([k, v]) => [k, String(v)]))}`)
      ));
    } catch (e) { return err(e.message); }
  }
);

// ── P&L ──
server.tool(
  "get_trade_pnl",
  "Get trade-wise profit and loss data.",
  {
    segment: z.enum(["EQ", "FO", "COM", "CD"]),
    financial_year: z.string().describe("e.g. 2425 for FY 2024-25"),
    page_number: z.number().int().min(1).optional(),
    page_size: z.number().int().min(1).max(5000).optional().describe("1-5000 (default 50)"),
  },
  async ({ segment, financial_year, page_number, page_size }) => {
    try {
      const pg = page_number || 1;
      const sz = page_size || 50;
      return ok(await cachedGet(
        `/v2/trade/profit-loss/data?segment=${segment}&financial_year=${financial_year}&page_number=${pg}&page_size=${sz}`,
        "trade_pnl"
      ));
    } catch (e) { return err(e.message); }
  }
);

// ── Market Info ──
server.tool(
  "get_market_holidays",
  "Get list of market holidays, or only the given date (path segment /v2/market/holidays/{date}).",
  { date: z.string().describe("YYYY-MM-DD (optional)").optional() },
  async ({ date }) => {
    try { return ok(await cachedGet(`/v2/market/holidays${date ? `/${enc(date)}` : ""}`, "holidays")); }
    catch (e) { return err(e.message); }
  }
);

server.tool(
  "get_market_timings",
  "Get exchange market timings.",
  { date: z.string().describe("YYYY-MM-DD (optional)").optional() },
  async ({ date }) => {
    try {
      // v2 takes the date as a PATH segment (was ?date= -> 404); default = today in IST.
      return ok(await cachedGet(`/v2/market/timings/${enc(date || todayIst())}`, "timings"));
    } catch (e) { return err(e.message); }
  }
);

// ── Additional read-only market / account tools ──
const SEG4 = z.enum(["EQ", "FO", "COM", "CD"]);
const DDMMYYYY = z.string().describe("dd-mm-yyyy");
const YMD = z.string().describe("YYYY-MM-DD");
const tool = (name, desc, schema, handler) =>
  server.tool(name, desc, schema, async (input) => {
    try { return ok(await handler(input)); } catch (e) { return err(e.message); }
  });

tool("get_full_quote_v3",
  "Full market quote (OHLC, depth, volume) via v3, up to 500 instruments.",
  { instrument_keys: z.array(z.string()).min(1).max(500) },
  ({ instrument_keys }) => cachedGet(`/v3/market-quote/quotes?instrument_key=${keysParam(instrument_keys)}`, "market_quote"));

tool("get_option_greeks",
  "Option greeks (delta, gamma, theta, vega, IV) for up to 50 option instruments.",
  { instrument_keys: z.array(z.string()).min(1).max(50) },
  ({ instrument_keys }) => cachedGet(`/v3/market-quote/option-greek?instrument_key=${keysParam(instrument_keys)}`, "greeks"));

tool("get_pnl_metadata",
  "Trade P&L metadata (counts/totals) for a segment and financial year.",
  { segment: SEG4, financial_year: z.string().describe("e.g. 2425 for FY 2024-25"), from_date: DDMMYYYY.optional(), to_date: DDMMYYYY.optional() },
  (a) => cachedGet(`/v2/trade/profit-loss/metadata${qs(a)}`, "pnl_meta"));

tool("get_pnl_charges",
  "Charges and taxes breakdown for realised P&L in a segment and financial year.",
  { segment: SEG4, financial_year: z.string().describe("e.g. 2425"), from_date: DDMMYYYY.optional(), to_date: DDMMYYYY.optional() },
  (a) => cachedGet(`/v2/trade/profit-loss/charges${qs(a)}`, "pnl_charges"));

tool("get_historical_trades",
  "Historical executed trades between two dates (paginated).",
  {
    start_date: YMD, end_date: YMD,
    page_number: z.number().int().min(1), page_size: z.number().int().min(1),
    segment: z.enum(["EQ", "FO", "COM", "CD", "MF"]).optional(),
  },
  (a) => cachedGet(`/v2/charges/historical-trades${qs(a)}`, "hist_trades"));

// Expired instruments (read-only reference data; requires Upstox expired-instruments access)
tool("get_expired_expiries",
  "List expired expiry dates available for an underlying instrument.",
  { instrument_key: z.string() },
  ({ instrument_key }) => cachedGet(`/v2/expired-instruments/expiries${qs({ instrument_key })}`, "expired"));

tool("get_expired_option_contracts",
  "Expired option contracts for an underlying on a given expiry.",
  { instrument_key: z.string(), expiry_date: YMD },
  (a) => cachedGet(`/v2/expired-instruments/option/contract${qs(a)}`, "expired"));

tool("get_expired_future_contracts",
  "Expired future contracts for an underlying on a given expiry.",
  { instrument_key: z.string(), expiry_date: YMD },
  (a) => cachedGet(`/v2/expired-instruments/future/contract${qs(a)}`, "expired"));

tool("get_expired_historical_candles",
  "Historical candles for an expired instrument key (from the expired contract listings).",
  {
    expired_instrument_key: z.string().describe("e.g. NSE_FO|73507|24-04-2025 (contains |)"),
    interval: z.enum(["1minute", "3minute", "5minute", "15minute", "30minute", "day"]),
    to_date: YMD, from_date: YMD,
  },
  ({ expired_instrument_key, interval, to_date, from_date }) =>
    cachedGet(`/v2/expired-instruments/historical-candle/${enc(expired_instrument_key)}/${interval}/${enc(to_date)}/${enc(from_date)}`, "expired"));

tool("get_exchange_status",
  "Current trading status of an exchange (e.g. NSE, BSE, NFO, BFO, MCX).",
  { exchange: z.string().describe("e.g. NSE") },
  ({ exchange }) => cachedGet(`/v2/market/status/${enc(exchange)}`, "exchange_status"));

tool("search_instruments",
  "Search instruments by text. exchanges/segments/instrument_types are comma-separated lists; records max 30.",
  {
    query: z.string().min(1),
    exchanges: z.string().optional(), segments: z.string().optional(), instrument_types: z.string().optional(),
    expiry: z.string().optional(), atm_offset: z.number().int().optional(),
    page_number: z.number().int().min(1).optional(), records: z.number().int().min(1).max(30).optional(),
  },
  (a) => cachedGet(`/v2/instruments/search${qs(a)}`, "search"));

tool("get_gtt_orders",
  "Read-only: list GTT orders, or fetch one by gtt_order_id.",
  { gtt_order_id: z.string().optional() },
  (a) => cachedGet(`/v3/order/gtt${qs(a)}`, "gtt"));

tool("get_kill_switch_status", "Kill-switch status per segment.", {},
  () => cachedGet("/v2/user/kill-switch", "kill_switch"));

tool("get_static_ips", "Static IPs registered for the account/app.", {},
  () => cachedGet("/v2/user/ip", "static_ips"));

tool("get_news",
  "News feed. category: instrument_keys (requires instrument_keys, max 30), positions, or holdings.",
  {
    category: z.enum(["instrument_keys", "positions", "holdings"]),
    instrument_keys: z.array(z.string()).max(30).optional(),
    page_number: z.number().int().min(1).optional(),
    page_size: z.number().int().min(1).max(100).optional(),
  },
  ({ category, instrument_keys, page_number, page_size }) =>
    cachedGet(`/v2/news${qs({ category, instrument_keys: instrument_keys?.length ? instrument_keys : undefined, page_number, page_size })}`, "news"));

tool("get_ipos",
  "IPO listings. status: open|closed|listed|upcoming; records max 30.",
  {
    status: z.enum(["open", "closed", "listed", "upcoming"]).optional(),
    issue_type: z.string().optional(),
    page_number: z.number().int().min(1).optional(),
    records: z.number().int().min(1).max(30).optional(),
  },
  (a) => cachedGet(`/v2/ipos${qs(a)}`, "ipos"));

tool("get_mf_holdings", "Mutual fund holdings.", {},
  () => cachedGet("/v2/mf/holdings", "mf_holdings"));

// Feed authorization: returns a one-time wss URL, so NEVER cached.
tool("authorize_market_feed",
  "Get a one-time wss:// URL for the v3 market data feed. Not cached; single use.", {},
  () => callAPI("/v3/feed/market-data-feed/authorize"));

tool("authorize_portfolio_feed",
  "Get a one-time wss:// URL for the portfolio stream feed. update_types: comma list of order,gtt_order,position,holding. Not cached.",
  { update_types: z.string().optional().describe("e.g. order,position") },
  ({ update_types }) => callAPI(`/v2/feed/portfolio-stream-feed/authorize${qs({ update_types })}`));

// ── Analytics (Upstox "Market Information" APIs; verified against the docs 2026-11) ──
const EXPIRY = z.string().describe("YYYY-MM-DD or current_week|next_week|far_week|current_month|next_month|far_month");

tool("get_open_interest",
  "Option OI by strike for an underlying (GET /v2/market/oi).",
  { instrument_key: z.string().describe("e.g. NSE_INDEX|Nifty 50"), expiry: EXPIRY, date: YMD },
  (a) => cachedGet(`/v2/market/oi${qs(a)}`, "analytics"));

tool("get_change_in_oi",
  "Change in option OI over N days (GET /v2/market/change-oi).",
  { instrument_key: z.string(), expiry: EXPIRY, date: YMD, interval: z.number().int().min(1).describe("days over which the OI difference is computed") },
  (a) => cachedGet(`/v2/market/change-oi${qs(a)}`, "analytics"));

tool("get_pcr",
  "Put-call ratio with intraday insights (GET /v2/market/pcr). bucket_interval is minutes between points (e.g. 60).",
  { instrument_key: z.string(), expiry: EXPIRY, date: YMD, bucket_interval: z.number().int().min(1) },
  (a) => cachedGet(`/v2/market/pcr${qs(a)}`, "analytics"));

tool("get_max_pain",
  "Max pain with intraday insights (GET /v2/market/max-pain). bucket_interval is minutes between points (e.g. 60).",
  { instrument_key: z.string(), expiry: EXPIRY, date: YMD, bucket_interval: z.number().int().min(1) },
  (a) => cachedGet(`/v2/market/max-pain${qs(a)}`, "analytics"));

const fiiDiiUrl = (path, { data_type, interval, from }) => {
  const parts = data_type.map((d) => `data_type=${enc(d)}`);
  parts.push(`interval=${interval}`);
  if (from) parts.push(`from=${enc(from)}`);
  return `/v2/market/${path}?${parts.join("&")}`;
};
tool("get_fii_activity",
  "FII activity (GET /v2/market/fii). 1D: up to 30 trading days; 1M: up to 12 months; data from 2026-04-01.",
  {
    data_type: z.array(z.enum(["NSE_FO|INDEX_FUTURES", "NSE_FO|STOCK_FUTURES", "NSE_FO|INDEX_OPTIONS", "NSE_FO|STOCK_OPTIONS", "NSE_EQ|CASH"])).min(1),
    interval: z.enum(["1D", "1M"]), from: YMD.optional(),
  },
  (a) => cachedGet(fiiDiiUrl("fii", a), "analytics"));

tool("get_dii_activity",
  "DII activity (GET /v2/market/dii), cash segment only. 1D: up to 30 trading days; 1M: up to 12 months.",
  { data_type: z.array(z.enum(["NSE_EQ|CASH"])).default(["NSE_EQ|CASH"]), interval: z.enum(["1D", "1M"]), from: YMD.optional() },
  (a) => cachedGet(fiiDiiUrl("dii", { ...a, data_type: a.data_type?.length ? a.data_type : ["NSE_EQ|CASH"] }), "analytics"));

tool("get_key_ratios",
  "Company key ratios vs sector (P/E, P/B, ROA, ROE, ROCE, EV/EBITDA) by ISIN (GET /v2/fundamentals/{isin}/key-ratios).",
  { isin: z.string().regex(/^[A-Z0-9]{12}$/, "12-character ISIN, e.g. INE002A01018") },
  ({ isin }) => cachedGet(`/v2/fundamentals/${enc(isin)}/key-ratios`, "fundamentals"));

// ── Token management tools ──
function tokenStatus() {
  loadTokensFromEnvFile();
  const exp = ACCESS_TOKEN ? getTokenExpiry() : null;
  const reqExp = Number(TOKEN_REQUEST_EXPIRY) || 0;
  return {
    token_set: !!ACCESS_TOKEN,
    token_preview: maskToken(ACCESS_TOKEN),
    expires_at: exp ? new Date(exp.ms).toISOString() : null,
    expires_at_ist: exp ? formatIst(exp.ms) : null,
    expiry_source: exp?.source ?? null,
    expired: ACCESS_TOKEN ? tokenIsExpired(0) : null,
    renew_strategy: RENEW_STRATEGY,
    totp_configured: TOTP_CONFIGURED, // secret and PIN are never exposed
    totp_consecutive_failures: Number(envState.UPSTOX_TOTP_FAILS) || 0,
    totp_auto_paused_until: Number(envState.UPSTOX_TOTP_BLOCKED_UNTIL) > Date.now() ? formatIst(Number(envState.UPSTOX_TOTP_BLOCKED_UNTIL)) : null,
    renew_lock_active: Number(envState.UPSTOX_RENEW_LOCK_UNTIL) > Date.now(),
    notifier_enabled: NOTIFIER_ENABLED,
    pending_request: reqExp > Date.now() ? { authorization_expiry: new Date(reqExp).toISOString(), authorization_expiry_ist: formatIst(reqExp) } : null,
    auth_port: AUTH_PORT,
    owns_auth_port: authPortOwned,
    notifier_path: NOTIFIER_PATH,
    scheduler: {
      enabled: AUTO_TOKEN_REQUEST,
      running: schedulerState.running,
      daily_time_ist: `${String(REQUEST_TIME.hour).padStart(2, "0")}:${String(REQUEST_TIME.minute).padStart(2, "0")}`,
      next_daily_at: schedulerState.nextDailyAt,
      last_check_at: schedulerState.lastCheckAt,
      last_result: schedulerState.lastResult,
      note: "Runs only in the process that owns the auth port.",
    },
  };
}

tool("get_token_status",
  "Token health: preview, expiry (ISO + IST), expired flag, renewal strategy, pending request, auth-port ownership, scheduler state. Never returns secrets.", {},
  async () => tokenStatus());

tool("renew_token",
  "Renew the access token now using the configured strategy: TOTP login (UPSTOX_TOTP_SECRET+UPSTOX_PIN) -> Access Token Request (UPSTOX_NOTIFIER_ENABLED=1) -> OAuth login URL. WARNING: TOTP login revokes the current token. force=true bypasses the 2-minute throttle and the 3-failure pause.",
  { force: z.boolean().optional() },
  ({ force }) => renewToken({ force: !!force }));

tool("request_access_token",
  "Send an Access Token Request (v3): you approve a notification in the Upstox app/WhatsApp, then Upstox POSTs the token to the Notifier Webhook (needs UPSTOX_NOTIFIER_ENABLED=1 and a registered public webhook URL). force=true resends even if one is pending.",
  { force: z.boolean().optional() },
  ({ force }) => requestAccessToken({ force: !!force }));

tool("logout",
  "Log out: DELETE /v2/logout (invalidates the access token) and clear it from .env. With auto-renewal enabled, the scheduler may obtain a new token shortly after.", {},
  async () => {
    const token = getLatestToken();
    if (!token) return { status: "no_token" };
    let api = "ok";
    try {
      await httpClient.delete(`${UPSTOX_BASE_URL}/v2/logout`, {
        headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
      });
    } catch (e) {
      api = `logout call failed: ${e.response?.data?.errors?.[0]?.message || e.message}`;
    }
    await updateEnvVars({ UPSTOX_ACCESS_TOKEN: "", UPSTOX_TOKEN_EXPIRES_AT: "", UPSTOX_TOKEN_SIG: "" });
    return { status: "logged_out", api, token_cleared_in_env: true };
  });

// ── Auth server lifecycle tools (lazy-start) ─────────────────────────

server.tool(
  "start_auth_server",
  `Start the embedded auth helper (OAuth /login + /callback, /status${NOTIFIER_ENABLED ? ", Notifier webhook" : ""}) on AUTH_PORT (currently ${AUTH_PORT}). Returns the login URL. Only one process sharing the .env can own the port; owns_port tells you whether this one does. Stays up until stop_auth_server or process exit.`,
  {},
  async () => {
    try {
      const inst = startAuthServer();
      const owns = await inst.ready;
      return ok({
        status: owns ? "running" : "port_in_use_by_another_process",
        owns_port: owns,
        auth_port: AUTH_PORT,
        login_url: inst.loginUrl,
        callback_url: inst.callbackUrl,
        started_at: inst.startedAt,
      });
    } catch (e) { return err(e.message); }
  }
);

server.tool(
  "stop_auth_server",
  `Stop the embedded auth helper in this process if it owns it, releasing AUTH_PORT (currently ${AUTH_PORT}) and stopping the token-renewal scheduler.`,
  {},
  async () => {
    const wasRunning = stopAuthServer();
    return ok({ status: wasRunning ? "stopped" : "not_running" });
  }
);

// ── Graceful shutdown ────────────────────────────────────────────────

let isShuttingDown = false;
function shutdown(signal) {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.error(`Received ${signal}, shutting down Upstox MCP...`);

  try { fs.unwatchFile(ENV_PATH); } catch (_) {}
  stopScheduler();

  const killTimer = setTimeout(() => process.exit(0), 3000);
  if (typeof killTimer.unref === "function") killTimer.unref();

  // Tear down auth server if it's up
  if (authServerInstance?.httpServer) {
    const { httpServer } = authServerInstance;
    authServerInstance = null;
    try {
      if (typeof httpServer.closeAllConnections === "function") httpServer.closeAllConnections();
    } catch (_) {}
    httpServer.close(() => {
      try { httpsAgent.destroy(); } catch (_) {}
      try { httpAgent.destroy(); } catch (_) {}
      process.exit(0);
    });
  } else {
    try { httpsAgent.destroy(); } catch (_) {}
    try { httpAgent.destroy(); } catch (_) {}
    process.exit(0);
  }
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGHUP", () => shutdown("SIGHUP"));

// Critical: when this process is launched via `docker exec -i`, the parent
// (the MCP client) disconnecting does NOT send a signal — it just closes
// stdin. Without these handlers the node process becomes a zombie inside
// the container, accumulating one per bot-side reconnection. Observed on
// 2026-05-15: 3,565 zombie processes / 9.7 GB RAM consumed by leaked
// node instances. Same leak pattern + fix as robinhood-mcp v1.3.1.
process.stdin.on("end", () => shutdown("stdin-end"));
process.stdin.on("close", () => shutdown("stdin-close"));
process.stdin.on("error", (err) => {
  console.error("stdin error:", err && err.message);
  shutdown("stdin-error");
});

process.on("uncaughtException", (err) => {
  console.error("Uncaught exception:", err);
  shutdown("uncaughtException");
});
process.on("unhandledRejection", (reason) => {
  console.error("Unhandled rejection:", reason);
});

// ── Main ─────────────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Upstox MCP Server v2.1.0 running on stdio");
  console.error(`Token: ${ACCESS_TOKEN ? maskToken(ACCESS_TOKEN) : "NOT SET"}`);
  console.error(`Token expiry: ${ACCESS_TOKEN ? formatIst(getTokenExpiryMs()) : "n/a"}; renewal strategy: ${RENEW_STRATEGY}; auto-renew: ${AUTO_TOKEN_REQUEST ? "on" : "off"}`);
  // Always start the auth server so /login is reachable as soon as the container boots.
  // If another process already owns the port (EADDRINUSE) the error is logged and ignored.
  startAuthServer();
  if (!ACCESS_TOKEN && !AUTO_TOKEN_REQUEST) {
    console.error(`⚠️  No tokens — login at http://localhost:${AUTH_PORT}/login`);
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
