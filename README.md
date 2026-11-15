# Quick Start Guide - Upstox MCP Server

### Step 1: Get Upstox API Credentials
1. Visit https://upstox.com/developer/
2. Create/login to your account
3. Generate API Key and API Secret
4. Set Redirect URI: `http://localhost:3000/callback`

### Step 2: Clone/Create Project


## Note Edit `.env` with your credentials:


### Step 3: Run with Docker 

docker-compose up

 Note: Replace the environment variable values in the docker-compose.yml

## References
- MCP Protocol and Server concepts
- Integration with Perplexity and other LLM APIs
- Portfolio rebalancing strategies with AI inference
- Perplexity Local MCP integration

## Architecture

- **Node.js MCP Server**: Implements MCP Protocol for communication.
- **LLM Integration Module**: Handles calls to external LLMs such as Perplexity for inference.
- **Docker Container**: Provides isolated, reproducible run environment.

## Development

### Running Locally
1. Install dependencies:
    
    npm install

2. Start the application:

    npm run start / dev

### Testing
Run tests with:

    npx @modelcontextprotocol/inspector node dist/server.js

# Connecting a Locally Running MCP to Perplexity

###  Configure Perplexity to Connect to MCP
1. Go to below path
    Settings -> Connectors -> + Add Connector
2. Provide a Name "Robinhood" so your LLM targets the mcp 
3. Under advanced tab  
    ### Copy paste the perplexity.config.json content in Advanced tab in connectors 
    ### Update your Perplexity environment variables to point to your MCP instance
4. Save and exit. You should be able to see your MCP showing runnng with number of tools.

###  Start Using and happy trading 

Once connected, you can use Perplexity to send commands and queries to your local MCP seamlessly. and you should be able to see the mcp under sources

# Note: Replace the environment variable values in perplexity.config.json

# Daily token renewal

Upstox access tokens expire every day at 03:30 IST and the OAuth flow returns no refresh token, so the server renews the token itself. Strategy order (`renew_token` tool / scheduler / 401 recovery):

1. **TOTP login (recommended, fully local, no public URL).**
   - In Upstox account security settings, enable TOTP and **save the base32 key** shown during setup. If you didn't save it, reset TOTP to see a new key.
   - Set `UPSTOX_TOTP_SECRET=<base32 key>` and `UPSTOX_PIN=<6-digit PIN>` in `.env`.
   - **Warning:** `.env` then holds everything needed to log in to your account (API key/secret, TOTP key, PIN). `chmod 600 .env` and never commit it. The values are never logged or returned by any tool.
   - TOTP login revokes the currently active token, so it only runs when the token is missing, expired or rejected. Limits: at most one auto attempt per 2 minutes, and auto attempts pause after 3 consecutive failures until the next IST day (or a manual `renew_token` with `force=true`). A `.env` lock (`UPSTOX_RENEW_LOCK_UNTIL`) keeps parallel `docker exec` processes from logging in simultaneously.
2. **Access Token Request + Notifier webhook (optional, `UPSTOX_NOTIFIER_ENABLED=1`).** Upstox sends an approval prompt to the Upstox app/WhatsApp; after you approve, it POSTs the token to your registered Notifier Webhook URL. That URL must be public HTTPS reaching container port 9082 at `/notifier/<UPSTOX_NOTIFIER_SECRET>` (a Cloudflare Tunnel on a stable domain works; Upstox blocks dynamic-DNS and proxy domains). Tools: `request_access_token`.
3. **OAuth login** at `http://localhost:9082/login` (manual fallback).

The scheduler (checks every 5 min, plus a daily run at `UPSTOX_TOKEN_REQUEST_TIME_IST`) runs only in the process that owns the auth port. Other tools: `get_token_status`, `logout`.

| Env var | Default | Purpose |
|---|---|---|
| `UPSTOX_TOTP_SECRET`, `UPSTOX_PIN` | unset | Enable TOTP login |
| `UPSTOX_NOTIFIER_ENABLED` | `0` | Enable Access Token Request path + `/notifier` route |
| `UPSTOX_NOTIFIER_SECRET` | unset | If set, webhook is served only at `/notifier/<secret>` |
| `UPSTOX_AUTO_TOKEN_REQUEST` | on | `0` disables the scheduler |
| `UPSTOX_TOKEN_REQUEST_TIME_IST` | `08:00` | Daily renewal check time (skips if token has >12h left) |
| `UPSTOX_TOKEN_REQUEST_COOLDOWN_MIN` | `30` | Dedupe window for Access Token Requests |
| `UPSTOX_ENV_PATH` | `../.env` | Alternate env file (testing) |
| `UPSTOX_BASE_URL` | `https://api.upstox.com` | API base override (testing) |
| `AUTH_PORT` | `9080` | Auth/notifier server port |

State written to `.env` by the server: `UPSTOX_ACCESS_TOKEN`, `UPSTOX_TOKEN_EXPIRES_AT`, `UPSTOX_TOKEN_SIG`, plus bookkeeping (`UPSTOX_RENEW_LOCK_UNTIL`, `UPSTOX_TOTP_*`, `UPSTOX_TOKEN_REQUEST*`).
