import express from "express";
import axios from "axios";
import dotenv from "dotenv";
import crypto from "crypto";

dotenv.config();

const app = express();
const PORT = process.env.AUTH_PORT || 3000;

// Upstox OAuth endpoints
const UPSTOX_AUTH_URL = "https://api.upstox.com/v2/login/authorization/login";
const UPSTOX_TOKEN_URL = "https://api.upstox.com/v2/login/authorization/token";

// Configuration from environment
const API_KEY = process.env.UPSTOX_API_KEY;
const API_SECRET = process.env.UPSTOX_API_SECRET;
const REDIRECT_URI = process.env.UPSTOX_REDIRECT_URI || "http://localhost:3000/callback";

// Store session state
const sessions = new Map();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Root endpoint
app.get("/", (req, res) => {
  res.json({
    status: "running",
    message: "Upstox OAuth 2.0 Authentication Server",
    endpoints: {
      login: "/login",
      callback: "/callback",
      token: "/token",
      status: "/status",
      docs: "/docs"
    }
  });
});

// Documentation endpoint
app.get("/docs", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Upstox OAuth Authentication</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .endpoint { background: #f0f0f0; padding: 15px; margin: 10px 0; border-radius: 5px; }
        code { background: #e0e0e0; padding: 5px 10px; border-radius: 3px; }
        pre { background: #333; color: #0f0; padding: 15px; border-radius: 5px; overflow-x: auto; }
        h2 { color: #333; }
      </style>
    </head>
    <body>
      <h1>Upstox OAuth 2.0 Authentication Server</h1>
      
      <h2>Setup</h2>
      <p>Create a .env file with:</p>
      <pre>
UPSTOX_API_KEY=your_api_key
UPSTOX_API_SECRET=your_api_secret
UPSTOX_REDIRECT_URI=http://localhost:3001/callback
AUTH_PORT=3001
      </pre>

      <h2>Authentication Flow</h2>
      
      <div class="endpoint">
        <h3>1. Start Login</h3>
        <p><strong>GET</strong> <code>/login</code></p>
        <p>Redirects you to Upstox login page</p>
      </div>

      <div class="endpoint">
        <h3>2. Callback (Automatic)</h3>
        <p><strong>GET</strong> <code>/callback?code=AUTH_CODE&state=STATE</code></p>
        <p>Handles the OAuth callback from Upstox</p>
      </div>

      <div class="endpoint">
        <h3>3. Get Token</h3>
        <p><strong>POST</strong> <code>/token</code></p>
        <p>Exchange authorization code for access token</p>
        <pre>
{
  "code": "your_auth_code"
}
        </pre>
      </div>

      <h2>Quick Start</h2>
      <ol>
        <li>Click: <a href="/login" style="color: blue; font-weight: bold;">Start Authentication</a></li>
        <li>Login to Upstox</li>
        <li>Authorize the application</li>
        <li>Your token will be displayed on screen</li>
        <li>Copy the token to your .env file</li>
      </ol>

      <h2>Manual Token Exchange</h2>
      <pre>
curl -X POST http://localhost:3001/token \\
  -H "Content-Type: application/json" \\
  -d '{"code": "your_auth_code"}'
      </pre>

      <h2>Check Session Status</h2>
      <pre>
curl http://localhost:3001/status
      </pre>
    </body>
    </html>
  `);
});

// Step 1: Generate login URL and redirect to Upstox
app.get("/login", (req, res) => {
  try {
    // Generate random state for CSRF protection
    const state = crypto.randomBytes(16).toString("hex");
    
    // Store state in session
    sessions.set(state, { timestamp: Date.now() });

    // Build authorization URL
    const params = new URLSearchParams({
      client_id: API_KEY,
      redirect_uri: REDIRECT_URI,
      response_type: "code",
      state: state
    });

    const authUrl = `${UPSTOX_AUTH_URL}?${params.toString()}`;

    console.log("ðŸ” Generated login URL");
    console.log(`State: ${state}`);

    res.redirect(authUrl);
  } catch (error) {
    console.error("âŒ Error in login:", error.message);
    res.status(500).json({
      error: "Login failed",
      message: error.message
    });
  }
});

// Step 2: Handle OAuth callback from Upstox
app.get("/callback", (req, res) => {
  try {
    const { code, state } = req.query;

    if (!code || !state) {
      return res.status(400).json({
        error: "Missing authorization code or state",
        received: { code: !!code, state: !!state }
      });
    }

    // Verify state matches (CSRF protection)
    if (!sessions.has(state)) {
      return res.status(401).json({
        error: "Invalid state - possible CSRF attack",
        state: state
      });
    }

    console.log("âœ… Authorization code received");
    console.log(`Code: ${code}`);
    console.log(`State: ${state}`);

    // Store code in session
    const sessionData = sessions.get(state) || {};
    sessionData.code = code;
    sessionData.codeTimestamp = Date.now();
    sessions.set(state, sessionData);

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Authorization Successful</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
          .success { color: green; font-size: 24px; margin: 20px 0; }
          .code-box { 
            background: #f0f0f0; 
            padding: 20px; 
            margin: 20px 0; 
            border-radius: 5px;
            text-align: left;
            word-break: break-all;
          }
          button { 
            background: #4CAF50; 
            color: white; 
            padding: 10px 20px; 
            border: none; 
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            margin: 10px;
          }
          button:hover { background: #45a049; }
          .next-step { margin-top: 30px; }
        </style>
      </head>
      <body>
        <h1>âœ… Authorization Successful!</h1>
        
        <p class="success">Authorization code received</p>
        
        <div class="code-box">
          <strong>Authorization Code:</strong><br><br>
          <code>${code}</code>
        </div>

        <div class="next-step">
          <h2>Next Steps:</h2>
          <p>Getting your access token...</p>
          <button onclick="getToken()">Get Access Token</button>
          <button onclick="copyCode()">Copy Code</button>
        </div>

        <div id="token-result"></div>

        <script>
          function copyCode() {
            const code = '${code}';
            navigator.clipboard.writeText(code).then(() => {
              alert('Authorization code copied to clipboard!');
            });
          }

          function getToken() {
            const code = '${code}';
            const resultDiv = document.getElementById('token-result');
            resultDiv.innerHTML = '<p>Getting token...</p>';

            fetch('http://localhost:3001/token', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ code: code })
            })
            .then(response => response.json())
            .then(data => {
              if (data.access_token) {
                resultDiv.innerHTML = \`
                  <div style="background: #e8f5e9; padding: 20px; border-radius: 5px; margin-top: 20px;">
                    <h3 style="color: green;">âœ… Token Generated!</h3>
                    <div style="background: white; padding: 15px; border-radius: 3px; margin: 10px 0;">
                      <strong>Access Token:</strong><br>
                      <code>\${data.access_token}</code>
                      <button onclick="copyToken()">Copy</button>
                    </div>
                    <div style="background: white; padding: 15px; border-radius: 3px; margin: 10px 0;">
                      <strong>Token Type:</strong> \${data.token_type}<br>
                      <strong>Expires In:</strong> \${data.expires_in} seconds
                    </div>
                    <p style="color: #666; font-size: 12px;">
                      Add this to your .env file as UPSTOX_ACCESS_TOKEN
                    </p>
                  </div>
                \`;
              } else {
                resultDiv.innerHTML = \`<p style="color: red;">Error: \${data.error || 'Unknown error'}</p>\`;
              }
            })
            .catch(error => {
              resultDiv.innerHTML = \`<p style="color: red;">Error: \${error.message}</p>\`;
            });
          }

          function copyToken() {
            const token = '${code}';
            fetch('http://localhost:3001/token', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ code: token })
            })
            .then(response => response.json())
            .then(data => {
              navigator.clipboard.writeText(data.access_token).then(() => {
                alert('Access token copied to clipboard!');
              });
            });
          }
        </script>
      </body>
      </html>
    `);
  } catch (error) {
    console.error("âŒ Error in callback:", error.message);
    res.status(500).json({
      error: "Callback processing failed",
      message: error.message
    });
  }
});

// Step 3: Exchange authorization code for access token
app.post("/token", async (req, res) => {
  try {
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({
        error: "Authorization code is required",
        hint: "Provide code in request body"
      });
    }

    console.log("ðŸ”„ Exchanging authorization code for access token...");

    // Exchange code for token
    const response = await axios.post(UPSTOX_TOKEN_URL, null, {
      params: {
        code: code,
        client_id: API_KEY,
        client_secret: API_SECRET,
        redirect_uri: REDIRECT_URI,
        grant_type: "authorization_code"
      },
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      }
    });

    const tokenData = response.data;

    console.log("âœ… Token exchange successful!");
    console.log(`Access Token: ${tokenData.access_token.substring(0, 20)}...`);
    console.log(`Expires In: ${tokenData.expires_in} seconds`);

    res.json({
      status: "success",
      access_token: tokenData.access_token,
      token_type: tokenData.token_type,
      expires_in: tokenData.expires_in,
      refresh_token: tokenData.refresh_token,
      message: "Add UPSTOX_ACCESS_TOKEN to your .env file"
    });
  } catch (error) {
    console.error("âŒ Token exchange error:", error.response?.data || error.message);
    res.status(error.response?.status || 500).json({
      error: "Token exchange failed",
      message: error.response?.data?.message || error.message,
      details: error.response?.data
    });
  }
});

// Refresh access token
app.post("/refresh-token", async (req, res) => {
  try {
    const { refresh_token } = req.body;

    if (!refresh_token) {
      return res.status(400).json({
        error: "Refresh token is required"
      });
    }

    console.log("ðŸ”„ Refreshing access token...");

    const response = await axios.post(UPSTOX_TOKEN_URL, null, {
      params: {
        refresh_token: refresh_token,
        client_id: API_KEY,
        client_secret: API_SECRET,
        grant_type: "refresh_token"
      },
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      }
    });

    const tokenData = response.data;

    console.log("âœ… Token refreshed successfully!");

    res.json({
      status: "success",
      access_token: tokenData.access_token,
      token_type: tokenData.token_type,
      expires_in: tokenData.expires_in
    });
  } catch (error) {
    console.error("âŒ Token refresh error:", error.response?.data || error.message);
    res.status(error.response?.status || 500).json({
      error: "Token refresh failed",
      message: error.response?.data?.message || error.message
    });
  }
});

// Get current session status
app.get("/status", (req, res) => {
  const sessionCount = sessions.size;
  const now = Date.now();
  let activeSession = null;

  for (const [state, data] of sessions) {
    const age = (now - data.timestamp) / 1000;
    if (age < 3600) { // Sessions active for less than 1 hour
      activeSession = {
        state: state.substring(0, 8) + "...",
        hasCode: !!data.code,
        age: `${Math.round(age)}s ago`,
        timestamp: new Date(data.timestamp).toISOString()
      };
      break;
    }
  }

  res.json({
    status: "running",
    server: {
      port: PORT,
      upstoxApiKey: API_KEY ? API_KEY.substring(0, 10) + "..." : "NOT SET",
      redirectUri: REDIRECT_URI
    },
    sessions: {
      total: sessionCount,
      active: activeSession || "None"
    },
    timestamp: new Date().toISOString()
  });
});

// Health check
app.get("/health", (req, res) => {
  res.json({
    status: "healthy",
    timestamp: new Date().toISOString()
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("âŒ Unhandled error:", err.message);
  res.status(500).json({
    error: "Internal server error",
    message: err.message
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: "Endpoint not found",
    path: req.path,
    availableEndpoints: ["/", "/login", "/callback", "/token", "/refresh-token", "/status", "/health", "/docs"]
  });
});

// Start server
app.listen(PORT, () => {
  console.log("\n" + "=".repeat(60));
  console.log("ðŸš€ Upstox OAuth 2.0 Authentication Server");
  console.log("=".repeat(60));
  console.log(`ðŸ“ Server running on: http://localhost:${PORT}`);
  console.log(`ðŸ“– Documentation: http://localhost:${PORT}/docs`);
  console.log(`ðŸ” Start auth: http://localhost:${PORT}/login`);
  console.log("=".repeat(60) + "\n");

  // Verify environment variables
  if (!API_KEY || !API_SECRET) {
    console.warn("âš ï¸  WARNING: UPSTOX_API_KEY or UPSTOX_API_SECRET not set in .env");
  }
});

export default app;