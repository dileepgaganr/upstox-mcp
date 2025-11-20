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
