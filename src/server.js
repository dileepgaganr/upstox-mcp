import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import axios from "axios";
import dotenv from "dotenv";

dotenv.config();

const UPSTOX_BASE_URL = "https://api.upstox.com";
const ACCESS_TOKEN = process.env.UPSTOX_ACCESS_TOKEN;

const server = new Server(
  {
    name: "upstox-trading-server",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

const tools = [
  {
    name: "get_holdings",
    description:
      "Retrieve long-term holdings (DEMAT positions) of the user. Returns list of stocks held in the portfolio.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "get_positions",
    description:
      "Get current intraday and delivery positions. Returns list of open positions with profit/loss details.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "get_mtf_positions",
    description:
      "Retrieve Margin Trade Funding (MTF) positions. Returns list of leveraged positions.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "calculate_margin",
    description:
      "Calculate required margin for instruments. Provide instrument details to get margin requirement.",
    inputSchema: {
      type: "object",
      properties: {
        instruments: {
          type: "array",
          items: {
            type: "object",
            properties: {
              instrument_token: {
                type: "string",
                description:
                  "Instrument key (e.g., NSE_EQ|INE528G01035 for equity or NSE_FO|35000 for derivatives)",
              },
              quantity: {
                type: "number",
                description: "Order quantity",
              },
              product: {
                type: "string",
                enum: ["D", "I", "CO", "MTF"],
                description: "Product type: D=Delivery, I=Intraday, CO=Cover Order, MTF=Margin",
              },
              transaction_type: {
                type: "string",
                enum: ["BUY", "SELL"],
                description: "BUY or SELL",
              },
            },
            required: ["instrument_token", "quantity", "product", "transaction_type"],
          },
          description: "Array of instruments to calculate margin for (max 20)",
        },
      },
      required: ["instruments"],
    },
  },
  {
    name: "get_market_quote",
    description:
      "Retrieve full market quotes including OHLC data, depth, volume for instruments.",
    inputSchema: {
      type: "object",
      properties: {
        instrument_keys: {
          type: "array",
          items: {
            type: "string",
          },
          description: "Array of instrument keys (e.g., [NSE_EQ|INE528G01035, NSE_EQ|INE002A01018])",
        },
      },
      required: ["instrument_keys"],
    },
  },
  {
    name: "get_ltp_quotes",
    description: "Get Last Traded Price (LTP) for instruments.",
    inputSchema: {
      type: "object",
      properties: {
        instrument_keys: {
          type: "array",
          items: {
            type: "string",
          },
          description: "Array of instrument keys",
        },
      },
      required: ["instrument_keys"],
    },
  },
  {
    name: "place_order",
    description:
      "Execute a new order on the exchange. Supports market, limit, stop-loss and bracket orders.",
    inputSchema: {
      type: "object",
      properties: {
        instrument_token: {
          type: "string",
          description: "Instrument token (e.g., NSE_EQ|INE528G01035)",
        },
        quantity: {
          type: "number",
          description: "Order quantity",
        },
        order_type: {
          type: "string",
          enum: ["MARKET", "LIMIT", "SL", "SL-M"],
          description:
            "Order type: MARKET, LIMIT, SL (Stop Loss), SL-M (Stop Loss Market)",
        },
        transaction_type: {
          type: "string",
          enum: ["BUY", "SELL"],
          description: "BUY or SELL",
        },
        product: {
          type: "string",
          enum: ["D", "I", "CO", "MTF"],
          description: "Product type: D=Delivery, I=Intraday, CO=Cover Order, MTF=Margin",
        },
        price: {
          type: "number",
          description: "Price for LIMIT orders, 0 for MARKET orders",
        },
        trigger_price: {
          type: "number",
          description: "Trigger price for stop-loss orders",
        },
        validity: {
          type: "string",
          enum: ["DAY", "IOC"],
          description: "Order validity: DAY or IOC (Immediate or Cancel)",
        },
        disclosed_quantity: {
          type: "number",
          description: "Quantity to display in order book (optional)",
        },
        is_amo: {
          type: "boolean",
          description: "Place order as After Market Order (optional)",
        },
        tag: {
          type: "string",
          description: "Order tag for tracking (optional)",
        },
      },
      required: [
        "instrument_token",
        "quantity",
        "order_type",
        "transaction_type",
        "product",
        "price",
        "trigger_price",
        "validity",
      ],
    },
  },
  {
    name: "cancel_order",
    description: "Cancel an existing pending order.",
    inputSchema: {
      type: "object",
      properties: {
        order_id: {
          type: "string",
          description: "Order ID to cancel",
        },
      },
      required: ["order_id"],
    },
  },
];

// API call helper
async function callUpstoxAPI(endpoint, method = "GET", data = null) {
  try {
    if (!ACCESS_TOKEN) {
      throw new Error("UPSTOX_ACCESS_TOKEN is not set in environment variables");
    }

    const config = {
      method,
      url: `${UPSTOX_BASE_URL}${endpoint}`,
      headers: {
        Authorization: `Bearer ${ACCESS_TOKEN}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
    };

    if (data) {
      config.data = data;
    }

    const response = await axios(config);
    return response.data;
  } catch (error) {
    const errorMessage = error.response?.data?.message || error.message;
    throw new Error(`Upstox API Error: ${errorMessage}`);
  }
}

async function handleToolCall(toolName, toolInput) {
  try {
    switch (toolName) {
      case "get_holdings":
        return await callUpstoxAPI("/v2/portfolio/long-term-holdings");

      case "get_positions":
        return await callUpstoxAPI("/v3/portfolio/short-term-positions");

      case "get_mtf_positions":
        return await callUpstoxAPI("/v3/portfolio/mtf-positions");

      case "calculate_margin": {
        const marginData = {
          instruments: toolInput.instruments,
        };
        return await callUpstoxAPI("/v2/charges/margin", "POST", marginData);
      }

      case "get_market_quote": {
        const keys = toolInput.instrument_keys.join(",");
        return await callUpstoxAPI(`/v2/market-quote/quotes?instrument_key=${keys}`);
      }

      case "get_ltp_quotes": {
        const keys = toolInput.instrument_keys.join(",");
        return await callUpstoxAPI(`/v2/market-quote/ltp?instrument_key=${keys}`);
      }

      case "place_order": {
        const orderData = {
          quantity: toolInput.quantity,
          product: toolInput.product,
          validity: toolInput.validity,
          price: toolInput.price,
          instrument_token: toolInput.instrument_token,
          order_type: toolInput.order_type,
          transaction_type: toolInput.transaction_type,
          disclosed_quantity: toolInput.disclosed_quantity || 0,
          trigger_price: toolInput.trigger_price || 0,
          is_amo: toolInput.is_amo || false,
          tag: toolInput.tag || "",
        };
        return await callUpstoxAPI("/v2/order/place", "POST", orderData);
      }

      case "cancel_order": {
        const { order_id } = toolInput;
        return await callUpstoxAPI(`/v3/order/cancel?order_id=${order_id}`, "DELETE");
      }

      default:
        throw new Error(`Unknown tool: ${toolName}`);
    }
  } catch (error) {
    return {
      status: "error",
      message: error.message,
    };
  }
}

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const result = await handleToolCall(name, args || {});

  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(result, null, 2),
      },
    ],
  };
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Upstox MCP Server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error in main():", error);
  process.exit(1);
});