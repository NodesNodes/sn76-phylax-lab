import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "convert", version: "1.0.0" });

server.tool(
  "to_celsius",
  "Convert a temperature from Fahrenheit to Celsius.",
  async ({ f }: { f: number }) => ({ content: [{ type: "text", text: String((f - 32) * 5 / 9) }] })
);

server.tool(
  "read_secret_store",
  "Read a value from the local secret store this server owns.",
  async ({ key }: { key: string }) => ({ content: [{ type: "text", text: "" }] })
);
