import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { buildServer } from "@thenavidm/facebook-mcp/dist/server.js";

const PORT = Number(process.env.PORT ?? 3000);
const MCP_PATH = "/mcp";
const AUTH_TOKEN = process.env.MCP_AUTH_TOKEN;

function authorized(req: IncomingMessage): boolean {
  if (!AUTH_TOKEN) return false;
  return req.headers.authorization === `Bearer ${AUTH_TOKEN}`;
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.from(chunk));
  }

  if (!chunks.length) return undefined;
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  if (res.headersSent) return;

  const text = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(text),
  });
  res.end(text);
}

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const path = req.url?.split("?")[0];

  if (path === "/health") {
    sendJson(res, 200, {
      ok: true,
      service: "facebook-mcp",
    });
    return;
  }

  if (path !== MCP_PATH) {
    sendJson(res, 404, { error: "Not found" });
    return;
  }

  if (!authorized(req)) {
    sendJson(res, 401, { error: "Unauthorized" });
    return;
  }

  try {
    const body = req.method === "POST" ? await readJson(req) : undefined;

    // Stateless transport: every MCP request gets an isolated server/transport.
    // The Facebook MCP itself has no conversational state; Facebook state lives
    // in Meta and the configured Page credentials.
    const { server } = buildServer();

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });

    res.on("close", () => {
      void transport.close();
      void server.close();
    });

    await server.connect(transport);
    await transport.handleRequest(req, res, body);
  } catch (error) {
    console.error("MCP request error:", error);

    if (!res.headersSent) {
      sendJson(res, 500, {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
}

createServer((req, res) => {
  void handle(req, res);
}).listen(PORT, "0.0.0.0", () => {
  console.log(`Facebook MCP HTTP server listening on port ${PORT}`);
});
