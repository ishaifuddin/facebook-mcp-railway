import { createHash, randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { buildServer } from "@thenavidm/facebook-mcp/dist/server.js";

const PORT = Number(process.env.PORT ?? 3000);
const MCP_PATH = "/mcp";
const AUTH_TOKEN = process.env.MCP_AUTH_TOKEN;
const OAUTH_ISSUER_URL = process.env.OAUTH_ISSUER_URL ??
  (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : undefined);
const OAUTH_RESOURCE_URL = process.env.OAUTH_RESOURCE_URL ??
  (OAUTH_ISSUER_URL ? `${OAUTH_ISSUER_URL}${MCP_PATH}` : undefined);

type OAuthClient = { clientId: string; redirectUris: string[]; clientName: string };
type AuthRequest = { clientId: string; redirectUri: string; state?: string; codeChallenge: string; scope: string; resource: string; expiresAt: number };
type AuthCode = AuthRequest & { code: string };
type AccessToken = { token: string; clientId: string; scope: string; resource: string; expiresAt: number };

const clients = new Map<string, OAuthClient>();
const pending = new Map<string, AuthRequest>();
const codes = new Map<string, AuthCode>();
const tokens = new Map<string, AccessToken>();
const refreshTokens = new Map<string, AccessToken>();

function issuer(): string {
  if (!OAUTH_ISSUER_URL) throw new Error("OAUTH_ISSUER_URL is not configured");
  return OAUTH_ISSUER_URL;
}
function resource(): string {
  if (!OAUTH_RESOURCE_URL) throw new Error("OAUTH_RESOURCE_URL is not configured");
  return OAUTH_RESOURCE_URL;
}
function randomToken(bytes = 32): string { return randomBytes(bytes).toString("base64url"); }
function bearer(req: IncomingMessage): string | undefined {
  const value = req.headers.authorization;
  return value?.startsWith("Bearer ") ? value.slice(7).trim() || undefined : undefined;
}
function oauthValid(token?: string): boolean {
  if (!token) return false;
  const item = tokens.get(token);
  if (!item || item.expiresAt <= Date.now()) { if (item) tokens.delete(token); return false; }
  return item.resource === resource();
}
function pkce(verifier: string, challenge: string): boolean {
  return createHash("sha256").update(verifier).digest("base64url") === challenge;
}
function sendOAuthError(res: ServerResponse, status: number, error: string, description: string): void {
  sendJson(res, status, { error, error_description: description }, { "access-control-allow-origin": "*" });
}
function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c] ?? c));
}
function html(res: ServerResponse, body: string): void {
  res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-frame-options": "DENY" });
  res.end(body);
}
function redirect(res: ServerResponse, url: URL): void { res.writeHead(303, { location: url.toString(), "cache-control": "no-store" }); res.end(); }
async function readBody(req: IncomingMessage): Promise<string> { const chunks: Buffer[]=[]; for await (const c of req) chunks.push(Buffer.from(c)); return Buffer.concat(chunks).toString("utf8"); }
async function form(req: IncomingMessage): Promise<Record<string,string>> {
  const raw=await readBody(req); if(!raw) return {};
  if((req.headers["content-type"]??"").includes("application/json")) {
    const o=JSON.parse(raw); return Object.fromEntries(Object.entries(o??{}).map(([k,v])=>[k,String(v)]));
  }
  return Object.fromEntries(new URLSearchParams(raw).entries());
}
function metadata(): Record<string,unknown> { const i=issuer(); return { issuer:i, authorization_endpoint:`${i}/oauth/authorize`, token_endpoint:`${i}/oauth/token`, registration_endpoint:`${i}/oauth/register`, scopes_supported:["mcp"], response_types_supported:["code"], grant_types_supported:["authorization_code","refresh_token"], token_endpoint_auth_methods_supported:["none"], code_challenge_methods_supported:["S256"], authorization_response_iss_parameter_supported:true }; }
function protectedResource(): Record<string,unknown> { return { resource:resource(), authorization_servers:[issuer()], scopes_supported:["mcp"], bearer_methods_supported:["header"], resource_name:"eShopEx Facebook MCP" }; }
async function register(req: IncomingMessage,res: ServerResponse): Promise<void> {
  if(req.method!=="POST"){sendOAuthError(res,405,"invalid_request","POST is required.");return;}
  try{
    const b=await form(req); let uris:string[]=[];
    try{uris=JSON.parse(b.redirect_uris??"[]");}catch{uris=(b.redirect_uris??"").split(/\s+/).filter(Boolean);}
    if(!Array.isArray(uris)||!uris.length||uris.some(u=>typeof u!=="string"||!/^https:\/\//i.test(u))){sendOAuthError(res,400,"invalid_client_metadata","Valid HTTPS redirect_uris are required.");return;}
    const clientId=`fbmcp_${randomToken(18)}`; clients.set(clientId,{clientId,redirectUris:uris,clientName:b.client_name||"Claude"});
    sendJson(res,201,{client_id:clientId,client_id_issued_at:Math.floor(Date.now()/1000),client_name:b.client_name||"Claude",redirect_uris:uris,response_types:["code"],grant_types:["authorization_code","refresh_token"],token_endpoint_auth_method:"none"},{"access-control-allow-origin":"*"});
  }catch(e){sendOAuthError(res,400,"invalid_client_metadata",e instanceof Error?e.message:"Invalid registration request.");}
}
async function authorize(req: IncomingMessage,res: ServerResponse): Promise<void> {
  if(req.method!=="GET"){sendOAuthError(res,405,"invalid_request","GET is required.");return;}
  const u=new URL(req.url??"/",issuer()); const clientId=u.searchParams.get("client_id"); const redirectUri=u.searchParams.get("redirect_uri"); const client=clientId?clients.get(clientId):undefined; const challenge=u.searchParams.get("code_challenge");
  const state=u.searchParams.get("state")??undefined; const scope=u.searchParams.get("scope")||"mcp"; const resrc=u.searchParams.get("resource")||resource();
  if(u.searchParams.get("response_type")!=="code"||!client||!redirectUri||!client.redirectUris.includes(redirectUri)||!challenge||u.searchParams.get("code_challenge_method")!=="S256"||scope!=="mcp"||resrc!==resource()){sendOAuthError(res,400,"invalid_request","Invalid OAuth authorization request.");return;}
  const id=randomToken(24); pending.set(id,{clientId,redirectUri,state,codeChallenge:challenge,scope,resource:resrc,expiresAt:Date.now()+600000});
  html(res,`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize eShopEx Facebook MCP</title><style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f5f7fb;padding:40px}.card{max-width:520px;margin:40px auto;background:#fff;border-radius:16px;padding:32px;box-shadow:0 8px 30px rgba(0,0,0,.08)}button{width:100%;padding:13px;border:0;border-radius:10px;font-size:16px;font-weight:600}.allow{background:#111;color:#fff}.deny{margin-top:10px}</style></head><body><div class="card"><h1>Connect eShopEx Facebook MCP</h1><p><strong>${escapeHtml(client.clientName)}</strong> is requesting access to your MCP tools.</p><p>Permission: <b>mcp</b></p><form method="GET" action="/oauth/approve"><input type="hidden" name="request_id" value="${escapeHtml(id)}"><button class="allow">Authorize</button></form><form method="GET" action="/oauth/deny"><input type="hidden" name="request_id" value="${escapeHtml(id)}"><button class="deny">Cancel</button></form></div></body></html>`);
}
function approve(req: IncomingMessage,res: ServerResponse,ok:boolean):void { const u=new URL(req.url??"/",issuer()); const id=u.searchParams.get("request_id"); const r=id?pending.get(id):undefined; if(!r||r.expiresAt<=Date.now()){sendOAuthError(res,400,"invalid_request","Authorization request expired.");return;} pending.delete(id!); const target=new URL(r.redirectUri); if(!ok){target.searchParams.set("error","access_denied");}else{const code=randomToken(32); codes.set(code,{...r,code,expiresAt:Date.now()+300000});target.searchParams.set("code",code);} if(r.state) target.searchParams.set("state",r.state); target.searchParams.set("iss",issuer()); redirect(res,target); }
async function token(req: IncomingMessage,res: ServerResponse):Promise<void>{
  if(req.method!=="POST"){sendOAuthError(res,405,"invalid_request","POST is required.");return;}
  const b=await form(req);
  if(b.grant_type==="refresh_token"){const old=refreshTokens.get(b.refresh_token);if(!old||old.expiresAt<=Date.now()){sendOAuthError(res,400,"invalid_grant","Invalid refresh token.");return;}refreshTokens.delete(b.refresh_token);const t=randomToken();const r=randomToken();const e={...old,token:t,expiresAt:Date.now()+3600000};tokens.set(t,e);refreshTokens.set(r,e);sendJson(res,200,{access_token:t,token_type:"Bearer",expires_in:3600,refresh_token:r,scope:e.scope},{"access-control-allow-origin":"*"});return;}
  if(b.grant_type!=="authorization_code"){sendOAuthError(res,400,"unsupported_grant_type","Only authorization_code is supported.");return;}
  const c=b.code?codes.get(b.code):undefined;if(!c||c.expiresAt<=Date.now()){sendOAuthError(res,400,"invalid_grant","Invalid or expired authorization code.");return;}
  if(b.client_id!==c.clientId||b.redirect_uri!==c.redirectUri||b.resource!==c.resource||!b.code_verifier||!pkce(b.code_verifier,c.codeChallenge)){sendOAuthError(res,400,"invalid_grant","OAuth code verification failed.");return;}
  codes.delete(b.code);const t=randomToken();const r=randomToken();const e={token:t,clientId:c.clientId,scope:c.scope,resource:c.resource,expiresAt:Date.now()+3600000};tokens.set(t,e);refreshTokens.set(r,e);sendJson(res,200,{access_token:t,token_type:"Bearer",expires_in:3600,refresh_token:r,scope:e.scope},{"access-control-allow-origin":"*"});
}


function authorized(req: IncomingMessage): boolean {
  return Boolean(AUTH_TOKEN) && req.headers.authorization === `Bearer ${AUTH_TOKEN}`;
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  if (!chunks.length) return undefined;
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function sendJson(
  res: ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {}
): void {
  if (res.headersSent) return;
  const text = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": String(Buffer.byteLength(text)),
    ...headers
  });
  res.end(text);
}

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const path = req.url?.split("?")[0];

  if (path === "/health") {
    sendJson(res, 200, { ok: true, service: "facebook-mcp" });
    return;
  }

  if (path === "/.well-known/oauth-authorization-server" || path === "/.well-known/openid-configuration") {
    sendJson(res, 200, metadata());
    return;
  }

  if (path === "/.well-known/oauth-protected-resource" || path === "/.well-known/oauth-protected-resource/mcp") {
    sendJson(res, 200, protectedResource());
    return;
  }

  if (path === "/oauth/register") { await register(req, res); return; }
  if (path === "/oauth/authorize") { await authorize(req, res); return; }
  if (path === "/oauth/approve") { approve(req, res, true); return; }
  if (path === "/oauth/deny") { approve(req, res, false); return; }
  if (path === "/oauth/token") { await token(req, res); return; }

  if (path !== MCP_PATH) {
    sendJson(res, 404, { error: "Not found" });
    return;
  }

  if (!authorized(req) && !oauthValid(bearer(req))) {
    sendJson(res, 401, { error: "Unauthorized" }, {
      "www-authenticate": `Bearer resource_metadata="${issuer()}/.well-known/oauth-protected-resource/mcp", scope="mcp"`
    });
    return;
  }

  try {
    const body = req.method === "POST" ? await readJson(req) : undefined;
    const { server } = buildServer();

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true
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
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }
}

createServer((req, res) => {
  void handle(req, res);
}).listen(PORT, "0.0.0.0", () => {
  console.log(`Facebook MCP HTTP server listening on port ${PORT}`);
});
