# Facebook MCP Railway

Remote Streamable HTTP wrapper for `@thenavidm/facebook-mcp`.

This keeps the original Facebook MCP tools and exposes them through an HTTPS `/mcp` endpoint suitable for a remote MCP client.

## Railway environment variables

Set these as Railway Variables. Do **not** put secrets in GitHub.

### Facebook

- `FACEBOOK_PAGE_ID` — your eShopEx Page ID
- `FACEBOOK_PAGE_TOKEN` — your current long-lived Page access token
- `FACEBOOK_PAGE_NAME` — `eShopEx`
- `FACEBOOK_ALLOW_WRITE` — `true`
- `FACEBOOK_PREFERRED_PAGES` — `eShopEx`

### MCP authentication

- `MCP_AUTH_TOKEN` — a long random secret used to protect `/mcp`

The service reads Facebook credentials from environment variables, so no `~/.facebook-mcp/pages.json` file is required on Railway.

## Endpoints

- `GET /health` — public health check
- `/mcp` — authenticated Streamable HTTP MCP endpoint

The MCP endpoint requires:

`Authorization: Bearer YOUR_MCP_AUTH_TOKEN`

## Important

Never commit:

- Facebook Page access tokens
- Meta App secrets
- MCP authentication tokens
- `.env` files

The Facebook MCP package is maintained separately at:
https://github.com/thenavidm/facebook-mcp
