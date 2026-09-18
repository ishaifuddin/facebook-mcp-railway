# Facebook MCP Railway

Remote Streamable HTTP wrapper for `@thenavidm/facebook-mcp`.

## Railway Variables

Set these in Railway. Never commit secrets to GitHub.

- `FACEBOOK_PAGE_ID`
- `FACEBOOK_PAGE_TOKEN`
- `FACEBOOK_PAGE_NAME=eShopEx`
- `FACEBOOK_ALLOW_WRITE=true`
- `FACEBOOK_PREFERRED_PAGES=eShopEx`
- `MCP_AUTH_TOKEN`

The MCP endpoint is `/mcp` and requires `Authorization: Bearer <MCP_AUTH_TOKEN>`.

`GET /health` is available for a basic health check.
