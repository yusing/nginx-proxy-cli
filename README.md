# nginx-proxy-cli
Manipulate reversed proxies in command line

Available commands:
-  list-user: List all users (no args)
-  list-cert: List all certificates (no args)
-  list-proxy: List all proxies (no args)
-  add-proxy: Add a new proxy (with optional `--dry-run` to preview changes)
-  delete-proxy: Delete a proxy (no args)

Environment Variables:
- `NPM_URL` (required): URL that points to Nginx Proxy Manager
- `NPM_AUTH_TOKEN` (optional): The "Bearer XXX" token for making API request, will ask for login with email and password if not provided.
- `HOME` (required): By default, auth credentials with be saved in $HOME/.local/nginx_proxy.json
