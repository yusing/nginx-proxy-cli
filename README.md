# nginx-proxy-cli
Manipulate reversed proxies in command line

(**Caution**) *I have no responsibility when causing bugs/conflicts using the script, use on your own risk. But feel free to create "issues" or feature requests on GitHub.*

### Why?

It saves time.

Heading into the web UI, tabs and buttons is annoying when you add proxies frequently.

This script allows you to create / delete proxy with few taps on your keyboard. With generated default location entry with proper proxy_set_header, etc. 

What you may want to do:
1. Rename it to something like `nginx_proxy_cli`
2. Move it to `$HOME/.local/bin`
3. `chmod +x $HOME/.local/bin/nginx_proxy_cli`
4. Enjoy

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

Sample Input/output:
```plain
Current User: [User 1] somebody@mail.com somebody yusing
Enter domain names (comma separated): home.domain.com
Enter target scheme (http/https): http
Enter target hostname / IP: homelab
Enter target port: 5037
{1: [Certificate 1]
    Nice Name: Let's Encrypt
    Domains: ['*.domain.com']
    Expires On: 2023-12-31 10:13:10}
Enter certificate ID: 1
Is this a websocket proxy? (y/n): n
Is this a HTTP/2 proxy? (y/n): n
Double check the following information:
{'cert': "Let's Encrypt",
 'domains': ['home.domain.com'],
 'is_websocket': 'no',
 'target': 'http://homelab:5037'}
Advanced config:
location / {
  proxy_pass http://homelab:5037;
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_http_version 1.1;
}
Confirm? (y/n): y
Response:
{'access_list': None,
 'access_list_id': 0,
 'advanced_config': 'location / {\n'
                    '  proxy_pass http://homelab:5037;\n'
                    '  proxy_set_header Host $host;\n'
                    '  proxy_set_header X-Real-IP $remote_addr;\n'
                    '  proxy_set_header X-Forwarded-For '
                    '$proxy_add_x_forwarded_for;\n'
                    '  proxy_set_header X-Forwarded-Proto $scheme;\n'
                    '  proxy_http_version 1.1;\n'
                    '}',
 'allow_websocket_upgrade': 0,
 'block_exploits': 1,
 'caching_enabled': 0,
 'certificate': {'created_on': '2023-10-02 11:20:40',
                 'domain_names': ['*.domain.com'],
                 'expires_on': '2023-12-31 10:13:10',
                 'id': 1,
                 'is_deleted': 0,
                 'meta': {},
                 'modified_on': '2023-10-02 11:20:40',
                 'nice_name': "Let's Encrypt",
                 'owner_user_id': 2,
                 'provider': 'other'},
 'certificate_id': 5,
 'created_on': '2023-10-09 11:42:23',
 'domain_names': ['home.domain.com'],
 'enabled': 1,
 'forward_host': 'homelab',
 'forward_port': 5037,
 'forward_scheme': 'http',
 'hsts_enabled': 0,
 'hsts_subdomains': 0,
 'http2_support': 0,
 'id': 1,
 'ipv6': True,
 'locations': [],
 'meta': {'dns_challenge': False, 'letsencrypt_agree': False},
 'modified_on': '2023-10-09 11:42:23',
 'owner': {'avatar': '//www.gravatar.com/avatar/3309f87ec4b86ff05a065680e1c40e6a?default=mm',
           'created_on': '2023-09-30 11:18:00',
           'email': 'somebody@mail.com',
           'id': 1,
           'is_deleted': 0,
           'is_disabled': 0,
           'modified_on': '2023-10-02 21:07:32',
           'name': 'somebody',
           'nickname': 'somebody',
           'roles': ['admin']},
 'owner_user_id': 1,
 'ssl_forced': 1,
 'use_default_location': False}
Done adding home.domain.com
```
