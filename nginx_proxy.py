#!/usr/bin/python3
from datetime import datetime
from getpass import getpass
import os
import sys
import json
from pprint import pprint
from typing import Optional

import requests

HELP = {
    (CMD_LIST_USER := "list-user"): "List all users",
    (CMD_LIST_CERT := "list-cert"): "List all certificates",
    (CMD_LIST_PROXY := "list-proxy"): "List all proxies",
    (CMD_ADD_PROXY := "add-proxy"): "Add a new proxy (with optional --dry-run)",
    (CMD_DELETE_PROXY := "delete-proxy"): "Delete a proxy",
}


def print_help():
    print("Available commands:")
    for cmd, description in HELP.items():
        print(f"  {cmd}: {description}")
    exit(1)


NEWLINE = "\n"
NPM_URL = os.getenv("NPM_URL", "")
NPM_AUTH_JSON = os.path.join(
    os.getenv("HOME", ""), ".local", "nginx-proxy-manager.json"
)
NPM_AUTH_TOKEN = os.getenv("NPM_AUTH_TOKEN")

if not os.getenv("HOME"):
    print("Cannot find home directory")
    exit(1)
if not NPM_URL:
    print("NPM_URL is not set")
    exit(1)
if not NPM_AUTH_TOKEN:
    if os.path.exists(NPM_AUTH_JSON):
        with open(NPM_AUTH_JSON, "r") as f:
            auth = json.load(f)
            expires = auth["expires"]
            expires = datetime.strptime(expires, "%Y-%m-%dT%H:%M:%S.%fZ")
            if expires < datetime.now():
                print("Token expired, please login again")
                os.remove(NPM_AUTH_JSON)
            else:
                NPM_AUTH_TOKEN = auth["token"]
if len(sys.argv) < 2:
    print("No command specified")
    print_help()

CMD = sys.argv[1]
last_resp = requests.Response()  # for mypy linting


class User(dict):
    @property
    def id(self) -> int:
        return self["id"]

    @property
    def email(self) -> str:
        return self["email"]

    @property
    def name(self) -> str:
        return self["name"]

    @property
    def nickname(self) -> str:
        return self["nickname"]

    def __str__(self) -> str:
        return f"[User {self.id}] {self.email} {self.name} {self.nickname}"

    def __repr__(self) -> str:
        return str(self)


class Proxy(dict):
    @property
    def id(self) -> int:
        return self["id"]

    @property
    def enabled(self) -> bool:
        return self["enabled"] == 1

    @property
    def domains(self) -> list[str]:
        return self["domain_names"]

    @property
    def target(self) -> str:
        return (
            f"{self['forward_scheme']}://{self['forward_host']}:{self['forward_port']}"
        )

    @property
    def cert(self) -> str:
        return self["certificate_id"]

    def __str__(self) -> str:
        return f"""[Proxy {self.id}]
    Is Enabled? {self.enabled}
    Domains: {self.domains}
    Target: {self.target}
    Cert ID: {self.cert}"""

    def __repr__(self) -> str:
        return str(self)


class Certificate(dict):
    @property
    def id(self) -> int:
        return self["id"]

    @property
    def nice_name(self) -> str:
        return self["nice_name"]

    @property
    def domains(self) -> list:
        return self["domain_names"]

    @property
    def expires_on(self) -> str:
        return self["expires_on"]

    def __str__(self) -> str:
        return f"""[Certificate {self.id}]
    Nice Name: {self.nice_name}
    Domains: {self.domains}
    Expires On: {self.expires_on}"""

    def __repr__(self) -> str:
        return str(self)


def make_request(
    endpoint: str,
    method="get",
    expected_status=200,
    map_class: Optional[type] = None,
    map_by_id=True,
    **kwargs,
) -> Optional[dict]:
    assert method in ["get", "post", "put", "delete"]
    assert NPM_AUTH_TOKEN is not None
    global last_resp
    last_resp = getattr(requests, method)(
        NPM_URL + endpoint,
        headers={
            "Authorization": "Bearer " + NPM_AUTH_TOKEN,
        },
        **kwargs,
    )
    if last_resp.status_code != expected_status:
        return None
    resp_obj = last_resp.json()
    if map_class and map_by_id:
        m = {}
        for item in resp_obj:
            m[item["id"]] = map_class(item)
        return m
    if map_class:
        return map_class(resp_obj)
    return resp_obj


def list_certs() -> Optional[dict[int, Certificate]]:
    return make_request("/api/nginx/certificates", map_class=Certificate)


def list_proxies() -> Optional[dict[int, Proxy]]:
    return make_request("/api/nginx/proxy-hosts?expand=certificate", map_class=Proxy)


def list_users() -> Optional[dict[int, User]]:
    return make_request("/api/users", map_class=User)


def get_user():
    return make_request("/api/users/me", map_class=User, map_by_id=False)


def show_current_user():
    user = get_user()
    if user is None:
        print("Failed to get user info")
        exit(1)
    print("Current User:", user)


def login():
    while NPM_AUTH_TOKEN == None:
        print("Login with credential you used on web UI:")
        email = input("Email: ")
        password = getpass()
        resp = make_request(
            "/api/tokens",
            method="post",
            expected_status=200,
            json={"identity": email, "secret": password},
        )
        if resp is None:
            print("Failed to login", last_resp.text)
            continue
        with open(NPM_AUTH_JSON, "w") as f:
            json.dump(resp, f)
        NPM_AUTH_TOKEN = resp["token"]


if not NPM_AUTH_TOKEN:
    login()

show_current_user()
if CMD == CMD_LIST_PROXY:
    pprint(list_proxies())
elif CMD == CMD_LIST_CERT:
    pprint(list_certs())
elif CMD == CMD_LIST_USER:
    pprint(list_users())
elif CMD == CMD_ADD_PROXY:
    certs = list_certs()
    if not certs:
        print("Failed to get certificate list")
        exit(1)
    domains = input("Enter domain names (comma separated): ").split(",")
    domains_fmt = "[" + ",".join(list(map(lambda d: f'"{d}"', domains))) + "]"
    server_name_entries = "\n  ".join(list(map(lambda d: f"server_name {d};", domains)))
    while True:
        scheme = input("Enter target scheme (http/https): ")
        if scheme not in ["http", "https"]:
            print("Invalid scheme")
            continue
        break
    host = input("Enter target hostname / IP: ")
    while True:
        port = input("Enter target port: ")
        if not port.isdigit():
            print("Invalid port")
            continue
        if int(port) > 65535:
            print("Port number too large")
            continue
        break
    pprint(certs)
    while True:
        cert_id = int(input("Enter certificate ID: "))
        if cert_id not in certs:
            print("Invalid certificate ID")
            continue
        break
    is_websocket = input("Is this a websocket proxy? (y/n): ").lower() == "y"
    is_http2 = input("Is this a HTTP/2 proxy? (y/n): ").lower() == "y"
    set_headers = {
        "Host": "$host",
        "X-Real-IP": "$remote_addr",
        "X-Forwarded-For": "$proxy_add_x_forwarded_for",
        "X-Forwarded-Proto": "$scheme",
    }
    adv_config = {
        "proxy_pass": f"{scheme}://{host}:{port}",
        "proxy_set_header": set_headers,
    }
    if is_websocket:
        set_headers["Upgrade"] = "$http_upgrade"
        set_headers["Connection"] = "upgrade"
    if not is_http2:
        adv_config["proxy_http_version"] = "1.1"
    adv_config_fmt = "location / {"
    for adv_key, adv_val in adv_config.items():
        if isinstance(adv_val, dict):
            for adv_subkey, adv_subval in adv_val.items():
                adv_config_fmt += f"{NEWLINE}  {adv_key} {adv_subkey} {adv_subval};"
        else:
            adv_config_fmt += f"{NEWLINE}  {adv_key} {adv_val};"
    adv_config_fmt += "\n}"
    info_json = {
        "domains": domains,
        "target": f"{scheme}://{host}:{port}",
        "is_websocket": "yes" if is_websocket else "no",
        "cert": certs[cert_id]["nice_name"],
    }
    print("Double check the following information:")
    pprint(info_json)
    print("Advanced config:")
    print(adv_config_fmt)
    confirm = input("Confirm? (y/n): ")
    if confirm.lower() != "y":
        print("Aborted")
        exit(1)
    if "--dry-run" in sys.argv:
        print("Dry run, not adding proxy")
        exit(0)
    json_req = {
        "domain_names": domains,
        "forward_scheme": scheme,
        "forward_host": host,
        "forward_port": port,
        "access_list_id": "0",
        "certificate_id": cert_id,
        "http2_support": is_http2,
        "meta": {"letsencrypt_agree": False, "dns_challenge": False},
        "advanced_config": adv_config_fmt,
        "locations": [],
        "block_exploits": True,
        "caching_enabled": False,
        "allow_websocket_upgrade": is_websocket,
        "hsts_enabled": False,
        "hsts_subdomains": False,
        "ssl_forced": True,
    }
    req = make_request(
        "/api/nginx/proxy-hosts", method="post", expected_status=201, json=json_req
    )
    print("Response:")
    pprint(req)
    if not req:
        print("Failed to add proxy")
        exit(1)
    print(f"Done adding {','.join(domains)}")
elif CMD == CMD_DELETE_PROXY:
    proxies = list_proxies()
    if not proxies:
        print("Failed to get proxy list")
        exit(1)
    pprint(proxies)
    while True:
        choice = int(input("Enter proxy ID to delete: "))
        if choice not in proxies:
            print("Invalid proxy ID")
            continue
        break
    pprint(proxies[choice])
    confirm = input("Confirm? (y/n): ")
    if confirm.lower() != "y":
        print("Aborted")
        exit(1)
    resp = make_request(f"/api/nginx/proxy-hosts/{choice}", method="delete")
    if resp != "true":
        print("Failed to delete proxy")
        exit(1)
else:
    print("Invalid command", CMD)
    print_help()
