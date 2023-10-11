#!/usr/bin/python3
from datetime import datetime
import difflib
from getpass import getpass
import os
import re
import sys
import json
from pprint import pprint
import tempfile
from typing import Any, Callable, Literal, Optional

import requests

HELP = {
    (CMD_LIST_USER := "list-user"): "List all users",
    (CMD_LIST_CERT := "list-cert"): "List all certificates",
    (CMD_LIST_PROXY := "list-proxy"): "List all proxies",
    (CMD_ADD_PROXY := "add-proxy"): "Add a new proxy (with optional --dry-run)",
    (CMD_DELETE_PROXY := "delete-proxy"): "Delete a proxy",
    (CMD_EDIT_PROXY := "edit-proxy"): "Edit a proxy details",
    (CMD_UPLOAD_CERT := "upload-cert"): "Upload a SSL certificate",
    (CMD_DELETE_CERT := "delete-cert"): "Delete a SSL certificate",
    (
        CMD_NEW_CERT := "new-cert"
    ): "Get new SSL certificate from Let's Encrypt with Cloudflare DNS challenge",
}


def print_help():
    print("Available commands:")
    for cmd, description in HELP.items():
        print(f"  {cmd}: {description}")
    exit(1)


NEWLINE = "\n"
NPM_AUTH_JSON = os.path.join(
    os.getenv("HOME", ""), ".local", "nginx-proxy-manager.json"
)
NPM_URL = os.getenv("NPM_URL", "")
NPM_USER = os.getenv("NPM_USER", "")
NPM_PASS = os.getenv("NPM_PASS", "")
NPM_AUTH_TOKEN: str = ""
NPM_LOGIN_ENDPOINT = "/api/tokens"
last_resp = requests.Response()  # for mypy linting


def login():
    global NPM_AUTH_TOKEN
    resp = requests.post(
        NPM_URL + NPM_LOGIN_ENDPOINT,
        json={"identity": NPM_USER, "secret": NPM_PASS},
    )
    if resp.status_code != 200:
        print("Failed to login", resp.status_code, "\n", resp.text)
        exit(1)
    NPM_AUTH_TOKEN = resp.json()["token"]


if not os.getenv("HOME"):
    raise RuntimeError("HOME directory not set")

if os.path.exists(NPM_AUTH_JSON):
    with open(NPM_AUTH_JSON, "r") as f:
        auth = json.load(f)
        try:
            NPM_URL = auth["url"]
            NPM_USER = auth["email"]
            NPM_PASS = auth["password"]
        except KeyError:
            os.remove(NPM_AUTH_JSON)

if not (NPM_URL and NPM_USER and NPM_PASS):
    print("NPM_URL, NPM_USER, NPM_PASS not set")
    NPM_URL = input("Enter NPM URL: ")
    NPM_USER = input("Enter NPM email: ")
    NPM_PASS = getpass("Enter NPM password: ")
    if not (NPM_URL and NPM_USER and NPM_PASS):
        print("Invalid input")
        exit(1)

login()

NPM_AUTH_HEADERS = {
    "Authorization": "Bearer " + NPM_AUTH_TOKEN,
}

if not os.path.exists(NPM_AUTH_JSON):
    with open(NPM_AUTH_JSON, "w") as f:
        json.dump({"url": NPM_URL, "email": NPM_USER, "password": NPM_PASS}, f)
    os.chmod(NPM_AUTH_JSON, 0o600)  # only user can read/write

if len(sys.argv) < 2:
    print("No command specified")
    print_help()

CMD = sys.argv[1]


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
    method: Literal["get", "post", "put", "delete"] = "get",
    expected_status=200,
    map_by_id: Optional[type] = None,
    extra_headers: dict[str, str] = {},
    **kwargs,
) -> dict:
    global last_resp

    assert method in ["get", "post", "put", "delete"]
    assert NPM_AUTH_TOKEN is not None
    headers = NPM_AUTH_HEADERS
    headers.update(extra_headers)
    last_resp = getattr(requests, method)(
        NPM_URL + endpoint,
        headers=headers,
        **kwargs,
    )
    if last_resp.status_code != expected_status:
        print(
            f"Request failed with status {last_resp.status_code}, {method} {endpoint}"
        )
        exit(1)
    resp_obj = last_resp.json()
    if map_by_id:
        m = {}
        for item in resp_obj:
            m[item["id"]] = map_by_id(item)
        return m
    return resp_obj


def list_certs() -> dict[int, Certificate]:
    return make_request("/api/nginx/certificates", map_by_id=Certificate)


def list_proxies() -> dict[int, Proxy]:
    return make_request("/api/nginx/proxy-hosts?expand=certificate", map_by_id=Proxy)


def list_users() -> dict[int, User]:
    return make_request("/api/users", map_by_id=User)


def get_user() -> User:
    return User(make_request("/api/users/me"))


def delete_entry(
    name: str, endpoint: str, getter: Callable[[], dict], expected_status=204
):
    entries = getter()
    pprint(entries)
    while True:
        choice = int(input(f"Enter {name} ID to delete: "))
        if choice not in entries:
            print(f"Invalid {name} ID")
            continue
        break
    pprint(entries[choice])
    confirm = input("Confirm? (y/n): ")
    if confirm.lower() != "y":
        print("Aborted")
        exit(1)
    resp = make_request(
        f"{endpoint}/{choice}", method="delete", expected_status=expected_status
    )
    if resp != "true":
        print(f"Failed to delete {name}", last_resp.status_code)
        exit(1)


def delete_proxy():
    delete_entry("proxy", "/api/nginx/proxy-hosts", list_proxies)


def delete_cert():
    delete_entry(
        "certificate", "/api/nginx/certificates", list_certs, expected_status=200
    )


def add_proxy():
    certs = list_certs()
    domains = input("Enter domain names (comma separated): ").split(",")
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
    print(f"Done adding {','.join(domains)}")


def edit_proxy():
    proxies = list_proxies()
    domain = input('Enter a domain to edit (* to list all) (e.g. "example.com"): ')
    if domain == "*":
        pprint(proxies)
        domain = input('Enter a domain to edit (e.g. "example.com"): ')
    selected = None
    for proxy in proxies.values():
        if domain in proxy.domains:
            selected = proxy
            break
    if not selected:
        print("Domain not found")
        exit(1)
    pprint(selected)
    adv_config = selected["advanced_config"]
    allowed_keys = [
        "domain_names",
        "forward_scheme",
        "forward_host",
        "forward_port",
        "access_list_id",
        "certificate_id",
        "ssl_forced",
        "http2_support",
        "meta",
        "block_exploits",
        "caching_enabled",
        "allow_websocket_upgrade",
        "hsts_enabled",
        "hsts_subdomains",
    ]
    proxy_id = selected.id
    selected = {key: selected[key] for key in allowed_keys}
    # nano config json
    with tempfile.NamedTemporaryFile(mode="w+", prefix="Config", suffix=".json") as f:
        json.dump(selected, f, indent=4)
        f.flush()
        os.system(f"nano {f.name}")
        f.seek(0)
        try:
            new_proxy: dict[str, Any] = json.load(f)
        except json.JSONDecodeError as e:
            print("Invalid JSON\n", e)
            exit(1)
    # nano advanced config
    with tempfile.NamedTemporaryFile(mode="w+", prefix="AdvancedConfig") as f:
        f.write(adv_config)
        f.flush()
        os.system(f"nano {f.name}")
        f.seek(0)
        new_adv_config = f.read()

    # check for unexpected keys and changes
    config_changes = []
    for key in new_proxy:
        if key not in selected:
            print(f"Unexpected Key: {key}")
            exit(1)
        if new_proxy[key] != selected[key]:
            config_changes.append((key, selected[key], new_proxy[key]))
    adv_config_changes = list(
        filter(
            lambda line: (
                line.startswith("+")
                and not line.startswith("+++")
                or line.startswith("-")
                and not line.startswith("---")
            )
            and line.strip() != "",
            difflib.unified_diff(adv_config.splitlines(), new_adv_config.splitlines()),
        )
    )

    # check for missing keys
    for key in selected:
        if key not in new_proxy:
            print(f"Missing Key: {key}")
            exit(1)

    if not any(config_changes) and not any(adv_config_changes):
        print("No changes")
        exit(0)

    print("Please review the following changes:")

    print("Config:")
    if any(config_changes):
        for key, old, new in config_changes:
            print(f"{key}: {old} -> {new}")
    else:
        print("No changes")

    print("\nAdvanced Config:")
    if any(adv_config_changes):
        print("\n".join(adv_config_changes))
    else:
        print("No changes")

    confirm = input("Confirm? (y/n): ")
    if confirm.lower() != "y":
        print("Aborted")
        exit(1)

    # update proxy
    new_proxy["advanced_config"] = new_adv_config

    req = make_request(
        f"/api/nginx/proxy-hosts/{proxy_id}",
        method="put",
        expected_status=200,
        json=new_proxy,
    )
    print("Done editing proxy")


def upload_cert():
    while True:
        fullchain = input("Enter fullchain path: ")
        if not os.path.exists(fullchain):
            print("File not found")
            continue
        break
    while True:
        privkey = input("Enter privkey path: ")
        if not os.path.exists(privkey):
            print("File not found")
            continue
        break

    def files():
        return {
            "certificate": ("fullchain.pem", open(fullchain, "r")),
            "certificate_key": ("privkey.pem", open(privkey, "r")),
        }

    validate_req = make_request(
        f"/api/nginx/certificates/validate",
        method="post",
        expected_status=200,
        files=files(),
    )
    print("Selected certificate:")
    pprint(validate_req)
    add_req = make_request(
        "/api/nginx/certificates",
        method="post",
        expected_status=201,
        json={"nice_name": input("Enter certificate name: "), "provider": "other"},
    )
    cert_id = add_req["id"]
    make_request(
        f"/api/nginx/certificates/{cert_id}/upload",
        method="post",
        expected_status=200,
        files=files(),
    )
    print("Done uploading certificate")


def new_cert():
    use_current_email = (
        input(f"Use {current_user.email} as Let's Encrypt Email? (y/n): ").lower()
        == "y"
    )
    if not use_current_email:
        email = input("Enter Let's Encrypt Email: ")
    else:
        email = current_user.email
    domain = input("Enter domain name: ")
    cf_token = input("Enter Cloudflare API Token: ")
    req_json = {
        "domain_names": [domain],
        "meta": {
            "letsencrypt_email": email,
            "dns_challenge": True,
            "dns_provider": "cloudflare",
            "dns_provider_credentials": f"# Cloudflare API token\r\ndns_cloudflare_api_token = {cf_token}",
            "letsencrypt_agree": True,
        },
        "provider": "letsencrypt",
    }
    print("Requesting certificate...")
    req = Certificate(
        make_request(
            "/api/nginx/certificates",
            method="post",
            expected_status=201,
            json=req_json,
        )
    )
    print("Done requesting certificate, details below:")
    pprint(req)


current_user = get_user()
print("Current User:", current_user)

if CMD == CMD_LIST_PROXY:
    pprint(list_proxies())
elif CMD == CMD_LIST_CERT:
    pprint(list_certs())
elif CMD == CMD_LIST_USER:
    pprint(list_users())
elif CMD == CMD_ADD_PROXY:
    add_proxy()
elif CMD == CMD_DELETE_PROXY:
    delete_proxy()
elif CMD == CMD_EDIT_PROXY:
    edit_proxy()
elif CMD == CMD_UPLOAD_CERT:
    upload_cert()
elif CMD == CMD_DELETE_CERT:
    delete_cert()
elif CMD == CMD_NEW_CERT:
    new_cert()
else:
    print("Invalid command", CMD)
    print_help()
