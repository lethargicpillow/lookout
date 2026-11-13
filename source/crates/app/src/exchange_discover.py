"""Exchange POX discovery. Credentials on stdin only; no automatic auth redirects."""
import json
import re
import signal
import sys
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit, urljoin
from xml.sax.saxutils import escape

LIMIT = 512 * 1024
PATH = "/autodiscover/autodiscover.xml"
CLOUD = {"autodiscover.outlook.com", "autodiscover-s.outlook.com",
         "outlook.office365.com", "outlook.office.com", "login.microsoftonline.com"}

def domain(address):
    local, sep, host = address.rpartition("@")
    if not sep or not local or "@" in local or any(c.isspace() for c in local):
        return None
    host = host.lower()
    if len(host) > 253 or "." not in host or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in host.split(".")):
        return None
    return host

def secure_url(value):
    try:
        p = urlsplit(value)
        if (p.scheme == "https" and p.hostname and not p.username and not p.password
                and not p.fragment and not p.query and not any(c.isspace() or ord(c)<32 or c=="\\" for c in value)
                and domain("x@" + p.hostname) and (p.port is None or p.port == 443)):
            return value
    except ValueError:
        pass
    return None

def related(host, original):
    return host == original or host.endswith("." + original)

def oab_manifest_url(value):
    url = secure_url(value)
    if not url:
        return None
    path = urlsplit(url).path
    if path.lower().endswith("/oab.xml"):
        return url
    if path.endswith("/") or re.fullmatch(r"[0-9a-fA-F-]{36}", path.rsplit("/", 1)[-1]):
        return url.rstrip("/") + "/oab.xml"
    return None


def oab_candidates(protocols, selected, ews):
    """Prefer published external URLs, then the advertised external EWS
    origin with the exact published OAB path, then other published URLs.
    Never invent a server name or mailbox GUID."""
    published = []
    other = []
    for p in [selected] + [p for p in protocols if p is not selected]:
        url = oab_manifest_url(p.findtext("OABUrl", "").strip())
        if not url:
            continue
        if p is selected or p.findtext("Type", "").upper() == "EXPR" or (
                p.findtext("Type", "").upper() == "EXHTTP"
                and urlsplit(url).hostname == urlsplit(ews).hostname):
            published.append(url)
        else:
            other.append(url)
    # Even when the internal OAB hostname is unreachable, its exact
    # published GUID path can be exposed on the external EWS origin.
    # These are candidates only; an authenticated manifest GET must
    # validate them before replacing the published external address.
    origin = urlsplit(ews)
    derived = []
    for url in published + other:
        path = urlsplit(url).path
        if path.lower().startswith("/oab/") and urlsplit(url).hostname != origin.hostname:
            derived.append(origin.scheme + "://" + origin.netloc + path)
    # GUID paths are more specific than a bare /OAB/ virtual directory.
    derived.sort(key=lambda u: urlsplit(u).path.lower() == "/oab/oab.xml")
    return list(dict.fromkeys(published + derived + other))[:8]


def parse(data):
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        return None
    try:
        root = ET.fromstring(data)
        for node in root.iter():
            node.tag = node.tag.rsplit("}", 1)[-1]
        account = root.find("./Response/Account")
        if account is None:
            return None
        action = account.findtext("Action", "").lower()
        if action == "redirectaddr":
            return {"status": "redirect_address", "address": account.findtext("RedirectAddr", "").strip()}
        if action == "redirecturl":
            return {"status": "redirect_url", "url": account.findtext("RedirectUrl", "").strip()}
        if account.findtext("MicrosoftOnline", "").lower() == "true":
            return {"status": "cloud"}
        if action not in ("", "settings"):
            return None
        protocols = account.findall("Protocol")
        # EXPR is the externally reachable configuration. Prefer it to
        # EXCH (internal) and EXHTTP, without mixing fields across blocks
        # unless the selected block omitted a field.
        priority = {"EXPR": 0, "EXHTTP": 1, "EXCH": 2}
        protocols.sort(key=lambda p: priority.get(p.findtext("Type", "").upper(), 3))
        for p in protocols:
            ews = next((url for key in ("EwsUrl", "ASUrl")
                        if (url := secure_url(p.findtext(key, "").strip()))
                        and urlsplit(url).path.lower() == "/ews/exchange.asmx"), None)
            if not ews:
                continue
            if urlsplit(ews).hostname in CLOUD:
                return {"status": "cloud"}
            urls = oab_candidates(protocols, p, ews)
            return {"status": "exchange", "ews": ews,
                    "oab": urls[0] if urls else None, "oab_candidates": urls}
    except (ET.ParseError, ValueError, TypeError):
        return None
    return None

def candidates(host):
    return ["https://" + host + PATH, "https://autodiscover." + host + PATH]

def srv_candidates(host):
    try:
        import dns.resolver
        records = dns.resolver.resolve("_autodiscover._tcp." + host, "SRV", lifetime=5)
        ordered = sorted(records, key=lambda r: (r.priority, -r.weight))
        return ["https://" + str(r.target).rstrip(".") + PATH for r in ordered
                if r.port == 443 and domain("x@" + str(r.target).rstrip("."))][:8]
    except Exception:
        return []

def valid_oab_manifest(data):
    if not data or b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        return False
    try:
        root = ET.fromstring(data)
        return root.tag == "OAB" and any(
            f.text and re.fullmatch(r"[A-Za-z0-9_.-]+\.lzx", f.text.strip(), re.I)
            and f.get("size") and f.get("SHA")
            for f in root.findall("./OAL/Full"))
    except (ET.ParseError, ValueError):
        return False


def choose_oab(urls, authorized, probe):
    """Return the first verified authorized endpoint, or a published
    authorized fallback for later retry. No credentials on untrusted hosts."""
    trusted = [url for url in urls if authorized(url)]
    for url in trusted:
        outcome = probe(url)
        if outcome == "ok":
            return url, True
        if outcome == "authentication":
            break  # no repeated rejected-password attempts
    return (trusted[0], False) if trusted else (None, False)


def probe_oab(session, url, login, password):
    import requests
    from requests_ntlm import HttpNtlmAuth
    args = dict(timeout=(3, 5), stream=True, allow_redirects=False)
    try:
        with session.get(url, **args) as response:
            status = response.status_code
            challenge = response.headers.get("WWW-Authenticate", "").lower()
            if status == 200:
                return "ok" if valid_oab_manifest(read_xml(response)) else "unavailable"
        if status != 401 or not password:
            return "unavailable"
        if "ntlm" in challenge or "negotiate" in challenge:
            auth = HttpNtlmAuth(login, password)
        elif "basic" in challenge:
            auth = requests.auth.HTTPBasicAuth(login, password)
        else:
            return "unavailable"
        with session.get(url, auth=auth, **args) as response:
            if response.status_code in (401, 403):
                return "authentication"
            if response.status_code == 200 and valid_oab_manifest(read_xml(response)):
                return "ok"
    except (requests.RequestException, ValueError):
        pass
    return "unavailable"


def discover(cfg):
    import requests
    from requests_ntlm import HttpNtlmAuth
    original = domain(cfg["email"])
    if not original:
        return {"status": "invalid"}
    address = cfg["email"]
    password = cfg.get("password", "")
    approved = set(cfg.get("approved", []))
    queue = [(address, url) for url in candidates(original)]
    seen = set()
    tried_fallback = set()
    redirects = 0
    auth_needed = False
    first_untrusted = None
    def authorized(url):
        host = urlsplit(url).hostname
        return related(host, original) or host in approved
    def approval(url):
        return {"status": "approval", "host": urlsplit(url).hostname}
    with requests.Session() as session:
        session.trust_env = False
        while len(seen) < 24:
            if not queue:
                d = domain(address)
                if d and d not in tried_fallback:
                    tried_fallback.add(d)
                    # HTTP is used ONLY to receive a redirect, without email,
                    # credentials, cookies, or authorization.
                    try:
                        with requests.get("http://autodiscover." + d + PATH,
                                          timeout=(4,5), allow_redirects=False, stream=True) as response:
                            target = secure_url(response.headers.get("Location", "")) if response.is_redirect else None
                            if target:
                                queue.append((address, target))
                    except requests.RequestException:
                        pass
                    queue.extend((address, u) for u in srv_candidates(d))
            if not queue:
                break
            address, url = queue.pop(0)
            if not secure_url(url) or (address, url) in seen:
                continue
            seen.add((address, url))
            host = urlsplit(url).hostname
            if host in CLOUD:
                return {"status": "cloud"}
            body = ('<?xml version="1.0" encoding="utf-8"?>'
                    '<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">'
                    '<Request><EMailAddress>' + escape(address) + '</EMailAddress>'
                    '<AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>'
                    '</Request></Autodiscover>')
            args = dict(data=body.encode(), headers={"Content-Type":"text/xml; charset=utf-8"},
                        timeout=(5, 10), stream=True, allow_redirects=False)
            try:
                # Always obtain the challenge first; never send a password
                # to a redirected or unrelated host without explicit consent.
                with session.post(url, **args) as response:
                    status = response.status_code
                    challenge = response.headers.get("WWW-Authenticate", "").lower()
                    location = response.headers.get("Location", "")
                    data = read_xml(response) if status == 200 else None
                if status == 401 and "bearer" in challenge and ("microsoftonline.com" in challenge or "outlook.com" in challenge):
                    return {"status": "cloud"}
                if status == 401 and ("ntlm" in challenge or "negotiate" in challenge or "basic" in challenge):
                    auth_needed = True
                    if not password:
                        continue
                    if not authorized(url):
                        first_untrusted = first_untrusted or url
                        continue
                    auth = HttpNtlmAuth(cfg.get("login") or cfg["email"], password) if (
                        "ntlm" in challenge or "negotiate" in challenge) else requests.auth.HTTPBasicAuth(
                        cfg.get("login") or cfg["email"], password)
                    with session.post(url, auth=auth, **args) as response:
                        status = response.status_code
                        location = response.headers.get("Location", "")
                        data = read_xml(response) if status == 200 else None
                    if status in (401, 403):
                        # Don't repeatedly try a rejected password on other
                        # endpoints: respect corporate lockout policy.
                        return {"status": "authentication"}
                if status in (301, 302, 303, 307, 308):
                    target = secure_url(urljoin(url, location))
                    if target and redirects < 10:
                        redirects += 1
                        queue.insert(0, (address, target))
                    continue
                result = parse(data) if data else None
                if result:
                    kind = result["status"]
                    if kind == "redirect_url" and redirects < 10:
                        target = secure_url(result["url"])
                        if target:
                            redirects += 1
                            queue.insert(0, (address, target))
                    elif kind == "redirect_address" and redirects < 10:
                        target = result["address"]
                        target_domain = domain(target)
                        if target_domain:
                            redirects += 1
                            queue[0:0] = [(target, u) for u in candidates(target_domain)]
                    elif kind == "cloud":
                        return result
                    elif kind == "exchange":
                        # EWS/OAB are where the actual account password will
                        # later be used, so apply the same trust boundary.
                        if not authorized(result["ews"]):
                            return approval(result["ews"])
                        urls = result.pop("oab_candidates", [])
                        selected, verified = choose_oab(urls, authorized, lambda endpoint:
                            probe_oab(session, endpoint, cfg.get("login") or cfg["email"], password))
                        if selected is None and urls:
                            return approval(urls[0])
                        # If none worked, keep the best published address
                        # for the background GAL retry, not a guessed host.
                        result["oab"] = selected
                        result["oab_verified"] = verified
                        return result
            except (requests.RequestException, ValueError):
                pass
        if first_untrusted:
            return approval(first_untrusted)
        if auth_needed and not password:
            return {"status": "password"}
        return {"status": "not_found"}

def read_xml(response):
    data = bytearray()
    for chunk in response.iter_content(16384):
        data.extend(chunk)
        if len(data) > LIMIT:
            return None
    return bytes(data)

def main():
    signal.alarm(110)
    try:
        cfg = json.load(sys.stdin)
        result = discover(cfg)
    except ImportError:
        result = {"status": "dependencies"}
    except Exception:
        result = {"status": "network"}
    print(json.dumps(result))

if __name__ == "__main__":
    main()
