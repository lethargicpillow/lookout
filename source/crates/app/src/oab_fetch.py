"""Private OAB transport helper. JSON on stdin; fixed status on stdout."""
import ctypes
import ctypes.util
import hashlib
import json
import os
import re
import resource
import signal
import sys
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlsplit

MAX_BOOK = 256 * 1024 * 1024
MAX_XML = 2 * 1024 * 1024

class Failure(Exception):
    pass

def fetch(session, url, limit, target=None):
    stage = "download" if target else "manifest"
    with session.get(url, timeout=(15, 45), stream=True, allow_redirects=False) as response:
        if response.status_code in (401, 403):
            raise Failure("authentication")
        if response.status_code != 200:
            raise Failure(stage + "_http_" + str(response.status_code))
        data = bytearray()
        count = 0
        digest = hashlib.sha1()
        stream = open(target, "wb") if target else None
        try:
            for chunk in response.iter_content(65536):
                count += len(chunk)
                if count > limit:
                    raise Failure("integrity")
                digest.update(chunk)
                if stream:
                    stream.write(chunk)
                else:
                    data.extend(chunk)
        finally:
            if stream:
                stream.close()
        return (count, digest.hexdigest()) if target else bytes(data)

def manifest(data):
    try:
        if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
            raise ValueError()
        root = ET.fromstring(data)
        if root.tag != "OAB":
            raise ValueError()
        lists = [oal for oal in root.findall("OAL") if oal.find("Full") is not None]
        default = [oal for oal in lists if oal.get("name", "").strip("\\").casefold() == "default global address list"]
        if len(default) == 1:
            lists = default
        if len(lists) != 1:
            raise ValueError()
        fulls = lists[0].findall("Full")
        if len(fulls) != 1:
            raise ValueError()
        f = fulls[0]
        name = (f.text or "").strip()
        size, expanded = int(f.get("size")), int(f.get("uncompressedsize"))
        sha = f.get("SHA", "").lower()
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.lzx", name, re.I):
            raise ValueError()
        if not (0 < size <= MAX_BOOK and 0 < expanded <= MAX_BOOK):
            raise ValueError()
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ValueError()
        return name, size, expanded, sha
    except (ET.ParseError, ValueError, TypeError, AttributeError):
        raise Failure("manifest") from None

def unpack(source, target):
    # The first field of msoab_decompressor is its decompress function.
    libname = ctypes.util.find_library("mspack")
    if not libname:
        raise Failure("dependencies")
    lib = ctypes.CDLL(libname)
    lib.mspack_create_oab_decompressor.argtypes = [ctypes.c_void_p]
    lib.mspack_create_oab_decompressor.restype = ctypes.c_void_p
    lib.mspack_destroy_oab_decompressor.argtypes = [ctypes.c_void_p]
    lib.mspack_destroy_oab_decompressor.restype = None
    ptr = lib.mspack_create_oab_decompressor(None)
    if not ptr:
        raise Failure("unpack")
    try:
        address = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_void_p))[0]
        fn = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p)(address)
        if fn(ptr, os.fsencode(source), os.fsencode(target)) != 0:
            raise Failure("unpack")
    finally:
        lib.mspack_destroy_oab_decompressor(ptr)

def main():
    os.umask(0o077)
    signal.alarm(300)
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_BOOK, MAX_BOOK))
    try:
        import requests
        from requests_ntlm import HttpNtlmAuth
    except ImportError:
        raise Failure("dependencies") from None
    cfg = json.load(sys.stdin)
    url = cfg["url"]
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise Failure("manifest")
    with requests.Session() as session:
        session.trust_env = False
        session.auth = HttpNtlmAuth(cfg["login"], cfg["password"])
        name, size, expanded, sha = manifest(fetch(session, url, MAX_XML))
        fingerprint = hashlib.sha256((url + "\n" + name + "\n" + sha).encode()).hexdigest()
        if cfg.get("known") == fingerprint:
            print("unchanged")
            return
        if fetch(session, urljoin(url, name), size, "full.lzx") != (size, sha):
            raise Failure("integrity")
        unpack("full.lzx", "full.oab")
        if os.stat("full.oab").st_size != expanded:
            raise Failure("integrity")
        print(fingerprint)

if __name__ == "__main__":
    try:
        main()
    except Failure as e:
        print(str(e))
        sys.exit(1)
    except Exception as exc:
        import requests
        if isinstance(exc, requests.exceptions.SSLError):
            code = "tls"
        elif isinstance(exc, requests.exceptions.Timeout):
            code = "timeout"
        elif isinstance(exc, requests.exceptions.ConnectionError):
            code = "connection"
        elif isinstance(exc, requests.exceptions.RequestException):
            code = "http_transport"
        else:
            code = "helper"
        print(code)
        sys.exit(1)
