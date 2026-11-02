# -*- coding: utf-8 -*-
"""Wiring tests: extracts real functions out of main.py and runs them with stubs.

main.py needs aiohttp/httpx/Crypto at import time, so we never import it. Instead
we AST-extract the few functions A1 touched and execute them against fake
modules. This catches wiring regressions (e.g. a call site that forgets
``device=``) without needing the bot's third-party dependencies.

Run:  python3 tests/test_main_wiring.py
"""

import ast
import asyncio
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import device_profile as dp  # noqa: E402

_failures = []
_dirs = []


def check(name, cond, extra=""):
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name} {extra}")
        _failures.append(name)


def fresh_dir():
    d = tempfile.mkdtemp(prefix="ffwire-")
    _dirs.append(d)
    dp.DEVICES_FILE = os.path.join(d, "devices.json")
    return d


# ───────────────────────────── stubs ──────────────────────────────

class _Resp:
    status_code = 200
    status = 200

    def __init__(self, payload):
        self._payload = payload

    async def text(self):
        return json.dumps(self._payload)

    def json(self):
        return self._payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _HttpxClient:
    """Stands in for the module-level httpx client."""

    def __init__(self, sink):
        self._sink = sink

    async def post(self, url, headers=None, data=None, **kw):
        self._sink.append({"url": url, "headers": headers, "data": data})
        return _Resp({"open_id": "oid", "access_token": "at", "platform": 4})

    async def get(self, url, headers=None, **kw):
        self._sink.append({"url": url, "headers": headers, "data": None})
        return _Resp({"open_id": "oid", "platform": 4})


class _Session:
    def __init__(self, sink):
        self._sink = sink

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def post(self, url, headers=None, data=None, timeout=None):
        self._sink.append({"url": url, "headers": headers, "data": data})
        return _Resp({"code": 0, "data": {
            "uid": 18980166008, "open_id": "o", "access_token": "a"}})


class _Aiohttp:
    TCPConnector = staticmethod(lambda *a, **k: None)
    ThreadedResolver = staticmethod(lambda *a, **k: None)
    ClientTimeout = staticmethod(lambda *a, **k: None)

    def __init__(self, sink):
        self._sink = sink

    def ClientSession(self, *a, **k):
        return _Session(self._sink)


def _extract(names, extra_globals):
    src_path = os.path.join(ROOT, "main.py")
    with open(src_path, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    fns = [n for n in tree.body if isinstance(n, ast.AsyncFunctionDef)
           and n.name in names]
    found = {f.name for f in fns}
    missing = set(names) - found
    if missing:
        raise AssertionError(f"functions not found in main.py: {missing}")
    ns = dict(extra_globals)
    exec(compile(ast.Module(body=fns, type_ignores=[]), "main_extract", "exec"), ns)
    return ns


def _payload_globals():
    import uuid
    from datetime import datetime
    return {
        "uuid": uuid,
        "datetime": datetime,
        "devprof": dp,
        "create_proto": lambda d: json.dumps(d, sort_keys=True).encode(),
        "encrypt_aes": lambda b: b.hex() if isinstance(b, bytes) else b,
    }


def _parse(blob):
    return json.loads(blob)


# ───────────────────────────── tests ──────────────────────────────

def test_payload_device_id():
    import uuid
    ns = _extract({"get_payload"}, _payload_globals())
    get_payload = ns["get_payload"]
    dev = dp.get_or_create("18980166008")

    async def go():
        mp, lp = await get_payload("tok", "oid", 4, "1.108.1", device=dev)
        a, b = _parse(mp), _parse(lp)
        again = _parse((await get_payload(
            "tok", "oid", 4, "1.108.1", device=dev))[0])
        fallback = _parse((await get_payload("tok", "oid", 4, "1.108.1"))[0])
        return a, b, again, fallback

    a, b, again, fallback = asyncio.run(go())
    check("major payload uses profile id", a["19"] == dev["device_id"], a["19"])
    check("login payload uses same id", b["19"] == dev["device_id"])
    check("id stable across calls", again["19"] == dev["device_id"])
    check("crypto constant 57 untouched",
          a["57"] == "7428b253defc164018c604a1ebbfebdf")
    check("field 25 still matches baseline", a["25"] == "samsung SM-E135F")
    check("no-device fallback still random-format",
          fallback["19"].startswith("Google|")
          and fallback["19"] != dev["device_id"])


def test_grant_and_register():
    fresh_dir()
    sink = []
    ns = _extract({"grant_token", "register_account"}, {
        "json": json, "uuid": __import__("uuid"), "devprof": dp,
        "HEX_KEY": "k", "generate_signature": lambda p: "sig",
        "aiohttp": _Aiohttp(sink),
    })
    dev = dp.get_or_create("18980166008")

    async def go():
        await ns["register_account"]("pw", "https://gop", "1.108.1", device=dev)
        await ns["grant_token"]("18980166008", "pw", "https://gop", "1.108.1",
                                device=dev)

    asyncio.run(go())
    reg, gr = sink
    body = json.loads(gr["data"])
    check("grant device_id is profile garena id",
          body["device_id"] == dev["garena_device_id"], body["device_id"])
    check("grant device_id is stable (02-uuid)",
          body["device_id"].startswith("02-") and len(body["device_id"]) == 39)
    check("register UA == grant UA",
          reg["headers"]["User-Agent"] == gr["headers"]["User-Agent"])
    check("UA == profile UA",
          reg["headers"]["User-Agent"] == dp.ua_msdk(dev, "1.108.1"))


def test_access_token_ua():
    fresh_dir()
    sink = []
    ns = _extract({"get_access_token"}, {
        "client": _HttpxClient(sink),
        "devprof": dp, "HEX_KEY": "k", "asyncio": asyncio,
    })
    dev = dp.get_or_create("18980166008")

    async def go():
        return await ns["get_access_token"]("18980166008", "pw", device=dev)

    res = asyncio.run(go())
    check("access token returns triplet", res == ("oid", "at", 4))
    check("oauth UA == profile UA",
          sink[0]["headers"]["User-Agent"] == dp.ua_dalvik(dev))


def test_all_call_sites_pass_device():
    with open(os.path.join(ROOT, "main.py"), encoding="utf-8") as f:
        tree = ast.parse(f.read())
    checked = 0
    bad = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        name = getattr(f, "id", None)
        if name not in ("get_payload", "grant_token", "get_access_token"):
            continue
        checked += 1
        if "device" not in [k.arg for k in node.keywords]:
            bad.append((name, node.lineno))
    check("found all call sites", checked >= 7, checked)
    check("every call site passes device=", not bad, bad)


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    fresh_dir()
    try:
        for t in tests:
            print(f"\n{t.__name__}")
            t()
    finally:
        import shutil
        for d in _dirs:
            shutil.rmtree(d, ignore_errors=True)
    print()
    if _failures:
        print(f"FAILED {len(_failures)}: {_failures}")
        return 1
    print(f"ALL PASS ({len(tests)} tests)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
