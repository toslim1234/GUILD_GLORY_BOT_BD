# -*- coding: utf-8 -*-
"""Phase A1 device fingerprint tests — stdlib only, no bot dependencies.

Run:  python3 tests/test_device_profile.py
"""

import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import device_profile as dp  # noqa: E402

_failures = []


def check(name, cond, extra=""):
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name} {extra}")
        _failures.append(name)


_dirs = []


def fresh_dir():
    d = tempfile.mkdtemp(prefix="ffdev-")
    _dirs.append(d)
    dp.DEVICES_FILE = os.path.join(d, "devices.json")
    return d


def test_save_failure_graceful():
    d = fresh_dir()
    blocker = os.path.join(d, "blocker")
    with open(blocker, "w", encoding="utf-8") as f:
        f.write("x")
    dp.DEVICES_FILE = os.path.join(blocker, "devices.json")
    dp._save_warned = True  # keep test output clean
    p = dp.get_or_create("1010")
    check("save failure still returns profile",
          p["device_id"].startswith("Google|"))
    p2 = dp.get_or_create("1010")
    check("save failure no crash on retry",
          p2["device_id"].startswith("Google|"))


def test_new_profile():
    fresh_dir()
    p = dp.new_profile()
    check("device_id Google|", p["device_id"].startswith("Google|"), p["device_id"])
    check("garena_id 02-", p["garena_device_id"].startswith("02-"))
    check("uuid length", len(p["device_id"]) == len("Google|") + 36)
    check("google_account_id 16 hex", len(p["google_account_id"]) == 16
          and all(c in "0123456789abcdef" for c in p["google_account_id"]))
    check("baseline model", p["model"] == "SM-E135F")
    check("has no file yet", not os.path.exists(dp.DEVICES_FILE))


def test_persistence():
    fresh_dir()
    a = dp.get_or_create("18980166008")
    b = dp.get("18980166008")
    c = dp.get_or_create("18980166008")
    check("persisted", b is not None)
    check("same device_id", a["device_id"] == b["device_id"] == c["device_id"])
    check("same garena id", a["garena_device_id"] == c["garena_device_id"])
    with open(dp.DEVICES_FILE, encoding="utf-8") as f:
        raw = json.load(f)
    check("json keyed by uid", "18980166008" in raw)
    check("json round-trip ids", raw["18980166008"]["device_id"] == a["device_id"])


def test_separate_accounts():
    fresh_dir()
    a = dp.get_or_create("111")
    b = dp.get_or_create("222")
    check("different ids per account", a["device_id"] != b["device_id"])
    check("two entries", len(dp.all_profiles()) == 2)


def test_bind():
    fresh_dir()
    pending = dp.new_profile()
    bound = dp.bind_account("333", pending, account_id="18800000001")
    check("bind keeps device_id", bound["device_id"] == pending["device_id"])
    check("bind sets account_id", bound["account_id"] == "18800000001")
    again = dp.bind_account("333", dp.new_profile(), account_id="18800000002")
    check("bind never replaces device", again["device_id"] == pending["device_id"])
    check("bind refreshes account_id", again["account_id"] == "18800000002")


def test_rotate():
    fresh_dir()
    a = dp.get_or_create("444")
    b = dp.rotate("444")
    check("rotate new device_id", a["device_id"] != b["device_id"])
    check("rotate new garena id", a["garena_device_id"] != b["garena_device_id"])
    check("rotate marks rotated", b["rotated"] > 0)
    check("rotate kept created", b["created"] == a["created"])
    check("rotate persisted", dp.get("444")["device_id"] == b["device_id"])


def test_remove():
    fresh_dir()
    dp.get_or_create("555")
    check("remove true", dp.remove("555") is True)
    check("gone", dp.get("555") is None)
    check("remove missing false", dp.remove("555") is False)


def test_corrupt_recovery():
    fresh_dir()
    with open(dp.DEVICES_FILE, "w", encoding="utf-8") as f:
        f.write("{not json")
    p = dp.get_or_create("666")
    check("recovered by creating", p["device_id"].startswith("Google|"))
    quarantined = [n for n in os.listdir(os.path.dirname(dp.DEVICES_FILE))
                   if ".corrupt-" in n]
    check("corrupt file quarantined", len(quarantined) == 1, quarantined)
    check("new file valid", dp.get("666") is not None)


def test_partial_profile_heals():
    fresh_dir()
    with open(dp.DEVICES_FILE, "w", encoding="utf-8") as f:
        json.dump({"777": {"model": "SM-E135F"}}, f)
    p = dp.get_or_create("777")
    check("heal adds device_id", p["device_id"].startswith("Google|"))
    check("heal adds garena id", p["garena_device_id"].startswith("02-"))
    check("heal keeps model", p["model"] == "SM-E135F")
    check("heal persisted", dp.get("777")["device_id"] == p["device_id"])


def test_user_agents():
    fresh_dir()
    p = dp.get_or_create("888")
    check("dalvik UA",
          dp.ua_dalvik(p) == "Dalvik/2.1.0 (Linux; U; Android 14; SM-E135F)",
          dp.ua_dalvik(p))
    msdk = dp.ua_msdk(p, "1.108.1")
    check("msdk UA",
          msdk == ("GarenaMSDK/4.0.44(SM-E135F ;Android 14;en;GB;"
                   "app 1.108.1 2019118525;)"), msdk)
    check("UA stable across calls", dp.ua_msdk(p, "1.108.1") == msdk)


def test_copy_isolation():
    fresh_dir()
    a = dp.get_or_create("999")
    a["device_id"] = "Google|tampered"
    check("get returns copy", dp.get("999")["device_id"] != "Google|tampered")
    everything = dp.all_profiles()
    everything["999"]["device_id"] = "Google|tampered2"
    check("all_profiles returns copy",
          dp.get("999")["device_id"] != "Google|tampered2")


def test_uid_coercion():
    fresh_dir()
    a = dp.get_or_create(123456)
    check("int uid coerced", dp.get("123456")["device_id"] == a["device_id"])


def test_seeded_reproducible():
    a = dp.new_profile(seed=42)
    b = dp.new_profile(seed=42)
    check("seed reproducible", a["device_id"] == b["device_id"])


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    fresh_dir()
    try:
        for t in tests:
            print(f"\n{t.__name__}")
            t()
    finally:
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
