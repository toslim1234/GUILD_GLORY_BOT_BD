# -*- coding: utf-8 -*-
"""Stable per-account device identity for the Free Fire bot.

Phase A1 (consistency only)
───────────────────────────
One account => one persisted device profile, forever.  The two identifiers that
used to be regenerated on every request (``Google|<uuid>`` in the MajorLogin
payload and ``02-<uuid>`` in the OAuth token grant) now come from this module,
and every user-agent string for that account describes the same device.

A1 deliberately uses the values the payload already hardcodes (Samsung
SM-E135F / Android 14 / API-34 / Mali-G52).  So the only behavioural change is:
random IDs become stable, and the OAuth UA stops contradicting the payload UA.
Model / GPU / screen / RAM randomisation is Phase A2 and is gated behind
``VARIATION_ENABLED``.

Stdlib only — safe to import from tests without the bot's third-party deps.
"""

import copy
import json
import os
import random
import sys
import threading
import time
import uuid

# Location is anchored to this file, not the process CWD, so the bot's working
# directory can never split one account across two device files.
_HERE = os.path.dirname(os.path.abspath(__file__))
DEVICES_FILE = os.environ.get("FF_DEVICES_FILE") or os.path.join(
    _HERE, "devices.json")

PROFILE_VERSION = 1
PHASE = "A1"

# A2 will flip this on and use DEVICE_POOL below.  A1 always takes BASELINE.
VARIATION_ENABLED = False

BASELINE = {
    "brand": "Samsung",
    "model": "SM-E135F",
    "gpu": "Mali-G52",
    "gpu_vendor": "ARM",
    "opengl": ("OpenGL ES 3.2 v1.r38p1-01bet0-mbs2v41_0.6d20ec041e51b2f2d25dfc2"
               "65586ebe8"),
    "os_version": "Android OS 14 / API-34 (UP1A.231005.007/E135FXXSEEZE2)",
    "android": "14",
    "api": 34,
    "build": "UP1A.231005.007/E135FXXSEEZE2",
    "screen_width": 750,
    "screen_height": 1672,
    "screen_dpi": "338",
    "memory": 3702,
    "cpu": "ARMv7 VFPv3 NEON | 2002 | 8",
    "city": "Khulna",
    "division": "D",
    "network": "CarrierDataNetwork",
    "locale": "en",
    "country": "GB",
}

# Reserved for Phase A2 — not reachable while VARIATION_ENABLED is False.
DEVICE_POOL = [
    {"brand": "Samsung", "model": "SM-A125F", "gpu": "Mali-G57",
     "android": "13", "api": 33, "memory": 3072, "screen_width": 720,
     "screen_height": 1600, "screen_dpi": "320"},
    {"brand": "Xiaomi", "model": "2201122G", "gpu": "Adreno (TM) 730",
     "android": "13", "api": 33, "memory": 6144, "screen_width": 1080,
     "screen_height": 2400, "screen_dpi": "395"},
    {"brand": "realme", "model": "RMX3700", "gpu": "Mali-G710",
     "android": "14", "api": 34, "memory": 6144, "screen_width": 1080,
     "screen_height": 2412, "screen_dpi": "400"},
    {"brand": "OnePlus", "model": "CPH2451", "gpu": "Adreno (TM) 740",
     "android": "13", "api": 33, "memory": 8192, "screen_width": 1080,
     "screen_height": 2412, "screen_dpi": "394"},
]

_LOCK = threading.RLock()


# ───────────────────────────── helpers ─────────────────────────────

def _norm_uid(auth_uid):
    uid = str(auth_uid).strip()
    if not uid:
        raise ValueError("auth_uid must be a non-empty string")
    return uid


def _new_uuid(rng):
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def _new_hex_id(rng, nbytes=8):
    return rng.getrandbits(nbytes * 8).to_bytes(nbytes, "big").hex()


def _load_locked():
    """Load devices.json. Corrupt file is quarantined, never fatal."""
    path = DEVICES_FILE
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {str(k): v for k, v in data.items() if isinstance(v, dict)}
        raise ValueError("root is not an object")
    except Exception:
        try:
            os.replace(path, f"{path}.corrupt-{int(time.time())}")
        except Exception:
            pass
        return {}


_save_warned = False


def _save_locked(data):
    """Atomically persist. A failed write must never stop the bot from logging in."""
    global _save_warned
    path = DEVICES_FILE
    tmp = f"{path}.tmp.{os.getpid()}.{threading.get_ident()}"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
        os.replace(tmp, path)
        return True
    except Exception as e:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        if not _save_warned:
            _save_warned = True
            try:
                print(f"[DEV] WARNING cannot write {path}: {e}", file=sys.stderr)
            except Exception:
                pass
        return False


def _normalize(profile):
    """Fill missing / stale keys without changing existing identifiers."""
    p = copy.deepcopy(BASELINE)
    p.update({k: v for k, v in (profile or {}).items() if v is not None})
    rng = random.SystemRandom()
    if not str(p.get("device_id", "")).startswith("Google|"):
        p["device_id"] = "Google|" + _new_uuid(rng)
    if not str(p.get("garena_device_id", "")).startswith("02-"):
        p["garena_device_id"] = "02-" + _new_uuid(rng)
    if not p.get("google_account_id"):
        p["google_account_id"] = _new_hex_id(rng)
    p.setdefault("variant", "baseline")
    p.setdefault("created", time.time())
    p.setdefault("rotated", 0)
    p.setdefault("account_id", None)
    p["version"] = PROFILE_VERSION
    p["phase"] = PHASE
    return p


# ─────────────────────────── public API ────────────────────────────

def new_profile(seed=None):
    """Return a fresh, *unsaved* device profile.

    ``seed`` makes IDs reproducible (tests only).
    """
    rng = random.Random(seed) if seed is not None else random.SystemRandom()
    base = BASELINE
    if VARIATION_ENABLED:
        base = dict(BASELINE)
        base.update(rng.choice(DEVICE_POOL))
    p = _normalize({})
    p.update(copy.deepcopy(base))
    p["device_id"] = "Google|" + _new_uuid(rng)
    p["garena_device_id"] = "02-" + _new_uuid(rng)
    p["google_account_id"] = _new_hex_id(rng)
    p["variant"] = "pool" if VARIATION_ENABLED else "baseline"
    p["created"] = time.time()
    p["rotated"] = 0
    p["account_id"] = None
    return p


def get(auth_uid):
    """Return the stored profile for ``auth_uid`` or ``None``."""
    uid = _norm_uid(auth_uid)
    with _LOCK:
        return copy.deepcopy(_load_locked().get(uid))


def get_or_create(auth_uid):
    """Return the stored profile, creating and persisting one if absent.

    Also self-heals profiles written by older versions (missing IDs gain new
    ones; existing IDs are never replaced).
    """
    uid = _norm_uid(auth_uid)
    with _LOCK:
        data = _load_locked()
        raw = data.get(uid)
        if raw is not None:
            p = _normalize(raw)
            if p != raw:
                data[uid] = p
                _save_locked(data)
            return copy.deepcopy(p)
        p = new_profile()
        data[uid] = p
        _save_locked(data)
        return copy.deepcopy(p)


def bind_account(auth_uid, profile=None, account_id=None):
    """Persist ``profile`` under ``auth_uid`` (used after registration).

    If the account already has a profile, the stored one wins — a re-login can
    never silently replace the device. ``account_id`` is always refreshed.
    """
    uid = _norm_uid(auth_uid)
    with _LOCK:
        data = _load_locked()
        existing = data.get(uid)
        if existing is not None:
            p = _normalize(existing)
        else:
            p = _normalize(profile) if profile else new_profile()
        if account_id is not None:
            p["account_id"] = str(account_id)
        elif p.get("account_id") is None and profile and profile.get("account_id"):
            p["account_id"] = str(profile["account_id"])
        data[uid] = p
        _save_locked(data)
        return copy.deepcopy(p)


def rotate(auth_uid):
    """Give an account brand-new identifiers, keeping account metadata.

    Not wired to the dashboard in A1; the API exists so A2 can expose it.
    """
    uid = _norm_uid(auth_uid)
    with _LOCK:
        data = _load_locked()
        old = _normalize(data.get(uid) or {})
        p = new_profile()
        p["created"] = old.get("created", p["created"])
        p["rotated"] = time.time()
        p["account_id"] = old.get("account_id")
        data[uid] = p
        _save_locked(data)
        return copy.deepcopy(p)


def remove(auth_uid):
    uid = _norm_uid(auth_uid)
    with _LOCK:
        data = _load_locked()
        if uid not in data:
            return False
        del data[uid]
        _save_locked(data)
        return True


def all_profiles():
    with _LOCK:
        return copy.deepcopy(_load_locked())


# ─────────────────────────── formatters ────────────────────────────

def ua_dalvik(profile):
    """User-Agent for the Garena OAuth (guest token) endpoint."""
    p = profile or BASELINE
    return "Dalvik/2.1.0 (Linux; U; Android {}; {})".format(
        p.get("android", "14"), p.get("model", "SM-E135F"))


def ua_msdk(profile, app_version):
    """User-Agent for /oauth/guest:register and /oauth/guest/token:grant."""
    p = profile or BASELINE
    return "GarenaMSDK/4.0.44({} ;Android {};{};{};app {} 2019118525;)".format(
        p.get("model", "SM-E135F"), p.get("android", "14"),
        p.get("locale", "en"), p.get("country", "GB"), app_version)


def google_device_id(profile):
    p = profile or {}
    did = str(p.get("device_id") or "")
    return did if did.startswith("Google|") else "Google|" + _new_uuid(
        random.SystemRandom())


def garena_device_id(profile):
    p = profile or {}
    did = str(p.get("garena_device_id") or "")
    return did if did.startswith("02-") else "02-" + _new_uuid(
        random.SystemRandom())


def summary(profile):
    """Short one-line description for ``[DEV]`` log lines."""
    p = profile or {}
    brand = p.get("brand", "Samsung")
    model = p.get("model", "SM-E135F")
    android = p.get("android", "14")
    did = str(p.get("device_id", ""))
    short = did.split("|", 1)[-1][:8]
    return f"{brand} {model} / Android {android} / Google|{short}…"
