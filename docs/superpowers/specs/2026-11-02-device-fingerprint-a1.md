# Device Fingerprint — Phase A1 (consistency)

Status: approved, implementing
Date: 2026-11-02
Scope: `device_profile.py`, `main.py` (wiring only), `tests/test_device_profile.py`

## Problem

Every login currently sends a **different device identity**:

| Place | Today | Risk |
|---|---|---|
| `get_payload()` field `19` | `Google|<uuid4>` regenerated on **every call** | server sees a new device each login/reconnect |
| `grant_token()` `device_id` | `02-<uuid4>` regenerated on every call | same account, new device every grant |
| `get_access_token()` UA | `Dalvik/... SM-G998B; Android 12` | contradicts the payload device |
| `register_account()` / `grant_token()` UA | `GarenaMSDK(... SM-E135F ;Android 14 ...)` | contradicts the OAuth UA |

The existing `_generate_new_device()` / `get_device_for_account()` functions are
dead code — `devices.json` has never existed.

## A1 goal

Only **volatile identifiers become stable**:

1. One account ⇒ one persisted device profile, forever.
2. `Google|uuid` (payload field 19) and `02-uuid` (grant body) come from that profile.
3. All HTTP user-agents for one account describe the **same** device.
4. Old accounts migrate automatically on first login (no manual step).

Explicitly **out of scope for A1**:
- randomising model / GPU / screen / RAM (`A2`)
- payload fields `8, 12, 13, 15, 16, 17, 18, 25, 26, 20` (`A2`)
- per-account IP / region (`A2`)
- device rotation from the dashboard (button ships in A2; `rotate()` API is
  already in the module and tested)

**Cryptographic constants are not touched.** Field `57`, `94`, `102`, `106`,
`107`, `GGRE_RAW`, AES keys/IV, signature function stay byte-identical.

## Safety argument

The A1 profile uses exactly the values the payload already hardcodes today:
`Samsung SM-E135F`, `Android 14 / API-34`, `Mali-G52`, `750x1672`, `3702 MB`,
locale `en`, country `GB`, city `Khulna`, division `D`.

So A1 changes **only** the two random IDs and the two UA strings. If login breaks
after A1, rolling back is a single `import` line, because nothing else moved.

## Module API — `device_profile.py` (stdlib only)

```python
new_profile(seed=None)              -> dict      # unsaved profile
get(auth_uid)                       -> dict|None
get_or_create(auth_uid)             -> dict      # creates + persists
bind_account(auth_uid, profile=None, account_id=None) -> dict
rotate(auth_uid)                    -> dict      # new IDs, same account
remove(auth_uid)                    -> bool
all_profiles()                      -> dict      # copy, for /api/devices
ua_dalvik(profile)                  -> str
ua_msdk(profile, app_version)       -> str
google_device_id(profile)           -> str       # "Google|<uuid>"
garena_device_id(profile)           -> str       # "02-<uuid>"
google_account_id(profile)          -> str       # Android GSF id (stable, 16 hex)
```

Profile schema (`devices.json`, keyed by `auth_uid`):

```json
{
  "version": 1,
  "variant": "baseline",
  "device_id": "Google|7c2f...",
  "garena_device_id": "02-9a11...",
  "google_account_id": "3f8a1c2d4e5b6a79",
  "brand": "Samsung", "model": "SM-E135F",
  "gpu": "Mali-G52", "gpu_vendor": "ARM",
  "opengl": "OpenGL ES 3.2 v1.r38p1-...",
  "os_version": "Android OS 14 / API-34 (UP1A.231005.007/E135FXXSEEZE2)",
  "android": "14", "api": 34,
  "build": "UP1A.231005.007/E135FXXSEEZE2",
  "screen_width": 720, "screen_height": 1600, "screen_dpi": "338",
  "memory": 3702, "cpu": "ARMv7 VFPv3 NEON | 2002 | 8",
  "city": "Khulna", "division": "D",
  "network": "CarrierDataNetwork",
  "locale": "en", "country": "GB",
  "account_id": "18980166008",
  "created": 1762000000.0, "rotated": 0
}
```

`devices.json` is written atomically (`tmp` + `os.replace`) under an `RLock`,
and its location is anchored to `device_profile.py` (not the process CWD), so a
different working directory can never split an account across two files. If a
write fails, the profile is still returned in memory (login proceeds, one
warning on stderr) instead of crashing the worker. A corrupt file is renamed to
`devices.json.corrupt-<ts>` and rebuilt.

## Wiring in `main.py`

| Location | Change |
|---|---|
| imports | `import device_profile as devprof` |
| `_generate_new_device()` / `get_device_for_account()` | thin delegates (dead-code paths now consistent) |
| `get_access_token(uid, password, device=None)` | UA from profile; `None` keeps old UA |
| `register_account(password, gop_url, app_version, device=None)` | UA from profile |
| `grant_token(..., device=None)` | `device_id` from profile + matching UA |
| `get_payload(..., device=None)` | field `19` from profile; `None` keeps `Google|uuid4()` |
| `process_account_uid_pass` | `get_or_create(uid)` before OAuth, bind `account_id` after login |
| `create_four_accounts` | `new_profile()` → register/grant/payload → `bind_account(uid, dev)` |
| `account_loop_token` | key `tok_<token[:20]>` |
| after login | one log line `[DEV] <uid> → Samsung SM-E135F / Android 14 / Google|<8>…` |

No other call sites exist (`get_payload` has exactly 5: lines 2601, 2823, 2834,
2861, 3278; all covered).

## Verification

1. `python3 -m py_compile main.py device_profile.py` — syntax.
2. `python3 tests/test_device_profile.py` — determinism, persistence, rotate,
   corrupt-file recovery, UA format, gap-free JSON round-trip.
3. Live: restart → Create Team (2 bots) → check log:
   - `[DEV] 1898... → Samsung SM-E135F / Android 14 / Google|xxxxxxxx…`
   - restart again → **same** `Google|...` prefix for the same UID.
4. `GET /api/devices` returns profiles without secrets.

## Rollback

`cp main.py.bak_audit main.py` (last pre-A1 backup) plus delete
`device_profile.py` / `devices.json` — no schema changes elsewhere.
