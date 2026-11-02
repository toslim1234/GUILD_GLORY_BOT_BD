"""Read-only EXP/level probe for PVT_GUILD_GLORY.

Does NOT touch main.py and does NOT start the bot. It reuses main.py's
functions so the measurement uses the exact same code path as the bot.

Usage (on the same machine where the bot runs, while the bot is running
so token_cache.json is fresh):
    python3 exp_probe.py

Run it once, play 2-3 matches, run it again. Compare the two outputs:
  - exp/current_exp unchanged after matches  -> server is not granting EXP
    (protocol gap, candidate A).
  - exp increases but level stays the same   -> EXP is granted but too small
    per match (candidate B).
  - level increases                         -> level-up works; check why the
    dashboard did not show it.
"""
import asyncio
import os
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

import main as M  # noqa: E402  (imports only; __main__ guard prevents running)


async def main():
    cache = M._load_token_cache()
    if not cache:
        print("No token cache found. Run the bot first so token_cache.json is fresh.")
        return

    now = time.time()
    for uid, ad in cache.items():
        print("=" * 60)
        print(f"UID {uid}  (account {ad.get('account_id')})")
        cached_at = ad.get("cached_at", 0)
        age = now - cached_at
        print(f"  cache age: {age:.0f}s  (TTL {M.TOKEN_CACHE_TTL}s)")
        if age > M.TOKEN_CACHE_TTL:
            print("  -> cache expired; skip (bot must refresh it)")
            continue

        # Make sure login_payload_data is bytes (cache stores it as hex dict).
        lp = ad.get("login_payload_data")
        if isinstance(lp, dict) and "__bytes_hex__" in lp:
            try:
                ad["login_payload_data"] = bytes.fromhex(lp["__bytes_hex__"])
            except Exception as e:
                print(f"  -> could not decode login_payload_data: {e}")

        aid = str(ad.get("account_id"))
        before = M.bot_state.accounts.get(aid, {})
        print(f"  BEFORE: level={before.get('level', ad.get('level'))} "
              f"exp={before.get('current_exp', ad.get('exp'))} "
              f"gained={before.get('gained_exp', 0)}")

        try:
            await M.refresh_account_profile(ad)
        except Exception as e:
            print(f"  refresh error: {e}")

        after = M.bot_state.accounts.get(aid, {})
        print(f"  AFTER : level={after.get('level', ad.get('level'))} "
              f"exp={after.get('current_exp', ad.get('exp'))} "
              f"gained={after.get('gained_exp', 0)}")

        # Also print the raw two sources for transparency.
        try:
            show = await M.get_player_personal_show(
                int(ad["account_id"]), ad["token"], ad["server_url"],
                ad["release_version"])
            print(f"  GetPlayerPersonalShow: {show}")
        except Exception as e:
            print(f"  GetPlayerPersonalShow error: {e}")
        try:
            lp2 = ad.get("login_payload_data")
            if lp2:
                ld = await M.get_login_data(lp2, ad["token"], ad["server_url"],
                                           ad["release_version"])
                print(f"  GetLoginData        : {ld}")
        except Exception as e:
            print(f"  GetLoginData error: {e}")


if __name__ == "__main__":
    asyncio.run(main())