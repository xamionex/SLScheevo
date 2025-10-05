#!/usr/bin/env python3
import concurrent.futures
import json
import os
import re
import shutil
import sys
import time
import traceback
import requests
from pathlib import Path

from steam.client import SteamClient
from steam.core.msg import MsgProto
from steam.enums.common import EResult
from steam.enums.emsg import EMsg
from steam.webauth import WebAuth

# Steam Data
STEAM_DIR = Path.home() / '.local/share/Steam'
LIBRARY_FILE = STEAM_DIR / 'steamapps/libraryfolders.vdf'
DEST_DIR = STEAM_DIR / 'appcache/stats'

# Data
DATA_DIR = Path('data')
OUTPUT_DIR = DATA_DIR / Path('bins')
SKIP_FILE = DATA_DIR / 'skip_generation'
NO_ACH_FILE = DATA_DIR / 'no_achievement_games'
ACCOUNTID_FILE = DATA_DIR / Path('accountid.txt')
REFRESH_TOKENS = DATA_DIR / "refresh_tokens.json"

# Steam ids with public profiles that own a lot of games
TOP_OWNER_IDS = [
    76561198028121353, 76561197979911851, 76561198017975643, 76561197993544755,
    76561198355953202, 76561198001237877, 76561198237402290, 76561198152618007,
    76561198355625888, 76561198213148949, 76561197969050296, 76561198217186687,
    76561198037867621, 76561198094227663, 76561198019712127, 76561197963550511,
    76561198134044398, 76561198001678750, 76561197973009892, 76561198044596404,
    76561197976597747, 76561197969810632, 76561198095049646, 76561198085065107,
    76561198864213876, 76561197962473290, 76561198388522904, 76561198033715344,
    76561197995070100, 76561198313790296, 76561198063574735, 76561197996432822,
    76561197976968076, 76561198281128349, 76561198154462478, 76561198027233260,
    76561198842864763, 76561198010615256, 76561198035900006, 76561198122859224,
    76561198235911884, 76561198027214426, 76561197970825215, 76561197968410781,
    76561198104323854, 76561198001221571, 76561198256917957, 76561198008181611,
    76561198407953371, 76561198062901118,
]

def ensure_directories():
    """Create necessary directories"""
    DEST_DIR.mkdir(exist_ok=True, parents=True)

    DATA_DIR.mkdir(exist_ok=True)
    OUTPUT_DIR.mkdir(exist_ok=True)

    # Ensure tracking files exist
    for file in [SKIP_FILE, NO_ACH_FILE]:
        file.touch(exist_ok=True)

def get_account_id(client):
    """Get Steam Account ID directly from logged-in client"""
    if client and hasattr(client, 'steam_id') and client.steam_id:
        account_id = client.steam_id.account_id
        print(f"[✓] Using Account ID from logged-in client: {account_id}")
        return str(account_id)

    print("[✗] No logged-in client available for Account ID")
    return None

def parse_libraryfolders_vdf():
    """Parse libraryfolders.vdf to extract app IDs"""
    if not LIBRARY_FILE.exists():
        print(f"Error: Steam library file not found at {LIBRARY_FILE}")
        sys.exit(1)

    print(f"Reading Steam library from: {LIBRARY_FILE}")

    content = LIBRARY_FILE.read_text()
    # Extract all app IDs using regex
    app_ids = set(re.findall(r'"apps"\s*{([^}]+)}', content, re.DOTALL))
    app_ids = set(re.findall(r'"(\d+)"\s*"', ''.join(app_ids)))

    return sorted([int(app_id) for app_id in app_ids if app_id.isdigit()])

def read_tracking_file(file_path):
    """Read tracking file and return set of app IDs"""
    if not file_path.exists():
        return set()
    return set(int(line.strip()) for line in file_path.read_text().splitlines() if line.strip().isdigit())

def get_stats_schema(client, game_id, owner_id):
    """Get the stats schema for a game from a specific owner"""
    message = MsgProto(EMsg.ClientGetUserStats)
    message.body.game_id = game_id
    message.body.schema_local_version = -1
    message.body.crc_stats = 0
    message.body.steam_id_for_user = owner_id

    client.send(message)
    return client.wait_msg(EMsg.ClientGetUserStatsResponse, timeout=5)

def check_single_owner(args, client):
    """Check a single owner for stats schema"""
    game_id, owner_id = args
    print(f"    → Requesting stats schema for {game_id} using owner {owner_id}")
    try:
        out = get_stats_schema(client, game_id, owner_id)

        if out is not None and len(out.body.schema) > 0:
            schema = out.body.schema
            print(f"    ✓ Got schema ({len(schema)} bytes) from owner {owner_id}")
            return schema
        else:
            print(f"    – Empty schema for owner {owner_id}")
    except Exception as e:
        print(f"    ✗ Exception for owner {owner_id}: {e}")
        traceback.print_exc()
    return None

def generate_stats_schema_bin_parallel(game_id, account_id, client=None):
    """Generate stats schema files using an existing logged-in SteamClient"""
    print(f"\n[→] Generating stats schema for game ID {game_id}")

    # Use existing client if provided
    if not client:
        client = steam_login()
        if not client:
            print("[✗] Aborting schema generation - not logged in")
            return False
        should_logout = True
    else:
        should_logout = False

    stats_schema_found = None
    found_owner = None

    print(f"[→] Checking {len(TOP_OWNER_IDS)} potential owners")

    for owner_id in TOP_OWNER_IDS:
        schema_data = check_single_owner((game_id, owner_id), client)
        if schema_data:
            stats_schema_found = schema_data
            found_owner = owner_id
            print(f"[✓] Found valid schema using owner {owner_id}")
            break

    if stats_schema_found is None:
        print(f"[✗] No schema found for game {game_id} after checking all owners")
        if should_logout:
            client.logout()
        return False

    try:
        schema_path = OUTPUT_DIR / f'UserGameStatsSchema_{game_id}.bin'
        with open(schema_path, "wb") as f:
            f.write(stats_schema_found)
        print(f"[✓] Saved {schema_path} ({len(stats_schema_found)} bytes)")

        user_path = OUTPUT_DIR / f'UserGameStats_{account_id}_{game_id}.bin'
        with open(user_path, "wb") as f:
            f.write(stats_schema_found)
        print(f"[✓] Saved {user_path} ({len(stats_schema_found)} bytes)")
    except Exception as e:
        print(f"[✗] Error writing schema files: {e}")
        if should_logout:
            client.logout()
        return False

    if should_logout:
        client.logout()
    print(f"[✓] Finished schema generation for game {game_id} (owner {found_owner})")
    return True

def steam_login():
    """Login to Steam using refresh tokens or interactive login"""
    client = SteamClient()

    # File to save/load credentials
    refresh_tokens = {}

    # Load existing tokens
    if REFRESH_TOKENS.exists():
        try:
            with open(REFRESH_TOKENS) as f:
                lf = json.load(f)
                refresh_tokens = lf if isinstance(lf, dict) else {}
        except:
            pass

    # Try environment variables first
    USERNAME = os.environ.get('GSE_CFG_USERNAME', '')
    PASSWORD = os.environ.get('GSE_CFG_PASSWORD', '')

    # If still no username, check saved tokens or prompt
    if not USERNAME:
        users = {i: user for i, user in enumerate(refresh_tokens, 1)}
        if users:
            print("Saved accounts:")
            for i, user in users.items():
                print(f"{i}: {user}")
            try:
                num = int(input("Choose an account to login (0 for new account): "))
                if num > 0:
                    USERNAME = users.get(num)
            except ValueError:
                pass

    # Still no username? ask user
    if not USERNAME:
        print("Didn't find steam account, please log in")
        USERNAME = input("Steam Username: ").strip()

    REFRESH_TOKEN = refresh_tokens.get(USERNAME)

    webauth, result = WebAuth(), None
    prompt_for_unavailable = True

    while result in (
        EResult.TryAnotherCM, EResult.ServiceUnavailable,
        EResult.InvalidPassword, None):

        if result in (EResult.TryAnotherCM, EResult.ServiceUnavailable):
            if prompt_for_unavailable and result == EResult.ServiceUnavailable:
                while True:
                    answer = input("Steam is down. Keep retrying? [y/n]: ").lower()
                    if answer in 'yn':
                        break

                prompt_for_unavailable = False
                if answer == 'n':
                    break

            client.reconnect(maxdelay=15)
        elif result == EResult.InvalidPassword:
            print("✗ Invalid password or refresh_token.")
            print(f"Correct the password or delete '{REFRESH_TOKENS}' and try again.")
            return None

        if not REFRESH_TOKEN:
            try:
                if not PASSWORD:
                    PASSWORD = input("Steam Password: ").strip()
                webauth.cli_login(USERNAME, PASSWORD)
            except Exception as e:
                print(f'✗ Login failed: {e}')
                return None

            USERNAME, PASSWORD = webauth.username, webauth.password
            REFRESH_TOKEN = webauth.refresh_token

        result = client.login(USERNAME, PASSWORD, REFRESH_TOKEN)

    # Save refresh token for future use
    if REFRESH_TOKEN:
        refresh_tokens[USERNAME] = REFRESH_TOKEN
        try:
            with open(REFRESH_TOKENS, 'w') as f:
                json.dump(refresh_tokens, f, indent=4)
            print(f"✓ Saved login token for {USERNAME}")
        except Exception as e:
            print(f"Warning: Could not save login token: {e}")

    if result == EResult.OK:
        print("[✓] Logged into Steam successfully")
        # Add our own account ID to the top of the owner list
        if client.steam_id:
            our_id = client.steam_id.as_64
            if our_id not in TOP_OWNER_IDS:
                TOP_OWNER_IDS.insert(0, our_id)
                print(f"[→] Added our account ID ({our_id}) to owner list")
        return client
    else:
        print(f"[✗] Steam login failed: {result.name}")
        return None

def main():
    ensure_directories()

    # Login first to get client
    client = steam_login()
    if not client:
        print("[✗] Failed to login to Steam")
        sys.exit(1)

    # Get account ID from logged-in client (no file dependency)
    account_id = get_account_id(client)
    if not account_id:
        print("[✗] Could not retrieve account ID")
        client.logout()
        sys.exit(1)

    # Parse Steam library
    all_app_ids = parse_libraryfolders_vdf()
    if not all_app_ids:
        print("No app IDs found in library file.")
        sys.exit(1)

    print(f"Found {len(all_app_ids)} games in library")

    # Read tracking files
    skip_generation = read_tracking_file(SKIP_FILE)
    no_achievements = read_tracking_file(NO_ACH_FILE)

    # Find missing app IDs
    missing_app_ids = []
    for app_id in all_app_ids:
        if app_id in no_achievements:
            continue  # doesn't have achievements
        if app_id in skip_generation:
            continue  # explicitly skipped

        # Check if schema file already exists in backup or destination
        schema_file = f"UserGameStats_{account_id}_{app_id}.bin"
        if (OUTPUT_DIR / schema_file).exists() or (DEST_DIR / schema_file).exists():
            continue

        missing_app_ids.append(app_id)

    if not missing_app_ids:
        print("All games already have stats schema files or are skipped. Nothing to do.")
        client.logout()
        return

    print(f"Found {len(missing_app_ids)} games missing stats schema files")
    print(f"Missing app IDs: {missing_app_ids}")
    print()

    # Generate stats schema for each missing app ID
    successful_generations = 0
    for app_id in missing_app_ids:
        print(f"Generating stats schema for appid {app_id}...")

        if generate_stats_schema_bin_parallel(app_id, account_id, client):
            successful_generations += 1
            print(f"[✓] Successfully generated stats schema for appid {app_id}")
        else:
            # Mark as skipped
            with open(SKIP_FILE, 'a') as f:
                f.write(f"{app_id}\n")
            print(f"[✗] Failed to generate stats schema for appid {app_id}")

    # Cleanup
    client.logout()

    print(f"Done! Generated stats schema files for {successful_generations} out of {len(missing_app_ids)} games.")

if __name__ == "__main__":
    main()
