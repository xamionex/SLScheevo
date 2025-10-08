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
import platform
import itertools
import threading
from pathlib import Path

from steam.client import SteamClient
from steam.core.msg import MsgProto
from steam.enums.common import EResult
from steam.enums.emsg import EMsg
from steam.webauth import WebAuth
from concurrent.futures import ThreadPoolExecutor, as_completed

# Determine Steam base directory
if platform.system() == "Windows":
    # Default Windows install path
    STEAM_DIR = Path("C:/Program Files (x86)/Steam")
else:
    STEAM_DIR = Path.home() / ".local/share/Steam"

LIBRARY_FILE = STEAM_DIR / "steamapps/libraryfolders.vdf"
LOGIN_FILE = STEAM_DIR / "config/loginusers.vdf"
DEST_DIR = STEAM_DIR / "appcache/stats"

# Data
DATA_DIR = Path("data")
OUTPUT_DIR = DATA_DIR / "bins"
SKIP_FILE = DATA_DIR / "skip_generation.txt"
NO_ACH_FILE = DATA_DIR / "no_achievement_games.txt"
MAX_TRIES_FILE = DATA_DIR / "maximum_tries.txt"
REFRESH_TOKENS = DATA_DIR / "refresh_tokens.json"
TEMPLATE_FILE = DATA_DIR / "UserGameStats_TEMPLATE.bin"

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

def get_maximum_tries():
    """Read maximum tries from file or create default file with value 5"""
    max_tries = 5
    try:
        if MAX_TRIES_FILE.exists():
            with open(MAX_TRIES_FILE, 'r') as f:
                content = f.read().strip()
                if content.isdigit():
                    max_tries = int(content)
                    print(f"[→] Using maximum tries from file: {max_tries}")
                else:
                    print(f"[!] Invalid content in {MAX_TRIES_FILE}, using default value: {max_tries}")
        else:
            # Create the file with default value 5
            with open(MAX_TRIES_FILE, 'w') as f:
                f.write("5")
            print(f"[→] Created {MAX_TRIES_FILE} with default value: {max_tries}")
    except Exception as e:
        print(f"[!] Error reading maximum_tries file: {e}, using default value: {max_tries}")

    return max_tries

def get_account_id(client):
    """Get Steam Account ID directly from logged-in client"""
    if client and hasattr(client, 'steam_id') and client.steam_id:
        account_id = client.steam_id.account_id
        print(f"[✓] Using Account ID from logged-in client: {account_id}")
        return str(account_id)

    print("[✗] No logged-in client available for Account ID")
    return None

def get_steam_id64(client):
    """Get Steam Steam ID64 directly from logged-in client"""
    if client and hasattr(client, 'steam_id') and client.steam_id:
        steam_id64 = client.steam_id.as_64
        print(f"[✓] Using Steam ID64 from logged-in client: {steam_id64}")
        return str(steam_id64)

    print("[✗] No logged-in client available for Steam ID64")
    return None

def parse_libraryfolders_vdf():
    """Parse libraryfolders.vdf to extract app IDs"""
    if not LIBRARY_FILE.exists():
        print(f"[✗] Steam library file not found at {LIBRARY_FILE}")
        sys.exit(1)

    print(f"[→] Reading Steam library from: {LIBRARY_FILE}")

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
    """Request the stats schema for a game from a specific owner"""
    msg = MsgProto(EMsg.ClientGetUserStats)
    msg.body.game_id = game_id
    msg.body.schema_local_version = -1
    msg.body.crc_stats = 0
    msg.body.steam_id_for_user = owner_id

    client.send(msg)
    return client.wait_msg(EMsg.ClientGetUserStatsResponse, timeout=5)

def check_single_owner(game_id, owner_id, client):
    """Return schema bytes or None"""
    try:
        out = get_stats_schema(client, game_id, owner_id)
        if out and hasattr(out.body, "schema") and out.body.schema:
            if len(out.body.schema) > 0:
                return out.body.schema
        # Check for the specific "no schema" response pattern
        elif (out and hasattr(out.body, 'eresult') and out.body.eresult == 2 and
              hasattr(out.body, 'crc_stats') and out.body.crc_stats == 0):
            return "NO_SCHEMA"  # Special indicator for no schema
    except Exception as e:
        print(f"\n    [✗] Exception for owner {owner_id}: {e}")
        traceback.print_exc(limit=1)
    return None

def generate_stats_schema_bin(game_id, account_id, max_no_schema_in_row, client=None):
    """Generate stats and schema files with no-schema detection"""
    print(f"\n[→] Generating stats schema for game ID {game_id}")

    should_logout = False
    if not client:
        client = steam_login()
        if not client:
            print("[✗] Aborting schema generation - not logged in")
            return False
        should_logout = True

    total_owners = len(TOP_OWNER_IDS)
    print(f"[→] Checking {total_owners} potential owners")

    stats_schema_found = None
    found_owner = None
    no_schema_count = 0

    spinner = itertools.cycle("|/-\\")
    for i, owner_id in enumerate(TOP_OWNER_IDS, start=1):
        sys.stdout.write(f"\r[{next(spinner)}] Checked {i-1}/{total_owners} owners... (no-schema streak: {no_schema_count}/{max_no_schema_in_row})")
        sys.stdout.flush()

        schema_data = check_single_owner(game_id, owner_id, client)

        if schema_data == "NO_SCHEMA":
            no_schema_count += 1
            # If we get too many "no schema" responses in a row, abort early
            if no_schema_count >= max_no_schema_in_row:
                break
        elif schema_data and schema_data != "NO_SCHEMA":
            stats_schema_found = schema_data
            found_owner = owner_id
            sys.stdout.write(f"\r[✓] Found valid schema using owner {owner_id} ({i}/{total_owners})\n")
            sys.stdout.flush()
            break
        else:
            # Reset counter if we get a different type of response (error, timeout, etc.)
            no_schema_count = 0

        time.sleep(0.1)  # small delay to avoid hammering Steam's API

    if not stats_schema_found:
        if no_schema_count >= max_no_schema_in_row:
            sys.stdout.write(f"\r[✗] No schema available for game {game_id} ({max_no_schema_in_row} consecutive 'no schema' responses)\n")
            sys.stdout.flush()
        else:
            sys.stdout.write(f"\r[✗] No schema found for game {game_id} after checking {total_owners} owners\n")
            sys.stdout.flush()

        if should_logout:
            client.logout()
        return False

    try:
        schema_path = OUTPUT_DIR / f"UserGameStatsSchema_{game_id}.bin"
        with open(schema_path, "wb") as f:
            f.write(stats_schema_found)
        print(f"[✓] Saved {schema_path} ({len(stats_schema_found)} bytes)")

        user_path = OUTPUT_DIR / f"UserGameStats_{account_id}_{game_id}.bin"
        shutil.copyfile(TEMPLATE_FILE, user_path)
        print(f"[✓] Copied template to {user_path} ({TEMPLATE_FILE.stat().st_size} bytes)")
    except Exception as e:
        print(f"[✗] Error writing schema files: {e}")
        if should_logout:
            client.logout()
        return False

    if should_logout:
        client.logout()

    print(f"[✓] Finished schema generation for game {game_id} (owner {found_owner})")
    return True

def parse_loginusers_vdf():
    """Return a list of all account names from loginusers.vdf"""
    if not LOGIN_FILE.exists():
        return []

    content = LOGIN_FILE.read_text(encoding="utf-8", errors="ignore")

    # Match all account entries
    users = re.findall(
        r'"(\d+)"\s*{\s*[^}]*?"AccountName"\s*"([^"]+)"',
        content,
        re.DOTALL
    )

    return [name for _, name in users]

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
        except Exception:
            pass

    # Try environment variables first
    USERNAME = os.environ.get('USERNAME', '')
    PASSWORD = os.environ.get('PASSWORD', '')

    # Try to get account list from loginusers.vdf if no username provided
    if not USERNAME:
        vdf_users = parse_loginusers_vdf()
        saved_users = list(refresh_tokens.keys())

        # Merge and deduplicate, preserving order
        all_users = list(dict.fromkeys(saved_users + vdf_users))

        if all_users:
            print("[→] Available accounts:")
            for i, user in enumerate(all_users, 1):
                print(f"[{i}]: {user}")
            try:
                num = int(input("[→] Choose an account to login (0 for new account): "))
                if 0 < num <= len(all_users):
                    USERNAME = all_users[num - 1]
            except ValueError:
                pass

    # Still no username? ask user
    if not USERNAME:
        print("[!] No Steam accounts found, please log in manually")
        USERNAME = input("[→] Steam Username: ").strip()

    REFRESH_TOKEN = refresh_tokens.get(USERNAME)
    webauth, result = WebAuth(), None
    prompt_for_unavailable = True

    while result in (
        EResult.TryAnotherCM, EResult.ServiceUnavailable,
        EResult.InvalidPassword, None):

        if result in (EResult.TryAnotherCM, EResult.ServiceUnavailable):
            if prompt_for_unavailable and result == EResult.ServiceUnavailable:
                while True:
                    answer = input("[!] Steam is down. Keep retrying? [y/n]: ").lower()
                    if answer in 'yn':
                        break

                prompt_for_unavailable = False
                if answer == 'n':
                    break

            client.reconnect(maxdelay=15)
        elif result == EResult.InvalidPassword:
            print("[✗] Invalid password or refresh_token.")
            print(f"[!] Correct the password or delete '{REFRESH_TOKENS}' and try again.")
            return None

        if not REFRESH_TOKEN:
            try:
                if not PASSWORD:
                    PASSWORD = input("[→] Steam Password: ").strip()
                webauth.cli_login(USERNAME, PASSWORD)
            except Exception as e:
                print(f'[✗] Login failed: {e}')
                return None

            USERNAME, PASSWORD = webauth.username, webauth.password
            REFRESH_TOKEN = webauth.refresh_token

        result = client.login(USERNAME, PASSWORD, REFRESH_TOKEN)

    # Save refresh token
    if REFRESH_TOKEN:
        refresh_tokens[USERNAME] = REFRESH_TOKEN
        try:
            with open(REFRESH_TOKENS, 'w') as f:
                json.dump(refresh_tokens, f, indent=4)
            print(f"[✓] Saved login token for {USERNAME}")
        except Exception as e:
            print(f"[✗] Could not save login token: {e}")

    if result == EResult.OK:
        print("[✓] Logged into Steam successfully")
        # Add our own account ID to the top of the owner list
        if client.steam_id:
            steam_id64 = client.steam_id.as_64
            if steam_id64 not in TOP_OWNER_IDS:
                TOP_OWNER_IDS.insert(0, steam_id64)
                print(f"[→] Added your account ({steam_id64}) to owner list")
        return client
    else:
        print(f"[✗] Steam login failed: {result.name}")
        return None

def copy_bins_to_steam_stats():
    """
    Copies all files from bins/* to the Steam appcache/stats directory
    for the given Steam ID64.
    """
    # Destination stats folder per user
    # dest_dir = steam_dir / "userdata" / steam_id64 / "config" / "stats"
    DEST_DIR.mkdir(parents=True, exist_ok=True)

    if not OUTPUT_DIR.exists():
        print(f"[✗] Source directory {OUTPUT_DIR} does not exist. Skipped copying")
        return

    files_copied = 0
    for file_path in OUTPUT_DIR.glob("*"):
        if not file_path.is_file():
            continue

        if files_copied == 0:
            print()

        dest_path = DEST_DIR / file_path.name

        # Schema files: always overwrite
        if file_path.name.startswith("UserGameStatsSchema_"):
            try:
                shutil.copy2(file_path, dest_path)
                files_copied += 1
                print(f"[✓] Overwrote Schema File: {file_path} -> {dest_path}")
            except Exception as e:
                print(f"[✗] Failed to copy schema {file_path} -> {dest_path}: {e}")

        # User stats files: only copy if not already present
        elif file_path.name.startswith("UserGameStats_"):
            if dest_path.exists():
                print(f"[!] Stats file already exists: {dest_path}")
                continue
            try:
                shutil.copy2(file_path, dest_path)
                files_copied += 1
                print(f"[✓] Copied Stats File: {file_path} -> {dest_path}")
            except Exception as e:
                print(f"[✗] Failed to copy stats {file_path} -> {dest_path}: {e}")

    if files_copied > 0:
        print(f"\n[✓] Copied {files_copied} files to {DEST_DIR}")

def main():
    # Clear term from building process
    os.system('cls||clear')

    ensure_directories()
    max_no_schema_in_row = get_maximum_tries()

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
        
    # Get account ID64 from logged-in client (no file dependency)
    steam_id64 = get_steam_id64(client)
    if not steam_id64:
        print("[✗] Could not retrieve account ID64")
        client.logout()
        sys.exit(1)

    # Parse Steam library
    all_app_ids = parse_libraryfolders_vdf()
    if not all_app_ids:
        print("[✗] No app IDs found in library file.")
        sys.exit(1)

    print(f"[✓] Found {len(all_app_ids)} games in library")

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
        print("[!] All games already have stats schema files or are skipped. Nothing to do.")
        client.logout()
        return

    print(f"[✓] Found {len(missing_app_ids)} games missing stats schema files")
    print(f"[!] Missing app IDs: {missing_app_ids}")

    # Generate stats schema for each missing app ID
    successful_generations = 0
    for app_id in missing_app_ids:
        if generate_stats_schema_bin(app_id, account_id, max_no_schema_in_row, client):
            successful_generations += 1
            print(f"[✓] Successfully generated stats schema for appid {app_id}")
        else:
            # Mark as skipped
            with open(SKIP_FILE, 'a') as f:
                f.write(f"{app_id}\n")
            print(f"[✗] Added {app_id} to skip_generation.txt")

    copy_bins_to_steam_stats()

    # Cleanup
    client.logout()

    print(f"\n[✓] Done! Generated stats schema files for {successful_generations} out of {len(missing_app_ids)} games.")

if __name__ == "__main__":
    main()
