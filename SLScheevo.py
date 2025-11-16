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
import base64
import subprocess
import uuid
import getpass
import hashlib
import argparse
import logging
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from steam.client import SteamClient
from steam.core.msg import MsgProto
from steam.enums.common import EResult
from steam.enums.emsg import EMsg
from steam.webauth import WebAuth
from concurrent.futures import ThreadPoolExecutor, as_completed

# Exit codes
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_LOGIN_FAILED = 2
EXIT_NO_ACCOUNT_ID = 3
EXIT_NO_APP_IDS = 4
EXIT_INPUT_REQUIRED = 5
EXIT_NO_SCHEMA_FOUND = 6
EXIT_FILE_ERROR = 7
EXIT_STEAM_NOT_FOUND = 8
EXIT_TOKEN_ERROR = 9
EXIT_NO_ACTIONS = 10
EXIT_NOT_SUPPORTED = 11
EXIT_FAILED_TO_GET_HWID = 12
EXIT_NO_ACCOUNT_SPECIFIED = 13
EXIT_FAILED_TO_PARSE_ID = 14

# Data
BASE_DIR = Path(os.path.dirname(os.path.abspath(sys.argv[0])))
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = DATA_DIR / "bins"
SKIP_FILE = DATA_DIR / "skip_generation.txt"
NO_ACH_FILE = DATA_DIR / "no_achievement_games.txt"
MAX_TRIES_FILE = DATA_DIR / "maximum_tries.txt"
SAVED_LOGINS_FILE = DATA_DIR / "saved_logins.encrypted"
LAST_ACCOUNT_FILE = DATA_DIR / "last_account.txt"
TEMPLATE_FILE = DATA_DIR / "UserGameStats_TEMPLATE.bin"
LOG_FILE = DATA_DIR / "slscheevo.log"
SILENT_MODE = False
VERBOSE = False

# Steam Path Vars
STEAM_DIR = None
LIBRARY_FILE = None
LOGIN_FILE = None
DEST_DIR = None

class ConsoleFormatter(logging.Formatter):
    """Formatter for console without timestamps"""
    SYMBOLS = {
        'SUCCESS': "[✓] ",
        'INFO': "[→] ",
        'WARNING': "[!] ",
        'ERROR': "[✗] "
    }

    def format(self, record):
        symbol = ""

        if hasattr(record, "custom_level"):
            symbol = self.SYMBOLS.get(record.custom_level, "")
        elif record.levelname == "INFO":
            symbol = "[→] "

        return f"{symbol}{record.getMessage()}"

def setup_logging():
    """Setup logging to both console and file"""
    DATA_DIR.mkdir(exist_ok=True, parents=True)

    # Create logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Clear any existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # File handler with timestamps
    file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    file_formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # Console handler without timestamps and UTF-8 encoding
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_formatter = ConsoleFormatter()
    console_handler.setFormatter(console_formatter)

    # Force UTF-8 encoding for console output
    if hasattr(console_handler, 'setStream'):
        import io
        console_handler.setStream(io.TextIOWrapper(
            console_handler.stream.detach(),
            encoding='utf-8',
            errors='replace'
        ))

    logger.addHandler(console_handler)

def log_base(message):
    """Log message without any symbols"""
    logger = logging.getLogger()
    if logger.isEnabledFor(logging.INFO):
        record = logging.LogRecord(
            name=__name__,
            level=logging.INFO,
            pathname=__file__,
            lineno=0,
            msg=message,
            args=None,
            exc_info=None
        )
        record.custom_level = 'BASE'
        logger.handle(record)

def log_info(message):
    """Log info message with [→] symbol"""
    logger = logging.getLogger()
    if logger.isEnabledFor(logging.INFO):
        record = logging.LogRecord(
            name=__name__,
            level=logging.INFO,
            pathname=__file__,
            lineno=0,
            msg=message,
            args=None,
            exc_info=None
        )
        record.custom_level = 'INFO'
        logger.handle(record)

def log_success(message):
    """Log success message with [✓] symbol"""
    logger = logging.getLogger()
    if logger.isEnabledFor(logging.INFO):
        record = logging.LogRecord(
            name=__name__,
            level=logging.INFO,
            pathname=__file__,
            lineno=0,
            msg=message,
            args=None,
            exc_info=None
        )
        record.custom_level = 'SUCCESS'
        logger.handle(record)

def log_error(message):
    """Log error message with [✗] symbol"""
    logger = logging.getLogger()
    if logger.isEnabledFor(logging.ERROR):
        record = logging.LogRecord(
            name=__name__,
            level=logging.ERROR,
            pathname=__file__,
            lineno=0,
            msg=message,
            args=None,
            exc_info=None
        )
        record.custom_level = 'ERROR'
        logger.handle(record)

def log_warning(message):
    """Log warning message with [!] symbol"""
    logger = logging.getLogger()
    if logger.isEnabledFor(logging.WARNING):
        record = logging.LogRecord(
            name=__name__,
            level=logging.WARNING,
            pathname=__file__,
            lineno=0,
            msg=message,
            args=None,
            exc_info=None
        )
        record.custom_level = 'WARNING'
        logger.handle(record)

def install_global_exception_logger():
    """Catch all unhandled exceptions and log them before exiting."""

    def handle_exception(exc_type, exc_value, exc_traceback):
        logger = logging.getLogger()

        if issubclass(exc_type, KeyboardInterrupt):
            # Don't log Ctrl+C as an error
            logger.info("Interrupted by user (KeyboardInterrupt).")
            return

        # Log full traceback to file
        logger.error("UNHANDLED EXCEPTION OCCURRED!", exc_info=(exc_type, exc_value, exc_traceback))

        # Also log a clean message to the console
        log_error(f"Unhandled crash: {exc_value}")

    sys.excepthook = handle_exception

def prompt(msg: str) -> str:
    """Log a prompt with [→] but keep input on same line."""
    # Get the formatted prefix from the logger (e.g. "[→] ")
    prefix = ConsoleFormatter.SYMBOLS.get("INFO", "[→] ")

    # Print prefix and message WITHOUT newline
    print(f"{prefix}{msg} ", end="", flush=True)

    # Now take input
    return input()

def determine_steam_directory():
    global STEAM_DIR, LIBRARY_FILE, LOGIN_FILE, DEST_DIR

    if platform.system() == "Windows":
        try:
            import winreg
    
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam")
            steam_path, _ = winreg.QueryValueEx(key, "SteamPath")
            winreg.CloseKey(key)
            log_info(f"Found Steam installation at: {steam_path}")
            STEAM_DIR = Path(os.path.normpath(steam_path))
        except Exception:
            log_error("Failed to read Steam path from registry.")
            sys.exit(EXIT_STEAM_NOT_FOUND)
    else:
        native_path = Path.home() / ".local/share/Steam"
        flatpak_path = Path.home() / ".var/app/com.valvesoftware.Steam/.local/share/Steam"

        native_exists = native_path.exists()
        flatpak_exists = flatpak_path.exists()

        if native_exists and flatpak_exists:
            if SILENT_MODE:
                STEAM_DIR = native_path
            else:
                log_base("Found both native and Flatpak Steam installations:")
                log_base(f"[1] Native: {native_path}")
                log_base(f"[2] Flatpak: {flatpak_path}")
                while True:
                    try:
                        choice = int(input("Which one to use? (1/2): "))
                        if choice == 1:
                            STEAM_DIR = native_path
                            break
                        elif choice == 2:
                            STEAM_DIR = flatpak_path
                            break
                        else:
                            log_base("Invalid input, please enter 1 or 2.")
                    except ValueError:
                        log_base("Invalid input, please enter 1 or 2.")
        elif native_exists:
            STEAM_DIR = native_path
        elif flatpak_exists:
            STEAM_DIR = flatpak_path
        else:
            log_error("No Steam installation found.")
            sys.exit(EXIT_STEAM_NOT_FOUND)

    if not STEAM_DIR.exists():
        log_error(f"Steam directory does not exist at '{STEAM_DIR}'. Please report this issue")
        sys.exit(EXIT_STEAM_NOT_FOUND)

    # Set the dependent paths
    LIBRARY_FILE = STEAM_DIR / "config/libraryfolders.vdf"
    LOGIN_FILE = STEAM_DIR / "config/loginusers.vdf"
    DEST_DIR = STEAM_DIR / "appcache/stats"

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

STEAMID64_BASE = 76561197960265728  # Valve's base offset for public Steam64 IDs

def steamid64_from_account_id(account_id: int) -> int:
    """Convert AccountID (32-bit) to public SteamID64"""
    return STEAMID64_BASE + account_id

def account_id_from_steamid64(steamid64: int) -> int:
    """Extract 32-bit AccountID from public Steam64"""
    return steamid64 - STEAMID64_BASE

def parse_steam_id(identifier: str):
    identifier = identifier.strip()
    account_id = None
    steam_id64 = None

    # Steam2 ID: STEAM_X:Y:Z
    if identifier.upper().startswith('STEAM_'):
        try:
            steam_prefix, y, z = identifier.split(':')
            universe = int(steam_prefix.split('_')[1])
            y = int(y)
            z = int(z)
            account_id = (z << 1) | y
            steam_id64 = steamid64_from_account_id(account_id)
        except Exception as e:
            log_error(f"Failed to parse Steam2 ID ({identifier}): {e}")
            sys.exit(EXIT_FAILED_TO_PARSE_ID)

    # Steam3 ID: [U:1:ACCOUNT_ID]
    elif identifier.startswith('[U:') and identifier.endswith(']'):
        try:
            parts = identifier[1:-1].split(':')
            account_id = int(parts[-1])
            steam_id64 = steamid64_from_account_id(account_id)
        except Exception as e:
            log_error(f"Failed to parse Steam3 ID ({identifier}): {e}")
            sys.exit(EXIT_FAILED_TO_PARSE_ID)

    # Pure numeric input
    elif identifier.isdigit():
        num = int(identifier)
        try:
            if num >= 76561197960265728:  # Steam64 (public)
                account_id = account_id_from_steamid64(num)
                steam_id64 = num
            elif num <= 4294967295:  # 32-bit AccountID
                account_id = num
                steam_id64 = steamid64_from_account_id(num)
            else:
                sys.exit(EXIT_FAILED_TO_PARSE_ID)
                log_error(f"Invalid numeric Steam ID range: {num}")
        except Exception as e:
            sys.exit(EXIT_FAILED_TO_PARSE_ID)
            log_error(f"Failed to parse numeric ID ({identifier}): {e}")

    return (
        str(account_id) if account_id is not None else None,
        str(steam_id64) if steam_id64 is not None else None
    )

def get_hwid():
    """Get Hardware ID that works on both Linux and Windows, with robust fallbacks."""
    system = platform.system()

    if system == "Windows":
        wmic_path = Path(r"C:\Windows\System32\wbem\wmic.exe")

        # Try WMIC if it exists
        if wmic_path.exists():
            try:
                result = subprocess.check_output(
                    'wmic csproduct get UUID',
                    shell=True,
                    stderr=subprocess.DEVNULL,
                    text=True
                )
                lines = [line.strip() for line in result.split('\n') if line.strip()]
                if len(lines) > 1 and lines[1]:
                    return lines[1]
            except Exception:
                pass  # fallback to PowerShell if WMIC fails

        # Fallback: PowerShell
        try:
            result = subprocess.check_output(
                'powershell -Command "Get-CimInstance Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID"',
                shell=True,
                stderr=subprocess.DEVNULL,
                text=True
            ).strip()
            if result:
                return result
        except Exception:
            pass

        log_error("Failed to retrieve HWID on Windows.")
        sys.exit(EXIT_FAILED_TO_GET_HWID)

    elif system == "Linux":
        # Linux: Try machine-id first
        try:
            with open("/etc/machine-id", "r") as f:
                machine_id = f.read().strip()
                if machine_id:
                    return machine_id
        except Exception:
            pass
        log_error("Failed to retrieve machine ID on Linux.")
        sys.exit(EXIT_FAILED_TO_GET_HWID)

    else:
        log_error(f"Unsupported platform: {system}")
        sys.exit(EXIT_NOT_SUPPORTED)

def derive_key():
    """Derive a Fernet key for encryption"""
    system_user = getpass.getuser()
    hwid = get_hwid()

    combined_secret = f"{system_user}:{hwid}"

    salt_prefix = b"steam_stats_salt_"
    salt = hashlib.sha256(salt_prefix + hwid.encode("utf-8")).digest()  # 32 bytes

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(combined_secret.encode("utf-8")))
    return key

def encrypt_saved_logins(logins_dict):
    """Encrypt saved logins"""
    try:
        key = derive_key()
        fernet = Fernet(key)

        # Convert dict to JSON string and encrypt
        logins_json = json.dumps(logins_dict)
        encrypted_data = fernet.encrypt(logins_json.encode())

        return encrypted_data
    except Exception as e:
        log_error(f"Error encrypting logins: {e}")
        return None

def decrypt_saved_logins(encrypted_data):
    """Decrypt saved logins"""
    try:
        key = derive_key()
        fernet = Fernet(key)

        # Decrypt and parse JSON
        decrypted_data = fernet.decrypt(encrypted_data)
        logins_dict = json.loads(decrypted_data.decode())

        return logins_dict
    except Exception as e:
        log_error(f"Error decrypting logins: {e}")
        return {}

def migrate_old_tokens_to_new_format():
    """Migrate old token files to new saved_logins format"""
    old_files = [
        DATA_DIR / "refresh_tokens.encrypted",
        DATA_DIR / "refresh_tokens.json"
    ]

    migrated = False
    new_logins = {}

    for old_file in old_files:
        if old_file.exists():
            try:
                if old_file.suffix == ".encrypted":
                    # Try to decrypt old format
                    with open(old_file, 'rb') as f:
                        encrypted_data = f.read()

                    # Use old derive_key function (same as before)
                    key = derive_key()
                    fernet = Fernet(key)
                    decrypted_data = fernet.decrypt(encrypted_data)
                    old_tokens = json.loads(decrypted_data.decode())

                    # Convert to new format
                    for username, refresh_token in old_tokens.items():
                        account_id, steam_id64 = parse_steam_id(username)
                        if account_id and steam_id64:
                            new_logins[steam_id64] = {
                                "username": username,
                                "refresh_token": refresh_token,
                                "account_id": account_id,
                                "steam_id64": steam_id64
                            }
                        else:
                            # If we can't parse as ID, keep as username
                            new_logins[username] = {
                                "username": username,
                                "refresh_token": refresh_token,
                                "account_id": None,
                                "steam_id64": None
                            }

                elif old_file.suffix == ".json":
                    # Plaintext JSON
                    with open(old_file, 'r') as f:
                        old_tokens = json.load(f)

                    # Convert to new format
                    for username, refresh_token in old_tokens.items():
                        account_id, steam_id64 = parse_steam_id(username)
                        if account_id and steam_id64:
                            new_logins[steam_id64] = {
                                "username": username,
                                "refresh_token": refresh_token,
                                "account_id": account_id,
                                "steam_id64": steam_id64
                            }
                        else:
                            # If we can't parse as ID, keep as username
                            new_logins[username] = {
                                "username": username,
                                "refresh_token": refresh_token,
                                "account_id": None,
                                "steam_id64": None
                            }

                # Delete old file after migration
                old_file.unlink()
                migrated = True
                log_info(f"Migrated {old_file} to new format")

            except Exception as e:
                log_error(f"Error migrating {old_file}: {e}")

    # Save migrated data
    if migrated and new_logins:
        if save_saved_logins(new_logins):
            log_success("Successfully migrated old tokens to saved_logins.encrypted")
        else:
            log_error("Failed to save migrated tokens")

    return migrated

def load_saved_logins():
    """Load saved logins, handling migration from old format if needed"""
    # Check if migration is needed
    old_files_exist = any([
        (DATA_DIR / "refresh_tokens.encrypted").exists(),
        (DATA_DIR / "refresh_tokens.json").exists()
    ])

    if old_files_exist:
        migrate_old_tokens_to_new_format()

    # Load from new encrypted file
    if SAVED_LOGINS_FILE.exists():
        try:
            with open(SAVED_LOGINS_FILE, 'rb') as f:
                encrypted_data = f.read()

            # Try to decrypt
            logins = decrypt_saved_logins(encrypted_data)
            if logins:
                return logins
            else:
                log_error("Failed to decrypt logins with current system")
                log_error("This might happen if you changed hardware or system user")

        except Exception as e:
            log_error(f"Error loading encrypted logins: {e}")

    return {}

def save_saved_logins(logins_dict):
    """Save logins in encrypted format"""
    encrypted_data = encrypt_saved_logins(logins_dict)
    if encrypted_data:
        try:
            with open(SAVED_LOGINS_FILE, 'wb') as f:
                f.write(encrypted_data)
            return True
        except Exception as e:
            log_error(f"Error saving encrypted logins: {e}")
            sys.exit(EXIT_TOKEN_ERROR)
    return False

def save_last_account(account_identifier):
    """Save the last used account identifier to a file"""
    try:
        with open(LAST_ACCOUNT_FILE, 'w') as f:
            f.write(account_identifier)
        return True
    except Exception as e:
        log_error(f"Error saving last account: {e}")
        return False

def load_last_account():
    """Load the last used account identifier from file"""
    try:
        if LAST_ACCOUNT_FILE.exists():
            with open(LAST_ACCOUNT_FILE, 'r') as f:
                return f.read().strip()
    except Exception as e:
        log_error(f"Error loading last account: {e}")
    return None

def ensure_directories():
    """Create necessary directories"""
    # Ensure Steam destination exists if set
    if DEST_DIR:
        DEST_DIR.mkdir(exist_ok=True, parents=True)

    DATA_DIR.mkdir(exist_ok=True, parents=True)
    OUTPUT_DIR.mkdir(exist_ok=True, parents=True)

    # Ensure tracking files exist
    for file in [SKIP_FILE, NO_ACH_FILE, LAST_ACCOUNT_FILE]:
        file.parent.mkdir(parents=True, exist_ok=True)
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
                    log_info(f"Using maximum tries from file: {max_tries}")
                else:
                    log_error(f"Invalid content in {MAX_TRIES_FILE}, using default value: {max_tries}")
        else:
            # Create the file with default value 5
            MAX_TRIES_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(MAX_TRIES_FILE, 'w') as f:
                f.write("5")
            log_info(f"Created {MAX_TRIES_FILE} with default value: {max_tries}")
    except Exception as e:
        log_error(f"Error reading maximum_tries file: {e}, using default value: {max_tries}")

    return max_tries

def get_account_id(client):
    """Get Steam Account ID directly from logged-in client"""
    if client and hasattr(client, 'steam_id') and client.steam_id:
        account_id = client.steam_id.account_id
        log_success(f"Using Account ID from logged-in client: {account_id}")
        return str(account_id)

    log_error("No logged-in client available for Account ID")
    return None

def get_steam_id64(client):
    """Get Steam Steam ID64 directly from logged-in client"""
    if client and hasattr(client, 'steam_id') and client.steam_id:
        steam_id64 = client.steam_id.as_64
        log_success(f"Using Steam ID64 from logged-in client: {steam_id64}")
        return str(steam_id64)

    log_error("No logged-in client available for Steam ID64")
    return None

def parse_libraryfolders_vdf():
    """Parse libraryfolders.vdf to extract app IDs"""
    if not LIBRARY_FILE or not LIBRARY_FILE.exists():
        log_error(f"Steam library file not found at {LIBRARY_FILE}")
        sys.exit(EXIT_STEAM_NOT_FOUND)

    log_info(f"Reading Steam library from: {LIBRARY_FILE}")

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
        log_error(f"Exception for owner {owner_id}: {e}")
        traceback.print_exc(limit=1)
    return None

def generate_stats_schema_bin(game_id, account_id, max_no_schema_in_row, client=None):
    """Generate stats and schema files with no-schema detection"""
    log_info(f"Generating stats schema for game ID {game_id}")

    should_logout = False
    if not client:
        client = steam_login()
        if not client:
            log_error("Aborting schema generation - not logged in")
            return False
        should_logout = True

    total_owners = len(TOP_OWNER_IDS)
    log_info(f"Checking {total_owners} potential owners")

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
            if SILENT_MODE and VERBOSE:
                sys.exit(EXIT_NO_SCHEMA_FOUND)
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
        log_success(f"Saved {schema_path} ({len(stats_schema_found)} bytes)")

        user_path = OUTPUT_DIR / f"UserGameStats_{account_id}_{game_id}.bin"
        shutil.copyfile(TEMPLATE_FILE, user_path)
        log_success(f"Copied template to {user_path} ({TEMPLATE_FILE.stat().st_size} bytes)")
    except Exception as e:
        log_error(f"Error writing schema files: {e}")
        if should_logout:
            client.logout()
        if SILENT_MODE:
            sys.exit(EXIT_FILE_ERROR)
        return False

    if should_logout:
        client.logout()

    log_success(f"Finished schema generation for game {game_id} (owner {found_owner})")
    return True

def parse_loginusers_vdf():
    """Return a list of all account names from loginusers.vdf"""
    if not LOGIN_FILE or not LOGIN_FILE.exists():
        return []

    content = LOGIN_FILE.read_text(encoding="utf-8", errors="ignore")

    # Match all account entries
    users = re.findall(
        r'"(\d+)"\s*{\s*[^}]*?"AccountName"\s*"([^"]+)"',
        content,
        re.DOTALL
    )

    return [name for _, name in users]

def get_available_accounts():
    """Get list of available accounts from various sources"""
    accounts = []

    # Get accounts from loginusers.vdf
    vdf_accounts = parse_loginusers_vdf()
    accounts.extend(vdf_accounts)

    # Get accounts from saved logins
    saved_logins = load_saved_logins()
    for login_data in saved_logins.values():
        if "username" in login_data and login_data["username"] not in accounts:
            accounts.append(login_data["username"])

    # Remove duplicates while preserving order
    seen = set()
    unique_accounts = []
    for account in accounts:
        if account not in seen:
            seen.add(account)
            unique_accounts.append(account)

    return unique_accounts

def steam_login(login_input=None):
    """Login to Steam using saved logins or interactive login"""
    client = SteamClient()

    # Try environment variables first
    USERNAME = os.environ.get('STEAMUSERNAME', '')
    PASSWORD = os.environ.get('STEAMPASSWORD', '')

    # Parse login input if provided
    target_username = None
    target_account_id = None
    target_steam_id64 = None

    if login_input:
        target_account_id, target_steam_id64 = parse_steam_id(login_input)
        if not target_account_id:
            # If we can't parse as ID, assume it's a username
            target_username = login_input

    # Load saved logins
    saved_logins = load_saved_logins()

    # Find matching login
    REFRESH_TOKEN = None
    if target_steam_id64 and target_steam_id64 in saved_logins:
        login_data = saved_logins[target_steam_id64]
        USERNAME = login_data.get("username", "")
        REFRESH_TOKEN = login_data.get("refresh_token")
    elif target_username and target_username in saved_logins:
        login_data = saved_logins[target_username]
        USERNAME = login_data.get("username", "")
        REFRESH_TOKEN = login_data.get("refresh_token")
    elif target_steam_id64 or target_username:
        # We have a target but no saved login
        USERNAME = target_username or target_steam_id64 or ""

    # If no username from environment or target, let user choose
    if not USERNAME and not SILENT_MODE:
        available_accounts = get_available_accounts()
        if available_accounts:
            log_info("Available accounts:")
            for i, user in enumerate(available_accounts, 1):
                log_base(f"[{i}]: {user}")
            try:
                num = int(prompt("Choose an account to login (0 for new account):"))
                if 0 < num <= len(available_accounts):
                    USERNAME = available_accounts[num - 1]
            except ValueError:
                pass

    # Still no username? ask user (unless silent mode)
    if not USERNAME:
        if SILENT_MODE:
            # In silent mode, try to use last account
            last_account = load_last_account()
            if last_account:
                log_info(f"Using last account: {last_account}")
                # Recursively call with last account
                return steam_login(last_account)
            else:
                log_error("No username provided, please select a user with --login. Read more with --help")
                sys.exit(EXIT_NO_ACCOUNT_SPECIFIED)
        log_base("No Steam accounts found, please log in manually")
        USERNAME = input("Steam Username: ").strip()

    # Try to get refresh token from saved logins if not already found
    if not REFRESH_TOKEN:
        for login_data in saved_logins.values():
            if login_data.get("username") == USERNAME:
                REFRESH_TOKEN = login_data.get("refresh_token")
                break

    webauth, result = WebAuth(), None
    prompt_for_unavailable = True

    while result in (
        EResult.TryAnotherCM, EResult.ServiceUnavailable,
        EResult.InvalidPassword, None):

        if result in (EResult.TryAnotherCM, EResult.ServiceUnavailable):
            if prompt_for_unavailable and result == EResult.ServiceUnavailable:
                if SILENT_MODE:
                    client.logout()
                    sys.exit(EXIT_LOGIN_FAILED)

                while True:
                    answer = input("[!] Steam is down. Keep retrying? [y/n]: ").lower()
                    if answer in 'yn':
                        break

                prompt_for_unavailable = False
                if answer == 'n':
                    break

            client.reconnect(maxdelay=15)
        elif result == EResult.InvalidPassword:
            log_error("Invalid password or refresh_token.")
            log_error(f"Correct the password or delete '{SAVED_LOGINS_FILE}' and try again.")
            client.logout()
            sys.exit(EXIT_LOGIN_FAILED)

        if not REFRESH_TOKEN:
            try:
                if not PASSWORD:
                    if SILENT_MODE:
                        client.logout()
                        sys.exit(EXIT_INPUT_REQUIRED)
                    PASSWORD = input("Steam Password: ").strip()
                webauth.cli_login(USERNAME, PASSWORD)
            except Exception as e:
                log_error(f'Login failed: {e}')
                client.logout()
                sys.exit(EXIT_LOGIN_FAILED)

            USERNAME, PASSWORD = webauth.username, webauth.password
            REFRESH_TOKEN = webauth.refresh_token

        result = client.login(USERNAME, PASSWORD, REFRESH_TOKEN)

    steam_id64 = client.steam_id.as_64
    account_id = client.steam_id.account_id

    # Save refresh token (encrypted)
    if REFRESH_TOKEN:
        login_key = steam_id64

        saved_logins[login_key] = {
            "username": USERNAME,
            "refresh_token": REFRESH_TOKEN,
            "account_id": account_id,
            "steam_id64": steam_id64
        }

        if save_saved_logins(saved_logins):
            log_success(f"Saved encrypted login token for {USERNAME}")
        else:
            log_error(f"Could not save encrypted login token for {USERNAME}")

    # Save last used account identifier
    if login_input:
        save_last_account(login_input)
    else:
        save_last_account(USERNAME)

    if result == EResult.OK:
        log_success("Logged into Steam successfully")
        # Add our own account ID to the top of the owner list
        if steam_id64 not in TOP_OWNER_IDS:
            TOP_OWNER_IDS.insert(0, steam_id64)
            log_info(f"Added your account ({steam_id64}) to owner list")
        return client, steam_id64, account_id
    else:
        log_error(f"Steam login failed: {result.name}")
        client.logout()
        sys.exit(EXIT_LOGIN_FAILED)

def copy_bins_to_steam_stats():
    """
    Copies all files from bins/* to the Steam appcache/stats directory
    for the given Steam ID64.
    """
    # Destination stats folder per user
    if DEST_DIR:
        DEST_DIR.mkdir(parents=True, exist_ok=True)

    if not OUTPUT_DIR.exists():
        log_error(f"Source directory {OUTPUT_DIR} does not exist. Skipped copying")
        return

    files_copied = 0
    for file_path in OUTPUT_DIR.glob("*"):
        if not file_path.is_file():
            continue

        if files_copied == 0:
            log_base("")

        dest_path = DEST_DIR / file_path.name if DEST_DIR else None

        # Schema files: always overwrite
        if file_path.name.startswith("UserGameStatsSchema_"):
            try:
                if dest_path:
                    shutil.copy2(file_path, dest_path)
                    files_copied += 1
                    log_success(f"Overwrote Schema File: {file_path} -> {dest_path}")
                else:
                    log_info(f"DEST_DIR not set, skipping copy of {file_path}")
            except Exception as e:
                log_error(f"Failed to copy schema {file_path} -> {dest_path}: {e}")
                if SILENT_MODE:
                    sys.exit(EXIT_FILE_ERROR)

        # User stats files: only copy if not already present
        elif file_path.name.startswith("UserGameStats_"):
            if dest_path and dest_path.exists():
                log_warning(f"Stats file already exists: {dest_path}")
                continue
            try:
                if dest_path:
                    shutil.copy2(file_path, dest_path)
                    files_copied += 1
                    log_success(f"Copied Stats File: {file_path} -> {dest_path}")
                else:
                    log_info(f"DEST_DIR not set, skipping copy of {file_path}")
            except Exception as e:
                log_error(f"Failed to copy stats {file_path} -> {dest_path}: {e}")
                if SILENT_MODE:
                    sys.exit(EXIT_FILE_ERROR)

    if files_copied > 0:
        log_success(f"Copied {files_copied} files to {DEST_DIR}")

def prompt_security_warning():
    """Prompt user about security and ask if they want to delete the encrypted tokens"""
    if SILENT_MODE:
        return

    log_base(f"\n{'='*80}")
    log_base(f"SLScheevo Security Notice")
    log_base(f"{'='*80}")
    log_base(f"Your Steam login tokens have been saved in an encrypted file:")
    log_base(f"{os.path.abspath(SAVED_LOGINS_FILE)}")
    log_base(f"While encrypted, this file still contains sensitive information.")
    log_base(f"If you don't plan to use SLScheevo for a while then please delete this file")
    log_base(f"{'='*80}")

    try:
        log_base("")
        response = prompt("Do you want to delete the encrypted tokens file now? (y/n): ").strip().lower()
        log_base("")
        if response in ['y', 'yes']:
            if SAVED_LOGINS_FILE.exists():
                SAVED_LOGINS_FILE.unlink()
                log_success("Encrypted tokens file deleted.")
            else:
                log_warning("File already deleted or doesn't exist.")
        else:
            log_warning("File kept. Remember to delete it manually if needed.")
    except (KeyboardInterrupt, EOFError):
        log_base("\nFile kept. Remember to delete it manually if needed.")

def parse_app_ids(appid_input):
    """Parse comma-separated app IDs string into list of integers"""
    if not appid_input:
        return []

    app_ids = []
    for part in appid_input.split(','):
        part = part.strip()
        if part.isdigit():
            app_ids.append(int(part))

    return app_ids

def main():
    global SILENT_MODE
    global VERBOSE
    global BASE_DIR, DATA_DIR, OUTPUT_DIR, SKIP_FILE, NO_ACH_FILE, MAX_TRIES_FILE, SAVED_LOGINS_FILE, TEMPLATE_FILE, LAST_ACCOUNT_FILE

    parser = argparse.ArgumentParser(description='SLScheevo - Steam Stats Schema Generator')
    parser.add_argument('--login', type=str, help='Login using AccountID, SteamID, Steam2 ID, Steam3 ID, or username')
    parser.add_argument('--silent', action='store_true', help='Silent mode - no input prompts, exit with status codes')
    parser.add_argument('--verbose', action='store_true', help='Exits on non-critical statuses like no schemas for appid and such')
    parser.add_argument('--appid', type=str, help='Comma-separated list of app IDs to generate schemas for')
    parser.add_argument('--save-dir', type=str, help='Base directory to save data and outputs (overrides default script-based base dir)')

    args = parser.parse_args()

    SILENT_MODE = args.silent
    VERBOSE = args.verbose

    # If user specified a save directory, update BASE_DIR and all dependent paths
    if args.save_dir:
        requested = Path(args.save_dir).expanduser().resolve()
        if not requested.exists():
            try:
                requested.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                log_error(f"Could not create save-dir '{requested}': {e}")
                sys.exit(EXIT_FILE_ERROR)
        BASE_DIR = requested
        DATA_DIR = BASE_DIR / "data"
        OUTPUT_DIR = DATA_DIR / "bins"
        SKIP_FILE = DATA_DIR / "skip_generation.txt"
        NO_ACH_FILE = DATA_DIR / "no_achievement_games.txt"
        MAX_TRIES_FILE = DATA_DIR / "maximum_tries.txt"
        SAVED_LOGINS_FILE = DATA_DIR / "saved_logins.encrypted"
        LAST_ACCOUNT_FILE = DATA_DIR / "last_account.txt"
        TEMPLATE_FILE = DATA_DIR / "UserGameStats_TEMPLATE.bin"
        LOG_FILE = DATA_DIR / "slscheevo.log"

    # Setup logging after paths are configured
    setup_logging()
    install_global_exception_logger()

    # Clear screen based on platform
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')

    determine_steam_directory()
    ensure_directories()
    max_no_schema_in_row = get_maximum_tries()

    # Login first to get client
    if args.login:
        client, steam_id64, account_id = steam_login(args.login)
    else:
        client, steam_id64, account_id = steam_login()

    if not client:
        log_error("Failed to login to Steam")
        sys.exit(EXIT_LOGIN_FAILED)

    if not account_id:
        log_error("Could not retrieve account ID")
        client.logout()
        sys.exit(EXIT_NO_ACCOUNT_ID)

    if not steam_id64:
        log_error("Could not retrieve Steam ID64")
        client.logout()
        sys.exit(EXIT_NO_ACCOUNT_ID)

    log_info(f"Parsed Account ID: {account_id}")
    log_info(f"Parsed Steam ID64: {steam_id64}")

    # Parse app IDs from command line or library
    if args.appid:
        app_ids = parse_app_ids(args.appid)
        if not app_ids:
            log_error("No valid app IDs provided with --appid")
            client.logout()
            sys.exit(EXIT_NO_APP_IDS)
        log_info(f"Using {len(app_ids)} app IDs from command line: {app_ids}")
    else:
        # Parse Steam library
        app_ids = parse_libraryfolders_vdf()
        if not app_ids:
            log_error("No app IDs found in library file.")
            client.logout()
            sys.exit(EXIT_NO_APP_IDS)
        log_success(f"Found {len(app_ids)} games in library")

    # Read tracking files
    skip_generation = read_tracking_file(SKIP_FILE)
    no_achievements = read_tracking_file(NO_ACH_FILE)

    # Find missing app IDs
    missing_app_ids = []
    for app_id in app_ids:
        if app_id in no_achievements:
            continue  # doesn't have achievements
        if app_id in skip_generation:
            continue  # explicitly skipped

        # Check if schema file already exists in backup or destination
        schema_file = f"UserGameStats_{account_id}_{app_id}.bin"
        if (OUTPUT_DIR / schema_file).exists() or (DEST_DIR and (DEST_DIR / schema_file).exists()):
            continue

        missing_app_ids.append(app_id)

    if not missing_app_ids:
        log_info("No missing stats files to generate")
        client.logout()
        copy_bins_to_steam_stats()
        prompt_security_warning()
        sys.exit(EXIT_NO_ACTIONS)

    log_info(f"Generating stats for {len(missing_app_ids)} missing games")

    # Generate missing stats
    success_count = 0
    failed_count = 0

    for i, app_id in enumerate(missing_app_ids, 1):
        log_base("")
        log_info(f"Progress: {i}/{len(missing_app_ids)}")

        if generate_stats_schema_bin(app_id, account_id, max_no_schema_in_row, client):
            success_count += 1
        else:
            failed_count += 1

    log_base("")
    log_success(f"Generation complete: {success_count} succeeded, {failed_count} failed")

    client.logout()

    # Copy generated files to Steam directory
    copy_bins_to_steam_stats()

    prompt_security_warning()

    sys.exit(EXIT_SUCCESS)

if __name__ == "__main__":
    main()
