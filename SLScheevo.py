#!/usr/bin/env python3
import json
import vdf
import os
import re
import shutil
import sys
import time
import traceback
import platform
import itertools
import base64
import subprocess
import getpass
import hashlib
import argparse
import logging
from gevent import Timeout
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from steam.client import SteamClient
from steam.core.msg import MsgProto
from steam.enums.common import EResult
from steam.enums.emsg import EMsg
from steam.webauth import WebAuth

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


class ConsoleFormatter(logging.Formatter):
    """Formatter for console without timestamps"""

    SYMBOLS = {
        "SUCCESS": "[OK] ",
        "INFO": "[->] ",
        "WARNING": "[!!] ",
        "ERROR": "[XX] ",
    }

    def format(self, record):
        symbol = ""

        if hasattr(record, "custom_level"):
            symbol = self.SYMBOLS.get(record.custom_level, "")
        elif record.levelname == "INFO":
            symbol = "[→] "

        return f"{symbol}{record.getMessage()}"


class Logger:
    """Logger class to handle all logging operations"""

    def __init__(self, main_instance):
        self.main = main_instance

    def setup_logging(self):
        """Setup logging to both console and file"""
        self.main.DATA_DIR.mkdir(exist_ok=True, parents=True)

        # Create logger
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)

        # Clear any existing handlers
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

        # File handler with timestamps
        file_handler = logging.FileHandler(self.main.LOG_FILE, encoding="utf-8")
        file_handler.setLevel(logging.INFO)
        file_formatter = logging.Formatter(
            "%(asctime)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        # Console handler without timestamps and UTF-8 encoding
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = ConsoleFormatter()
        console_handler.setFormatter(console_formatter)

        logger.addHandler(console_handler)

    def log_base(self, message):
        """Log message without any symbols"""
        self._log_with_level("BASE", message, logging.INFO)

    def log_info(self, message):
        """Log info message with [->] symbol"""
        self._log_with_level("INFO", message, logging.INFO)

    def log_success(self, message):
        """Log success message with [OK] symbol"""
        self._log_with_level("SUCCESS", message, logging.INFO)

    def log_error(self, message):
        """Log error message with [XX] symbol"""
        self._log_with_level("ERROR", message, logging.ERROR)

    def log_warning(self, message):
        """Log warning message with [!!] symbol"""
        self._log_with_level("WARNING", message, logging.WARNING)

    @staticmethod
    def _log_with_level(custom_level, message, level):
        logger = logging.getLogger()
        if logger.isEnabledFor(level):
            record = logging.LogRecord(
                name=__name__,
                level=level,
                pathname=__file__,
                lineno=0,
                msg=message,
                args=None,
                exc_info=None,
            )
            record.custom_level = custom_level
            logger.handle(record)

    def install_global_exception_logger(self):
        """Catch all unhandled exceptions and log them before exiting."""

        def handle_exception(exc_type, exc_value, exc_traceback):
            logger = logging.getLogger()

            if issubclass(exc_type, KeyboardInterrupt):
                # Don't log Ctrl+C as an error
                logger.info("Interrupted by user (KeyboardInterrupt).")
                return

            # Log full traceback to file
            logger.error(
                "UNHANDLED EXCEPTION OCCURRED!",
                exc_info=(exc_type, exc_value, exc_traceback),
            )

            # Also log a clean message to the console
            self.log_error(f"Unhandled crash: {exc_value}")

        sys.excepthook = handle_exception

    @staticmethod
    def prompt(msg: str) -> str:
        """Log a prompt with [→] but keep input on same line."""
        prefix = ConsoleFormatter.SYMBOLS.get("INFO", "[->] ")

        # Print prefix and message WITHOUT newline
        print(f"{prefix}{msg} ", end="", flush=True)

        # Now take input
        return input()

    @staticmethod
    def promptwarn(msg: str) -> str:
        """Log a prompt with [→] but keep input on same line."""
        prefix = ConsoleFormatter.SYMBOLS.get("WARNING", "[!!] ")

        # Print prefix and message WITHOUT newline
        print(f"{prefix}{msg} ", end="", flush=True)

        # Now take input
        return input()


class SteamLogin:
    """Class to handle Steam login operations"""

    def __init__(self, main_instance):
        self.main = main_instance
        self.logger = main_instance.logger
        self.saved_logins = {}
        self.login_input = None
        self.target_username = None
        self.target_account_id = None
        self.target_steam_id64 = None
        self.env_username = ""
        self.env_password = ""
        self.saved_username = None
        self.saved_refresh_token = None
        self.username = None
        self.refresh_token = None
        self.client = None
        self.steam_id64 = None
        self.account_id = None

    def setup_login_credentials(self, login_input=None):
        """Setup all login credentials and target information"""
        self.saved_logins = self.load_saved_logins()
        self.login_input = login_input

        # Parse target account info
        self.target_username, self.target_account_id, self.target_steam_id64 = (
            self.get_target_account_info(login_input)
        )

        # Get environment credentials
        self.env_username = os.environ.get("STEAMUSERNAME", "")
        self.env_password = os.environ.get("STEAMPASSWORD", "")

        # Find saved login
        self.saved_username, self.saved_refresh_token = self.find_saved_login()

        # Determine final username
        self.username = self.determine_username()

        # Find refresh token
        self.refresh_token = self.find_refresh_token()

    def login(self, login_input=None):
        """Login to Steam using saved logins or interactive login"""
        # Step 1: Setup all login credentials
        self.setup_login_credentials(login_input)

        # Step 2: Perform login cycle
        result = self.attempt_login()

        # Step 3: Handle login result
        if result != EResult.OK:
            self.logger.log_error("Steam login failed, exiting")
            self.client.logout()
            sys.exit(EXIT_LOGIN_FAILED)

        # Extract account info
        self.steam_id64 = self.client.steam_id.as_64
        self.account_id = self.client.steam_id.account_id

        # Step 4: Save successful login data
        self.save_successful_login()

        self.logger.log_success("Logged into Steam successfully")
        return self.client, self.steam_id64, self.account_id

    def get_username_silent_mode(self):
        """Handle silent mode when no username is available"""
        last_account = self.load_last_account()
        if last_account:
            self.logger.log_info(f"Using last account: {last_account}")
            # Just return the username, not the full login result
            # The login() method will be called again with this username
            return last_account
        else:
            self.logger.log_error(
                "No username provided, please select a user with --login. Read more with --help"
            )
            sys.exit(EXIT_NO_ACCOUNT_SPECIFIED)

    def determine_username(self):
        """Determine the final username through various methods"""
        username = (
            self.saved_username
            or self.target_username
            or self.target_steam_id64
            or self.env_username
        )

        if not username:
            username = self.get_username_from_user()

        return username

    def get_username_from_user(self):
        """Get username through interactive selection or input"""
        # In silent mode, directly use the last saved account instead of interactive selection
        if self.main.SILENT_MODE:
            return self.get_username_silent_mode()

        # Try interactive selection first (interactive mode only)
        selected_username = self.select_account_interactively()
        if selected_username:
            return selected_username

        # Fallback to manual input
        self.logger.log_base("No Steam accounts found, please log in manually")
        return input("Steam Username: ").strip()

    def select_account_interactively(self):
        """Let user select an account from available options"""
        available_accounts = self.get_available_accounts()
        if not available_accounts:
            return None

        self.logger.log_info("Available accounts:")
        for i, user in enumerate(available_accounts, 1):
            self.logger.log_base(f"[{i}]: {user}")

        try:
            num = int(
                self.logger.prompt("Choose an account to login (0 for new account):")
            )
            if 0 < num <= len(available_accounts):
                return available_accounts[num - 1]
        except ValueError:
            pass

        return None

    def get_available_accounts(self):
        """Get list of available account names from various sources"""
        accounts = []

        # Accounts from loginusers.vdf (dict keyed by steamid)
        vdf_accounts = self.parse_loginusers_vdf()
        for user in vdf_accounts.values():
            name = user.get("AccountName")
            if name:
                accounts.append(name)

        # Accounts from saved logins
        saved_logins = self.load_saved_logins()
        for login_data in saved_logins.values():
            name = login_data.get("username")
            if name:
                accounts.append(name)

        # Remove duplicates while preserving order
        seen = set()
        unique_accounts = []
        for name in accounts:
            if name not in seen:
                seen.add(name)
                unique_accounts.append(name)

        return unique_accounts

    def attempt_login(self):
        """Perform the main login"""
        result = None
        prompt_disabled = False
        login_timeout = 60
        retry_count = 1
        max_tries = 10
        self.client = SteamClient()

        while True:
            try:
                print("")
                if retry_count == 1:
                    self.logger.log_info("Logging in...")
                else:
                    self.logger.log_info(f"Login attempt {retry_count}...")
                with Timeout(login_timeout):
                    if not self.refresh_token:
                        if not self.perform_web_authentication():
                            self.client.logout()
                            sys.exit(EXIT_LOGIN_FAILED)
                    if self.env_password or self.refresh_token:
                        result = self.client.login(
                            self.username, self.env_password, self.refresh_token
                        )
            except Timeout:
                self.logger.log_warning(
                    f"Login timed out after {login_timeout} seconds"
                )
                result = EResult.Timeout
            except Exception as e:
                self.logger.log_error(f"Login error: {e}")
                result = None

            extra_wait_time = 0
            if result == EResult.OK:
                break
            elif result == EResult.InvalidPassword:
                if self.refresh_token or self.main.SILENT_MODE:
                    self.logger.log_error(
                        "Looks like the token wasn't accepted or the password is wrong"
                    )
                    self.logger.log_error(
                        f"Try deleting '{self.main.SAVED_LOGINS_FILE}' and then try again."
                    )
                    sys.exit(EXIT_LOGIN_FAILED)
                else:
                    self.logger.log_error(
                        "Invalid password. Please try again with the correct one"
                    )
                    self.client.logout()
                    self.client.disconnect()
                    continue
            elif result == EResult.TryAnotherCM:
                self.logger.log_error(
                    "The Steam Servers aren't letting us login (TryAnotherCM) - Waiting longer before contacting the servers again"
                )
                extra_wait_time = 20
            elif result == EResult.Timeout:
                self.logger.log_error("The login attempt timed out (Timeout)")
            elif result == EResult.ServiceUnavailable:
                self.logger.log_error(
                    "The Steam Servers aren't available right now (ServiceUnavailable)"
                )
            else:
                self.logger.log_error(
                    f"An unrecognized error occurred when trying to login: {result}"
                )

            if (
                self.main.SILENT_MODE
                and not self.main.INFINITE_RETRY
                and prompt_disabled
            ):
                sys.exit(EXIT_LOGIN_FAILED)

            if not self.main.SILENT_MODE and not prompt_disabled:
                self.handle_service_unavailable()
            prompt_disabled = True

            # Ask if we should continue
            if (
                not self.main.INFINITE_RETRY
                and not self.main.SILENT_MODE
                and retry_count >= max_tries
            ):
                self.handle_service_unavailable()
                max_tries += 5

            base_wait = min(5 * (2 ** (retry_count - 1)), 60)
            jitter = base_wait * 0.1  # Add 10% random jitter
            wait_time = base_wait + (time.time() % jitter) + extra_wait_time

            self.logger.log_info(
                f"Waiting {wait_time:.1f} seconds before retrying ({retry_count}/{'infinity' if self.main.INFINITE_RETRY else max_tries})"
            )
            self.client.logout()
            self.client.disconnect()
            time.sleep(wait_time * 0.3)
            self.client = SteamClient()
            time.sleep(wait_time * 0.7)

            retry_count += 1
            continue

        return result

    def handle_service_unavailable(self):
        """Handle Steam service unavailable scenario with y/n/i options"""
        while True:
            answer = self.logger.promptwarn(
                "Keep retrying? (y=yes, n=no, i=infinite): "
            ).lower()
            if answer == "i":
                self.main.INFINITE_RETRY = True
                self.logger.log_info("Retrying infinitely. Press CTRL+C to cancel")
                return
            elif answer == "y":
                self.main.INFINITE_RETRY = False
                self.logger.log_info("Retrying.")
                return
            else:
                self.logger.log_info("No retry selected, exiting.")
                sys.exit(EXIT_LOGIN_FAILED)

    def perform_web_authentication(self):
        """Perform web-based authentication when no refresh token exists"""
        if not self.env_password and self.main.SILENT_MODE:
            return False

        try:
            webauth = WebAuth()
            webauth.cli_login(self.username, self.env_password)
            self.username = webauth.username
            self.env_password = webauth.password
            self.refresh_token = webauth.refresh_token
            return True
        except Exception as e:
            self.logger.log_error(f"Web authentication failed: {e}")
            return False

    def save_successful_login(self):
        """Save login data after successful authentication"""
        if self.refresh_token:
            self.saved_logins[self.steam_id64] = {
                "username": self.username,
                "refresh_token": self.refresh_token,
                "account_id": self.account_id,
                "steam_id64": self.steam_id64,
            }

            if self.save_saved_logins(self.saved_logins):
                self.logger.log_success(
                    f"Saved encrypted login token for {self.username}"
                )

        # Save last used account
        account_identifier = self.login_input if self.login_input else self.username
        self.save_last_account(account_identifier)

        # Add our account to owner list
        if self.steam_id64 not in self.main.TOP_OWNER_IDS:
            self.main.TOP_OWNER_IDS.insert(0, self.steam_id64)
            self.logger.log_info(
                f"Added your account ({self.steam_id64}) to owner list"
            )

    def get_target_account_info(self, login_input):
        """Parse login input to determine target account"""
        if not login_input:
            return None, None, None

        target_account_id, target_steam_id64 = self.parse_steam_id(login_input)
        target_username = login_input if not target_account_id else None

        return target_username, target_account_id, target_steam_id64

    def find_saved_login(self):
        """Find matching login in saved logins database"""
        if self.target_steam_id64 and self.target_steam_id64 in self.saved_logins:
            login_data = self.saved_logins[self.target_steam_id64]
            return login_data.get("username", ""), login_data.get("refresh_token")
        elif self.target_username and self.target_username in self.saved_logins:
            login_data = self.saved_logins[self.target_username]
            return login_data.get("username", ""), login_data.get("refresh_token")

        return "", None

    def find_refresh_token(self):
        """Find refresh token for the current username"""
        if self.saved_refresh_token:
            return self.saved_refresh_token

        # Search all saved logins for this username
        for login_data in self.saved_logins.values():
            if login_data.get("username") == self.username:
                return login_data.get("refresh_token")

        return None

    def steamid64_from_account_id(self, account_id: int) -> int:
        """Convert AccountID (32-bit) to public SteamID64"""
        return self.main.STEAMID64_BASE + account_id

    def account_id_from_steamid64(self, steamid64: int) -> int:
        """Extract 32-bit AccountID from public Steam64"""
        return steamid64 - self.main.STEAMID64_BASE

    def parse_steam_id(self, identifier: str):
        identifier = identifier.strip()
        account_id = None
        steam_id64 = None

        # Steam2 ID: STEAM_X:Y:Z
        if identifier.upper().startswith("STEAM_"):
            try:
                steam_prefix, y, z = identifier.split(":")
                int(steam_prefix.split("_")[1])
                y = int(y)
                z = int(z)
                account_id = (z << 1) | y
                steam_id64 = self.steamid64_from_account_id(account_id)
            except (ValueError, IndexError) as e:
                self.logger.log_error(f"Failed to parse Steam2 ID ({identifier}): {e}")
                sys.exit(EXIT_FAILED_TO_PARSE_ID)

        # Steam3 ID: [U:1:ACCOUNT_ID]
        elif identifier.startswith("[U:") and identifier.endswith("]"):
            try:
                parts = identifier[1:-1].split(":")
                account_id = int(parts[-1])
                steam_id64 = self.steamid64_from_account_id(account_id)
            except (ValueError, IndexError) as e:
                self.logger.log_error(f"Failed to parse Steam3 ID ({identifier}): {e}")
                sys.exit(EXIT_FAILED_TO_PARSE_ID)

        # Pure numeric input
        elif identifier.isdigit():
            num = int(identifier)
            try:
                if num >= 76561197960265728:  # Steam64 (public)
                    account_id = self.account_id_from_steamid64(num)
                    steam_id64 = num
                elif num <= 4294967295:  # 32-bit AccountID
                    account_id = num
                    steam_id64 = self.steamid64_from_account_id(num)
                else:
                    self.logger.log_error(f"Invalid numeric Steam ID range: {num}")
                    sys.exit(EXIT_FAILED_TO_PARSE_ID)
            except ValueError as e:
                self.logger.log_error(f"Failed to parse numeric ID ({identifier}): {e}")
                sys.exit(EXIT_FAILED_TO_PARSE_ID)

        return (
            str(account_id) if account_id is not None else None,
            str(steam_id64) if steam_id64 is not None else None,
        )

    def get_hwid(self):
        """Get Hardware ID that works on both Linux and Windows, with robust fallbacks."""
        system = platform.system()

        if system == "Windows":
            wmic_path = Path(r"C:\Windows\System32\wbem\wmic.exe")

            # Try WMIC if it exists
            if wmic_path.exists():
                try:
                    result = subprocess.check_output(
                        "wmic csproduct get UUID",
                        shell=True,
                        stderr=subprocess.DEVNULL,
                        text=True,
                    )
                    lines = [
                        line.strip() for line in result.split("\n") if line.strip()
                    ]
                    if len(lines) > 1 and lines[1]:
                        return lines[1]
                except subprocess.SubprocessError:
                    pass  # fallback to PowerShell if WMIC fails

            # Fallback: PowerShell
            try:
                result = subprocess.check_output(
                    'powershell -Command "Get-CimInstance Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID"',
                    shell=True,
                    stderr=subprocess.DEVNULL,
                    text=True,
                ).strip()
                if result:
                    return result
            except subprocess.SubprocessError:
                pass

            self.logger.log_error("Failed to retrieve HWID on Windows.")
            sys.exit(EXIT_FAILED_TO_GET_HWID)

        elif system == "Linux":
            # Linux: Try machine-id first
            try:
                with open("/etc/machine-id", "r") as f:
                    machine_id = f.read().strip()
                    if machine_id:
                        return machine_id
            except OSError:
                pass
            self.logger.log_error("Failed to retrieve machine ID on Linux.")
            sys.exit(EXIT_FAILED_TO_GET_HWID)

        else:
            self.logger.log_error(f"Unsupported platform: {system}")
            sys.exit(EXIT_NOT_SUPPORTED)

    def derive_key(self):
        """Derive a Fernet key for encryption"""
        system_user = getpass.getuser()
        hwid = self.get_hwid()

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

    def encrypt_saved_logins(self, logins_dict):
        """Encrypt saved logins"""
        try:
            key = self.derive_key()
            fernet = Fernet(key)

            # Convert dict to JSON string and encrypt
            logins_json = json.dumps(logins_dict)
            encrypted_data = fernet.encrypt(logins_json.encode())

            return encrypted_data
        except Exception as e:
            self.logger.log_error(f"Error encrypting logins: {e}")
            return None

    def decrypt_saved_logins(self, encrypted_data):
        """Decrypt saved logins"""
        try:
            key = self.derive_key()
            fernet = Fernet(key)

            # Decrypt and parse JSON
            decrypted_data = fernet.decrypt(encrypted_data)
            logins_dict = json.loads(decrypted_data.decode())

            return logins_dict
        except Exception as e:
            self.logger.log_error(f"Error decrypting logins: {e}")
            return {}

    def migrate_old_tokens_to_new_format(self):
        """Migrate old token files to new saved_logins format"""
        old_files = [
            self.main.DATA_DIR / "refresh_tokens.encrypted",
            self.main.DATA_DIR / "refresh_tokens.json",
        ]

        migrated = False
        new_logins = {}

        for old_file in old_files:
            if old_file.exists():
                try:
                    if old_file.suffix == ".encrypted":
                        # Try to decrypt old format
                        with open(old_file, "rb") as f:
                            encrypted_data = f.read()

                        # Use old derive_key function (same as before)
                        key = self.derive_key()
                        fernet = Fernet(key)
                        decrypted_data = fernet.decrypt(encrypted_data)
                        old_tokens = json.loads(decrypted_data.decode())

                        # Convert to new format
                        self._convert_tokens_to_new_format(old_tokens, new_logins)

                    elif old_file.suffix == ".json":
                        # Plaintext JSON
                        with open(old_file, "r") as f:
                            old_tokens = json.load(f)

                        # Convert to new format
                        self._convert_tokens_to_new_format(old_tokens, new_logins)

                    # Delete old file after migration
                    old_file.unlink()
                    migrated = True
                    self.logger.log_info(f"Migrated {old_file} to new format")

                except (OSError, json.JSONDecodeError) as e:
                    self.logger.log_error(f"Error migrating {old_file}: {e}")

        # Save migrated data
        if migrated and new_logins:
            if self.save_saved_logins(new_logins):
                self.logger.log_success(
                    "Successfully migrated old tokens to saved_logins.encrypted"
                )
            else:
                self.logger.log_error("Failed to save migrated tokens")

        return migrated

    def _convert_tokens_to_new_format(self, old_tokens, new_logins):
        for username, refresh_token in old_tokens.items():
            account_id, steam_id64 = self.parse_steam_id(username)
            if account_id and steam_id64:
                new_logins[steam_id64] = {
                    "username": username,
                    "refresh_token": refresh_token,
                    "account_id": account_id,
                    "steam_id64": steam_id64,
                }
            else:
                # If we can't parse as ID, keep as username
                new_logins[username] = {
                    "username": username,
                    "refresh_token": refresh_token,
                    "account_id": None,
                    "steam_id64": None,
                }

    def load_saved_logins(self):
        """Load saved logins, handling migration from old format if needed"""
        # Check if migration is needed
        old_files_exist = any(
            [
                (self.main.DATA_DIR / "refresh_tokens.encrypted").exists(),
                (self.main.DATA_DIR / "refresh_tokens.json").exists(),
            ]
        )

        if old_files_exist:
            self.migrate_old_tokens_to_new_format()

        # Load from new encrypted file
        if self.main.SAVED_LOGINS_FILE.exists():
            try:
                with open(self.main.SAVED_LOGINS_FILE, "rb") as f:
                    encrypted_data = f.read()

                # Try to decrypt
                logins = self.decrypt_saved_logins(encrypted_data)
                if logins:
                    return logins
                else:
                    self.logger.log_error(
                        "Failed to decrypt logins with current system"
                    )
                    self.logger.log_error(
                        "This might happen if you changed hardware or system user"
                    )

            except OSError as e:
                self.logger.log_error(f"Error loading encrypted logins: {e}")

        return {}

    def save_saved_logins(self, logins_dict):
        """Save logins in encrypted format"""
        encrypted_data = self.encrypt_saved_logins(logins_dict)
        if encrypted_data:
            try:
                with open(self.main.SAVED_LOGINS_FILE, "wb") as f:
                    f.write(encrypted_data)
                return True
            except OSError as e:
                self.logger.log_error(f"Error saving encrypted logins: {e}")
                sys.exit(EXIT_TOKEN_ERROR)
        return False

    def save_last_account(self, account_identifier):
        """Save the last used account identifier to a file"""
        try:
            with open(self.main.LAST_ACCOUNT_FILE, "w") as f:
                f.write(account_identifier)
            return True
        except OSError as e:
            self.logger.log_error(f"Error saving last account: {e}")
            return False

    def load_last_account(self):
        """Load the last used account identifier from file"""
        try:
            if self.main.LAST_ACCOUNT_FILE.exists():
                with open(self.main.LAST_ACCOUNT_FILE, "r") as f:
                    return f.read().strip()
        except OSError as e:
            self.logger.log_error(f"Error loading last account: {e}")
        return None

    def get_account_id(self, client):
        """Get Steam Account ID directly from logged-in client"""
        if client and hasattr(client, "steam_id") and client.steam_id:
            account_id = client.steam_id.account_id
            self.logger.log_success(
                f"Using Account ID from logged-in client: {account_id}"
            )
            return str(account_id)

        self.logger.log_error("No logged-in client available for Account ID")
        return None

    def get_steam_id64(self, client):
        """Get Steam Steam ID64 directly from logged-in client"""
        if client and hasattr(client, "steam_id") and client.steam_id:
            steam_id64 = client.steam_id.as_64
            self.logger.log_success(
                f"Using Steam ID64 from logged-in client: {steam_id64}"
            )
            return str(steam_id64)

        self.logger.log_error("No logged-in client available for Steam ID64")
        return None

    def parse_loginusers_vdf(self):
        if not self.main.LOGIN_FILE or not self.main.LOGIN_FILE.exists():
            return {}

        with self.main.LOGIN_FILE.open("r", encoding="utf-8", errors="ignore") as f:
            data = vdf.load(f)

        # data["users"] is keyed by SteamID
        users = {
            steamid: {
                "AccountName": info.get("AccountName"),
                "PersonaName": info.get("PersonaName"),
                "MostRecent": info.get("MostRecent") == "1",
                "Timestamp": int(info.get("Timestamp", 0)),
            }
            for steamid, info in data.get("users", {}).items()
        }

        return users


class SteamUtils:
    """Class to handle Steam utility operations"""

    def __init__(self, main_instance):
        self.main = main_instance
        self.logger = main_instance.logger
        self.steam_login = main_instance.steam_login

    def determine_steam_directory(self):
        if platform.system() == "Windows":
            try:
                import winreg

                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam")
                steam_path, _ = winreg.QueryValueEx(key, "SteamPath")
                winreg.CloseKey(key)
                self.logger.log_info(f"Found Steam installation at: {steam_path}")
                self.main.STEAM_DIR = Path(os.path.normpath(steam_path))
            except OSError:
                self.logger.log_error("Failed to read Steam path from registry.")
                sys.exit(EXIT_STEAM_NOT_FOUND)
        else:
            native_path = Path.home() / ".local/share/Steam"
            symlink_path = Path.home() / ".steam/steam"
            flatpak_path = Path.home() / ".var/app/com.valvesoftware.Steam/data/Steam"

            if native_path.exists():
                self.main.STEAM_DIR = native_path
                self.logger.log_base(f"Using native Steam installation: {native_path}")

            elif symlink_path.exists():
                self.main.STEAM_DIR = symlink_path
                self.logger.log_base(
                    f"Using symlink Steam installation: {symlink_path}"
                )

            elif flatpak_path.exists():
                self.main.STEAM_DIR = flatpak_path
                self.logger.log_base(
                    f"Using Flatpak Steam installation: {flatpak_path}"
                )

            else:
                self.logger.log_error(
                    "No Steam installation found in ~/.local/share/Steam, ~/.steam/steam, ~/.var/app/com.valvesoftware.Steam/data/Steam"
                )
                sys.exit(EXIT_STEAM_NOT_FOUND)

        if not self.main.STEAM_DIR.exists():
            self.logger.log_error(
                f"Steam directory does not exist at '{self.main.STEAM_DIR}'. Please report this issue"
            )
            sys.exit(EXIT_STEAM_NOT_FOUND)

        # Set the dependent paths
        self.main.LIBRARY_FILE = self.main.STEAM_DIR / "config/libraryfolders.vdf"
        self.main.LOGIN_FILE = self.main.STEAM_DIR / "config/loginusers.vdf"
        self.main.DEST_DIR = self.main.STEAM_DIR / "appcache/stats"

    def parse_libraryfolders_vdf(self):
        """Parse libraryfolders.vdf to extract app IDs"""
        if not self.main.LIBRARY_FILE or not self.main.LIBRARY_FILE.exists():
            self.logger.log_error(
                f"Steam library file not found at {self.main.LIBRARY_FILE}"
            )
            sys.exit(EXIT_STEAM_NOT_FOUND)

        self.logger.log_info(f"Reading Steam library from: {self.main.LIBRARY_FILE}")

        content = self.main.LIBRARY_FILE.read_text()
        # Extract all app IDs using regex
        app_ids = set(re.findall(r'"apps"\s*{([^}]+)}', content, re.DOTALL))
        app_ids = set(re.findall(r'"(\d+)"\s*"', "".join(app_ids)))

        return sorted([int(app_id) for app_id in app_ids if app_id.isdigit()])

    @staticmethod
    def read_tracking_file(file_path):
        """Read tracking file and return set of app IDs"""
        if not file_path.exists():
            return set()
        return set(
            int(line.strip())
            for line in file_path.read_text().splitlines()
            if line.strip().isdigit()
        )

    @staticmethod
    def get_stats_schema(client, game_id, owner_id):
        """Request the stats schema for a game from a specific owner"""
        msg = MsgProto(EMsg.ClientGetUserStats)
        msg.body.game_id = game_id
        msg.body.schema_local_version = -1
        msg.body.crc_stats = 0
        msg.body.steam_id_for_user = owner_id

        client.send(msg)
        return client.wait_msg(EMsg.ClientGetUserStatsResponse, timeout=5)

    def check_single_owner(self, game_id, owner_id, client):
        """Return schema bytes or None"""
        try:
            out = self.get_stats_schema(client, game_id, owner_id)
            if out and hasattr(out.body, "schema") and out.body.schema:
                if len(out.body.schema) > 0:
                    return out.body.schema
            # Check for the specific "no schema" response pattern
            elif (
                out
                and hasattr(out.body, "eresult")
                and out.body.eresult == 2
                and hasattr(out.body, "crc_stats")
                and out.body.crc_stats == 0
            ):
                return "NO_SCHEMA"  # Special indicator for no schema
        except Exception as e:
            self.logger.log_error(f"Exception for owner {owner_id}: {e}")
            traceback.print_exc(limit=1)
        return None

    def generate_stats_schema_bin(
        self, game_id, _account_id, max_no_schema_in_row, client
    ):
        """Generate stats and schema files with no-schema detection"""
        self.logger.log_info(f"Generating stats schema for game ID {game_id}")

        should_logout = False
        if not client:
            client, steam_id64, account_id = self.steam_login.login()
            if not client:
                self.logger.log_error("Aborting schema generation - not logged in")
                return False
            should_logout = True

        total_owners = len(self.main.TOP_OWNER_IDS)
        self.logger.log_info(f"Checking {total_owners} potential owners")

        stats_schema_found = None
        found_owner = None
        no_schema_count = 0

        spinner = itertools.cycle("|/-\\")
        for i, owner_id in enumerate(self.main.TOP_OWNER_IDS, start=1):
            sys.stdout.write(
                f"\r[{next(spinner)}] Checked {i-1}/{total_owners} owners... (no-schema streak: {no_schema_count}/{max_no_schema_in_row})"
            )
            sys.stdout.flush()

            schema_data = self.check_single_owner(game_id, owner_id, client)

            if schema_data == "NO_SCHEMA":
                no_schema_count += 1
                # If we get too many "no schema" responses in a row, abort early
                if no_schema_count >= max_no_schema_in_row:
                    break
            elif schema_data and schema_data != "NO_SCHEMA":
                stats_schema_found = schema_data
                found_owner = owner_id
                sys.stdout.write(
                    f"\r[OK] Found valid schema using owner {owner_id} ({i}/{total_owners})\n"
                )
                sys.stdout.flush()
                break
            else:
                # Reset counter if we get a different type of response (error, timeout, etc.)
                no_schema_count = 0

            time.sleep(0.1)  # small delay to avoid hammering Steam's API

        if not stats_schema_found:
            if no_schema_count >= max_no_schema_in_row:
                sys.stdout.write(
                    f"\r[XX] No schema available for game {game_id} ({max_no_schema_in_row} consecutive 'no schema' responses)\n"
                )
                sys.stdout.flush()
                if self.main.SILENT_MODE and self.main.VERBOSE:
                    sys.exit(EXIT_NO_SCHEMA_FOUND)
            else:
                sys.stdout.write(
                    f"\r[XX] No schema found for game {game_id} after checking {total_owners} owners\n"
                )
                sys.stdout.flush()

            if should_logout:
                client.logout()
            return False

        try:
            schema_path = self.main.OUTPUT_DIR / f"UserGameStatsSchema_{game_id}.bin"
            with open(schema_path, "wb") as f:
                f.write(stats_schema_found)
            self.logger.log_success(
                f"Saved {schema_path} ({len(stats_schema_found)} bytes)"
            )

            vdf_accounts = self.steam_login.parse_loginusers_vdf()
            for steamid in vdf_accounts:
                user_path = (
                    self.main.OUTPUT_DIR
                    / f"UserGameStats_{self.steam_login.account_id_from_steamid64(int(steamid))}_{game_id}.bin"
                )
                shutil.copyfile(self.main.TEMPLATE_FILE, user_path)
        except OSError as e:
            self.logger.log_error(f"Error writing schema files: {e}")
            if should_logout:
                client.logout()
            if self.main.SILENT_MODE:
                sys.exit(EXIT_FILE_ERROR)
            return False

        if should_logout:
            client.logout()

        self.logger.log_success(
            f"Finished schema generation for game {game_id} (owner {found_owner})"
        )
        return True

    def ensure_directories(self):
        """Create necessary directories"""
        # Ensure Steam destination exists if set
        if self.main.DEST_DIR:
            self.main.DEST_DIR.mkdir(exist_ok=True, parents=True)

        self.main.DATA_DIR.mkdir(exist_ok=True, parents=True)
        self.main.OUTPUT_DIR.mkdir(exist_ok=True, parents=True)

        # Ensure tracking files exist
        for file in [
            self.main.SKIP_FILE,
            self.main.NO_ACH_FILE,
            self.main.LAST_ACCOUNT_FILE,
        ]:
            file.parent.mkdir(parents=True, exist_ok=True)
            file.touch(exist_ok=True)

    def get_maximum_tries(self):
        """Read maximum tries from file or create default file"""
        max_tries = self.main.DEFAULT_MAX_TRIES
        try:
            if self.main.MAX_TRIES_FILE.exists():
                with open(self.main.MAX_TRIES_FILE, "r") as f:
                    content = f.read()

                    # Remove everything except digits
                    digits = "".join(ch for ch in content if ch.isdigit())

                    if digits:
                        max_tries = int(digits)
                        self.logger.log_info(
                            f"Using maximum tries from file: {max_tries}"
                        )
                    else:
                        self.logger.log_error(
                            f"Invalid content in {self.main.MAX_TRIES_FILE}"
                        )
                        self.create_default_maximum_tries_files()
            else:
                self.create_default_maximum_tries_files()

        except (OSError, ValueError) as e:
            self.logger.log_error(
                f"Error reading maximum_tries file: {e}, using default value: {max_tries}"
            )

        return max_tries

    def create_default_maximum_tries_files(self):
        """Create the file with default value 5"""
        self.main.MAX_TRIES_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(self.main.MAX_TRIES_FILE, "w") as f:
            f.write(f"{self.main.DEFAULT_MAX_TRIES}")
        self.logger.log_info(
            f"Created {self.main.MAX_TRIES_FILE} with default value: {self.main.DEFAULT_MAX_TRIES}"
        )

    def copy_bins_to_steam_stats(self):
        """
        Copies all files from bins/* to the Steam appcache/stats directory
        for the given Steam ID64.
        """
        # Destination stats folder per user
        if self.main.DEST_DIR:
            self.main.DEST_DIR.mkdir(parents=True, exist_ok=True)

        if not self.main.OUTPUT_DIR.exists():
            self.logger.log_error(
                f"Source directory {self.main.OUTPUT_DIR} does not exist. Skipped copying"
            )
            return

        files_copied = 0
        for file_path in self.main.OUTPUT_DIR.glob("*"):
            if not file_path.is_file():
                continue

            if files_copied == 0:
                self.logger.log_base("")

            dest_path = (
                self.main.DEST_DIR / file_path.name if self.main.DEST_DIR else None
            )

            # Schema files: always overwrite
            if file_path.name.startswith("UserGameStatsSchema_"):
                try:
                    if dest_path:
                        shutil.copy2(file_path, dest_path)
                        files_copied += 1
                        self.logger.log_success(
                            f"Overwrote Schema File: {file_path} -> {dest_path}"
                        )
                    else:
                        self.logger.log_info(
                            f"DEST_DIR not set, skipping copy of {file_path}"
                        )
                except OSError as e:
                    self.logger.log_error(
                        f"Failed to copy schema {file_path} -> {dest_path}: {e}"
                    )
                    if self.main.SILENT_MODE:
                        sys.exit(EXIT_FILE_ERROR)

            # User stats files: only copy if not already present
            elif file_path.name.startswith("UserGameStats_"):
                if dest_path and dest_path.exists():
                    self.logger.log_warning(f"Stats file already exists: {dest_path}")
                    continue
                try:
                    if dest_path:
                        shutil.copy2(file_path, dest_path)
                        files_copied += 1
                        self.logger.log_success(
                            f"Copied Stats File: {file_path} -> {dest_path}"
                        )
                    else:
                        self.logger.log_info(
                            f"DEST_DIR not set, skipping copy of {file_path}"
                        )
                except OSError as e:
                    self.logger.log_error(
                        f"Failed to copy stats {file_path} -> {dest_path}: {e}"
                    )
                    if self.main.SILENT_MODE:
                        sys.exit(EXIT_FILE_ERROR)

        if files_copied > 0:
            self.logger.log_success(
                f"Copied {files_copied} files to {self.main.DEST_DIR}"
            )

    def prompt_security_warning(self):
        """Prompt user about security and ask if they want to delete the encrypted tokens"""
        if self.main.SILENT_MODE:
            return

        self.logger.log_base(f"\n{'='*80}")
        self.logger.log_base("SLScheevo Security Notice")
        self.logger.log_base(f"{'='*80}")
        self.logger.log_base(
            "Your Steam login tokens have been saved in an encrypted file:"
        )
        self.logger.log_base(f"{os.path.abspath(self.main.SAVED_LOGINS_FILE)}")
        self.logger.log_base(
            "While encrypted, this file still contains sensitive information."
        )
        self.logger.log_base(
            "If you don't plan to use SLScheevo for a while then please delete this file"
        )
        self.logger.log_base(f"{'='*80}")

        try:
            self.logger.log_base("")
            response = (
                self.logger.prompt(
                    "Do you want to delete the encrypted tokens file now? (y/n): "
                )
                .strip()
                .lower()
            )
            self.logger.log_base("")
            if response in ["y", "yes"]:
                if self.main.SAVED_LOGINS_FILE.exists():
                    self.main.SAVED_LOGINS_FILE.unlink()
                    self.logger.log_success("Encrypted tokens file deleted.")
                else:
                    self.logger.log_warning("File already deleted or doesn't exist.")
            else:
                self.logger.log_warning(
                    "File kept. Remember to delete it manually if needed."
                )
        except (KeyboardInterrupt, EOFError):
            self.logger.log_base(
                "\nFile kept. Remember to delete it manually if needed."
            )

    @staticmethod
    def parse_app_ids(appid_input):
        """Parse comma-separated app IDs string into list of integers"""
        if not appid_input:
            return []

        app_ids = []
        for part in appid_input.split(","):
            part = part.strip()
            if part.isdigit():
                app_ids.append(int(part))

        return app_ids


class Main:
    """Main class to hold the application state and coordinate operations"""

    def __init__(self):
        self.DEFAULT_MAX_TRIES = 6

        # Steam ids with public profiles that own a lot of games
        self.TOP_OWNER_IDS = [
            76561198028121353,
            76561198017975643,
            76561198001678750,
            76561198355953202,
            76561197993544755,
            76561198121643357,
            76561198001237877,
            76561197979911851,
            76561198217186687,
            76561198152618007,
            76561197973009892,
            76561198237402290,
            76561198213148949,
            76561198108581917,
            76561198037867621,
            76561197965319961,
            76561197976597747,
            76561198019712127,
            76561198094227663,
            76561199492215670,
            76561198367471798,
            76561197969050296,
            76561198139084236,
            76561198134044398,
            76561198119667710,
            76561197962473290,
            76561198842603734,
            76561198027214426,
            76561197963550511,
            76561198064456960,
            76561199004166042,
            76561197995070100,
            76561198044596404,
            76561197996432822,
            76561198017902347,
            76561198033715344,
            76561198082995144,
            76561198051887711,
            76561197969810632,
            76561198890581618,
            76561198339417346,
            76561198388522904,
            76561198085065107,
            76561199168919006,
            76561198864213876,
            76561197970825215,
            76561198313790296,
            76561197975329196,
            76561198035900006,
            76561198095049646,
            76561198029503957,
            76561198062901118,
            76561198154462478,
            76561198021180815,
            76561197972378106,
            76561198842864763,
            76561197974742349,
            76561198052189902,
            76561199080934614,
            76561197976968076,
            76561198281128349,
            76561198063574735,
            76561197997477460,
            76561198001221571,
            76561198256917957,
            76561198093753361,
            76561198104323854,
            76561198172367910,
            76561198326510209,
            76561198118726910,
            76561199130977924,
            76561199173688191,
            76561198008797636,
            76561197990233857,
            76561198077213101,
            76561198235911884,
            76561198122859224,
            76561197965978376,
            76561198121336040,
            76561198097945516,
            76561198074920693,
            76561197979667190,
            76561197983517848,
            76561198010615256,
            76561198063728345,
            76561198049905605,
            76561198124872187,
            76561198407953371,
            76561198077248235,
            76561198037809069,
            76561197981111953,
            76561198072361453,
            76561197971026489,
            76561198025858988,
            76561197994616562,
            76561198061393233,
            76561197988664525,
            76561198396723427,
            76561198096081579,
            76561198121398682,
            76561197963534359,
            76561197995008105,
            76561197972184312,
            76561198318944318,
            76561199353305847,
            76561198109083829,
            76561197968410781,
            76561198382166453,
            76561198006391846,
            76561197992133229,
            76561198158932704,
            76561197978640923,
            76561198031837797,
            76561198097877669,
            76561198019009765,
            76561198005337430,
            76561198040421250,
            76561197972951657,
            76561198035552258,
            76561198015856631,
            76561198004332929,
            76561198045455280,
            76561198015514779,
            76561198808371265,
            76561198090111762,
            76561198171791210,
            76561198152760885,
            76561198048373585,
            76561198028011423,
            76561199187733000,
            76561198417144062,
            76561198377660182,
            76561198425583786,
            76561198031164839,
            76561198105279930,
            76561197973230221,
            76561197993312863,
            76561198015992850,
            76561198370460172,
            76561198003041763,
            76561198018254158,
            76561197992548975,
            76561198054210948,
            76561198098314980,
            76561197982718230,
            76561197976796589,
            76561197992105918,
            76561197996152700,
            76561198294806446,
            76561197981027062,
            76561198042781427,
            76561198443388781,
            76561198251835488,
            76561198150467988,
            76561198102767019,
            76561198058415025,
            76561198075477583,
            76561198039492467,
            76561197999452690,
            76561197966082557,
            76561198315929726,
            76561198846208086,
            76561198413266831,
            76561198043532513,
            76561198034213886,
            76561198025835281,
            76561198293265369,
            76561198047438206,
            76561198044387084,
            76561198085238363,
            76561198025111129,
            76561197991699268,
            76561197966617426,
            76561198030850135,
            76561198045540632,
            76561197977920776,
            76561197970545939,
            76561198128158703,
            76561198026221141,
            76561198111433283,
            76561197968401807,
            76561198028428529,
            76561197970307937,
            76561198996604130,
            76561198106145311,
            76561197973701057,
            76561198015685843,
            76561198106206019,
            76561198025038660,
            76561198093146971,
            76561198026306582,
            76561198318111105,
            76561198861936199,
            76561198050474710,
            76561197967923946,
            76561198027904347,
            76561198252374474,
            76561198168877244,
            76561197981228012,
            76561198051725954,
            76561198155124847,
            76561198333322621,
            76561197970970678,
            76561198219343843,
            76561198056157641,
            76561198004532679,
            76561198104561325,
            76561197970246998,
            76561197960366517,
            76561198071709714,
            76561198070407141,
            76561198057648189,
            76561197988445370,
            76561198072467648,
            76561197984235967,
            76561198408922198,
            76561198225501624,
            76561197992967892,
            76561197969548941,
            76561198085376246,
            76561198165450871,
            76561198006715789,
            76561197984605215,
            76561198020746864,
            76561198070220549,
            76561198051740093,
            76561197995591077,
            76561197998058239,
            76561198108986611,
            76561197986240493,
            76561198817834075,
            76561197996991818,
            76561198210187312,
            76561197992224405,
            76561198118796541,
            76561197984010356,
            76561198048151962,
            76561198019555404,
            76561197969148931,
            76561198426000196,
            76561198009596142,
            76561198192399786,
            76561198124865933,
            76561197971084458,
            76561198025653291,
            76561198028125071,
            76561198020125851,
            76561197972673568,
            76561198046642155,
            76561198035612474,
            76561198172925593,
            76561197962630138,
            76561198017172075,
            76561198029532782,
            76561198043393470,
            76561198358510879,
            76561198060520130,
            76561198096632451,
            76561197967884002,
            76561198072936438,
            76561198025391492,
            76561198053834404,
            76561197994575642,
            76561198020728639,
            76561198158969968,
            76561198043280416,
            76561198884799650,
            76561198017851315,
            76561198031326193,
            76561198120120943,
            76561197963341353,
            76561197967716198,
            76561198093579202,
            76561198027668357,
            76561198012138768,
            76561198196507927,
            76561198154522279,
            76561198264362271,
            76561198001046455,
            76561198044662581,
            76561198097699691,
            76561198001991912,
            76561198048165534,
            76561197985091630,
            76561198269242105,
            76561198117483409,
            76561198082118649,
            76561197980638659,
            76561198393004695,
            76561198033284646,
            76561198110425795,
            76561198011732976,
            76561197991987349,
            76561197962850521,
            76561197966536160,
            76561198025834664,
            76561198072325646,
            76561197971339745,
            76561197970539274,
            76561197995746514,
            76561197961542845,
            76561198082117469,
            76561198007200913,
            76561198040597721,
            76561199032872345,
            76561198086250077,
            76561197961047782,
            76561198079227501,
            76561198002536379,
            76561198114550841,
            76561198043974359,
            76561197970727958,
            76561198176662470,
            76561198003481850,
            76561198181526215,
            76561198079896896,
            76561198844130640,
            76561198088628817,
            76561197991197575,
            76561198070585472,
            76561198065494561,
            76561197989418818,
            76561197970771247,
            76561198130807766,
            76561198283395702,
            76561197986617621,
            76561198148627568,
            76561198019005921,
            76561198122276418,
            76561198034072369,
            76561198056971296,
            76561197972235753,
            76561198078266186,
            76561198034906703,
            76561198027066612,
            76561198424544684,
            76561198090373469,
            76561198025309409,
            76561198045482572,
            76561197985718185,
            76561198083550415,
            76561198034087509,
            76561197986603983,
            76561197991361144,
            76561197982273259,
            76561197965599446,
            76561198119915053,
            76561198018771271,
            76561198150126284,
            76561198042965266,
            76561198121938079,
            76561198021097269,
            76561198027917594,
            76561198002535276,
            76561197971727681,
            76561197989374217,
            76561197970539229,
            76561198032614383,
            76561198010497284,
            76561198008568758,
            76561198413088851,
            76561198018844571,
            76561198009281043,
            76561198075489828,
            76561198031329226,
            76561198116760721,
            76561198126804411,
            76561197988052802,
            76561198048668312,
            76561198356842617,
            76561198101049562,
            76561198008034709,
            76561197981323238,
            76561197972529138,
            76561198001921063,
            76561198427572372,
            76561198033107814,
            76561199198704766,
            76561197962737643,
            76561197992906798,
            76561197961823296,
            76561198111157752,
            76561197991613008,
            76561198001518866,
            76561198123987772,
            76561198283045312,
            76561198110729323,
            76561198125567580,
            76561197982793768,
            76561198020810038,
            76561198149784241,
            76561198180230006,
            76561198136397211,
            76561197976583176,
            76561198007444036,
            76561197999376568,
            76561198080917310,
            76561198016825144,
            76561198074261126,
            76561198043428662,
            76561198041631636,
            76561198034276722,
            76561198010294701,
            76561198046423728,
            76561198279620099,
            76561197988482558,
            76561198103516871,
            76561198090946797,
            76561197962840572,
            76561197980393534,
            76561198272374716,
            76561197990069739,
            76561197966904457,
            76561198089139675,
            76561198114236038,
            76561198434998728,
            76561198033967307,
            76561198811114019,
            76561198038294520,
            76561198240603702,
            76561198422695156,
            76561198063530782,
            76561198083977059,
            76561198062615216,
            76561198073355162,
            76561197966778988,
            76561198026976167,
            76561198007332488,
            76561198004130853,
            76561198062652955,
            76561198026278913,
            76561198113238279,
            76561198058556635,
            76561198038618103,
            76561198116086535,
            76561198041686345,
            76561198050440411,
            76561198071780149,
            76561198051461389,
            76561198046709348,
            76561198056047449,
            76561198043828654,
            76561198023879713,
            76561198035865245,
            76561198031049865,
            76561198252131616,
            76561198282714886,
            76561197970693531,
            76561197965380791,
            76561198047546311,
            76561198031129658,
            76561198008549198,
            76561197971561879,
            76561197970561785,
            76561198859098173,
            76561198024095656,
            76561198286209051,
            76561198067307411,
            76561198007403855,
            76561198062529088,
            76561197975756949,
            76561197970360549,
            76561198346824641,
            76561197996825541,
            76561198051353063,
            76561198445125260,
            76561197996707987,
            76561197962290563,
            76561198103935634,
            76561197968781961,
            76561198286549023,
            76561198080773680,
            76561197985036092,
            76561197986162321,
            76561198410211049,
            76561198152321140,
            76561198009363591,
            76561198051210083,
            76561197960309122,
            76561198047414009,
            76561198217979953,
            76561198034976883,
            76561198046980920,
            76561198019841907,
            76561198044067612,
            76561198100921214,
            76561198079158823,
            76561198039332365,
            76561198107962129,
            76561198010134836,
            76561197961838161,
            76561198258304011,
            76561197994153029,
            76561198073789253,
            76561198070850294,
            76561198040673812,
            76561198039532124,
            76561198019466684,
            76561198008934375,
            76561198027034035,
            76561198990467793,
            76561197960293516,
            76561198014069772,
            76561198833296725,
            76561198274212182,
            76561197998422093,
            76561198052328446,
            76561197984777354,
            76561198029582429,
            76561198034503074,
            76561198021434614,
            76561197970127197,
            76561198097690532,
            76561198024983909,
            76561198099530754,
            76561198026921217,
            76561197971004328,
            76561198037498212,
            76561197970526676,
            76561198103654291,
            76561198025609524,
            76561197966359970,
            76561197972918264,
            76561197992357639,
            76561197969100147,
            76561197971373352,
            76561198070303533,
            76561197992624948,
            76561198050105543,
            76561198024662414,
            76561198016813175,
            76561198011647032,
            76561198141387426,
            76561198929318638,
            76561198044523282,
            76561198337784749,
            76561198034250078,
            76561198057329243,
            76561198040127846,
            76561198377565432,
            76561198028508165,
            76561198026779638,
            76561198013775203,
            76561198112627553,
            76561198277005351,
            76561198313220322,
            76561197996760388,
            76561197968357064,
            76561197984598389,
            76561198078548926,
            76561198041891495,
            76561198346980693,
            76561197960554164,
            76561198890567999,
            76561198114585399,
            76561198068747739,
            76561198082765157,
            76561197960532616,
            76561198321551799,
            76561197970672279,
            76561198029305165,
            76561197965588718,
            76561198055645163,
            76561198077815123,
            76561198132235994,
            76561197990220861,
            76561198104311295,
            76561198147298672,
            76561198035623512,
            76561198028415882,
            76561197977528867,
            76561198112606289,
            76561198130545082,
            76561198040719002,
            76561198010001511,
            76561198074650486,
            76561198051210203,
            76561198106004590,
            76561198005070096,
            76561197970257188,
            76561197967485417,
            76561198312913303,
            76561199415682308,
            76561197989849128,
            76561199273751121,
            76561197977403803,
            76561198075800444,
            76561198035789301,
            76561197960330700,
            76561198011979289,
            76561198002555892,
            76561198046504053,
            76561198100306249,
            76561197970548935,
            76561198139190743,
            76561198219152947,
            76561198125562823,
            76561198026992236,
            76561198321552794,
            76561197989446733,
            76561198014272103,
            76561198035906518,
            76561199799695391,
            76561198359346391,
            76561198308351970,
            76561198001559322,
            76561198839406428,
            76561198028969193,
            76561198130936889,
            76561198139304625,
            76561197970479334,
            76561198148223691,
            76561197970285890,
            76561197986752656,
            76561198085567251,
            76561197971356759,
            76561198009920610,
            76561197991669382,
            76561198023282990,
            76561197961857994,
            76561198065497949,
            76561198047178231,
            76561198093541039,
            76561198177635874,
            76561198036342287,
            76561198049970296,
            76561198072727400,
            76561198052941278,
            76561198053710885,
            76561198072833066,
            76561198040600573,
            76561198151065365,
            76561198998437078,
            76561198114136579,
            76561198129192831,
            76561197960477226,
            76561198040573679,
            76561198037245513,
            76561198013300512,
            76561198025115329,
            76561197989907277,
            76561197974007233,
            76561198004200726,
            76561197972529603,
            76561198016096893,
            76561198040561960,
            76561197993490341,
            76561197992625648,
            76561198003258890,
            76561198062469228,
            76561198257414959,
            76561198053167763,
            76561197960302579,
            76561198027319973,
            76561197993612995,
            76561197979158138,
            76561198084948591,
            76561198055884873,
            76561198138923135,
            76561197970378912,
            76561197979392232,
            76561198031770629,
            76561198074104374,
            76561198067557075,
            76561198110133835,
            76561197990627522,
            76561197970691370,
            76561197960462483,
            76561197970851257,
            76561198103602015,
            76561198051757267,
            76561198062096138,
            76561198098353911,
            76561197970642447,
            76561198039115706,
            76561197970758289,
            76561197970673455,
            76561198066765397,
            76561198008107842,
            76561197981142609,
            76561197992076130,
            76561198159531833,
            76561198064230555,
            76561198030273896,
            76561198045752225,
            76561198166097372,
            76561197976761795,
            76561198064220280,
            76561197999018973,
            76561198026507269,
            76561198017054389,
            76561198134189436,
            76561197990746461,
            76561198042298738,
            76561198018841605,
            76561198023297831,
            76561197971204006,
            76561197996565477,
            76561198305960245,
            76561198044323597,
            76561198285853567,
            76561197969362616,
            76561198045463085,
            76561198002823435,
            76561198039747760,
            76561198050036517,
            76561198040380492,
            76561198037796318,
            76561198099081012,
            76561198033663431,
            76561197962019866,
            76561199365583923,
            76561197990492433,
            76561197992807568,
            76561198018963744,
            76561197960265749,
            76561197971048113,
            76561198053200093,
            76561198075904194,
            76561198145946545,
            76561198032318007,
            76561198000537256,
            76561198008789775,
            76561198120619094,
            76561198033785465,
            76561197993525512,
            76561197994934521,
            76561198030576533,
            76561198011839810,
            76561198052340158,
            76561197993698981,
            76561198122607176,
            76561198053965300,
            76561198078482246,
            76561198218240912,
            76561198033782224,
            76561199067837755,
            76561198056523764,
            76561198006697906,
            76561198025061331,
            76561198063507168,
            76561198046559893,
            76561198050161752,
            76561198078831158,
            76561197976303200,
            76561197972259379,
            76561198118982727,
            76561198126545924,
            76561197967599040,
            76561198869445968,
            76561198024569356,
            76561197987584995,
            76561198048948841,
            76561197983705136,
            76561198160900075,
            76561198058870490,
            76561198027001357,
            76561198000885362,
            76561198059470973,
            76561198156960400,
            76561197996091247,
            76561198069062200,
            76561198031255971,
            76561197969158018,
            76561198039089657,
            76561198078054877,
            76561198151316669,
            76561197996816992,
            76561198009013127,
            76561198003032905,
            76561198094370568,
            76561198071276876,
            76561197997896525,
            76561198078444091,
            76561198136077175,
            76561198016486782,
            76561198024528824,
            76561198136549274,
            76561198011516446,
            76561198019313469,
            76561198027335328,
            76561198044488388,
            76561197969520868,
            76561198211983788,
            76561197970557283,
            76561198045316700,
            76561197976508482,
            76561198286185639,
            76561197968511678,
            76561198028362020,
            76561198041139462,
            76561197966896320,
            76561198025081902,
            76561198072343374,
            76561198125164789,
            76561198260851718,
            76561198223385552,
            76561198051495245,
            76561198091880157,
            76561199099525135,
            76561198129921987,
            76561198083241021,
            76561197994237580,
            76561198074921847,
            76561197967197052,
            76561198098342214,
            76561198018228127,
            76561198012248506,
            76561198011545009,
            76561198045189623,
            76561197978284105,
            76561198052314353,
            76561197972614454,
            76561197968407019,
            76561198004384623,
            76561198029707247,
            76561197990587455,
            76561198005785233,
            76561198122826308,
            76561197997525590,
            76561198087126470,
            76561198028018671,
            76561198003770847,
            76561199168979577,
            76561198064568395,
            76561198043809500,
            76561198281175891,
            76561198081691855,
            76561198017384135,
            76561198160693238,
            76561197970594515,
            76561197998345602,
            76561198026324627,
            76561198024968498,
            76561197971565582,
            76561198363576174,
            76561198078114634,
            76561198077182192,
            76561198062495540,
            76561198018794458,
            76561198280751409,
            76561197974133625,
            76561198000942210,
            76561197983101869,
            76561197982275081,
            76561198351673664,
            76561198067717494,
            76561198131230651,
            76561198093915416,
            76561197999686451,
            76561197960561169,
            76561198003115494,
            76561197974393359,
            76561198039474824,
            76561198001468649,
            76561198001384872,
            76561198068685808,
            76561198055770803,
            76561198064484943,
            76561198050019099,
            76561198169299825,
            76561198085529088,
            76561198071517589,
            76561198101366739,
            76561198011405182,
            76561198015199992,
            76561199004069906,
            76561198241050434,
            76561198150550857,
            76561198158905982,
            76561198313877230,
            76561198118798719,
            76561197997857627,
            76561198007070703,
            76561198064018552,
            76561198287628621,
            76561197990721580,
            76561197967628180,
            76561198072615110,
            76561198091122385,
            76561197993209165,
            76561197970799580,
            76561198150396857,
            76561198279695780,
            76561198295607770,
            76561198048530931,
            76561198041742609,
            76561198878163382,
            76561197996697802,
            76561198057805082,
            76561198023853577,
            76561197991280042,
            76561197998953068,
            76561198090812491,
            76561198027034019,
            76561197989203587,
            76561198085829633,
            76561198047527390,
            76561198007142386,
            76561197964907623,
            76561198020708554,
            76561198060296206,
            76561198058211957,
            76561197992085306,
            76561197978666713,
            76561198078685126,
            76561198116515265,
            76561198061514519,
            76561198234142828,
            76561198839032966,
            76561198308627039,
            76561197996662419,
            76561197979445690,
            76561198207393095,
            76561198004390798,
            76561198091521195,
            76561198005465695,
            76561198104974360,
            76561198063725672,
            76561197963714403,
            76561199029213468,
            76561197994995452,
            76561197963590173,
            76561198028173888,
            76561197997419024,
            76561198112009549,
            76561197963040896,
            76561197998444372,
            76561197968422114,
            76561197967408154,
            76561198357558302,
            76561198031792303,
            76561198052283077,
            76561198007008912,
            76561198006218423,
            76561198127864208,
            76561197970613303,
            76561198019373005,
            76561198118891321,
            76561198313432047,
            76561198032415501,
            76561197976571431,
            76561198008293937,
            76561198093594122,
            76561197995784864,
            76561198043655647,
            76561198020833533,
            76561198863205604,
            76561198025862827,
            76561198179742038,
            76561198017082605,
            76561198043828367,
            76561198255073210,
            76561197965181332,
            76561197987507997,
            76561197982486651,
            76561198111894292,
            76561198060688156,
            76561197977826934,
            76561198208410516,
            76561197981159039,
            76561198087381980,
            76561197964102547,
            76561197969292180,
            76561198015481934,
            76561198072065628,
            76561198006325591,
            76561198339649191,
            76561198039663324,
            76561197971287348,
            76561197998544521,
            76561197979043237,
            76561198080326946,
            76561197976298658,
            76561197970099174,
            76561198078126278,
            76561198393315345,
            76561198096137689,
            76561198167205706,
            76561198176652222,
            76561198160147881,
            76561198160618322,
            76561197970330150,
            76561198257778274,
            76561198810104246,
            76561198040059649,
            76561198970840083,
            76561198066382393,
            76561198237459734,
            76561198021988758,
            76561198058848103,
            76561198091853107,
            76561198139001462,
            76561197978088497,
            76561197960442683,
            76561197992562594,
            76561198086062937,
            76561198078014418,
            76561197993215917,
            76561198033851262,
        ]

        self.STEAMID64_BASE = (
            76561197960265728  # Valve's base offset for public Steam64 IDs
        )

        self.BASE_DIR = Path(os.path.dirname(os.path.abspath(sys.argv[0])))
        self.DATA_DIR = self.BASE_DIR / "data"
        self.OUTPUT_DIR = self.DATA_DIR / "bins"
        self.SKIP_FILE = self.DATA_DIR / "skip_generation.txt"
        self.NO_ACH_FILE = self.DATA_DIR / "no_achievement_games.txt"
        self.MAX_TRIES_FILE = self.DATA_DIR / "maximum_tries.txt"
        self.SAVED_LOGINS_FILE = self.DATA_DIR / "saved_logins.encrypted"
        self.LAST_ACCOUNT_FILE = self.DATA_DIR / "last_account.txt"
        self.TEMPLATE_FILE = self.DATA_DIR / "UserGameStats_TEMPLATE.bin"
        self.LOG_FILE = self.DATA_DIR / "slscheevo.log"
        self.SILENT_MODE = False
        self.VERBOSE = False
        self.INFINITE_RETRY = False

        # Steam Path Vars
        self.STEAM_DIR = None
        self.LIBRARY_FILE = None
        self.LOGIN_FILE = None
        self.DEST_DIR = None

        # Initialize helper classes
        self.logger = Logger(self)
        self.steam_login = SteamLogin(self)
        self.steam_utils = SteamUtils(self)

    def _get_app_ids(self, args):
        """Helper function to get app IDs from command line or library."""
        if args.appid:
            app_ids = self.steam_utils.parse_app_ids(args.appid)
            if not app_ids:
                self.logger.log_error("No valid app IDs provided with --appid")
                return None
            self.logger.log_info(
                f"Using {len(app_ids)} app IDs from command line: {app_ids}"
            )
            return app_ids
        else:
            app_ids = self.steam_utils.parse_libraryfolders_vdf()
            if not app_ids:
                self.logger.log_error("No app IDs found in library file.")
                return None
            self.logger.log_success(f"Found {len(app_ids)} games in library")
            return app_ids

    def process_add_owner_ids(self, add_owner_id_arg: str):
        """
        Process the --add-owner-id argument.
        - Splits by comma, validates if numeric, adds to self.TOP_OWNER_IDS
        """
        if not add_owner_id_arg:
            return

        raw_ids = [
            id_str.strip() for id_str in add_owner_id_arg.split(",") if id_str.strip()
        ]

        added_ids = []

        for id_str in raw_ids:
            if not id_str.isdigit():
                self.logger.log_warning(f"Skipping invalid (non-numeric) ID: {id_str}")
                continue

            #if len(id_str) != 17:
            #    self.logger.log_warning(f"Skipping invalid length ID: {id_str}")
            #    continue

            if int(id_str) in self.TOP_OWNER_IDS:
                self.logger.log_warning(f"Skipping duplicate ID (already in list): {id_str}")
                continue

            self.TOP_OWNER_IDS.insert(0, id_str)
            added_ids.append(id_str)

        if added_ids:
            self.logger.log_info(f"Added owner IDs: {', '.join(added_ids)}")
        else:
            self.logger.log_warning("No new valid owner IDs were added.")

    def run(self):
        """Main execution method"""
        parser = argparse.ArgumentParser(
            description="SLScheevo - Steam Stats Schema Generator"
        )
        parser.add_argument(
            "--login",
            type=str,
            help="Login using AccountID, SteamID, Steam2 ID, Steam3 ID, or username",
        )
        parser.add_argument(
            "--silent",
            action="store_true",
            help="Silent mode - no input prompts, exit with status codes",
        )
        parser.add_argument(
            "--verbose",
            action="store_true",
            help="Exits on non-critical statuses like no schemas for appid and such",
        )
        parser.add_argument(
            "--noclear",
            action="store_true",
            help="Don't clear console when starting, for developers",
        )
        parser.add_argument(
            "--appid",
            type=str,
            help="Comma-separated list of app IDs to generate schemas for",
        )
        parser.add_argument(
            "--save-dir",
            type=str,
            help="Base directory to save data and outputs (overrides default script-based base dir)",
        )
        parser.add_argument(
            "--max-tries",
            type=int,
            help='Maximum number of consecutive "no schema" responses before giving up',
        )
        parser.add_argument(
            "--infinite-retry",
            action="store_true",
            help="Retry login attempts infinitely when encountering network errors",
        )
        parser.add_argument(
            "--add-owner-id",
            type=str,
            help="Adds custom owner ids separated by commas (eg. 76561198028121353,76561198017975643)",
        )

        args = parser.parse_args()

        self.SILENT_MODE = args.silent
        self.VERBOSE = args.verbose
        self.INFINITE_RETRY = args.infinite_retry

        # If user specified a save directory, update BASE_DIR and all dependent paths
        if args.save_dir:
            requested = Path(args.save_dir).expanduser().resolve()
            if not requested.exists():
                try:
                    requested.mkdir(parents=True, exist_ok=True)
                except OSError as e:
                    self.logger.log_error(
                        f"Could not create save-dir '{requested}': {e}"
                    )
                    sys.exit(EXIT_FILE_ERROR)
            self.BASE_DIR = requested
            self.DATA_DIR = self.BASE_DIR / "data"
            self.OUTPUT_DIR = self.DATA_DIR / "bins"
            self.SKIP_FILE = self.DATA_DIR / "skip_generation.txt"
            self.NO_ACH_FILE = self.DATA_DIR / "no_achievement_games.txt"
            self.MAX_TRIES_FILE = self.DATA_DIR / "maximum_tries.txt"
            self.SAVED_LOGINS_FILE = self.DATA_DIR / "saved_logins.encrypted"
            self.LAST_ACCOUNT_FILE = self.DATA_DIR / "last_account.txt"
            self.TEMPLATE_FILE = self.DATA_DIR / "UserGameStats_TEMPLATE.bin"
            self.LOG_FILE = self.DATA_DIR / "slscheevo.log"

        # Setup logging after paths are configured
        self.logger.setup_logging()
        self.logger.install_global_exception_logger()
        self.process_add_owner_ids(args.add_owner_id)

        # Clear screen based on platform
        if not args.noclear and platform.system() == "Windows":
            os.system("cls")
        elif not args.noclear:
            os.system("clear")

        self.steam_utils.determine_steam_directory()
        self.steam_utils.ensure_directories()
        if args.max_tries is not None:
            max_no_schema_in_row = args.max_tries
            self.logger.log_info(
                f"Using command line max tries: {max_no_schema_in_row}"
            )
        else:
            max_no_schema_in_row = self.steam_utils.get_maximum_tries()


        # Login first to get client
        if args.login:
            client, steam_id64, account_id = self.steam_login.login(args.login)
        else:
            client, steam_id64, account_id = self.steam_login.login()

        if not client:
            self.logger.log_error("Failed to login to Steam")
            sys.exit(EXIT_LOGIN_FAILED)

        if not account_id:
            self.logger.log_error("Could not retrieve account ID")
            client.logout()
            sys.exit(EXIT_NO_ACCOUNT_ID)

        if not steam_id64:
            self.logger.log_error("Could not retrieve Steam ID64")
            client.logout()
            sys.exit(EXIT_NO_ACCOUNT_ID)

        self.logger.log_info(f"Parsed Account ID: {account_id}")
        self.logger.log_info(f"Parsed Steam ID64: {steam_id64}")

        app_ids = self._get_app_ids(args)
        if app_ids is None:
            client.logout()
            sys.exit(EXIT_NO_APP_IDS)

        # Read tracking files
        skip_generation = self.steam_utils.read_tracking_file(self.SKIP_FILE)
        no_achievements = self.steam_utils.read_tracking_file(self.NO_ACH_FILE)

        # Find missing app IDs
        missing_app_ids = []
        for app_id in app_ids:
            if app_id in no_achievements:
                continue  # doesn't have achievements
            if app_id in skip_generation:
                continue  # explicitly skipped

            missing_app_ids.append(app_id)

        if not missing_app_ids:
            self.logger.log_info("No missing stats files to generate")
            client.logout()
            self.steam_utils.copy_bins_to_steam_stats()
            self.steam_utils.prompt_security_warning()
            sys.exit(EXIT_NO_ACTIONS)

        self.logger.log_info(
            f"Generating stats for {len(missing_app_ids)} missing games"
        )

        # Generate missing stats
        success_count = 0
        failed_count = 0

        for i, app_id in enumerate(missing_app_ids, 1):
            self.logger.log_base("")
            self.logger.log_info(f"Progress: {i}/{len(missing_app_ids)}")

            if self.steam_utils.generate_stats_schema_bin(
                app_id, account_id, max_no_schema_in_row, client
            ):
                success_count += 1
            else:
                failed_count += 1

        self.logger.log_base("")
        self.logger.log_success(
            f"Generation complete: {success_count} succeeded, {failed_count} failed"
        )

        client.logout()

        # Copy generated files to Steam directory
        self.steam_utils.copy_bins_to_steam_stats()

        self.steam_utils.prompt_security_warning()

        sys.exit(EXIT_SUCCESS)


def main():
    """Main function to create and run the application"""
    app = Main()
    app.run()


if __name__ == "__main__":
    main()
