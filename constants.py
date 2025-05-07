# -*- coding: utf-8 -*-
"""
Constants for the CryptLink application.
"""
import os
from pathlib import Path

# --- Application Info ---
APP_NAME = "CryptLink"
APP_VERSION = "0.4.0" # Or your current version

# --- Networking ---
DEFAULT_PORT = 7900
BUFFER_SIZE = 262144  # 256 KB buffer for file transfer (was 16384)
SOCKET_TIMEOUT = 5.0 # Timeout for socket operations (accept, connect)
CONNECTION_TIMEOUT = 10.0 # Timeout for establishing a new connection
HEARTBEAT_INTERVAL = 15 # Check connection every 15 seconds
HEARTBEAT_TIMEOUT = HEARTBEAT_INTERVAL * 3 # Timeout after 3 missed heartbeats (45s)


# --- Security & Display ---
FINGERPRINT_DISPLAY_LENGTH = 16 # Show first 16 chars of fingerprint
CONFIRMATION_TIMEOUT = 60.0 # Seconds to wait for user/peer fingerprint confirmation
# Bundle Encryption
BUNDLE_FILE_EXTENSION = ".clb"
BUNDLE_SALT_SIZE = 16
BUNDLE_KDF_ITERATIONS = 480000 # Increased iterations for PBKDF2

# --- GUI Settings ---
SENDER_STATUS_DISPLAY_DURATION = 20000 # milliseconds (20 seconds)

# --- File Transfer ---
FILE_ACCEPT_TIMEOUT = 60.0 # Seconds to wait for user to accept/reject incoming file
FILE_CHUNK_SIZE = 128 * 1024 # 128 KB chunks for file transfer
MAX_CMD_LEN = 5 * 1024 * 1024 # Max length for JSON command messages (5MB) to prevent DoS
MAX_REMEMBERED_PEERS = 10 # Maximum number of peers to remember in the dropdown

# --- Logging ---
LOG_LEVEL_DEBUG = 0
LOG_LEVEL_INFO = 1
LOG_LEVEL_WARN = 2
LOG_LEVEL_ERROR = 3
DEFAULT_LOGGING_LEVEL_STR = "DEBUG" # Default if settings file is missing/corrupt
LOG_LEVEL_MAP = {
    "DEBUG": LOG_LEVEL_DEBUG,
    "INFO": LOG_LEVEL_INFO,
    "WARN": LOG_LEVEL_WARN,
    "ERROR": LOG_LEVEL_ERROR
}
CURRENT_LOG_LEVEL = LOG_LEVEL_MAP[DEFAULT_LOGGING_LEVEL_STR] # Initial default
SETTINGS_FILE_PATH = os.path.join(str(Path.home()), ".cryptlink", "settings.json")
