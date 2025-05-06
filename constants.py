# -*- coding: utf-8 -*-
"""
Constants for the CryptLink application.
"""

# --- Application Info ---
APP_NAME = "CryptLink"
APP_VERSION = "1.10" # Keep version, or increment if desired

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
BUNDLE_KDF_ITERATIONS = 390000 # Adjust as needed, higher is more secure but slower

# --- GUI ---
SENDER_STATUS_DISPLAY_DURATION = 20000 # Milliseconds to display final sender status (20 seconds)

# --- File Transfer ---
# TRANSFER_ACK_TIMEOUT = 20.0 # REMOVED - Sender no longer waits for ACK
FILE_ACCEPT_TIMEOUT = 60.0 # Seconds to wait for user to accept/reject incoming file
FILE_CHUNK_SIZE = 128 * 1024 # 128 KB chunks for file transfer
MAX_CMD_LEN = 5 * 1024 * 1024 # Max length for JSON command messages (5MB) to prevent DoS

# --- Logging ---
LOG_LEVEL_DEBUG = 0
LOG_LEVEL_INFO = 1
LOG_LEVEL_WARN = 2
LOG_LEVEL_ERROR = 3
CURRENT_LOG_LEVEL = LOG_LEVEL_DEBUG # Default logging level
