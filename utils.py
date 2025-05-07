# -*- coding: utf-8 -*-
"""
Utility functions for the CryptLink application.
"""

import socket
import os
import sys
import platform
import subprocess
import importlib.util
import webbrowser # For opening URLs
from pathlib import Path
import tkinter.messagebox as messagebox # For error in open_file

# The 'cryptography' and 'keyring' libraries are now checked by dependencies.py
# Import cryptography components only after check
import cryptography.x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Import constants
try:
    import constants
except ImportError:
    print("ERROR: constants.py not found. Make sure it's in the same directory.", file=sys.stderr)
    sys.exit(1)


def get_local_ip():
    """Gets the local IP address used for outbound connections."""
    s = None
    # Try connecting to a known external host (doesn't send data)
    targets = [("8.8.8.8", 80), ("1.1.1.1", 80)] # Google DNS, Cloudflare DNS
    ip = None
    for target_ip, target_port in targets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Set a short timeout for the connection attempt
            s.settimeout(0.5)
            s.connect((target_ip, target_port))
            ip = s.getsockname()[0]
            break # Success
        except socket.timeout:
            continue # Try next target if timeout occurs
        except OSError: # Catch specific network errors like Network is unreachable
            continue # Try next target
        except Exception: # Catch other potential errors
             continue # Try next target
        finally:
            if s:
                s.close()

    # Fallback if external connection fails (e.g., offline)
    if ip is None:
        try:
            # Try getting hostname and resolving it
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            # If resolved to loopback, try harder (this might still be the only valid IP)
            if ip.startswith("127."):
                 # Check if there are other non-loopback IPs available
                 all_ips = socket.getaddrinfo(hostname, None, socket.AF_INET)
                 non_loopback_ips = [info[4][0] for info in all_ips if not info[4][0].startswith("127.")]
                 if non_loopback_ips:
                     ip = non_loopback_ips[0] # Take the first non-loopback one
                 # else: stick with 127.x.x.x if it's the only one resolved
        except socket.gaierror: # Changed from socket.error for hostname resolution issues
            # Last resort: return loopback as final fallback
            ip = "127.0.0.1"
        except Exception: # Catch other errors during fallback
            ip = "127.0.0.1"

    return ip


def get_certificate_fingerprint(cert_path):
    """Calculates the full SHA-256 fingerprint of a certificate file."""
    if not cert_path or not os.path.exists(cert_path):
        return None # Return None instead of "N/A" for easier checking
    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
        # Use default_backend() here
        cert = cryptography.x509.load_pem_x509_certificate(cert_data, default_backend())
        fingerprint_bytes = cert.fingerprint(hashes.SHA256())
        return fingerprint_bytes.hex().upper() # Return full hex fingerprint
    except ValueError as e:
        # Handle potential PEM parsing errors more specifically
        print(f"Error parsing certificate PEM data from {cert_path}: {e}")
        return "Parse Error" # Keep error strings distinct
    except Exception as e:
        print(f"Error getting fingerprint for {cert_path}: {e}") # Log error
        return "Error"

def format_fingerprint_display(full_fingerprint):
    """Formats the fingerprint for display (shortened and spaced)."""
    if not full_fingerprint or len(full_fingerprint) < constants.FINGERPRINT_DISPLAY_LENGTH:
        return "N/A"
    fp_short = full_fingerprint[:constants.FINGERPRINT_DISPLAY_LENGTH]
    # Insert spaces every 4 characters
    return ' '.join(fp_short[i:i+4] for i in range(0, constants.FINGERPRINT_DISPLAY_LENGTH, 4))


def open_file_in_default_app(file_path):
    """Opens a file using the OS default application."""
    try:
        if not os.path.exists(file_path):
             messagebox.showerror("Error", f"File not found: {file_path}")
             return

        if platform.system() == "Windows":
            os.startfile(file_path)
        elif platform.system() == "Darwin": # macOS
            subprocess.run(["open", file_path], check=True)
        else: # Linux and other Unix-like
            subprocess.run(["xdg-open", file_path], check=True)
    except FileNotFoundError:
        # This might happen if the file exists but the open command doesn't
        messagebox.showerror("Error", f"File not found or 'open'/'xdg-open' command failed: {file_path}")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Command failed opening file '{file_path}': {e}")
    except Exception as e:
        messagebox.showerror("Error", f"Could not open file '{file_path}': {e}")

def open_url_in_browser(url):
    """Opens a URL in the default web browser."""
    try:
        webbrowser.open_new_tab(url)
    except Exception as e:
        # Log to console and show a simple Tkinter error if possible
        print(f"Error opening URL '{url}': {e}")
        messagebox.showerror("Error", f"Could not open URL:\n{url}\n\nError: {e}")

def format_bytes(size):
    """Formats bytes into a human-readable string (KB, MB, GB)."""
    if not isinstance(size, (int, float)) or size < 0:
        return "Invalid size"
    if size < 1024:
        return f"{size} B"
    elif size < 1024**2:
        return f"{size/1024:.2f} KB"
    elif size < 1024**3:
        return f"{size/1024**2:.2f} MB"
    else:
        return f"{size/1024**3:.2f} GB"

def format_eta(seconds):
    """Formats seconds into a human-readable ETA string (HH:MM:SS or MM:SS)."""
    if not isinstance(seconds, (int, float)) or seconds < 0:
        return "N/A"
    if seconds == float('inf') or seconds > 3600 * 24 * 7: # More than a week, consider it "forever"
        return "Unknown"

    seconds = int(seconds)
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    if hours > 0:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"

def get_downloads_folder():
    """Gets the default Downloads folder path for the current OS."""
    try:
        # Use pathlib for better cross-platform handling
        downloads = Path.home() / "Downloads"
        # Check if it exists, create if not (optional, but good practice)
        downloads.mkdir(parents=True, exist_ok=True)
        return str(downloads)
    except Exception as e:
        print(f"Error getting Downloads folder: {e}. Falling back to home directory.")
        # Fallback to home directory if Downloads isn't standard or accessible
        return str(Path.home())

# --- Start of Admin Tools Additions ---

import datetime
import json
import logging
import zipfile
import io
import keyring
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.fernet import Fernet, InvalidToken
import base64
import zlib # For compressing data before storing in keyring
from pathlib import Path # For handling app data directory
# Assuming constants might be better placed in constants.py eventually
KEYRING_SERVICE_NAME = "cryptlink_ca"
CA_CERT_USERNAME = "ca_cert"
CA_KEY_USERNAME = "ca_key"
KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537
CERT_VALIDITY_DAYS = 365 * 5 # 5 years for CA and client certs
# Using constants from constants.py where available
# BUNDLE_SALT_SIZE = 16 # Defined in constants.py
# BUNDLE_KDF_ITERATIONS = 390000 # Defined in constants.py

# Keyring constants for user identity persistence
KEYRING_SERVICE_IDENTITY = "cryptlink_user_identity"
IDENTITY_KEYRING_USERNAME_FERNET_KEY = "identity_fernet_key_v1" # Stores the Fernet key

# Application data storage for the encrypted identity file
APP_DATA_DIR_NAME = ".cryptlink"
ENCRYPTED_IDENTITY_FILENAME = "user_identity.enc"


# Basic logging setup (adjust as needed for your project's logging config)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Cryptography Helpers ---

def generate_private_key():
    """Generates an RSA private key."""
    try:
        private_key = rsa.generate_private_key(
            public_exponent=PUBLIC_EXPONENT,
            key_size=KEY_SIZE,
            backend=default_backend()
        )
        return private_key
    except Exception as e:
        logger.error(f"Error generating private key: {e}")
        return None

def serialize_private_key(private_key, password=None):
    """Serializes a private key to PEM format, optionally encrypting it."""
    try:
        encryption_algorithm = serialization.NoEncryption()
        if password:
            # Ensure password is bytes
            password_bytes = password.encode('utf-8') if isinstance(password, str) else password
            encryption_algorithm = serialization.BestAvailableEncryption(password_bytes)

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        return pem.decode('utf-8')
    except Exception as e:
        logger.error(f"Error serializing private key: {e}")
        return None

def serialize_certificate(cert):
    """Serializes a certificate to PEM format."""
    try:
        pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
        return pem.decode('utf-8')
    except Exception as e:
        logger.error(f"Error serializing certificate: {e}")
        return None

def load_private_key_from_pem(pem_data, password=None):
    """Loads a private key from PEM data."""
    try:
        password_bytes = password.encode('utf-8') if password else None
        private_key = serialization.load_pem_private_key(
            pem_data.encode('utf-8'),
            password=password_bytes,
            backend=default_backend()
        )
        return private_key
    except (ValueError, TypeError, serialization.UnsupportedAlgorithm) as e:
        logger.error(f"Error loading private key from PEM: {e}")
        return None

def load_cert_from_pem(pem_data):
    """Loads a certificate from PEM data."""
    try:
        cert = x509.load_pem_x509_certificate(pem_data.encode('utf-8'), default_backend())
        return cert
    except ValueError as e:
        logger.error(f"Error loading certificate from PEM: {e}")
        return None

# --- CA Management ---

def create_and_store_ca(subject_attrs):
    """Generates a CA certificate and key, stores them securely in the system keyring."""
    try:
        ca_private_key = generate_private_key()
        if not ca_private_key:
            return False, "Failed to generate CA private key."

        # Build subject name from provided attributes
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, subject_attrs.get("C", "XX")),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject_attrs.get("ST", "State")),
            x509.NameAttribute(NameOID.LOCALITY_NAME, subject_attrs.get("L", "City")),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_attrs.get("O", "Organization")),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject_attrs.get("OU", "Unit")),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_attrs.get("CN", "CryptLink Root CA")),
        ])

        ca_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            ca_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=CERT_VALIDITY_DAYS)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(ca_private_key, hashes.SHA256(), default_backend())

        # Serialize (no password for key storage in keyring, rely on keyring security)
        ca_key_pem = serialize_private_key(ca_private_key)
        ca_cert_pem = serialize_certificate(ca_cert)

        if not ca_key_pem or not ca_cert_pem:
             return False, "Failed to serialize CA key or certificate."

        # Store in keyring
        keyring.set_password(KEYRING_SERVICE_NAME, CA_KEY_USERNAME, ca_key_pem)
        keyring.set_password(KEYRING_SERVICE_NAME, CA_CERT_USERNAME, ca_cert_pem)
        logger.info("CA certificate and key stored successfully in keyring.")
        return True, "CA created and stored successfully."

    except Exception as e:
        logger.error(f"Error creating or storing CA: {e}", exc_info=True)
        return False, f"Error creating or storing CA: {e}"

def get_ca_from_keyring():
    """Retrieves the CA certificate and key from the keyring."""
    try:
        ca_key_pem = keyring.get_password(KEYRING_SERVICE_NAME, CA_KEY_USERNAME)
        ca_cert_pem = keyring.get_password(KEYRING_SERVICE_NAME, CA_CERT_USERNAME)

        if not ca_key_pem or not ca_cert_pem:
            logger.warning("CA key or certificate not found in keyring.")
            return None, None, "CA key or certificate not found in keyring."

        ca_private_key = load_private_key_from_pem(ca_key_pem)
        ca_cert = load_cert_from_pem(ca_cert_pem)

        if not ca_private_key or not ca_cert:
             return None, None, "Failed to load CA key or certificate from stored PEM."

        logger.info("CA certificate and key retrieved successfully from keyring.")
        return ca_cert, ca_private_key, "CA retrieved successfully."

    except Exception as e:
        logger.error(f"Error retrieving CA from keyring: {e}", exc_info=True)
        return None, None, f"Error retrieving CA from keyring: {e}"

def export_ca_from_keyring(cert_output_path, key_output_path):
    """Retrieves CA cert and key from keyring and saves them to specified PEM files."""
    try:
        ca_cert, ca_private_key, msg = get_ca_from_keyring()
        if not ca_cert or not ca_private_key:
            return False, f"Cannot export: {msg}"

        ca_cert_pem = serialize_certificate(ca_cert)
        ca_key_pem = serialize_private_key(ca_private_key) # Key is stored unencrypted in keyring

        if not ca_cert_pem or not ca_key_pem:
            return False, "Failed to serialize CA certificate or key after retrieval."

        with open(cert_output_path, 'w') as f:
            f.write(ca_cert_pem)
        with open(key_output_path, 'w') as f:
            f.write(ca_key_pem)

        logger.info(f"CA exported successfully to {cert_output_path} and {key_output_path}")
        return True, "CA exported successfully."

    except OSError as e:
        logger.error(f"Error writing CA files during export: {e}", exc_info=True)
        return False, f"Error writing files: {e}"
    except Exception as e:
        logger.error(f"Error exporting CA from keyring: {e}", exc_info=True)
        return False, f"Error exporting CA: {e}"

def clear_ca_from_keyring():
    """Removes the CA certificate and key from the system keyring."""
    try:
        keyring.delete_password(KEYRING_SERVICE_NAME, CA_KEY_USERNAME)
        keyring.delete_password(KEYRING_SERVICE_NAME, CA_CERT_USERNAME)
        logger.info("CA certificate and key removed from keyring.")
        return True, "CA cleared successfully from keyring."
    except keyring.errors.PasswordDeleteError as e:
        logger.error(f"Error deleting CA from keyring (might not exist): {e}", exc_info=True)
        return False, f"Error deleting CA from keyring: {e}" # Might fail if not found, treat as warning?
    except Exception as e:
        logger.error(f"Unexpected error clearing CA from keyring: {e}", exc_info=True)
        return False, f"Unexpected error clearing CA: {e}"

# --- Client Cert Generation ---

def create_client_cert_and_key(ca_cert, ca_private_key, client_common_name):
    """Generates a client certificate and key signed by the provided CA."""
    try:
        client_private_key = generate_private_key()
        if not client_private_key:
            return None, None, "Failed to generate client private key."

        # Build subject name based on CA, but override CN
        ca_subject_attrs = {attr.oid: attr.value for attr in ca_cert.subject}
        # Use CA's attributes but replace the Common Name
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, ca_subject_attrs.get(NameOID.COUNTRY_NAME, "XX")),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ca_subject_attrs.get(NameOID.STATE_OR_PROVINCE_NAME, "State")),
            x509.NameAttribute(NameOID.LOCALITY_NAME, ca_subject_attrs.get(NameOID.LOCALITY_NAME, "City")),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ca_subject_attrs.get(NameOID.ORGANIZATION_NAME, "Organization")),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ca_subject_attrs.get(NameOID.ORGANIZATIONAL_UNIT_NAME, "Unit")),
            x509.NameAttribute(NameOID.COMMON_NAME, client_common_name), # Use the provided CN
        ])
        issuer = ca_cert.subject # Signed by the CA

        client_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            client_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=CERT_VALIDITY_DAYS)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        ).add_extension(
            x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False,
                          data_encipherment=False, key_agreement=False, encipher_only=False,
                          decipher_only=False, key_cert_sign=False, crl_sign=False), critical=True
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH  # Added for server role
            ]), critical=False
        ).sign(ca_private_key, hashes.SHA256(), default_backend())

        # Serialize (no password for key bundling)
        client_key_pem = serialize_private_key(client_private_key)
        client_cert_pem = serialize_certificate(client_cert)

        if not client_key_pem or not client_cert_pem:
             return None, None, "Failed to serialize client key or certificate."

        logger.info(f"Client certificate and key generated for CN={client_common_name}")
        return client_cert_pem, client_key_pem, "Client certificate and key generated successfully."

    except Exception as e:
        # client_common_name is already defined from the function argument
        return None, None, f"Error creating client certificate/key: {e}"

# --- Bundling Logic ---

def _derive_key(password: str, salt: bytes) -> bytes:
    """Derives a Fernet key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # Fernet key length
        salt=salt,
        iterations=constants.BUNDLE_KDF_ITERATIONS, # Use constant from constants.py
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key

def create_encrypted_bundle(output_path: str, password: str, ca_cert: x509.Certificate, client_cert_pem: str, client_key_pem: str, client_cn: str):
    """Creates a password-protected, encrypted .clb bundle containing certs and key."""
    try:
        # Extract CA Common Name for display
        ca_cn = "ca" # Default if CN not found
        try:
            ca_cn = ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except IndexError:
            logger.warning("Could not extract Common Name from CA certificate for bundle naming.")

        # Use the exact same structure as the main GUI export (_encrypt_certs)
        # Base64 encode the PEM strings (as bytes) and decode to ASCII for JSON compatibility
        ca_cert_pem = serialize_certificate(ca_cert) # Serialize the CA cert object to PEM
        if not ca_cert_pem:
            raise ValueError("Failed to serialize CA certificate for bundle.")

        bundle_content = {
            "ca_name": f"{ca_cn}.pem", # Use CA CN for display name
            "cert_name": f"{client_cn}.pem", # Use client CN for display name
            "key_name": f"{client_cn}.key", # Use client CN for display name
            "ca_b64": base64.b64encode(ca_cert_pem.encode('utf-8')).decode('ascii'),
            "cert_b64": base64.b64encode(client_cert_pem.encode('utf-8')).decode('ascii'),
            "key_b64": base64.b64encode(client_key_pem.encode('utf-8')).decode('ascii'),
        }
        content_json = json.dumps(bundle_content, indent=2)

        # --- Removed Zip File Logic ---
        # The main import expects the JSON to be encrypted directly, not zipped first.
        # zip_buffer = io.BytesIO()
        # with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        #     zipf.writestr("cryptlink_bundle.json", content_json)
        # zip_data = zip_buffer.getvalue()

        # Encrypt the zipped data
        salt = os.urandom(constants.BUNDLE_SALT_SIZE) # Use constant from constants.py
        key = _derive_key(password, salt)
        f = Fernet(key)

        # Encrypt the JSON data directly
        encrypted_data = f.encrypt(content_json.encode('utf-8'))

        # Write salt + encrypted JSON data to the output file
        logger.debug(f"Attempting to write bundle to: {output_path}") # Add debug log
        with open(output_path, 'wb') as f_out:
            f_out.write(salt)
            f_out.write(encrypted_data)

        logger.info(f"Encrypted bundle created successfully at {output_path}")
        return True, f"Bundle created successfully at {output_path}"

    except Exception as e:
        # Ensure exc_info=True to get the traceback in the logs
        logger.error(f"Error creating encrypted bundle for path '{output_path}': {e}", exc_info=True)
        return False, f"Error creating encrypted bundle: {e}"

def load_encrypted_bundle(file_path: str, password: str):
    """Loads and decrypts a .clb bundle, returning the content dictionary."""
    try:
        with open(file_path, 'rb') as f_in:
            salt = f_in.read(constants.BUNDLE_SALT_SIZE) # Use constant from constants.py
            encrypted_data = f_in.read()

        if len(salt) != constants.BUNDLE_SALT_SIZE: # Use constant from constants.py
             logger.error(f"Bundle file {file_path} is too short or corrupted.")
             return None, "Bundle file is too short or corrupted."

        key = _derive_key(password, salt)
        f = Fernet(key)
        decrypted_json_bytes = f.decrypt(encrypted_data) # Can raise InvalidToken

        # Decode and parse the JSON
        bundle_data = json.loads(decrypted_json_bytes.decode('utf-8'))

        # Basic validation (using keys expected by _decrypt_certs)
        required_keys = ["ca_name", "cert_name", "key_name", "ca_b64", "cert_b64", "key_b64"]
        if not all(k in bundle_data for k in required_keys):
            logger.error(f"Bundle {file_path} is missing required keys.")
            return None, "Bundle format error: Missing required keys."

        logger.info(f"Bundle loaded successfully from {file_path}")
        return bundle_data, "Bundle loaded successfully."

    except (FileNotFoundError, IsADirectoryError):
        logger.error(f"Bundle file not found: {file_path}")
        return None, "Bundle file not found."
    except InvalidToken:
        logger.error(f"Failed to decrypt bundle {file_path}: Invalid password or corrupt file.")
        return None, "Failed to decrypt bundle. Invalid password or corrupt file."
    except (json.JSONDecodeError, ValueError, TypeError, base64.binascii.Error) as e:
        logger.error(f"Error parsing bundle {file_path}: {e}")
        return None, f"Failed to parse bundle content: {e}"
    except Exception as e:
        logger.error(f"Unexpected error loading bundle {file_path}: {e}", exc_info=True)
        return None, f"Unexpected error loading bundle: {e}"

# --- User Identity Persistence in Keyring ---

def _get_app_data_file_path() -> Path:
    """Returns the path to the encrypted identity file in the app's data directory."""
    home_dir = Path.home()
    app_data_dir = home_dir / APP_DATA_DIR_NAME
    app_data_dir.mkdir(parents=True, exist_ok=True) # Ensure directory exists
    return app_data_dir / ENCRYPTED_IDENTITY_FILENAME

def save_identity_to_keyring(ca_cert_pem: str, client_cert_pem: str, client_key_pem: str,
                             ca_display_name: str, client_cert_display_name: str, client_key_display_name: str) -> tuple[bool, str]:
    """
    Encrypts the identity bundle and saves it to a file.
    Saves the encryption key to the system keyring.
    """
    try:
        if not all([ca_cert_pem, client_cert_pem, client_key_pem,
                    ca_display_name, client_cert_display_name, client_key_display_name]):
            return False, "Missing one or more required identity components."

        identity_data = {
            "ca_cert_pem": ca_cert_pem,
            "client_cert_pem": client_cert_pem,
            "client_key_pem": client_key_pem,
            "ca_display_name": ca_display_name,
            "client_cert_display_name": client_cert_display_name,
            "client_key_display_name": client_key_display_name
        }
        identity_json = json.dumps(identity_data).encode('utf-8')

        fernet_key = Fernet.generate_key()
        f = Fernet(fernet_key)
        encrypted_identity = f.encrypt(identity_json)

        encrypted_file_path = _get_app_data_file_path()
        with open(encrypted_file_path, "wb") as ef:
            ef.write(encrypted_identity)

        keyring.set_password(KEYRING_SERVICE_IDENTITY, IDENTITY_KEYRING_USERNAME_FERNET_KEY, fernet_key.decode('ascii'))

        logger.info("User identity saved to keyring successfully.")
        return True, "Identity saved to keyring."
    except Exception as e:
        logger.error(f"Error saving identity to keyring: {e}", exc_info=True)
        # Attempt to clean up if partially saved
        try:
            clear_identity_from_keyring()
        except Exception:
            pass # Ignore cleanup errors during primary error handling
        return False, f"Error saving identity to keyring: {e}"

def get_identity_from_keyring() -> tuple[dict | None, str]:
    """
    Retrieves the encryption key from keyring, decrypts the identity file,
    and returns the identity data.
    """
    try:
        fernet_key_str = keyring.get_password(KEYRING_SERVICE_IDENTITY, IDENTITY_KEYRING_USERNAME_FERNET_KEY)
        if not fernet_key_str:
            return None, "No identity Fernet key found in keyring."

        fernet_key = fernet_key_str.encode('ascii')
        f = Fernet(fernet_key)

        encrypted_file_path = _get_app_data_file_path()
        if not encrypted_file_path.exists():
            logger.warning(f"Encrypted identity file not found at {encrypted_file_path}, but key exists in keyring. Clearing key.")
            try:
                keyring.delete_password(KEYRING_SERVICE_IDENTITY, IDENTITY_KEYRING_USERNAME_FERNET_KEY)
            except Exception:
                pass # Ignore error during cleanup
            return None, "Encrypted identity file missing."

        with open(encrypted_file_path, "rb") as ef:
            encrypted_identity = ef.read()

        decrypted_json = f.decrypt(encrypted_identity)
        identity_data_pem = json.loads(decrypted_json.decode('utf-8'))

        # Validate required keys
        required_keys = [
            "ca_cert_pem", "client_cert_pem", "client_key_pem",
            "ca_display_name", "client_cert_display_name", "client_key_display_name"
        ]
        if not all(key in identity_data_pem for key in required_keys):
            logger.error("Identity data from decrypted file is missing required keys.")
            clear_identity_from_keyring() # Clear corrupted/invalid entry
            return None, "Invalid identity format in decrypted file. Entry cleared."

        logger.info("User identity retrieved and parsed from keyring successfully.")
        return identity_data_pem, "Identity loaded from keyring."

    except FileNotFoundError:
        logger.info(f"Encrypted identity file not found at expected path. This is normal if no identity is saved.")
        return None, "Encrypted identity file not found."
    except InvalidToken:
        logger.error("Failed to decrypt identity file: Invalid Fernet key or corrupted file.", exc_info=True)
        clear_identity_from_keyring() # Clear corrupted entry
        return None, "Corrupted identity (decryption failed). Entry cleared."
    except (json.JSONDecodeError, TypeError) as e:
        logger.error(f"Error decoding identity JSON from decrypted file: {e}", exc_info=True)
        clear_identity_from_keyring() # Clear corrupted entry
        return None, "Corrupted identity (JSON error). Entry cleared."
    except Exception as e: # Catch other keyring or unexpected errors
        logger.error(f"Error retrieving identity from keyring: {e}", exc_info=True)
        return None, f"Error retrieving identity from keyring: {e}"

def clear_identity_from_keyring() -> tuple[bool, str]:
    """Removes the Fernet key from keyring and deletes the encrypted identity file."""
    key_deleted = False
    file_deleted = False
    errors = []

    try:
        keyring.delete_password(KEYRING_SERVICE_IDENTITY, IDENTITY_KEYRING_USERNAME_FERNET_KEY)
        logger.info("Identity Fernet key removed from keyring.")
        key_deleted = True
    except keyring.errors.PasswordDeleteError:
        logger.info("Identity Fernet key not found in keyring (already cleared or never set).")
        key_deleted = True # Consider it success for clearing
    except Exception as e:
        logger.error(f"Error clearing identity Fernet key from keyring: {e}", exc_info=True)
        errors.append(f"Keyring error: {e}")

    try:
        encrypted_file_path = _get_app_data_file_path()
        if encrypted_file_path.exists():
            os.remove(encrypted_file_path)
            logger.info(f"Encrypted identity file removed: {encrypted_file_path}")
            file_deleted = True
        else:
            logger.info("Encrypted identity file not found (already deleted or never created).")
            file_deleted = True # Consider it success for clearing
    except OSError as e:
        logger.error(f"Error removing encrypted identity file {encrypted_file_path}: {e}", exc_info=True)
        errors.append(f"File deletion error: {e}")
    except Exception as e:
        logger.error(f"Unexpected error removing encrypted identity file: {e}", exc_info=True)
        errors.append(f"File deletion error: {e}")

    if key_deleted and file_deleted and not errors:
        return True, "Identity cleared from keyring and disk."
    elif errors:
        return False, f"Errors encountered while clearing identity: {'; '.join(errors)}"
    else: # Should not happen if logic is correct
        return True, "Identity cleared (some components might have been missing)."


# --- End of Admin Tools Additions ---
