# -*- coding: utf-8 -*-
"""
CryptLink: Secure Peer-to-Peer File Transfer Application
Main application class.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog # Keep messagebox/simpledialog for direct use
import os
import sys
import socket
import ssl
import threading
import queue
import json
import time
import datetime
import base64
import tempfile
import hashlib
import re # For parsing peer input string

# --- Import Third-Party Libraries ---
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.exceptions import UnsupportedAlgorithm
    import keyring
    import keyring.errors
except ImportError as e:
    # This error should ideally be caught by dependencies.py first
    print(f"ERROR: Missing critical dependencies: {e}", file=sys.stderr)
    # Attempt a Tkinter popup if possible, as a fallback
    try:
        root_err = tk.Tk()
        root_err.withdraw()
        messagebox.showerror("Dependency Error", f"A critical dependency is missing: {e}\nPlease run main.py to install dependencies.")
        root_err.destroy()
    except tk.TclError:
        pass # Fallback to console output if Tkinter isn't fully available
    sys.exit(1)

# --- Import Local Modules ---
try:
    import constants
    import utils
    import gui # The new GUI module
except ImportError as e:
    print(f"ERROR: Failed to import local modules (constants.py, utils.py, gui.py): {e}", file=sys.stderr)
    print("Ensure all .py files are in the same directory or accessible in PYTHONPATH.", file=sys.stderr)
    try:
        root_err = tk.Tk()
        root_err.withdraw()
        messagebox.showerror("Import Error", f"Failed to import required modules: {e}\nEnsure constants.py, utils.py, and gui.py are present.")
        root_err.destroy()
    except tk.TclError:
        pass
    sys.exit(1)


class CryptLinkApp:
    def __init__(self, root_window):
        self.root = root_window
        self.root.title(f"{constants.APP_NAME} v{constants.APP_VERSION}")
        self.root.protocol("WM_DELETE_WINDOW", self._quit_app)
        # Attempt to set a modern theme
        try:
            style = ttk.Style()
            #('winnative', 'clam', 'alt', 'default', 'classic', 'vista', 'xpnative')
            available_themes = style.theme_names()
            if 'clam' in available_themes: style.theme_use('clam')
            elif 'vista' in available_themes: style.theme_use('vista')
        except tk.TclError:
            self._log_message("Could not set custom theme, using default.", constants.LOG_LEVEL_WARN)


        # --- State Variables ---
        self.ca_cert_path = tk.StringVar()
        self.client_cert_path = tk.StringVar()
        self.client_key_path = tk.StringVar()
        self.ca_cert_display_name = tk.StringVar()
        self.client_cert_display_name = tk.StringVar()
        self.client_key_display_name = tk.StringVar()

        self.connection_status = tk.StringVar(value="Initializing...")
        self.peer_ip_hostname = tk.StringVar()
        self.local_fingerprint_display = tk.StringVar(value="N/A")
        self.peer_fingerprint_display = tk.StringVar(value="N/A")
        self.peer_hostname = tk.StringVar(value="N/A") # For display

        self.file_to_send_path = tk.StringVar()
        self.transfer_progress = tk.DoubleVar(value=0.0)
        self.sender_transfer_status = tk.StringVar()
        self.transfer_speed = tk.StringVar(value="Speed: N/A")
        self.transfer_eta = tk.StringVar(value="ETA: N/A")

        self.remembered_peers = [] # List of {'ip': '...', 'hostname': '...', 'fingerprint': '...'}
        self.certs_loaded_correctly = False
        self.bundle_exported_this_session = False # Track if current certs came from manual load and were then exported
        self.loaded_from_bundle = False # True if current certs were loaded from a .clb file
        self.identity_loaded_from_keyring = False # True if current identity loaded from system keyring
        self.keyring_has_user_identity = False # Updated by _load_identity_from_keyring_on_startup

        self.is_connected = False
        self.is_connecting = False
        self.is_transferring = False
        self.transfer_cancelled_by_user = False
        self.current_transfer_info = {} # {'filename', 'filesize', 'role': 'sender'/'receiver'}
        self.received_files = {} # display_name: full_path
        self.temp_cert_files = [] # Store paths of temporary cert files from bundle import

        # --- Networking ---
        self.local_ip = utils.get_local_ip()
        self.local_hostname = socket.gethostname()
        self.server_socket = None
        self.client_socket = None # Represents the active connection socket (either from server or client role)
        # self.ssl_context = None # This is now created locally in server/client methods
        self.peer_info = {} # Store dict of peer's hostname, ip, fingerprint
        self.local_full_fingerprint = None
        self.peer_full_fingerprint = None

        # --- Threading & Queues ---
        self.gui_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.server_thread = None
        self.client_connection_thread = None # For outgoing connections
        self.heartbeat_thread = None
        self.heartbeat_lock = threading.Lock()
        # self._socket_write_lock = threading.Lock() # This was added in a previous step for bug fix
        self._socket_write_lock = threading.Lock() # ADD THIS LINE for serializing socket writes
        self.last_heartbeat_ack_time = 0
        self.sender_status_clear_timer = None # For gui.py to manage

        # --- Admin Tools Specific ---
        self.admin_ca_cert = None # Stores loaded CA cert (PEM bytes) for admin use
        self.admin_ca_key = None  # Stores loaded CA key (PEM bytes) for admin use

        # --- Chat Feature State ---
        # Chat view widgets will be assigned here after creation by chat.create_chat_widgets
        self.chat_view_frame_container = None
        self.chat_status_frame_replica = None # The status frame within the chat view
        self.chat_view_status_label = None
        self.chat_view_local_info_label = None
        self.chat_view_local_fp_label = None
        self.chat_view_peer_info_label = None
        self.chat_view_peer_fp_label = None
        self.chat_right_frame = None
        self.chat_conversation_area = None
        self.chat_input_frame = None
        self.chat_message_entry = None
        self.chat_send_button = None
        self.chat_view_quit_button = None # For the new quit button in chat view

        # --- Application Settings ---
        self.app_settings = {} # Will be loaded from file
        self.logging_verbosity_var = tk.StringVar() # For the settings UI
        self.manual_id_config_enabled_var = tk.BooleanVar(value=False) # Default to False
        self._load_app_settings() # Load settings on startup

        # --- Create GUI Widgets (delegated to gui.py) ---
        gui.create_widgets(self) # Pass self (app instance) to gui functions

        # --- Initial Setup ---
        gui.update_local_info(self)
        self._load_identity_from_keyring_on_startup() # Attempt to load saved identity
        # gui.set_connection_status will be called by _load_identity_from_keyring_on_startup or if it fails
        if not self.certs_loaded_correctly:
            gui.set_connection_status(self, "No Certs")

        self._process_gui_queue() # Start the GUI queue processor

    def _log_message(self, message, level=constants.LOG_LEVEL_INFO):
        """Formats and queues a message for logging in the GUI."""
        if level < constants.CURRENT_LOG_LEVEL:
            return
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        self.gui_queue.put(("log", log_entry))
        if level >= constants.LOG_LEVEL_ERROR: # Also print errors to stderr
            print(f"ERROR: {message}", file=sys.stderr)

    def _process_gui_queue(self):
        """Processes messages from the GUI queue to update Tkinter widgets safely."""
        try:
            while not self.gui_queue.empty():
                msg_type, data = self.gui_queue.get_nowait()
                if not self.root.winfo_exists(): # Check if root window is still alive
                    if msg_type != "log": # Avoid logging about log if window is gone
                        print(f"GUI queue: Root window destroyed, discarding {msg_type}")
                    continue

                if msg_type == "log":
                    gui.update_log_widget(self, data)
                elif msg_type == "status":
                    gui.set_connection_status(self, data)
                elif msg_type == "peer_info":
                    peer_host, peer_info_dict = data
                    gui.update_peer_info_display(self, peer_host, peer_info_dict)
                elif msg_type == "clear_peer_info":
                    gui.clear_peer_info_display(self)
                elif msg_type == "progress":
                    progress, speed, eta = data
                    gui.update_progress_display(self, progress, speed, eta)
                elif msg_type == "sender_status":
                    text, color, temporary = data
                    gui.update_sender_status(self, text, color, temporary)
                elif msg_type == "transfer_complete_ui":
                    gui.handle_transfer_complete_ui(self, is_sender_role=data)
                elif msg_type == "transfer_cancelled_ui":
                    gui.handle_transfer_cancelled_ui(self, is_sender_role=data)
                elif msg_type == "add_received_file":
                    display_name, full_path = data
                    gui.add_received_file_display(self, display_name, full_path)
                elif msg_type == "show_error":
                    messagebox.showerror("Error", data, parent=self.root)
                elif msg_type == "show_info":
                    messagebox.showinfo("Information", data, parent=self.root)
                elif msg_type == "show_warning":
                    messagebox.showwarning("Warning", data, parent=self.root)
                elif msg_type == "prompt_fingerprint":
                    peer_fp_display, callback = data
                    self._verify_peer_fingerprint_dialog(peer_fp_display, callback)
                elif msg_type == "update_peer_list_dropdown":
                    gui.update_peer_list_dropdown(self) # Call the GUI function to update the dropdown
                elif msg_type == "chat_message_display": # New queue message type for chat
                    gui.append_chat_message(self, data['sender_type'], data['text'], data.get('timestamp'))
                elif msg_type == "prompt_file_accept":
                    filename, filesize_str, callback = data
                    self._prompt_accept_file_dialog(filename, filesize_str, callback)

        except queue.Empty:
            pass
        except Exception as e:
            # Log any unexpected error during queue processing
            self._log_message(f"Error processing GUI queue: {e}", constants.LOG_LEVEL_ERROR)
        finally:
            if self.root.winfo_exists(): # Schedule next check only if window exists
                self.root.after(100, self._process_gui_queue)

    def _save_certs(self):
        """Validates selected certificates and key, then updates status."""
        self._log_message("Attempting to load and validate certificates...")
        ca_path = self.ca_cert_path.get()
        cert_path = self.client_cert_path.get()
        key_path = self.client_key_path.get()

        if not all([ca_path, cert_path, key_path]):
            self.gui_queue.put(("show_error", "All certificate/key files must be selected."))
            self._log_message("Certificate loading failed: Not all files selected.", constants.LOG_LEVEL_WARN)
            return

        for p, name in [(ca_path, "CA cert"), (cert_path, "Client cert"), (key_path, "Client key")]:
            if not os.path.exists(p):
                self.gui_queue.put(("show_error", f"{name} file not found: {os.path.basename(p)}"))
                self._log_message(f"Certificate loading failed: {name} file not found: {p}", constants.LOG_LEVEL_ERROR)
                return

        try:
            # Basic validation: can we load them?
            with open(ca_path, "rb") as f: utils.load_cert_from_pem(f.read().decode('utf-8'))
            with open(cert_path, "rb") as f: utils.load_cert_from_pem(f.read().decode('utf-8'))
            with open(key_path, "rb") as f: utils.load_private_key_from_pem(f.read().decode('utf-8'), password=None)

            self.certs_loaded_correctly = True
            self._log_message("Certificates and key loaded and appear valid.")
            gui.update_local_info(self) # Update fingerprint display
            gui.set_connection_status(self, "Certs Loaded")
            gui.visual_feedback(self, self.save_certs_button, "Load Certs", "Loaded!")

            if not self.loaded_from_bundle and not self.identity_loaded_from_keyring:
                # Only prompt if certs were manually selected and not yet exported or from keyring
                gui.prompt_export_after_load(self)
            gui.update_identity_persistence_buttons_state(self)
            # Explicitly try to start the server now that certs are confirmed valid
            self._start_server_if_needed()

        except ValueError as e: # Catches errors from cryptography library loading
            self.certs_loaded_correctly = False
            self.gui_queue.put(("show_error", f"Error loading certificate/key: {e}"))
            self._log_message(f"Certificate validation error: {e}", constants.LOG_LEVEL_ERROR)
            gui.set_connection_status(self, "No Certs")
            self.local_fingerprint_display.set("N/A")
            self.local_full_fingerprint = None
        except Exception as e:
            self.certs_loaded_correctly = False
            self.gui_queue.put(("show_error", f"An unexpected error occurred validating certificates: {e}"))
            self._log_message(f"Unexpected certificate validation error: {e}", constants.LOG_LEVEL_ERROR)
            gui.set_connection_status(self, "No Certs")
            self.local_fingerprint_display.set("N/A")
            self.local_full_fingerprint = None
        finally:
            gui.check_enable_load_certs(self) # Update button states regardless

    def _prepare_bundle_data_for_encryption(self, password):
        """Reads current cert/key files, returns salt and encrypted data for bundle."""
        if not self.certs_loaded_correctly:
            self._log_message("Cannot prepare bundle data: Certificates not loaded correctly.", constants.LOG_LEVEL_ERROR)
            return None
        try:
            with open(self.ca_cert_path.get(), "rb") as f: ca_data = f.read()
            with open(self.client_cert_path.get(), "rb") as f: cert_data = f.read()
            with open(self.client_key_path.get(), "rb") as f: key_data = f.read()

            # Use utils function to perform the encryption logic
            return utils.create_encrypted_bundle_from_data(
                password,
                ca_data, cert_data, key_data,
                self.ca_cert_display_name.get(),
                self.client_cert_display_name.get(),
                self.client_key_display_name.get()
            )
        except Exception as e:
            self._log_message(f"Error preparing bundle data for encryption: {e}", constants.LOG_LEVEL_ERROR)
            self.gui_queue.put(("show_error", f"Failed to prepare bundle data:\n{e}"))
            return None

    def _decrypt_bundle_data_from_file(self, bundle_path, password):
        """Reads and decrypts a bundle file, returns dictionary of certs_info."""
        try:
            # utils.load_encrypted_bundle returns (bundle_data, message) or (None, message)
            bundle_data, message = utils.load_encrypted_bundle(bundle_path, password)
            if bundle_data:
                return bundle_data
            else:
                # Log the message from utils.load_encrypted_bundle if it failed there
                self._log_message(f"Bundle decryption/load failed: {message}", constants.LOG_LEVEL_ERROR)
                # The InvalidToken exception below will handle showing a generic error to the user
                # or we can show the specific message if it's not an InvalidToken.
                if "Invalid password or corrupt bundle" not in message and "Bundle file not found" not in message : # Avoid duplicate generic messages
                    self.gui_queue.put(("show_error", f"Failed to load bundle: {message}"))
                return None # Ensure None is returned on failure
        except InvalidToken:
            self._log_message("Bundle decryption failed: Invalid password or corrupt bundle.", constants.LOG_LEVEL_ERROR)
            self.gui_queue.put(("show_error", "Invalid password or corrupt bundle file."))
            return None
        except Exception as e:
            self._log_message(f"Error decrypting bundle data: {e}", constants.LOG_LEVEL_ERROR)
            self.gui_queue.put(("show_error", f"Failed to decrypt bundle:\n{e}"))
            return None

    def _write_temp_cert(self, cert_data_pem, suffix=".crt"):
        """Writes certificate data to a temporary file and returns its path."""
        # Ensure cert_data_pem is bytes
        if isinstance(cert_data_pem, str):
            cert_data_pem = cert_data_pem.encode('utf-8')

        fd, temp_path = tempfile.mkstemp(suffix=suffix, prefix="cryptlink_")
        with os.fdopen(fd, "wb") as f:
            f.write(cert_data_pem)
        self.temp_cert_files.append(temp_path)
        self._log_message(f"Created temporary certificate file: {os.path.basename(temp_path)}", constants.LOG_LEVEL_DEBUG)
        return temp_path

    def _cleanup_temp_files(self):
        """Deletes any temporary certificate files created during bundle import."""
        cleaned_count = 0
        for path in self.temp_cert_files:
            try:
                if os.path.exists(path):
                    os.remove(path)
                    self._log_message(f"Cleaned up temporary file: {os.path.basename(path)}", constants.LOG_LEVEL_DEBUG)
                    cleaned_count +=1
            except OSError as e:
                self._log_message(f"Error cleaning up temp file {os.path.basename(path)}: {e}", constants.LOG_LEVEL_WARN)
        if cleaned_count > 0:
             self._log_message(f"Cleaned up {cleaned_count} temporary certificate files.", constants.LOG_LEVEL_INFO)
        self.temp_cert_files = []


    def _create_ssl_context(self, purpose=ssl.Purpose.SERVER_AUTH):
        """Creates and configures an SSL context."""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT if purpose == ssl.Purpose.SERVER_AUTH else ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = False # We verify fingerprint manually

            context.load_verify_locations(cafile=self.ca_cert_path.get())
            context.load_cert_chain(certfile=self.client_cert_path.get(), keyfile=self.client_key_path.get())
            self._log_message(f"SSLContext created for {'client' if purpose == ssl.Purpose.SERVER_AUTH else 'server'}. CA: {self.ca_cert_display_name.get()}, Cert: {self.client_cert_display_name.get()}", constants.LOG_LEVEL_DEBUG)
            return context
        except ssl.SSLError as e:
            self._log_message(f"SSL Context Error: {e}. Check certificate paths and formats.", constants.LOG_LEVEL_ERROR)
            self.gui_queue.put(("show_error", f"SSL Setup Error: {e}\nEnsure certificates are valid and paths are correct."))
            return None
        except FileNotFoundError as e:
            self._log_message(f"SSL Context Error: Certificate file not found: {e}", constants.LOG_LEVEL_ERROR)
            self.gui_queue.put(("show_error", f"SSL Setup Error: Certificate file not found.\n{e}"))
            return None

    def _start_server_if_needed(self):
        """Starts the server listening thread if certs are loaded and it's not already running."""
        if self.certs_loaded_correctly and (not self.server_thread or not self.server_thread.is_alive()):
            self.stop_event.clear()
            self.server_thread = threading.Thread(target=self._server_listen_loop, daemon=True)
            self.server_thread.start()
            self._log_message(f"Server listening on {self.local_ip}:{constants.DEFAULT_PORT}")
        elif not self.certs_loaded_correctly:
            self._log_message("Cannot start server: Certificates not loaded.", constants.LOG_LEVEL_WARN)

    def _server_listen_loop(self):
        """Listens for incoming connections and handles them in new threads."""
        # Create a local SSL context specifically for the server
        server_ssl_context = self._create_ssl_context(purpose=ssl.Purpose.CLIENT_AUTH)
        if not server_ssl_context: # Check if context creation failed
            self._log_message("Server cannot start: Failed to create SSL context.", constants.LOG_LEVEL_ERROR)
            gui.set_connection_status(self, "SSL Error")
            return

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', constants.DEFAULT_PORT)) # Listen on all interfaces
            self.server_socket.listen(1) # Listen for one connection at a time
            self.server_socket.settimeout(1.0) # Timeout to check stop_event

            self._log_message(f"Server socket bound and listening on {self.local_ip}:{constants.DEFAULT_PORT}.", constants.LOG_LEVEL_DEBUG)

            while not self.stop_event.is_set():
                if self.is_connected or self.is_connecting: # Don't accept new if already busy
                    time.sleep(0.5)
                    continue
                try:
                    conn, addr = self.server_socket.accept()
                    self._log_message(f"Incoming connection from {addr[0]}:{addr[1]}")
                    if self.is_connected or self.is_connecting:
                        self._log_message("Already connected/connecting, rejecting new incoming connection.", constants.LOG_LEVEL_WARN)
                        conn.close()
                        continue

                    self.is_connecting = True
                    self.gui_queue.put(("status", "Connecting"))
                    # Pass the raw socket `conn` and the server_ssl_context to _handle_client_connection
                    threading.Thread(target=self._handle_client_connection, args=(conn, addr, server_ssl_context), daemon=True).start()
                except socket.timeout:
                    continue # Loop to check stop_event
                except Exception as e:
                    if not self.stop_event.is_set(): # Don't log if we are stopping
                        self._log_message(f"Server accept error: {e}", constants.LOG_LEVEL_ERROR)
                    break # Exit loop on other errors
        except OSError as e: # e.g. Address already in use
             self._log_message(f"Server socket error: {e}", constants.LOG_LEVEL_ERROR)
             self.gui_queue.put(("show_error", f"Could not start server: {e}\nAnother application might be using port {constants.DEFAULT_PORT}."))
             self.gui_queue.put(("status", "Port Error"))
        finally:
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
            self._log_message("Server listening loop stopped.", constants.LOG_LEVEL_DEBUG)
            if not self.is_connected and not self.is_connecting and self.certs_loaded_correctly:
                 self.gui_queue.put(("status", "Certs Loaded")) # Or Disconnected if it was previously connected

    def _handle_client_connection(self, conn_socket, addr, server_context):
        """Handles an incoming client connection (SSL handshake, peer verification)."""
        peer_ip = addr[0]
        self.client_socket = None # Ensure it's clean before assignment
        self._log_message(f"SERVER_HANDLE: Thread started for {peer_ip}.", constants.LOG_LEVEL_DEBUG)
        try:
            self._log_message(f"SERVER_HANDLE: Attempting SSL wrap for {peer_ip}.", constants.LOG_LEVEL_DEBUG)
            self.client_socket = server_context.wrap_socket(conn_socket, server_side=True)
            self._log_message(f"SERVER_HANDLE: SSL handshake successful with {peer_ip}. Performing peer verification.", constants.LOG_LEVEL_DEBUG)

            # Exchange peer info (hostname, IP, cert fingerprint)
            self._log_message(f"SERVER_HANDLE: Getting peer certificate from {peer_ip}.", constants.LOG_LEVEL_DEBUG)
            peer_cert = self.client_socket.getpeercert(binary_form=True)
            if not peer_cert:
                self._log_message(f"SERVER_HANDLE: Could not get peer certificate from {peer_ip}.", constants.LOG_LEVEL_ERROR)
                raise ssl.SSLError("Could not get peer certificate.")
            self._log_message(f"SERVER_HANDLE: Calculating peer fingerprint for {peer_ip}.", constants.LOG_LEVEL_DEBUG)
            self.peer_full_fingerprint = hashlib.sha256(peer_cert).hexdigest().upper() # Ensure upper for consistency
            peer_fp_display = utils.format_fingerprint_display(self.peer_full_fingerprint)
            self._log_message(f"SERVER_HANDLE: Peer {peer_ip} fingerprint: {peer_fp_display}", constants.LOG_LEVEL_DEBUG)

            # Send our info
            self._log_message(f"SERVER_HANDLE: Preparing to send local info to {peer_ip}.", constants.LOG_LEVEL_DEBUG)
            local_info = self._get_local_peer_info()
            if local_info.get("fingerprint") is None: # This check was for the "N/A_FP" case, which is now handled in _get_local_peer_info
                self._log_message(f"SERVER_HANDLE: CRITICAL - Local fingerprint is None when sending PEER_INFO to {peer_ip}.", constants.LOG_LEVEL_ERROR)

            self._log_message(f"SERVER_HANDLE: Sending PEER_INFO to {peer_ip}: {local_info}", constants.LOG_LEVEL_DEBUG)
            self._send_command(self.client_socket, {"type": "PEER_INFO", "data": local_info})
            self._log_message(f"SERVER_HANDLE: PEER_INFO sent to {peer_ip}.", constants.LOG_LEVEL_DEBUG)

            # Receive peer's info
            self._log_message(f"SERVER_HANDLE: Receiving PEER_INFO from {peer_ip}.", constants.LOG_LEVEL_DEBUG)
            peer_info_cmd = self._receive_command(self.client_socket)
            if not peer_info_cmd or peer_info_cmd.get("type") != "PEER_INFO":
                self._log_message(f"SERVER_HANDLE: Failed to receive PEER_INFO from {peer_ip} or malformed.", constants.LOG_LEVEL_ERROR)
                raise ConnectionError("Failed to receive peer info or malformed command.")
            self._log_message(f"SERVER_HANDLE: Received PEER_INFO from {peer_ip}: {peer_info_cmd['data']}", constants.LOG_LEVEL_DEBUG)
            self.gui_queue.put(("peer_info", (peer_ip, peer_info_cmd["data"])))

            # Fingerprint verification dialog (via GUI queue)
            verification_event = threading.Event()
            user_accepted = None
            def set_verification_result(accepted):
                nonlocal user_accepted
                user_accepted = accepted
                verification_event.set()

            self.gui_queue.put(("status", "Confirming Peer"))
            self.gui_queue.put(("prompt_fingerprint", (peer_fp_display, set_verification_result)))
            verification_event.wait(timeout=constants.CONFIRMATION_TIMEOUT) # Wait for user input

            if user_accepted is None: # Timeout
                self._log_message("Peer fingerprint confirmation timed out.", constants.LOG_LEVEL_WARN)
                self._send_command(self.client_socket, {"type": "VERIFICATION_REJECTED", "reason": "Timeout"})
                raise ConnectionRefusedError("Fingerprint confirmation timed out.")
            elif user_accepted:
                self._log_message("Peer fingerprint accepted by user.", constants.LOG_LEVEL_INFO)
                self._send_command(self.client_socket, {"type": "VERIFICATION_ACCEPTED"})
                self._log_message(f"SERVER_HANDLE: Socket timeout before set to None: {self.client_socket.gettimeout()}", constants.LOG_LEVEL_DEBUG)
                self.client_socket.settimeout(None) # Ensure blocking reads for comms loop
                self.is_connected = True
                self.is_connecting = False
                self.gui_queue.put(("status", "Securely Connected"))
                self._start_heartbeat()
                # gui.update_status_display(self) # Ensure chat menu is enabled
                self._communication_loop() # Start receiving commands
                # For remembered peers, use the IP address the server actually saw the connection from (peer_ip)
                # but keep the hostname and fingerprint from the PEER_INFO message.
                info_to_remember = peer_info_cmd["data"].copy() # Make a copy to modify
                info_to_remember["ip"] = peer_ip # Override with the observed incoming IP
                self._log_message(f"SERVER_HANDLE: Storing remembered peer with observed IP {peer_ip}, "
                                  f"original reported IP was {peer_info_cmd['data'].get('ip')}",
                                  constants.LOG_LEVEL_DEBUG)
                self._add_remembered_peer(info_to_remember)
            else: # User rejected
                self._log_message("Peer fingerprint rejected by user.", constants.LOG_LEVEL_WARN)
                self._send_command(self.client_socket, {"type": "VERIFICATION_REJECTED", "reason": "User rejected"})
                raise ConnectionRefusedError("Fingerprint rejected by user.")

        except (ssl.SSLError, ConnectionError, socket.error, json.JSONDecodeError) as e:
            self._log_message(f"SERVER_HANDLE: Connection handling error with {peer_ip}: {e}", constants.LOG_LEVEL_ERROR)
            if self.client_socket: self.client_socket.close() # Close the wrapped socket
            else: conn_socket.close() # Close the raw socket if wrapping failed
            self.client_socket = None
            self.is_connecting = False
            self.is_connected = False
            self.gui_queue.put(("clear_peer_info", None))
            if self.certs_loaded_correctly: self.gui_queue.put(("status", "Disconnected"))
            else: self.gui_queue.put(("status", "No Certs"))
        except Exception as e: # Catch any other unexpected error
            self._log_message(f"SERVER_HANDLE: Unexpected error handling client {peer_ip}: {e}", constants.LOG_LEVEL_ERROR)
            if self.client_socket: self.client_socket.close()
            else: conn_socket.close()
            self.client_socket = None
            self.is_connecting = False
            self.is_connected = False
            self.gui_queue.put(("clear_peer_info", None))
            if self.certs_loaded_correctly: self.gui_queue.put(("status", "Disconnected"))
            else: self.gui_queue.put(("status", "No Certs"))
        finally:
            self._log_message(f"SERVER_HANDLE: Thread finished for {peer_ip}.", constants.LOG_LEVEL_DEBUG)


    def _connect_peer(self):
        """Initiates an outgoing connection to a peer."""
        if not self.certs_loaded_correctly:
            self.gui_queue.put(("show_error", "Cannot connect: Certificates not loaded."))
            return
        if self.is_connected or self.is_connecting:
            self.gui_queue.put(("show_error", "Already connected or attempting to connect."))
            return

        peer_input_string = self.peer_ip_hostname.get().strip()
        if not peer_input_string:
            self.gui_queue.put(("show_error", "Peer IP/Hostname cannot be empty."))
            return

        # Parse peer_input_string to get the actual target for connection
        target_address_to_connect = ""
        # Regex to find an IP address v4 pattern: xxx.xxx.xxx.xxx within the string
        ip_pattern = r'\b((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b' # Capture the IP
        ip_match = re.search(ip_pattern, peer_input_string)

        if ip_match:
            target_address_to_connect = ip_match.group(1) # Get the captured IP address
            self._log_message(f"Extracted IP '{target_address_to_connect}' from input '{peer_input_string}' for connection.", constants.LOG_LEVEL_DEBUG)
        else:
            # No IP found via regex. If it contains ' (', assume the part before it is a hostname.
            # Otherwise, use the whole string (could be a hostname or a mistyped entry).
            if ' (' in peer_input_string:
                target_address_to_connect = peer_input_string.split(' (')[0].strip()
                self._log_message(f"Extracted Hostname '{target_address_to_connect}' from input '{peer_input_string}' for connection.", constants.LOG_LEVEL_DEBUG)
            else:
                target_address_to_connect = peer_input_string
                self._log_message(f"Using full input '{target_address_to_connect}' as target (hostname or IP).", constants.LOG_LEVEL_DEBUG)

        if not target_address_to_connect: # Should not happen if peer_input_string was not empty
            self.gui_queue.put(("show_error", "Could not parse Peer IP/Hostname."))
            return

        self.is_connecting = True
        self.gui_queue.put(("status", "Connecting"))
        self.gui_queue.put(("clear_peer_info", None)) # Clear previous peer info

        # Run connection in a separate thread to keep GUI responsive
        self.client_connection_thread = threading.Thread(target=self._initiate_connection, args=(target_address_to_connect,), daemon=True)
        self.client_connection_thread.start()

    def _initiate_connection(self, peer_host):
        """Core logic for establishing an outgoing TLS connection."""
        client_ssl_context = self._create_ssl_context(purpose=ssl.Purpose.SERVER_AUTH)
        if not client_ssl_context:
            self._log_message("Client connection failed: Could not create SSL context.", constants.LOG_LEVEL_ERROR)
            self.is_connecting = False
            self.gui_queue.put(("status", "SSL Error"))
            return

        raw_socket = None
        try:
            raw_socket = socket.create_connection((peer_host, constants.DEFAULT_PORT), timeout=constants.CONNECTION_TIMEOUT)
            self.client_socket = client_ssl_context.wrap_socket(raw_socket, server_hostname=peer_host) # server_hostname for SNI
            self._log_message(f"Successfully connected and SSL handshake complete with {peer_host}.", constants.LOG_LEVEL_DEBUG)

            # Exchange peer info
            peer_cert = self.client_socket.getpeercert(binary_form=True)
            if not peer_cert:
                raise ssl.SSLError("Could not get peer certificate.")
            self.peer_full_fingerprint = hashlib.sha256(peer_cert).hexdigest().upper() # Ensure upper
            peer_fp_display = utils.format_fingerprint_display(self.peer_full_fingerprint)

            # Receive peer's info first (server sends first)
            peer_info_cmd = self._receive_command(self.client_socket)
            if not peer_info_cmd or peer_info_cmd.get("type") != "PEER_INFO":
                raise ConnectionError("Failed to receive peer info or malformed command.")
            self.gui_queue.put(("peer_info", (peer_host, peer_info_cmd["data"]))) # Pass peer_host for display consistency

            # Send our info
            local_info = self._get_local_peer_info()
            self._send_command(self.client_socket, {"type": "PEER_INFO", "data": local_info})

            # Fingerprint verification dialog
            verification_event = threading.Event()
            user_accepted = None
            def set_verification_result(accepted):
                nonlocal user_accepted
                user_accepted = accepted
                verification_event.set()

            self.gui_queue.put(("status", "Confirming Peer"))
            self.gui_queue.put(("prompt_fingerprint", (peer_fp_display, set_verification_result)))
            verification_event.wait(timeout=constants.CONFIRMATION_TIMEOUT)

            if user_accepted is None: # Timeout
                self._log_message("Peer fingerprint confirmation timed out.", constants.LOG_LEVEL_WARN)
                self._send_command(self.client_socket, {"type": "VERIFICATION_REJECTED", "reason": "Timeout"})
                raise ConnectionRefusedError("Fingerprint confirmation timed out.")
            elif user_accepted:
                self._log_message("Peer fingerprint accepted by user.", constants.LOG_LEVEL_INFO)
                self._send_command(self.client_socket, {"type": "VERIFICATION_ACCEPTED"})
                # Wait for server's final confirmation (it might have also timed out or rejected)
                server_response = self._receive_command(self.client_socket) # Client waits for server's acceptance
                if server_response and server_response.get("type") == "VERIFICATION_ACCEPTED":
                    self.is_connected = True
                    self._log_message(f"CLIENT_INITIATE: Socket timeout before set to None: {self.client_socket.gettimeout()}", constants.LOG_LEVEL_DEBUG)
                    self.client_socket.settimeout(None) # Ensure blocking reads for comms loop
                    self.is_connecting = False
                    self.gui_queue.put(("status", "Securely Connected"))
                    self._start_heartbeat()
                    # gui.update_status_display(self) # Ensure chat menu is enabled
                    self._communication_loop()
                    # For remembered peers, use the IP address the client actually connected to (peer_host)
                    # but keep the hostname and fingerprint from the PEER_INFO message received from the server.
                    info_to_remember = self.peer_info.copy() # Contains hostname, reported IP, fingerprint from server
                    info_to_remember["ip"] = peer_host # Override with the IP/host we successfully connected to
                    self._log_message(f"CLIENT_INITIATE: Storing remembered peer with connection target IP/host {peer_host}, "
                                      f"original reported IP was {self.peer_info.get('ip')}",
                                      constants.LOG_LEVEL_DEBUG)
                    self._add_remembered_peer(info_to_remember)
                else:
                    reason = server_response.get("reason", "Server rejected connection") if server_response else "No response from server"
                    self._log_message(f"Connection rejected by peer: {reason}", constants.LOG_LEVEL_WARN)
                    self.gui_queue.put(("show_warning", f"Connection rejected by peer: {reason}"))
                    raise ConnectionRefusedError(f"Peer rejected: {reason}")
            else: # User rejected
                self._log_message("Peer fingerprint rejected by user.", constants.LOG_LEVEL_WARN)
                self._send_command(self.client_socket, {"type": "VERIFICATION_REJECTED", "reason": "User rejected"})
                raise ConnectionRefusedError("Fingerprint rejected by user.")

        except (socket.timeout, socket.error) as e:
            self._log_message(f"Connection to {peer_host} failed: {e}", constants.LOG_LEVEL_ERROR)
            self.gui_queue.put(("show_error", f"Could not connect to {peer_host}:\n{e}"))
        except (ssl.SSLError, ConnectionError, ConnectionRefusedError, json.JSONDecodeError) as e:
            self._log_message(f"Connection to {peer_host} failed during setup: {e}", constants.LOG_LEVEL_ERROR)
            # Error message already shown for ConnectionRefusedError if it's specific
            if not isinstance(e, ConnectionRefusedError) or "Fingerprint" not in str(e):
                 self.gui_queue.put(("show_error", f"Connection to {peer_host} failed:\n{e}"))
        except Exception as e: # Catch any other unexpected error
            self._log_message(f"Unexpected error connecting to {peer_host}: {e}", constants.LOG_LEVEL_ERROR)
            self.gui_queue.put(("show_error", f"An unexpected error occurred:\n{e}"))
        finally:
            if not self.is_connected:
                if self.client_socket: self.client_socket.close()
                elif raw_socket: raw_socket.close() # Close raw socket if SSL wrapping failed or didn't happen
                self.client_socket = None
                self.is_connecting = False
                self.gui_queue.put(("clear_peer_info", None))
                if self.certs_loaded_correctly: self.gui_queue.put(("status", "Disconnected"))
                else: self.gui_queue.put(("status", "No Certs"))

    def _get_local_peer_info(self):
        """Gathers local hostname, IP, and certificate fingerprint."""
        fingerprint_to_send = self.local_full_fingerprint
        if fingerprint_to_send is None:
            self._log_message("CRITICAL_INFO: _get_local_peer_info: self.local_full_fingerprint is None. Sending 'N/A_FP'.", constants.LOG_LEVEL_ERROR)
            fingerprint_to_send = "N/A_FP" # Send a placeholder

        return {
            "hostname": self.local_hostname,
            "ip": self.local_ip,
            "fingerprint": fingerprint_to_send
        }

    def _add_remembered_peer(self, peer_info_dict):
        """Adds a peer's info to the remembered list, keeping it unique and limited."""
        if not peer_info_dict or not peer_info_dict.get("fingerprint"):
            self._log_message("Attempted to add invalid peer info to remembered list.", constants.LOG_LEVEL_WARN)
            return
        # Remove existing entry with the same fingerprint
        self.remembered_peers = [
            p for p in self.remembered_peers
            if p.get("fingerprint") != peer_info_dict.get("fingerprint")
        ]

        # Add the new peer to the end
        self.remembered_peers.append(peer_info_dict)

        # Keep only the last MAX_REMEMBERED_PEERS
        self.remembered_peers = self.remembered_peers[-constants.MAX_REMEMBERED_PEERS:]

        self._save_app_settings() # Save the updated list
        self.gui_queue.put(("update_peer_list_dropdown", None)) # Trigger GUI update

    def _verify_peer_fingerprint_dialog(self, peer_fp_display, callback):
        """Shows a dialog to verify the peer's certificate fingerprint."""
        # This runs in the main GUI thread due to _process_gui_queue
        title = "Verify Peer Identity"
        message = (
            f"You are connecting to a peer with the following certificate fingerprint:\n\n"
            f"{peer_fp_display}\n\n"
            f"Your fingerprint is:\n"
            f"{self.local_fingerprint_display.get()}\n\n"
            f"Please VERIFY this fingerprint with the peer out-of-band (e.g., voice, text).\n"
            f"Do you trust this fingerprint and want to connect?"
        )
        try:
            # Ensure the dialog is transient to the main window if possible
            # For simpledialog, parent is implicitly handled if self.root is active
            # For messagebox, parent=self.root is good practice.
            user_choice = messagebox.askyesnocancel(title, message, icon=messagebox.QUESTION, parent=self.root)

            if user_choice is True: # Yes
                callback(True)
            elif user_choice is False: # No
                callback(False)
            else: # Cancel or dialog closed
                self._log_message("Peer fingerprint verification cancelled by user.", constants.LOG_LEVEL_INFO)
                callback(None) # Indicate cancellation / timeout scenario
        except tk.TclError as e: # Window might be closing
            self._log_message(f"Error showing fingerprint dialog (window closed?): {e}", constants.LOG_LEVEL_WARN)
            callback(None)


    def _send_command(self, sock, command_dict):
        """Sends a JSON command over the SSL socket."""
        if not sock:
            self._log_message("Send command failed: socket is None.", constants.LOG_LEVEL_ERROR)
            return

        # Prepare a display version for logging, especially for FILE_CHUNK
        log_cmd_dict = command_dict.copy()
        if log_cmd_dict.get("type") == "FILE_CHUNK" and "data" in log_cmd_dict and isinstance(log_cmd_dict["data"], dict):
            original_chunk_b64 = log_cmd_dict["data"].get("chunk", "") # Assuming 'chunk' holds the b64 data
            try:
                # Log the length of the original binary data, not the base64 string
                decoded_chunk_len = len(base64.b64decode(original_chunk_b64.encode('ascii') if isinstance(original_chunk_b64, str) else original_chunk_b64))
                log_cmd_dict["data"] = f"<FILE_CHUNK: original data len {decoded_chunk_len}>"
            except Exception: # Fallback if b64decode fails or data isn't as expected
                log_cmd_dict["data"] = "<FILE_CHUNK: error preparing log display>"

        command_json = json.dumps(command_dict)
        if len(command_json) > constants.MAX_CMD_LEN:
            self._log_message(f"Command too long to send: {len(command_json)} bytes. Type: {command_dict.get('type', 'Unknown')}", constants.LOG_LEVEL_ERROR)
            if command_dict.get("type") != "FILE_CHUNK":
                self._disconnect_peer(reason="Command too long")
                return False # Explicitly return False
            # If it's a FILE_CHUNK, this indicates a serious issue with chunking logic.
            self._disconnect_peer(reason="Oversized file chunk (internal error)")
            return False # Explicitly return False

        command_bytes = command_json.encode('utf-8')
        length_prefix = len(command_bytes).to_bytes(4, 'big')

        with self._socket_write_lock: # Acquire lock before writing
            if not sock or self.stop_event.is_set() or (hasattr(sock, '_closed') and sock._closed): # Check if socket is still valid
                self._log_message(f"Send command ({command_dict.get('type')}): Socket closed or stop event set (after lock).", constants.LOG_LEVEL_DEBUG)
                return False
            try:
                sock.sendall(length_prefix + command_bytes)
                self._log_message(f"Sent command: {log_cmd_dict}", constants.LOG_LEVEL_DEBUG) # Use the prepared log_cmd_dict
                return True # Indicate success
            except (socket.error, ssl.SSLError, AttributeError, ValueError) as e:
                self._log_message(f"Error sending command: {e}. Command type: {command_dict.get('type', 'Unknown')}", constants.LOG_LEVEL_ERROR)
                self._disconnect_peer(reason=f"Send error: {e}") # Disconnect on send error
                return False
        # Fallback if logic somehow exits the 'with' block without returning (should not happen)
        self._log_message(f"Command send ({command_dict.get('type')}) exited _socket_write_lock without explicit return.", constants.LOG_LEVEL_WARN)
        return False

    def _receive_command(self, sock):
        """Receives a JSON command from the SSL socket."""
        if not sock:
            self._log_message("Receive command failed: socket is None.", constants.LOG_LEVEL_ERROR)
            return None
        try:
            # Receive length prefix
            length_prefix_bytes = sock.recv(4)
            if not length_prefix_bytes: # Connection closed by peer
                self._log_message("Connection closed by peer while waiting for command length.", constants.LOG_LEVEL_INFO)
                return None
            msg_len = int.from_bytes(length_prefix_bytes, 'big')

            if msg_len > constants.MAX_CMD_LEN: # Corrected constant name
                self._log_message(f"Received command too long: {msg_len} bytes. Disconnecting.", constants.LOG_LEVEL_ERROR)
                self._disconnect_peer(reason="Received oversized command")
                return None

            # Receive the actual command
            chunks = []
            bytes_recd = 0
            while bytes_recd < msg_len:
                chunk = sock.recv(min(msg_len - bytes_recd, constants.BUFFER_SIZE)) # Corrected constant name
                if not chunk: # Connection closed unexpectedly
                    self._log_message("Connection closed by peer unexpectedly during command receive.", constants.LOG_LEVEL_ERROR)
                    return None
                chunks.append(chunk)
                bytes_recd += len(chunk)

            command_json = b"".join(chunks).decode('utf-8')
            command_dict = json.loads(command_json)
            # Log sensitive data carefully
            log_cmd_dict = command_dict.copy()
            if log_cmd_dict.get("type") == "FILE_CHUNK" and "data" in log_cmd_dict and isinstance(log_cmd_dict["data"], dict):
                # log_cmd_dict['data'] is {'chunk': 'base64string'}
                received_chunk_b64 = log_cmd_dict["data"].get("chunk", "")
                log_cmd_dict["data"] = f"<FILE_CHUNK: original data len {len(base64.b64decode(received_chunk_b64.encode('ascii') if isinstance(received_chunk_b64, str) else received_chunk_b64))}>"
            self._log_message(f"Received command: {log_cmd_dict}", constants.LOG_LEVEL_DEBUG)
            return command_dict
        except (socket.error, ssl.SSLError, json.JSONDecodeError, ValueError, TypeError, AttributeError) as e: # Added more error types
            self._log_message(f"Error receiving or parsing command: {e}", constants.LOG_LEVEL_ERROR)
            # Don't auto-disconnect here, let the communication_loop handle it based on context
            return None # Indicate error to caller

    def _communication_loop(self):
        """Main loop for receiving and processing commands from the peer."""
        self._log_message("Starting communication loop.", constants.LOG_LEVEL_DEBUG)
        try:
            while self.is_connected and not self.stop_event.is_set():
                if not self.client_socket: break # Socket closed by another thread
                # Set a timeout on recv so the loop can break if self.is_connected becomes false
                # This is implicitly handled by _receive_command if it uses socket.settimeout or select
                # For now, _receive_command blocks until data or error.
                # A better approach might involve select() or making client_socket non-blocking
                # and handling EWOULDBLOCK/EAGAIN.
                # However, for simplicity, we rely on heartbeat to detect dead connections.
                # If _receive_command returns None due to graceful close or error, loop will break.

                command = self._receive_command(self.client_socket)
                if command is None: # Error or connection closed
                    self._log_message("Communication loop: receive_command returned None. Assuming disconnection.", constants.LOG_LEVEL_INFO)
                    self._disconnect_peer(reason="Peer disconnected or receive error")
                    break # Exit loop

                cmd_type = command.get("type")
                cmd_data = command.get("data")

                if cmd_type == "HEARTBEAT":
                    self._send_command(self.client_socket, {"type": "HEARTBEAT_ACK"})
                elif cmd_type == "HEARTBEAT_ACK":
                    with self.heartbeat_lock:
                        self.last_heartbeat_ack_time = time.monotonic()
                elif cmd_type == "SEND_FILE":
                    self._handle_send_file_command(cmd_data)
                elif cmd_type == "ACCEPT_FILE":
                    self._handle_accept_file_command(cmd_data)
                elif cmd_type == "REJECT_FILE":
                    self._handle_reject_file_command(cmd_data)
                elif cmd_type == "FILE_CHUNK":
                    self._handle_file_chunk_command(cmd_data)
                elif cmd_type == "TRANSFER_COMPLETE":
                    self._handle_transfer_complete_command(cmd_data)
                elif cmd_type == "VERIFICATION_ACCEPTED":
                    # This is the client confirming its side after server already started comms loop.
                    self._log_message("Received final VERIFICATION_ACCEPTED from peer. Connection fully established.", constants.LOG_LEVEL_DEBUG)
                    # No specific action needed here by the receiver of this message in the main loop.
                elif cmd_type == "CANCEL_TRANSFER":
                    self._handle_cancel_transfer_command(cmd_data)
                elif cmd_type == "CHAT_MESSAGE": # Handle incoming chat messages
                    self._handle_chat_message_command(cmd_data) # Corrected handler
                # VERIFICATION_ACCEPTED/REJECTED are handled during connection setup
                else:
                    self._log_message(f"Received unknown command type: {cmd_type}", constants.LOG_LEVEL_WARN)

        except Exception as e:
            if self.is_connected: # Only log if we didn't expect to disconnect
                self._log_message(f"Exception in communication loop: {e}", constants.LOG_LEVEL_ERROR)
            # self._disconnect_peer(reason=f"Comm loop error: {e}") # This might cause double disconnect
        finally:
            self._log_message("Communication loop ended.", constants.LOG_LEVEL_DEBUG)
            # If still "connected" but loop ended, means an issue.
            if self.is_connected:
                 self._disconnect_peer(reason="Communication loop terminated unexpectedly")


    def _start_heartbeat(self):
        """Starts the heartbeat thread."""
        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            return # Already running
        with self.heartbeat_lock:
            self.last_heartbeat_ack_time = time.monotonic() # Initialize
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()
        self._log_message("Heartbeat thread started.", constants.LOG_LEVEL_DEBUG)

    def _heartbeat_loop(self):
        """Periodically sends heartbeats and checks for acknowledgments."""
        while self.is_connected and not self.stop_event.is_set():
            try:
                time.sleep(constants.HEARTBEAT_INTERVAL)
                if not self.is_connected: break # Check again after sleep

                with self.heartbeat_lock:
                    if time.monotonic() - self.last_heartbeat_ack_time > constants.HEARTBEAT_TIMEOUT:
                        self._log_message("Heartbeat timeout. Peer unresponsive.", constants.LOG_LEVEL_WARN)
                        self._disconnect_peer(reason="Heartbeat timeout")
                        break
                if self.client_socket: # Ensure socket exists before sending
                    self._send_command(self.client_socket, {"type": "HEARTBEAT"})
                else: # Socket got closed somehow
                    self._log_message("Heartbeat: client_socket is None. Disconnecting.", constants.LOG_LEVEL_WARN)
                    self._disconnect_peer(reason="Socket closed unexpectedly")
                    break
            except Exception as e:
                if self.is_connected: # Only log if we didn't expect to disconnect
                    self._log_message(f"Error in heartbeat loop: {e}", constants.LOG_LEVEL_ERROR)
                break # Exit loop on error
        self._log_message("Heartbeat thread stopped.", constants.LOG_LEVEL_DEBUG)

    def _disconnect_peer(self, reason="Unknown"):
        """Closes the connection to the peer and resets state."""
        if not self.is_connected and not self.is_connecting:
            # self._log_message(f"Disconnect called but not connected/connecting. Reason: {reason}", constants.LOG_LEVEL_DEBUG)
            return # Already disconnected or not connected

        self._log_message(f"Disconnecting from peer. Reason: {reason}", constants.LOG_LEVEL_INFO)

        was_connected = self.is_connected
        self.is_connected = False
        self.is_connecting = False # Also reset if was in connecting state

        gui.update_status_display(self) # Update menu states, including Chat
        if self.is_transferring:
            self._cancel_transfer(notify_peer=False) # Cancel local transfer, don't notify if connection is already dead

        if self.client_socket:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except (socket.error, OSError): pass # Ignore errors on shutdown, socket might be already closed
            try:
                self.client_socket.close()
            except (socket.error, OSError): pass
            self.client_socket = None
            self._log_message("Client socket closed.", constants.LOG_LEVEL_DEBUG)

        # Stop heartbeat thread by virtue of self.is_connected being False
        # The thread should check this flag and exit.

        self.gui_queue.put(("clear_peer_info", None))
        if self.certs_loaded_correctly:
            self.gui_queue.put(("status", "Disconnected"))
        else:
            self.gui_queue.put(("status", "No Certs")) # Should not happen if was connected

        # If server was handling this connection, it's now free to accept new ones.
        # If client initiated this, it's now fully disconnected.
        # Restart server listening if it was stopped due to active connection
        self.gui_queue.put(("update_peer_list_dropdown", None)) # Refresh dropdown after disconnect
        if was_connected and self.certs_loaded_correctly and (not self.server_thread or not self.server_thread.is_alive()):
             self._log_message("Attempting to restart server listening after disconnect.", constants.LOG_LEVEL_DEBUG)
             self._start_server_if_needed()


    def _send_file(self):
        """Initiates the file sending process."""
        if not self.is_connected:
            self.gui_queue.put(("show_error", "Not connected to a peer."))
            return
        if self.is_transferring:
            self.gui_queue.put(("show_error", "A file transfer is already in progress."))
            return

        filepath = self.file_to_send_path.get()
        if not filepath or not os.path.exists(filepath):
            self.gui_queue.put(("show_error", "File not found or not selected."))
            return

        try:
            filesize = os.path.getsize(filepath)
            filename = os.path.basename(filepath)

            self.is_transferring = True
            self.transfer_cancelled_by_user = False
            self.current_transfer_info = {
                "filepath": filepath, "filename": filename,
                "filesize": filesize, "role": "sender",
                "bytes_sent": 0, "start_time": time.monotonic()
            }
            self.gui_queue.put(("sender_status", ("Waiting for peer to accept...", "blue", False)))
            gui.update_status_display(self) # Disable other buttons

            self._send_command(self.client_socket, {
                "type": "SEND_FILE",
                "data": {"filename": filename, "filesize": filesize}
            })
            self._log_message(f"Sent SEND_FILE command for {filename} ({utils.format_bytes(filesize)}).")

        except OSError as e:
            self._log_message(f"Error accessing file {filepath}: {e}", constants.LOG_LEVEL_ERROR)
            self.gui_queue.put(("show_error", f"Error accessing file: {e}"))
            self._reset_transfer_state()
            self.gui_queue.put(("transfer_cancelled_ui", True)) # True for sender role
        except Exception as e:
            self._log_message(f"Unexpected error initiating file send: {e}", constants.LOG_LEVEL_ERROR)
            self.gui_queue.put(("show_error", f"Unexpected error: {e}"))
            self._reset_transfer_state()
            self.gui_queue.put(("transfer_cancelled_ui", True))

    def _handle_send_file_command(self, data):
        """Handles an incoming SEND_FILE command from the peer."""
        if self.is_transferring:
            self._log_message("Received SEND_FILE while another transfer is in progress. Rejecting.", constants.LOG_LEVEL_WARN)
            self._send_command(self.client_socket, {"type": "REJECT_FILE", "data": {"reason": "Busy with another transfer."}})
            return

        filename = data.get("filename")
        filesize = data.get("filesize")
        if not filename or filesize is None:
            self._log_message("Received malformed SEND_FILE command.", constants.LOG_LEVEL_ERROR)
            self._send_command(self.client_socket, {"type": "REJECT_FILE", "data": {"reason": "Malformed command."}})
            return

        self.is_transferring = True # Tentatively set, might be rejected by user
        self.transfer_cancelled_by_user = False
        self.current_transfer_info = {
            "filename": filename, "filesize": filesize, "role": "receiver",
            "bytes_received": 0, "start_time": time.monotonic(), "file_handle": None, "temp_filepath": None
        }
        gui.update_status_display(self) # Disable other buttons

        # Prompt user to accept/reject via GUI queue
        filesize_str = utils.format_bytes(filesize)
        self.gui_queue.put(("sender_status", (f"Receiving {filename} ({filesize_str})...", "blue", False)))

        accept_event = threading.Event()
        user_choice = None # True for accept, False for reject, None for timeout/error

        def set_accept_result(accepted):
            nonlocal user_choice
            user_choice = accepted
            accept_event.set()

        self.gui_queue.put(("prompt_file_accept", (filename, filesize_str, set_accept_result)))
        accept_event.wait(timeout=constants.FILE_ACCEPT_TIMEOUT) # Wait for user input

        if user_choice is True:
            self._log_message(f"User accepted file: {filename}", constants.LOG_LEVEL_INFO)
            # Prepare to receive file
            downloads_folder = utils.get_downloads_folder()
            # Sanitize filename slightly (very basic, consider more robust library if needed)
            safe_filename = "".join(c for c in filename if c.isalnum() or c in ('.', '_', '-')).strip()
            if not safe_filename: safe_filename = "downloaded_file"

            # Ensure unique filename in downloads folder
            base, ext = os.path.splitext(safe_filename)
            counter = 1
            final_filename = safe_filename
            while os.path.exists(os.path.join(downloads_folder, final_filename)):
                final_filename = f"{base}_{counter}{ext}"
                counter += 1
            self.current_transfer_info["final_filepath"] = os.path.join(downloads_folder, final_filename)

            # Use a temporary name during download
            temp_fd, temp_dl_path = tempfile.mkstemp(suffix=".part", prefix=f"{base}_", dir=downloads_folder)
            self.current_transfer_info["temp_filepath"] = temp_dl_path
            self.current_transfer_info["file_handle"] = os.fdopen(temp_fd, "wb")

            self._send_command(self.client_socket, {"type": "ACCEPT_FILE", "data": {"filename": filename}})
            self.gui_queue.put(("sender_status", (f"Downloading {filename}...", "blue", False)))
        elif user_choice is False:
            self._log_message(f"User rejected file: {filename}", constants.LOG_LEVEL_INFO)
            self._send_command(self.client_socket, {"type": "REJECT_FILE", "data": {"reason": "User rejected file."}})
            self._reset_transfer_state()
            self.gui_queue.put(("transfer_cancelled_ui", False)) # False for receiver role
            self.gui_queue.put(("sender_status", ("File rejected by you.", "red", True)))
        else: # Timeout or error
            self._log_message(f"File acceptance for {filename} timed out or was cancelled.", constants.LOG_LEVEL_WARN)
            self._send_command(self.client_socket, {"type": "REJECT_FILE", "data": {"reason": "Acceptance timed out."}})
            self._reset_transfer_state()
            self.gui_queue.put(("transfer_cancelled_ui", False))
            self.gui_queue.put(("sender_status", ("File acceptance timed out.", "red", True)))


    def _prompt_accept_file_dialog(self, filename, filesize_str, callback):
        """Shows a dialog to accept or reject an incoming file."""
        # Runs in main GUI thread
        title = "Incoming File Transfer"
        peer_display = self.peer_hostname.get() if self.peer_hostname.get() != "N/A" else "Peer"
        message = (
            f"{peer_display} wants to send you a file:\n\n"
            f"Filename: {filename}\n"
            f"Size: {filesize_str}\n\n"
            f"Do you want to accept this file?"
        )
        try:
            user_choice = messagebox.askyesno(title, message, icon=messagebox.QUESTION, parent=self.root)
            callback(user_choice) # True for Yes, False for No
        except tk.TclError as e:
            self._log_message(f"Error showing file accept dialog (window closed?): {e}", constants.LOG_LEVEL_WARN)
            callback(None) # Indicate error/cancellation

    def _handle_accept_file_command(self, data):
        """Handles peer's acceptance of a file transfer."""
        if not self.is_transferring or self.current_transfer_info.get("role") != "sender":
            self._log_message("Received ACCEPT_FILE but not in sending state.", constants.LOG_LEVEL_WARN)
            return

        filename_accepted = data.get("filename")
        if filename_accepted != self.current_transfer_info["filename"]:
            self._log_message(f"Received ACCEPT_FILE for wrong file: {filename_accepted} (expected {self.current_transfer_info['filename']})", constants.LOG_LEVEL_WARN)
            self._cancel_transfer(notify_peer=True, reason="File mismatch")
            return

        self._log_message(f"Peer accepted file: {filename_accepted}. Starting transfer.", constants.LOG_LEVEL_INFO)
        self.gui_queue.put(("sender_status", (f"Sending {filename_accepted}...", "blue", False)))

        # Start sending chunks in a new thread to keep comms loop responsive
        threading.Thread(target=self._send_file_chunks, daemon=True).start()

    def _send_file_chunks(self):
        """Reads file and sends it in chunks."""
        info = self.current_transfer_info
        filepath = info["filepath"]
        filesize = info["filesize"]
        bytes_sent = 0
        try:
            with open(filepath, "rb") as f:
                while bytes_sent < filesize:
                    if self.transfer_cancelled_by_user or not self.is_connected:
                        self._log_message("File sending cancelled or disconnected during chunk sending.", constants.LOG_LEVEL_INFO)
                        # _cancel_transfer would have been called already if user cancelled
                        if not self.transfer_cancelled_by_user: # If disconnected, notify peer might fail
                             self._cancel_transfer(notify_peer=self.is_connected, reason="Disconnected during send")
                        return

                    chunk = f.read(constants.FILE_CHUNK_SIZE)
                    if not chunk: break # End of file

                    self._send_command(self.client_socket, {
                        "type": "FILE_CHUNK",
                        "data": {"chunk": base64.b64encode(chunk).decode('ascii')}
                    })
                    bytes_sent += len(chunk)
                    info["bytes_sent"] = bytes_sent

                    # Update progress
                    progress = (bytes_sent / filesize) * 100 if filesize > 0 else 100
                    elapsed_time = time.monotonic() - info["start_time"]
                    speed_bps = (bytes_sent / elapsed_time) if elapsed_time > 0 else 0
                    speed_str = f"Speed: {utils.format_bytes(speed_bps)}/s"
                    eta_str = f"ETA: {utils.format_eta((filesize - bytes_sent) / speed_bps if speed_bps > 0 else 0)}"
                    self.gui_queue.put(("progress", (progress, speed_str, eta_str)))
                    # Small sleep to allow other threads (like GUI queue processing) to run
                    # and to prevent overwhelming the network socket buffer on fast systems.
                    time.sleep(0.001)


            if bytes_sent == filesize:
                self._log_message(f"All chunks sent for {info['filename']}.", constants.LOG_LEVEL_INFO)
                self._send_command(self.client_socket, {"type": "TRANSFER_COMPLETE", "data": {"filename": info["filename"]}})
                self.gui_queue.put(("sender_status", ("Transfer complete!", "green", True)))
                # Sender's job is done, reset state and UI
                self._reset_transfer_state()
                self.gui_queue.put(("transfer_complete_ui", True)) # True for sender role
            else: # Should not happen if EOF is handled correctly (e.g. file shrunk during read)
                self._log_message(f"File sending ended prematurely for {info['filename']}. Sent {bytes_sent}/{filesize}", constants.LOG_LEVEL_WARN)
                self._cancel_transfer(notify_peer=True, reason="Incomplete send")

        except OSError as e:
            self._log_message(f"Error reading file {filepath} during send: {e}", constants.LOG_LEVEL_ERROR)
            self.gui_queue.put(("sender_status", (f"Error reading file: {e}", "red", True)))
            self._cancel_transfer(notify_peer=True, reason=f"File read error: {e}")
        except Exception as e:
            self._log_message(f"Unexpected error sending file chunks: {e}", constants.LOG_LEVEL_ERROR)
            self.gui_queue.put(("sender_status", (f"Transfer error: {e}", "red", True)))
            self._cancel_transfer(notify_peer=True, reason=f"Unexpected send error: {e}")


    def _handle_reject_file_command(self, data):
        """Handles peer's rejection of a file transfer."""
        if not self.is_transferring or self.current_transfer_info.get("role") != "sender":
            self._log_message("Received REJECT_FILE but not in sending state.", constants.LOG_LEVEL_WARN)
            return
        reason = data.get("reason", "No reason given.")
        self._log_message(f"Peer rejected file transfer. Reason: {reason}", constants.LOG_LEVEL_INFO)
        self.gui_queue.put(("sender_status", (f"Peer rejected file: {reason}", "red", True)))
        self._reset_transfer_state()
        self.gui_queue.put(("transfer_cancelled_ui", True)) # True for sender role

    def _handle_file_chunk_command(self, data):
        """Handles an incoming file chunk."""
        if not self.is_transferring or self.current_transfer_info.get("role") != "receiver":
            self._log_message("Received FILE_CHUNK but not in receiving state.", constants.LOG_LEVEL_WARN)
            return
        if self.transfer_cancelled_by_user: # User cancelled while chunks were in flight
            self._log_message("Ignoring FILE_CHUNK, transfer was cancelled by receiver.", constants.LOG_LEVEL_INFO)
            return

        info = self.current_transfer_info
        try:
            chunk_b64 = data.get("chunk")
            if chunk_b64 is None:
                raise ValueError("FILE_CHUNK missing 'chunk' data.")
            chunk = base64.b64decode(chunk_b64)

            if info["file_handle"] and not info["file_handle"].closed:
                info["file_handle"].write(chunk)
                info["bytes_received"] += len(chunk)

                # Update progress
                progress = (info["bytes_received"] / info["filesize"]) * 100 if info["filesize"] > 0 else 100
                elapsed_time = time.monotonic() - info["start_time"]
                speed_bps = (info["bytes_received"] / elapsed_time) if elapsed_time > 0 else 0
                speed_str = f"Speed: {utils.format_bytes(speed_bps)}/s"
                eta_str = f"ETA: {utils.format_eta((info['filesize'] - info['bytes_received']) / speed_bps if speed_bps > 0 else 0)}"
                self.gui_queue.put(("progress", (progress, speed_str, eta_str)))
            else:
                self._log_message("File handle closed or None while receiving chunk.", constants.LOG_LEVEL_WARN)
                # This might happen if transfer was cancelled and file handle closed, but chunks still arrive.
                # No need to send CANCEL_TRANSFER again if already handled.

        except (base64.binascii.Error, OSError, ValueError) as e:
            self._log_message(f"Error processing file chunk for {info['filename']}: {e}", constants.LOG_LEVEL_ERROR)
            self.gui_queue.put(("sender_status", (f"Error receiving chunk: {e}", "red", True)))
            self._cancel_transfer(notify_peer=True, reason=f"Chunk processing error: {e}")
        except Exception as e:
            self._log_message(f"Unexpected error handling file chunk: {e}", constants.LOG_LEVEL_ERROR)
            self.gui_queue.put(("sender_status", (f"Transfer error: {e}", "red", True)))
            self._cancel_transfer(notify_peer=True, reason=f"Unexpected chunk error: {e}")


    def _handle_transfer_complete_command(self, data):
        """Handles peer's signal that file transfer is complete."""
        filename_completed = data.get("filename")
        info = self.current_transfer_info

        if not self.is_transferring:
            self._log_message(f"Received TRANSFER_COMPLETE for {filename_completed} but not transferring.", constants.LOG_LEVEL_WARN)
            return

        if info["filename"] != filename_completed:
            self._log_message(f"Received TRANSFER_COMPLETE for wrong file: {filename_completed} (expected {info['filename']})", constants.LOG_LEVEL_WARN)
            # Don't cancel our current transfer if it's a different file, just log.
            return

        if info["role"] == "receiver":
            if info["bytes_received"] == info["filesize"]:
                self._log_message(f"Transfer of {info['filename']} completed successfully by sender. Verifying size.", constants.LOG_LEVEL_INFO)
                if info["file_handle"]: info["file_handle"].close(); info["file_handle"] = None

                # Rename from .part to final name
                try:
                    if os.path.exists(info["temp_filepath"]):
                         os.rename(info["temp_filepath"], info["final_filepath"])
                         self._log_message(f"File {info['filename']} saved to {info['final_filepath']}", constants.LOG_LEVEL_INFO)
                         self.gui_queue.put(("add_received_file", (info["filename"], info["final_filepath"])))
                         self.gui_queue.put(("sender_status", (f"Received {info['filename']}!", "green", True)))
                    else: # Temp file disappeared?
                        self._log_message(f"Error: Temporary file {info['temp_filepath']} not found after transfer.", constants.LOG_LEVEL_ERROR)
                        self.gui_queue.put(("sender_status", (f"Error: Lost {info['filename']}", "red", True)))

                except OSError as e:
                    self._log_message(f"Error renaming/finalizing received file {info['filename']}: {e}", constants.LOG_LEVEL_ERROR)
                    self.gui_queue.put(("sender_status", (f"Error saving {info['filename']}: {e}", "red", True)))
                finally:
                    info["temp_filepath"] = None # Clear temp path

            else: # Size mismatch
                self._log_message(f"Transfer of {info['filename']} complete by sender, but size mismatch. Expected {info['filesize']}, got {info['bytes_received']}", constants.LOG_LEVEL_WARN)
                self.gui_queue.put(("sender_status", (f"Size mismatch for {info['filename']}", "red", True)))
                if info["file_handle"]: info["file_handle"].close(); info["file_handle"] = None
                if info["temp_filepath"] and os.path.exists(info["temp_filepath"]):
                    try: os.remove(info["temp_filepath"])
                    except OSError as e: self._log_message(f"Could not remove partial file {info['temp_filepath']}: {e}", constants.LOG_LEVEL_WARN)
                    info["temp_filepath"] = None

            self._reset_transfer_state()
            self.gui_queue.put(("transfer_complete_ui", False)) # False for receiver role
        elif info["role"] == "sender":
            # This means the receiver acknowledged our TRANSFER_COMPLETE (if we were to implement such an ack)
            # For now, sender assumes completion after sending TRANSFER_COMPLETE and getting no error.
            # If receiver sends TRANSFER_COMPLETE, it's an error in protocol for sender.
            self._log_message(f"Sender received unexpected TRANSFER_COMPLETE for {filename_completed}.", constants.LOG_LEVEL_WARN)
            # We can choose to finalize our side if we haven't already.
            if info["bytes_sent"] == info["filesize"]:
                 self._log_message(f"Transfer of {info['filename']} already marked complete on sender side.", constants.LOG_LEVEL_INFO)
            self._reset_transfer_state()
            self.gui_queue.put(("transfer_complete_ui", True)) # True for sender role

    def _cancel_transfer(self, notify_peer=True, reason="User cancelled"):
        """Cancels the current file transfer."""
        if not self.is_transferring:
            # self._log_message("Cancel transfer called but no transfer in progress.", constants.LOG_LEVEL_DEBUG)
            return

        self._log_message(f"Cancelling transfer of {self.current_transfer_info.get('filename', 'unknown file')}. Reason: {reason}", constants.LOG_LEVEL_INFO)
        self.transfer_cancelled_by_user = (reason == "User cancelled") # Track if user initiated

        role_is_sender = (self.current_transfer_info.get("role") == "sender")

        if notify_peer and self.is_connected and self.client_socket:
            try:
                self._send_command(self.client_socket, {"type": "CANCEL_TRANSFER", "data": {"filename": self.current_transfer_info.get("filename"), "reason": reason}})
            except Exception as e:
                self._log_message(f"Error sending CANCEL_TRANSFER notification: {e}", constants.LOG_LEVEL_WARN)

        # Clean up receiver-specific resources
        if self.current_transfer_info.get("role") == "receiver":
            fh = self.current_transfer_info.get("file_handle")
            if fh and not fh.closed: fh.close()
            temp_path = self.current_transfer_info.get("temp_filepath")
            if temp_path and os.path.exists(temp_path):
                try: os.remove(temp_path)
                except OSError as e: self._log_message(f"Error removing temp file {temp_path} on cancel: {e}", constants.LOG_LEVEL_WARN)

        self.gui_queue.put(("sender_status", (f"Transfer cancelled: {reason}", "orange", True)))
        self._reset_transfer_state()
        self.gui_queue.put(("transfer_cancelled_ui", role_is_sender))


    def _handle_cancel_transfer_command(self, data):
        """Handles peer's signal to cancel the transfer."""
        if not self.is_transferring:
            self._log_message("Received CANCEL_TRANSFER but no transfer in progress.", constants.LOG_LEVEL_WARN)
            return

        filename_cancelled = data.get("filename")
        reason = data.get("reason", "Peer cancelled")
        current_filename = self.current_transfer_info.get("filename")

        if filename_cancelled != current_filename:
            self._log_message(f"Received CANCEL_TRANSFER for {filename_cancelled}, but current is {current_filename}.", constants.LOG_LEVEL_WARN)
            return # Not for our current transfer

        self._log_message(f"Peer cancelled transfer of {current_filename}. Reason: {reason}", constants.LOG_LEVEL_INFO)
        self.gui_queue.put(("sender_status", (f"Peer cancelled: {reason}", "orange", True)))

        role_is_sender = (self.current_transfer_info.get("role") == "sender")
        # Clean up receiver-specific resources if we are receiver
        if not role_is_sender:
            fh = self.current_transfer_info.get("file_handle")
            if fh and not fh.closed: fh.close()
            temp_path = self.current_transfer_info.get("temp_filepath")
            if temp_path and os.path.exists(temp_path):
                try: os.remove(temp_path)
                except OSError as e: self._log_message(f"Error removing temp file {temp_path} on peer cancel: {e}", constants.LOG_LEVEL_WARN)

        self._reset_transfer_state()
        self.gui_queue.put(("transfer_cancelled_ui", role_is_sender))

    def _send_chat_message_action(self):
        """Sends the current chat message to the peer."""
        if not self.is_connected:
            self.gui_queue.put(("show_error", "Not connected to a peer to send chat message."))
            return
        if not hasattr(self, 'chat_message_entry') or not self.chat_message_entry: # Check if chat UI is initialized
            self._log_message("Chat UI not ready for sending message.", constants.LOG_LEVEL_WARN)
            return

        message_text = self.chat_message_entry.get("1.0", tk.END).strip() # Get text from Text widget
        if not message_text:
            return # Don't send empty messages

        success = self._send_command(self.client_socket, {"type": "CHAT_MESSAGE", "data": {"text": message_text}})
        if success:
            # Display sent message locally
            timestamp = datetime.datetime.now().strftime("%I:%M:%S %p") # Use 12-hour format
            self.gui_queue.put(("chat_message_display", {"sender_type": "local", "text": message_text, "timestamp": timestamp}))
            self.chat_message_entry.delete("1.0", tk.END) # Clear Text widget
            self._log_message(f"Sent chat message: {message_text}", constants.LOG_LEVEL_DEBUG)
        else:
            self._log_message("Failed to send chat message.", constants.LOG_LEVEL_ERROR)
            # Error handling (e.g., disconnect) is likely handled by _send_command
        return "break" # Prevents the default Enter key behavior (newline) in the Text widget

    def _handle_chat_message_command(self, data):
        """Handles an incoming CHAT_MESSAGE command from the peer."""
        message_text = data.get("text", "")
        timestamp = datetime.datetime.now().strftime("%I:%M:%S %p") # Use 12-hour format
        self.gui_queue.put(("chat_message_display", {"sender_type": "peer", "text": message_text, "timestamp": timestamp}))
        self._log_message(f"Received chat message: {message_text}", constants.LOG_LEVEL_DEBUG)

    def _reset_transfer_state(self):
        """Resets all variables related to an active file transfer."""
        self._log_message("Resetting transfer state.", constants.LOG_LEVEL_DEBUG)
        self.is_transferring = False
        self.transfer_cancelled_by_user = False
        # Close file handle if it's open (receiver side)
        fh = self.current_transfer_info.get("file_handle")
        if fh and not fh.closed:
            try: fh.close()
            except Exception as e: self._log_message(f"Error closing file handle during reset: {e}", constants.LOG_LEVEL_WARN)

        self.current_transfer_info = {}
        self.file_to_send_path.set("") # Clear selected file for sending
        # UI reset for progress etc. is handled by transfer_complete_ui or transfer_cancelled_ui
        # gui.reset_transfer_ui(self) # This is now called by the UI handlers

    def _load_identity_from_keyring_on_startup(self):
        """Attempts to load the user's identity from the keyring on startup."""
        self._log_message("Attempting to load identity from keyring...", constants.LOG_LEVEL_INFO)
        # utils.get_identity_from_keyring() returns (identity_dict, message_str) or (None, message_str)
        identity_dict, message = utils.get_identity_from_keyring()
        self._log_message(message, constants.LOG_LEVEL_DEBUG) # Log the message from utils

        if identity_dict: # Check if the dictionary part is not None
            self._cleanup_temp_files() # Clean any previous temp files
            try:
                # Access items from the identity_dict
                ca_pem = identity_dict["ca_cert_pem"]
                client_cert_pem = identity_dict["client_cert_pem"]
                client_key_pem = identity_dict["client_key_pem"]
                
                # Display names are also in the dictionary
                ca_disp_name = identity_dict.get("ca_display_name", "ca_from_keyring.crt")
                client_cert_disp_name = identity_dict.get("client_cert_display_name", "client_from_keyring.crt")
                client_key_disp_name = identity_dict.get("client_key_display_name", "key_from_keyring.key")

                self.ca_cert_path.set(self._write_temp_cert(ca_pem, "_ca.crt"))
                self.client_cert_path.set(self._write_temp_cert(client_cert_pem, "_client.crt"))
                self.client_key_path.set(self._write_temp_cert(client_key_pem, "_client.key"))
                self.ca_cert_display_name.set(ca_disp_name)
                self.client_cert_display_name.set(client_cert_disp_name)
                self.client_key_display_name.set(client_key_disp_name)

                self.identity_loaded_from_keyring = True
                self.loaded_from_bundle = True # Treat as a bundle for export prompts
                self.bundle_exported_this_session = True # No need to prompt export
                self.keyring_has_user_identity = True
                self._log_message("Identity successfully loaded from keyring using temporary files.", constants.LOG_LEVEL_INFO)
                self.root.after(100, self._save_certs) # Validate and load the temp certs
            except KeyError as e:
                self._log_message(f"Error processing identity from keyring: Missing key {e}", constants.LOG_LEVEL_ERROR)
                self.gui_queue.put(("show_error", f"Failed to load identity from keyring: Data format error (missing {e})."))
                self._cleanup_temp_files()
                self.identity_loaded_from_keyring = False
                self.keyring_has_user_identity = False
            except Exception as e:
                self._log_message(f"Error processing identity from keyring: {e}", constants.LOG_LEVEL_ERROR)
                self.gui_queue.put(("show_error", f"Failed to load identity from keyring:\n{e}"))
                self._cleanup_temp_files()
                self.identity_loaded_from_keyring = False
                self.keyring_has_user_identity = False # Could be partially loaded then failed
        else:
            self._log_message("No saved identity found in keyring or error retrieving it.", constants.LOG_LEVEL_INFO)
            # Message from utils.get_identity_from_keyring() was already logged
            self.keyring_has_user_identity = False # Ensure this is set if identity_dict is None
        gui.update_identity_persistence_buttons_state(self)


    def _save_current_identity_to_keyring(self):
        """Saves the currently loaded valid identity to the system keyring."""
        if not self.certs_loaded_correctly:
            self.gui_queue.put(("show_error", "Cannot save: No valid identity loaded."))
            return
        if self.identity_loaded_from_keyring:
            self.gui_queue.put(("show_info", "This identity is already loaded from the keyring."))
            return
        if self.is_transferring:
            self.gui_queue.put(("show_error", "Cannot save identity during an active transfer."))
            return

        try:
            with open(self.ca_cert_path.get(), "r") as f: ca_pem = f.read()
            with open(self.client_cert_path.get(), "r") as f: client_cert_pem = f.read()
            with open(self.client_key_path.get(), "r") as f: client_key_pem = f.read()

            # Pass display names as individual arguments
            ca_disp_name = self.ca_cert_display_name.get()
            client_cert_disp_name = self.client_cert_display_name.get()
            client_key_disp_name = self.client_key_display_name.get()

            success, msg = utils.save_identity_to_keyring(
                ca_pem, client_cert_pem, client_key_pem,
                ca_disp_name, client_cert_disp_name, client_key_disp_name
            )
            if success:
                self._log_message(f"Identity saved to keyring: {msg}", constants.LOG_LEVEL_INFO)
                self.gui_queue.put(("show_info", "Current identity saved to system keyring."))
                self.identity_loaded_from_keyring = True # Mark as if loaded from keyring now
                self.keyring_has_user_identity = True
                gui.visual_feedback(self, self.save_identity_button, "Save to Keyring", "Saved!")
            else:
                self._log_message(f"Failed to save identity to keyring: {msg}", constants.LOG_LEVEL_ERROR)
                self.gui_queue.put(("show_error", f"Failed to save identity:\n{msg}"))
        except OSError as e:
            self._log_message(f"Error reading certificate files for keyring save: {e}", constants.LOG_LEVEL_ERROR)
            self.gui_queue.put(("show_error", f"Error reading certificate files:\n{e}"))
        except Exception as e:
            self._log_message(f"Unexpected error saving identity to keyring: {e}", constants.LOG_LEVEL_ERROR)
            self.gui_queue.put(("show_error", f"Unexpected error saving identity:\n{e}"))
        finally:
            gui.update_identity_persistence_buttons_state(self)


    def _clear_identity_from_keyring_action(self):
        """Clears the saved user identity from the system keyring."""
        if self.is_transferring:
            self.gui_queue.put(("show_error", "Cannot clear identity during an active transfer."))
            return

        if messagebox.askyesno("Confirm Clear Identity",
                               "Are you sure you want to remove the saved CryptLink user identity "
                               "from your system keyring?\n\nThis will not affect currently loaded certificates, "
                               "only the persisted identity.", icon='warning', parent=self.root):
            success, msg = utils.clear_identity_from_keyring()
            if success:
                self._log_message(f"Identity cleared from keyring: {msg}", constants.LOG_LEVEL_INFO)
                self.gui_queue.put(("show_info", "Saved identity cleared from system keyring."))
                self.keyring_has_user_identity = False
                if self.identity_loaded_from_keyring: # If current identity was from keyring
                    self.identity_loaded_from_keyring = False # It's no longer "from keyring"
                gui.visual_feedback(self, self.clear_identity_button, "Clear from Keyring", "Cleared!")
            else:
                self._log_message(f"Issue clearing identity from keyring: {msg}", constants.LOG_LEVEL_WARN)
                self.gui_queue.put(("show_warning", f"Could not clear identity (it might not have existed):\n{msg}"))
            gui.update_identity_persistence_buttons_state(self)
        else:
            self._log_message("User cancelled identity clearing from keyring.", constants.LOG_LEVEL_INFO)

    def _clear_remembered_peers_action(self):
        """Clears the list of remembered peers after confirmation."""
        if not self.remembered_peers:
            self.gui_queue.put(("show_info", "There are no past connections to clear."))
            self._log_message("Attempted to clear past connections, but list is already empty.", constants.LOG_LEVEL_INFO)
            return

        if messagebox.askyesno("Confirm Clear",
                               "Are you sure you want to clear all past connection history?",
                               parent=self.root):
            self._log_message("User confirmed clearing past connection history.", constants.LOG_LEVEL_INFO)
            self.remembered_peers = []
            self._save_app_settings() # Save immediately
            self.gui_queue.put(("update_peer_list_dropdown", None)) # Update GUI
            self.gui_queue.put(("show_info", "Past connection history has been cleared."))
            # Optional: Visual feedback on the button if we pass it or have a reference
            # For now, the info message and log should suffice.
        else:
            self._log_message("User cancelled clearing past connection history.", constants.LOG_LEVEL_INFO)


    def _load_app_settings(self):
        """Loads application settings from the JSON file."""
        try:
            if os.path.exists(constants.SETTINGS_FILE_PATH):
                with open(constants.SETTINGS_FILE_PATH, 'r') as f:
                    self.app_settings = json.load(f)
                self._log_message(f"Loaded settings from {constants.SETTINGS_FILE_PATH}", constants.LOG_LEVEL_DEBUG)
            else:
                self._log_message(f"Settings file not found at {constants.SETTINGS_FILE_PATH}. Using defaults.", constants.LOG_LEVEL_INFO)
                self.app_settings = {} # Start with empty, defaults will apply

        except (json.JSONDecodeError, OSError) as e:
            self._log_message(f"Error loading settings file: {e}. Using defaults.", constants.LOG_LEVEL_ERROR)
            self.app_settings = {} # Reset to defaults on error

        # Apply loaded settings or defaults
        loaded_log_level_str = self.app_settings.get("logging_level", constants.DEFAULT_LOGGING_LEVEL_STR)
        
        # Ensure constants.CURRENT_LOG_LEVEL is updated correctly
        # This needs to be done carefully as constants are module-level.
        # The best way is to re-import or modify the constant if the module structure allows.
        # For now, we'll update it directly, assuming this is the main control point.
        constants.CURRENT_LOG_LEVEL = constants.LOG_LEVEL_MAP.get(loaded_log_level_str, constants.LOG_LEVEL_MAP[constants.DEFAULT_LOGGING_LEVEL_STR])
        
        self.logging_verbosity_var.set(loaded_log_level_str) # Update Tkinter variable for UI
        self._log_message(f"Logging level set to: {loaded_log_level_str} (numeric: {constants.CURRENT_LOG_LEVEL})", constants.LOG_LEVEL_INFO)

        # Load Manual Identity Configuration setting
        manual_id_config_enabled = self.app_settings.get("manual_id_config_enabled", False) # Default to False
        self.manual_id_config_enabled_var.set(manual_id_config_enabled)

        # Load Remembered Peers
        self.remembered_peers = self.app_settings.get("remembered_peers", [])
        self._log_message(f"Loaded {len(self.remembered_peers)} remembered peers.", constants.LOG_LEVEL_DEBUG)


    def _save_app_settings(self):
        """Saves current application settings to the JSON file."""
        # Update self.app_settings from UI variables
        new_log_level_str = self.logging_verbosity_var.get()
        self.app_settings["logging_level"] = new_log_level_str
        self.app_settings["manual_id_config_enabled"] = self.manual_id_config_enabled_var.get()

        # Apply the new logging level immediately
        constants.CURRENT_LOG_LEVEL = constants.LOG_LEVEL_MAP.get(new_log_level_str, constants.LOG_LEVEL_MAP[constants.DEFAULT_LOGGING_LEVEL_STR])
        self._log_message(f"Logging level changed to: {new_log_level_str} (numeric: {constants.CURRENT_LOG_LEVEL})", constants.LOG_LEVEL_INFO)
        self._log_message(f"Manual Identity Configuration set to: {self.manual_id_config_enabled_var.get()}", constants.LOG_LEVEL_INFO)

        gui.update_identities_view_visibility(self) # Update Identities view based on new setting

        # Save Remembered Peers
        self.app_settings["remembered_peers"] = self.remembered_peers

        try:
            os.makedirs(os.path.dirname(constants.SETTINGS_FILE_PATH), exist_ok=True)
            with open(constants.SETTINGS_FILE_PATH, 'w') as f:
                json.dump(self.app_settings, f, indent=4)
            self._log_message(f"Settings saved to {constants.SETTINGS_FILE_PATH}", constants.LOG_LEVEL_INFO)
            if hasattr(self, 'save_settings_button') and self.save_settings_button.winfo_exists(): # Check if button exists
                gui.visual_feedback(self, self.save_settings_button, "Save Settings", "Saved!")
        except OSError as e:
            self._log_message(f"Error saving settings file: {e}", constants.LOG_LEVEL_ERROR)
            self.gui_queue.put(("show_error", f"Could not save settings:\n{e}"))

    def run(self):
        """Starts the Tkinter main loop and server thread."""
        self._start_server_if_needed() # Start server listening if certs are ready
        self.root.mainloop()

    def _quit_app(self):
        """Handles application shutdown."""
        quit_message = "Are you sure you want to quit CryptLink?"
        if self.is_transferring:
            quit_message = "A file transfer is in progress. Are you sure you want to quit?"

        if not messagebox.askyesno("Confirm Quit", quit_message, parent=self.root):
            self._log_message("Quit cancelled by user.", constants.LOG_LEVEL_INFO)
            return

        self._log_message("Quit confirmed by user. Shutting down...", constants.LOG_LEVEL_INFO)
        # Prompt to save bundle if certs were manually loaded and not saved/exported
        if self.certs_loaded_correctly and not self.loaded_from_bundle and \
           not self.bundle_exported_this_session and not self.identity_loaded_from_keyring:
            if messagebox.askyesno("Save Certificates?",
                                   "You have manually loaded certificates that have not been exported to a bundle or saved to keyring.\n"
                                   "Do you want to export them to a bundle now?", parent=self.root):
                gui.export_bundle_dialog(self) # This is a GUI function

        self.stop_event.set() # Signal all threads to stop

        if self.is_connected:
            self._disconnect_peer(reason="Application quitting")

        if self.server_socket:
            try: self.server_socket.close()
            except: pass
            self.server_socket = None
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=2)
            if self.server_thread.is_alive():
                 self._log_message("Server thread did not shut down cleanly.", constants.LOG_LEVEL_WARN)

        if self.client_connection_thread and self.client_connection_thread.is_alive():
             self.client_connection_thread.join(timeout=1) # Usually short-lived

        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            self.heartbeat_thread.join(timeout=1)

        self._cleanup_temp_files()

        # Cancel any pending GUI updates via root.after
        # This is tricky; Tkinter doesn't have a direct way to cancel all.
        # Destroying the root window handles this.
        if self.root:
            self.root.destroy()
        self._log_message("Application shut down.", constants.LOG_LEVEL_INFO)
        sys.exit(0)
