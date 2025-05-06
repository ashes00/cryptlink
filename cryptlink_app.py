# -*- coding: utf-8 -*-
"""
CryptLink: Secure Peer-to-Peer File Transfer using TLS and Tkinter.
Main Application Class.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog
import socket
import ssl
import threading
import os
import sys
import platform
import time
import json
# import hashlib # No longer used directly?
import queue
import subprocess
import datetime
import base64
import tempfile # Added for temporary files during import

# --- Import Cryptography Components ---
import cryptography.x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.x509.oid import NameOID # Added for Admin Tools details dialog
from cryptography.fernet import Fernet, InvalidToken

# --- Import Keyring (needed for Admin Tools) ---
import keyring # Added for Admin Tools


# --- Import Local Modules ---
try:
    import constants
    import utils
except ImportError as e:
    print(f"ERROR: Failed to import local modules (constants.py, utils.py): {e}", file=sys.stderr)
    print("Ensure all .py files are in the same directory.", file=sys.stderr)
    try:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Import Error", f"Failed to import required modules: {e}\nEnsure constants.py and utils.py are present.")
        root.destroy()
    except tk.TclError:
        pass
    sys.exit(1)


# --- Main Application Class ---

class CryptLinkApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{constants.APP_NAME} v{constants.APP_VERSION}")
        self.root.protocol("WM_DELETE_WINDOW", self._quit_app)
        # Set minimum size - Increased width further to prevent log wrapping
        self.root.minsize(1500, 500) # Increased min width again

        self.style = ttk.Style()
        try:
            if "clam" in self.style.theme_names(): self.style.theme_use("clam")
            elif "vista" in self.style.theme_names() and platform.system() == "Windows": self.style.theme_use("vista")
            elif "aqua" in self.style.theme_names() and platform.system() == "Darwin": self.style.theme_use("aqua")
        except tk.TclError:
            print("Warning: Could not set preferred theme.")

        # --- Certificate Paths & State ---
        self.ca_cert_path = tk.StringVar()
        self.client_cert_path = tk.StringVar()
        self.client_key_path = tk.StringVar()
        self.ca_cert_display_name = tk.StringVar()
        self.client_cert_display_name = tk.StringVar()
        self.client_key_display_name = tk.StringVar()

        self.certs_loaded_correctly = False
        self.bundle_exported_this_session = False
        self.loaded_from_bundle = False
        self.temp_cert_files = []

        # --- Connection State ---
        self.peer_ip_hostname = tk.StringVar()
        self.local_ip = utils.get_local_ip()
        self.local_hostname = socket.gethostname()
        self.local_full_fingerprint = None
        self.local_fingerprint_display = tk.StringVar(value="N/A")
        self.peer_full_fingerprint = None
        self.peer_fingerprint_display = tk.StringVar(value="N/A")
        self.peer_hostname = tk.StringVar(value="N/A")
        self.connection_status = tk.StringVar(value="No Certs")
        self.server_socket = None
        self.client_socket = None
        self.peer_info = {}
        self.server_thread = None
        self.client_thread = None
        self.listen_thread = None
        self.is_connected = False
        self.is_connecting = False
        self.is_server_running = False
        self.stop_server_event = threading.Event()
        self.heartbeat_timer = None
        self.last_heartbeat_ack_time = 0
        self.connection_confirmation_queue = queue.Queue()

        # --- File Transfer State ---
        self.file_to_send_path = tk.StringVar()
        self.transfer_progress = tk.DoubleVar()
        self.transfer_speed = tk.StringVar(value="Speed: N/A")
        self.transfer_eta = tk.StringVar(value="ETA: N/A")
        self.sender_transfer_status = tk.StringVar(value="")
        self.is_transferring = False
        self.transfer_cancelled = threading.Event()
        self.transfer_start_time = 0
        self.bytes_transferred = 0
        self.total_file_size = 0
        self.current_transfer_id = 0
        self.receiving_file_handle = None
        self.receiving_file_path = None
        self.transfer_lock = threading.Lock()
        self.sender_status_clear_timer = None
        self._pending_transfer_request = None

        # --- Received Files ---
        self.received_files = {}

        # --- Admin Tools State ---
        self.admin_tools_window = None # No longer used for Toplevel
        self.admin_ca_cert = None
        self.admin_ca_key = None

        # --- GUI Update Queue ---
        self.gui_queue = queue.Queue()
        self._after_id_queue = self.root.after(100, self._process_gui_queue)

        # --- Build GUI ---
        self._create_widgets()
        self._update_local_info()
        self._update_status_display()


    def _create_widgets(self):
        # --- Menu Bar ---
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)

        # --- Top-Level Menu Commands ---
        self.menu_bar.add_command(label="Home", command=self._show_main_view, state='disabled')
        self.menu_bar.add_command(label="Identities", command=self._show_identities_view, state='normal')
        self.menu_bar.add_command(label="Admin Tools", command=self._show_admin_tools_view, state='normal') # Changed from cascade

        # File Menu (Example - you might already have one)
        # file_menu = tk.Menu(self.menu_bar, tearoff=0)
        # self.menu_bar.add_cascade(label="File", menu=file_menu)
        # file_menu.add_command(label="Exit", command=self._quit_app)


        # --- Main Frame Setup (2 Columns) ---
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Configure main_frame columns with weights for proportional resizing (35% / 65%)
        main_frame.columnconfigure(0, weight=0) # Left column (controls) - Let it shrink to content size
        main_frame.columnconfigure(1, weight=1) # Right column (received files + logs) - Let it expand
        # Configure main_frame rows to allow vertical expansion
        main_frame.rowconfigure(0, weight=1) # Row for Received Files (allow expansion)
        main_frame.rowconfigure(1, weight=1) # Row for Logs (allow expansion)

        # --- Left Column Frame ---
        left_frame = ttk.Frame(main_frame)
        left_frame.grid(row=0, column=0, rowspan=2, sticky=(tk.W, tk.N, tk.S), padx=(0, 10)) # Removed tk.E from sticky
        left_frame.columnconfigure(0, weight=1) # Allow internal content to align/expand if needed within the frame
        left_frame.rowconfigure(0, weight=0) # Certs
        left_frame.rowconfigure(1, weight=0) # Connection
        left_frame.rowconfigure(2, weight=0) # Status
        left_frame.rowconfigure(3, weight=0) # Transfer
        left_frame.rowconfigure(4, weight=0) # Admin Tools (will occupy row 0-3 when shown)
        left_frame.rowconfigure(4, weight=1) # Filler/Spacing
        left_frame.rowconfigure(5, weight=0) # Quit Button

        # --- Certificate Section (in left_frame) ---
        self.cert_frame = ttk.LabelFrame(left_frame, text="Certificates & Bundles", padding="10")
        self.cert_frame.grid(row=0, column=0, sticky=tk.W, pady=5) # Changed sticky to tk.W
        self.cert_frame.columnconfigure(1, weight=1) # Use self.cert_frame

        ttk.Button(self.cert_frame, text="CA Cert", command=self._select_ca).grid(row=0, column=0, padx=5, pady=2, sticky=tk.W) # Use self.cert_frame
        self.ca_entry = ttk.Entry(self.cert_frame, textvariable=self.ca_cert_display_name, state='readonly', width=30) # Use self.cert_frame
        self.ca_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=2)
        self.save_certs_button = ttk.Button(self.cert_frame, text="Load Certs", command=self._save_certs, state='disabled') # Use self.cert_frame
        self.save_certs_button.grid(row=0, column=2, padx=5, pady=2, sticky=tk.E)

        ttk.Button(self.cert_frame, text="Client Cert", command=self._select_cert).grid(row=1, column=0, padx=5, pady=2, sticky=tk.W) # Use self.cert_frame
        self.cert_entry = ttk.Entry(self.cert_frame, textvariable=self.client_cert_display_name, state='readonly', width=30) # Use self.cert_frame
        self.cert_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5, pady=2)
        self.export_bundle_button = ttk.Button(self.cert_frame, text="Export Bundle", command=self._export_bundle, state='disabled') # Use self.cert_frame
        self.export_bundle_button.grid(row=1, column=2, padx=5, pady=2, sticky=tk.E)

        ttk.Button(self.cert_frame, text="Client Key", command=self._select_key).grid(row=2, column=0, padx=5, pady=2, sticky=tk.W) # Use self.cert_frame
        self.key_entry = ttk.Entry(self.cert_frame, textvariable=self.client_key_display_name, state='readonly', width=30) # Use self.cert_frame
        self.key_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=5, pady=2)
        self.import_bundle_button = ttk.Button(self.cert_frame, text="Import Bundle", command=self._import_bundle, state='normal') # Use self.cert_frame
        self.import_bundle_button.grid(row=2, column=2, padx=5, pady=2, sticky=tk.E)

        # --- Connection Section (in left_frame) ---
        self.conn_frame = ttk.LabelFrame(left_frame, text="Connection", padding="10")
        self.conn_frame.grid(row=1, column=0, sticky=tk.W, pady=5) # Changed sticky to tk.W
        self.conn_frame.columnconfigure(1, weight=1) # Use self.conn_frame

        ttk.Label(self.conn_frame, text="Peer IP/Host:").grid(row=0, column=0, padx=5, pady=2, sticky=tk.W) # Use self.conn_frame
        self.peer_entry = ttk.Entry(self.conn_frame, textvariable=self.peer_ip_hostname, state='disabled', width=7) # Use self.conn_frame - Reduced width further
        self.peer_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=2)

        # Move button frame to the next row (row=1) and align right under the entry
        conn_button_frame = ttk.Frame(self.conn_frame) # Use self.conn_frame
        conn_button_frame.grid(row=1, column=1, columnspan=2, padx=5, pady=(2, 5), sticky=tk.E) # Changed row, added columnspan and padding
        self.connect_button = ttk.Button(conn_button_frame, text="Connect", command=self._connect_peer, state='disabled')
        self.connect_button.pack(side=tk.LEFT, padx=(0, 2)) # Keep packing within the frame
        self.disconnect_button = ttk.Button(conn_button_frame, text="Disconnect", command=lambda: self._disconnect_peer(reason="User disconnected"), state='disabled')
        self.disconnect_button.pack(side=tk.LEFT)

        # --- Status Display Section (in left_frame) ---
        self.status_frame = ttk.LabelFrame(left_frame, text="Status", padding="10")
        self.status_frame.grid(row=2, column=0, sticky=tk.W, pady=5) # Changed sticky to tk.W
        self.status_frame.columnconfigure(1, weight=1) # Use self.status_frame

        ttk.Label(self.status_frame, text="Status:").grid(row=0, column=0, sticky=tk.W, padx=5) # Use self.status_frame
        self.status_label = ttk.Label(self.status_frame, textvariable=self.connection_status, font=('TkDefaultFont', 10, 'bold')) # Use self.status_frame
        self.status_label.grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Label(self.status_frame, text="Local:").grid(row=1, column=0, sticky=tk.W, padx=5) # Use self.status_frame
        self.local_info_label = ttk.Label(self.status_frame, text=f"{self.local_hostname} ({self.local_ip})", wraplength=250) # Use self.status_frame, Added wraplength
        self.local_info_label.grid(row=1, column=1, sticky=tk.W, padx=5)
        ttk.Label(self.status_frame, text="Local FP:").grid(row=2, column=0, sticky=tk.W, padx=5) # Use self.status_frame
        self.local_fp_label = ttk.Label(self.status_frame, textvariable=self.local_fingerprint_display, font=('Courier', 9)) # Use self.status_frame
        self.local_fp_label.grid(row=2, column=1, sticky=tk.W, padx=5)
        ttk.Label(self.status_frame, text="Peer:").grid(row=3, column=0, sticky=tk.W, padx=5) # Use self.status_frame
        self.peer_info_label = ttk.Label(self.status_frame, textvariable=self.peer_hostname, wraplength=250) # Use self.status_frame, Added wraplength
        self.peer_info_label.grid(row=3, column=1, sticky=tk.W, padx=5)
        ttk.Label(self.status_frame, text="Peer FP:").grid(row=4, column=0, sticky=tk.W, padx=5) # Use self.status_frame
        self.peer_fp_label = ttk.Label(self.status_frame, textvariable=self.peer_fingerprint_display, font=('Courier', 9)) # Use self.status_frame
        self.peer_fp_label.grid(row=4, column=1, sticky=tk.W, padx=5)

        # --- File Transfer Section (in left_frame) ---
        self.transfer_frame = ttk.LabelFrame(left_frame, text="File Transfer", padding="10")
        self.transfer_frame.grid(row=3, column=0, sticky=tk.W, pady=5) # Changed sticky to tk.W
        self.transfer_frame.columnconfigure(1, weight=1) # Use self.transfer_frame

        self.choose_file_button = ttk.Button(self.transfer_frame, text="Choose File", command=self._choose_file, state='disabled') # Use self.transfer_frame
        self.choose_file_button.grid(row=0, column=0, padx=5, pady=2, sticky=tk.W)
        self.file_entry = ttk.Entry(self.transfer_frame, textvariable=self.file_to_send_path, state='readonly', width=8) # Use self.transfer_frame - Reduced width further
        self.file_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=2)

        # Move button frame to the next row (row=1) and align right under the entry
        transfer_button_frame = ttk.Frame(self.transfer_frame) # Use self.transfer_frame
        transfer_button_frame.grid(row=1, column=1, columnspan=2, padx=5, pady=(2, 5), sticky=tk.E) # Changed row, added columnspan and padding
        transfer_button_frame.columnconfigure(0, weight=0)
        transfer_button_frame.columnconfigure(1, weight=0)

        self.send_file_button = ttk.Button(transfer_button_frame, text="Send File", command=self._send_file, state='disabled')
        self.send_file_button.grid(row=0, column=0, padx=(0, 2))
        self.cancel_button = ttk.Button(transfer_button_frame, text="Cancel", command=lambda: self._cancel_transfer(notify_peer=True), state='disabled') # Parent is already correct
        self.cancel_button.grid(row=0, column=1)

        self.progress_bar = ttk.Progressbar(self.transfer_frame, variable=self.transfer_progress, maximum=100) # Use self.transfer_frame
        self.progress_bar.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), padx=5, pady=5) # Moved to row 2

        status_speed_eta_frame = ttk.Frame(self.transfer_frame) # Use self.transfer_frame
        status_speed_eta_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E)) # Moved to row 3
        status_speed_eta_frame.columnconfigure(1, weight=1)
        self.sender_status_label = ttk.Label(status_speed_eta_frame, textvariable=self.sender_transfer_status)
        self.sender_status_label.grid(row=0, column=0, sticky=tk.W, padx=5)
        self.speed_label = ttk.Label(status_speed_eta_frame, textvariable=self.transfer_speed)
        self.speed_label.grid(row=0, column=1, sticky=tk.W, padx=5)
        self.eta_label = ttk.Label(status_speed_eta_frame, textvariable=self.transfer_eta)
        self.eta_label.grid(row=0, column=2, sticky=tk.E, padx=5)

        # --- Quit Button (in left_frame) ---
        self.quit_button = ttk.Button(left_frame, text="Quit", command=self._quit_app)
        self.quit_button.grid(row=5, column=0, sticky=tk.E, pady=10, padx=5) # Use self.quit_button

        # --- Received Files Section (Right Column, Row 0) ---
        self.received_frame = ttk.LabelFrame(main_frame, text="Received Files (Double-click to open)", padding="10") # Assign to self.received_frame
        self.received_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 5)) # Use self.received_frame here too
        self.received_frame.columnconfigure(0, weight=1) # Use self.received_frame
        self.received_frame.rowconfigure(0, weight=1) # Use self.received_frame

        self.received_listbox = tk.Listbox(self.received_frame, height=5, width=40) # Use self.received_frame
        self.received_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.received_listbox.bind("<Double-Button-1>", self._open_received_file)
        recv_scrollbar_y = ttk.Scrollbar(self.received_frame, orient=tk.VERTICAL, command=self.received_listbox.yview) # Use self.received_frame
        recv_scrollbar_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.received_listbox['yscrollcommand'] = recv_scrollbar_y.set
        recv_scrollbar_x = ttk.Scrollbar(self.received_frame, orient=tk.HORIZONTAL, command=self.received_listbox.xview) # Use self.received_frame
        recv_scrollbar_x.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E))
        self.received_listbox['xscrollcommand'] = recv_scrollbar_x.set

        # --- Logging Section (Right Column, Row 1) ---
        # Use LabelFrame for consistent border and title
        self.log_frame_outer = ttk.LabelFrame(main_frame, text="Logs", padding="10")
        self.log_frame_outer.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(5, 0)) # Use self.log_frame_outer
        # Configure resizing for log_frame_outer's internal grid
        self.log_frame_outer.columnconfigure(0, weight=1) # Text area column expands # Use self.log_frame_outer
        self.log_frame_outer.columnconfigure(1, weight=0) # Scrollbar column doesn't expand # Use self.log_frame_outer
        self.log_frame_outer.rowconfigure(0, weight=0) # Button row doesn't expand # Use self.log_frame_outer
        self.log_frame_outer.rowconfigure(1, weight=1) # Text area row expands # Use self.log_frame_outer
        self.log_frame_outer.rowconfigure(2, weight=0) # Horizontal scrollbar row doesn't expand # Use self.log_frame_outer

        # Frame for Copy/Clear buttons (inside the LabelFrame)
        log_button_frame = ttk.Frame(self.log_frame_outer) # Use self.log_frame_outer
        # Place buttons in row 0, spanning relevant columns, sticking East
        log_button_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.E), pady=(0, 5))

        self.copy_log_button = ttk.Button(log_button_frame, text="Copy", command=self._copy_logs)
        self.clear_log_button = ttk.Button(log_button_frame, text="Clear", command=self._clear_logs)
        self.clear_log_button.pack(side=tk.RIGHT, padx=5) # Pack within button frame
        self.copy_log_button.pack(side=tk.RIGHT, padx=5) # Pack within button frame

        # Text widget and scrollbars directly inside log_frame_outer
        self.log_text = tk.Text(self.log_frame_outer, height=10, state='disabled', wrap=tk.WORD, width=50) # Use self.log_frame_outer
        self.log_text.grid(row=1, column=0, sticky="nsew") # Row 1, below buttons

        log_scrollbar_y = ttk.Scrollbar(self.log_frame_outer, orient=tk.VERTICAL, command=self.log_text.yview) # Use self.log_frame_outer
        log_scrollbar_y.grid(row=1, column=1, sticky=(tk.N, tk.S)) # Row 1, next to text
        self.log_text['yscrollcommand'] = log_scrollbar_y.set

        log_scrollbar_x = ttk.Scrollbar(self.log_frame_outer, orient=tk.HORIZONTAL, command=self.log_text.xview) # Use self.log_frame_outer
        log_scrollbar_x.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E)) # Row 2, below text
        self.log_text['xscrollcommand'] = log_scrollbar_x.set

        # --- Admin Tools Section (in left_frame, initially hidden) ---
        self.admin_tools_frame = ttk.Frame(left_frame, padding="5")
        # We will grid this later in _show_admin_tools_view
        self.admin_tools_frame.columnconfigure(0, weight=1)

        # CA Section (within admin_tools_frame)
        ca_frame = ttk.LabelFrame(self.admin_tools_frame, text="Certificate Authority (CA)", padding="10")
        ca_frame.grid(row=0, column=0, sticky=tk.W, pady=5) # Changed sticky to tk.W
        ca_frame.columnconfigure(1, weight=1)

        self.admin_ca_status_var = tk.StringVar(value="CA Status: Unknown")
        ttk.Label(ca_frame, textvariable=self.admin_ca_status_var).grid(row=0, column=0, columnspan=2, sticky=tk.W, padx=5, pady=2)
        self.admin_load_ca_button = ttk.Button(ca_frame, text="Load/Create CA", command=self._admin_load_create_ca)
        self.admin_load_ca_button.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)

        ca_button_frame = ttk.Frame(ca_frame)
        ca_button_frame.grid(row=1, column=1, sticky=tk.E, padx=5, pady=5)
        self.admin_export_ca_button = ttk.Button(ca_button_frame, text="Export CA...", command=self._admin_export_ca, state='disabled')
        self.admin_export_ca_button.pack(side=tk.LEFT, padx=(0, 5))
        self.admin_clear_ca_button = ttk.Button(ca_button_frame, text="Clear CA", command=self._admin_clear_ca, state='disabled')
        self.admin_clear_ca_button.pack(side=tk.LEFT)

        # Client Bundle Section (within admin_tools_frame)
        client_frame = ttk.LabelFrame(self.admin_tools_frame, text="Generate Client Bundle (.clb)", padding="10")
        client_frame.grid(row=1, column=0, sticky=tk.W, pady=5) # Changed sticky to tk.W
        client_frame.columnconfigure(1, weight=1)

        ttk.Label(client_frame, text="Client Name (CN):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.admin_client_cn_var = tk.StringVar()
        self.admin_client_cn_entry = ttk.Entry(client_frame, textvariable=self.admin_client_cn_var, width=30)
        self.admin_client_cn_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=2)

        self.admin_generate_bundle_button = ttk.Button(client_frame, text="Generate Bundle", command=self._admin_generate_bundle, state='disabled')
        self.admin_generate_bundle_button.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        # --- End Admin Tools Section ---

        # Set initial view
        self._show_main_view()


    # --- GUI Update & Logging ---
    def _log_message(self, message, level=constants.LOG_LEVEL_INFO):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{now}] [{level}] {message}\n"
        self.gui_queue.put(("log", log_entry))
    def _update_log_widget(self, log_entry):
        try:
             if not self.log_text.winfo_exists(): return
             self.log_text.config(state='normal')
             self.log_text.insert(tk.END, log_entry)
             self.log_text.see(tk.END)
             self.log_text.config(state='disabled')
        except tk.TclError:
             print("Log widget destroyed, message ignored:", log_entry.strip())
    def _process_gui_queue(self):
        try:
            while True:
                message_type, data = self.gui_queue.get_nowait()
                if not self.root.winfo_exists(): break
                if message_type == "log": self._update_log_widget(data)
                elif message_type == "status": self._set_connection_status(data)
                elif message_type == "peer_info": self._update_peer_info_display(data[0], data[1])
                elif message_type == "disconnect": self._handle_disconnection_ui(data)
                elif message_type == "progress": self._update_progress_display(*data)
                elif message_type == "transfer_complete": self._handle_transfer_complete_ui(data)
                elif message_type == "transfer_cancelled_ui": self._handle_transfer_cancelled_ui(data)
                elif message_type == "add_received_file": self._add_received_file_display(data[0], data[1])
                elif message_type == "show_error": messagebox.showerror("Error", data, parent=self.root)
                elif message_type == "show_info": messagebox.showinfo("Info", data, parent=self.root)
                elif message_type == "ask_connection_confirm":
                      peer_host, peer_ip, peer_fp_display, confirm_q = data
                      accept = messagebox.askyesno("Confirm Peer Connection", f"Accept incoming connection from:\nHost: {peer_host} ({peer_ip})\nFingerprint: {peer_fp_display}\n\nVerify fingerprint with sender before accepting.", parent=self.root)
                      confirm_q.put(accept)
                elif message_type == "ask_yes_no":
                      transfer_id, filename, filesize_str = data
                      accept = messagebox.askyesno("Incoming File Transfer", f"Accept file '{filename}' ({filesize_str}) from peer?", parent=self.root)
                      threading.Thread(target=self._respond_to_file_request, args=(accept, transfer_id, filename), daemon=True).start()
                elif message_type == "sender_status": self._update_sender_status(*data)
        except queue.Empty: pass
        except Exception as e:
             print(f"Error processing GUI queue: {e}")
             self._log_message(f"Error processing GUI queue: {e}", constants.LOG_LEVEL_ERROR)
        finally:
            if self.root.winfo_exists(): self._after_id_queue = self.root.after(100, self._process_gui_queue)
    def _set_connection_status(self, status):
        self.connection_status.set(status)
        self._update_status_display()
    def _update_status_display(self):
        if not self.root.winfo_exists(): return
        status = self.connection_status.get()
        peer_entry_state = 'disabled'; connect_button_state = 'disabled'; disconnect_button_state = 'disabled'
        choose_file_button_state = 'disabled'; send_file_button_state = 'disabled'; cancel_button_state = 'disabled'
        export_bundle_button_state = 'disabled'; import_bundle_button_state = 'normal'
        save_certs_button_state = 'normal' if (self.ca_cert_display_name.get() and self.client_cert_display_name.get() and self.client_key_display_name.get()) else 'disabled'
        status_color = "red"
        if status == "No Certs": pass
        elif status == "Certs Loaded":
            status_color = "darkorange"
            if self.certs_loaded_correctly: peer_entry_state = 'normal'; connect_button_state = 'normal'; export_bundle_button_state = 'normal'
        elif status == "Disconnected":
            status_color = "darkorange"
            if self.certs_loaded_correctly: peer_entry_state = 'normal'; connect_button_state = 'normal'; export_bundle_button_state = 'normal'
            else: export_bundle_button_state = 'disabled'
        elif status == "Connecting":
            status_color = "blue"; disconnect_button_state = 'normal'; import_bundle_button_state = 'disabled'
            export_bundle_button_state = 'disabled'; save_certs_button_state = 'disabled'
        elif status == "Confirming Peer":
             status_color = "purple"; disconnect_button_state = 'normal'; import_bundle_button_state = 'disabled'
             export_bundle_button_state = 'disabled'; save_certs_button_state = 'disabled'
        elif status == "Securely Connected":
            status_color = "green"; disconnect_button_state = 'normal'; choose_file_button_state = 'normal'
            send_file_button_state = 'normal' if self.file_to_send_path.get() else 'disabled'
            export_bundle_button_state = 'normal'; import_bundle_button_state = 'disabled'; save_certs_button_state = 'disabled'
        else: status_color = "red"
        try:
            self.status_label.config(foreground=status_color)
            self.peer_entry.config(state=peer_entry_state)
            self.connect_button.config(state=connect_button_state)
            self.disconnect_button.config(state=disconnect_button_state)
            self.choose_file_button.config(state=choose_file_button_state)
            self.send_file_button.config(state=send_file_button_state)
            self.save_certs_button.config(state=save_certs_button_state)
            self.import_bundle_button.config(state=import_bundle_button_state)
            self.export_bundle_button.config(state=export_bundle_button_state)
            if self.is_transferring:
                 self.cancel_button.config(state='normal'); self.choose_file_button.config(state='disabled')
                 self.send_file_button.config(state='disabled'); self.disconnect_button.config(state='disabled')
                 self.connect_button.config(state='disabled'); self.import_bundle_button.config(state='disabled')
                 self.export_bundle_button.config(state='disabled'); self.save_certs_button.config(state='disabled')
            else:
                 self.cancel_button.config(state='disabled')
                 if not self.sender_status_clear_timer: self.sender_transfer_status.set("")
        except tk.TclError as e: print(f"Error updating widget states (window likely closing): {e}")
    def _update_local_info(self):
        if not self.root.winfo_exists(): return
        self.local_info_label.config(text=f"{self.local_hostname} ({self.local_ip})")
        cert_path = self.client_cert_path.get()
        if cert_path:
             self.local_full_fingerprint = utils.get_certificate_fingerprint(cert_path)
             self.local_fingerprint_display.set(utils.format_fingerprint_display(self.local_full_fingerprint))
        else:
             self.local_full_fingerprint = None; self.local_fingerprint_display.set("N/A")
    def _update_peer_info_display(self, peer_host, peer_info_dict):
        if not self.root.winfo_exists(): return
        self.peer_info = peer_info_dict
        hostname = peer_info_dict.get('hostname', 'N/A'); ip = peer_info_dict.get('ip', 'N/A')
        self.peer_full_fingerprint = peer_info_dict.get('fingerprint', None)
        self.peer_hostname.set(f"{hostname} ({ip})")
        self.peer_fingerprint_display.set(utils.format_fingerprint_display(self.peer_full_fingerprint))
        if self.connection_status.get() == "Securely Connected": self.peer_ip_hostname.set(peer_host or ip)
        self._log_message(f"Received peer info: {hostname}({ip}) FP: {self.peer_fingerprint_display.get()}")
    def _clear_peer_info_display(self):
        if not self.root.winfo_exists(): return
        self.peer_hostname.set("N/A"); self.peer_fingerprint_display.set("N/A")
        self.peer_full_fingerprint = None; self.peer_info = {}; self.peer_ip_hostname.set("")
    def _visual_feedback(self, button, original_text, feedback_text="Done"):
        try:
            if button and isinstance(button, ttk.Button) and button.winfo_exists():
                 original_state = button.cget("state")
                 button.config(text=feedback_text, state=tk.DISABLED)
                 self.root.after(2000, lambda b=button, ot=original_text, os=original_state: self._revert_button_config(b, ot, os))
            elif button: print(f"Warning: _visual_feedback called on non-button or non-existent widget: {button}")
        except Exception as e:
            print(f"Error during visual feedback for {button}: {e}")
            try:
                 if button and button.winfo_exists(): button.config(text=original_text, state=original_state)
            except: pass
    def _revert_button_config(self, button, original_text, original_state):
         try:
              if button and button.winfo_exists():
                   button.config(text=original_text, state=original_state)
                   if button == self.export_bundle_button and not self.certs_loaded_correctly: button.config(state=tk.DISABLED)
                   elif button == self.save_certs_button and not (self.ca_cert_display_name.get() and self.client_cert_display_name.get() and self.client_key_display_name.get()): button.config(state=tk.DISABLED)
         except tk.TclError as e: print(f"Info: Could not revert button config (widget likely destroyed): {e}")
         except Exception as e: print(f"Error reverting button config: {e}")

    # --- Certificate Handling Callbacks ---
    def _check_enable_load_certs(self):
         can_load = bool(self.ca_cert_display_name.get() and self.client_cert_display_name.get() and self.client_key_display_name.get())
         self.save_certs_button.config(state='normal' if can_load else 'disabled')
         self.export_bundle_button.config(state='normal' if self.certs_loaded_correctly else 'disabled')
    def _select_file(self, variable, display_variable, title):
        initial_dir = os.getcwd()
        filename = filedialog.askopenfilename(title=title, filetypes=[("All files", "*.*")], initialdir=initial_dir, parent=self.root)
        if filename:
            variable.set(filename)
            display_variable.set(os.path.basename(filename))
            self._log_message(f"Selected {title}: {os.path.basename(filename)}")
            if self.certs_loaded_correctly:
                self.certs_loaded_correctly = False
                self.gui_queue.put(("status", "No Certs"))
                self.local_fingerprint_display.set("N/A")
                self.local_full_fingerprint = None
            self.bundle_exported_this_session = False
            self.loaded_from_bundle = False
            self._cleanup_temp_files()
            self._check_enable_load_certs()
    def _select_ca(self): self._select_file(self.ca_cert_path, self.ca_cert_display_name, "Select CA Certificate")
    def _select_cert(self): self._select_file(self.client_cert_path, self.client_cert_display_name, "Select Client Certificate")
    def _select_key(self): self._select_file(self.client_key_path, self.client_key_display_name, "Select Client Private Key")
    def _save_certs(self):
        self.certs_loaded_correctly = False
        ca_path = self.ca_cert_path.get(); cert_path = self.client_cert_path.get(); key_path = self.client_key_path.get()
        if not (ca_path and cert_path and key_path): self.gui_queue.put(("show_error", "Internal error: Missing certificate path data.")); return
        if not all(os.path.exists(p) for p in [ca_path, cert_path, key_path]):
             self.gui_queue.put(("show_error", "One or more certificate/key files not found at the specified paths.\nPlease re-select or re-import."))
             self.ca_cert_display_name.set(""); self.client_cert_display_name.set(""); self.client_key_display_name.set("")
             self._check_enable_load_certs(); return
        try:
            full_fp = utils.get_certificate_fingerprint(cert_path)
            if full_fp in ["Error", "Parse Error", None]:
                 if full_fp == "Parse Error": raise ValueError("Could not parse client certificate (invalid PEM format?).")
                 else: raise ValueError(f"Could not read client certificate or calculate fingerprint ({full_fp}). Path: {cert_path}")
            self.local_full_fingerprint = full_fp; self.local_fingerprint_display.set(utils.format_fingerprint_display(full_fp))
            try:
                 with open(key_path, "rb") as key_file: serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
            except ValueError as key_e: raise ValueError(f"Error loading private key file: {key_e}. Check format (PEM) and ensure it's not password protected. Path: {key_path}") from key_e
            except TypeError as key_e:
                 if "private key is encrypted" in str(key_e): raise ValueError("Private key is password protected (passwords not supported).") from key_e
                 else: raise ValueError(f"Error loading private key: {key_e}") from key_e
            except Exception as key_e: raise ValueError(f"Cannot read private key file. Path: {key_path}. Error: {key_e}") from key_e
            try:
                 with open(ca_path, "rb") as ca_file: cryptography.x509.load_pem_x509_certificate(ca_file.read(), default_backend())
            except ValueError as ca_e: raise ValueError(f"Error loading CA certificate: {ca_e}. Check format (PEM). Path: {ca_path}") from ca_e
            except Exception as ca_e: raise ValueError(f"Cannot read CA certificate file. Path: {ca_path}. Error: {ca_e}") from ca_e
            self.certs_loaded_correctly = True; self._log_message("Certificate and key files validated successfully.")
            self._visual_feedback(self.save_certs_button, "Load Certs", "Loaded!"); self._update_local_info()
            self.gui_queue.put(("status", "Certs Loaded")); self._check_enable_load_certs(); self._start_server_if_needed()
            if not self.loaded_from_bundle: self.root.after(100, self._prompt_export_after_load)
            else: self.loaded_from_bundle = False
        except ValueError as e:
             self.gui_queue.put(("show_error", f"Certificate validation failed:\n{e}"))
             self._log_message(f"Certificate validation failed: {e}", constants.LOG_LEVEL_ERROR)
             self.gui_queue.put(("status", "No Certs")); self.local_fingerprint_display.set("N/A"); self.local_full_fingerprint = None
             self._check_enable_load_certs()
             if self.loaded_from_bundle: self._cleanup_temp_files()
             self.loaded_from_bundle = False
        except Exception as e:
            self.gui_queue.put(("show_error", f"Unexpected error validating certificates: {e}"))
            self._log_message(f"Unexpected error validating certificates: {e}", constants.LOG_LEVEL_ERROR)
            self.gui_queue.put(("status", "No Certs")); self.local_fingerprint_display.set("N/A"); self.local_full_fingerprint = None
            self._check_enable_load_certs()
            if self.loaded_from_bundle: self._cleanup_temp_files()
            self.loaded_from_bundle = False
    def _prompt_export_after_load(self):
        if not self.certs_loaded_correctly: return
        if messagebox.askyesno("Export Certificate Bundle","Certificates loaded successfully.\n\nDo you want to export these certificates to a password-protected bundle for easier loading next time?", parent=self.root):
            self._export_bundle()
        else:
            self._log_message("User chose not to export bundle after loading.")
            self.bundle_exported_this_session = False

    # --- Bundle Import/Export ---
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        if not isinstance(password, str) or not password: raise ValueError("Password must be a non-empty string.")
        if not isinstance(salt, bytes) or len(salt) != constants.BUNDLE_SALT_SIZE: raise ValueError(f"Salt must be bytes of size {constants.BUNDLE_SALT_SIZE}.")
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=constants.BUNDLE_KDF_ITERATIONS, backend=default_backend())
        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8'))); return key
    def _encrypt_certs(self, password: str) -> tuple[bytes, bytes] | None:
        ca_path = self.ca_cert_path.get(); cert_path = self.client_cert_path.get(); key_path = self.client_key_path.get()
        if not (ca_path and cert_path and key_path): self._log_message("Cannot encrypt: Not all certificate paths are set.", constants.LOG_LEVEL_ERROR); return None
        try:
            with open(ca_path, "rb") as f: ca_data = f.read()
            with open(cert_path, "rb") as f: cert_data = f.read()
            with open(key_path, "rb") as f: key_data = f.read()
            ca_name = self.ca_cert_display_name.get() or os.path.basename(ca_path)
            cert_name = self.client_cert_display_name.get() or os.path.basename(cert_path)
            key_name = self.client_key_display_name.get() or os.path.basename(key_path)
        except OSError as e: self._log_message(f"Error reading certificate file for encryption: {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"Error reading certificate file for export:\n{e}")); return None
        certs_dict = {"ca_name": ca_name, "cert_name": cert_name, "key_name": key_name, "ca_b64": base64.b64encode(ca_data).decode('ascii'), "cert_b64": base64.b64encode(cert_data).decode('ascii'), "key_b64": base64.b64encode(key_data).decode('ascii')}
        certs_json = json.dumps(certs_dict).encode('utf-8'); salt = os.urandom(constants.BUNDLE_SALT_SIZE)
        try: key = self._derive_key(password, salt); f = Fernet(key); encrypted_data = f.encrypt(certs_json); return salt, encrypted_data
        except Exception as e: self._log_message(f"Encryption failed: {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"Encryption failed: {e}")); return None
    def _decrypt_certs(self, bundle_file_path: str, password: str) -> dict | None:
        try:
            with open(bundle_file_path, "rb") as f:
                salt = f.read(constants.BUNDLE_SALT_SIZE)
                if len(salt) < constants.BUNDLE_SALT_SIZE: raise ValueError("Bundle file is too short to contain salt.")
                encrypted_certs = f.read()
            if not encrypted_certs: raise ValueError("Bundle file is missing encrypted data after salt.")
            derived_key = self._derive_key(password, salt); f = Fernet(derived_key); decrypted_json = f.decrypt(encrypted_certs)
            certs_dict_b64 = json.loads(decrypted_json.decode('utf-8'))
            required_keys = ["ca_name", "cert_name", "key_name", "ca_b64", "cert_b64", "key_b64"]
            if not all(k in certs_dict_b64 for k in required_keys): raise ValueError("Decrypted data is missing required certificate names or content.")
            certs_data = {"ca_name": certs_dict_b64["ca_name"], "cert_name": certs_dict_b64["cert_name"], "key_name": certs_dict_b64["key_name"], "ca_data": base64.b64decode(certs_dict_b64["ca_b64"]), "cert_data": base64.b64decode(certs_dict_b64["cert_b64"]), "key_data": base64.b64decode(certs_dict_b64["key_b64"])}
            return certs_data
        except (OSError, ValueError, json.JSONDecodeError, base64.binascii.Error) as e: self._log_message(f"Failed to read or parse bundle structure: {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"Invalid bundle format or structure:\n{e}")); return None
        except InvalidToken: self._log_message("Decryption failed: Invalid token (likely wrong password or corrupted bundle).", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", "Decryption failed.\nLikely incorrect password or corrupted bundle file.")); return None
        except Exception as e: self._log_message(f"Decryption failed: {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"Decryption failed: {e}")); return None
    def _export_bundle(self):
        if not self.certs_loaded_correctly: self.gui_queue.put(("show_error", "Please load and validate certificates before exporting.")); return
        password = simpledialog.askstring("Set Bundle Password", "Enter a password to encrypt the bundle:", show='*', parent=self.root)
        if not password: self._log_message("Bundle export cancelled."); return
        password_confirm = simpledialog.askstring("Confirm Password", "Confirm the password:", show='*', parent=self.root)
        if password != password_confirm: self.gui_queue.put(("show_error", "Passwords do not match.")); return
        bundle_path = filedialog.asksaveasfilename(title="Save Certificate Bundle", defaultextension=constants.BUNDLE_FILE_EXTENSION, filetypes=[(f"CryptLink Bundle (*{constants.BUNDLE_FILE_EXTENSION})", f"*{constants.BUNDLE_FILE_EXTENSION}"), ("All Files", "*.*")], initialdir=os.getcwd(), parent=self.root)
        if not bundle_path: self._log_message("Bundle export cancelled."); return
        encryption_result = self._encrypt_certs(password)
        if not encryption_result: return
        salt, encrypted_data = encryption_result
        try:
            with open(bundle_path, "wb") as f: f.write(salt); f.write(encrypted_data)
            self._log_message(f"Certificates successfully exported to bundle: {os.path.basename(bundle_path)}")
            self.gui_queue.put(("show_info", f"Bundle exported successfully to:\n{bundle_path}"))
            self.bundle_exported_this_session = True
            self._visual_feedback(self.export_bundle_button, "Export Bundle", "Exported!")
        except OSError as e: self._log_message(f"Error writing bundle file '{bundle_path}': {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"Failed to write bundle file:\n{e}"))
        except Exception as e: self._log_message(f"Unexpected error exporting bundle: {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"An unexpected error occurred during export:\n{e}"))
    def _import_bundle(self):
        if self.is_connected or self.is_connecting: self.gui_queue.put(("show_error", "Cannot import bundle while connected or connecting.")); return
        bundle_path = filedialog.askopenfilename(title="Import Certificate Bundle", filetypes=[(f"CryptLink Bundle (*{constants.BUNDLE_FILE_EXTENSION})", f"*{constants.BUNDLE_FILE_EXTENSION}"), ("All Files", "*.*")], initialdir=os.getcwd(), parent=self.root)
        if not bundle_path: self._log_message("Bundle import cancelled."); return
        password = simpledialog.askstring("Bundle Password", "Enter the password for the bundle:", show='*', parent=self.root)
        if not password: self._log_message("Bundle import cancelled."); return
        certs_info = self._decrypt_certs(bundle_path, password)
        if not certs_info: return
        self._cleanup_temp_files(); temp_files_created = {}
        try:
            # Use specific keys based on data type for storing temp paths
            temp_files_created["ca_data"] = self._write_temp_cert(certs_info["ca_data"], ".crt")
            temp_files_created["cert_data"] = self._write_temp_cert(certs_info["cert_data"], ".crt")
            temp_files_created["key_data"] = self._write_temp_cert(certs_info["key_data"], ".key")

            self.ca_cert_path.set(temp_files_created["ca_data"]); self.client_cert_path.set(temp_files_created["cert_data"]); self.client_key_path.set(temp_files_created["key_data"])
            self.ca_cert_display_name.set(certs_info.get("ca_name", "ca.crt")); self.client_cert_display_name.set(certs_info.get("cert_name", "client.crt")); self.client_key_display_name.set(certs_info.get("key_name", "client.key"))
            self._log_message(f"Certificates successfully imported from bundle: {os.path.basename(bundle_path)} (using temporary files)")
            self._visual_feedback(self.import_bundle_button, "Import Bundle", "Imported!")
            self.loaded_from_bundle = True; self.bundle_exported_this_session = True
            self.root.after(100, self._save_certs)
        except (OSError, KeyError, ValueError) as e:
            self._log_message(f"Error processing imported certificate data: {e}", constants.LOG_LEVEL_ERROR)
            self.gui_queue.put(("show_error", f"Failed to process imported certificates:\n{e}"))
            self._cleanup_temp_files(); self.ca_cert_path.set(""); self.client_cert_path.set(""); self.client_key_path.set("")
            self.ca_cert_display_name.set(""); self.client_cert_display_name.set(""); self.client_key_display_name.set(""); self.loaded_from_bundle = False
        except Exception as e:
             self._log_message(f"Unexpected error during bundle import processing: {e}", constants.LOG_LEVEL_ERROR)
             self.gui_queue.put(("show_error", f"An unexpected error occurred during import:\n{e}"))
             self._cleanup_temp_files(); self.ca_cert_path.set(""); self.client_cert_path.set(""); self.client_key_path.set("")
             self.ca_cert_display_name.set(""); self.client_cert_display_name.set(""); self.client_key_display_name.set(""); self.loaded_from_bundle = False

    def _write_temp_cert(self, data: bytes, suffix: str) -> str:
        """Writes data to a temporary file and returns the path."""
        # delete=False is crucial here so the file persists after the 'with' block
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False, mode='wb') as tf:
            tf.write(data)
            self.temp_cert_files.append(tf.name) # Track for cleanup
            return tf.name

    def _cleanup_temp_files(self):
        cleaned_count = 0
        for temp_path in list(self.temp_cert_files):
            try:
                if os.path.exists(temp_path): os.remove(temp_path); cleaned_count += 1
                if temp_path in self.temp_cert_files: self.temp_cert_files.remove(temp_path)
            except OSError as e: self._log_message(f"Error removing temporary file {temp_path}: {e}", constants.LOG_LEVEL_WARN)
            except Exception as e: self._log_message(f"Unexpected error cleaning temp file {temp_path}: {e}", constants.LOG_LEVEL_WARN)
        if cleaned_count > 0: self._log_message(f"Cleaned up {cleaned_count} temporary certificate files.")
    def _create_ssl_context(self, purpose):
         if not self.certs_loaded_correctly: self._log_message("Cannot create SSL context: Certs not loaded correctly.", constants.LOG_LEVEL_ERROR); return None
         ca_path = self.ca_cert_path.get(); cert_path = self.client_cert_path.get(); key_path = self.client_key_path.get()
         if not all(os.path.exists(p) for p in [ca_path, cert_path, key_path]):
             self._log_message("Cannot create SSL context: One or more cert/key files not found at specified paths.", constants.LOG_LEVEL_ERROR)
             self.gui_queue.put(("show_error", "One or more certificate/key files could not be found.\nPlease re-select or re-import."))
             self.certs_loaded_correctly = False; self.gui_queue.put(("status", "No Certs")); self._check_enable_load_certs(); return None
         if not all([ca_path, cert_path, key_path]): self._log_message("Cannot create SSL context: Missing cert paths.", constants.LOG_LEVEL_ERROR); return None
         try:
              context = ssl.SSLContext(purpose)
              if hasattr(context, "minimum_version"): context.minimum_version = ssl.TLSVersion.TLSv1_2
              else:
                  context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1
                  try:
                      context.options |= ssl.OP_NO_TLSv1_1
                  except AttributeError:
                      pass
                  print("Warning: Python < 3.6, TLSv1.2 minimum not guaranteed via modern API.")
                  self._log_message("Attempting to disable older protocols for Python < 3.6", constants.LOG_LEVEL_WARN)
              context.verify_mode = ssl.CERT_REQUIRED; context.check_hostname = False
              context.load_verify_locations(cafile=ca_path); context.load_cert_chain(certfile=cert_path, keyfile=key_path)
              self._log_message(f"SSLContext created for purpose: {purpose}", constants.LOG_LEVEL_DEBUG); return context
         except ssl.SSLError as e: self._log_message(f"Failed to create SSLContext: {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"SSL Error creating context: {e}\nCheck cert/key files again.")); self.certs_loaded_correctly = False; self.gui_queue.put(("status", "No Certs")); self._check_enable_load_certs(); return None
         except Exception as e: self._log_message(f"Unexpected error creating SSLContext: {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"Unexpected error creating SSL context: {e}")); self.certs_loaded_correctly = False; self.gui_queue.put(("status", "No Certs")); self._check_enable_load_certs(); return None

    # --- Connection Handling Methods ---
    # ... (Methods _start_server_if_needed through _handle_peer_transfer_cancel remain the same) ...
    def _start_server_if_needed(self):
        if self.certs_loaded_correctly and not self.is_server_running:
             if not self.is_connected and not self.is_connecting: self._start_server()
             else: self._log_message("Already connected/connecting as client, not starting server.", constants.LOG_LEVEL_INFO)
    def _start_server(self):
        if self.is_server_running: self._log_message("Server is already running.", constants.LOG_LEVEL_WARN); return
        if not self.certs_loaded_correctly: self._log_message("Cannot start server: Certificates not loaded correctly.", constants.LOG_LEVEL_ERROR); return
        self.is_server_running = True; self.stop_server_event.clear()
        self.server_thread = threading.Thread(target=self._server_listen_loop, daemon=True); self.server_thread.start()
    def _stop_server(self):
        if not self.is_server_running: return
        self._log_message("Stopping server thread..."); self.stop_server_event.set()
        server_sock = self.server_socket
        if server_sock:
            try: dummy_sock = socket.create_connection(('127.0.0.1', constants.DEFAULT_PORT), timeout=0.1); dummy_sock.close()
            except (socket.timeout, ConnectionRefusedError): pass
            except Exception as e: self._log_message(f"Minor error sending dummy connection to stop server: {e}", constants.LOG_LEVEL_DEBUG)
            try: server_sock.close(); self.server_socket = None
            except Exception as e: self._log_message(f"Error closing server socket: {e}", constants.LOG_LEVEL_WARN)
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=1.0)
            if self.server_thread.is_alive(): self._log_message("Server thread did not stop gracefully after join.", constants.LOG_LEVEL_WARN)
        self.is_server_running = False; self.server_thread = None
    def _server_listen_loop(self):
        self.server_socket = None; ssl_context = None
        try:
            ssl_context = self._create_ssl_context(ssl.PROTOCOL_TLS_SERVER)
            if not ssl_context: raise ValueError("Failed to create SSLContext for server.")
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM); self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('', constants.DEFAULT_PORT)); self.server_socket.listen(1); self.server_socket.settimeout(1.0)
            self._log_message(f"Server listening on port {constants.DEFAULT_PORT}")
            while not self.stop_server_event.is_set():
                if self.is_connected or self.is_connecting: time.sleep(0.5); continue
                try:
                    conn_unwrapped, addr = self.server_socket.accept(); self._log_message(f"Incoming connection attempt from {addr}")
                    if self.is_connected or self.is_connecting: self._log_message("Already connected/connecting, rejecting new connection.", constants.LOG_LEVEL_WARN); conn_unwrapped.close(); continue
                    handler_thread = threading.Thread(target=self._handle_client_connection, args=(conn_unwrapped, addr, ssl_context), daemon=True); handler_thread.start()
                except socket.timeout: continue
                except OSError as e:
                     if self.stop_server_event.is_set() or "Socket operation on non-socket" in str(e) or "Bad file descriptor" in str(e): self._log_message("Server socket closed, exiting listen loop.", constants.LOG_LEVEL_INFO)
                     else: self._log_message(f"Server socket OS error: {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"Server socket error: {e}. Try restarting.")); self.gui_queue.put(("status", "No Certs"))
                     break
                except Exception as e: self._log_message(f"Unexpected error in server accept loop: {e}", constants.LOG_LEVEL_ERROR); time.sleep(1)
        except ValueError as e: self._log_message(f"Server thread cannot start: {e}", constants.LOG_LEVEL_ERROR)
        except ssl.SSLError as e: self._log_message(f"Server thread failed due to SSL config: {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"Server SSL setup failed: {e}")); self.gui_queue.put(("status", "No Certs"))
        except OSError as e: self._log_message(f"Server thread failed to bind/listen: {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"Failed to start server on port {constants.DEFAULT_PORT}: {e}\nAnother application might be using the port.")); self.gui_queue.put(("status", "No Certs"))
        except Exception as e: self._log_message(f"Server thread failed unexpectedly: {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"Server failed: {e}")); self.gui_queue.put(("status", "No Certs"))
        finally:
            self.is_server_running = False;
            if self.is_connecting: self.is_connecting = False
            if self.server_socket:
                try:
                    self.server_socket.close()
                except Exception:
                    pass
                self.server_socket = None
            self._log_message("Server listening loop stopped.")
            if self.certs_loaded_correctly and not self.is_connected: self.gui_queue.put(("status", "Disconnected"))
            elif not self.certs_loaded_correctly: self.gui_queue.put(("status", "No Certs"))
    def _handle_client_connection(self, conn_unwrapped, addr, context):
        wrapped_socket = None; connection_confirmed = False; peer_host = "N/A"
        try:
            self.is_connecting = True; self.gui_queue.put(("status", "Connecting"))
            self._log_message(f"Attempting TLS handshake with {addr} (Server Role)...")
            wrapped_socket = context.wrap_socket(conn_unwrapped, server_side=True)
            self._log_message(f"TLS Handshake successful with {addr}. Awaiting confirmation...")
            peer_cert_bin = wrapped_socket.getpeercert(binary_form=True)
            if not peer_cert_bin: raise ConnectionError("Could not get peer certificate after handshake.")
            peer_cert = cryptography.x509.load_der_x509_certificate(peer_cert_bin, default_backend()); peer_fp_bytes = peer_cert.fingerprint(hashes.SHA256())
            peer_full_fp = peer_fp_bytes.hex().upper(); peer_fp_display = utils.format_fingerprint_display(peer_full_fp)
            peer_ip = addr[0]
            try:
                peer_host, _ = socket.getnameinfo(addr, 0)
            except socket.gaierror:
                peer_host = peer_ip
            self.gui_queue.put(("status", "Confirming Peer")); confirm_data = (peer_host, peer_ip, peer_fp_display, self.connection_confirmation_queue); self.gui_queue.put(("ask_connection_confirm", confirm_data))
            try:
                 accept = self.connection_confirmation_queue.get(timeout=constants.CONFIRMATION_TIMEOUT)
                 if accept: connection_confirmed = True; self._log_message(f"User accepted connection from {peer_host} ({peer_ip}).")
                 else: self._log_message(f"User rejected connection from {peer_host} ({peer_ip}).")
            except queue.Empty: self._log_message(f"Connection confirmation timed out for {peer_host} ({peer_ip}). Rejecting.")
            if not connection_confirmed: wrapped_socket.close(); conn_unwrapped.close(); self.is_connecting = False; self.gui_queue.put(("status", "Disconnected")); return
            self.client_socket = wrapped_socket; self.is_connected = True; self.is_connecting = False
            peer_info_dict = {"ip": peer_ip, "hostname": peer_host, "fingerprint": peer_full_fp}
            self.gui_queue.put(("peer_info", (peer_host, peer_info_dict))); self.gui_queue.put(("status", "Securely Connected"))
            self._log_message(f"Peer connection confirmed and established with {peer_host} ({peer_ip}).")
            self._send_command({"command": "PEER_INFO", "hostname": self.local_hostname, "ip": self.local_ip, "fingerprint": self.local_full_fingerprint})
            self._start_listen_thread(wrapped_socket); self._start_heartbeat()
        except ssl.SSLCertVerificationError as e: self._log_message(f"TLS Handshake failed (Cert Verify) with {addr}: {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"Connection failed: Peer certificate verification error.\nEnsure peer uses a certificate signed by the loaded CA."))
        except ssl.SSLError as e: self._log_message(f"TLS Handshake failed (SSL Error) with {addr}: {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"Connection failed: TLS handshake error with {addr}.\n{e}"))
        except socket.error as e: self._log_message(f"Socket error during handshake/setup with {addr}: {e}", constants.LOG_LEVEL_ERROR)
        except ConnectionError as e: self._log_message(f"Connection error during post-handshake setup with {addr}: {e}", constants.LOG_LEVEL_ERROR)
        except Exception as e: self._log_message(f"Error handling connection from {addr}: {e}", constants.LOG_LEVEL_ERROR)
        finally:
             if not self.is_connected:
                 if wrapped_socket:
                     try:
                         wrapped_socket.close()
                     except Exception:
                         pass
                 if conn_unwrapped:
                     try:
                         conn_unwrapped.close()
                     except Exception:
                         pass
                 if self.is_connecting:
                      self.is_connecting = False;
                      if self.connection_status.get() not in ["Disconnected", "No Certs", "Certs Loaded"]: self.gui_queue.put(("status", "Disconnected"))
    def _connect_peer(self):
        if not self.certs_loaded_correctly: self.gui_queue.put(("show_error", "Load and validate certificates before connecting.")); return
        if self.is_connected or self.is_connecting: self._log_message("Already connected or connecting.", constants.LOG_LEVEL_WARN); return
        peer_address = self.peer_ip_hostname.get().strip()
        if not peer_address: self.gui_queue.put(("show_error", "Please enter the Peer IP or Hostname.")); return
        self.gui_queue.put(("status", "Connecting")); self.is_connecting = True; self._stop_server()
        self.client_thread = threading.Thread(target=self._initiate_connection, args=(peer_address,), daemon=True); self.client_thread.start()
    def _initiate_connection(self, peer_address):
        unwrapped_socket = None; wrapped_socket = None; peer_ip = None; connection_succeeded = False; ssl_context = None
        try:
            ssl_context = self._create_ssl_context(ssl.PROTOCOL_TLS_CLIENT)
            if not ssl_context: raise ValueError("Failed to create SSLContext for client.")
            try: addr_info = socket.getaddrinfo(peer_address, constants.DEFAULT_PORT, socket.AF_INET, socket.SOCK_STREAM); peer_ip = addr_info[0][4][0]; self._log_message(f"Resolved '{peer_address}' to {peer_ip}")
            except socket.gaierror: self._log_message(f"Could not resolve hostname: {peer_address}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"Could not resolve hostname: {peer_address}")); return
            self._log_message(f"Attempting to connect to {peer_address} ({peer_ip}) on port {constants.DEFAULT_PORT}...")
            unwrapped_socket = socket.create_connection((peer_ip, constants.DEFAULT_PORT), timeout=constants.SOCKET_TIMEOUT)
            self._log_message("Socket connected, attempting TLS handshake (Client Role)...")
            hostname_for_tls = peer_address if not peer_ip == peer_address else None
            wrapped_socket = ssl_context.wrap_socket(unwrapped_socket, server_side=False, server_hostname=hostname_for_tls)
            self.client_socket = wrapped_socket; self.is_connected = True; self.is_connecting = False; connection_succeeded = True
            peer_cert_bin = wrapped_socket.getpeercert(binary_form=True)
            if not peer_cert_bin: raise ConnectionError("Could not get peer certificate after handshake.")
            peer_cert = cryptography.x509.load_der_x509_certificate(peer_cert_bin, default_backend()); peer_fp_bytes = peer_cert.fingerprint(hashes.SHA256())
            peer_full_fp = peer_fp_bytes.hex().upper(); peer_host = peer_address
            peer_info_dict = {"ip": peer_ip, "hostname": peer_host, "fingerprint": peer_full_fp}
            self.gui_queue.put(("peer_info", (peer_host, peer_info_dict))); self.gui_queue.put(("status", "Securely Connected"))
            self._log_message(f"TLS Handshake successful with {peer_host} ({peer_ip}).")
            self._send_command({"command": "PEER_INFO", "hostname": self.local_hostname, "ip": self.local_ip, "fingerprint": self.local_full_fingerprint})
            self._start_listen_thread(wrapped_socket); self._start_heartbeat()
        except socket.timeout: self._log_message(f"Connection timed out to {peer_address}.", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"Connection to {peer_address} timed out."))
        except socket.error as e: self._log_message(f"Socket error connecting to {peer_address}: {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"Could not connect to {peer_address}: {e}"))
        except ssl.SSLCertVerificationError as e: self._log_message(f"Certificate verification failed for {peer_address}: {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"Certificate verification failed for {peer_address}.\nEnsure peer uses a certificate signed by the loaded CA and that the CA cert is correct."))
        except ssl.SSLError as e: self._log_message(f"SSL Error connecting to {peer_address}: {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"SSL connection error with {peer_address}: {e}"))
        except ConnectionError as e: self._log_message(f"Connection error during connect/setup with {peer_address}: {e}", constants.LOG_LEVEL_ERROR)
        except ValueError as e: self._log_message(f"Client connection cannot start: {e}", constants.LOG_LEVEL_ERROR)
        except Exception as e: self._log_message(f"Unexpected error connecting to {peer_address}: {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"An unexpected error occurred: {e}"))
        finally:
            if not connection_succeeded:
                 if wrapped_socket:
                     try:
                         wrapped_socket.close()
                     except Exception:
                         pass
                 elif unwrapped_socket:
                     try:
                         unwrapped_socket.close()
                     except Exception:
                         pass
                 self.client_socket = None
                 if self.is_connecting:
                      self.is_connecting = False;
                      if self.connection_status.get() == "Connecting": self.gui_queue.put(("status", "Disconnected"))
                 self.root.after(100, self._start_server_if_needed)
    def _disconnect_peer(self, reason="User disconnected", notify_peer=True):
        current_status = self.connection_status.get()
        if current_status in ["Disconnected", "No Certs", "Certs Loaded"]: return
        if self.is_connecting:
             self._log_message(f"Disconnect requested during connection attempt. Cancelling. Reason: {reason}", constants.LOG_LEVEL_INFO)
             self.is_connecting = False; self.is_connected = False; sock_to_close = self.client_socket
             if sock_to_close:
                 try:
                     sock_to_close.close()
                 except Exception:
                     pass
             self.client_socket = None; self.gui_queue.put(("disconnect", f"Connection attempt cancelled: {reason}")); return
        self._log_message(f"Disconnecting from peer. Reason: {reason}")
        if self.heartbeat_timer: self.heartbeat_timer.cancel(); self.heartbeat_timer = None; self._log_message("Heartbeat timer cancelled.")
        if self.sender_status_clear_timer: self.sender_status_clear_timer.cancel(); self.sender_status_clear_timer = None; self._log_message("Sender status clear timer cancelled.")
        if self.is_transferring: self._log_message("Cancelling active transfer due to disconnect."); self._cancel_transfer(notify_peer=False, reason="Disconnecting")
        sock_to_close = self.client_socket; self.client_socket = None; self.is_connected = False; self.is_connecting = False
        if notify_peer and sock_to_close: threading.Thread(target=self._send_disconnect_notification, args=(sock_to_close, reason), daemon=True).start()
        else: self._close_socket_gracefully(sock_to_close)
        if self.listen_thread and self.listen_thread.is_alive():
             self._log_message("Waiting briefly for listen thread to exit..."); self.listen_thread.join(timeout=0.5)
             if self.listen_thread.is_alive(): self._log_message("Listen thread did not exit quickly.", constants.LOG_LEVEL_WARN)
        self.listen_thread = None; self.client_thread = None; self.gui_queue.put(("disconnect", reason))
    def _send_disconnect_notification(self, sock, reason):
         try:
              sock.settimeout(1.0); command_json = json.dumps({"command": "DISCONNECT", "reason": reason})
              message_length = len(command_json).to_bytes(4, byteorder='big'); sock.sendall(message_length + command_json.encode('utf-8'))
              self._log_message("Sent disconnect notification to peer."); time.sleep(0.1)
         except (OSError, ssl.SSLError, AttributeError) as e: self._log_message(f"Could not notify peer of disconnect (socket error): {e}", constants.LOG_LEVEL_WARN)
         except Exception as e: self._log_message(f"Unexpected error notifying peer of disconnect: {e}", constants.LOG_LEVEL_WARN)
         finally: self._close_socket_gracefully(sock)
    def _close_socket_gracefully(self, sock):
         if sock:
              try:
                  sock.shutdown(socket.SHUT_RDWR)
              except (OSError, ssl.SSLError):
                  pass
              except Exception as e:
                  self._log_message(f"Error during socket shutdown: {e}", constants.LOG_LEVEL_WARN)
              try:
                  sock.close()
                  self._log_message("Socket closed.")
              except Exception as e:
                  self._log_message(f"Error during socket close: {e}", constants.LOG_LEVEL_WARN)
    def _handle_disconnection_ui(self, reason):
        self._log_message(f"Handling UI disconnection. Reason: {reason}")
        self.is_connected = False; self.is_connecting = False; self.client_socket = None; self._reset_transfer_ui()
        with self.transfer_lock:
             if self.is_transferring: self._reset_transfer_state()
        self._clear_peer_info_display(); self._set_connection_status("Disconnected"); self.root.after(200, self._start_server_if_needed)
    def _send_command(self, command_dict):
        sock = self.client_socket
        if not self.is_connected or sock is None:
            if command_dict.get("command") != "DISCONNECT": self._log_message("Cannot send command: Not connected.", constants.LOG_LEVEL_ERROR)
            raise ConnectionError("Not connected")
        try:
            command_json = json.dumps(command_dict); encoded_command = command_json.encode('utf-8')
            message_length = len(encoded_command).to_bytes(4, byteorder='big')
            if sock != self.client_socket: raise ConnectionError("Socket changed during send operation.")
            sock.sendall(message_length + encoded_command)
            log_dict = command_dict.copy()
            if log_dict.get("command") == "FILE_CHUNK" and 'data' in log_dict:
                try:
                    data_len = len(bytes.fromhex(log_dict['data']))
                    log_dict['data'] = f"<bytes len={data_len}>"
                except Exception: # Catch potential errors during decoding/len
                    log_dict['data'] = "<invalid hex data>"
            elif log_dict.get("command") == "PEER_INFO" and 'fingerprint' in log_dict: log_dict['fingerprint'] = utils.format_fingerprint_display(log_dict['fingerprint'])
            elif 'data' in log_dict: log_dict['data'] = '<data>'
            self._log_message(f"Sent command: {log_dict}", constants.LOG_LEVEL_DEBUG)
        except (ssl.SSLError, socket.error, BrokenPipeError, ConnectionResetError, AttributeError, ValueError) as e: self._log_message(f"Network error sending command ({command_dict.get('command', 'N/A')}): {e}", constants.LOG_LEVEL_ERROR); self._disconnect_peer(reason=f"Network error sending: {e}", notify_peer=False); raise ConnectionError(f"Network error sending command: {e}") from e
        except Exception as e: self._log_message(f"Unexpected error sending command ({command_dict.get('command', 'N/A')}): {e}", constants.LOG_LEVEL_ERROR); self._disconnect_peer(reason=f"Unexpected send error: {e}", notify_peer=False); raise ConnectionError(f"Unexpected error sending command: {e}") from e
    def _receive_data(self, sock, length):
        if not sock: raise ConnectionError("Socket is invalid for receive.")
        data = b''; start_time = time.time()
        try:
            while len(data) < length:
                 if time.time() - start_time > (constants.HEARTBEAT_TIMEOUT * 1.1): raise socket.timeout("Timeout waiting for data chunk.")
                 try:
                     chunk = sock.recv(length - len(data))
                 except ssl.SSLWantReadError:
                     time.sleep(0.05)
                     continue
                 except socket.timeout:
                     continue # Let outer timeout handle it
                 if not chunk: raise ConnectionError("Connection closed by peer while receiving data.")
                 data += chunk
            return data
        except socket.timeout as e: self._log_message(f"Socket timeout receiving data ({e}).", constants.LOG_LEVEL_ERROR); raise ConnectionError("Socket timeout waiting for data.") from e
        except (ssl.SSLError, socket.error, BrokenPipeError, ConnectionResetError) as e: self._log_message(f"Network error receiving data: {e}", constants.LOG_LEVEL_ERROR); raise ConnectionError(f"Network error receiving data: {e}") from e
        except Exception as e: self._log_message(f"Unexpected error receiving data: {e}", constants.LOG_LEVEL_ERROR); raise ConnectionError(f"Unexpected error receiving data: {e}") from e
    def _receive_command(self, sock):
        if not sock or not self.is_connected: return None
        json_data = "N/A"
        try:
            raw_msglen = self._receive_data(sock, 4);
            if not raw_msglen: return None
            msglen = int.from_bytes(raw_msglen, byteorder='big')
            if not (0 < msglen <= constants.MAX_CMD_LEN): raise ConnectionError(f"Invalid command length received ({msglen}). Max allowed: {constants.MAX_CMD_LEN}")
            json_data = self._receive_data(sock, msglen).decode('utf-8'); command_dict = json.loads(json_data)
            log_dict = command_dict.copy()
            if log_dict.get("command") == "FILE_CHUNK" and 'data' in log_dict:
                try:
                    data_len = len(bytes.fromhex(log_dict['data']))
                    log_dict['data'] = f"<bytes len={data_len}>"
                except Exception: # Catch potential errors during decoding/len
                    log_dict['data'] = "<invalid hex data>"
            elif log_dict.get("command") == "PEER_INFO" and 'fingerprint' in log_dict: log_dict['fingerprint'] = utils.format_fingerprint_display(log_dict['fingerprint'])
            elif 'data' in log_dict: log_dict['data'] = '<data>'
            self._log_message(f"Received command type: {log_dict.get('command', 'UNKNOWN')}", constants.LOG_LEVEL_DEBUG); return command_dict
        except json.JSONDecodeError as e:
            self._log_message(f"Error decoding JSON command: {e}. Data received: '{json_data[:100]}...'", constants.LOG_LEVEL_ERROR)
            self._disconnect_peer(reason=f"Protocol error: Invalid JSON received", notify_peer=False)
            return None
        except ConnectionError as e:
            self._log_message(f"Connection error while receiving command: {e}", constants.LOG_LEVEL_INFO)
            if self.is_connected:
                self._disconnect_peer(reason=f"Receive error: {e}", notify_peer=False)
            return None
        except Exception as e:
            self._log_message(f"Unexpected error receiving/parsing command: {e}", constants.LOG_LEVEL_ERROR)
            if self.is_connected:
                self._disconnect_peer(reason=f"Receive error: {e}", notify_peer=False)
            return None
    def _start_listen_thread(self, sock):
        if self.listen_thread and self.listen_thread.is_alive(): self._log_message("Listen thread already running.", constants.LOG_LEVEL_WARN); return
        self.listen_thread = threading.Thread(target=self._listen_for_commands, args=(sock,), daemon=True); self.listen_thread.start()
    def _listen_for_commands(self, sock):
        self._log_message("Command listening thread started."); self.last_heartbeat_ack_time = time.time()
        while self.is_connected and self.client_socket == sock:
            try:
                 now = time.time()
                 if now - self.last_heartbeat_ack_time > constants.HEARTBEAT_TIMEOUT: self._log_message(f"Heartbeat timeout ({(now - self.last_heartbeat_ack_time):.1f}s > {constants.HEARTBEAT_TIMEOUT}s). Disconnecting.", constants.LOG_LEVEL_WARN); self._disconnect_peer(reason="Heartbeat timeout", notify_peer=False); break
                 command = self._receive_command(sock)
                 if command:
                     self.last_heartbeat_ack_time = time.time()
                     try:
                         self._process_command(command)
                     except Exception as proc_e:
                         self._log_message(f"Error processing command '{command.get('command')}': {proc_e}", constants.LOG_LEVEL_ERROR)
                 elif not self.is_connected:
                     self._log_message("Listen loop: Detected disconnection.", constants.LOG_LEVEL_INFO)
                     break
            except Exception as e:
                 self._log_message(f"Unexpected error in listen loop: {e}", constants.LOG_LEVEL_ERROR)
                 if self.is_connected:
                     self._disconnect_peer(reason=f"Listen loop error: {e}", notify_peer=False)
                 break
        self._log_message("Command listening thread stopped.")
    def _process_command(self, command):
        cmd_type = command.get("command")
        try:
            if cmd_type == "PEER_INFO": peer_host = command.get('hostname', command.get('ip', 'N/A')); self.gui_queue.put(("peer_info", (peer_host, command)))
            elif cmd_type == "SEND_FILE": self._handle_incoming_file_request(command)
            elif cmd_type == "ACCEPT_FILE": self._handle_file_accept(command)
            elif cmd_type == "REJECT_FILE": self._handle_file_reject(command)
            elif cmd_type == "FILE_CHUNK": self._handle_file_chunk(command)
            elif cmd_type == "TRANSFER_COMPLETE": self._handle_peer_transfer_complete(command)
            elif cmd_type == "CANCEL_TRANSFER": self._handle_peer_transfer_cancel(command)
            elif cmd_type == "DISCONNECT": self._log_message(f"Received disconnect command from peer. Reason: {command.get('reason', 'N/A')}"); disconnect_reason = f"Peer disconnected: {command.get('reason', 'N/A')}"; self.gui_queue.put(("disconnect", disconnect_reason))
            elif cmd_type == "HEARTBEAT": self._send_command({"command": "HEARTBEAT_ACK"})
            elif cmd_type == "HEARTBEAT_ACK": self._log_message("Received Heartbeat ACK.", constants.LOG_LEVEL_DEBUG)
            else: self._log_message(f"Received unknown command: {cmd_type}", constants.LOG_LEVEL_WARN)
        except Exception as e:
             self._log_message(f"Error processing command logic for '{cmd_type}': {e}", constants.LOG_LEVEL_ERROR)
             if cmd_type in ["FILE_CHUNK", "TRANSFER_COMPLETE", "ACCEPT_FILE"]:
                 self._log_message(f"Cancelling transfer due to processing error.", constants.LOG_LEVEL_ERROR)
                 self._cancel_transfer(notify_peer=True, reason=f"Receiver processing error: {e}")
    def _start_heartbeat(self):
        if not self.is_connected: self._log_message("Cannot start heartbeat: Not connected.", constants.LOG_LEVEL_DEBUG); return
        if self.heartbeat_timer: self.heartbeat_timer.cancel(); self.heartbeat_timer = None
        def beat():
            if self.is_connected and self.client_socket:
                 try:
                      self._log_message("Sending Heartbeat.", constants.LOG_LEVEL_DEBUG)
                      self._send_command({"command": "HEARTBEAT"})
                      if self.is_connected:
                          self.heartbeat_timer = threading.Timer(constants.HEARTBEAT_INTERVAL, beat)
                          self.heartbeat_timer.daemon = True
                          self.heartbeat_timer.start()
                      else:
                          self._log_message("Heartbeat stopping: Disconnected during beat.", constants.LOG_LEVEL_DEBUG)
                 except ConnectionError:
                      self._log_message("Heartbeat send failed (connection likely lost).", constants.LOG_LEVEL_WARN)
                 except Exception as e:
                      self._log_message(f"Error sending heartbeat: {e}", constants.LOG_LEVEL_ERROR)
            else:
                 self._log_message("Heartbeat stopping: No longer connected or socket invalid.", constants.LOG_LEVEL_DEBUG)
        self._log_message("Starting heartbeat timer."); self.heartbeat_timer = threading.Timer(constants.HEARTBEAT_INTERVAL, beat); self.heartbeat_timer.daemon = True; self.heartbeat_timer.start()
    def _choose_file(self):
        if not self.is_connected: self.gui_queue.put(("show_error", "Not connected to a peer.")); return
        if self.is_transferring: self.gui_queue.put(("show_error", "A file transfer is already in progress.")); return
        filename = filedialog.askopenfilename(title="Choose File to Send", parent=self.root, initialdir=os.getcwd(), filetypes=[("All files", "*.*")])
        if filename:
            try:
                with open(filename, "rb") as f:
                    f.read(1)
                self.file_to_send_path.set(filename)
                self.send_file_button.config(state='normal')
                self._log_message(f"Selected file for sending: {os.path.basename(filename)}")
            except OSError as e:
                self.gui_queue.put(("show_error", f"Cannot read selected file:\n{filename}\nError: {e}"))
                self.file_to_send_path.set("")
                self.send_file_button.config(state='disabled')
        else:
            self.file_to_send_path.set("")
            self.send_file_button.config(state='disabled')
    def _send_file(self):
        filepath = self.file_to_send_path.get()
        if not filepath or not os.path.exists(filepath): self.gui_queue.put(("show_error", "Invalid or non-existent file selected.")); self.file_to_send_path.set(""); self.send_file_button.config(state='disabled'); return
        try:
            with open(filepath, "rb") as f:
                f.read(1)
        except OSError as e:
            self.gui_queue.put(("show_error", f"Cannot read file just before sending:\n{filepath}\nError: {e}"))
            self.file_to_send_path.set("")
            self.send_file_button.config(state='disabled')
            return
        if not self.is_connected: self.gui_queue.put(("show_error", "Not connected to a peer.")); return
        with self.transfer_lock:
            if self.is_transferring: self.gui_queue.put(("show_error", "A file transfer is already in progress.")); return
            try:
                 filesize = os.path.getsize(filepath); filename = os.path.basename(filepath)
                 self.is_transferring = True; self.transfer_cancelled.clear(); self.current_transfer_id += 1
                 self.total_file_size = filesize; self.bytes_transferred = 0; self.transfer_start_time = time.time()
                 self._log_message(f"Requesting to send file: {filename} ({utils.format_bytes(filesize)}) ID: {self.current_transfer_id}")
                 self.gui_queue.put(("progress", (0, "Speed: Pending...", "ETA: Pending...")))
                 self.gui_queue.put(("sender_status", ("Requesting...", "blue", False)))
                 self._update_status_display()
                 self._send_command({"command": "SEND_FILE", "filename": filename, "filesize": filesize, "transfer_id": self.current_transfer_id})
                 self._log_message(f"SEND_FILE request sent for ID {self.current_transfer_id}.")
            except OSError as e:
                 self._log_message(f"Error accessing file {filepath}: {e}", constants.LOG_LEVEL_ERROR)
                 self.gui_queue.put(("show_error", f"Error accessing file: {e}"))
                 self._reset_transfer_state()
                 self.gui_queue.put(("transfer_cancelled_ui", True))
            except ConnectionError as e:
                 self._log_message(f"Connection error starting file transfer: {e}", constants.LOG_LEVEL_ERROR)
            except Exception as e:
                 self._log_message(f"Unexpected error starting file transfer: {e}", constants.LOG_LEVEL_ERROR)
                 self.gui_queue.put(("show_error", f"Unexpected error: {e}"))
                 self._reset_transfer_state()
                 self.gui_queue.put(("transfer_cancelled_ui", True))
    def _handle_file_accept(self, command):
        transfer_id = command.get("transfer_id")
        with self.transfer_lock:
             if not self.is_transferring or transfer_id != self.current_transfer_id or self.receiving_file_handle: self._log_message(f"Received ACCEPT_FILE for wrong/old/receiving transfer ID {transfer_id}. Ignoring.", constants.LOG_LEVEL_WARN); return
             filepath = self.file_to_send_path.get()
             if not filepath or not os.path.exists(filepath): self._log_message(f"Cannot start sending for {transfer_id}: File path '{filepath}' missing or invalid.", constants.LOG_LEVEL_ERROR); self._cancel_transfer(notify_peer=True, reason="Sender file disappeared before sending chunks"); return
             self._log_message(f"Peer accepted file transfer {transfer_id}. Starting send thread for {os.path.basename(filepath)}")
             self.gui_queue.put(("sender_status", ("Sending...", "blue", False)))
             send_thread = threading.Thread(target=self._send_file_chunks, args=(filepath, transfer_id), daemon=True); send_thread.start()
    def _send_file_chunks(self, filepath, transfer_id):
        sent_successfully = False; bytes_done = 0; total_size = 0
        try:
            total_size = os.path.getsize(filepath)
            with open(filepath, "rb") as f:
                 while True:
                     if self.transfer_cancelled.is_set() or not self.is_connected: self._log_message(f"Stopping file send thread for {transfer_id} (cancelled/disconnected).", constants.LOG_LEVEL_INFO); break
                     chunk = f.read(constants.BUFFER_SIZE)
                     if not chunk:
                         if bytes_done == total_size: sent_successfully = True
                         else: self._log_message(f"File send {transfer_id}: Read finished but size mismatch (read {bytes_done}, expected {total_size}).", constants.LOG_LEVEL_WARN)
                         break
                     if self.transfer_cancelled.is_set() or not self.is_connected: break
                     self._send_command({"command": "FILE_CHUNK", "transfer_id": transfer_id, "data": chunk.hex()})
                     bytes_done += len(chunk)
                     with self.transfer_lock:
                          if transfer_id != self.current_transfer_id or not self.is_transferring: self._log_message(f"Transfer ID changed during send ({transfer_id} vs {self.current_transfer_id}). Stopping send thread.", constants.LOG_LEVEL_WARN); sent_successfully = False; break
                          self.bytes_transferred = bytes_done; current_bytes_done = self.bytes_transferred; current_total_size = self.total_file_size; start_time = self.transfer_start_time
                     now = time.time(); elapsed = now - start_time
                     if elapsed > 0.5 or (current_bytes_done > 0 and current_bytes_done % (constants.BUFFER_SIZE * 10) == 0) or current_bytes_done == current_total_size:
                         progress = (current_bytes_done / current_total_size) * 100 if current_total_size > 0 else 100
                         speed_bps = current_bytes_done / elapsed if elapsed > 0 else 0; speed_str = f"Speed: {utils.format_bytes(int(speed_bps))}/s"
                         eta = ((current_total_size - current_bytes_done) / speed_bps) if speed_bps > 0 and current_bytes_done < current_total_size else 0
                         eta_str = f"ETA: {int(eta // 60)}m {int(eta % 60)}s" if eta > 0 else "ETA: ..."; self.gui_queue.put(("progress", (progress, speed_str, eta_str)))
            with self.transfer_lock: is_still_current_transfer = (transfer_id == self.current_transfer_id and self.is_transferring)
            if is_still_current_transfer and not self.transfer_cancelled.is_set() and self.is_connected:
                 if sent_successfully:
                     self._log_message(f"Finished sending file {transfer_id} ({utils.format_bytes(bytes_done)}). Notifying peer.")
                     self._send_command({"command": "TRANSFER_COMPLETE", "transfer_id": transfer_id, "filename": os.path.basename(filepath)})
                     self.gui_queue.put(("sender_status", ("Transfer Completed!", "green", True)))
                     self.gui_queue.put(("transfer_complete", True))
                 else:
                     self._log_message(f"File send {transfer_id} stopped unexpectedly or size mismatch. Sent {bytes_done}/{total_size} bytes.", constants.LOG_LEVEL_ERROR)
                     self.gui_queue.put(("transfer_cancelled_ui", True))
                     if self.is_connected:
                         self._cancel_transfer(notify_peer=True, reason="Sender error or size mismatch")
        except FileNotFoundError:
             self._log_message(f"File not found during send: {filepath}", constants.LOG_LEVEL_ERROR)
             self.gui_queue.put(("show_error", f"File disappeared during transfer: {filepath}"))
             with self.transfer_lock:
                  if transfer_id == self.current_transfer_id and self.is_transferring: self._cancel_transfer(notify_peer=True, reason="Sender file disappeared")
        except (ConnectionError, ssl.SSLError, socket.error) as e:
             self._log_message(f"Network error sending file chunk for {transfer_id}: {e}", constants.LOG_LEVEL_ERROR)
             with self.transfer_lock:
                  if transfer_id == self.current_transfer_id and self.is_transferring: self.gui_queue.put(("transfer_cancelled_ui", True))
        except Exception as e:
             self._log_message(f"Unexpected error sending file chunks for {transfer_id}: {e}", constants.LOG_LEVEL_ERROR)
             self.gui_queue.put(("show_error", f"Error during file send: {e}"))
             with self.transfer_lock:
                  if transfer_id == self.current_transfer_id and self.is_transferring: self._cancel_transfer(notify_peer=True, reason=f"Sender error: {e}")
    def _schedule_sender_status_clear(self):
        if self.sender_status_clear_timer: self.sender_status_clear_timer.cancel()
        def clear_status():
             if self.root.winfo_exists():
                  if not self.is_transferring: self.gui_queue.put(("sender_status", ("", "blue", False)))
             self.sender_status_clear_timer = None
        self.sender_status_clear_timer = threading.Timer(constants.SENDER_STATUS_DISPLAY_DURATION / 1000.0, clear_status); self.sender_status_clear_timer.daemon = True; self.sender_status_clear_timer.start()
    def _handle_file_reject(self, command):
        transfer_id = command.get("transfer_id")
        with self.transfer_lock:
            if not self.is_transferring or transfer_id != self.current_transfer_id or self.receiving_file_handle: self._log_message(f"Received REJECT_FILE for wrong/old/receiving transfer ID {transfer_id}. Ignoring.", constants.LOG_LEVEL_WARN); return
            reason = command.get("reason", "No reason given"); self._log_message(f"Peer rejected file transfer {transfer_id}. Reason: {reason}", constants.LOG_LEVEL_WARN)
            self.gui_queue.put(("show_info", f"Peer rejected the file transfer.\nReason: {reason}")); self._reset_transfer_state(); self.gui_queue.put(("transfer_cancelled_ui", True))
    def _handle_incoming_file_request(self, command):
        filename = command.get("filename", "unknown_file"); filesize = command.get("filesize", 0); transfer_id = command.get("transfer_id")
        if not transfer_id or not filename or filesize < 0: self._log_message(f"Received invalid file request (id:{transfer_id}, name:{filename}, size:{filesize}). Ignoring.", constants.LOG_LEVEL_ERROR); return
        with self.transfer_lock:
            if self.is_transferring:
                self._log_message("Received file request while another transfer is active. Rejecting.", constants.LOG_LEVEL_WARN)
                try:
                    self._send_command({"command": "REJECT_FILE", "transfer_id": transfer_id, "reason": "Another transfer is in progress."})
                except ConnectionError:
                    self._log_message("Connection error trying to reject busy transfer.", constants.LOG_LEVEL_WARN)
                except Exception as e:
                    self._log_message(f"Error sending busy rejection: {e}", constants.LOG_LEVEL_WARN)
                return
            self._pending_transfer_request = {"id": transfer_id, "filename": filename, "filesize": filesize}; self._log_message(f"Incoming file request: {filename} ({utils.format_bytes(filesize)}) ID: {transfer_id}")
            self.gui_queue.put(("ask_yes_no", (transfer_id, filename, utils.format_bytes(filesize))))
    def _respond_to_file_request(self, accept, transfer_id, filename):
        pending_request = getattr(self, '_pending_transfer_request', None)
        if not pending_request or pending_request["id"] != transfer_id: self._log_message(f"No matching pending request found for ID {transfer_id} response.", constants.LOG_LEVEL_WARN); return
        delattr(self, '_pending_transfer_request'); filesize = pending_request["filesize"]
        if accept:
            with self.transfer_lock:
                 if self.is_transferring:
                      self._log_message(f"Transfer started while user was deciding on {transfer_id}. Rejecting.", constants.LOG_LEVEL_WARN)
                      try:
                          self._send_command({"command": "REJECT_FILE", "transfer_id": transfer_id, "reason": "Another transfer started."})
                      except ConnectionError:
                          pass
                      except Exception as e:
                          self._log_message(f"Error sending late rejection: {e}", constants.LOG_LEVEL_WARN)
                      return
                 downloads_dir = utils.get_downloads_folder()
                 safe_filename = "".join(c for c in filename if c.isalnum() or c in (' ', '.', '_', '-')).strip()
                 if not safe_filename: safe_filename = f"downloaded_file_{transfer_id}"
                 base, ext = os.path.splitext(safe_filename); counter = 1; temp_receiving_path = os.path.join(downloads_dir, f"{base}{ext}")
                 while os.path.exists(temp_receiving_path): temp_receiving_path = os.path.join(downloads_dir, f"{base}_{counter}{ext}"); counter += 1
                 self.receiving_file_path = temp_receiving_path
                 try:
                      self.receiving_file_handle = open(self.receiving_file_path, "wb")
                      self.is_transferring = True; self.transfer_cancelled.clear(); self.current_transfer_id = transfer_id
                      self.total_file_size = filesize; self.bytes_transferred = 0; self.transfer_start_time = time.time()
                      self._log_message(f"User accepted transfer {transfer_id}. Saving to {os.path.basename(self.receiving_file_path)}")
                      self.gui_queue.put(("progress", (0, "Speed: Starting...", "ETA: Starting..."))); self._update_status_display()
                      self._send_command({"command": "ACCEPT_FILE", "transfer_id": transfer_id})
                 except OSError as e:
                      self._log_message(f"Error opening file for receiving {self.receiving_file_path}: {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"Cannot write to target folder: {e}"))
                      if self.receiving_file_handle: self.receiving_file_handle.close(); self.receiving_file_handle = None
                      self._reset_transfer_state(); self.gui_queue.put(("transfer_cancelled_ui", False))
                      try:
                          self._send_command({"command": "REJECT_FILE", "transfer_id": transfer_id, "reason": f"Receiver cannot write file: {e}"})
                      except ConnectionError:
                          pass
                      except Exception as e_rej:
                          self._log_message(f"Error sending reject after write fail: {e_rej}", constants.LOG_LEVEL_WARN)
                 except ConnectionError as e:
                      self._log_message(f"Connection error accepting file transfer: {e}", constants.LOG_LEVEL_ERROR)
                      if self.receiving_file_handle: self.receiving_file_handle.close(); self.receiving_file_handle = None
                 except Exception as e:
                      self._log_message(f"Unexpected error accepting transfer {transfer_id}: {e}", constants.LOG_LEVEL_ERROR)
                      if self.receiving_file_handle: self.receiving_file_handle.close(); self.receiving_file_handle = None
                      self._reset_transfer_state(); self.gui_queue.put(("transfer_cancelled_ui", False))
                      try:
                          self._send_command({"command": "REJECT_FILE", "transfer_id": transfer_id, "reason": f"Receiver error: {e}"})
                      except ConnectionError:
                          pass
                      except Exception as e_rej:
                          self._log_message(f"Error sending reject after setup fail: {e_rej}", constants.LOG_LEVEL_WARN)
        else:
            self._log_message(f"User rejected file transfer {transfer_id}.")
            try: self._send_command({"command": "REJECT_FILE", "transfer_id": transfer_id, "reason": "User rejected."})
            except ConnectionError: self._log_message("Connection error sending REJECT_FILE.", constants.LOG_LEVEL_WARN)
            except Exception as e: self._log_message(f"Error sending reject file cmd: {e}", constants.LOG_LEVEL_WARN)
    def _handle_file_chunk(self, command):
        transfer_id = command.get("transfer_id"); hex_data = command.get("data"); cancel_needed = False; cancel_reason = ""
        if not hex_data: self._log_message("Received empty file chunk data.", constants.LOG_LEVEL_WARN); return
        try: chunk_data = bytes.fromhex(hex_data); chunk_len = len(chunk_data)
        except (TypeError, ValueError) as e: self._log_message(f"Error decoding hex data for chunk {transfer_id}: {e}. Cancelling.", constants.LOG_LEVEL_ERROR); self._cancel_transfer(notify_peer=True, reason="Receiver received corrupt data"); return
        with self.transfer_lock:
            if not self.is_transferring or transfer_id != self.current_transfer_id or not self.receiving_file_handle:
                 if not self.transfer_cancelled.is_set(): self._log_message(f"Received unexpected/outdated FILE_CHUNK for ID {transfer_id}. Ignoring.", constants.LOG_LEVEL_WARN)
                 return
            try:
                 if (self.bytes_transferred + chunk_len) > self.total_file_size and self.total_file_size > 0:
                      self._log_message(f"Received chunk for {transfer_id} exceeds expected file size ({self.bytes_transferred + chunk_len} > {self.total_file_size}). Truncating and cancelling.", constants.LOG_LEVEL_WARN)
                      bytes_to_write = self.total_file_size - self.bytes_transferred
                      if bytes_to_write > 0: self.receiving_file_handle.write(chunk_data[:bytes_to_write]); self.bytes_transferred += bytes_to_write
                      cancel_needed = True; cancel_reason = "Received excess data from peer"
                 else: self.receiving_file_handle.write(chunk_data); self.bytes_transferred += chunk_len
                 bytes_done = self.bytes_transferred; total_size = self.total_file_size; start_time = self.transfer_start_time
                 now = time.time(); elapsed = now - start_time
                 if elapsed > 0.5 or (bytes_done > 0 and bytes_done % (constants.BUFFER_SIZE * 10) == 0) or (total_size > 0 and bytes_done == total_size):
                     progress = (bytes_done / total_size) * 100 if total_size > 0 else 100
                     speed_bps = bytes_done / elapsed if elapsed > 0 else 0; speed_str = f"Speed: {utils.format_bytes(int(speed_bps))}/s"
                     eta = ((total_size - bytes_done) / speed_bps) if speed_bps > 0 and bytes_done < total_size else 0
                     eta_str = f"ETA: {int(eta // 60)}m {int(eta % 60)}s" if eta > 0 and total_size > 0 else "ETA: ..."
                     self.gui_queue.put(("progress", (progress, speed_str, eta_str)))
            except OSError as e: self._log_message(f"Error writing received file chunk for {transfer_id}: {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"Error writing received file: {e}")); cancel_needed = True; cancel_reason = f"Receiver write error: {e}"
            except Exception as e: self._log_message(f"Unexpected error handling file chunk for {transfer_id}: {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"Unexpected error receiving file: {e}")); cancel_needed = True; cancel_reason = f"Receiver unexpected error: {e}"
        if cancel_needed: self._cancel_transfer(notify_peer=True, reason=cancel_reason)
    def _handle_peer_transfer_complete(self, command):
        transfer_id = command.get("transfer_id"); filename = command.get("filename", "unknown_file"); success = False; display_name = "N/A"; final_path = "N/A"
        with self.transfer_lock:
            if not self.is_transferring or transfer_id != self.current_transfer_id or not self.receiving_file_handle:
                 if not self.transfer_cancelled.is_set(): self._log_message(f"Received unexpected/outdated TRANSFER_COMPLETE for ID {transfer_id}. Ignoring.", constants.LOG_LEVEL_WARN)
                 return
            self._log_message(f"Peer completed sending file transfer {transfer_id} ({filename}). Verifying size."); final_path = self.receiving_file_path
            try: self.receiving_file_handle.close(); self.receiving_file_handle = None
            except Exception as e: self._log_message(f"Error closing received file handle: {e}", constants.LOG_LEVEL_WARN); self.gui_queue.put(("show_error", f"Error closing file '{filename}': {e}")); self.gui_queue.put(("transfer_cancelled_ui", False)); self._reset_transfer_state(); self._cleanup_partial_file(final_path); return
            final_size = self.bytes_transferred; expected_size = self.total_file_size
            if (expected_size == 0 and final_size == 0) or (expected_size > 0 and final_size == expected_size): success = True
            if success: self._log_message(f"File '{os.path.basename(final_path)}' received successfully ({utils.format_bytes(final_size)})."); display_name = os.path.basename(final_path); self.received_files[display_name] = final_path
            else: self._log_message(f"File transfer {transfer_id} size mismatch! Expected {expected_size}, got {final_size}.", constants.LOG_LEVEL_ERROR)
            self._reset_transfer_state()
        if success: self.gui_queue.put(("show_info", f"File '{display_name}' received successfully.")); self.gui_queue.put(("add_received_file", (display_name, final_path))); self.gui_queue.put(("transfer_complete", False))
        else: self.gui_queue.put(("show_error", f"File transfer failed: Size mismatch for '{filename}'. Expected {utils.format_bytes(expected_size)}, received {utils.format_bytes(final_size)}.")); self._cleanup_partial_file(final_path); self.gui_queue.put(("transfer_cancelled_ui", False))
    def _cancel_transfer(self, notify_peer=True, reason="User cancelled"):
        current_transfer_id = -1; is_sender = False; partial_file_path = None
        with self.transfer_lock:
            if not self.is_transferring: return
            if self.transfer_cancelled.is_set(): return
            self._log_message(f"Initiating cancel for transfer ID {self.current_transfer_id}. Reason: {reason}"); self.transfer_cancelled.set()
            current_transfer_id = self.current_transfer_id; is_sender = self.receiving_file_handle is None
            if self.sender_status_clear_timer: self.sender_status_clear_timer.cancel(); self.sender_status_clear_timer = None; self._log_message("Sender status clear timer cancelled.")
            if self.receiving_file_handle:
                try:
                    self.receiving_file_handle.close()
                except Exception as e:
                    self._log_message(f"Error closing receiving file handle during cancel: {e}", constants.LOG_LEVEL_WARN)
            partial_file_path = self.receiving_file_path if not is_sender else None; self._reset_transfer_state()
        if partial_file_path: self._cleanup_partial_file(partial_file_path)
        if notify_peer and self.is_connected and current_transfer_id != -1: threading.Thread(target=self._send_cancel_notification, args=(current_transfer_id,), daemon=True).start()
        self.gui_queue.put(("transfer_cancelled_ui", is_sender))
    def _send_cancel_notification(self, transfer_id):
         if self.is_connected:
              try: self._send_command({"command": "CANCEL_TRANSFER", "transfer_id": transfer_id}); self._log_message(f"Sent cancellation notice to peer for transfer {transfer_id}.")
              except ConnectionError: self._log_message("Could not notify peer of cancellation (connection lost).", constants.LOG_LEVEL_WARN)
              except Exception as e: self._log_message(f"Error sending cancellation notice: {e}", constants.LOG_LEVEL_ERROR)
    def _handle_peer_transfer_cancel(self, command):
        transfer_id = command.get("transfer_id"); partial_file_path = None; is_sender = False
        with self.transfer_lock:
            if not self.is_transferring or transfer_id != self.current_transfer_id:
                 if not self.transfer_cancelled.is_set(): self._log_message(f"Received CANCEL_TRANSFER for wrong/old transfer ID {transfer_id}. Ignoring.", constants.LOG_LEVEL_WARN)
                 return
            if self.transfer_cancelled.is_set(): return
            self._log_message(f"Peer cancelled file transfer {transfer_id}.", constants.LOG_LEVEL_WARN); self.transfer_cancelled.set()
            if self.sender_status_clear_timer: self.sender_status_clear_timer.cancel(); self.sender_status_clear_timer = None; self._log_message("Sender status clear timer cancelled due to peer cancellation.")
            is_sender = self.receiving_file_handle is None; partial_file_path = self.receiving_file_path if not is_sender else None
            if self.receiving_file_handle:
                try:
                    self.receiving_file_handle.close()
                except Exception:
                    pass
            self._reset_transfer_state()
        if partial_file_path: self._cleanup_partial_file(partial_file_path)
        self.gui_queue.put(("transfer_cancelled_ui", is_sender)); self.gui_queue.put(("show_info", "Peer cancelled the file transfer."))
    def _cleanup_partial_file(self, file_path):
         if file_path and os.path.exists(file_path):
              try: os.remove(file_path); self._log_message(f"Removed partially received file: {os.path.basename(file_path)}")
              except OSError as e: self._log_message(f"Error removing partially received file {os.path.basename(file_path)}: {e}", constants.LOG_LEVEL_ERROR)
    def _reset_transfer_state(self):
        self.is_transferring = False; self.file_to_send_path.set("")
        self.bytes_transferred = 0; self.total_file_size = 0; self.transfer_start_time = 0
        if self.receiving_file_handle:
            try:
                self.receiving_file_handle.close()
            except Exception:
                pass # Ignore errors on close during reset
        self.receiving_file_handle = None; self.receiving_file_path = None; self.sender_transfer_status.set("")
        if self.sender_status_clear_timer: self.sender_status_clear_timer.cancel(); self.sender_status_clear_timer = None
    def _reset_transfer_ui(self):
        self.gui_queue.put(("progress", (0, "Speed: N/A", "ETA: N/A"))); self.gui_queue.put(("sender_status", ("", "blue", False)))
    def _update_progress_display(self, progress, speed, eta):
        if not self.root.winfo_exists(): return
        try: safe_progress = max(0.0, min(100.0, progress)); self.transfer_progress.set(safe_progress); self.transfer_speed.set(speed); self.transfer_eta.set(eta)
        except tk.TclError as e: print(f"Error updating progress display (window likely closing): {e}")
    def _update_sender_status(self, status_text, color="blue", temporary=False):
         if not self.root.winfo_exists(): return
         try:
              if self.sender_status_clear_timer: self.sender_status_clear_timer.cancel(); self.sender_status_clear_timer = None
              self.sender_status_label.config(foreground=color); self.sender_transfer_status.set(status_text)
              if temporary and status_text: self._schedule_sender_status_clear()
         except tk.TclError as e: print(f"Error updating sender status (window likely closing): {e}")
    def _handle_transfer_complete_ui(self, is_sender):
        self._log_message(f"Transfer complete UI update (Sender={is_sender}).")
        with self.transfer_lock:
             if self.is_transferring: self._reset_transfer_state()
        self._reset_transfer_ui(); self._update_status_display()
    def _handle_transfer_cancelled_ui(self, is_sender):
        self._log_message(f"Transfer cancelled UI update (Sender={is_sender}).")
        self._reset_transfer_ui(); self._update_status_display()
    def _add_received_file_display(self, display_name, full_path):
        if not self.root.winfo_exists(): return
        try:
             if display_name not in self.received_listbox.get(0, tk.END): self.received_listbox.insert(tk.END, display_name)
             self.received_files[display_name] = full_path
        except tk.TclError as e: print(f"Error adding received file to listbox (window likely closing): {e}")
    def _open_received_file(self, event=None):
        try:
             selected_indices = self.received_listbox.curselection()
             if not selected_indices: return
             selected_display_name = self.received_listbox.get(selected_indices[0])
             file_path = self.received_files.get(selected_display_name)
             if file_path: self._log_message(f"Attempting to open received file: {file_path}"); utils.open_file_in_default_app(file_path)
             else: self._log_message(f"Cannot open received file: Path not found for '{selected_display_name}'.", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"Internal error: Path not found for '{selected_display_name}'."))
        except tk.TclError as e: print(f"Error opening received file (window likely closing): {e}")

    # --- Logging GUI ---
    # Removed _toggle_logs method

    def _copy_logs(self):
        if not self.root.winfo_exists(): return
        try:
            log_content = self.log_text.get("1.0", tk.END).strip()
            if log_content:
                self.root.clipboard_clear()
                self.root.clipboard_append(log_content)
                self._log_message("Logs copied to clipboard.")
                self._visual_feedback(self.copy_log_button, "Copy", "Copied!")
            else:
                self._log_message("No logs to copy.", constants.LOG_LEVEL_INFO)
        except Exception as e: self._log_message(f"Error copying logs: {e}", constants.LOG_LEVEL_ERROR); self.gui_queue.put(("show_error", f"Could not copy logs: {e}"))
    def _clear_logs(self):
        if not self.root.winfo_exists(): return
        try:
            self.log_text.config(state='normal')
            self.log_text.delete("1.0", tk.END)
            self.log_text.config(state='disabled')
            self._log_message("Logs cleared.")
            self._visual_feedback(self.clear_log_button, "Clear", "Cleared!")
        except tk.TclError as e: print(f"Error clearing logs (window likely closing): {e}")

    # --- Admin Tools ---
    def _open_admin_tools(self):
        # --- This function is no longer used, logic moved to _create_widgets and _show_admin_tools_view ---
        if self.admin_tools_window and self.admin_tools_window.winfo_exists():
            self.admin_tools_window.lift()
            return

        self.admin_tools_window = tk.Toplevel(self.root)
        self.admin_tools_window.title("Admin Tools")
        self.admin_tools_window.geometry("500x400")
        self.admin_tools_window.resizable(False, True)
        self.admin_tools_window.transient(self.root) # Keep it on top of the main window

        # --- Admin Window Widgets ---
        admin_frame = ttk.Frame(self.admin_tools_window, padding="10")
        admin_frame.pack(fill=tk.BOTH, expand=True)
        admin_frame.columnconfigure(0, weight=1) # Allow content to expand horizontally
        # admin_frame.rowconfigure(2, weight=1) # No longer needed for log area

        # CA Section
        ca_frame = ttk.LabelFrame(admin_frame, text="Certificate Authority (CA)", padding="10")
        ca_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        ca_frame.columnconfigure(1, weight=1)

        self.admin_ca_status_var = tk.StringVar(value="CA Status: Unknown")
        ttk.Label(ca_frame, textvariable=self.admin_ca_status_var).grid(row=0, column=0, columnspan=2, sticky=tk.W, padx=5, pady=2)
        self.admin_load_ca_button = ttk.Button(ca_frame, text="Load/Create CA", command=self._admin_load_create_ca)
        self.admin_load_ca_button.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)

        ca_button_frame = ttk.Frame(ca_frame)
        ca_button_frame.grid(row=1, column=1, sticky=tk.E, padx=5, pady=5)
        self.admin_export_ca_button = ttk.Button(ca_button_frame, text="Export CA...", command=self._admin_export_ca, state='disabled')
        self.admin_export_ca_button.pack(side=tk.LEFT, padx=(0, 5))
        self.admin_clear_ca_button = ttk.Button(ca_button_frame, text="Clear CA", command=self._admin_clear_ca, state='disabled')
        self.admin_clear_ca_button.pack(side=tk.LEFT)

        # Client Bundle Section
        client_frame = ttk.LabelFrame(admin_frame, text="Generate Client Bundle (.clb)", padding="10")
        client_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        client_frame.columnconfigure(1, weight=1)

        ttk.Label(client_frame, text="Client Name (CN):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.admin_client_cn_var = tk.StringVar()
        self.admin_client_cn_entry = ttk.Entry(client_frame, textvariable=self.admin_client_cn_var, width=30)
        self.admin_client_cn_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=2)

        self.admin_generate_bundle_button = ttk.Button(client_frame, text="Generate Bundle", command=self._admin_generate_bundle, state='disabled')
        self.admin_generate_bundle_button.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        # --- Removed Admin Log Section ---

        # Close Button
        # Adjusted row index from 3 to 2 since log section is removed
        close_button = ttk.Button(admin_frame, text="Close", command=self.admin_tools_window.destroy)
        close_button.grid(row=3, column=0, sticky=tk.E, pady=(10, 0), padx=5)

        # Initial CA check
        self._admin_check_ca_status()

    def _admin_log(self, message):
        self._log_message(f"[Admin] {message}", constants.LOG_LEVEL_INFO) # Also log to main window

    def _admin_check_ca_status(self):
        """Checks keyring for CA and updates Admin Tools UI elements."""
        self.admin_ca_cert, self.admin_ca_key, msg = utils.get_ca_from_keyring()
        if self.admin_ca_cert and self.admin_ca_key:
            # Update widgets directly, no need to check if window exists
            self.admin_ca_status_var.set("CA Status: Loaded from Keyring")
            self.admin_generate_bundle_button.config(state='normal')
            self.admin_export_ca_button.config(state='normal')
            self.admin_clear_ca_button.config(state='normal')
            self._log_message("[Admin] CA loaded successfully from keyring.", constants.LOG_LEVEL_INFO)
        else:
            self.admin_ca_status_var.set("CA Status: Not Found")
            # Check if admin_tools_frame exists before configuring buttons
            if hasattr(self, 'admin_tools_frame') and self.admin_tools_frame.winfo_exists():
                self.admin_generate_bundle_button.config(state='disabled')
                self.admin_export_ca_button.config(state='disabled')
                self.admin_clear_ca_button.config(state='disabled')
            self._log_message(f"[Admin] CA not found in keyring: {msg}", constants.LOG_LEVEL_INFO)

    def _admin_load_create_ca(self):
        self._admin_check_ca_status() # Re-check first
        if not self.admin_ca_cert:
            if messagebox.askyesno("Create CA?", "No CA found in the system keyring.\n\nDo you want to create a new CA certificate and key and store them securely?", parent=self.root): # Use self.root as parent
                self._admin_log("Attempting to create and store new CA...")
                # Prompt for CA details
                ca_details = self._prompt_ca_details()
                if not ca_details:
                    self._log_message("[Admin] CA creation cancelled by user (details dialog).", constants.LOG_LEVEL_INFO)
                    return
                success, msg = utils.create_and_store_ca(ca_details)
                if success:
                    self._log_message(f"[Admin] CA creation successful: {msg}", constants.LOG_LEVEL_INFO)
                    messagebox.showinfo("CA Created", "New CA certificate and key created and stored in your system keyring.", parent=self.root) # Use self.root as parent
                    self._admin_check_ca_status() # Update status after creation
                else:
                    self._log_message(f"[Admin] CA creation failed: {msg}", constants.LOG_LEVEL_ERROR)
                    messagebox.showerror("CA Creation Failed", f"Could not create or store the CA:\n{msg}", parent=self.root) # Use self.root as parent
            else:
                self._log_message("[Admin] User chose not to create a new CA.", constants.LOG_LEVEL_INFO)
        else:
            messagebox.showinfo("CA Loaded", "CA is already loaded from the keyring.", parent=self.root) # Use self.root as parent

    def _prompt_ca_details(self):
        """Opens a dialog to collect CA subject details."""
        # Use self.root as parent for the dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Enter CA Details")
        dialog.transient(self.root) # Make transient to root
        dialog.grab_set()
        dialog.resizable(False, False)

        details = {}
        frame = ttk.Frame(dialog, padding="10")
        frame.pack(expand=True, fill="both")

        fields = {
            "CN": "Common Name:",
            "O": "Organization:",
            "OU": "Organizational Unit:",
            "L": "Locality (City):",
            "ST": "State/Province:",
            "C": "Country Code (2 letters):"
        }
        entries = {}

        for i, (key, label) in enumerate(fields.items()):
            ttk.Label(frame, text=label).grid(row=i, column=0, sticky=tk.W, padx=5, pady=3)
            var = tk.StringVar()
            entry = ttk.Entry(frame, textvariable=var, width=40)
            entry.grid(row=i, column=1, sticky=(tk.W, tk.E), padx=5, pady=3)
            entries[key] = var
            if key == "CN": var.set("CryptLink Root CA") # Default CN
            if key == "C": entry.config(width=5) # Shorter entry for country code

        button_frame = ttk.Frame(frame)
        button_frame.grid(row=len(fields), column=0, columnspan=2, pady=10)

        def on_ok():
            # Basic validation (e.g., CN and C are required)
            if not entries["CN"].get():
                messagebox.showerror("Missing Field", "Common Name (CN) is required.", parent=dialog)
                return
            if not entries["C"].get() or len(entries["C"].get()) != 2:
                messagebox.showerror("Invalid Field", "Country Code (C) must be 2 letters.", parent=dialog)
                return

            for key, var in entries.items():
                details[key] = var.get().strip()
            dialog.destroy()

        def on_cancel():
            details.clear() # Indicate cancellation
            dialog.destroy()

        ok_button = ttk.Button(button_frame, text="OK", command=on_ok)
        ok_button.pack(side=tk.LEFT, padx=5)
        cancel_button = ttk.Button(button_frame, text="Cancel", command=on_cancel)
        cancel_button.pack(side=tk.LEFT, padx=5)

        dialog.protocol("WM_DELETE_WINDOW", on_cancel) # Handle window close
        dialog.wait_window() # Wait for the dialog to close

        # Return the collected details dictionary, or empty if cancelled
        return details if details else None



    def _admin_generate_bundle(self):
        if not self.admin_ca_cert or not self.admin_ca_key:
            messagebox.showerror("CA Not Loaded", "Cannot generate bundle: CA is not loaded. Use 'Load/Create CA' first.", parent=self.root) # Use self.root as parent
            self._log_message("[Admin] Bundle generation failed: CA not loaded.", constants.LOG_LEVEL_ERROR)
            return

        client_cn = self.admin_client_cn_var.get().strip()
        if not client_cn:
            messagebox.showerror("Client Name Required", "Please enter a Client Name (Common Name) for the certificate.", parent=self.root) # Use self.root as parent
            self._log_message("[Admin] Bundle generation failed: Client Name missing.", constants.LOG_LEVEL_ERROR)
            return

        # --- Removed client details dialog ---
        # client_details = self._prompt_client_details()
        # if not client_details:
        #     self._log_message("[Admin] Client details entry cancelled.", constants.LOG_LEVEL_INFO)
        #     return

        self._log_message(f"[Admin] Generating client certificate and key for CN: {client_cn}...", constants.LOG_LEVEL_INFO)
        client_cert_pem, client_key_pem, msg = utils.create_client_cert_and_key(self.admin_ca_cert, self.admin_ca_key, client_cn) # Pass only CN

        if not client_cert_pem or not client_key_pem:
            self._log_message(f"[Admin] Client cert/key generation failed: {msg}", constants.LOG_LEVEL_ERROR) # Use _log_message
            messagebox.showerror("Generation Failed", f"Could not generate client certificate/key:\n{msg}", parent=self.root) # Use self.root as parent
            return
        self._log_message("[Admin] Client certificate and key generated successfully.", constants.LOG_LEVEL_INFO) # Use _log_message

        password = simpledialog.askstring("Set Bundle Password", "Enter a password to encrypt the bundle:", show='*', parent=self.root) # Use self.root as parent
        if not password: self._log_message("[Admin] Bundle creation cancelled by user (no password).", constants.LOG_LEVEL_INFO); return
        password_confirm = simpledialog.askstring("Confirm Password", "Confirm the password:", show='*', parent=self.root) # Use self.root as parent
        if password != password_confirm: messagebox.showerror("Password Mismatch", "Passwords do not match.", parent=self.root); self._log_message("[Admin] Bundle creation failed: Password mismatch.", constants.LOG_LEVEL_ERROR); return

        bundle_path = filedialog.asksaveasfilename(title="Save Client Bundle", defaultextension=constants.BUNDLE_FILE_EXTENSION, filetypes=[(f"CryptLink Bundle (*{constants.BUNDLE_FILE_EXTENSION})", f"*{constants.BUNDLE_FILE_EXTENSION}"), ("All Files", "*.*")], initialdir=utils.get_downloads_folder(), parent=self.root) # Use self.root as parent
        if not bundle_path: self._log_message("[Admin] Bundle creation cancelled by user (no save path).", constants.LOG_LEVEL_INFO); return

        self._log_message(f"[Admin] Creating encrypted bundle at: {bundle_path}...", constants.LOG_LEVEL_INFO)
        # Pass the CA cert object directly, not its PEM string
        success, msg = utils.create_encrypted_bundle(bundle_path, password, self.admin_ca_cert, client_cert_pem, client_key_pem, client_cn)

        if success:
            self._log_message(f"[Admin] Bundle created successfully: {msg}", constants.LOG_LEVEL_INFO)
            messagebox.showinfo("Bundle Created", f"Client bundle for '{client_cn}' created successfully:\n{bundle_path}", parent=self.root) # Use self.root as parent
        else:
            self._log_message(f"[Admin] Bundle creation failed: {msg}", constants.LOG_LEVEL_ERROR) # Use _log_message
            messagebox.showerror("Bundle Creation Failed", f"Could not create the encrypted bundle:\n{msg}", parent=self.root) # Use self.root as parent

    def _prompt_client_details(self):
        """Opens a dialog to collect Client subject details, pre-filled from CA."""
        # --- This function is no longer called and can be removed entirely ---
        if not self.admin_ca_cert:
            messagebox.showerror("CA Not Loaded", "Cannot get defaults: CA is not loaded.", parent=self.root) # Use self.root as parent
            return None

        dialog = tk.Toplevel(self.root) # Use self.root as parent
        dialog.title("Enter Client Certificate Details")
        dialog.transient(self.root) # Make transient to root
        dialog.grab_set()
        dialog.resizable(False, False)

        details = {}
        frame = ttk.Frame(dialog, padding="10")
        frame.pack(expand=True, fill="both")

        # Fields excluding CN (which is entered in the main admin window)
        fields = {
            "O": "Organization:",
            "OU": "Organizational Unit:",
            "L": "Locality (City):",
            "ST": "State/Province:",
            "C": "Country Code (2 letters):"
        }
        entries = {}

        # Get defaults from CA subject
        ca_subject_dict = {attr.oid.dotted_string: attr.value for attr in self.admin_ca_cert.subject}
        defaults = {
            "C": ca_subject_dict.get(NameOID.COUNTRY_NAME.dotted_string, ""),
            "ST": ca_subject_dict.get(NameOID.STATE_OR_PROVINCE_NAME.dotted_string, ""),
            "L": ca_subject_dict.get(NameOID.LOCALITY_NAME.dotted_string, ""),
            "O": ca_subject_dict.get(NameOID.ORGANIZATION_NAME.dotted_string, ""),
            "OU": ca_subject_dict.get(NameOID.ORGANIZATIONAL_UNIT_NAME.dotted_string, ""),
        }

        for i, (key, label) in enumerate(fields.items()):
            ttk.Label(frame, text=label).grid(row=i, column=0, sticky=tk.W, padx=5, pady=3)
            var = tk.StringVar(value=defaults.get(key, "")) # Pre-fill with default
            entry = ttk.Entry(frame, textvariable=var, width=40)
            entry.grid(row=i, column=1, sticky=(tk.W, tk.E), padx=5, pady=3)
            entries[key] = var
            if key == "C": entry.config(width=5)

        button_frame = ttk.Frame(frame)
        button_frame.grid(row=len(fields), column=0, columnspan=2, pady=10)

        def on_ok():
            # Basic validation (e.g., C is required)
            if not entries["C"].get() or len(entries["C"].get()) != 2:
                messagebox.showerror("Invalid Field", "Country Code (C) must be 2 letters.", parent=dialog)
                return

            for key, var in entries.items():
                details[key] = var.get().strip()
            dialog.destroy()

        def on_cancel():
            details.clear() # Indicate cancellation
            dialog.destroy()

        ok_button = ttk.Button(button_frame, text="OK", command=on_ok)
        ok_button.pack(side=tk.LEFT, padx=5)
        cancel_button = ttk.Button(button_frame, text="Cancel", command=on_cancel)
        cancel_button.pack(side=tk.LEFT, padx=5)

        dialog.protocol("WM_DELETE_WINDOW", on_cancel)
        dialog.wait_window()

        return details if details else None

    def _admin_export_ca(self):
        if not self.admin_ca_cert or not self.admin_ca_key:
            messagebox.showerror("CA Not Loaded", "Cannot export: CA is not loaded.", parent=self.root); return # Use self.root as parent

        cert_path = filedialog.asksaveasfilename(title="Save CA Certificate As...", defaultextension=".pem", filetypes=[("PEM Certificate", "*.pem"), ("CRT Certificate", "*.crt"), ("All Files", "*.*")], initialdir=utils.get_downloads_folder(), parent=self.root) # Use self.root as parent
        if not cert_path: self._log_message("[Admin] CA export cancelled (no cert path).", constants.LOG_LEVEL_INFO); return
        key_path = filedialog.asksaveasfilename(title="Save CA Private Key As...", defaultextension=".key", filetypes=[("PEM Private Key", "*.key"), ("All Files", "*.*")], initialdir=utils.get_downloads_folder(), parent=self.root) # Use self.root as parent
        if not key_path: self._log_message("[Admin] CA export cancelled (no key path).", constants.LOG_LEVEL_INFO); return

        self._log_message(f"[Admin] Attempting to export CA cert to {cert_path} and key to {key_path}...", constants.LOG_LEVEL_INFO)
        success, msg = utils.export_ca_from_keyring(cert_path, key_path)
        if success: messagebox.showinfo("CA Exported", f"CA certificate and key exported successfully.", parent=self.root); self._log_message(f"[Admin] {msg}", constants.LOG_LEVEL_INFO) # Use self.root as parent
        else: messagebox.showerror("Export Failed", f"Could not export CA:\n{msg}", parent=self.root); self._log_message(f"[Admin] CA export failed: {msg}", constants.LOG_LEVEL_ERROR) # Use self.root as parent

    def _admin_clear_ca(self):
        if messagebox.askyesno("Confirm Clear CA", "Are you sure you want to permanently remove the CryptLink CA certificate and key from your system keyring?\n\nThis cannot be undone easily.", icon='warning', parent=self.root): # Use self.root as parent
            self._log_message("[Admin] Attempting to clear CA from keyring...", constants.LOG_LEVEL_INFO)
            success, msg = utils.clear_ca_from_keyring()
            if success: messagebox.showinfo("CA Cleared", "CA certificate and key removed from keyring.", parent=self.root); self._log_message(f"[Admin] {msg}", constants.LOG_LEVEL_INFO) # Use self.root as parent
            else: messagebox.showwarning("Clear CA Warning", f"Could not fully clear CA from keyring (it might not have existed):\n{msg}", parent=self.root); self._log_message(f"[Admin] CA clear warning/error: {msg}", constants.LOG_LEVEL_WARN) # Use self.root as parent
            self._admin_check_ca_status() # Update status display
        else: self._log_message("[Admin] User cancelled CA clearing.", constants.LOG_LEVEL_INFO) # Use _log_message

    # --- View Switching ---
    def _show_main_view(self):
        """Shows the main connection/transfer view, hides identities."""
        try:
            # Show main view widgets
            self.conn_frame.grid(row=1, column=0, sticky=tk.W, pady=5) # Changed sticky
            self.status_frame.grid(row=2, column=0, sticky=tk.W, pady=5) # Changed sticky
            self.transfer_frame.grid(row=3, column=0, sticky=tk.W, pady=5) # Changed sticky
            self.received_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 5))

            # Hide other views
            self.cert_frame.grid_forget()
            self.admin_tools_frame.grid_forget()

            # Update menu state
            self.menu_bar.entryconfig("Home", state='disabled')
            self.menu_bar.entryconfig("Admin Tools", state='normal')
            self.menu_bar.entryconfig("Identities", state='normal')
            self._log_message("Switched to Main View.", constants.LOG_LEVEL_DEBUG)
        except AttributeError:
            self._log_message("Error switching to Main View: Widgets not fully initialized yet.", constants.LOG_LEVEL_WARN)

    def _show_identities_view(self):
        """Shows the identities/certificates view, hides main connection/transfer."""
        # Hide main view widgets
        self.conn_frame.grid_forget()
        self.status_frame.grid_forget()
        self.transfer_frame.grid_forget()
        self.received_frame.grid_forget()
        self.admin_tools_frame.grid_forget()

        # Show identities widget
        self.cert_frame.grid(row=0, column=0, sticky=tk.W, pady=5) # Changed sticky

        # Update menu state
        self.menu_bar.entryconfig("Home", state='normal')
        self.menu_bar.entryconfig("Admin Tools", state='normal')
        self.menu_bar.entryconfig("Identities", state='disabled')
        self._log_message("Switched to Identities View.", constants.LOG_LEVEL_DEBUG)

    def _show_admin_tools_view(self):
        """Shows the admin tools view, hides others."""
        # Hide other views
        self.conn_frame.grid_forget()
        self.status_frame.grid_forget()
        self.transfer_frame.grid_forget()
        self.received_frame.grid_forget()
        self.cert_frame.grid_forget()

        # Show admin tools frame (spanning multiple rows conceptually)
        self.admin_tools_frame.grid(row=0, column=0, rowspan=4, sticky=tk.W, pady=5) # Changed sticky
        self._admin_check_ca_status() # Check status when showing the view

        # Update menu state
        self.menu_bar.entryconfig("Home", state='normal')
        self.menu_bar.entryconfig("Identities", state='normal')
        self.menu_bar.entryconfig("Admin Tools", state='disabled')
        self._log_message("Switched to Admin Tools View.", constants.LOG_LEVEL_DEBUG) # Corrected log message

    # --- Application Exit ---
    def _quit_app(self):
        self._log_message("Quit requested.")
        if hasattr(self, '_quitting') and self._quitting: return
        self._quitting = True
        if self.certs_loaded_correctly and not self.bundle_exported_this_session and not self.loaded_from_bundle:
            if messagebox.askyesno("Export Bundle Before Quitting?","Do you want to export the current certificates to an encrypted bundle before quitting?\n\n(This makes loading them easier next time.)",parent=self.root):
                try: self._export_bundle()
                except Exception as e: self._log_message(f"Error during export on quit: {e}", constants.LOG_LEVEL_ERROR); messagebox.showerror("Export Error", f"Could not export bundle before quitting:\n{e}", parent=self.root)
        if self.is_connected or self.is_connecting:
            self._disconnect_peer(reason="Application quitting", notify_peer=True)
            time.sleep(0.2)
        self._stop_server()
        if self.heartbeat_timer: self.heartbeat_timer.cancel()
        if self.sender_status_clear_timer: self.sender_status_clear_timer.cancel()
        if hasattr(self, '_after_id_queue') and self._after_id_queue:
            try:
                self.root.after_cancel(self._after_id_queue)
            except tk.TclError:
                pass
            self._after_id_queue = None
        self._cleanup_temp_files()
        self._log_message("Exiting application.")
        self.root.destroy()
