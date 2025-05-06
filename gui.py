# -*- coding: utf-8 -*-
"""
GUI-related functions for the CryptLink application.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog
import os
import sys
import datetime
import queue # For type hinting if needed, not directly used for queue ops here
import base64
import tempfile # For _import_bundle_dialog

# --- Import Local Modules ---
try:
    # These modules are expected to be in the same directory or Python path
    import constants
    import utils # utils.py will contain general utilities
except ImportError as e:
    # This basic error handling is for when gui.py itself is run or imported
    # in an environment where its siblings aren't found.
    # The main application (main.py) should handle robust error reporting.
    print(f"ERROR (gui.py): Failed to import local modules (constants.py, utils.py): {e}", file=sys.stderr)
    print("Ensure all .py files are in the same directory or accessible in PYTHONPATH.", file=sys.stderr)
    # Attempt a Tkinter popup if possible, as a fallback
    try:
        root_err = tk.Tk()
        root_err.withdraw()
        messagebox.showerror("GUI Import Error", f"Failed to import required modules for GUI: {e}\nEnsure constants.py and utils.py are present.")
        root_err.destroy()
    except tk.TclError:
        pass # Fallback to console output if Tkinter isn't fully available
    sys.exit(1)


def create_widgets(app):
    """Creates all the main widgets for the CryptLink application."""
    # --- Menu Bar ---
    app.menu_bar = tk.Menu(app.root)
    app.root.config(menu=app.menu_bar)

    # --- Top-Level Menu Commands ---
    app.menu_bar.add_command(label="Home", command=lambda: show_main_view(app), state='disabled')
    app.menu_bar.add_command(label="Identities", command=lambda: show_identities_view(app), state='normal')
    app.menu_bar.add_command(label="Admin Tools", command=lambda: show_admin_tools_view(app), state='normal')

    # --- Main Frame Setup (2 Columns) ---
    main_frame = ttk.Frame(app.root, padding="10")
    main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    app.root.columnconfigure(0, weight=1)
    app.root.rowconfigure(0, weight=1)

    main_frame.columnconfigure(0, weight=0)
    main_frame.columnconfigure(1, weight=1)
    main_frame.rowconfigure(0, weight=1)
    main_frame.rowconfigure(1, weight=1)

    # --- Left Column Frame ---
    left_frame = ttk.Frame(main_frame)
    left_frame.grid(row=0, column=0, rowspan=2, sticky=(tk.W, tk.N, tk.S), padx=(0, 10))
    left_frame.columnconfigure(0, weight=1)
    # Define rows for layout management
    for i in range(6): left_frame.rowconfigure(i, weight=0)
    left_frame.rowconfigure(4, weight=1) # Filler/Spacing for main view

    # --- Certificate Section (for Identities View) ---
    app.cert_frame = ttk.LabelFrame(left_frame, text="Certificates & Bundles", padding="10")
    # Gridded later by show_identities_view
    app.cert_frame.columnconfigure(1, weight=1)

    ttk.Button(app.cert_frame, text="CA Cert", command=lambda: select_ca(app)).grid(row=0, column=0, padx=5, pady=2, sticky=tk.W)
    app.ca_entry = ttk.Entry(app.cert_frame, textvariable=app.ca_cert_display_name, state='readonly', width=20)
    app.ca_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=2)
    app.save_certs_button = ttk.Button(app.cert_frame, text="Load Certs", command=app._save_certs, state='disabled')
    app.save_certs_button.grid(row=0, column=2, padx=5, pady=2, sticky=tk.E)

    ttk.Button(app.cert_frame, text="Client Cert", command=lambda: select_cert(app)).grid(row=1, column=0, padx=5, pady=2, sticky=tk.W)
    app.cert_entry = ttk.Entry(app.cert_frame, textvariable=app.client_cert_display_name, state='readonly', width=20)
    app.cert_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5, pady=2)
    app.export_bundle_button = ttk.Button(app.cert_frame, text="Export Bundle", command=lambda: export_bundle_dialog(app), state='disabled')
    app.export_bundle_button.grid(row=1, column=2, padx=5, pady=2, sticky=tk.E)

    ttk.Button(app.cert_frame, text="Client Key", command=lambda: select_key(app)).grid(row=2, column=0, padx=5, pady=2, sticky=tk.W)
    app.key_entry = ttk.Entry(app.cert_frame, textvariable=app.client_key_display_name, state='readonly', width=20)
    app.key_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=5, pady=2)
    app.import_bundle_button = ttk.Button(app.cert_frame, text="Import Bundle", command=lambda: import_bundle_dialog(app), state='normal')
    app.import_bundle_button.grid(row=2, column=2, padx=5, pady=2, sticky=tk.E)

    # --- Identity Persistence Section (for Identities View) ---
    app.identity_persistence_frame = ttk.LabelFrame(left_frame, text="Identity Persistence (Keyring)", padding="10")
    # Gridded later by show_identities_view
    app.identity_persistence_frame.columnconfigure(0, weight=1, uniform="id_persist_buttons")
    app.identity_persistence_frame.columnconfigure(1, weight=1, uniform="id_persist_buttons")

    app.save_identity_button = ttk.Button(app.identity_persistence_frame, text="Save to Keyring", command=app._save_current_identity_to_keyring, state='disabled')
    app.save_identity_button.grid(row=0, column=0, padx=5, pady=5, sticky=tk.EW)
    app.clear_identity_button = ttk.Button(app.identity_persistence_frame, text="Clear from Keyring", command=app._clear_identity_from_keyring_action, state='disabled')
    app.clear_identity_button.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)

    # --- Connection Section (for Main View) ---
    app.conn_frame = ttk.LabelFrame(left_frame, text="Connection", padding="10")
    # Gridded later by show_main_view
    app.conn_frame.columnconfigure(1, weight=1)

    ttk.Label(app.conn_frame, text="Peer IP/Host:").grid(row=0, column=0, padx=5, pady=2, sticky=tk.W)
    app.peer_entry = ttk.Entry(app.conn_frame, textvariable=app.peer_ip_hostname, state='disabled', width=7)
    app.peer_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=2)

    conn_button_frame = ttk.Frame(app.conn_frame)
    conn_button_frame.grid(row=1, column=1, columnspan=2, padx=5, pady=(2, 5), sticky=tk.E)
    app.connect_button = ttk.Button(conn_button_frame, text="Connect", command=app._connect_peer, state='disabled')
    app.connect_button.pack(side=tk.LEFT, padx=(0, 2))
    app.disconnect_button = ttk.Button(conn_button_frame, text="Disconnect", command=lambda: app._disconnect_peer(reason="User disconnected"), state='disabled')
    app.disconnect_button.pack(side=tk.LEFT)

    # --- Status Display Section (for Main View) ---
    app.status_frame = ttk.LabelFrame(left_frame, text="Status", padding="10")
    # Gridded later by show_main_view
    app.status_frame.columnconfigure(1, weight=1)

    ttk.Label(app.status_frame, text="Status:").grid(row=0, column=0, sticky=tk.W, padx=5)
    app.status_label = ttk.Label(app.status_frame, textvariable=app.connection_status, font=('TkDefaultFont', 10, 'bold'))
    app.status_label.grid(row=0, column=1, sticky=tk.W, padx=5)
    ttk.Label(app.status_frame, text="Local:").grid(row=1, column=0, sticky=tk.W, padx=5)
    app.local_info_label = ttk.Label(app.status_frame, text=f"{app.local_hostname} ({app.local_ip})", wraplength=250)
    app.local_info_label.grid(row=1, column=1, sticky=tk.W, padx=5)
    ttk.Label(app.status_frame, text="Local FP:").grid(row=2, column=0, sticky=tk.W, padx=5)
    app.local_fp_label = ttk.Label(app.status_frame, textvariable=app.local_fingerprint_display, font=('Courier', 9))
    app.local_fp_label.grid(row=2, column=1, sticky=tk.W, padx=5)
    ttk.Label(app.status_frame, text="Peer:").grid(row=3, column=0, sticky=tk.W, padx=5)
    app.peer_info_label = ttk.Label(app.status_frame, textvariable=app.peer_hostname, wraplength=250)
    app.peer_info_label.grid(row=3, column=1, sticky=tk.W, padx=5)
    ttk.Label(app.status_frame, text="Peer FP:").grid(row=4, column=0, sticky=tk.W, padx=5)
    app.peer_fp_label = ttk.Label(app.status_frame, textvariable=app.peer_fingerprint_display, font=('Courier', 9))
    app.peer_fp_label.grid(row=4, column=1, sticky=tk.W, padx=5)

    # --- File Transfer Section (for Main View) ---
    app.transfer_frame = ttk.LabelFrame(left_frame, text="File Transfer", padding="10")
    # Gridded later by show_main_view
    app.transfer_frame.columnconfigure(1, weight=1)

    app.choose_file_button = ttk.Button(app.transfer_frame, text="Choose File", command=lambda: choose_file_dialog(app), state='disabled')
    app.choose_file_button.grid(row=0, column=0, padx=5, pady=2, sticky=tk.W)
    app.file_entry = ttk.Entry(app.transfer_frame, textvariable=app.file_to_send_path, state='readonly', width=8)
    app.file_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=2)

    transfer_button_frame = ttk.Frame(app.transfer_frame)
    transfer_button_frame.grid(row=1, column=1, columnspan=2, padx=5, pady=(2, 5), sticky=tk.E)
    app.send_file_button = ttk.Button(transfer_button_frame, text="Send File", command=app._send_file, state='disabled')
    app.send_file_button.grid(row=0, column=0, padx=(0, 2))
    app.cancel_button = ttk.Button(transfer_button_frame, text="Cancel", command=lambda: app._cancel_transfer(notify_peer=True), state='disabled')
    app.cancel_button.grid(row=0, column=1)

    app.progress_bar = ttk.Progressbar(app.transfer_frame, variable=app.transfer_progress, maximum=100)
    app.progress_bar.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), padx=5, pady=5)

    status_speed_eta_frame = ttk.Frame(app.transfer_frame)
    status_speed_eta_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E))
    status_speed_eta_frame.columnconfigure(1, weight=1)
    app.sender_status_label = ttk.Label(status_speed_eta_frame, textvariable=app.sender_transfer_status)
    app.sender_status_label.grid(row=0, column=0, sticky=tk.W, padx=5)
    app.speed_label = ttk.Label(status_speed_eta_frame, textvariable=app.transfer_speed)
    app.speed_label.grid(row=0, column=1, sticky=tk.W, padx=5)
    app.eta_label = ttk.Label(status_speed_eta_frame, textvariable=app.transfer_eta)
    app.eta_label.grid(row=0, column=2, sticky=tk.E, padx=5)

    # --- Admin Tools Section (for Admin Tools View) ---
    app.admin_tools_frame = ttk.Frame(left_frame, padding="5")
    # Gridded later by show_admin_tools_view
    app.admin_tools_frame.columnconfigure(0, weight=1)

    ca_admin_frame = ttk.LabelFrame(app.admin_tools_frame, text="Certificate Authority (CA)", padding="10")
    ca_admin_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
    ca_admin_frame.columnconfigure(1, weight=1)

    app.admin_ca_status_var = tk.StringVar(value="CA Status: Unknown")
    ttk.Label(ca_admin_frame, textvariable=app.admin_ca_status_var).grid(row=0, column=0, columnspan=2, sticky=tk.W, padx=5, pady=2)
    app.admin_load_ca_button = ttk.Button(ca_admin_frame, text="Load/Create CA", command=lambda: admin_load_create_ca(app))
    app.admin_load_ca_button.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)

    ca_admin_button_frame = ttk.Frame(ca_admin_frame)
    ca_admin_button_frame.grid(row=1, column=1, sticky=tk.E, padx=5, pady=5)
    app.admin_export_ca_button = ttk.Button(ca_admin_button_frame, text="Export CA...", command=lambda: admin_export_ca(app), state='disabled')
    app.admin_export_ca_button.pack(side=tk.LEFT, padx=(0, 5))
    app.admin_clear_ca_button = ttk.Button(ca_admin_button_frame, text="Clear CA", command=lambda: admin_clear_ca(app), state='disabled')
    app.admin_clear_ca_button.pack(side=tk.LEFT)

    client_admin_frame = ttk.LabelFrame(app.admin_tools_frame, text="Generate Client Bundle (.clb)", padding="10")
    client_admin_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
    client_admin_frame.columnconfigure(1, weight=1)

    ttk.Label(client_admin_frame, text="Client Name (CN):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
    app.admin_client_cn_var = tk.StringVar()
    app.admin_client_cn_entry = ttk.Entry(client_admin_frame, textvariable=app.admin_client_cn_var, width=30)
    app.admin_client_cn_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=2)

    app.admin_generate_bundle_button = ttk.Button(client_admin_frame, text="Generate Bundle", command=lambda: admin_generate_bundle(app), state='disabled')
    app.admin_generate_bundle_button.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

    # --- Quit Button (always visible at the bottom of left_frame) ---
    app.quit_button = ttk.Button(left_frame, text="Quit", command=app._quit_app)
    app.quit_button.grid(row=5, column=0, sticky=tk.E, pady=10, padx=5)

    # --- Right Column: Received Files and Logs (always visible) ---
    app.received_frame = ttk.LabelFrame(main_frame, text="Received Files (Double-click to open)", padding="10")
    # Gridded later by show_main_view, but also needs to be accessible if main view is not default
    app.received_frame.columnconfigure(0, weight=1)
    app.received_frame.rowconfigure(0, weight=1)

    app.received_listbox = tk.Listbox(app.received_frame, height=5, width=40)
    app.received_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    app.received_listbox.bind("<Double-Button-1>", lambda event: open_received_file(app, event))
    recv_scrollbar_y = ttk.Scrollbar(app.received_frame, orient=tk.VERTICAL, command=app.received_listbox.yview)
    recv_scrollbar_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
    app.received_listbox['yscrollcommand'] = recv_scrollbar_y.set
    recv_scrollbar_x = ttk.Scrollbar(app.received_frame, orient=tk.HORIZONTAL, command=app.received_listbox.xview)
    recv_scrollbar_x.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E))
    app.received_listbox['xscrollcommand'] = recv_scrollbar_x.set

    app.log_frame_outer = ttk.LabelFrame(main_frame, text="Logs", padding="10")
    app.log_frame_outer.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(5, 0))
    app.log_frame_outer.columnconfigure(0, weight=1)
    app.log_frame_outer.rowconfigure(1, weight=1)

    log_button_frame = ttk.Frame(app.log_frame_outer)
    log_button_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.E), pady=(0, 5))
    app.copy_log_button = ttk.Button(log_button_frame, text="Copy", command=lambda: copy_logs(app))
    app.clear_log_button = ttk.Button(log_button_frame, text="Clear", command=lambda: clear_logs(app))
    app.clear_log_button.pack(side=tk.RIGHT, padx=5)
    app.copy_log_button.pack(side=tk.RIGHT, padx=5)

    app.log_text = tk.Text(app.log_frame_outer, height=10, state='disabled', wrap=tk.WORD, width=50)
    app.log_text.grid(row=1, column=0, sticky="nsew")
    log_scrollbar_y = ttk.Scrollbar(app.log_frame_outer, orient=tk.VERTICAL, command=app.log_text.yview)
    log_scrollbar_y.grid(row=1, column=1, sticky=(tk.N, tk.S))
    app.log_text['yscrollcommand'] = log_scrollbar_y.set
    log_scrollbar_x = ttk.Scrollbar(app.log_frame_outer, orient=tk.HORIZONTAL, command=app.log_text.xview)
    log_scrollbar_x.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E))
    app.log_text['xscrollcommand'] = log_scrollbar_x.set

    # Set initial view
    show_main_view(app)


def update_log_widget(app, log_entry):
    """Appends a log entry to the log Text widget."""
    try:
        if not app.log_text.winfo_exists(): return
        app.log_text.config(state='normal')
        app.log_text.insert(tk.END, log_entry)
        app.log_text.see(tk.END)
        app.log_text.config(state='disabled')
    except tk.TclError:
        print("Log widget destroyed, message ignored:", log_entry.strip())

def set_connection_status(app, status):
    """Sets the connection status string and updates the UI display."""
    app.connection_status.set(status)
    update_status_display(app)
    update_identity_persistence_buttons_state(app)

def update_status_display(app):
    """Updates the enabled/disabled state of various widgets based on app status."""
    if not app.root.winfo_exists(): return
    status = app.connection_status.get()
    peer_entry_state = 'disabled'; connect_button_state = 'disabled'; disconnect_button_state = 'disabled'
    choose_file_button_state = 'disabled'; send_file_button_state = 'disabled'; cancel_button_state = 'disabled'
    export_bundle_button_state = 'disabled'; import_bundle_button_state = 'normal'
    save_certs_button_state = 'normal' if (app.ca_cert_display_name.get() and app.client_cert_display_name.get() and app.client_key_display_name.get()) else 'disabled'
    status_color = "red"

    if status == "No Certs": pass
    elif status == "Certs Loaded":
        status_color = "darkorange"
        if app.certs_loaded_correctly:
            peer_entry_state = 'normal'; connect_button_state = 'normal'; export_bundle_button_state = 'normal'
    elif status == "Disconnected":
        status_color = "darkorange"
        if app.certs_loaded_correctly:
            peer_entry_state = 'normal'; connect_button_state = 'normal'; export_bundle_button_state = 'normal'
        else: export_bundle_button_state = 'disabled'
    elif status == "Connecting":
        status_color = "blue"; disconnect_button_state = 'normal'; import_bundle_button_state = 'disabled'
        export_bundle_button_state = 'disabled'; save_certs_button_state = 'disabled'
    elif status == "Confirming Peer":
        status_color = "purple"; disconnect_button_state = 'normal'; import_bundle_button_state = 'disabled'
        export_bundle_button_state = 'disabled'; save_certs_button_state = 'disabled'
    elif status == "Securely Connected":
        status_color = "green"; disconnect_button_state = 'normal'; choose_file_button_state = 'normal'
        send_file_button_state = 'normal' if app.file_to_send_path.get() else 'disabled'
        export_bundle_button_state = 'normal'; import_bundle_button_state = 'disabled'; save_certs_button_state = 'disabled'
    else: status_color = "red"

    try:
        app.status_label.config(foreground=status_color)
        if hasattr(app, 'peer_entry'): app.peer_entry.config(state=peer_entry_state)
        if hasattr(app, 'connect_button'): app.connect_button.config(state=connect_button_state)
        if hasattr(app, 'disconnect_button'): app.disconnect_button.config(state=disconnect_button_state)
        if hasattr(app, 'choose_file_button'): app.choose_file_button.config(state=choose_file_button_state)
        if hasattr(app, 'send_file_button'): app.send_file_button.config(state=send_file_button_state)
        if hasattr(app, 'save_certs_button'): app.save_certs_button.config(state=save_certs_button_state)
        if hasattr(app, 'import_bundle_button'): app.import_bundle_button.config(state=import_bundle_button_state)
        if hasattr(app, 'export_bundle_button'): app.export_bundle_button.config(state=export_bundle_button_state)

        if app.is_transferring:
            if hasattr(app, 'cancel_button'): app.cancel_button.config(state='normal')
            if hasattr(app, 'choose_file_button'): app.choose_file_button.config(state='disabled')
            if hasattr(app, 'send_file_button'): app.send_file_button.config(state='disabled')
            if hasattr(app, 'disconnect_button'): app.disconnect_button.config(state='disabled')
            if hasattr(app, 'connect_button'): app.connect_button.config(state='disabled')
            if hasattr(app, 'import_bundle_button'): app.import_bundle_button.config(state='disabled')
            if hasattr(app, 'export_bundle_button'): app.export_bundle_button.config(state='disabled')
            if hasattr(app, 'save_certs_button'): app.save_certs_button.config(state='disabled')
            if hasattr(app, 'save_identity_button'): app.save_identity_button.config(state='disabled')
        else:
            if hasattr(app, 'cancel_button'): app.cancel_button.config(state='disabled')
            if not app.sender_status_clear_timer: app.sender_transfer_status.set("")
    except tk.TclError as e:
        app._log_message(f"Error updating widget states (window likely closing): {e}", constants.LOG_LEVEL_DEBUG)

def update_local_info(app):
    """Updates GUI labels with local IP, hostname, and certificate fingerprint."""
    if not app.root.winfo_exists(): return
    app.local_info_label.config(text=f"{app.local_hostname} ({app.local_ip})")
    cert_path = app.client_cert_path.get()
    if cert_path and os.path.exists(cert_path): # Check existence
        app.local_full_fingerprint = utils.get_certificate_fingerprint(cert_path)
        app.local_fingerprint_display.set(utils.format_fingerprint_display(app.local_full_fingerprint))
    else:
        app.local_full_fingerprint = None
        app.local_fingerprint_display.set("N/A")

def update_peer_info_display(app, peer_host_param, peer_info_dict):
    """Updates GUI labels with peer's hostname, IP, and certificate fingerprint."""
    if not app.root.winfo_exists(): return
    app.peer_info = peer_info_dict
    hostname = peer_info_dict.get('hostname', 'N/A')
    ip_addr = peer_info_dict.get('ip', 'N/A') # Renamed to avoid conflict
    app.peer_full_fingerprint = peer_info_dict.get('fingerprint', None)
    app.peer_hostname.set(f"{hostname} ({ip_addr})")
    app.peer_fingerprint_display.set(utils.format_fingerprint_display(app.peer_full_fingerprint))
    if app.connection_status.get() == "Securely Connected":
        app.peer_ip_hostname.set(peer_host_param or ip_addr)
    app._log_message(f"Received peer info: {hostname}({ip_addr}) FP: {app.peer_fingerprint_display.get()}")

def clear_peer_info_display(app):
    """Clears peer information from the GUI."""
    if not app.root.winfo_exists(): return
    app.peer_hostname.set("N/A")
    app.peer_fingerprint_display.set("N/A")
    app.peer_full_fingerprint = None
    app.peer_info = {}
    app.peer_ip_hostname.set("")

def visual_feedback(app, button, original_text, feedback_text="Done"):
    """Provides temporary visual feedback on a button (e.g., changes text to 'Done')."""
    try:
        if button and isinstance(button, ttk.Button) and button.winfo_exists():
            original_state = button.cget("state")
            button.config(text=feedback_text, state=tk.DISABLED)
            app.root.after(2000, lambda b=button, ot=original_text, os=original_state: revert_button_config(app, b, ot, os))
        elif button:
            app._log_message(f"Warning: visual_feedback called on non-button or non-existent widget: {button}", constants.LOG_LEVEL_WARN)
    except Exception as e:
        app._log_message(f"Error during visual feedback for {button}: {e}", constants.LOG_LEVEL_ERROR)
        try:
            if button and button.winfo_exists():
                button.config(text=original_text, state=original_state) # Try to revert
        except: pass

def revert_button_config(app, button, original_text, original_state):
    """Reverts a button's text and state after visual feedback."""
    try:
        if button and button.winfo_exists():
            button.config(text=original_text, state=original_state)
            # Special handling for buttons whose state depends on other factors
            if button == app.export_bundle_button and not app.certs_loaded_correctly:
                button.config(state=tk.DISABLED)
            elif button == app.save_certs_button and not (app.ca_cert_display_name.get() and app.client_cert_display_name.get() and app.client_key_display_name.get()):
                button.config(state=tk.DISABLED)
    except tk.TclError as e:
        app._log_message(f"Info: Could not revert button config (widget likely destroyed): {e}", constants.LOG_LEVEL_DEBUG)
    except Exception as e:
        app._log_message(f"Error reverting button config: {e}", constants.LOG_LEVEL_ERROR)

def check_enable_load_certs(app):
    """Enables or disables the 'Load Certs' and 'Export Bundle' buttons based on selections."""
    can_load = bool(app.ca_cert_display_name.get() and app.client_cert_display_name.get() and app.client_key_display_name.get())
    if hasattr(app, 'save_certs_button'): app.save_certs_button.config(state='normal' if can_load else 'disabled')
    if hasattr(app, 'export_bundle_button'): app.export_bundle_button.config(state='normal' if app.certs_loaded_correctly else 'disabled')

def select_file(app, variable_to_set, display_variable_to_set, dialog_title):
    """Handles generic file selection dialog and updates app state."""
    initial_dir = os.getcwd()
    filename = filedialog.askopenfilename(title=dialog_title, filetypes=[("All files", "*.*")], initialdir=initial_dir, parent=app.root)
    if filename:
        variable_to_set.set(filename)
        display_variable_to_set.set(os.path.basename(filename))
        app._log_message(f"Selected {dialog_title}: {os.path.basename(filename)}")

        if app.certs_loaded_correctly:
            app.certs_loaded_correctly = False
            app.gui_queue.put(("status", "No Certs")) # Use app's queue
            app.local_fingerprint_display.set("N/A")
            app.local_full_fingerprint = None

        app.bundle_exported_this_session = False
        app.loaded_from_bundle = False
        app._cleanup_temp_files() # Call app's method
        app.identity_loaded_from_keyring = False
        check_enable_load_certs(app)

def select_ca(app):
    """Callback for selecting the CA certificate file."""
    select_file(app, app.ca_cert_path, app.ca_cert_display_name, "Select CA Certificate")

def select_cert(app):
    """Callback for selecting the client certificate file."""
    select_file(app, app.client_cert_path, app.client_cert_display_name, "Select Client Certificate")

def select_key(app):
    """Callback for selecting the client private key file."""
    select_file(app, app.client_key_path, app.client_key_display_name, "Select Client Private Key")

def prompt_export_after_load(app):
    """Prompts the user to export a bundle after manually loading certificates."""
    if not app.certs_loaded_correctly: return
    if messagebox.askyesno("Export Certificate Bundle",
                           "Certificates loaded successfully.\n\n"
                           "Do you want to export these certificates to a password-protected bundle "
                           "for easier loading next time?", parent=app.root):
        export_bundle_dialog(app)
    else:
        app._log_message("User chose not to export bundle after loading.")
        app.bundle_exported_this_session = False

def export_bundle_dialog(app):
    """Handles the GUI interaction for exporting a certificate bundle."""
    if not app.certs_loaded_correctly:
        app.gui_queue.put(("show_error", "Please load and validate certificates before exporting."))
        return

    password = simpledialog.askstring("Set Bundle Password", "Enter a password to encrypt the bundle:", show='*', parent=app.root)
    if not password:
        app._log_message("Bundle export cancelled (no password).")
        return
    password_confirm = simpledialog.askstring("Confirm Password", "Confirm the password:", show='*', parent=app.root)
    if password != password_confirm:
        app.gui_queue.put(("show_error", "Passwords do not match."))
        return

    bundle_path = filedialog.asksaveasfilename(
        title="Save Certificate Bundle",
        defaultextension=constants.BUNDLE_FILE_EXTENSION,
        filetypes=[(f"CryptLink Bundle (*{constants.BUNDLE_FILE_EXTENSION})", f"*{constants.BUNDLE_FILE_EXTENSION}"), ("All Files", "*.*")],
        initialdir=os.getcwd(), parent=app.root
    )
    if not bundle_path:
        app._log_message("Bundle export cancelled (no save path).")
        return

    # Call the app's method for the actual encryption and file writing
    encryption_result = app._prepare_bundle_data_for_encryption(password) # Corrected method name
    if not encryption_result: return # Error already logged by _encrypt_certs

    salt, encrypted_data = encryption_result
    try:
        with open(bundle_path, "wb") as f:
            f.write(salt)
            f.write(encrypted_data)
        app._log_message(f"Certificates successfully exported to bundle: {os.path.basename(bundle_path)}")
        app.gui_queue.put(("show_info", f"Bundle exported successfully to:\n{bundle_path}"))
        app.bundle_exported_this_session = True
        visual_feedback(app, app.export_bundle_button, "Export Bundle", "Exported!")
    except OSError as e:
        app._log_message(f"Error writing bundle file '{bundle_path}': {e}", constants.LOG_LEVEL_ERROR)
        app.gui_queue.put(("show_error", f"Failed to write bundle file:\n{e}"))
    except Exception as e:
        app._log_message(f"Unexpected error exporting bundle: {e}", constants.LOG_LEVEL_ERROR)
        app.gui_queue.put(("show_error", f"An unexpected error occurred during export:\n{e}"))

def import_bundle_dialog(app):
    """Handles the GUI interaction for importing a certificate bundle."""
    if app.is_connected or app.is_connecting:
        app.gui_queue.put(("show_error", "Cannot import bundle while connected or connecting."))
        return

    bundle_path = filedialog.askopenfilename(
        title="Import Certificate Bundle",
        filetypes=[(f"CryptLink Bundle (*{constants.BUNDLE_FILE_EXTENSION})", f"*{constants.BUNDLE_FILE_EXTENSION}"), ("All Files", "*.*")],
        initialdir=os.getcwd(), parent=app.root
    )
    if not bundle_path:
        app._log_message("Bundle import cancelled.")
        return
    password = simpledialog.askstring("Bundle Password", "Enter the password for the bundle:", show='*', parent=app.root)
    if not password:
        app._log_message("Bundle import cancelled (no password).")
        return

    # Call app's method for decryption and data extraction
    certs_info = app._decrypt_bundle_data_from_file(bundle_path, password) # Corrected method name
    if not certs_info: return # Error already handled by _decrypt_bundle_data_from_file

    app._cleanup_temp_files() # Call app's method
    temp_files_created = {}
    try:
        # Decode base64 data before writing to temp files
        ca_data_pem = base64.b64decode(certs_info["ca_b64"])
        cert_data_pem = base64.b64decode(certs_info["cert_b64"])
        key_data_pem = base64.b64decode(certs_info["key_b64"])

        temp_files_created["ca_data"] = app._write_temp_cert(ca_data_pem, ".crt")
        temp_files_created["cert_data"] = app._write_temp_cert(cert_data_pem, ".crt")
        temp_files_created["key_data"] = app._write_temp_cert(key_data_pem, ".key")


        app.ca_cert_path.set(temp_files_created["ca_data"])
        app.client_cert_path.set(temp_files_created["cert_data"])
        app.client_key_path.set(temp_files_created["key_data"])
        app.ca_cert_display_name.set(certs_info.get("ca_name", "ca.crt"))
        app.client_cert_display_name.set(certs_info.get("cert_name", "client.crt"))
        app.client_key_display_name.set(certs_info.get("key_name", "client.key"))

        app._log_message(f"Certificates successfully imported from bundle: {os.path.basename(bundle_path)} (using temporary files)")
        visual_feedback(app, app.import_bundle_button, "Import Bundle", "Imported!")
        app.identity_loaded_from_keyring = False
        app.loaded_from_bundle = True
        app.bundle_exported_this_session = True # Consider it "saved" in a sense
        app.root.after(100, app._save_certs) # Trigger validation and loading
    except (OSError, KeyError, ValueError, base64.binascii.Error) as e: # Added b64 error
        app._log_message(f"Error processing imported certificate data: {e}", constants.LOG_LEVEL_ERROR)
        app.gui_queue.put(("show_error", f"Failed to process imported certificates:\n{e}"))
        app._cleanup_temp_files()
        app.ca_cert_path.set(""); app.client_cert_path.set(""); app.client_key_path.set("")
        app.ca_cert_display_name.set(""); app.client_cert_display_name.set(""); app.client_key_display_name.set("")
        app.loaded_from_bundle = False; app.identity_loaded_from_keyring = False
        update_identity_persistence_buttons_state(app)
    except Exception as e:
        app._log_message(f"Unexpected error during bundle import processing: {e}", constants.LOG_LEVEL_ERROR)
        app.gui_queue.put(("show_error", f"An unexpected error occurred during import:\n{e}"))
        app._cleanup_temp_files() # Ensure cleanup on any error
        # Reset paths and flags
        app.ca_cert_path.set(""); app.client_cert_path.set(""); app.client_key_path.set("")
        app.ca_cert_display_name.set(""); app.client_cert_display_name.set(""); app.client_key_display_name.set("")
        app.loaded_from_bundle = False; app.identity_loaded_from_keyring = False
        update_identity_persistence_buttons_state(app)


def choose_file_dialog(app):
    """Handles the 'Choose File' dialog for selecting a file to send."""
    if not app.is_connected:
        app.gui_queue.put(("show_error", "Not connected to a peer."))
        return
    if app.is_transferring:
        app.gui_queue.put(("show_error", "A file transfer is already in progress."))
        return

    filename = filedialog.askopenfilename(title="Choose File to Send", parent=app.root, initialdir=os.getcwd(), filetypes=[("All files", "*.*")])
    if filename:
        try:
            # Minimal check to see if file is readable
            with open(filename, "rb") as f:
                f.read(1)
            app.file_to_send_path.set(filename)
            if hasattr(app, 'send_file_button'): app.send_file_button.config(state='normal')
            app._log_message(f"Selected file for sending: {os.path.basename(filename)}")
        except OSError as e:
            app.gui_queue.put(("show_error", f"Cannot read selected file:\n{filename}\nError: {e}"))
            app.file_to_send_path.set("")
            if hasattr(app, 'send_file_button'): app.send_file_button.config(state='disabled')
    else:
        app.file_to_send_path.set("")
        if hasattr(app, 'send_file_button'): app.send_file_button.config(state='disabled')


def update_progress_display(app, progress_val, speed_str, eta_str):
    """Updates the file transfer progress bar and labels."""
    if not app.root.winfo_exists(): return
    try:
        safe_progress = max(0.0, min(100.0, progress_val))
        app.transfer_progress.set(safe_progress)
        app.transfer_speed.set(speed_str)
        app.transfer_eta.set(eta_str)
    except tk.TclError as e:
        app._log_message(f"Error updating progress display (window likely closing): {e}", constants.LOG_LEVEL_DEBUG)

def update_sender_status(app, status_text, color="blue", temporary=False):
    """Updates the sender status label with text and color."""
    if not app.root.winfo_exists(): return
    try:
        if app.sender_status_clear_timer:
            app.root.after_cancel(app.sender_status_clear_timer) # Use root.after_cancel
            app.sender_status_clear_timer = None
        app.sender_status_label.config(foreground=color)
        app.sender_transfer_status.set(status_text)
        if temporary and status_text:
            schedule_sender_status_clear(app)
    except tk.TclError as e:
        app._log_message(f"Error updating sender status (window likely closing): {e}", constants.LOG_LEVEL_DEBUG)

def schedule_sender_status_clear(app):
    """Schedules the sender status label to be cleared after a delay."""
    if app.sender_status_clear_timer:
        app.root.after_cancel(app.sender_status_clear_timer)
    def clear_status():
        if app.root.winfo_exists():
            if not app.is_transferring: # Only clear if not actively transferring
                update_sender_status(app, "", "blue", False)
        app.sender_status_clear_timer = None
    app.sender_status_clear_timer = app.root.after(constants.SENDER_STATUS_DISPLAY_DURATION, clear_status)


def handle_transfer_complete_ui(app, is_sender_role):
    """Handles UI updates when a transfer completes."""
    app._log_message(f"Transfer complete UI update (Sender Role={is_sender_role}).")
    # Core state reset is in app._reset_transfer_state()
    reset_transfer_ui(app)
    update_status_display(app) # Re-enable/disable buttons

def handle_transfer_cancelled_ui(app, is_sender_role):
    """Handles UI updates when a transfer is cancelled."""
    app._log_message(f"Transfer cancelled UI update (Sender Role={is_sender_role}).")
    # Core state reset is in app._reset_transfer_state()
    reset_transfer_ui(app)
    update_status_display(app) # Re-enable/disable buttons

def add_received_file_display(app, display_name, full_path):
    """Adds a successfully received file to the listbox."""
    if not app.root.winfo_exists(): return
    try:
        if display_name not in app.received_listbox.get(0, tk.END):
            app.received_listbox.insert(tk.END, display_name)
        app.received_files[display_name] = full_path # Store mapping
    except tk.TclError as e:
        app._log_message(f"Error adding received file to listbox (window likely closing): {e}", constants.LOG_LEVEL_DEBUG)

def open_received_file(app, event=None):
    """Opens a selected file from the received files listbox."""
    try:
        selected_indices = app.received_listbox.curselection()
        if not selected_indices: return
        selected_display_name = app.received_listbox.get(selected_indices[0])
        file_path = app.received_files.get(selected_display_name)
        if file_path:
            app._log_message(f"Attempting to open received file: {file_path}")
            utils.open_file_in_default_app(file_path) # Uses utility function
        else:
            app._log_message(f"Cannot open received file: Path not found for '{selected_display_name}'.", constants.LOG_LEVEL_ERROR)
            app.gui_queue.put(("show_error", f"Internal error: Path not found for '{selected_display_name}'."))
    except tk.TclError as e:
        app._log_message(f"Error opening received file (window likely closing): {e}", constants.LOG_LEVEL_DEBUG)

def copy_logs(app):
    """Copies the content of the log Text widget to the clipboard."""
    if not app.root.winfo_exists(): return
    try:
        log_content = app.log_text.get("1.0", tk.END).strip()
        if log_content:
            app.root.clipboard_clear()
            app.root.clipboard_append(log_content)
            app._log_message("Logs copied to clipboard.")
            visual_feedback(app, app.copy_log_button, "Copy", "Copied!")
        else:
            app._log_message("No logs to copy.", constants.LOG_LEVEL_INFO)
    except Exception as e:
        app._log_message(f"Error copying logs: {e}", constants.LOG_LEVEL_ERROR)
        app.gui_queue.put(("show_error", f"Could not copy logs: {e}"))

def clear_logs(app):
    """Clears the content of the log Text widget."""
    if not app.root.winfo_exists(): return
    try:
        app.log_text.config(state='normal')
        app.log_text.delete("1.0", tk.END)
        app.log_text.config(state='disabled')
        app._log_message("Logs cleared.") # This will re-add "Logs cleared." to the log
        visual_feedback(app, app.clear_log_button, "Clear", "Cleared!")
    except tk.TclError as e:
        app._log_message(f"Error clearing logs (window likely closing): {e}", constants.LOG_LEVEL_DEBUG)


def admin_check_ca_status(app):
    """Checks keyring for CA and updates Admin Tools UI elements."""
    app.admin_ca_cert, app.admin_ca_key, msg = utils.get_ca_from_keyring()
    if app.admin_ca_cert and app.admin_ca_key:
        app.admin_ca_status_var.set("CA Status: Loaded from Keyring")
        if hasattr(app, 'admin_generate_bundle_button'): app.admin_generate_bundle_button.config(state='normal')
        if hasattr(app, 'admin_export_ca_button'): app.admin_export_ca_button.config(state='normal')
        if hasattr(app, 'admin_clear_ca_button'): app.admin_clear_ca_button.config(state='normal')
        app._log_message("[Admin] CA loaded successfully from keyring.", constants.LOG_LEVEL_INFO)
    else:
        app.admin_ca_status_var.set(f"CA Status: Not Found ({msg})")
        if hasattr(app, 'admin_generate_bundle_button'): app.admin_generate_bundle_button.config(state='disabled')
        if hasattr(app, 'admin_export_ca_button'): app.admin_export_ca_button.config(state='disabled')
        if hasattr(app, 'admin_clear_ca_button'): app.admin_clear_ca_button.config(state='disabled')
        app._log_message(f"[Admin] CA not found in keyring: {msg}", constants.LOG_LEVEL_INFO)

def admin_load_create_ca(app):
    """Handles loading or creating a CA in the Admin Tools."""
    admin_check_ca_status(app) # Re-check first
    if not app.admin_ca_cert:
        if messagebox.askyesno("Create CA?", "No CA found in the system keyring.\n\n"
                               "Do you want to create a new CA certificate and key and store them securely?",
                               parent=app.root):
            app._log_message("[Admin] Attempting to create and store new CA...", constants.LOG_LEVEL_INFO)
            ca_details = prompt_ca_details(app)
            if not ca_details:
                app._log_message("[Admin] CA creation cancelled by user (details dialog).", constants.LOG_LEVEL_INFO)
                return
            success, msg = utils.create_and_store_ca(ca_details)
            if success:
                app._log_message(f"[Admin] CA creation successful: {msg}", constants.LOG_LEVEL_INFO)
                messagebox.showinfo("CA Created", "New CA certificate and key created and stored in your system keyring.", parent=app.root)
                admin_check_ca_status(app)
            else:
                app._log_message(f"[Admin] CA creation failed: {msg}", constants.LOG_LEVEL_ERROR)
                messagebox.showerror("CA Creation Failed", f"Could not create or store the CA:\n{msg}", parent=app.root)
        else:
            app._log_message("[Admin] User chose not to create a new CA.", constants.LOG_LEVEL_INFO)
    else:
        messagebox.showinfo("CA Loaded", "CA is already loaded from the keyring.", parent=app.root)

def prompt_ca_details(app):
    """Opens a dialog to collect CA subject details."""
    dialog = tk.Toplevel(app.root)
    dialog.title("Enter CA Details")
    dialog.transient(app.root)
    dialog.grab_set()
    dialog.resizable(False, False)

    details = {}
    frame = ttk.Frame(dialog, padding="10")
    frame.pack(expand=True, fill="both")

    fields = {
        "CN": "Common Name:", "O": "Organization:", "OU": "Organizational Unit:",
        "C": "Country Code (2 letters):", "ST": "State/Province:", "L": "Locality (City):"
    }
    entries = {}
    for i, (key, label_text) in enumerate(fields.items()):
        ttk.Label(frame, text=label_text).grid(row=i, column=0, sticky=tk.W, padx=5, pady=3)
        var = tk.StringVar()
        entry = ttk.Entry(frame, textvariable=var, width=40)
        entry.grid(row=i, column=1, sticky=(tk.W, tk.E), padx=5, pady=3)
        entries[key] = var
        if key == "CN": var.set("CryptLink Root CA")
        if key == "C": entry.config(width=5)

    button_frame = ttk.Frame(frame)
    button_frame.grid(row=len(fields), column=0, columnspan=2, pady=10)

    def on_ok():
        if not entries["CN"].get():
            messagebox.showerror("Missing Field", "Common Name (CN) is required.", parent=dialog)
            return
        if not entries["C"].get() or len(entries["C"].get()) != 2 or not entries["C"].get().isalpha():
            messagebox.showerror("Invalid Field", "Country Code (C) must be 2 letters.", parent=dialog)
            return
        for key, var_obj in entries.items(): details[key] = var_obj.get().strip()
        dialog.destroy()

    def on_cancel():
        details.clear()
        dialog.destroy()

    ok_button = ttk.Button(button_frame, text="OK", command=on_ok)
    ok_button.pack(side=tk.LEFT, padx=5)
    cancel_button = ttk.Button(button_frame, text="Cancel", command=on_cancel)
    cancel_button.pack(side=tk.LEFT, padx=5)
    dialog.protocol("WM_DELETE_WINDOW", on_cancel)
    dialog.wait_window()
    return details if details else None

def admin_generate_bundle(app):
    """Handles generating a client certificate bundle from the Admin Tools."""
    if not app.admin_ca_cert or not app.admin_ca_key:
        messagebox.showerror("CA Not Loaded", "Cannot generate bundle: CA is not loaded. Use 'Load/Create CA' first.", parent=app.root)
        app._log_message("[Admin] Bundle generation failed: CA not loaded.", constants.LOG_LEVEL_ERROR)
        return

    client_cn = app.admin_client_cn_var.get().strip()
    if not client_cn:
        messagebox.showerror("Client Name Required", "Please enter a Client Name (Common Name) for the certificate.", parent=app.root)
        app._log_message("[Admin] Bundle generation failed: Client Name missing.", constants.LOG_LEVEL_ERROR)
        return

    app._log_message(f"[Admin] Generating client certificate and key for CN: {client_cn}...", constants.LOG_LEVEL_INFO)
    client_cert_pem, client_key_pem, msg = utils.create_client_cert_and_key(app.admin_ca_cert, app.admin_ca_key, client_cn)

    if not client_cert_pem or not client_key_pem:
        app._log_message(f"[Admin] Client cert/key generation failed: {msg}", constants.LOG_LEVEL_ERROR)
        messagebox.showerror("Generation Failed", f"Could not generate client certificate/key:\n{msg}", parent=app.root)
        return
    app._log_message("[Admin] Client certificate and key generated successfully.", constants.LOG_LEVEL_INFO)

    password = simpledialog.askstring("Set Bundle Password", "Enter a password to encrypt the bundle:", show='*', parent=app.root)
    if not password: app._log_message("[Admin] Bundle creation cancelled (no password).", constants.LOG_LEVEL_INFO); return
    password_confirm = simpledialog.askstring("Confirm Password", "Confirm the password:", show='*', parent=app.root)
    if password != password_confirm:
        messagebox.showerror("Password Mismatch", "Passwords do not match.", parent=app.root)
        app._log_message("[Admin] Bundle creation failed: Password mismatch.", constants.LOG_LEVEL_ERROR); return

    bundle_path = filedialog.asksaveasfilename(
        title="Save Client Bundle", defaultextension=constants.BUNDLE_FILE_EXTENSION,
        filetypes=[(f"CryptLink Bundle (*{constants.BUNDLE_FILE_EXTENSION})", f"*{constants.BUNDLE_FILE_EXTENSION}"), ("All Files", "*.*")],
        initialdir=utils.get_downloads_folder(), parent=app.root
    )
    if not bundle_path: app._log_message("[Admin] Bundle creation cancelled (no save path).", constants.LOG_LEVEL_INFO); return

    app._log_message(f"[Admin] Creating encrypted bundle at: {bundle_path}...", constants.LOG_LEVEL_INFO)
    success, msg = utils.create_encrypted_bundle(bundle_path, password, app.admin_ca_cert, client_cert_pem, client_key_pem, client_cn)

    if success:
        app._log_message(f"[Admin] Bundle created successfully: {msg}", constants.LOG_LEVEL_INFO)
        messagebox.showinfo("Bundle Created", f"Client bundle for '{client_cn}' created successfully:\n{bundle_path}", parent=app.root)
    else:
        app._log_message(f"[Admin] Bundle creation failed: {msg}", constants.LOG_LEVEL_ERROR)
        messagebox.showerror("Bundle Creation Failed", f"Could not create the encrypted bundle:\n{msg}", parent=app.root)

def admin_export_ca(app):
    """Handles exporting the CA certificate and key from the Admin Tools."""
    if not app.admin_ca_cert or not app.admin_ca_key:
        messagebox.showerror("CA Not Loaded", "Cannot export: CA is not loaded.", parent=app.root); return

    cert_path = filedialog.asksaveasfilename(
        title="Save CA Certificate As...", defaultextension=".pem",
        filetypes=[("PEM Certificate", "*.pem"), ("CRT Certificate", "*.crt"), ("All Files", "*.*")],
        initialdir=utils.get_downloads_folder(), parent=app.root
    )
    if not cert_path: app._log_message("[Admin] CA export cancelled (no cert path).", constants.LOG_LEVEL_INFO); return
    key_path = filedialog.asksaveasfilename(
        title="Save CA Private Key As...", defaultextension=".key",
        filetypes=[("PEM Private Key", "*.key"), ("All Files", "*.*")],
        initialdir=utils.get_downloads_folder(), parent=app.root
    )
    if not key_path: app._log_message("[Admin] CA export cancelled (no key path).", constants.LOG_LEVEL_INFO); return

    app._log_message(f"[Admin] Attempting to export CA cert to {cert_path} and key to {key_path}...", constants.LOG_LEVEL_INFO)
    success, msg = utils.export_ca_from_keyring(cert_path, key_path)
    if success:
        messagebox.showinfo("CA Exported", "CA certificate and key exported successfully.", parent=app.root)
        app._log_message(f"[Admin] {msg}", constants.LOG_LEVEL_INFO)
    else:
        messagebox.showerror("Export Failed", f"Could not export CA:\n{msg}", parent=app.root)
        app._log_message(f"[Admin] CA export failed: {msg}", constants.LOG_LEVEL_ERROR)

def admin_clear_ca(app):
    """Handles clearing the CA from the keyring via Admin Tools."""
    if messagebox.askyesno("Confirm Clear CA", "Are you sure you want to permanently remove the CryptLink CA certificate and key "
                           "from your system keyring?\n\nThis cannot be undone easily.", icon='warning', parent=app.root):
        app._log_message("[Admin] Attempting to clear CA from keyring...", constants.LOG_LEVEL_INFO)
        success, msg = utils.clear_ca_from_keyring()
        if success:
            messagebox.showinfo("CA Cleared", "CA certificate and key removed from keyring.", parent=app.root)
            app._log_message(f"[Admin] {msg}", constants.LOG_LEVEL_INFO)
        else:
            messagebox.showwarning("Clear CA Warning", f"Could not fully clear CA from keyring (it might not have existed):\n{msg}", parent=app.root)
            app._log_message(f"[Admin] CA clear warning/error: {msg}", constants.LOG_LEVEL_WARN)
        admin_check_ca_status(app) # Update status display
    else:
        app._log_message("[Admin] User cancelled CA clearing.", constants.LOG_LEVEL_INFO)


def show_main_view(app):
    """Shows the main connection/transfer view, hides others."""
    try:
        # Hide other views' main frames first
        if hasattr(app, 'cert_frame'): app.cert_frame.grid_forget()
        if hasattr(app, 'identity_persistence_frame'): app.identity_persistence_frame.grid_forget()
        if hasattr(app, 'admin_tools_frame'): app.admin_tools_frame.grid_forget()

        # Show main view widgets in left_frame
        if hasattr(app, 'conn_frame'): app.conn_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5) # Use tk.W, tk.E for full width
        if hasattr(app, 'status_frame'): app.status_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        if hasattr(app, 'transfer_frame'): app.transfer_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)
        # Ensure right column (received files, logs) is visible
        if hasattr(app, 'received_frame'): app.received_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 5))
        if hasattr(app, 'log_frame_outer'): app.log_frame_outer.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(5, 0))


        # Update menu state
        app.menu_bar.entryconfig("Home", state='disabled')
        app.menu_bar.entryconfig("Identities", state='normal')
        app.menu_bar.entryconfig("Admin Tools", state='normal')
        app._log_message("Switched to Main View.", constants.LOG_LEVEL_DEBUG)
        update_status_display(app) # Refresh button states
    except AttributeError as e:
        app._log_message(f"Error switching to Main View (widgets might not be fully initialized): {e}", constants.LOG_LEVEL_WARN)


def show_identities_view(app):
    """Shows the identities/certificates view, hides others."""
    try:
        # Hide other views' main frames
        if hasattr(app, 'conn_frame'): app.conn_frame.grid_forget()
        if hasattr(app, 'status_frame'): app.status_frame.grid_forget()
        if hasattr(app, 'transfer_frame'): app.transfer_frame.grid_forget()
        if hasattr(app, 'admin_tools_frame'): app.admin_tools_frame.grid_forget()
        # Keep right column (received files, logs) visible
        if hasattr(app, 'received_frame'): app.received_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 5))
        if hasattr(app, 'log_frame_outer'): app.log_frame_outer.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(5, 0))


        # Show identities widgets in left_frame
        if hasattr(app, 'cert_frame'): app.cert_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        if hasattr(app, 'identity_persistence_frame'): app.identity_persistence_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5, padx=5)
        update_identity_persistence_buttons_state(app)

        # Update menu state
        app.menu_bar.entryconfig("Home", state='normal')
        app.menu_bar.entryconfig("Identities", state='disabled')
        app.menu_bar.entryconfig("Admin Tools", state='normal')
        app._log_message("Switched to Identities View.", constants.LOG_LEVEL_DEBUG)
    except AttributeError as e:
        app._log_message(f"Error switching to Identities View (widgets might not be fully initialized): {e}", constants.LOG_LEVEL_WARN)


def show_admin_tools_view(app):
    """Shows the admin tools view, hides others."""
    try:
        # Hide other views' main frames
        if hasattr(app, 'conn_frame'): app.conn_frame.grid_forget()
        if hasattr(app, 'status_frame'): app.status_frame.grid_forget()
        if hasattr(app, 'transfer_frame'): app.transfer_frame.grid_forget()
        if hasattr(app, 'cert_frame'): app.cert_frame.grid_forget()
        if hasattr(app, 'identity_persistence_frame'): app.identity_persistence_frame.grid_forget()
        # Keep right column (received files, logs) visible
        if hasattr(app, 'received_frame'): app.received_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 5))
        if hasattr(app, 'log_frame_outer'): app.log_frame_outer.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(5, 0))


        # Show admin tools frame in left_frame
        if hasattr(app, 'admin_tools_frame'): app.admin_tools_frame.grid(row=0, column=0, rowspan=3, sticky=(tk.W, tk.E), pady=5) # rowspan to occupy similar space
        admin_check_ca_status(app)

        # Update menu state
        app.menu_bar.entryconfig("Home", state='normal')
        app.menu_bar.entryconfig("Identities", state='normal')
        app.menu_bar.entryconfig("Admin Tools", state='disabled')
        app._log_message("Switched to Admin Tools View.", constants.LOG_LEVEL_DEBUG)
    except AttributeError as e:
        app._log_message(f"Error switching to Admin Tools View (widgets might not be fully initialized): {e}", constants.LOG_LEVEL_WARN)


def update_identity_persistence_buttons_state(app):
    """Updates the state of 'Save to Keyring' and 'Clear from Keyring' buttons."""
    if not hasattr(app, 'save_identity_button') or not app.save_identity_button.winfo_exists():
        return # Widgets not ready

    can_save = app.certs_loaded_correctly and not app.identity_loaded_from_keyring and not app.is_transferring
    app.save_identity_button.config(state='normal' if can_save else 'disabled')

    can_clear = app.keyring_has_user_identity and not app.is_transferring
    app.clear_identity_button.config(state='normal' if can_clear else 'disabled')

def reset_transfer_ui(app):
    """Resets transfer-related UI elements to their default state."""
    app.gui_queue.put(("progress", (0, "Speed: N/A", "ETA: N/A")))
    # The sender status message will be cleared by its own timer if it was set as temporary.
