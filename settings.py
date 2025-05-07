# -*- coding: utf-8 -*-
"""
Settings view for the CryptLink application.
"""

import tkinter as tk
from tkinter import ttk
import sys # Added for sys.exit

try:
    import constants # For LOG_LEVEL_MAP keys
except ImportError:
    # This should ideally be caught by the main app, but as a fallback:
    print("ERROR (settings.py): Failed to import constants.py", file=sys.stderr)
    sys.exit(1)


def create_settings_widgets(app, parent_frame):
    """
    Creates the widgets for the Settings view.
    'app' is the main CryptLinkApp instance.
    'parent_frame' is the ttk.Frame where these widgets should be placed.
    """
    app.settings_frame = ttk.Frame(parent_frame, padding="10")
    # This frame will be gridded by show_settings_view in gui.py

    # --- Logging Settings ---
    logging_frame = ttk.LabelFrame(app.settings_frame, text="Logging Settings", padding="10")
    logging_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N), padx=5, pady=5)
    logging_frame.columnconfigure(1, weight=1)

    ttk.Label(logging_frame, text="Logging Verbosity:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)

    # Ensure app.logging_verbosity_var is initialized in CryptLinkApp.__init__
    # It should be a tk.StringVar()
    # The values for the combobox should be the keys of constants.LOG_LEVEL_MAP
    log_level_options = list(constants.LOG_LEVEL_MAP.keys())

    app.logging_verbosity_combobox = ttk.Combobox(
        logging_frame,
        textvariable=app.logging_verbosity_var,
        values=log_level_options,
        state="readonly", # User can only select from the list
        width=15
    )
    app.logging_verbosity_combobox.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=5)
    # Set current value if not already set by app._load_app_settings
    # This check is important for when the settings UI is created *after* settings are loaded.
    if not app.logging_verbosity_var.get() and log_level_options:
        # If app.logging_verbosity_var is still empty, it means _load_app_settings might not have run
        # or didn't set it. We default to constants.DEFAULT_LOGGING_LEVEL_STR.
        # The actual application of this default to constants.CURRENT_LOG_LEVEL happens in _load_app_settings.
        app.logging_verbosity_var.set(constants.DEFAULT_LOGGING_LEVEL_STR)


    # --- Add more settings sections here in the future ---
    # Example:
    # network_frame = ttk.LabelFrame(app.settings_frame, text="Network Settings", padding="10")
    # network_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N), padx=5, pady=5)

    # --- Save Button ---
    # Place it at the bottom of app.settings_frame, spanning columns if necessary
    app.save_settings_button = ttk.Button(app.settings_frame, text="Save Settings", command=app._save_app_settings)
    app.save_settings_button.grid(row=10, column=0, sticky=(tk.E), padx=5, pady=20) # row=10 to leave space

    return app.settings_frame
