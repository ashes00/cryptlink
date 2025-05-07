# -*- coding: utf-8 -*-
"""
About view for the CryptLink application.
"""

import tkinter as tk
from tkinter import ttk
import sys

try:
    import constants
    import utils # For opening URL
except ImportError:
    print("ERROR (about.py): Failed to import constants.py or utils.py", file=sys.stderr)
    sys.exit(1)

GITHUB_URL = "https://github.com/ashes00/cryptlink"

def create_about_widgets(app, parent_frame):
    """
    Creates the widgets for the About view.
    'app' is the main CryptLinkApp instance.
    'parent_frame' is the ttk.Frame where these widgets should be placed.
    """
    app.about_frame = ttk.Frame(parent_frame, padding="20") # Added more padding
    # This app.about_frame (app.about_view_frame_container) will be gridded by show_about_view
    # to take up the whole main_frame area.
    # We configure its rows/columns to center the actual content.

    app.about_frame.rowconfigure(0, weight=1)    # Flexible space above
    app.about_frame.rowconfigure(1, weight=0)    # Content row (no extra space)
    app.about_frame.rowconfigure(2, weight=1)    # Flexible space below
    app.about_frame.columnconfigure(0, weight=1) # Flexible space left
    app.about_frame.columnconfigure(1, weight=0) # Content column (no extra space)
    app.about_frame.columnconfigure(2, weight=1) # Flexible space right

    # Create an inner frame to hold the actual content and pack it
    content_holder = ttk.Frame(app.about_frame)
    content_holder.grid(row=1, column=1, sticky="nsew") # Center the holder

    title_label = ttk.Label(content_holder, text=constants.APP_NAME, font=("TkDefaultFont", 20, "bold"))
    title_label.pack(pady=(10, 5)) # More padding

    version_label = ttk.Label(content_holder, text=f"Version: {constants.APP_VERSION}", font=("TkDefaultFont", 12))
    version_label.pack(pady=(0, 20))

    # Separator is optional, can be added if desired
    # separator = ttk.Separator(content_holder, orient='horizontal')
    # separator.pack(fill='x', pady=15, padx=20)

    github_info_frame = ttk.Frame(content_holder)
    github_info_frame.pack(pady=10)

    github_text_label = ttk.Label(github_info_frame, text="Project Home:", font=("TkDefaultFont", 10))
    github_text_label.pack(side=tk.LEFT, padx=(0,5))

    github_link_label = ttk.Label(github_info_frame, text=GITHUB_URL, foreground="blue", cursor="hand2", font=("TkDefaultFont", 10))
    github_link_label.pack(side=tk.LEFT)
    github_link_label.bind("<Button-1>", lambda e: utils.open_url_in_browser(GITHUB_URL))

    # You can add more information here, like author, license, etc.
    # description_label = ttk.Label(app.about_frame, text="A secure peer-to-peer file transfer tool.", wraplength=300)
    # description_label.pack(pady=10)

    return app.about_frame
