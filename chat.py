# -*- coding: utf-8 -*-
"""
Chat view for the CryptLink application.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import sys

try:
    import constants # For APP_NAME, APP_VERSION if needed directly, or other constants
    # utils might be needed if we add specific utility functions for chat display
except ImportError:
    print("ERROR (chat.py): Failed to import constants.py", file=sys.stderr)
    # Fallback for basic error display if Tkinter is available
    try:
        root_err = tk.Tk()
        root_err.withdraw()
        tk.messagebox.showerror("Chat Module Error", "Failed to import constants.py for Chat module.")
        root_err.destroy()
    except Exception:
        pass
    sys.exit(1)

def create_chat_widgets(app, parent_frame):
    """
    Creates the widgets for the Chat view.
    'app' is the main CryptLinkApp instance.
    'parent_frame' is the ttk.Frame where these widgets should be placed (main_frame from gui.py).
    """
    # This main container will be gridded by gui.show_chat_view
    app.chat_view_frame_container = ttk.Frame(parent_frame, padding="10")
    app.chat_view_frame_container.columnconfigure(0, weight=3, uniform="chat_group") # Left column (30%)
    app.chat_view_frame_container.columnconfigure(1, weight=7, uniform="chat_group") # Right column (70%)
    app.chat_view_frame_container.rowconfigure(0, weight=1)

    # --- Left Column (Status Display) ---
    # Replicates the status display from the main view, using app's StringVars
    app.chat_status_frame_replica = ttk.LabelFrame(app.chat_view_frame_container, text="Connection Status", padding="10")
    app.chat_status_frame_replica.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
    app.chat_status_frame_replica.columnconfigure(1, weight=1)
    app.chat_status_frame_replica.rowconfigure(5, weight=1) # Add weight to a row for the Quit button to push down

    ttk.Label(app.chat_status_frame_replica, text="Status:").grid(row=0, column=0, sticky=tk.W, padx=5)
    app.chat_view_status_label = ttk.Label(app.chat_status_frame_replica, textvariable=app.connection_status, font=('TkDefaultFont', 10, 'bold'))
    app.chat_view_status_label.grid(row=0, column=1, sticky=tk.W, padx=5)

    ttk.Label(app.chat_status_frame_replica, text="Local:").grid(row=1, column=0, sticky=tk.W, padx=5)
    app.chat_view_local_info_label = ttk.Label(app.chat_status_frame_replica, text=f"{app.local_hostname} ({app.local_ip})", wraplength=180)
    app.chat_view_local_info_label.grid(row=1, column=1, sticky=tk.W, padx=5)

    ttk.Label(app.chat_status_frame_replica, text="Local FP:").grid(row=2, column=0, sticky=tk.W, padx=5)
    app.chat_view_local_fp_label = ttk.Label(app.chat_status_frame_replica, textvariable=app.local_fingerprint_display, font=('Courier', 9))
    app.chat_view_local_fp_label.grid(row=2, column=1, sticky=tk.W, padx=5)

    ttk.Label(app.chat_status_frame_replica, text="Peer:").grid(row=3, column=0, sticky=tk.W, padx=5)
    app.chat_view_peer_info_label = ttk.Label(app.chat_status_frame_replica, textvariable=app.peer_hostname, wraplength=180)
    app.chat_view_peer_info_label.grid(row=3, column=1, sticky=tk.W, padx=5)

    ttk.Label(app.chat_status_frame_replica, text="Peer FP:").grid(row=4, column=0, sticky=tk.W, padx=5)
    app.chat_view_peer_fp_label = ttk.Label(app.chat_status_frame_replica, textvariable=app.peer_fingerprint_display, font=('Courier', 9))
    app.chat_view_peer_fp_label.grid(row=4, column=1, sticky=tk.W, padx=5)

    # Add Quit button to the bottom-right of the left status column
    app.chat_view_quit_button = ttk.Button(app.chat_status_frame_replica, text="Quit", command=app._quit_app)
    app.chat_view_quit_button.grid(row=6, column=1, sticky=(tk.S, tk.E), pady=(10,0), padx=5) # Placed in a new row, aligned bottom-right

    # --- Right Column (Chat Area) ---
    app.chat_right_frame = ttk.Frame(app.chat_view_frame_container)
    app.chat_right_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
    app.chat_right_frame.rowconfigure(0, weight=75) # Conversation area (75%)
    app.chat_right_frame.rowconfigure(1, weight=25) # Input area (25%)
    app.chat_right_frame.columnconfigure(0, weight=1)

    # Top Row: Conversation Area
    chat_conversation_outer_frame = ttk.Frame(app.chat_right_frame) # Frame to hold Text and Scrollbar
    chat_conversation_outer_frame.grid(row=0, column=0, sticky="nsew", pady=(0,5))
    chat_conversation_outer_frame.rowconfigure(0, weight=1)
    chat_conversation_outer_frame.columnconfigure(0, weight=1)

    app.chat_conversation_area = tk.Text(chat_conversation_outer_frame, wrap=tk.WORD, state='disabled', relief=tk.SOLID, borderwidth=1)
    app.chat_conversation_area.grid(row=0, column=0, sticky="nsew")

    chat_scrollbar = ttk.Scrollbar(chat_conversation_outer_frame, orient=tk.VERTICAL, command=app.chat_conversation_area.yview)
    chat_scrollbar.grid(row=0, column=1, sticky="ns")
    app.chat_conversation_area['yscrollcommand'] = chat_scrollbar.set

    # Define tags for message styling
    # Message content tags (color and justification for the main text body)
    app.chat_conversation_area.tag_configure("peer_message_content", foreground="blue", justify="left", lmargin1=10, lmargin2=10, rmargin=10)
    app.chat_conversation_area.tag_configure("local_message_content", foreground="green", justify="right", lmargin1=50, lmargin2=50, rmargin=10)

    # Sender name tags (bold, color, and justification matching the message body)
    app.chat_conversation_area.tag_configure("peer_sender_name", foreground="blue", font=('TkDefaultFont', 9, 'bold'), justify="left", lmargin1=10, lmargin2=10, rmargin=0) # No right margin for sender name itself
    app.chat_conversation_area.tag_configure("local_sender_name", foreground="green", font=('TkDefaultFont', 9, 'bold'), justify="right", lmargin1=50, lmargin2=50, rmargin=0) # No right margin for sender name itself

    app.chat_conversation_area.tag_configure("system_message", foreground="gray", justify="center", font=('TkDefaultFont', 9, 'italic'))
    # Define tags for timestamp styling
    app.chat_conversation_area.tag_configure("peer_timestamp_tag", foreground="black", font=('TkDefaultFont', 8, 'italic'), justify="left", lmargin1=10, lmargin2=10, rmargin=10) # Left justify for peer timestamp
    app.chat_conversation_area.tag_configure("local_timestamp_tag", foreground="black", font=('TkDefaultFont', 8, 'italic'), justify="right", rmargin=10) # Removed lmargins for full right justification

    # Bottom Row: Input Area
    app.chat_input_frame = ttk.Frame(app.chat_right_frame, padding=(0, 5, 0, 0))
    app.chat_input_frame.grid(row=1, column=0, sticky="nsew")
    app.chat_input_frame.columnconfigure(0, weight=1) # Entry takes up available space
    app.chat_input_frame.columnconfigure(1, weight=0) # Button fixed size

    # Change Entry to Text widget for multi-line input
    app.chat_message_entry = tk.Text(app.chat_input_frame, height=3, wrap=tk.WORD, relief=tk.SOLID, borderwidth=1)
    app.chat_message_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
    # For Text widget, Enter usually means newline. We'll handle send on button click.
    # If you want Enter to send and Shift+Enter for newline, that's more complex.
    # For now, Enter will insert a newline in the Text widget.
    # To make Enter send and prevent newline:
    app.chat_message_entry.bind("<Return>", lambda event: app._send_chat_message_action() or "break")

    app.chat_send_button = ttk.Button(app.chat_input_frame, text="Send", command=app._send_chat_message_action)
    app.chat_send_button.grid(row=0, column=1, sticky="e")

    return app.chat_view_frame_container
