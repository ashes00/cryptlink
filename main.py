#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CryptLink: Secure Peer-to-Peer File Transfer using TLS and Tkinter.
Main entry point.
"""

import tkinter as tk
import sys
import os

# --- Add current directory to path to find local modules ---
# This helps if the script is run from a different directory
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# --- Dependency Check ---
try:
    from dependencies import check_dependencies
except ImportError:
    print("ERROR: dependencies.py not found.", file=sys.stderr)
    print("Ensure all .py files (main.py, cryptlink_app.py, constants.py, utils.py, dependencies.py) are in the same directory.", file=sys.stderr)
    # Try a basic Tkinter error if possible
    try:
        root_err = tk.Tk()
        root_err.withdraw()
        tk.messagebox.showerror("Startup Error", "Could not find dependencies.py.\nEnsure all required files are present.")
        root_err.destroy()
    except Exception:
        pass # Fallback to console output
    sys.exit(1)

if not check_dependencies():
    sys.exit(1) # Exit if dependency check fails (check_dependencies shows the error)

# --- Import Main App Class (after dependency check) ---
try:
    from cryptlink_app import CryptLinkApp
except ImportError as e:
    print(f"ERROR: Failed to import CryptLinkApp from cryptlink_app.py: {e}", file=sys.stderr)
    print("Ensure all .py files are in the same directory.", file=sys.stderr)
    try:
        root_err = tk.Tk()
        root_err.withdraw()
        tk.messagebox.showerror("Startup Error", f"Could not import CryptLinkApp: {e}\nEnsure all required files are present.")
        root_err.destroy()
    except Exception:
        pass # Fallback to console output
    sys.exit(1)


# --- Main Execution ---
if __name__ == "__main__":
    root = tk.Tk()
    # Keep the root window hidden initially until the app is created
    # This prevents a blank window flashing briefly if there's an error
    # during CryptLinkApp initialization.
    root.withdraw()

    try:
        app = CryptLinkApp(root)
        # Now show the window
        root.deiconify()
        root.mainloop()
    except Exception as e:
        print(f"\nFATAL ERROR during application startup: {e}", file=sys.stderr)
        # Try to show a final error message box
        try:
            root_err = tk.Tk()
            root_err.withdraw()
            tk.messagebox.showerror("Fatal Error", f"Application failed to start:\n\n{e}\n\nCheck console for details.")
            root_err.destroy()
        except Exception:
            pass # Fallback to console output
        sys.exit(1)


