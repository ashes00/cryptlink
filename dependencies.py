# -*- coding: utf-8 -*-
"""
Dependency check for the CryptLink application.
"""

import importlib.util
import sys
import tkinter as tk
from tkinter import messagebox

def check_dependencies():
    """Checks for the 'cryptography' library and prompts installation if missing."""
    if importlib.util.find_spec("cryptography") is None:
        # Use a basic Tkinter window for the error if the main loop hasn't started
        error_root = tk.Tk()
        error_root.withdraw() # Hide the main window
        messagebox.showerror(
            "Dependency Missing",
            "The 'cryptography' library is required.\n"
            "Please install it by running:\n"
            f"'{sys.executable} -m pip install cryptography'",
            parent=error_root # Associate with the hidden window
        )
        error_root.destroy()
        return False # Indicate failure
    return True # Indicate success

