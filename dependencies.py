# -*- coding: utf-8 -*-
"""
Dependency check for the CryptLink application.
"""

import importlib.util
import sys
import tkinter as tk
from tkinter import messagebox
import subprocess

# (module_name_to_import, package_name_for_pip, friendly_name)
REQUIRED_PACKAGES = [
    ("cryptography", "cryptography", "Cryptography"),
    ("keyring", "keyring", "Keyring")
]

_tk_root_for_popups = None

def _get_hidden_tk_root():
    """Creates or returns a hidden Tk root window for popups."""
    global _tk_root_for_popups
    if _tk_root_for_popups is None or not _tk_root_for_popups.winfo_exists():
        _tk_root_for_popups = tk.Tk()
        _tk_root_for_popups.withdraw()
    return _tk_root_for_popups

def _destroy_hidden_tk_root():
    """Destroys the hidden Tk root if it exists."""
    global _tk_root_for_popups
    if _tk_root_for_popups and _tk_root_for_popups.winfo_exists():
        _tk_root_for_popups.destroy()
    _tk_root_for_popups = None

def _install_package(package_name_for_pip, friendly_name, parent_window):
    """Attempts to install a package using pip."""
    try:
        # Check if pip is available
        try:
            subprocess.run([sys.executable, "-m", "pip", "--version"], check=True, capture_output=True, text=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            messagebox.showerror(
                "Installation Error",
                f"Could not find 'pip'. Please ensure Python and pip are correctly installed and in your system's PATH.\n"
                f"Cannot automatically install '{friendly_name}'.",
                parent=parent_window
            )
            return False

        messagebox.showinfo(
            "Installation",
            f"Attempting to install '{friendly_name}' using pip. This may take a moment.\n"
            f"Command: {sys.executable} -m pip install {package_name_for_pip}",
            parent=parent_window
        )
        process = subprocess.run(
            [sys.executable, "-m", "pip", "install", package_name_for_pip],
            capture_output=True,
            text=True
        )
        if process.returncode == 0:
            messagebox.showinfo(
                "Installation Successful",
                f"'{friendly_name}' installed successfully.\n"
                "You might need to restart the application for the changes to take full effect.",
                parent=parent_window
            )
            importlib.invalidate_caches() # Important for Python to find the new module
            return True
        else:
            error_details = f"Pip command: {sys.executable} -m pip install {package_name_for_pip}\n" \
                            f"Return code: {process.returncode}\n" \
                            f"Output:\n{process.stderr or process.stdout}"
            print(f"ERROR: Failed to install '{friendly_name}'.\n{error_details}") # Log to console
            messagebox.showerror(
                "Installation Failed",
                f"Failed to install '{friendly_name}'. Check the console for details.",
                parent=parent_window
            )
            return False
    except Exception as e:
        messagebox.showerror(
            "Installation Exception",
            f"An unexpected error occurred while trying to install '{friendly_name}':\n{e}",
            parent=parent_window
        )
        return False

def check_dependencies():
    """Checks for required Python libraries and prompts installation if missing."""
    all_ok = True
    root_popup = _get_hidden_tk_root() # Get a hidden root for popups

    for module_name, pip_name, friendly_name in REQUIRED_PACKAGES:
        if importlib.util.find_spec(module_name) is None:
            install_prompt = (
                f"The '{friendly_name}' library is required but not found.\n\n"
                "Do you want to attempt to install it using pip?"
            )
            if messagebox.askyesno(f"Dependency Missing: {friendly_name}", install_prompt, parent=root_popup):
                if not _install_package(pip_name, friendly_name, root_popup) or importlib.util.find_spec(module_name) is None:
                    messagebox.showerror("Dependency Error", f"Failed to install or load '{friendly_name}'. The application cannot continue.", parent=root_popup)
                    all_ok = False
                    break
            else:
                messagebox.showerror("Dependency Required", f"The '{friendly_name}' library is essential. The application cannot continue without it.", parent=root_popup)
                all_ok = False
                break

    _destroy_hidden_tk_root() # Clean up the hidden root
    return all_ok
