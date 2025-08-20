#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetOps Toolkit Pro: The All-in-One Command Platform

Author: Gemini (Advanced AI Assistant) & User Collaboration
Version: 4.3.3
License: Apache 2.0
"""
from __future__ import print_function
import sys
import os
import subprocess
import venv
import logging
import platform
import shutil
from pathlib import Path

# --- Bootstrap Section ---
# This part of the script is designed to run with standard Python libraries only.
# It sets up the virtual environment and installs dependencies before launching the main app.

def bootstrap_and_launch():
    """
    Ensures a proper virtual environment exists, installs dependencies,
    and then re-launches the main application within that environment.
    """
    project_root = Path(__file__).resolve().parent
    venv_dir = project_root / ".venv-netops-toolkit"
    log_file = project_root / "netops_toolkit.log"

    # Configure logging
    log_format = "%(asctime)s [%(levelname)-7s] %(message)s"
    # Use 'a' for append mode to not overwrite logs on each start
    file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
    file_handler.setFormatter(logging.Formatter(log_format))
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(logging.Formatter(log_format))
    logging.basicConfig(level=logging.INFO, handlers=[file_handler, stream_handler])

    # --- Check if we are already in the correct venv ---
    try:
        in_venv = Path(sys.prefix).resolve() == venv_dir.resolve()
    except Exception:
        in_venv = False

    if in_venv:
        # If we are in the venv, we can proceed to run the GUI
        return

    # --- Environment Setup ---
    if sys.version_info < (3, 8):
        logging.error("Python 3.8 or newer is required to run this application.")
        sys.exit("Python 3.8 or newer is required to run this application.")

    # Check for and clean up a potentially broken venv from a failed previous run
    first_run_marker = venv_dir / ".first_run_complete"
    if venv_dir.exists() and not first_run_marker.exists():
        logging.warning("Detected a stale or incomplete virtual environment. Cleaning up...")
        try:
            shutil.rmtree(venv_dir)
        except OSError as e:
            msg = f"Could not clean up the broken environment at '{venv_dir}'. Please remove it manually and try again. Error: {e}"
            logging.error(msg)
            sys.exit(msg)

    # Create venv if it doesn't exist
    if not venv_dir.exists():
        logging.info(f"Creating virtual environment in '{venv_dir}'...")
        try:
            venv.create(str(venv_dir), with_pip=True)
        except Exception as e:
            msg = f"Failed to create virtual environment. Error: {e}"
            logging.error(msg)
            sys.exit(msg)

    # Define platform-specific paths to executables
    py_exe = str(venv_dir / ('Scripts' if platform.system() == 'Windows' else 'bin') / 'python')
    
    def run_subprocess(command, error_msg):
        logging.info(f"Running command: {' '.join(command)}")
        try:
            # Use text=True for automatic decoding with default encoding, or specify encoding
            result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8', errors='replace')
            logging.info(f"Command successful. STDOUT:\n{result.stdout}")
            if result.stderr:
                logging.warning(f"Command has STDERR:\n{result.stderr}")
        except subprocess.CalledProcessError as e:
            logging.error(f"{error_msg}. Code: {e.returncode}\nSTDOUT:\n{e.stdout}\nSTDERR:\n{e.stderr}")
            print(f"\n--- [ERROR] --- \n{error_msg}. Check logs for details: {log_file}", file=sys.stderr)
            sys.exit(1)
        except FileNotFoundError:
            logging.error(f"Command not found: {command[0]}. Is Python/pip correctly installed and in the system PATH?")
            print(f"\n--- [ERROR] --- \nCommand '{command[0]}' not found. Ensure Python is in your PATH.", file=sys.stderr)
            sys.exit(1)

    logging.info("Installing/upgrading dependencies...")
    
    # Upgrade pip first using the venv's python interpreter
    run_subprocess([py_exe, "-m", "pip", "install", "--upgrade", "pip"], "Failed to upgrade pip.")

    # --- FIX: Added 'numpy' and AI packages to the dependency list ---
    dependencies = [
        "PySide6", "httpx[http2]", "dnspython", "cryptography", "rich",
        "qasync", "python-whois", "psutil", "pyserial", "scapy", "netmiko",
        "pysnmp", "pyyaml", "networkx", "mac-vendor-lookup", "asyncssh",
        "boto3", "openai", "google-generativeai", "ollama", "numpy"
    ]
    
    run_subprocess([py_exe, "-m", "pip", "install"] + dependencies, "Failed to install required dependencies.")
    
    # Mark the setup as complete
    first_run_marker.touch()

    logging.info("Bootstrap complete. Re-launching the application inside the virtual environment...")
    # Replace the current process with the one running from the venv
    os.execv(py_exe, [py_exe, __file__] + sys.argv[1:])


def run_gui():
    """
    Imports the necessary GUI components and starts the application event loop.
    This function is only called once the script is running inside the virtual environment.
    """
    # Add the project root to the path to ensure 'app' module can be found
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    
    import qasync
    from PySide6.QtWidgets import QApplication
    from app.main_window import MainWindow

    app = QApplication(sys.argv)
    loop = qasync.QEventLoop(app)
    
    main_win = MainWindow()
    main_win.show()
    
    with loop:
        sys.exit(loop.run_forever())

def main():
    """
    Main entry point of the application.
    It triggers the bootstrap process and then runs the GUI.
    """
    # The bootstrap will only run if we're not already in the venv.
    # If we are, it returns immediately and run_gui() is called.
    bootstrap_and_launch()
    
    run_gui()


if __name__ == "__main__":
    main()