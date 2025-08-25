#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetOps Toolkit Pro: The All-in-One Command Platform

Author: Gemini (Advanced AI Assistant) & User Collaboration
Version: 5.2.5
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
def bootstrap_and_launch():
    project_root = Path(__file__).resolve().parent
    venv_dir = project_root / ".venv-netops-toolkit"
    log_file = project_root / "netops_toolkit.log"

    # Configure logging
    log_format = "%(asctime)s [%(levelname)-7s] %(message)s"
    file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
    file_handler.setFormatter(logging.Formatter(log_format))
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(logging.Formatter(log_format))
    logging.basicConfig(level=logging.INFO, handlers=[file_handler, stream_handler])

    try:
        in_venv = Path(sys.prefix).resolve() == venv_dir.resolve()
    except Exception:
        in_venv = False

    if in_venv:
        return

    if sys.version_info < (3, 8):
        logging.error("Python 3.8 or newer is required to run this application.")
        sys.exit("Python 3.8 or newer is required to run this application.")

    first_run_marker = venv_dir / ".first_run_complete"
    if venv_dir.exists() and not first_run_marker.exists():
        logging.warning("Detected a stale or incomplete virtual environment. Cleaning up...")
        try:
            shutil.rmtree(venv_dir)
        except OSError as e:
            msg = f"Could not clean up the broken environment at '{venv_dir}'. Please remove it manually and try again. Error: {e}"
            logging.error(msg)
            sys.exit(msg)

    if not venv_dir.exists():
        logging.info(f"Creating virtual environment in '{venv_dir}'...")
        try:
            venv.create(str(venv_dir), with_pip=True)
        except Exception as e:
            msg = f"Failed to create virtual environment. Error: {e}"
            logging.error(msg)
            sys.exit(msg)

    py_exe = str(venv_dir / ('Scripts' if platform.system() == 'Windows' else 'bin') / 'python')
    
    def run_subprocess(command, error_msg, shell=False):
        log_command = command if isinstance(command, str) else ' '.join(command)
        logging.info(f"Running command: {log_command}")
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8', errors='replace', shell=shell)
            logging.info(f"Command successful. STDOUT:\n{result.stdout}")
            if result.stderr:
                logging.warning(f"Command has STDERR:\n{result.stderr}")
        except subprocess.CalledProcessError as e:
            logging.error(f"{error_msg}. Code: {e.returncode}\nSTDOUT:\n{e.stdout}\nSTDERR:\n{e.stderr}")
            print(f"\n--- [ERROR] --- \n{error_msg}. Check logs for details: {log_file}", file=sys.stderr)
            sys.exit(1)
        except FileNotFoundError:
            cmd_name = command if isinstance(command, str) else command[0]
            logging.error(f"Command not found: {cmd_name}. Is it correctly installed and in the system PATH?")
            print(f"\n--- [ERROR] --- \nCommand '{cmd_name}' not found. Ensure it is in your PATH.", file=sys.stderr)
            sys.exit(1)

    if platform.system() == "Linux":
        logging.info("Detected Linux. Checking for external security tools...")
        # FIX: Added libpcap-dev, which is required by scapy for Layer 2 network operations (ARP scans, packet sniffing).
        linux_deps_install_command = "apt-get update && apt-get install -y nikto hydra exploitdb nmap libsnmp-dev libpcap-dev"
        
        if shutil.which("sudo") and os.geteuid() != 0:
            linux_deps_command = ["sudo", "bash", "-c", linux_deps_install_command]
            run_subprocess(linux_deps_command, "Failed to install Linux security tools.")
        elif os.geteuid() == 0:
             run_subprocess(linux_deps_install_command, "Failed to install Linux security tools as root.", shell=True)
        else:
            logging.warning("sudo command not found and not running as root. Please install the required tools manually.")

    logging.info("Installing/upgrading Python dependencies...")
    
    run_subprocess([py_exe, "-m", "pip", "install", "--upgrade", "pip"], "Failed to upgrade pip.")

    dependencies = [
        "PySide6", "httpx[http2]", "dnspython", "cryptography", "rich",
        "qasync", "python-whois", "psutil", "pyserial", "scapy", "netmiko",
        "pysnmp", "pyyaml", "networkx", "mac-vendor-lookup", "asyncssh",
        "boto3", "openai", "google-generativeai", "ollama", "numpy", "dnspython",
        "vulners", "python-wappalyzer", "setuptools", "python-nmap", "easysnmp", "natsort", "tldextract", "yara-python", "pandas", "python-magic"
    ]
    
    run_subprocess([py_exe, "-m", "pip", "install"] + dependencies, "Failed to install required Python dependencies.")
    
    first_run_marker.touch()

    logging.info("Bootstrap complete. Re-launching the application inside the virtual environment...")
    os.execv(py_exe, [py_exe, __file__] + sys.argv[1:])


def run_gui():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    
    if platform.system() == "Linux" and os.geteuid() == 0:
        os.environ['QTWEBENGINE_CHROMIUM_FLAGS'] = '--no-sandbox'

    import qasync
    import asyncio
    from PySide6.QtWidgets import QApplication
    from app.main_window import MainWindow

    app = QApplication(sys.argv)
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)
    
    main_win = MainWindow()
    main_win.show()
    
    with loop:
        sys.exit(loop.run_forever())

def main():
    bootstrap_and_launch()
    run_gui()


if __name__ == "__main__":
    main()
