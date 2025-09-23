#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetOps Toolkit Pro: The All-in-One Command Platform

Auto bootstrap + environment wiring for Kali/Debian.
- Installs external tools via apt (where available) or pipx (prowler).
- Clones nuclei-templates and persists the path into QSettings.
- Ensures zap.sh is in PATH via symlink.
- Starts ZAP daemon and polls for API readiness (non-blocking fallback).
- Seeds scanner settings (only if empty).
- Re-execs into the venv once everything is staged.

Author: You & Assistant
License: Apache 2.0
"""

from __future__ import annotations

import sys
import os
import subprocess
import venv
import logging
import platform
import shutil
import time
from pathlib import Path
from typing import List

# -------------------------------
# Tiny helpers
# -------------------------------


def _log_setup(project_root: Path) -> None:
    log_file = project_root / "netops_toolkit.log"
    log_format = "%(asctime)s [%(levelname)-7s] %(message)s"
    file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
    file_handler.setFormatter(logging.Formatter(log_format))
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(logging.Formatter(log_format))
    logging.basicConfig(level=logging.INFO, handlers=[file_handler, stream_handler])
    logging.info("Bootstrap starting…")


def _run(cmd, check=True, shell=False, env=None, can_fail=False) -> subprocess.CompletedProcess:
    printable = cmd if isinstance(cmd, str) else " ".join(cmd)
    logging.info("Running: %s", printable)
    try:
        p = subprocess.run(
            cmd, shell=shell, check=check, capture_output=True, text=True, env=env
        )
        if p.stdout:
            logging.info(p.stdout.strip())
        if p.stderr:
            logging.warning(p.stderr.strip())
        return p
    except subprocess.CalledProcessError as e:
        logging.error("Command failed [%s]: %s\nSTDOUT:\n%s\nSTDERR:\n%s",
                      e.returncode, printable, e.stdout, e.stderr)
        if can_fail:
            return e
        raise


def _is_root() -> bool:
    if platform.system() != "Linux":
        return False
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def _sudo_prefix() -> List[str]:
    # Use sudo only when not root and sudo exists
    return [] if _is_root() or shutil.which("sudo") is None else ["sudo"]


def _sudo_run_as(user: str, *args: str) -> List[str]:
    """
    Build a command to run as another user.
    Prefer sudo if available, else runuser.
    """
    if shutil.which("sudo"):
        return ["sudo", "-u", user, "-H", *args]
    elif shutil.which("runuser"):
        return ["runuser", "-u", user, "--", *args]
    else:
        # Fallback: try su -c
        return ["su", "-", user, "-c", " ".join(args)]


def _ensure_symlink(src: Path, dst: Path) -> None:
    try:
        if dst.exists() or dst.is_symlink():
            try:
                if dst.is_symlink() and Path(os.readlink(dst)) != src:
                    dst.unlink(missing_ok=True)
                    dst.symlink_to(src)
            except OSError:
                pass
            return
        if src.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.symlink_to(src)
            logging.info("Symlink created: %s -> %s", dst, src)
    except Exception as e:
        logging.warning("Could not create symlink %s -> %s: %s", dst, src, e)


# -------------------------------
# Bootstrap + environment wiring
# -------------------------------


def bootstrap_and_launch():
    project_root = Path(__file__).resolve().parent
    _log_setup(project_root)

    venv_dir = project_root / ".venv-netops-toolkit"
    py_exe = venv_dir / ('Scripts' if platform.system() == 'Windows' else 'bin') / 'python'

    # Create venv if needed
    if not venv_dir.exists():
        logging.info("Creating virtual environment at %s", venv_dir)
        venv.create(str(venv_dir), with_pip=True)

    # Are we already running inside the venv?
    in_venv = Path(sys.prefix).resolve() == venv_dir.resolve()
    if not in_venv:
        # Install Python deps (base)
        _run([str(py_exe), "-m", "pip", "install", "--upgrade", "pip"])
        # NOTE: easysnmp requires system libraries (net-snmp, swig) to build — we install the dev packages
        _run([
            str(py_exe), "-m", "pip", "install",
            "PySide6", "httpx[http2]", "dnspython", "cryptography", "rich", "qasync",
            "python-whois", "psutil", "pyserial", "scapy", "netmiko", "pysnmp",
            "pyyaml", "networkx", "mac-vendor-lookup", "asyncssh", "boto3", "openai",
            "google-generativeai", "ollama", "numpy", "vulners", "python-wappalyzer",
            "setuptools", "python-nmap", "natsort", "tldextract", "yara-python",
            "pandas", "python-magic", "easysnmp"
        ])

        # Linux: install external CLI tools via apt
        if platform.system() == "Linux":
            logging.info("Installing external tools via apt (Kali/Debian)…")
            _run(_sudo_prefix() + ["apt-get", "update"], can_fail=True)
            apt_tools = [
                "zaproxy", "naabu", "nuclei", "amass", "jq", "curl",
                "nmap", "nikto", "hydra", "exploitdb", "gvm",
                "gvm-tools", "python3-gvm",
                # native build deps for certain Python extensions (SNMP, SWIG for easysnmp)
                "libsnmp-dev", "swig", "build-essential", "python3-dev"
            ]
            # Joining into a single apt-get install call helps avoid multiple prompts
            _run(_sudo_prefix() + ["bash", "-lc", "apt-get install -y " + " ".join(apt_tools)], can_fail=True)

            # prowler via pipx
            logging.info("Attempting Prowler via pipx…")
            _run(_sudo_prefix() + ["bash", "-lc", "apt-get update && apt-get install -y pipx"], can_fail=True)
            _run(_sudo_prefix() + ["bash", "-lc", "pipx ensurepath"], can_fail=True)

            sudo_user = os.environ.get("SUDO_USER")
            if sudo_user:
                # Install prowler for the invoking non-root user
                prowler_cmd = _sudo_run_as(sudo_user, "pipx", "install", "prowler")
                _run(prowler_cmd, can_fail=True)
                user_local_bin = Path(f"/home/{sudo_user}/.local/bin")
                if user_local_bin.exists():
                    os.environ["PATH"] = f"{str(user_local_bin)}:{os.environ.get('PATH','')}"
            else:
                # No sudo_user (running as root directly)
                _run(["pipx", "install", "prowler"], can_fail=True)
                root_local_bin = Path("/root/.local/bin")
                if root_local_bin.exists():
                    os.environ["PATH"] = f"{str(root_local_bin)}:{os.environ.get('PATH','')}"

            # Clone nuclei-templates if missing
            bootstrap_dir = project_root / ".bootstrap"
            nuc_tpl = bootstrap_dir / "nuclei-templates"
            if not nuc_tpl.exists():
                logging.info("Cloning nuclei-templates into %s…", nuc_tpl)
                bootstrap_dir.mkdir(parents=True, exist_ok=True)
                _run(["git", "clone", "--depth", "1",
                      "https://github.com/projectdiscovery/nuclei-templates.git",
                      str(nuc_tpl)], can_fail=True)

        logging.info("Bootstrap complete. Re-launching inside virtualenv…")
        # Re-exec into the newly-created venv Python
        try:
            os.execv(str(py_exe), [str(py_exe), __file__] + sys.argv[1:])
        except Exception as e:
            logging.error("Failed to re-exec into venv python: %s", e)
            raise
        return

    # We are inside venv: finish environment wiring (Linux specific)
    logging.info("Running inside virtualenv; continuing post-setup…")

    if platform.system() == "Linux":
        # 1) Ensure zap.sh is in PATH
        _ensure_symlink(Path("/usr/share/zaproxy/zap.sh"), Path("/usr/local/bin/zap.sh"))

        # 2) Seed QSettings with defaults (only if empty)
        _seed_qsettings_defaults(project_root)

        # 3) Start ZAP and poll API readiness (non-blocking fallback)
        _start_zap_daemon_and_wait()

    # Hand off to GUI
    run_gui()


def _seed_qsettings_defaults(project_root: Path) -> None:
    """
    Seed scanner settings *only if they are empty*:
      - scanner/nuclei_templates_path
      - scanner/zap_api_key (random, if empty)
    """
    try:
        from PySide6.QtCore import QSettings
    except Exception as e:
        logging.warning("Could not import QSettings to seed settings: %s", e)
        return

    settings = QSettings("NetOpsToolkit", "NetOps Toolkit Pro")

    # Nuclei templates path
    tpl_key = "scanner/nuclei_templates_path"
    current_tpl = settings.value(tpl_key, "")
    if not current_tpl:
        tpl_guess = str((project_root / ".bootstrap" / "nuclei-templates").resolve())
        if Path(tpl_guess).exists():
            settings.setValue(tpl_key, tpl_guess)
            logging.info("Seeded nuclei templates path: %s", tpl_guess)

    # ZAP API key
    zap_key_key = "scanner/zap_api_key"
    zap_key = settings.value(zap_key_key, "")
    if not zap_key:
        zap_key = _random_hex(32)
        settings.setValue(zap_key_key, zap_key)
        logging.info("Seeded ZAP API key.")


def _random_hex(nbytes: int) -> str:
    import secrets
    return secrets.token_hex(nbytes)


def _start_zap_daemon_and_wait() -> None:
    """
    Start ZAP daemon if not running and poll the API for up to 40 seconds.
    Skips autostart if the API port is already in use. Uses Popen so we do
    NOT block on the daemon process.
    """
    import socket
    zap_bin = shutil.which("zap.sh")
    if not zap_bin:
        logging.warning("ZAP not found in PATH (zap.sh). Skipping auto-start.")
        return

    # Read API host/port/key
    try:
        from PySide6.QtCore import QSettings
        settings = QSettings("NetOpsToolkit", "NetOps Toolkit Pro")
        zap_host = settings.value("scanner/zap_api_host", "127.0.0.1")
        zap_port = int(settings.value("scanner/zap_api_port", 8090))
        zap_key  = settings.value("scanner/zap_api_key", "") or _random_hex(32)
        settings.setValue("scanner/zap_api_key", zap_key)
    except Exception:
        zap_host, zap_port, zap_key = "127.0.0.1", 8090, _random_hex(32)

    # If port already in use, do NOT try to spawn another ZAP
    s = socket.socket(); s.settimeout(0.5)
    try:
        in_use = s.connect_ex((zap_host, zap_port)) == 0
    except Exception:
        in_use = False
    finally:
        s.close()

    if in_use:
        logging.info("ZAP appears to be running on %s:%d — skipping autostart.", zap_host, zap_port)
        return

    # Launch ZAP (daemon) without waiting — IMPORTANT: use Popen here
    try:
        cmd = [
            zap_bin, "-daemon",
            "-port", str(zap_port),
            "-config", f"api.key={zap_key}",
            "-config", f"api.addrs.addr.name={zap_host}",
            "-config", "api.addrs.addr.regex=false"
        ]
        logging.info("Spawning (non-blocking): %s", " ".join(cmd))
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True
        )
    except Exception as e:
        logging.warning("Failed to spawn ZAP daemon: %s", e)
        return

    # Poll API (non-fatal)
    import urllib.request
    api_url = f"http://{zap_host}:{zap_port}/JSON/core/view/version/"
    t0 = time.time(); timeout = 40.0
    while time.time() - t0 < timeout:
        try:
            with urllib.request.urlopen(api_url, timeout=4) as resp:
                if resp.status == 200:
                    body = resp.read().decode("utf-8", errors="ignore")
                    logging.info("ZAP API reachable: %s", body.strip()[:120]); return
        except Exception:
            time.sleep(1.0)
    logging.warning("ZAP API not reachable after %ss. App will continue; you can start ZAP later.", int(timeout))


# -------------------------------
# GUI bootstrap
# -------------------------------


def run_gui():
    # Make sure our project root is importable
    sys.path.insert(0, str(Path(__file__).resolve().parent))

    # If running GUI as root on Linux, avoid Qt WebEngine sandbox issues
    if platform.system() == "Linux" and _is_root():
        os.environ.setdefault('QTWEBENGINE_CHROMIUM_FLAGS', '--no-sandbox')

    # Ensure optional native deps don't crash import path — give clear warning instead.
    try:
        import qasync
        from PySide6.QtWidgets import QApplication
        # Delay importing application widgets until runtime so missing optional native
        # extensions don't blow up the bootstrap earlier than necessary.
        from app.main_window import MainWindow
    except ModuleNotFoundError as e:
        logging.error("Missing Python module required to launch GUI: %s", e)
        logging.error("If this is easysnmp or another native lib, ensure system libs are installed: libsnmp-dev, swig, build-essential and re-run bootstrap.")
        raise
    except Exception as e:
        logging.exception("Unexpected error while preparing GUI: %s", e)
        raise

    import asyncio

    app = QApplication(sys.argv)
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    main_win = MainWindow()
    main_win.show()

    with loop:
        sys.exit(loop.run_forever())


def main():
    bootstrap_and_launch()


if __name__ == "__main__":
    main()
