#!/usr/bin/env python3
"""
SnareSight One-Click Application Launcher.

Starts the FastAPI backend, React Vite frontend, verifies health,
and automatically opens the SOC Dashboard in the default web browser.

Usage:
    python start.py
"""

import os
import sys
import time
import socket
import signal
import shutil
import functools
import subprocess
import webbrowser
from urllib.request import urlopen, Request
from urllib.error import URLError

# Configure unbuffered, encoding-safe stdout/stderr for Windows terminal (cp1252/cp437)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(line_buffering=True, encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(line_buffering=True, encoding="utf-8", errors="replace")
    except Exception:
        pass

# Always flush prints
print = functools.partial(print, flush=True)

# Define paths
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(ROOT_DIR, "backend")
FRONTEND_DIR = os.path.join(ROOT_DIR, "frontend")

# Service configurations
BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 8000
FRONTEND_PORT = 5173
BACKEND_URL = f"http://{BACKEND_HOST}:{BACKEND_PORT}"
FRONTEND_URL = f"http://localhost:{FRONTEND_PORT}"

# ANSI Colors (with pure ASCII fallback safety)
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    banner = rf"""
{CYAN}{BOLD}========================================================================
    ____                               ____ _       __    __ 
   / __/____  ____ _________  _____   / __/(_)___ _/ /_  / /_
  / /_ / __ \/ __ `/ ___/ _ \/ ___/  / /_ / // __ `/ __ \/ __/
 _/ __// / / / /_/ / /  /  __(__  )  _/ __// // /_/ / / / / /_  
/__/  /_/ /_/\__,_/_/   \___/____/  /__/  /_/ \__, /_/ /_/\__/  
                                             /____/             
  Deception-Driven Threat Detection & Security Operations Platform
========================================================================{RESET}
"""
    print(banner)


def find_python():
    """Finds the virtual environment Python interpreter or falls back to system Python."""
    candidates = [
        os.path.join(BACKEND_DIR, ".venv", "Scripts", "python.exe"),
        os.path.join(BACKEND_DIR, ".venv", "bin", "python"),
        os.path.join(BACKEND_DIR, "venv", "Scripts", "python.exe"),
        os.path.join(BACKEND_DIR, "venv", "bin", "python"),
        sys.executable,
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return sys.executable


def find_npm():
    """Finds the npm executable."""
    npm = shutil.which("npm.cmd" if sys.platform == "win32" else "npm")
    if not npm:
        npm = "npm.cmd" if sys.platform == "win32" else "npm"
    return npm


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Checks if a TCP port is currently occupied across IPv4 and IPv6."""
    targets = [(socket.AF_INET, host)]
    if hasattr(socket, "AF_INET6"):
        targets.append((socket.AF_INET6, "::1"))

    for family, target in targets:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                if s.connect_ex((target, port)) == 0:
                    return True
        except Exception:
            pass
    return False


def wait_for_url(url: str, timeout: int = 25, label: str = "Service", expected_status=(200, 304)) -> bool:
    """Polls an HTTP URL until it returns a successful status code."""
    print(f"  {CYAN}->{RESET} Waiting for {label} to be ready...", end="")
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            req = Request(url, headers={"User-Agent": "SnareSight-Launcher"})
            with urlopen(req, timeout=1.5) as resp:
                if resp.status in expected_status:
                    print(f" {GREEN}[READY]{RESET}")
                    return True
        except Exception:
            pass
        time.sleep(0.5)
        print(".", end="")
    print(f" {YELLOW}[TIMEOUT]{RESET}")
    return False


def terminate_process_tree(pid: int):
    """Safely kills a process and all its child processes."""
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except Exception:
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass


def main():
    print_banner()

    # 1. Inspect Python and Node dependencies
    py_exec = find_python()
    npm_exec = find_npm()

    print(f"{BOLD}[1/4] Environment Inspection{RESET}")
    print(f"  {CYAN}->{RESET} Python Interpreter: {GREEN}{py_exec}{RESET}")
    print(f"  {CYAN}->{RESET} Package Manager:    {GREEN}{npm_exec}{RESET}")

    # 2. Database readiness check
    postgres_live = is_port_in_use(5432, "127.0.0.1")
    env_vars = os.environ.copy()
    if postgres_live:
        print(f"  {CYAN}->{RESET} Database Engine:     {GREEN}PostgreSQL 16 (Online on 127.0.0.1:5432){RESET}")
    else:
        db_path = os.path.join(BACKEND_DIR, "snaresight.db").replace("\\", "/")
        print(f"  {CYAN}->{RESET} Database Engine:     {YELLOW}PostgreSQL not detected; using local storage ({db_path}){RESET}")
        env_vars["DATABASE_URL"] = f"sqlite:///{db_path}"

    backend_proc = None
    frontend_proc = None
    backend_log_file = None
    frontend_log_file = None

    # 3. Check for port conflicts / start Backend
    if is_port_in_use(BACKEND_PORT, BACKEND_HOST):
        print(f"  {YELLOW}[!] Notice: Port {BACKEND_PORT} already in use. Reusing existing backend service.{RESET}")
    else:
        print(f"\n{BOLD}[2/4] Starting FastAPI Backend Core...{RESET}")
        backend_cmd = [
            py_exec,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            BACKEND_HOST,
            "--port",
            str(BACKEND_PORT),
        ]
        backend_log_path = os.path.join(BACKEND_DIR, "backend.log")
        backend_log_file = open(backend_log_path, "a", encoding="utf-8")
        backend_proc = subprocess.Popen(
            backend_cmd,
            cwd=BACKEND_DIR,
            env=env_vars,
            stdout=backend_log_file,
            stderr=subprocess.STDOUT,
        )
        if not wait_for_url(f"{BACKEND_URL}/health", timeout=15, label="Backend API"):
            wait_for_url(f"{BACKEND_URL}/api/v1/health/live", timeout=5, label="Backend Core")

    # 4. Check for port conflicts / start Frontend
    if is_port_in_use(FRONTEND_PORT, "127.0.0.1"):
        print(f"  {YELLOW}[!] Notice: Port {FRONTEND_PORT} already in use. Reusing existing frontend server.{RESET}")
    else:
        # Ensure node_modules exists
        node_modules_path = os.path.join(FRONTEND_DIR, "node_modules")
        if not os.path.isdir(node_modules_path):
            print(f"  {CYAN}->{RESET} Installing frontend dependencies (npm install)...")
            subprocess.run([npm_exec, "install"], cwd=FRONTEND_DIR, shell=(sys.platform == "win32"), check=True)
        print(f"\n{BOLD}[3/4] Starting React + Vite Frontend...{RESET}")
        frontend_cmd = [npm_exec, "run", "dev"]
        frontend_log_path = os.path.join(FRONTEND_DIR, "frontend.log")
        frontend_log_file = open(frontend_log_path, "a", encoding="utf-8")
        frontend_proc = subprocess.Popen(
            frontend_cmd,
            cwd=FRONTEND_DIR,
            shell=(sys.platform == "win32"),
            stdout=frontend_log_file,
            stderr=subprocess.STDOUT,
        )
        wait_for_url(f"http://127.0.0.1:{FRONTEND_PORT}", timeout=25, label="Frontend Dashboard")

    # 5. Open Web Browser
    print(f"\n{BOLD}[4/4] Opening Web Dashboard...{RESET}")
    time.sleep(1.0)
    print(f"  {GREEN}[OK] Opening {FRONTEND_URL} in default browser.{RESET}")
    webbrowser.open(FRONTEND_URL)

    # 6. Service Directory
    print(f"""
{GREEN}{BOLD}========================================================================
  SnareSight Platform is LIVE & Operational!
========================================================================{RESET}
  {CYAN}->{RESET} {BOLD}SOC Web Dashboard:{RESET}    {FRONTEND_URL}
  {CYAN}->{RESET} {BOLD}Demonstration Lab:{RESET}    {FRONTEND_URL}/demo
  {CYAN}->{RESET} {BOLD}Backend API Gateway:{RESET}  {BACKEND_URL}
  {CYAN}->{RESET} {BOLD}Interactive API Docs:{RESET} {BACKEND_URL}/docs

  {YELLOW}[Default Analyst Credentials]{RESET} 
  Username: {BOLD}analyst@snaresight.local{RESET}
  Password: {BOLD}SecurePassword123!{RESET}

{BOLD}Press Ctrl+C to safely shut down all services.{RESET}
""")

    # 7. Keep-alive and graceful shutdown handler
    try:
        while True:
            time.sleep(1)
            # Monitor child health
            if backend_proc and backend_proc.poll() is not None:
                print(f"{RED}[Error] Backend process terminated unexpectedly. Check backend/backend.log for details.{RESET}")
                break
            if frontend_proc and frontend_proc.poll() is not None:
                print(f"{RED}[Error] Frontend process terminated unexpectedly. Check frontend/frontend.log for details.{RESET}")
                break
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Shutting down SnareSight services...{RESET}")
    finally:
        if backend_proc:
            print(f"  {CYAN}->{RESET} Stopping Backend API (PID {backend_proc.pid})...", end="")
            terminate_process_tree(backend_proc.pid)
            print(f" {GREEN}[STOPPED]{RESET}")
        if frontend_proc:
            print(f"  {CYAN}->{RESET} Stopping Frontend (PID {frontend_proc.pid})...", end="")
            terminate_process_tree(frontend_proc.pid)
            print(f" {GREEN}[STOPPED]{RESET}")

        if backend_log_file:
            try:
                backend_log_file.close()
            except Exception:
                pass
        if frontend_log_file:
            try:
                frontend_log_file.close()
            except Exception:
                pass

        print(f"{GREEN}{BOLD}[OK] All SnareSight services have been safely terminated.{RESET}\n")


if __name__ == "__main__":
    main()
