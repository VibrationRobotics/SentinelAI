#!/usr/bin/env python3
"""
Docker entrypoint script for SentinelAI.
This Python script replaces the bash script to avoid line ending issues on Windows.
"""
import os
import sys
import subprocess
import time

def wait_for_service(host, port, service_name, max_tries=30):
    """Wait for a service to be ready."""
    import socket
    tries = 0
    while tries < max_tries:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                print(f"{service_name} is ready!")
                return True
        except Exception as e:
            pass
        tries += 1
        print(f"Waiting for {service_name} to be ready... {tries}/{max_tries}")
        time.sleep(2)
    print(f"{service_name} connection failed after {max_tries} attempts")
    return False

def run_snort_connector():
    """Start the Snort IDS Connector."""
    print("Starting Snort IDS Connector...")
    os.makedirs("/app/snort_logs", exist_ok=True)
    
    snort_log_path = os.environ.get("SNORT_LOG_PATH", "/app/snort_logs/alert")
    api_url = os.environ.get("API_URL", "http://web:8000/api/v1/threats/analyze")
    poll_interval = os.environ.get("POLL_INTERVAL", "5")
    batch_mode = os.environ.get("BATCH_MODE", "")
    
    cmd = [
        "python", "/app/tools/snort_connector.py",
        "--log-path", snort_log_path,
        "--api-url", api_url,
        "--poll-interval", poll_interval
    ]
    if batch_mode:
        cmd.extend(batch_mode.split())
    
    os.execvp("python", cmd)

def run_web_app():
    """Start the web application."""
    # Wait for database
    print("Waiting for database to be ready...")
    if not wait_for_service("db", 5432, "Database"):
        sys.exit(1)
    
    # Wait for Redis
    print("Waiting for Redis to be ready...")
    if not wait_for_service("redis", 6379, "Redis"):
        sys.exit(1)
    
    # Create migrations directory if needed
    os.makedirs("/app/alembic/versions", exist_ok=True)
    
    # Run alembic migrations
    if os.path.isdir("/app/alembic/versions"):
        print("Applying database migrations...")
        try:
            subprocess.run(["alembic", "upgrade", "head"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Warning: Alembic migration failed: {e}")
            # Continue anyway - tables might already exist
    
    # Start the application
    print("Starting the application...")
    os.execvp("uvicorn", [
        "uvicorn", "app.main:app",
        "--host", "0.0.0.0",
        "--port", "8000",
        "--reload"
    ])

def main():
    run_mode = os.environ.get("RUN_MODE", "")
    
    if run_mode == "snort-connector":
        run_snort_connector()
    else:
        run_web_app()

if __name__ == "__main__":
    main()
