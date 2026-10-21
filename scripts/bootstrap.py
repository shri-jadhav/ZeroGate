#!/usr/bin/env python3
"""
ZeroGate Cloud - Core Platform Local Bootstrap & Readiness Verification
Phase 1: Keycloak + OAuth2-Proxy + Grafana + Gitea
"""

import sys
import os
import time
import socket
import secrets
import base64
import subprocess
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent

PORTS_TO_CHECK = {
    8080: "Keycloak OIDC IdP",
    4180: "ZeroGate Grafana Access Proxy",
    4181: "ZeroGate Gitea Access Proxy",
}


def check_port_free(port: int) -> bool:
    """Check whether a given port is free on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def ensure_env_file():
    """Ensure .env exists with strong random secrets."""
    env_file = WORKSPACE_ROOT / ".env"
    env_example = WORKSPACE_ROOT / ".env.example"

    if env_file.exists():
        print("[+] Existing .env file detected.")
        return

    print("[*] Generating secure local .env from .env.example...")
    grafana_client_secret = secrets.token_hex(16)
    gitea_client_secret = secrets.token_hex(16)
    grafana_cookie_secret = secrets.token_hex(16)  # Exactly 32 hex chars = 32 bytes
    gitea_cookie_secret = secrets.token_hex(16)    # Exactly 32 hex chars = 32 bytes
    admin_pw = f"ZG_Admin_{secrets.token_urlsafe(12)}!"
    pg_pw = f"ZG_PG_{secrets.token_urlsafe(12)}!"
    grafana_pw = f"ZG_Graf_{secrets.token_urlsafe(12)}!"
    gitea_pw = f"ZG_Git_{secrets.token_urlsafe(12)}!"

    content = f"""# ZeroGate Local Environment Secrets
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD={admin_pw}

POSTGRES_DB=keycloak
POSTGRES_USER=keycloak
POSTGRES_PASSWORD={pg_pw}

GRAFANA_CLIENT_SECRET={grafana_client_secret}
GITEA_CLIENT_SECRET={gitea_client_secret}

GRAFANA_COOKIE_SECRET={grafana_cookie_secret}
GITEA_COOKIE_SECRET={gitea_cookie_secret}

GRAFANA_ADMIN_PASSWORD={grafana_pw}
GITEA_ADMIN_PASSWORD={gitea_pw}

TEST_USER_PASSWORD=ZeroGate@2026Pass!
"""
    env_file.write_text(content, encoding="utf-8")
    print(f"[+] Created {env_file.name} with unique local development secrets.")


def verify_docker_ready():
    """Verify Docker daemon is reachable."""
    print("[*] Verifying Docker daemon connectivity...")
    try:
        res = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if res.returncode != 0:
            print("[-] Docker is not running or unreachable:", res.stderr.strip())
            sys.exit(1)
        print("[+] Docker daemon is operational.")
    except Exception as e:
        print(f"[-] Failed to execute docker command: {e}")
        sys.exit(1)


def verify_ports():
    """Check required host ports for conflicts before spinning up containers."""
    print("[*] Checking host port availability...")
    conflicts = []
    for port, name in PORTS_TO_CHECK.items():
        if not check_port_free(port):
            # Check if it's already one of our own running containers
            conflicts.append((port, name))

    if conflicts:
        print("[-] Notice: The following ports are currently occupied:")
        for p, name in conflicts:
            print(f"    - Port {p} ({name})")
        print("[*] If ZeroGate containers are already running, this is expected.")
    else:
        print("[+] All required ports (8080, 4180, 4181) are free.")


def start_services():
    """Run docker compose up -d."""
    print("[*] Launching ZeroGate Core Platform services via Docker Compose...")
    cmd = ["docker", "compose", "up", "-d"]
    res = subprocess.run(cmd, cwd=WORKSPACE_ROOT, check=False)
    if res.returncode != 0:
        print("[-] Failed to start Docker Compose services.")
        sys.exit(res.returncode)
    print("[+] Containers initiated.")


def wait_for_readiness(timeout_secs: int = 120):
    """Wait for Keycloak, Grafana proxy, and Gitea proxy to become responsive."""
    import urllib.request
    import urllib.error

    print(f"[*] Waiting for core services to become ready (max {timeout_secs}s)...")
    start = time.time()

    services_to_probe = [
        ("Keycloak OIDC Realm", "http://localhost:8080/realms/zerogate", [200]),
        ("Keycloak OIDC Discovery", "http://localhost:8080/realms/zerogate/.well-known/openid-configuration", [200]),
        ("Grafana Access Proxy Ping", "http://localhost:4180/ping", [200]),
        ("Gitea Access Proxy Ping", "http://localhost:4181/ping", [200]),
    ]

    for name, url, valid_codes in services_to_probe:
        print(f"    - Probing {name} at {url}...", end="", flush=True)
        ready = False
        while time.time() - start < timeout_secs:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "ZeroGate-Bootstrap"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    if resp.status in valid_codes:
                        ready = True
                        print(f" READY ({resp.status})")
                        break
            except (urllib.error.HTTPError, urllib.error.URLError, ConnectionResetError, TimeoutError, OSError):
                time.sleep(2)
        if not ready:
            print(" TIMEOUT!")
            print(f"[-] Service {name} did not become ready within {timeout_secs} seconds.")
            print("[*] Checking container logs:")
            subprocess.run(["docker", "compose", "logs", "--tail=20"], cwd=WORKSPACE_ROOT)
            return False

    print("[+] All ZeroGate Phase 1 core services are healthy and operational!")
    return True


if __name__ == "__main__":
    ensure_env_file()
    verify_docker_ready()
    verify_ports()
    start_services()
    success = wait_for_readiness()
    if not success:
        sys.exit(1)
    print("\n[+] ZeroGate Phase 1 bootstrap completed successfully.")
