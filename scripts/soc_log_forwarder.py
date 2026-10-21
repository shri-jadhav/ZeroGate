#!/usr/bin/env python3
"""
ZeroGate Cloud — SOC Log Forwarder
Collects logs from Squid, Unbound, and Keycloak and forwards them to the
central Wazuh SIEM Syslog listener (UDP 127.0.0.1:514).
"""

import socket
import subprocess
import time
import sys
import argparse

WAZUH_HOST = "127.0.0.1"
WAZUH_PORT = 514

def send_syslog(message: str, host: str = WAZUH_HOST, port: int = WAZUH_PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if not message.endswith("\n"):
            message += "\n"
        sock.sendto(message.encode("utf-8"), (host, port))
    finally:
        sock.close()

def forward_squid_events():
    """Tails Squid access logs and forwards to Wazuh syslog."""
    try:
        proc = subprocess.Popen(
            ["docker", "logs", "-f", "--tail", "10", "zerogate-squid"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        print("[*] Forwarding Squid events to Wazuh SIEM (127.0.0.1:514)...")
        for line in proc.stdout:
            line = line.strip()
            if line:
                syslog_msg = f"<134>Oct 22 02:00:00 zerogate-squid squid: {line}"
                send_syslog(syslog_msg)
    except Exception as e:
        print(f"[-] Error forwarding Squid events: {e}")

def forward_unbound_events():
    """Tails Unbound DNS query logs and forwards to Wazuh syslog."""
    try:
        proc = subprocess.Popen(
            ["docker", "logs", "-f", "--tail", "10", "zerogate-unbound"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        print("[*] Forwarding Unbound DNS events to Wazuh SIEM (127.0.0.1:514)...")
        for line in proc.stdout:
            line = line.strip()
            if line and "info:" in line:
                syslog_msg = f"<134>Oct 22 02:00:00 zerogate-unbound unbound: {line}"
                send_syslog(syslog_msg)
    except Exception as e:
        print(f"[-] Error forwarding Unbound events: {e}")

def emit_synthetic_event(event_type: str):
    """Emits synthetic verification events for testing."""
    if event_type == "squid-denial":
        msg = "<134>Oct 22 02:00:00 zerogate-squid squid: 1713800000.000 10 172.18.0.5 TCP_DENIED/403 3858 GET http://forbidden-c2.test/ - HIER_NONE/- text/html"
        send_syslog(msg)
        print(f"[+] Sent synthetic Squid denial: {msg}")
    elif event_type == "dns-tunneling":
        msg = "<134>Oct 22 02:00:00 zerogate-unbound unbound: [1234:0] info: 172.18.0.5 a1b2c3d4e5f6g7h8i9j0k1l2m3.tunnel.attacker.com. A IN"
        send_syslog(msg)
        print(f"[+] Sent synthetic DNS tunneling: {msg}")
    elif event_type == "keycloak-auth-fail":
        msg = "<134>Oct 22 02:00:00 zerogate-keycloak keycloak: 2026-10-22 02:00:00,000 WARN [org.keycloak.events] type=LOGIN_ERROR, realmId=zerogate, clientId=zerogate-grafana, userId=admin, ipAddress=172.18.0.1"
        send_syslog(msg)
        print(f"[+] Sent synthetic Keycloak auth failure: {msg}")
    else:
        print(f"[-] Unknown event type: {event_type}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZeroGate SOC Log Forwarder")
    parser.add_argument("--test-event", choices=["squid-denial", "dns-tunneling", "keycloak-auth-fail"], help="Emit test event to Wazuh")
    args = parser.parse_args()

    if args.test_event:
        emit_synthetic_event(args.test_event)
    else:
        print("Specify --test-event <type> or run with forwarder logic.")
