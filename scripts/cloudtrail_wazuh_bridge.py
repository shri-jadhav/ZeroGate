"""
ZeroGate Cloud — CloudTrail to Wazuh SIEM Audit Bridge (Phase 4)
Retrieves recent AWS CloudTrail management events (or formats verified CloudTrail records)
and forwards structured, redacted audit events to Wazuh Manager over UDP port 514.
"""

from __future__ import annotations

import json
import socket
import time
from typing import Any, Dict, List, Optional

import boto3


def format_cloudtrail_event_for_wazuh(event: Dict[str, Any]) -> str:
    """
    Converts an AWS CloudTrail event record into a structured syslog line
    decoded by the 'zerogate-cloudtrail' Wazuh decoder.
    """
    event_name = event.get("EventName") or event.get("eventName") or "UnknownEvent"
    event_source = event.get("EventSource") or event.get("eventSource") or "aws.amazonaws.com"
    username = event.get("Username") or event.get("userIdentity", {}).get("arn", "UnknownPrincipal")
    # Sanitize spaces in principal
    principal = str(username).replace(" ", "_")

    # Determine status (Success vs AccessDenied/ErrorCode)
    raw_ct = event.get("CloudTrailEvent")
    error_code = event.get("errorCode")
    if raw_ct and isinstance(raw_ct, str):
        try:
            parsed = json.loads(raw_ct)
            error_code = parsed.get("errorCode")
            region = parsed.get("awsRegion", "ap-south-1")
        except json.JSONDecodeError:
            region = "ap-south-1"
    else:
        region = event.get("awsRegion", "ap-south-1")

    if error_code and ("AccessDenied" in str(error_code) or "Unauthorized" in str(error_code)):
        tag = "CLOUDTRAIL_DENIED"
        status = "AccessDenied"
    elif error_code:
        tag = "CLOUDTRAIL_ERROR"
        status = str(error_code).replace(" ", "_")
    else:
        tag = "CLOUDTRAIL_AUDIT"
        status = "Success"

    ts = time.strftime("%b %d %H:%M:%S")
    return (
        f"{ts} zerogate-cloud cloudtrail: {tag} "
        f"event={event_name} source={event_source} principal={principal} "
        f"status={status} region={region}\n"
    )


def forward_cloudtrail_events_to_wazuh(
    region_name: str = "ap-south-1",
    max_results: int = 10,
    wazuh_host: str = "127.0.0.1",
    wazuh_port: int = 514,
    ct_client: Optional[Any] = None,
) -> List[str]:
    client = ct_client or boto3.client("cloudtrail", region_name=region_name)
    resp = client.lookup_events(MaxResults=max_results)
    events = resp.get("Events", [])
    forwarded_lines: List[str] = []

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2.0)
        for ev in events:
            line = format_cloudtrail_event_for_wazuh(ev)
            sock.sendto(line.encode("utf-8"), (wazuh_host, wazuh_port))
            forwarded_lines.append(line)

    return forwarded_lines
