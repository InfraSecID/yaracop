#!/usr/bin/env python3
"""
yaracop — Wazuh + Shuffle Integration
Usage:
    python integration.py wazuh --alert-file hasil.json --manager-url https://localhost:55000 --user wazuh --password wazuh
    python integration.py shuffle --alert-file hasil.json --webhook http://localhost:3001/api/v1/hooks/webhook_xxx
"""

import argparse
import json
import sys
from pathlib import Path

import requests


def load_alert(path):
    p = Path(path)
    if not p.exists():
        print(f"❌ Alert file not found: {path}")
        sys.exit(1)
    data = json.loads(p.read_text())
    return data if isinstance(data, list) else [data]


def send_wazuh(alerts, manager_url, user, password):
    try:
        auth = requests.post(
            f"{manager_url}/security/user/authenticate",
            auth=(user, password), verify=False, timeout=10,
        )
        if auth.status_code != 200:
            print(f"❌ Wazuh auth failed: {auth.status_code}")
            return False
        token = auth.json()["data"]["token"]
        headers = {"Authorization": f"Bearer {token}"}
        ok = 0
        for alert in alerts:
            payload = {
                "log_format": "json",
                "location": alert.get("location", "yaracop"),
                "event": json.dumps(alert),
            }
            r = requests.post(
                f"{manager_url}/logtest", headers=headers,
                json=payload, verify=False, timeout=10,
            )
            if r.status_code == 200:
                ok += 1
        print(f"✅ Sent {ok}/{len(alerts)} alert(s) to Wazuh")
        return ok == len(alerts)
    except requests.RequestException as e:
        print(f"❌ Wazuh error: {e}")
        return False


def send_shuffle(alerts, webhook_url):
    try:
        ok = 0
        for alert in alerts:
            r = requests.post(webhook_url, json=alert, timeout=10)
            if r.status_code in (200, 201, 202):
                ok += 1
        print(f"✅ Sent {ok}/{len(alerts)} alert(s) to Shuffle")
        return ok == len(alerts)
    except requests.RequestException as e:
        print(f"❌ Shuffle error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="yaracop integration")
    sub = parser.add_subparsers(dest="command", required=True)

    wp = sub.add_parser("wazuh")
    wp.add_argument("--alert-file", required=True)
    wp.add_argument("--manager-url", default="https://localhost:55000")
    wp.add_argument("--user", default="wazuh")
    wp.add_argument("--password", default="wazuh")

    sp = sub.add_parser("shuffle")
    sp.add_argument("--alert-file", required=True)
    sp.add_argument("--webhook", required=True)

    args = parser.parse_args()
    alerts = load_alert(args.alert_file)

    if args.command == "wazuh":
        ok = send_wazuh(alerts, args.manager_url, args.user, args.password)
    else:
        ok = send_shuffle(alerts, args.webhook)

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
