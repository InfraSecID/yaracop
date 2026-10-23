#!/usr/bin/env python3
"""
yaracop — YARA Malware Scanner
Usage:
    python scanner.py scan --path /tmp/malware --rules rules/
    python scanner.py scan --path /tmp/malware --rules rules/ --json out.json --summary
    python scanner.py watch --path /tmp/malware --rules rules/ --json live.json
"""

import argparse
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import yara
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"]


def compile_rules(rules_dir):
    rules_path = Path(rules_dir)
    if not rules_path.exists():
        print(f"❌ Rules dir not found: {rules_dir}")
        sys.exit(1)
    rule_files = {}
    for f in list(rules_path.glob("*.yar")) + list(rules_path.glob("*.yara")):
        rule_files[f.stem] = str(f)
    if not rule_files:
        print(f"❌ No .yar/.yara files in {rules_dir}")
        sys.exit(1)
    try:
        rules = yara.compile(filepaths=rule_files)
        print(f"✅ Compiled {len(rule_files)} rule file(s)")
        return rules
    except yara.SyntaxError as e:
        print(f"❌ YARA syntax error: {e}")
        sys.exit(1)


def scan_file(rules, file_path):
    matches = []
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        result = rules.match(data=data)
        for m in result:
            matches.append({
                "rule": m.rule,
                "namespace": m.namespace,
                "tags": list(m.tags),
                "meta": m.meta,
                "file": str(file_path),
            })
    except PermissionError:
        pass
    except Exception as e:
        print(f"⚠️  Error scanning {file_path}: {e}")
    return matches


def make_alert(matches):
    alerts = []
    for m in matches:
        severity = m["meta"].get("severity", "unknown")
        level = 12 if severity == "critical" else (10 if severity == "high" else 7)
        alerts.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule": {
                "id": "100300",
                "level": level,
                "description": f"YARA match: {m['rule']}",
                "groups": ["yara", "malware"],
                "mitre": {"id": m["meta"].get("mitre", ["T1204"])},
            },
            "agent": {"id": "000", "name": "yaracop"},
            "data": {"yara": {
                "rule": m["rule"],
                "file": m["file"],
                "tags": m["tags"],
                "severity": severity,
                "description": m["meta"].get("description", ""),
            }},
            "location": m["file"],
            "full_log": f"YARA rule '{m['rule']}' matched file {m['file']}",
        })
    return alerts


def print_summary(alerts):
    if not alerts:
        print("📊 Summary: no alerts")
        return
    counts = Counter(a["data"]["yara"]["severity"] for a in alerts)
    print("\n📊 Summary by severity:")
    for sev in SEVERITY_ORDER:
        if counts.get(sev):
            print(f"  {sev:10s} : {counts[sev]}")
    print(f"  {'TOTAL':10s} : {len(alerts)}")


def cmd_scan(rules, path, json_output=None, summary=False):
    p = Path(path)
    if not p.exists():
        print(f"❌ Path not found: {path}")
        sys.exit(1)
    files = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file()]
    print(f"🔍 Scanning {len(files)} file(s)...")

    all_matches = []
    for f in files:
        for m in scan_file(rules, f):
            sev = m["meta"].get("severity", "?")
            print(f"🚨 [{sev}] {m['rule']} → {f}")
            all_matches.append(m)

    alerts = make_alert(all_matches) if all_matches else []

    if summary:
        print_summary(alerts)

    if json_output:
        Path(json_output).write_text(json.dumps(alerts, indent=2), encoding="utf-8")
        print(f"💾 Saved to: {json_output}")
    elif alerts:
        print("\n" + json.dumps(alerts, indent=2))
    else:
        print("✅ No matches")


class WatchHandler(FileSystemEventHandler):
    def __init__(self, rules, json_output=None):
        self.rules = rules
        self.json_output = json_output

    def on_created(self, event):
        if not event.is_directory:
            self._check(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._check(event.src_path)

    def _check(self, path):
        matches = scan_file(self.rules, path)
        if not matches:
            return
        for m in matches:
            sev = m["meta"].get("severity", "?")
            print(f"🚨 [{sev}] {m['rule']} → {path}")
        if self.json_output:
            alerts = make_alert(matches)
            out = Path(self.json_output)
            existing = []
            if out.exists():
                try:
                    existing = json.loads(out.read_text())
                except json.JSONDecodeError:
                    existing = []
            existing.extend(alerts)
            out.write_text(json.dumps(existing, indent=2), encoding="utf-8")


def cmd_watch(rules, path, json_output=None):
    p = Path(path)
    if not p.exists():
        print(f"❌ Path not found: {path}")
        sys.exit(1)
    handler = WatchHandler(rules, json_output)
    observer = Observer()
    observer.schedule(handler, str(p), recursive=True)
    observer.start()
    print(f"👁️  Watching: {p}")
    if json_output:
        print(f"💾 Appending to: {json_output}")
    print("Press Ctrl+C to stop\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n🛑 Stopped")
    observer.join()


def main():
    parser = argparse.ArgumentParser(description="yaracop — YARA Malware Scanner")
    sub = parser.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("scan", help="Scan file/folder")
    sp.add_argument("--path", required=True)
    sp.add_argument("--rules", required=True)
    sp.add_argument("--json", dest="json_output")
    sp.add_argument("--summary", action="store_true")

    wp = sub.add_parser("watch", help="Watch folder")
    wp.add_argument("--path", required=True)
    wp.add_argument("--rules", required=True)
    wp.add_argument("--json", dest="json_output")

    args = parser.parse_args()
    rules = compile_rules(args.rules)

    if args.command == "scan":
        cmd_scan(rules, args.path, args.json_output, args.summary)
    elif args.command == "watch":
        cmd_watch(rules, args.path, args.json_output)


if __name__ == "__main__":
    main()
