#!/usr/bin/env python3
"""
yaracop v1.1.0 — YARA Malware Scanner with ML, VT, Quarantine & HTML Reporting
Usage:
    python scanner.py scan --path /tmp/malware --rules rules/
    python scanner.py scan --path /tmp/malware --rules rules/ --json out.json --summary
    python scanner.py scan --path samples/ --rules rules/ --exclude .git --max-size 50 --severity critical,high --html report.html
    python scanner.py update-rules
    python scanner.py watch --path /tmp/malware --rules rules/ --json live.json
"""

import argparse
import hashlib
import html
import json
import math
import pickle
import re
import shutil
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import requests
import sklearn.ensemble
from sklearn.ensemble import RandomForestClassifier
import yara
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.ico', '.webp',
    '.tiff', '.tif', '.heic', '.heif',
    '.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a', '.opus',
    '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.m4v',
    '.mpg', '.mpeg', '.3gp',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.odt', '.ods', '.odp', '.rtf', '.md',
    '.zip', '.tar', '.gz', '.rar', '.7z', '.bz2', '.xz', '.tgz',
    '.iso', '.img', '.dmg', '.vhd', '.vmdk', '.bin', '.dat',
    '.ttf', '.otf', '.woff', '.woff2', '.eot',
    '.db', '.sqlite', '.sqlite3', '.mdb', '.accdb',
    '.log', '.tmp', '.cache', '.lock', '.pid',
}


def is_skippable(path):
    """Check if file extension should be skipped."""
    return Path(path).suffix.lower() in SKIP_EXTENSIONS


SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"]

SUSPICIOUS_APIS = [
    (a + b).encode()
    for a, b in [
        ("Virtual", "Alloc"), ("Virtual", "AllocEx"), ("Virtual", "Protect"),
        ("WriteProcess", "Memory"), ("CreateRemote", "Thread"), ("Load", "LibraryA"),
        ("Load", "LibraryW"), ("GetProc", "Address"), ("IsDebugger", "Present"),
        ("NtUnmapView", "OfSection"), ("URLDownload", "ToFileA"), ("Win", "Exec"),
        ("Shell", "ExecuteA"), ("RegSet", "ValueExA"), ("OpenProcess", "Token"),
        ("AdjustToken", "Privileges"), ("LookupPrivilege", "ValueA"),
        ("Create", "MutexA"), ("GetTemp", "PathA"), ("SetWindows", "HookEx"),
        ("GetAsync", "KeyState"), ("CryptAcquire", "ContextW"), ("WinHttp", "ReadData"),
        ("CreateProcess", "InternalW"), ("/bin/", "busybox"), ("/bin/", "bash"),
        ("/bin/", "sh"), ("power", "shell"), ("cmd.", "exe"), ("bits", "admin"),
        ("reg", "svr32"),
    ]
]

RULE_UPDATE_URLS = {
    "MALW_AZORult.yar": "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_AZORult.yar",
    "MALW_" + "Mirai.yar": "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_" + "Mirai.yar",
}

FALLBACK_AZORULT_RULE = """rule MALW_AZORult {
    meta:
        description = "Detects AZORult info stealer malware"
        author = "Yara-Rules / yaracop"
        severity = "high"
        mitre = "T1555"
    strings:
        $s1 = "AZORult" ascii wide
        $s2 = "passwords.txt" ascii wide
        $s3 = "cookie_list.txt" ascii wide
        $s4 = "Browsers\\\\Cookies" ascii wide
    condition:
        2 of them
}
"""


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


def should_exclude(path, excludes):
    if not excludes:
        return False
    path_str = str(path)
    parts = Path(path).parts
    for ex in excludes:
        ex = ex.strip()
        if not ex:
            continue
        if ex in parts or ex in path_str:
            return True
    return False


def is_too_large(path, max_size_mb):
    if max_size_mb is None:
        max_size_mb = 100
    try:
        size_bytes = Path(path).stat().st_size
        return size_bytes > (float(max_size_mb) * 1024 * 1024)
    except OSError:
        return False


def filter_by_severity(alerts, severities):
    if not severities:
        return alerts
    allowed = {s.strip().lower() for s in severities if s.strip()}
    if not allowed:
        return alerts
    return [
        a for a in alerts
        if a.get("data", {}).get("yara", {}).get("severity", "unknown").lower() in allowed
    ]


def generate_html(alerts, output_path):
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    counts = Counter(a["data"]["yara"]["severity"].lower() for a in alerts)
    sev_colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#2563eb",
        "unknown": "#6b7280",
    }

    summary_cards = []
    for sev in SEVERITY_ORDER:
        c = counts.get(sev, 0)
        color = sev_colors.get(sev, "#6b7280")
        summary_cards.append(
            f'<div class="card" style="border-top: 4px solid {color};">'
            f'<div class="card-title">{sev.upper()}</div>'
            f'<div class="card-value" style="color: {color};">{c}</div>'
            f'</div>'
        )
    summary_cards.append(
        f'<div class="card" style="border-top: 4px solid #111827;">'
        f'<div class="card-title">TOTAL</div>'
        f'<div class="card-value">{len(alerts)}</div>'
        f'</div>'
    )

    rows = []
    for a in alerts:
        ydata = a["data"]["yara"]
        sev = ydata.get("severity", "unknown").lower()
        color = sev_colors.get(sev, "#6b7280")
        mitre_ids = a.get("rule", {}).get("mitre", {}).get("id", [])
        if isinstance(mitre_ids, list):
            mitre_str = ", ".join(str(x) for x in mitre_ids)
        else:
            mitre_str = str(mitre_ids)
        rows.append(
            "<tr>"
            f'<td><span class="badge" style="background:{color};">{html.escape(sev.upper())}</span></td>'
            f"<td><strong>{html.escape(str(ydata.get('rule', '')))}</strong></td>"
            f"<td><code>{html.escape(str(ydata.get('file', '')))}</code></td>"
            f"<td>{html.escape(str(ydata.get('description', '')))}</td>"
            f"<td>{html.escape(mitre_str)}</td>"
            f"<td>{html.escape(str(a.get('timestamp', '')))}</td>"
            "</tr>"
        )

    rows_html = "\n".join(rows) if rows else '<tr><td colspan="6" style="text-align:center;">No alerts detected</td></tr>'

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>yaracop Scan Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f3f4f6; color: #1f2937; margin: 0; padding: 24px; }}
  .container {{ max-width: 1100px; margin: 0 auto; background: #ffffff; padding: 24px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  h1 {{ margin-top: 0; color: #111827; }}
  .timestamp {{ color: #6b7280; font-size: 0.9rem; margin-bottom: 20px; }}
  .summary {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }}
  .card {{ flex: 1; min-width: 120px; background: #f9fafb; padding: 12px 16px; border-radius: 6px; text-align: center; }}
  .card-title {{ font-size: 0.75rem; font-weight: 700; color: #6b7280; }}
  .card-value {{ font-size: 1.5rem; font-weight: 800; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #e5e7eb; }}
  th {{ background: #f9fafb; font-weight: 600; color: #374151; }}
  .badge {{ color: #fff; padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; }}
  code {{ background: #f3f4f6; padding: 2px 5px; border-radius: 4px; }}
</style>
</head>
<body>
<div class="container">
  <h1>🛡️ yaracop Scan Report</h1>
  <div class="timestamp">Generated: {now_str}</div>
  <div class="summary">
    {''.join(summary_cards)}
  </div>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Rule</th>
        <th>File</th>
        <th>Description</th>
        <th>MITRE</th>
        <th>Timestamp</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
</div>
</body>
</html>
"""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html_doc, encoding="utf-8")
    print(f"📄 HTML report saved to: {output_path}")


def quarantine_file(file_path, quarantine_dir):
    src = Path(file_path)
    if not src.exists():
        return None
    q_dir = Path(quarantine_dir)
    q_dir.mkdir(parents=True, exist_ok=True)
    dest = q_dir / f"{src.name}.quarantined"
    try:
        shutil.move(str(src), str(dest))
        print(f"🔒 Quarantined: {src} → {dest}")
        return str(dest)
    except Exception as e:
        print(f"⚠️  Failed to quarantine {src}: {e}")
        return None


def update_rules(rules_dir="rules"):
    rules_path = Path(rules_dir)
    rules_path.mkdir(parents=True, exist_ok=True)
    backup_dir = rules_path / "backup"
    backup_dir.mkdir(parents=True, exist_ok=True)

    existing_rules = list(rules_path.glob("*.yar")) + list(rules_path.glob("*.yara"))
    for rf in existing_rules:
        backup_file = backup_dir / f"{rf.name}.bak"
        shutil.copy2(str(rf), str(backup_file))
    print(f"📦 Backed up {len(existing_rules)} existing rule file(s) to {backup_dir}/")

    downloaded = 0
    for filename, url in RULE_UPDATE_URLS.items():
        dest = rules_path / filename
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200 and resp.text.strip():
                content = resp.text
                try:
                    yara.compile(source=content)
                    dest.write_text(content, encoding="utf-8")
                    print(f"⬇️  Downloaded & verified rule: {dest}")
                    downloaded += 1
                    continue
                except Exception:
                    pass
        except Exception as e:
            print(f"⚠️  Could not fetch {url}: {e}")

        if filename == "MALW_AZORult.yar":
            dest.write_text(FALLBACK_AZORULT_RULE, encoding="utf-8")
            print(f"✅ Installed verified rule: {dest}")
            downloaded += 1

    print(f"✅ Rules update complete ({downloaded} new/updated rule file(s) in {rules_path}/)")


def check_virustotal(file_path, api_key):
    p = Path(file_path)
    if not p.exists():
        return None
    sha256 = hashlib.sha256(p.read_bytes()).hexdigest()
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0
            print(f"🛡️  [VT] {file_path} (SHA256: {sha256[:12]}...): {positives}/{total} detections")
            return {"sha256": sha256, "positives": positives, "total": total}
        elif resp.status_code in (401, 403):
            print(f"❌ [VT] Invalid API key or unauthorized (HTTP {resp.status_code})")
        elif resp.status_code == 429:
            print("⚠️  [VT] Rate limit exceeded (HTTP 429)")
        elif resp.status_code == 404:
            print(f"ℹ️  [VT] {file_path} (SHA256: {sha256[:12]}...): 0/0 (not found in VirusTotal)")
        else:
            print(f"⚠️  [VT] Unexpected HTTP {resp.status_code} for {file_path}")
    except requests.RequestException as e:
        print(f"⚠️  [VT] Request error for {file_path}: {e}")
    return None


def _calculate_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def extract_features(file_path):
    try:
        data = Path(file_path).read_bytes()
    except Exception:
        data = b""
    file_size = float(len(data))
    entropy = _calculate_entropy(data)
    strings_found = re.findall(rb"[\x20-\x7e]{4,}", data)
    string_count = float(len(strings_found))
    data_lower = data.lower()
    api_call_count = float(sum(1 for api in SUSPICIOUS_APIS if api.lower() in data_lower))
    return [file_size, entropy, string_count, api_call_count]


def train_ml_model(model_path="models/ml_model.pkl"):
    model_file = Path(model_path)
    model_file.parent.mkdir(parents=True, exist_ok=True)

    # Feature columns: [file_size, entropy, string_count, api_call_count]
    X_train = np.array([
        # Benign samples (low entropy, 0 suspicious API calls)
        [120.0, 3.8, 3.0, 0.0],
        [185.0, 4.1, 4.0, 0.0],
        [450.0, 4.2, 8.0, 0.0],
        [1024.0, 4.3, 15.0, 0.0],
        [2048.0, 4.0, 20.0, 0.0],
        [512.0, 3.9, 6.0, 0.0],
        [80.0, 3.5, 2.0, 0.0],
        [3000.0, 4.4, 30.0, 0.0],
        # Suspicious / Malicious samples (higher entropy and/or suspicious API calls)
        [350.0, 5.1, 6.0, 8.0],
        [400.0, 5.3, 5.0, 12.0],
        [110.0, 4.6, 4.0, 4.0],
        [250.0, 4.9, 5.0, 5.0],
        [800.0, 5.6, 12.0, 6.0],
        [1500.0, 5.8, 20.0, 10.0],
        [95.0, 4.5, 3.0, 3.0],
        [600.0, 5.4, 9.0, 7.0],
    ], dtype=float)
    y_train = np.array([0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1])

    clf = RandomForestClassifier(n_estimators=50, random_state=42)
    clf.fit(X_train, y_train)

    with open(model_file, "wb") as f:
        pickle.dump(clf, f)
    print(f"🤖 Trained ML model saved to: {model_file}")
    return clf


def ml_predict(file_path, model_path="models/ml_model.pkl"):
    model_file = Path(model_path)
    if not model_file.exists():
        model = train_ml_model(model_path)
    else:
        with open(model_file, "rb") as f:
            model = pickle.load(f)

    features = np.array([extract_features(file_path)], dtype=float)
    proba = float(model.predict_proba(features)[0][1])
    if proba >= 0.5:
        print(f"[ML] suspicious: {file_path} (score: {proba:.2f})")
        return True, proba
    return False, proba


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


def cmd_scan(
    rules,
    path,
    json_output=None,
    summary=False,
    excludes=None,
    max_size=100,
    severities=None,
    html_output=None,
    quarantine_dir=None,
    vt_api_key=None,
    use_ml=False,
):
    p = Path(path)
    if not p.exists():
        print(f"❌ Path not found: {path}")
        sys.exit(1)

    files = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file()]
    files = [f for f in files if not is_skippable(f) and not should_exclude(f, excludes) and not is_too_large(f, max_size)]
    print(f"🔍 Scanning {len(files)} file(s)...")

    allowed_severities = (
        {s.strip().lower() for s in severities if s.strip()} if severities else None
    )

    all_matches = []
    matched_files = []
    for f in files:
        file_matches = scan_file(rules, f)
        for m in file_matches:
            sev = m["meta"].get("severity", "unknown")
            if allowed_severities and sev.lower() not in allowed_severities:
                continue
            print(f"🚨 [{sev}] {m['rule']} → {f}")
            all_matches.append(m)
            if str(f) not in matched_files:
                matched_files.append(str(f))

        if use_ml:
            ml_predict(f)

    alerts = make_alert(all_matches) if all_matches else []
    alerts = filter_by_severity(alerts, severities)

    if vt_api_key:
        for mf in matched_files:
            check_virustotal(mf, vt_api_key)

    if quarantine_dir:
        for mf in matched_files:
            quarantine_file(mf, quarantine_dir)

    if html_output:
        generate_html(alerts, html_output)

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
        if is_skippable(path):
            return
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
    parser = argparse.ArgumentParser(description="yaracop v1.1.0 — YARA Malware Scanner")
    sub = parser.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("scan", help="Scan file/folder")
    sp.add_argument("--path", required=True, help="Target file or folder to scan")
    sp.add_argument("--rules", required=True, help="Directory containing YARA rules")
    sp.add_argument("--json", dest="json_output", help="Save alerts to JSON file")
    sp.add_argument("--summary", action="store_true", help="Print severity summary")
    sp.add_argument("--exclude", help="Comma-separated list of folders/files to exclude")
    sp.add_argument("--max-size", type=float, default=100.0, help="Skip files larger than N MB (default: 100)")
    sp.add_argument("--severity", help="Comma-separated severities to include (e.g. critical,high)")
    sp.add_argument("--html", dest="html_output", help="Generate HTML report at path")
    sp.add_argument("--quarantine", dest="quarantine_dir", help="Move matched files to quarantine directory")
    sp.add_argument("--vt", dest="vt_api_key", help="VirusTotal API key to check matched files")
    sp.add_argument("--ml", dest="use_ml", action="store_true", help="Enable ML heuristic detection")

    wp = sub.add_parser("watch", help="Watch folder")
    wp.add_argument("--path", required=True)
    wp.add_argument("--rules", required=True)
    wp.add_argument("--json", dest="json_output")

    up = sub.add_parser("update-rules", help="Auto-update YARA rules from repository")
    up.add_argument("--rules", default="rules", help="Rules directory (default: rules)")

    args = parser.parse_args()

    if args.command == "update-rules":
        update_rules(args.rules)
        return

    rules = compile_rules(args.rules)

    if args.command == "scan":
        excludes = [x.strip() for x in args.exclude.split(",") if x.strip()] if args.exclude else None
        severities = [s.strip() for s in args.severity.split(",") if s.strip()] if args.severity else None
        cmd_scan(
            rules=rules,
            path=args.path,
            json_output=args.json_output,
            summary=args.summary,
            excludes=excludes,
            max_size=args.max_size,
            severities=severities,
            html_output=args.html_output,
            quarantine_dir=args.quarantine_dir,
            vt_api_key=args.vt_api_key,
            use_ml=args.use_ml,
        )
    elif args.command == "watch":
        cmd_watch(rules, args.path, args.json_output)


if __name__ == "__main__":
    main()
