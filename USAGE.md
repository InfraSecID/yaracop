# yaracop v1.1.0 — Complete Usage Guide (Local)

## Table of Contents
1. Prerequisites
2. Installation
3. Quick Test
4. Basic Scanning
5. New v1.1.0 Features (`--exclude`, `--max-size`, `--severity`, `--html`, `--quarantine`, `update-rules`, `--vt`, `--ml`)
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
| Scikit-learn & NumPy | `python3 -c "import sklearn, numpy"` | `pip install scikit-learn numpy` |

---

## 2. Installation

### Step 1: Enter directory
```bash
cd ~/yaracop
```

### Step 2: Install Python dependencies
```bash
pip install -r requirements.txt
# Or on externally managed environments:
pip install --break-system-packages -r requirements.txt
```

### Step 3: Verify installation
```bash
python3 scanner.py --help
python3 scanner.py scan --help
```

---

## 3. Quick Test (Using Built-in `samples/`)

```bash
cd ~/yaracop
python3 scanner.py scan --path samples/ --rules rules/ --summary
```

---

## 4. Basic Scanning

### Scan a single file
```bash
python3 scanner.py scan --path samples/malware.txt --rules rules/
```

### Scan a folder (recursive) + JSON + summary
```bash
python3 scanner.py scan --path samples/ --rules rules/ --json result.json --summary
```

---

## 5. New v1.1.0 Features

### 5.1 `--exclude` — Skip Specific Folders or Files
Comma-separated list of path substrings to exclude from scanning:
```bash
python3 scanner.py scan --path ~/yaracop --rules rules/ --exclude rules,.git,__pycache__,node_modules --summary
```

### 5.2 `--max-size` — Skip Large Files
Skip files larger than the specified size in MB (default: `100` MB):
```bash
python3 scanner.py scan --path samples/ --rules rules/ --max-size 50 --summary
```

### 5.3 `--severity` — Filter Alerts by Severity
Only report alerts matching the comma-separated severities (`critical`, `high`, `medium`, `low`):
```bash
python3 scanner.py scan --path samples/ --rules rules/ --severity critical,high --summary
```

### 5.4 `--html` — Generate HTML Report
Create a styled HTML report with severity summary cards and alert table:
```bash
python3 scanner.py scan --path samples/ --rules rules/ --html /tmp/report.html --summary
```

### 5.5 `--quarantine` — Quarantine Malicious Files
Move matched files into a quarantine directory with a `.quarantined` suffix:
```bash
mkdir -p /tmp/quarantine
python3 scanner.py scan --path samples/ --rules rules/ --quarantine /tmp/quarantine
ls -la /tmp/quarantine/
```

### 5.6 `update-rules` — Auto-Update YARA Rules
Backup existing rules to `rules/backup/` and download the latest rules:
```bash
python3 scanner.py update-rules
ls -la rules/
```

### 5.7 `--vt` — VirusTotal Integration
Compute SHA256 for matched files and query VirusTotal API for detection ratios:
```bash
python3 scanner.py scan --path samples/ --rules rules/ --vt YOUR_VIRUSTOTAL_API_KEY
```

### 5.8 `--ml` — Machine Learning Heuristic Detection
Use `scikit-learn` (`RandomForestClassifier` stored in `models/ml_model.pkl`) to detect suspicious files based on file size, Shannon entropy, string count, and suspicious API call count:
```bash
python3 scanner.py scan --path samples/ --rules rules/ --ml --summary
```

---

## 6. Watch Mode (Real-time Detection)

```bash
python3 scanner.py watch --path /tmp/test-malware --rules rules/ --json live.json
```

---

## 7. Wazuh Integration (Optional)

```bash
python3 integration.py wazuh \
  --alert-file alerts.json \
  --manager-url https://localhost:55000 \
  --user wazuh \
  --password wazuh
```

---

## 8. Shuffle Integration (Optional)

```bash
python3 integration.py shuffle \
  --alert-file alerts.json \
  --webhook http://localhost:3001/api/v1/hooks/webhook_abc123
```

---

## 9. Real-World Scenarios

### Scenario A: Full workstation triage with HTML report & ML
```bash
python3 ~/yaracop/scanner.py scan \
  --path ~/Downloads \
  --rules ~/yaracop/rules/ \
  --exclude .git,node_modules \
  --max-size 25 \
  --severity critical,high \
  --ml \
  --html ~/scan-report.html \
  --summary
```

### Scenario B: Automated USB quarantine scan
```bash
python3 ~/yaracop/scanner.py scan \
  --path /media/$USER/USB_DRIVE \
  --rules ~/yaracop/rules/ \
  --quarantine /var/quarantine \
  --json /var/log/yaracop-usb.json \
  --summary
```

---

## 10. Troubleshooting

- **`ModuleNotFoundError: No module named 'sklearn'`**: Run `pip install --break-system-packages -r requirements.txt`
- **False positives when scanning `~/yaracop`**: Use `--exclude rules,.git,__pycache__`
- **VirusTotal `HTTP 401/403`**: Verify your VirusTotal API key passed to `--vt`

---

**yaracop v1.1.0** — YARA Malware Scanner

---

## 📂 Scanning Other Folders

### Scan Downloads
```bash
cd ~/yaracop
python3 scanner.py scan --path ~/Downloads --rules rules/ --summary
```

### Scan Documents
```bash
python3 scanner.py scan --path ~/Documents --rules rules/ --summary
```

### Scan Desktop
```bash
python3 scanner.py scan --path ~/Desktop --rules rules/ --summary
```

### Scan USB Drive
```bash
ls /media/$USER/
python3 scanner.py scan --path /media/$USER/USB_NAME --rules rules/ --summary
```

### Scan Entire Home (safe mode)
```bash
python3 scanner.py scan --path ~ --rules rules/ \
  --exclude .git,__pycache__,node_modules,.cache,.local,rules \
  --max-size 50 \
  --summary
```

### Scan Single File
```bash
python3 scanner.py scan --path ~/Downloads/suspicious.exe --rules rules/ --summary
```

### Scan Project Before Commit
```bash
cd ~/my-project
python3 ~/yaracop/scanner.py scan --path . --rules ~/yaracop/rules/ --summary
```

---

## 🎯 Combo Examples

### Full scan (all features)
```bash
python3 scanner.py scan --path ~/Downloads --rules rules/ \
  --exclude .git,__pycache__ \
  --max-size 50 \
  --severity critical,high \
  --json hasil.json \
  --html report.html \
  --quarantine /tmp/quarantine \
  --ml \
  --summary
```

### Scan + JSON + HTML
```bash
python3 scanner.py scan --path ~/Downloads --rules rules/ \
  --json hasil.json --html report.html --summary
```

### Watch + JSON (real-time)
```bash
python3 scanner.py watch --path ~/Downloads --rules rules/ --json live.json
```

---

## 🌍 Real-World Scenarios

### Scenario A: Scan downloaded file
```bash
cd ~/Downloads
python3 ~/yaracop/scanner.py scan --path . --rules ~/yaracop/rules/ --summary
```

### Scenario B: Scan USB from friend
```bash
ls /media/$USER/
python3 ~/yaracop/scanner.py scan --path /media/$USER/USB_NAME \
  --rules ~/yaracop/rules/ --quarantine /tmp/quarantine --summary
```

### Scenario C: Daily scan with cron
```bash
crontab -e
# Add this line (scan Downloads every day at 2 AM):
0 2 * * * cd ~/yaracop && python3 scanner.py scan --path ~/Downloads --rules rules/ --json ~/scan-$(date +\%Y\%m\%d).json --summary >> ~/scan.log 2>&1
```

### Scenario D: Scan email attachments
```bash
mkdir -p /tmp/attachments
# Extract attachments to /tmp/attachments first
python3 ~/yaracop/scanner.py scan --path /tmp/attachments --rules ~/yaracop/rules/ --summary
```

---

## 🐛 Troubleshooting (Expanded)

### False positive on rules/ folder
```bash
# BAD
python3 scanner.py scan --path ~/yaracop --rules rules/

# GOOD
python3 scanner.py scan --path ~/yaracop --rules rules/ --exclude rules,.git,__pycache__
```

### Scan is slow
- Use `--max-size 50` to skip large files
- Use `--exclude` to skip large folders
- Scan specific folders only (not entire home)

### File not detected
- YARA only reads raw bytes (not ZIP/PDF inside)
- Extract archives first, then scan
- File might not match any rule

### Quarantine file not coming back
```bash
cp /tmp/quarantine/malware.txt.quarantined ~/yaracop/samples/malware.txt
```

### No matches found
- Check rules loaded: `✅ Compiled N rule file(s)`
- Check target files: `🔍 Scanning N file(s)...`
- Files might be clean

---

## 📊 Example Outputs

### Scan Downloads
```
✅ Compiled 3 rule file(s)
🔍 Scanning 25 file(s)...
🚨 [critical] Mirai → /home/user/Downloads/suspicious.exe
🚨 [high] Trojan_Generic → /home/user/Downloads/crack.dll

📊 Summary by severity:
  critical   : 1
  high       : 1
  TOTAL      : 2
```

### HTML Report
```
📄 HTML report saved to: /tmp/report.html
```

### ML Detection
```
🤖 Trained ML model saved to: models/ml_model.pkl
[ML] suspicious: samples/malware.txt (score: 0.96)
[ML] suspicious: samples/suspicious.txt (score: 1.00)
```

### Quarantine
```
🔒 Quarantined: samples/malware.txt → /tmp/quarantine/malware.txt.quarantined
```

