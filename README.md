# yaracop v1.1.0 — YARA Malware Scanner + ML, VT & SOAR Integration

![CI](https://github.com/InfraSecID/yaracop/actions/workflows/ci.yml/badge.svg)
![GitHub release](https://img.shields.io/github/v/release/InfraSecID/yaracop)
![GitHub stars](https://img.shields.io/github/stars/InfraSecID/yaracop)
![License](https://img.shields.io/github/license/InfraSecID/yaracop)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

Functional YARA scanner with JSON/HTML export, severity filtering, quarantine, VirusTotal lookup, ML heuristic detection, and Wazuh/Shuffle SOAR integration.

## Features
- 🦠 Scan files/folders with 11 built-in YARA rules (+ auto-updater)
- 👁️ Watch mode (real-time detection)
- 🚫 `--exclude` skip specific folders or files
- 📏 `--max-size` skip large files (in MB, default 100 MB)
- 🎯 `--severity` filter alerts by severity (`critical,high,medium,low`)
- 📄 `--html` generate rich HTML report with summary cards & severity badges
- 🔒 `--quarantine` move matched files safely with `.quarantined` extension
- 🔄 `update-rules` auto-update & backup YARA rules
- 🛡️ `--vt` VirusTotal SHA256 reputation check
- 🤖 `--ml` scikit-learn RandomForest heuristic malware detection
- 💾 `--json` export to file & 📊 `--summary` severity breakdown
- 🔗 Wazuh logtest & 🚀 Shuffle SOAR webhook integration

## Requirements
- Python 3.10+
- YARA (`apt install yara` atau `pip install yara-python`)
- `pip install -r requirements.txt`

## Install
```bash
git clone https://github.com/InfraSecID/yaracop.git
cd yaracop
pip install -r requirements.txt
```

## Usage

### Basic Scan with summary
```bash
python3 scanner.py scan --path samples/ --rules rules/ --summary
```

---

## 📂 Scan Any Folder

| Folder | Command |
|--------|---------|
| Downloads | `python3 scanner.py scan --path ~/Downloads --rules rules/ --summary` |
| Documents | `python3 scanner.py scan --path ~/Documents --rules rules/ --summary` |
| Desktop | `python3 scanner.py scan --path ~/Desktop --rules rules/ --summary` |
| USB | `python3 scanner.py scan --path /media/$USER/USB_NAME --rules rules/ --summary` |
| Home (safe) | `python3 scanner.py scan --path ~ --rules rules/ --exclude rules,.git,__pycache__ --max-size 50 --summary` |
| Single file | `python3 scanner.py scan --path ~/Downloads/file.exe --rules rules/ --summary` |

For full guide, see [USAGE.md](USAGE.md).

---

## 🎯 Combo Examples

### Full scan (all features)
```bash
python3 scanner.py scan --path ~/Downloads --rules rules/ \
  --exclude .git,__pycache__ --max-size 50 --severity critical,high \
  --json hasil.json --html report.html --quarantine /tmp/quarantine \
  --ml --summary
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

### Scan downloaded file
```bash
cd ~/Downloads
python3 ~/yaracop/scanner.py scan --path . --rules ~/yaracop/rules/ --summary
```

### Scan USB from friend
```bash
ls /media/$USER/
python3 ~/yaracop/scanner.py scan --path /media/$USER/USB_NAME \
  --rules ~/yaracop/rules/ --quarantine /tmp/quarantine --summary
```

### Daily scan with cron
```bash
crontab -e
# Add: 0 2 * * * cd ~/yaracop && python3 scanner.py scan --path ~/Downloads --rules rules/ --json ~/scan-$(date +\%Y\%m\%d).json --summary >> ~/scan.log 2>&1
```

---

### Filter with `--exclude`, `--max-size`, and `--severity`
```bash
python3 scanner.py scan --path ~/yaracop --rules rules/ \
  --exclude rules,.git,__pycache__,node_modules \
  --max-size 50 \
  --severity critical,high \
  --summary
```

### Generate HTML Report (`--html`)
```bash
python3 scanner.py scan --path samples/ --rules rules/ --html report.html --summary
```

### Quarantine Matched Files (`--quarantine`)
```bash
python3 scanner.py scan --path samples/ --rules rules/ --quarantine /tmp/quarantine
```

### Auto-Update YARA Rules (`update-rules`)
```bash
python3 scanner.py update-rules
```

### Machine Learning Heuristic Detection (`--ml`)
```bash
python3 scanner.py scan --path samples/ --rules rules/ --ml --summary
```

### VirusTotal Check (`--vt`)
```bash
python3 scanner.py scan --path samples/ --rules rules/ --vt YOUR_VT_API_KEY
```

### Watch folder
```bash
python3 scanner.py watch --path /tmp/malware --rules rules/ --json live.json
```

### Send to Wazuh / Shuffle
```bash
python3 integration.py wazuh --alert-file hasil.json --manager-url https://localhost:55000 --user wazuh --password wazuh
python3 integration.py shuffle --alert-file hasil.json --webhook http://localhost:3001/api/v1/hooks/webhook_xxx
```

## Built-in Rules
| Rule | Detects | Severity | MITRE |
|------|---------|----------|-------|
| Mirai | Botnet | Critical | T1204 |
| EICAR_Test | Test file | Medium | T1204 |
| Ransomware_Note | Ransom note | Critical | T1486 |
| Ransomware_Extension | Ransom extensions | High | T1486 |
| Trojan_Generic | Trojan API calls | High | T1055 |
| Backdoor_ReverseShell | Reverse shell | Critical | T1059 |
| Suspicious_Base64 | Obfuscation | Low | T1027 |
| Miner_XMRig | Crypto miner | High | T1496 |
| WebShell_PHP | PHP/ASP web shell | Critical | T1505 |
| Ransomware_WannaCry | WannaCry ransomware | Critical | T1486 |
| Trojan_Emotet | Emotet banking trojan | High | T1055 |

---

## 🐛 Troubleshooting

| Problem | Fix |
|---------|-----|
| False positive on rules/ | Use `--exclude rules,.git,__pycache__` |
| Scan is slow | Use `--max-size 50` or `--exclude` |
| File not detected | YARA only reads raw bytes; extract archives first |
| Quarantine file not coming back | `cp /tmp/quarantine/file.quarantined samples/file.txt` |
| No matches found | Check rules loaded; files might be clean |
| `ModuleNotFoundError: yara` | `pip install yara-python` |
| Wazuh auth failed | Check `--manager-url`, `--user`, `--password` |

---

## License
MIT
