# yaracop — YARA Malware Scanner + Wazuh/Shuffle Integration

Functional YARA scanner with JSON export, severity summary, and SOAR integration.

## Features
- 🦠 Scan files/folders with 9 built-in YARA rules
- 👁️ Watch mode (real-time detection)
- 💾 `--json` export to file
- 📊 `--summary` severity breakdown
- 🔗 Wazuh logtest integration
- 🚀 Shuffle SOAR webhook integration

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

### Scan with summary
```bash
python scanner.py scan --path /tmp/malware --rules rules/ --summary
```

### Scan + export JSON
```bash
python scanner.py scan --path /tmp/malware --rules rules/ --json hasil.json --summary
```

### Watch folder
```bash
python scanner.py watch --path /tmp/malware --rules rules/ --json live.json
```

### Send to Wazuh
```bash
python integration.py wazuh --alert-file hasil.json --manager-url https://localhost:55000 --user wazuh --password wazuh
```

### Send to Shuffle
```bash
python integration.py shuffle --alert-file hasil.json --webhook http://localhost:3001/api/v1/hooks/webhook_xxx
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

## License
MIT
