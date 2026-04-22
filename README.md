# privesc-kit 🔓

Privilege Escalation Techniques & Detection Lab

## Features
- SUID/SGID binary detection with exploitability assessment
- Writable cron job detection
- PATH hijacking vulnerability check
- JSON report export

## Usage (Linux/Lab Environment Only)
```bash
pip install -r requirements.txt
python main.py --mode full
python main.py --mode suid --output suid_report.json
```

## Disclaimer
For use in CTF environments and authorized penetration testing labs only.
