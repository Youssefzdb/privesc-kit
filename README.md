# privesc-kit 🔓

Privilege Escalation Detection & Lab Tool

> ⚠️ **FOR AUTHORIZED USE ONLY** — CTF environments, authorized pentests, and personal lab machines.

## Features
- Linux system enumeration (OS, users, sudo perms, env)
- SUID binary discovery with GTFObins links
- Cron job misconfiguration detection
- Writable cron path detection

## Usage
```bash
# Full enumeration
sudo python main.py --full

# Only SUID check
python main.py --suid

# Only cron check
python main.py --cron
```
