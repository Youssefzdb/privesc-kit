#!/usr/bin/env python3
"""Cron Checker - Detect writable cron jobs"""
import os
import stat

CRON_PATHS = [
    "/etc/crontab", "/etc/cron.d", "/etc/cron.daily",
    "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron"
]

class CronChecker:
    def check(self):
        findings = []
        print("[*] Checking cron jobs for privilege escalation...")
        for path in CRON_PATHS:
            if os.path.exists(path):
                try:
                    st = os.stat(path)
                    mode = st.st_mode
                    world_writable = bool(mode & stat.S_IWOTH)
                    if world_writable:
                        findings.append({
                            "path": path,
                            "writable": True,
                            "severity": "CRITICAL",
                            "note": "World-writable cron path"
                        })
                        print(f"[!] WORLD-WRITABLE CRON: {path}")
                except:
                    pass
        return findings
