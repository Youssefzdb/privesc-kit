#!/usr/bin/env python3
"""Cron Job Checker - Find writable cron jobs and weak permissions"""
import subprocess
import os

CRON_PATHS = [
    "/etc/crontab",
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.weekly/",
    "/var/spool/cron/",
]

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, text=True).strip()
    except:
        return ""

class CronChecker:
    def check(self):
        findings = []
        print("[*] Checking cron jobs for misconfigurations...")

        # Check system crontab
        crontab = run_cmd("cat /etc/crontab 2>/dev/null")
        if crontab:
            for line in crontab.splitlines():
                if line and not line.startswith("#"):
                    findings.append({"source": "/etc/crontab", "entry": line})

        # Check cron.d
        cron_d = run_cmd("ls -la /etc/cron.d/ 2>/dev/null")
        if cron_d:
            findings.append({"source": "/etc/cron.d", "entry": cron_d[:200]})

        # Check for world-writable cron scripts
        writable = run_cmd("find /etc/cron* -writable 2>/dev/null")
        if writable:
            for path in writable.splitlines():
                findings.append({
                    "source": "writable_cron",
                    "entry": path,
                    "severity": "CRITICAL",
                    "note": f"WORLD WRITABLE: {path} - possible cron hijack"
                })
                print(f"[!] CRITICAL: Writable cron file: {path}")

        print(f"[+] Found {len(findings)} cron entries")
        return findings
