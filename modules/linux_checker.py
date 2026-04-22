#!/usr/bin/env python3
"""Linux Privilege Escalation Checker"""
import os
import subprocess

class LinuxPrivescChecker:
    def __init__(self):
        self.findings = []

    def _run(self, cmd):
        try:
            return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=5).decode()
        except:
            return ""

    def check_suid_binaries(self):
        result = self._run("find / -perm -4000 -type f 2>/dev/null")
        suid_files = [f for f in result.strip().split("\n") if f]
        dangerous = ["/usr/bin/nmap", "/usr/bin/vim", "/usr/bin/python", "/usr/bin/find", "/usr/bin/perl"]
        for f in suid_files:
            if any(d in f for d in dangerous):
                self.findings.append({"type": "SUID Binary", "path": f, "severity": "HIGH",
                                       "note": "Can be used for privesc via GTFOBins"})
                print(f"[!] Dangerous SUID: {f}")
        return suid_files

    def check_writable_etc(self):
        for f in ["/etc/passwd", "/etc/sudoers", "/etc/crontab"]:
            if os.access(f, os.W_OK):
                self.findings.append({"type": "Writable Critical File", "path": f,
                                       "severity": "CRITICAL", "note": "World-writable system file"})
                print(f"[!] CRITICAL: {f} is writable!")

    def check_sudo(self):
        result = self._run("sudo -l 2>/dev/null")
        if "NOPASSWD" in result:
            self.findings.append({"type": "NOPASSWD sudo", "detail": result[:200],
                                   "severity": "HIGH", "note": "Can run commands as root without password"})
            print("[!] NOPASSWD sudo entry found!")

    def check_cron_jobs(self):
        cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/var/spool/cron"]
        for d in cron_dirs:
            if os.path.isdir(d):
                for f in os.listdir(d):
                    path = os.path.join(d, f)
                    if os.access(path, os.W_OK):
                        self.findings.append({"type": "Writable Cron Job", "path": path,
                                               "severity": "HIGH", "note": "Modifiable cron job"})

    def check(self):
        print("[*] Checking SUID binaries...")
        self.check_suid_binaries()
        print("[*] Checking writable system files...")
        self.check_writable_etc()
        print("[*] Checking sudo permissions...")
        self.check_sudo()
        print("[*] Checking cron jobs...")
        self.check_cron_jobs()
        print(f"[+] Found {len(self.findings)} potential vectors")
        return self.findings
