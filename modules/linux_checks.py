#!/usr/bin/env python3
"""Linux Privilege Escalation Detection Checks"""
import subprocess
import os
import stat

class LinuxPrivEscChecker:
    def __init__(self):
        self.findings = []

    def _run(self, cmd):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            return result.stdout.strip()
        except:
            return ""

    def check_suid_files(self):
        """Check for SUID/SGID binaries that can be abused"""
        print("[*] Checking SUID/SGID binaries...")
        output = self._run("find / -perm -4000 -type f 2>/dev/null")
        dangerous = ["/usr/bin/python", "/usr/bin/perl", "/usr/bin/find",
                     "/usr/bin/vim", "/usr/bin/nmap", "/usr/bin/awk", "/usr/bin/bash"]
        for line in output.splitlines():
            if any(d in line for d in dangerous):
                self.findings.append({
                    "type": "Dangerous SUID Binary",
                    "path": line,
                    "severity": "CRITICAL",
                    "description": f"{line} has SUID bit set — potential GTFOBins abuse",
                    "mitigation": f"Remove SUID: chmod u-s {line}"
                })
                print(f"[!] CRITICAL: SUID binary: {line}")

    def check_writable_passwd(self):
        """Check if /etc/passwd is writable"""
        print("[*] Checking /etc/passwd permissions...")
        if os.access("/etc/passwd", os.W_OK):
            self.findings.append({
                "type": "Writable /etc/passwd",
                "path": "/etc/passwd",
                "severity": "CRITICAL",
                "description": "World-writable /etc/passwd allows adding root user",
                "mitigation": "chmod 644 /etc/passwd"
            })
            print("[!] CRITICAL: /etc/passwd is writable!")

    def check_sudo_nopasswd(self):
        """Check for NOPASSWD sudo entries"""
        print("[*] Checking sudo configuration...")
        output = self._run("sudo -l 2>/dev/null")
        if "NOPASSWD" in output:
            self.findings.append({
                "type": "Sudo NOPASSWD",
                "detail": output[:200],
                "severity": "HIGH",
                "description": "User can run commands as root without password",
                "mitigation": "Review /etc/sudoers and remove NOPASSWD entries"
            })
            print("[!] HIGH: NOPASSWD sudo found")

    def check_cron_writable(self):
        """Check for writable cron files"""
        print("[*] Checking cron jobs...")
        cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/var/spool/cron"]
        for d in cron_dirs:
            if os.path.exists(d) and os.access(d, os.W_OK):
                self.findings.append({
                    "type": "Writable Cron Directory",
                    "path": d,
                    "severity": "HIGH",
                    "description": "Writable cron directory can be abused for persistence",
                    "mitigation": f"chmod o-w {d}"
                })
                print(f"[!] HIGH: Writable cron dir: {d}")

    def check_world_writable(self):
        """Check critical world-writable files"""
        print("[*] Checking world-writable files...")
        output = self._run("find /etc /usr/bin /usr/sbin -perm -002 -type f 2>/dev/null")
        for f in output.splitlines()[:10]:
            self.findings.append({
                "type": "World-Writable File",
                "path": f,
                "severity": "MEDIUM",
                "description": "World-writable system file can be modified by any user",
                "mitigation": f"chmod o-w {f}"
            })
            print(f"[!] MEDIUM: World-writable: {f}")

    def check_kernel_version(self):
        """Check for outdated kernel"""
        print("[*] Checking kernel version...")
        kernel = self._run("uname -r")
        self.findings.append({
            "type": "Kernel Version",
            "version": kernel,
            "severity": "INFO",
            "description": f"Running kernel: {kernel} — check for known CVEs",
            "mitigation": "Keep kernel updated"
        })

    def check_all(self):
        self.check_suid_files()
        self.check_writable_passwd()
        self.check_sudo_nopasswd()
        self.check_cron_writable()
        self.check_world_writable()
        self.check_kernel_version()
        return self.findings
