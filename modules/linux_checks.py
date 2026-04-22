#!/usr/bin/env python3
"""Linux Privilege Escalation Checks"""
import os
import subprocess
import stat

class LinuxPrivescChecker:
    def __init__(self):
        self.findings = []

    def _run(self, cmd):
        try:
            return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=5).decode(errors="ignore").strip()
        except:
            return ""

    def _check_suid(self):
        out = self._run("find / -perm -4000 -type f 2>/dev/null")
        known_suid = {"/usr/bin/sudo", "/usr/bin/passwd", "/bin/su"}
        for f in out.splitlines():
            if f not in known_suid:
                self.findings.append({"type": "SUID Binary", "detail": f, "severity": "HIGH",
                                       "desc": f"Non-standard SUID binary: {f}"})
                print(f"[!] SUID: {f}")

    def _check_sudo(self):
        out = self._run("sudo -l 2>/dev/null")
        if "NOPASSWD" in out:
            self.findings.append({"type": "Sudo NOPASSWD", "detail": out[:200], "severity": "CRITICAL",
                                   "desc": "sudo NOPASSWD configured - passwordless privilege escalation possible"})
            print("[!] sudo NOPASSWD found!")

    def _check_writable_etc(self):
        sensitive = ["/etc/passwd", "/etc/shadow", "/etc/crontab", "/etc/sudoers"]
        for f in sensitive:
            try:
                if os.access(f, os.W_OK):
                    self.findings.append({"type": "Writable File", "detail": f, "severity": "CRITICAL",
                                           "desc": f"{f} is world-writable!"})
                    print(f"[!] Writable: {f}")
            except:
                pass

    def _check_cron(self):
        cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/var/spool/cron"]
        for d in cron_dirs:
            try:
                for f in os.listdir(d):
                    fpath = os.path.join(d, f)
                    s = os.stat(fpath)
                    if s.st_mode & stat.S_IWOTH:
                        self.findings.append({"type": "Writable Cron", "detail": fpath, "severity": "HIGH",
                                               "desc": f"World-writable cron job: {fpath}"})
            except:
                pass

    def _check_path(self):
        path = os.environ.get("PATH", "")
        for p in path.split(":"):
            if p in [".", "", ".."]:
                self.findings.append({"type": "PATH Injection", "detail": p, "severity": "HIGH",
                                       "desc": f"Current dir in PATH: '{p}' - PATH hijacking possible"})

    def check(self):
        self._check_suid()
        self._check_sudo()
        self._check_writable_etc()
        self._check_cron()
        self._check_path()
        return self.findings
