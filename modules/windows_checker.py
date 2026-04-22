#!/usr/bin/env python3
"""Windows Privilege Escalation Checker"""
import subprocess
import platform

class WindowsPrivescChecker:
    def __init__(self):
        self.findings = []
        self.is_windows = platform.system() == "Windows"

    def _run(self, cmd):
        try:
            return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=5).decode()
        except:
            return ""

    def check_unquoted_service_paths(self):
        if not self.is_windows:
            self.findings.append({"type": "Demo: Unquoted Service Path",
                                   "detail": "C:\\Program Files\\Vulnerable Service\\svc.exe",
                                   "severity": "HIGH", "note": "Unquoted path allows DLL planting"})
            return
        result = self._run('wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows\\\\"')
        if result:
            self.findings.append({"type": "Unquoted Service Path", "detail": result[:300], "severity": "HIGH"})

    def check_weak_service_permissions(self):
        if not self.is_windows:
            self.findings.append({"type": "Demo: Weak Service Permission",
                                   "detail": "MyService - Everyone has WRITE permission",
                                   "severity": "HIGH", "note": "Can replace service binary"})

    def check_alwaysinstallelevated(self):
        if not self.is_windows:
            self.findings.append({"type": "Demo: AlwaysInstallElevated",
                                   "detail": "Registry key set to 1",
                                   "severity": "CRITICAL", "note": "MSI files run as SYSTEM"})
            return
        result = self._run("reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated")
        if "0x1" in result:
            self.findings.append({"type": "AlwaysInstallElevated", "severity": "CRITICAL",
                                   "note": "Any user can install MSI as SYSTEM"})
            print("[!] CRITICAL: AlwaysInstallElevated enabled!")

    def check(self):
        self.check_unquoted_service_paths()
        self.check_weak_service_permissions()
        self.check_alwaysinstallelevated()
        return self.findings
