#!/usr/bin/env python3
"""Windows Privilege Escalation Checks"""
import subprocess

class WindowsPrivescChecker:
    def __init__(self):
        self.findings = []

    def _run(self, cmd):
        try:
            return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=5).decode(errors="ignore").strip()
        except:
            return ""

    def _check_unquoted_services(self):
        out = self._run('wmic service get name,pathname,startmode 2>nul')
        for line in out.splitlines():
            if " " in line and '"' not in line and "C:\\Windows" not in line:
                self.findings.append({"type": "Unquoted Service Path", "detail": line[:100], "severity": "HIGH",
                                       "desc": "Unquoted service path - possible DLL hijacking"})
                print(f"[!] Unquoted path: {line[:80]}")

    def _check_always_install_elevated(self):
        for key in [
            "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"
        ]:
            out = self._run(f'reg query {key} /v AlwaysInstallElevated 2>nul')
            if "0x1" in out:
                self.findings.append({"type": "AlwaysInstallElevated", "detail": key, "severity": "CRITICAL",
                                       "desc": "AlwaysInstallElevated enabled - MSI privesc possible!"})
                print("[!] AlwaysInstallElevated!")

    def _check_weak_service_perms(self):
        out = self._run("sc query type= all state= all 2>nul")
        services = [line.split(":")[1].strip() for line in out.splitlines() if "SERVICE_NAME" in line]
        for svc in services[:10]:
            perms = self._run(f"sc sdshow {svc} 2>nul")
            if "WD" in perms or "BU" in perms:
                self.findings.append({"type": "Weak Service ACL", "detail": svc, "severity": "HIGH",
                                       "desc": f"Service {svc} has weak permissions"})

    def check(self):
        self._check_unquoted_services()
        self._check_always_install_elevated()
        self._check_weak_service_perms()
        return self.findings
