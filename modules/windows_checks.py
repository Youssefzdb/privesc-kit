#!/usr/bin/env python3
"""Windows Privilege Escalation Detection Checks"""
import subprocess

class WindowsPrivEscChecker:
    def __init__(self):
        self.findings = []

    def _run(self, cmd):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            return result.stdout.strip()
        except:
            return ""

    def check_unquoted_service_paths(self):
        """Detect unquoted service paths"""
        print("[*] Checking unquoted service paths...")
        output = self._run('wmic service get name,displayname,pathname,startmode 2>nul')
        for line in output.splitlines():
            if " " in line and '"' not in line and "C:\\Windows" not in line and ".exe" in line:
                self.findings.append({
                    "type": "Unquoted Service Path",
                    "detail": line[:120],
                    "severity": "HIGH",
                    "description": "Service path with spaces not quoted — allows hijacking",
                    "mitigation": "Quote all service binary paths in the registry"
                })
                print(f"[!] HIGH: Unquoted service path: {line[:80]}")

    def check_alwaysinstallelevated(self):
        """Check AlwaysInstallElevated registry key"""
        print("[*] Checking AlwaysInstallElevated...")
        r1 = self._run('reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul')
        r2 = self._run('reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul')
        if "0x1" in r1 or "0x1" in r2:
            self.findings.append({
                "type": "AlwaysInstallElevated Enabled",
                "severity": "CRITICAL",
                "description": "MSI packages install with SYSTEM privileges",
                "mitigation": "Disable AlwaysInstallElevated in Group Policy"
            })
            print("[!] CRITICAL: AlwaysInstallElevated is ON!")

    def check_writable_services(self):
        """Check for services with writable binary paths"""
        print("[*] Checking service permissions...")
        output = self._run("sc query type= all state= all 2>nul")
        self.findings.append({
            "type": "Service Check",
            "detail": "Review service permissions with AccessChk",
            "severity": "INFO",
            "description": "Use Sysinternals AccessChk to audit service permissions",
            "mitigation": "Restrict service binary directory permissions"
        })

    def check_uac_level(self):
        """Check UAC configuration"""
        print("[*] Checking UAC level...")
        output = self._run('reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA 2>nul')
        if "0x0" in output:
            self.findings.append({
                "type": "UAC Disabled",
                "severity": "CRITICAL",
                "description": "UAC is disabled — any program runs with admin privileges",
                "mitigation": "Enable UAC via Group Policy or registry"
            })
            print("[!] CRITICAL: UAC is DISABLED")

    def check_all(self):
        self.check_unquoted_service_paths()
        self.check_alwaysinstallelevated()
        self.check_writable_services()
        self.check_uac_level()
        return self.findings
