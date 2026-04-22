#!/usr/bin/env python3
"""SUID Checker - Find SUID/SGID binaries"""
import subprocess
import os

KNOWN_EXPLOITABLE = [
    "bash", "sh", "python", "python3", "perl", "ruby", "find",
    "vim", "nano", "less", "more", "nmap", "awk", "gdb", "strace"
]

class SUIDChecker:
    def check(self):
        findings = []
        print("[*] Scanning for SUID/SGID binaries...")
        try:
            result = subprocess.run(
                ["find", "/", "-perm", "-4000", "-type", "f", "-ls"],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.splitlines():
                binary_name = line.split()[-1] if line.split() else ""
                name = os.path.basename(binary_name)
                is_exploitable = name.lower() in KNOWN_EXPLOITABLE
                findings.append({
                    "binary": binary_name,
                    "suid": True,
                    "exploitable": is_exploitable,
                    "severity": "CRITICAL" if is_exploitable else "INFO"
                })
                if is_exploitable:
                    print(f"[!] EXPLOITABLE SUID: {binary_name}")
        except Exception as e:
            findings.append({"error": str(e)})
        print(f"[+] Found {len(findings)} SUID binaries")
        return findings
