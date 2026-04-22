#!/usr/bin/env python3
"""SUID Binary Finder - Detect exploitable SUID binaries"""
import subprocess

EXPLOITABLE_SUID = [
    "bash", "sh", "python", "python3", "perl", "ruby", "find",
    "vim", "vi", "nano", "less", "more", "awk", "sed", "nmap",
    "env", "tee", "cp", "mv", "chmod", "chown", "dd", "tar",
    "zip", "gcc", "make", "cat", "head", "tail", "curl", "wget"
]

class SUIDFinder:
    def find(self):
        print("[*] Searching for SUID binaries...")
        findings = []
        try:
            output = subprocess.check_output(
                "find / -perm -4000 -type f 2>/dev/null",
                shell=True, text=True
            ).strip().splitlines()
            for path in output:
                binary = path.split("/")[-1]
                is_exploitable = binary.lower() in EXPLOITABLE_SUID
                findings.append({
                    "path": path,
                    "binary": binary,
                    "exploitable": is_exploitable,
                    "severity": "HIGH" if is_exploitable else "INFO"
                })
                if is_exploitable:
                    print(f"[!] HIGH: Exploitable SUID - {path}")
                    print(f"    GTFObins: https://gtfobins.github.io/gtfobins/{binary}/")
        except:
            pass
        return findings
