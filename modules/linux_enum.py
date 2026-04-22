#!/usr/bin/env python3
"""Linux System Enumerator - OS, users, network, running services"""
import subprocess
import os

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, text=True).strip()
    except:
        return ""

class LinuxEnumerator:
    def enumerate(self):
        info = {}
        print("[*] Enumerating system info...")
        info["os"] = run_cmd("uname -a")
        info["hostname"] = run_cmd("hostname")
        info["whoami"] = run_cmd("whoami")
        info["id"] = run_cmd("id")
        info["sudo_perms"] = run_cmd("sudo -l 2>/dev/null || echo 'no sudo'")
        info["users"] = run_cmd("cat /etc/passwd | grep -v nologin | grep -v false")
        info["network"] = run_cmd("ip addr 2>/dev/null || ifconfig 2>/dev/null")
        info["listening"] = run_cmd("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
        info["env"] = run_cmd("env")
        info["writable_dirs"] = run_cmd("find / -writable -type d 2>/dev/null | head -20")

        for k, v in info.items():
            if v:
                print(f"[+] {k}: {v[:80]}...")

        return info
