#!/usr/bin/env python3
"""Writable Path Checker - Find writable directories in PATH"""
import os
import subprocess

class WritableChecker:
    def check(self):
        findings = []
        print("[*] Checking PATH directories for writability...")
        path_dirs = os.environ.get("PATH", "").split(":")
        for directory in path_dirs:
            if os.path.exists(directory) and os.access(directory, os.W_OK):
                findings.append({
                    "path": directory,
                    "writable": True,
                    "severity": "HIGH",
                    "note": "Writable PATH directory (hijacking risk)"
                })
                print(f"[!] WRITABLE PATH DIR: {directory}")

        # Check /tmp
        if os.access("/tmp", os.W_OK):
            findings.append({
                "path": "/tmp",
                "writable": True,
                "severity": "INFO",
                "note": "/tmp is writable"
            })
        return findings
