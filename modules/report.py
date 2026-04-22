#!/usr/bin/env python3
"""Privilege Escalation Report Generator"""
from datetime import datetime

class PrivescReport:
    def __init__(self, results):
        self.results = results

    def save(self, filename):
        lines = [
            "=" * 60,
            "privesc-kit Report",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 60,
        ]

        if "system" in self.results:
            lines.append("\n[SYSTEM INFO]")
            for k, v in self.results["system"].items():
                lines.append(f"  {k}: {v[:200] if v else 'N/A'}")

        if "suid" in self.results:
            lines.append("\n[SUID BINARIES]")
            for item in self.results["suid"]:
                flag = "[EXPLOITABLE]" if item["exploitable"] else "[ok]"
                lines.append(f"  {flag} {item['path']}")
                if item["exploitable"]:
                    lines.append(f"       GTFObins: https://gtfobins.github.io/gtfobins/{item['binary']}/")

        if "cron" in self.results:
            lines.append("\n[CRON JOBS]")
            for item in self.results["cron"]:
                severity = item.get("severity", "")
                prefix = "[!!!]" if severity == "CRITICAL" else "[cron]"
                lines.append(f"  {prefix} {item.get('entry', '')[:120]}")

        with open(filename, "w") as f:
            f.write("\n".join(lines))
        print(f"[+] Report saved: {filename}")
