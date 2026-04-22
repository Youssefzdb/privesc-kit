#!/usr/bin/env python3
from datetime import datetime

SEVERITY_COLORS = {
    "CRITICAL": "#ff0000",
    "HIGH": "#ff6600",
    "MEDIUM": "#ffaa00",
    "LOW": "#88cc00",
    "INFO": "#4488ff"
}

class PrivEscReport:
    def __init__(self, os_type, findings):
        self.os_type = os_type
        self.findings = findings

    def save(self, filename):
        rows = ""
        for f in self.findings:
            color = SEVERITY_COLORS.get(f.get("severity", "INFO"), "#fff")
            rows += f"""<tr>
              <td style='color:{color}'><b>{f.get('severity','')}</b></td>
              <td>{f.get('type','')}</td>
              <td>{f.get('description','')}</td>
              <td><code>{f.get('mitigation','')}</code></td>
            </tr>"""

        crit = len([f for f in self.findings if f.get("severity") == "CRITICAL"])
        high = len([f for f in self.findings if f.get("severity") == "HIGH"])

        html = f"""<!DOCTYPE html><html><head><title>PrivEsc Report</title>
<style>
body{{font-family:Arial;background:#0d0d0d;color:#e0e0e0;padding:20px}}
h1{{color:#ff6600}}table{{width:100%;border-collapse:collapse;margin:10px 0}}
td,th{{padding:8px;border:1px solid #333;vertical-align:top}}
th{{background:#1a1a1a}}code{{color:#00ff88;font-size:0.85em}}
.summary{{display:flex;gap:15px;margin:10px 0}}
.badge{{padding:10px 20px;border-radius:6px;font-weight:bold;text-align:center}}
</style></head>
<body>
<h1>🔐 PrivEsc Detection Report</h1>
<p>OS: <b>{self.os_type.upper()}</b> | {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
<div class="summary">
  <div class="badge" style="background:#660000">CRITICAL: {crit}</div>
  <div class="badge" style="background:#663300">HIGH: {high}</div>
  <div class="badge" style="background:#333">TOTAL: {len(self.findings)}</div>
</div>
<table>
  <tr><th>Severity</th><th>Type</th><th>Description</th><th>Mitigation</th></tr>
  {rows}
</table>
</body></html>"""
        with open(filename, "w") as f:
            f.write(html)
        print(f"[+] Report saved: {filename}")
