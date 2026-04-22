#!/usr/bin/env python3
from datetime import datetime

SEV_COLOR = {"CRITICAL": "#ff2222", "HIGH": "#ff8800", "MEDIUM": "#ffdd00", "LOW": "#88dd00"}

class Report:
    def __init__(self, os_type, findings):
        self.os_type = os_type
        self.findings = findings

    def save(self, filename):
        rows = "".join(
            f"<tr><td style='color:{SEV_COLOR.get(f.get(\"severity\",\"LOW\"),\"white\")}'>{f.get('severity')}</td>"
            f"<td>{f.get('type')}</td><td>{f.get('desc')}</td><td><code>{f.get('detail','')[:80]}</code></td></tr>"
            for f in self.findings
        )
        html = f"""<!DOCTYPE html><html><head><title>PrivEsc Kit</title>
<style>body{{font-family:monospace;background:#1a0a00;color:#ffcc88;padding:20px}}
h1{{color:#ff8800}}table{{width:100%;border-collapse:collapse;margin:10px 0}}
td,th{{padding:7px;border:1px solid #331100}}th{{background:#331100}}code{{color:#ffff88;font-size:11px}}</style></head>
<body><h1>PrivEsc-Kit Report [{self.os_type.upper()}]</h1>
<p>Vectors found: <b>{len(self.findings)}</b> | {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
<table><tr><th>Severity</th><th>Type</th><th>Description</th><th>Detail</th></tr>
{rows if rows else '<tr><td colspan=4>No vectors found</td></tr>'}
</table></body></html>"""
        with open(filename, "w") as f:
            f.write(html)
        print(f"[+] Saved: {filename}")
