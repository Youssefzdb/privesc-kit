#!/usr/bin/env python3
"""Privesc Report Generator"""
from datetime import datetime

class PrivescReport:
    def __init__(self, target_os, results):
        self.target_os = target_os
        self.results = results if isinstance(results, list) else sum(results.values(), [])

    def save(self, filename):
        findings_html = "".join(
            f"<tr><td>{f.get('type','')}</td><td>{f.get('detail',f.get('path',''))}</td>"
            f"<td class='{f.get('severity','').lower()}'>{f.get('severity','')}</td>"
            f"<td>{f.get('note','')}</td></tr>"
            for f in self.results
        )
        html = f"""<!DOCTYPE html>
<html><head><title>Privesc Report</title>
<style>
body{{font-family:Arial;background:#0f0f0f;color:#ddd;padding:20px}}
h1{{color:#f59e0b}} .card{{background:#1a1a1a;border-radius:8px;padding:15px;margin:10px 0}}
table{{width:100%;border-collapse:collapse}} td,th{{padding:8px;border:1px solid #333}}
th{{background:#222}} .critical{{color:#ef4444}} .high{{color:#f97316}} .medium{{color:#facc15}}
</style></head>
<body>
<h1>Privesc-Kit Report [{self.target_os.upper()}]</h1>
<p>{datetime.now().strftime('%Y-%m-%d %H:%M')} | {len(self.results)} findings</p>
<div class="card">
  <table><tr><th>Type</th><th>Detail</th><th>Severity</th><th>Note</th></tr>
  {findings_html}</table>
</div>
</body></html>"""
        with open(filename, "w") as f:
            f.write(html)

cat > /tmp/privesc_req.txt << 'EOF'
colorama>=0.4.6
