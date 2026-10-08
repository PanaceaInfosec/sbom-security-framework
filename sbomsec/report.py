
import csv, json, html
from pathlib import Path

def write_reports(findings, summary, outdir):
    out=Path(outdir); out.mkdir(parents=True,exist_ok=True)
    (out/"report.json").write_text(json.dumps({"summary":summary,"findings":findings},indent=2),encoding="utf-8")
    cols=["severity","type","title","component","version","original_version","cve","fixed_version","kev","epss","recommendations","detail"]
    with (out/"report.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=cols,extrasaction="ignore"); w.writeheader()
        for x in findings: w.writerow(x)
    rows=""
    for x in findings:
        rows += "<tr>"+"".join(f"<td>{html.escape(str(x.get(k,'')))}</td>" for k in cols)+"</tr>"
    page=f"""<!doctype html><meta charset="utf-8"><title>SBOM Security Report</title>
<style>body{{font-family:Arial,sans-serif;margin:32px}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:6px;text-align:left;vertical-align:top}}th{{background:#eee}}code{{word-break:break-all}}</style>
<h1>SBOM Security Report</h1><pre>{html.escape(json.dumps(summary,indent=2))}</pre>
<table><thead><tr>{''.join('<th>'+k+'</th>' for k in cols)}</tr></thead><tbody>{rows}</tbody></table>"""
    (out/"report.html").write_text(page,encoding="utf-8")
