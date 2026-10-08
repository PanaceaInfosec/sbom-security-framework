#!/usr/bin/env python3
import argparse, json, sys
from pathlib import Path
from sbomsec.analyzer import analyze_sbom, sev_rank
from sbomsec.intel import query_osv, load_kev, get_epss
from sbomsec.report import write_reports



def _display_version(version):
    """Return clean upstream/base version for reports; preserve original separately."""
    if version is None:
        return ""
    v=str(version).strip()
    # PEP 440 local version identifier, e.g. 2.13.0+cu126 -> 2.13.0
    return v.split("+",1)[0] if "+" in v else v

def _extract_fixed_versions(v, component=None):
    out=[]
    cname=(component or {}).get("name","").lower()
    cpurl=(component or {}).get("purl","")
    for affected in v.get("affected") or []:
        pkg=affected.get("package") or {}
        # Prefer the affected package record that corresponds to the SBOM component.
        if cname and pkg.get("name") and pkg.get("name","").lower()!=cname:
            if not (cpurl and pkg.get("purl") and cpurl.split("@",1)[0]==pkg.get("purl","").split("@",1)[0]):
                continue
        for rng in affected.get("ranges") or []:
            rtype=str(rng.get("type","")).upper()
            if rtype=="GIT":
                continue
            for event in rng.get("events") or []:
                fixed=event.get("fixed")
                if fixed and fixed not in out:
                    out.append(str(fixed))
    return out

def _make_recommendation(v, c, kev=False):
    fixed=_extract_fixed_versions(v, c)
    name=c.get("name","component"); current=c.get("version","unknown")
    if fixed:
        rec=f"Upgrade {name} from {current} to a fixed version: {', '.join(fixed[:5])}. Rebuild/redeploy the artifact and rerun SCA plus regression testing."
    else:
        rec=f"No explicit fixed version was returned by OSV for {name} {current}. Review the vendor/upstream advisory and upgrade to a confirmed supported non-vulnerable release; validate applicability and reachability before closure."
    if kev:
        rec += " CISA KEV-listed vulnerability: prioritize remediation and apply the vendor mitigation immediately if patching is delayed."
    return rec, fixed

def main():
    ap=argparse.ArgumentParser(description="CycloneDX SBOM security validation and vulnerability correlation")
    ap.add_argument("--sbom",required=True)
    ap.add_argument("--config",default="config.json")
    ap.add_argument("--output",default="reports")
    ap.add_argument("--offline",action="store_true",help="Run SBOM quality checks only; no internet APIs")
    args=ap.parse_args()
    doc=json.loads(Path(args.sbom).read_text(encoding="utf-8"))
    cfg=json.loads(Path(args.config).read_text(encoding="utf-8")) if Path(args.config).exists() else {}
    findings=analyze_sbom(doc,cfg)
    components=doc.get("components") or []

    vuln_findings=[]
    if not args.offline and cfg.get("osv_enabled",True):
        for c in components:
            for v in query_osv(c):
                aliases=v.get("aliases") or []
                cves=[a for a in aliases+[v.get("id","")] if str(a).startswith("CVE-")]
                rec, fixed = _make_recommendation(v, c)
                vuln_findings.append({
                    "type":"VULNERABILITY","severity":"UNKNOWN","title":v.get("summary") or v.get("id"),
                    "component":c.get("name"),"version":_display_version(c.get("version")),"original_version":c.get("version"),"purl":c.get("purl"),
                    "cve":cves[0] if cves else v.get("id"),"osv_id":v.get("id"),
                    "fixed_version":", ".join(fixed[:5]) if fixed else "",
                    "recommendations":rec, "_osv":v, "_component":c,
                    "detail":"OSV package/version match. Validate reachability and vendor applicability before final disposition."
                })
        kev=load_kev() if cfg.get("kev_enabled",True) else {}
        cves=sorted({x["cve"] for x in vuln_findings if str(x.get("cve","")).startswith("CVE-")})
        epss=get_epss(cves) if cfg.get("epss_enabled",True) else {}
        for x in vuln_findings:
            cve=x.get("cve")
            if cve in kev:
                x["kev"]=True; x["severity"]="CRITICAL"
                x["detail"] += " Listed in CISA Known Exploited Vulnerabilities catalog."
                rec, fixed = _make_recommendation(x.get("_osv",{}), x.get("_component",{}), True)
                x["recommendations"]=rec
                if fixed: x["fixed_version"]=", ".join(fixed[:5])
            if cve in epss:
                x["epss"]=epss[cve].get("epss")
                x["epss_percentile"]=epss[cve].get("percentile")
            if x["severity"]=="UNKNOWN": x["severity"]="HIGH"
    findings.extend(vuln_findings)

    defaults={
      "SBOM_QUALITY":"Regenerate the SBOM with complete component metadata and vulnerability enrichment, then validate the new SBOM before release.",
      "SBOM_INTEGRITY":"Verify hashes against the original artifacts and regenerate the SBOM if component identity/hash attribution is incorrect.",
      "SUPPLY_CHAIN":"Replace pre-release dependencies with stable vendor-supported releases where feasible, then rerun compatibility and security testing.",
      "VULNERABILITY":"Review the vendor advisory, upgrade to a confirmed non-vulnerable supported version, then rerun SCA and regression testing."
    }
    for x in findings:
        x.setdefault("recommendations", defaults.get(x.get("type"),"Validate the finding, remediate as appropriate, and retest."))
        x.pop("_osv",None); x.pop("_component",None)

    counts={s:sum(1 for x in findings if x.get("severity")==s) for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO","UNKNOWN"]}
    summary={"components":len(components),"findings":len(findings),"severity":counts,
             "embedded_vulnerabilities":len(doc.get("vulnerabilities") or [])}
    write_reports(findings,summary,args.output)
    print(json.dumps(summary,indent=2))
    threshold=sev_rank(cfg.get("fail_on","HIGH"))
    return 2 if any(sev_rank(x.get("severity"))>=threshold for x in findings) else 0

if __name__=="__main__":
    sys.exit(main())
