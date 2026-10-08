
import re
from collections import defaultdict

PRE = re.compile(r"(?i)(?:^|[.\-_])(alpha|beta|rc|snapshot|preview|milestone|ea)(?:[.\-_]?\d*)?(?:$|[.\-_])")

def sev_rank(s):
    return {"INFO":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}.get(str(s).upper(),0)

def component_key(c):
    return c.get("purl") or f'{c.get("group","")}:{c.get("name","")}:{c.get("version","")}'

def analyze_sbom(doc, cfg):
    findings, components = [], doc.get("components") or []
    vulns = doc.get("vulnerabilities")

    if vulns == []:
        findings.append({
            "type":"SBOM_QUALITY", "severity":cfg.get("empty_vulnerabilities_severity","HIGH"),
            "title":"SBOM vulnerability array is empty",
            "detail":"The SBOM contains no embedded vulnerability records. This does not prove that all components are vulnerability-free."
        })

    hash_to_components = defaultdict(set)
    for c in components:
        name, version, purl = c.get("name","unknown"), str(c.get("version","")), c.get("purl")
        if not purl and c.get("type") not in ("operating-system","container"):
            findings.append({
                "type":"SBOM_QUALITY","severity":cfg.get("missing_purl_severity","LOW"),
                "title":"Component missing PURL","component":name,"version":version,
                "detail":"Package URL is absent, reducing vulnerability-correlation accuracy."
            })
        if PRE.search(version):
            findings.append({
                "type":"SUPPLY_CHAIN","severity":cfg.get("beta_severity","MEDIUM"),
                "title":"Pre-release dependency detected","component":name,"version":version,
                "purl":purl, "detail":"Alpha/beta/RC/snapshot dependency found; review production suitability and support status."
            })
        for h in c.get("hashes") or []:
            alg, val = h.get("alg"), h.get("content")
            if alg and val:
                hash_to_components[(alg,val)].add(component_key(c))

    for (alg,val), comps in hash_to_components.items():
        if len(comps) > 1:
            findings.append({
                "type":"SBOM_INTEGRITY","severity":cfg.get("duplicate_hash_severity","MEDIUM"),
                "title":"Same hash used by multiple distinct components",
                "detail":f"{alg} {val} is associated with {len(comps)} distinct component identities.",
                "evidence":sorted(comps)[:20]
            })

    return findings
