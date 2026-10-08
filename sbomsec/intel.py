
import requests

UA = {"User-Agent":"sbom-security-framework/1.0"}

def _ecosystem_from_purl(purl):
    if not purl or not purl.startswith("pkg:"): return None, None
    body = purl[4:].split("?",1)[0].split("#",1)[0]
    typ, rest = body.split("/",1) if "/" in body else (body,"")
    namever = rest.rsplit("@",1)
    name = namever[0]
    version = namever[1] if len(namever)==2 else None
    mapping = {"maven":"Maven","pypi":"PyPI","npm":"npm","golang":"Go","cargo":"crates.io","nuget":"NuGet","gem":"RubyGems"}
    return mapping.get(typ), (name, version)

def query_osv(component, timeout=15):
    purl = component.get("purl")
    ecosystem, nv = _ecosystem_from_purl(purl)
    if not ecosystem or not nv or not nv[1]: return []
    name, version = nv
    try:
        r = requests.post("https://api.osv.dev/v1/query",
            json={"package":{"name":name,"ecosystem":ecosystem},"version":version},
            headers=UA, timeout=timeout)
        r.raise_for_status()
        vulns = r.json().get("vulns",[])
        enriched=[]
        for v in vulns:
            vid=v.get("id")
            if not vid:
                enriched.append(v); continue
            try:
                d=requests.get(f"https://api.osv.dev/v1/vulns/{vid}",headers=UA,timeout=timeout)
                d.raise_for_status()
                enriched.append(d.json())
            except Exception:
                enriched.append(v)
        return enriched
    except Exception:
        return []

def load_kev(timeout=20):
    try:
        r=requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                       headers=UA, timeout=timeout)
        r.raise_for_status()
        return {x["cveID"]:x for x in r.json().get("vulnerabilities",[])}
    except Exception:
        return {}

def get_epss(cves, timeout=20):
    if not cves: return {}
    out={}
    for i in range(0,len(cves),100):
        chunk=",".join(cves[i:i+100])
        try:
            r=requests.get("https://api.first.org/data/v1/epss",params={"cve":chunk},headers=UA,timeout=timeout)
            r.raise_for_status()
            for x in r.json().get("data",[]):
                out[x["cve"]]={"epss":x.get("epss"),"percentile":x.get("percentile")}
        except Exception:
            pass
    return out
