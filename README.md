# SBOM Security Framework

A lightweight CycloneDX JSON validator and vulnerability-correlation tool.

## Detects
- Empty embedded vulnerability arrays
- Alpha/beta/RC/snapshot dependencies
- Missing PURLs
- Suspicious identical hashes across distinct components
- OSV package/version matches
- CISA Known Exploited Vulnerabilities correlation
- FIRST EPSS enrichment
- JSON, CSV and HTML reports
- CI-friendly exit status

## Install
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
# source .venv/bin/activate
pip install -r requirements.txt
```

## Run offline
```bash
python sbom_analyzer.py --sbom your-cyclonedx.json --offline --output reports
```

## Run with vulnerability intelligence
```bash
python sbom_analyzer.py --sbom your-cyclonedx.json --output reports
```

Internet access is required for OSV, CISA KEV and EPSS enrichment.

## Docker
```bash
docker build -t sbom-security-framework .
docker run --rm -v "$PWD:/data" sbom-security-framework --sbom /data/bom.json --output /data/reports
```

## Important
A package/version advisory match is a triage finding, not proof of exploitability. Confirm vendor applicability, configuration and code reachability before final VAPT disposition.


## Recommendations column
Reports now include `recommendations`. For OSV vulnerability matches the framework extracts explicit fixed versions where available and recommends that upgrade. If the source does not provide a fixed version, the tool does not invent one and instead directs the analyst to the vendor/upstream advisory. KEV findings receive urgent remediation guidance.


## v3 fixes
- OSV query results are enriched with `GET /v1/vulns/{id}` before fixed-version extraction.
- `fixed_version` is extracted from matching non-GIT OSV affected ranges/events/fixed values.
- The report `version` field strips Python/PEP 440 local build metadata after `+` (for example `2.13.0+cu126` displays as `2.13.0`).
- `original_version` preserves the exact SBOM value (`2.13.0+cu126`) for auditability and accurate vulnerability lookup.
