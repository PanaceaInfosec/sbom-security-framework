
from sbomsec.analyzer import analyze_sbom
def test_empty_and_beta_and_duplicate_hash():
    doc={"components":[
      {"type":"library","name":"a","version":"1.0-beta2","purl":"pkg:maven/x/a@1.0-beta2","hashes":[{"alg":"SHA-1","content":"abc"}]},
      {"type":"library","name":"b","version":"2.0","purl":"pkg:maven/x/b@2.0","hashes":[{"alg":"SHA-1","content":"abc"}]}
    ],"vulnerabilities":[]}
    f=analyze_sbom(doc,{})
    titles={x["title"] for x in f}
    assert "SBOM vulnerability array is empty" in titles
    assert "Pre-release dependency detected" in titles
    assert "Same hash used by multiple distinct components" in titles
