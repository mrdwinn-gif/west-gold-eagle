// 1. INGEST / UPDATE UNTREATED GOLD EAGLE DISCOVERY
MERGE (v:Vulnerability {id: $deterministic_id})
ON CREATE SET
    v.created = datetime($timestamp),
    v.primary_id = $gold_eagle_id,
    v.ast_hash = $ast_hash,
    v.purl = $purl,
    v.status = "Pre-CVE",
    v.cisa_status = $vex_status,
    v.ssvc_decision = $ssvc_decision,
    v.confidence = toInteger($confidence)
ON MATCH SET
    v.modified = datetime($timestamp),
    v.cisa_status = $vex_status,
    v.ssvc_decision = $ssvc_decision,
    v.confidence = toInteger($confidence)

MERGE (ref:ExternalReference {id: "ref_" + $gold_eagle_id})
ON CREATE SET
    ref.source = "cisa-gold-eagle",
    ref.external_id = $gold_eagle_id,
    ref.url = $gold_eagle_url
MERGE (v)-[:HAS_REFERENCE]->(ref);

// 2. COMPONENT RELATIONSHIP ASSIGNMENT
MERGE (s:Software {purl: $purl})
ON CREATE SET
    s.name = $software_name,
    s.version = $software_version,
    s.cpe = $cpe
MERGE (v)-[r:AFFECTS]->(s)
ON CREATE SET r.created = datetime($timestamp);

// 3. POST-CVE TRANSITION & IDENTITY RESOLUTION
MATCH (v:Vulnerability {id: $deterministic_id})
WHERE v.status = "Pre-CVE" OR v.primary_id STARTS WITH "GE-"
SET v.status = "Resolved",
    v.pre_cve_id = v.primary_id,
    v.primary_id = $cve_id,
    v.modified = datetime($timestamp)

MERGE (new_ref:ExternalReference {id: "ref_" + $cve_id})
ON CREATE SET
    new_ref.source = "cve",
    new_ref.external_id = $cve_id,
    new_ref.url = "https://nvd.nist.gov/vuln/detail/" + $cve_id
MERGE (v)-[:HAS_REFERENCE]->(new_ref);
