import uuid
import hashlib
from datetime import datetime, timezone
import stix2

# Define a consistent namespace for deterministic UUIDv5 generation across Pre-CVE and Post-CVE states
WEST_VULN_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
GOLD_EAGLE_EXT_ID = "extension-definition--a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"

def generate_deterministic_vuln_id(purl: str, ast_hash: str) -> str:
    """
    Generates a deterministic STIX 2.1 Vulnerability ID based on component PURL
    and root-cause AST hash rather than mutable CVE/GE tracking names.
    """
    canonical_seed = f"{purl.strip().lower()}::{ast_hash.strip().lower()}"
    deterministic_uuid = uuid.uuid5(WEST_VULN_NAMESPACE, canonical_seed)
    return f"vulnerability--{deterministic_uuid}"

def transform_goldeagle_vex_to_stix(advisory_payload: dict) -> stix2.Bundle:
    """
    Transforms a GOLD EAGLE / CSAF VEX JSON payload into a STIX 2.1 Bundle
    with VEX exploitability gating and deterministic identity resolution.
    """
    ge_id = advisory_payload.get("gold_eagle_id")
    cve_id = advisory_payload.get("cve_id")  # May be None during initial AI discovery
    purl = advisory_payload["target"]["purl"]
    cpe = advisory_payload["target"]["cpe"]
    ast_hash = advisory_payload["ai_telemetry"]["sarif_ast_hash"]
    vex_status = advisory_payload["vex"]["status"]
    poc_verified = advisory_payload["ai_telemetry"]["poc_sandbox_verified"]
    ai_confidence = advisory_payload["ai_telemetry"]["confidence_score"]

    # 1. Gate confidence scoring based on VEX status and sandbox PoC verification
    if vex_status == "not_affected":
        stix_confidence = 0
    elif vex_status == "affected" and poc_verified:
        stix_confidence = int(ai_confidence * 100)
    else:
        stix_confidence = 35  # 'under_investigation' or unverified PoC

    # 2. Construct External References (handling both Pre-CVE and Post-CVE states)
    ext_refs = [
        stix2.ExternalReference(
            source_name="cisa-gold-eagle",
            external_id=ge_id,
            url=f"https://kb.cert.org/vince/comm/{ge_id.lower()}"
        )
    ]
    if cve_id:
        ext_refs.append(
            stix2.ExternalReference(
                source_name="cve",
                external_id=cve_id,
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            )
        )

    # 3. Generate deterministic STIX Vulnerability SDO
    vuln_id = generate_deterministic_vuln_id(purl, ast_hash)
    primary_name = cve_id if cve_id else f"{ge_id} (Pre-CVE)"

    vuln_sdo = stix2.Vulnerability(
        id=vuln_id,
        name=primary_name,
        description=advisory_payload.get("summary", "GOLD EAGLE AI-validated defect."),
        confidence=stix_confidence,
        external_references=ext_refs,
        extensions={
            GOLD_EAGLE_EXT_ID: {
                "extension_type": "property-extension",
                "ai_discovery_confidence": ai_confidence,
                "poc_sandbox_verified": poc_verified,
                "sarif_ast_hash": ast_hash,
                "vex_status": vex_status,
                "vex_justification": advisory_payload["vex"].get("justification"),
                "ssvc_decision": advisory_payload["triage"].get("ssvc_decision", "Track")
            }
        },
        allow_custom=True
    )

    # 4. Generate Software SCO
    software_uuid = uuid.uuid5(WEST_VULN_NAMESPACE, purl.strip().lower())
    software_sco = stix2.Software(
        id=f"software--{software_uuid}",
        name=advisory_payload["target"]["name"],
        version=advisory_payload["target"]["version"],
        cpe=cpe,
        x_purl=purl,
        allow_custom=True
    )

    # 5. Link via Relationship SRO
    rel_uuid = uuid.uuid5(WEST_VULN_NAMESPACE, f"{vuln_id}::affects::{software_sco.id}")
    rel_sro = stix2.Relationship(
        id=f"relationship--{rel_uuid}",
        relationship_type="affects",
        source_ref=vuln_sdo.id,
        target_ref=software_sco.id,
        start_time=datetime.now(timezone.utc)
    )

    return stix2.Bundle(objects=[vuln_sdo, software_sco, rel_sro], allow_custom=True)
