# WEST-DOSSIER-2026-1109 — GOLD EAGLE Cyber Defense & STIX 2.1 / VEX Telemetry Architecture

_Text export of the source ODT (WEST-DOSSIER-2026-1109__GOLD_EAGLE_Cyber_Defense___STIX_2.1_VEX_Telemetry_Architecture_0_gt9m.odt), November 9, 2026. PRIVATE / Internal only — see README.md. Code blocks are extracted verbatim into `src/`; this file is the full dossier text for reference._

WESTERN INTELLIGENCE LLC (WEST) — TECHNICAL DOSSIER
DOCUMENT ID: WEST-DOSSIER-2026-1109
DATE: November 9, 2026
TO: Daniel P. Winn, Director, Western Intelligence LLC (WEST)
SUBJECT: GOLD EAGLE Federal Cyber Defense Clearinghouse & STIX 2.1 / VEX Telemetry Automation Architecture
1. EXECUTIVE BRIEFING (DIRECTOR'S DESK)
Established July 14, 2026 under Executive Order 14409 (Promoting Advanced Artificial Intelligence) and co-chaired by the U.S. Department of the Treasury, CISA, and the Department of War, GOLD EAGLE operates on Carnegie Mellon’s VINCE infrastructure as the federal clearinghouse for AI-discovered software vulnerabilities. Because frontier AI models discover code defects faster than MITRE/NVD can mint CVE identifiers, defensive operations have shifted from vulnerability discovery to high-speed deduplication, reachability validation, and automated exposure mapping.

To prevent unverified Pre-CVE advisories from flooding internal Threat Intelligence Platforms or fracturing graph topologies, WEST's ingestion architecture enforces a four-stage operational pipeline:

Deterministic Identity Resolution (Pre-CVE to Post-CVE): Incoming GOLD EAGLE disclosures (GE-2026-XXXXX) are keyed in Redis and STIX 2.1 using a deterministic UUIDv5 derived from the target component's Package URL (PURL) and the root-cause Abstract Syntax Tree (SARIF AST) hash rather than mutable tracking strings. When an official NVD CVE is assigned weeks later, Neo4j MERGE logic re-keys the master node in place—preserving all historical edges, indicator relationships, and audit trails without spawning duplicate graph entities.
VEX & SSVC Pre-Execution Gating: Raw clearinghouse feeds are filtered through CSAF/OpenVEX exploitability states (affected, not_affected, under_investigation) and CISA Stakeholder-Specific Vulnerability Categorization (SSVC) decisions (Track, Attend, Act) embedded within a custom STIX 2.1 property extension. Non-reachable flaws (not_affected) are logged to immutable storage and suppressed from active analyst queues.
Autonomous External Surface Recon (Shodan + PostGIS): When a sandbox-verified flaw enters OpenCTI with vex_status == "affected" and ssvc_decision == "Act", an asynchronous Python enrichment worker automatically extracts the target CPE, queries Shodan for exposed internet-facing instances, and cross-references host IP coordinates against PostGIS critical infrastructure boundary polygons (5 km proximity radius).
Closed-Loop STIX 2.1 Indicator Injection: Verified external exposures within critical sector proximity are automatically written back into OpenCTI as high-confidence STIX 2.1 Indicator objects ([ipv4-addr:value = 'X.X.X.X' AND network-traffic:dst_port = YYYY]) linked via an indicates relationship to the parent vulnerability node for immediate defensive action.
2. GOLD EAGLE GOVERNANCE & FEDERAL ROUTING ARCHITECTURE
Governance & Mandate
Operational Dimension
Structural Specification
Statutory Authority
Executive Order 14409 (Promoting Advanced Artificial Intelligence, June 2, 2026)
Operational Launch
July 14, 2026 (Updated CISA TLP:CLEAR operational guidance issued August 14, 2026)
Lead Co-Chairs
U.S. Department of the Treasury & Cybersecurity and Infrastructure Security Agency (CISA)
Interagency Partners
Office of the National Cyber Director (ONCD), National Security Agency (NSA), and U.S. Department of War
Private Sector Scope
Voluntary participation from frontier AI model developers, open-source software (OSS) maintainers, commercial vendors, and critical infrastructure operators
Core Operational Pillars
Scan Deconfliction & Deduplication: Normalizes intake and deconflicts multi-engine AI scanning activity to eliminate redundant triage across agencies and vendors.
Automated Validation & Triage: Validates reproduction steps, affected versions, and exploitability signals in sandboxes before routing findings to asset owners.
Contextual Prioritization: Prioritizes defects based on sector consequence, active exploitation signals, internet exposure, dependency prevalence, and safe deployment cost.
Coordinated Vulnerability Disclosure (CVD) at Scale: Streamlines initial report triage and owner assignment across complex supply chains.
Remediation & Patch Orchestration: Coordinates rapid distribution of validated patches and actionable mitigation telemetry to critical infrastructure defenders.
Federal Channel Routing Boundaries
GOLD EAGLE (clearinghouse@cisa.dhs.gov / cisa.gov/GoldEagle): Dedicated strictly to large-scale, AI-discovered software vulnerabilities and automated multi-target scanning disclosures requiring deconfliction and multi-vendor validation.
VINCE (Vulnerability Information and Coordination Environment): Primary channel for traditional, single-instance or human-discovered Coordinated Vulnerability Disclosures.
JCDC (Joint Cyber Defense Collaborative): Operational intelligence regarding malicious adversary use of AI.
CISA Central / Incident Reporting: Active cyber intrusions, breaches, and kinetic/OT impact reporting.
3. STIX 2.1 & CSAF/VEX INTERSECTION ARCHITECTURE
Pipeline Stage
Primary Data Standard
Operational Function in GOLD EAGLE Workflow
1. Raw AI Intake
SARIF 2.1.0 + Custom PoC Traces
Frontier AI scanners submit abstract syntax tree (AST) paths, sink/source dataflow traces, and reproducer payloads to GOLD EAGLE.
2. Clearinghouse Deduplication
Semantic AST / Call-Graph Hashing
GOLD EAGLE normalizes disparate reports hitting the same underlying code defect, assigns a provisional Clearinghouse Tracking ID, and initiates sandboxed PoC verification.
3. Exploitability Attestation
CSAF 2.0 / OpenVEX / CycloneDX VEX
Upstream maintainers and clearinghouse validators emit machine-readable VEX statements (under_investigation, not_affected, affected, fixed) tied to PURL and CPE 2.3 identifiers.
4. Threat Context Dissemination
STIX 2.1 / TAXII 2.1
Validated, exploitable flaws (affected) are wrapped in STIX 2.1 Bundles combining vulnerability, software, indicator, and course-of-action SDOs/SCOs for automated ingestion into TIPs (OpenCTI / MISP).
STIX 2.1 Custom Extension Reference Payload (x-gold-eagle-vex-ext)
{
  "type": "bundle",
  "id": "bundle--8f4e2a10-5c9b-4d3e-9a1b-7c8d9e0f1a2b",
  "objects": [
    {
      "type": "vulnerability",
      "spec_version": "2.1",
      "id": "vulnerability--c24f9e1a-7b8d-4e5f-8a2c-9d1e2f3a4b5c",
      "created": "2026-11-09T18:00:00.000Z",
      "modified": "2026-11-09T18:00:00.000Z",
      "name": "GE-2026-08914 (Pre-CVE)",
      "description": "AI-identified heap buffer overflow in industrial Modbus TCP packet parser via crafted MBAP header length field.",
      "confidence": 92,
      "external_references": [
        {
          "source_name": "cisa-gold-eagle",
          "external_id": "GE-2026-08914",
          "url": "https://kb.cert.org/vince/comm/ge-2026-08914"
        }
      ],
      "extensions": {
        "extension-definition--a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d": {
          "extension_type": "property-extension",
          "ai_discovery_confidence": 0.94,
          "poc_sandbox_verified": true,
          "sarif_ast_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
          "vex_status": "affected",
          "vex_justification": null,
          "ssvc_decision": "Act"
        }
      }
    },
    {
      "type": "software",
      "spec_version": "2.1",
      "id": "software--4d5e6f7a-8b9c-5d6e-9f0a-1b2c3d4e5f6a",
      "name": "libmodbus-rtu-gw",
      "version": "3.1.8",
      "cpe": "cpe:2.3:a:vendor:libmodbus_rtu_gw:3.1.8:*:*:*:*:*:*:*",
      "x_purl": "pkg:generic/libmodbus-rtu-gw@3.1.8"
    },
    {
      "type": "relationship",
      "spec_version": "2.1",
      "id": "relationship--1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
      "created": "2026-11-09T18:00:00.000Z",
      "modified": "2026-11-09T18:00:00.000Z",
      "relationship_type": "affects",
      "source_ref": "vulnerability--c24f9e1a-7b8d-4e5f-8a2c-9d1e2f3a4b5c",
      "target_ref": "software--4d5e6f7a-8b9c-5d6e-9f0a-1b2c3d4e5f6a"
    }
  ]
}
4. PRODUCTION CODE PACKAGE
Module A: CSAF/VEX + GOLD EAGLE to STIX 2.1 Deterministic Transformer (Python)
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
Module B: Neo4j Graph Orchestration & Pre-CVE to Post-CVE State Machine (Cypher)
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
Module C: OpenCTI Enrichment Worker with Shodan & PostGIS Spatial Correlation (Python)
import os
import asyncio
import httpx
import asyncpg
from pycti import OpenCTIConnectorHelper

helper = OpenCTIConnectorHelper()
GOLD_EAGLE_EXT_ID = "extension-definition--a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
POSTGIS_DSN = os.getenv("POSTGIS_DSN")

async def query_shodan_exposures(cpe: str) -> list:
    if not SHODAN_API_KEY:
        return []
    parts = cpe.split(":")
    if len(parts) < 5:
        return []
    product_query = f'product:"{parts[4]}"'
    if len(parts) >= 6 and parts[5] != "*":
        product_query += f' version:"{parts[5]}"'

    url = f"https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query={product_query}"
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(url)
            if response.status_code == 200:
                return response.json().get("matches", [])
        except Exception as err:
            helper.log_error(f"Shodan API call failed: {str(err)}")
    return []

async def enrich_via_postgis(ip: str) -> dict:
    conn = await asyncpg.connect(POSTGIS_DSN)
    try:
        query = """
            SELECT
                geo.country_code,
                geo.city,
                geo.organization,
                ST_X(geo.geom) as longitude,
                ST_Y(geo.geom) as latitude,
                infra.sector_name,
                ST_Distance(geo.geom, infra.geom) as distance_to_critical_facility
            FROM ip_geolocation geo
            LEFT JOIN critical_infrastructure_facilities infra
              ON ST_DWithin(geo.geom, infra.geom, 5000)
            WHERE geo.ip_network >> $1::inet
            ORDER BY distance_to_critical_facility ASC
            LIMIT 1;
        """
        row = await conn.fetchrow(query, ip)
        if row:
            return {
                "country": row["country_code"],
                "city": row["city"],
                "org": row["organization"],
                "longitude": row["longitude"],
                "latitude": row["latitude"],
                "critical_proximity": row["sector_name"] if row["distance_to_critical_facility"] else "None"
            }
    except Exception as err:
        helper.log_error(f"PostGIS Spatial Query failed: {str(err)}")
    finally:
        await conn.close()
    return {}

async def process_incoming_gold_eagle_vulnerability(event_data: dict):
    vulnerability = event_data.get("vulnerability")
    extensions = vulnerability.get("extensions", {})
    ge_ext = extensions.get(GOLD_EAGLE_EXT_ID, {})

    if ge_ext.get("ssvc_decision") != "Act" or ge_ext.get("vex_status") != "affected":
        return

    software_nodes = event_data.get("affected_software", [])
    for sw in software_nodes:
        cpe = sw.get("cpe")
        if not cpe:
            continue

        exposures = await query_shodan_exposures(cpe)
        for exp in exposures:
            ip = exp.get("ip_str")
            port = exp.get("port")
            geo_risk = await enrich_via_postgis(ip)

            indicator_name = f"Vulnerable Exposure - {ip}:{port} Running {cpe}"
            desc_geo_add = ""
            if geo_risk:
                desc_geo_add = (
                    f" Location: {geo_risk['city']}, {geo_risk['country']} ({geo_risk['org']}). "
                    f"Geo-spatial sector proximity risk: {geo_risk['critical_proximity']}."
                )

            indicator = helper.api.indicator.create(
                name=indicator_name,
                description=(
                    f"Identified exposed host {ip}:{port} potentially vulnerable to "
                    f"{vulnerability['name']} via Automated GOLD EAGLE enrichment.{desc_geo_add}"
                ),
                pattern_type="stix",
                pattern=f"[ipv4-addr:value = '{ip}' AND network-traffic:dst_port = {port}]",
                x_opencti_main_observable_type="IPv4-Addr"
            )

            helper.api.relationship.create(
                fromId=indicator["id"],
                toId=vulnerability["id"],
                relationship_type="indicates"
            )
5. DEPLOYMENT CHECKLIST
STIX 2.1 / VEX Transformer: Ready — Deploy transform_goldeagle_vex_to_stix() to the primary intake worker.
Neo4j Graph State Machine: Ready — Execute the 3-stage Cypher MERGE constraints on the production graph instance.
OpenCTI Shodan/PostGIS Worker: Ready — Configure SHODAN_API_KEY and POSTGIS_DSN environment variables in container stack.
Federal Clearinghouse Channel: Active — Direct large-scale AI vulnerability coordination to clearinghouse@cisa.dhs.gov.

