# west-gold-eagle — PRIVATE / Internal only

**WEST-DOSSIER-2026-1109 — GOLD EAGLE Federal Cyber Defense Clearinghouse &
STIX 2.1 / VEX Telemetry Automation Architecture**
Western Intelligence LLC (WEST), Director Daniel Patrick Winn — November 9, 2026.

> **PRIVATE / Internal only. Do NOT make this repository public.**
> The source dossier carries no Tier/Handling marking; it is treated as
> Internal only by default under WEST Desk 3 rules until the Director
> assigns a tier. No part of this repo is published, posted, or shared
> outside WEST.

## What this is

GOLD EAGLE is described in the dossier as the federal clearinghouse for
AI-discovered software vulnerabilities (established July 14, 2026, under
Executive Order 14409; co-chaired by the U.S. Department of the Treasury,
CISA, and the Department of War; operating on Carnegie Mellon University's
VINCE infrastructure). Because frontier AI models discover code defects
faster than MITRE/NVD can mint CVE identifiers, WEST's ingestion
architecture shifts defensive work from discovery to high-speed
deduplication, reachability validation, and automated exposure mapping.

Source document: `docs/WEST-DOSSIER-2026-1109__GOLD_EAGLE_Cyber_Defense___STIX_2.1_VEX_Telemetry_Architecture_0_gt9m.odt`
(3.0 MB — most of that is fonts embedded in the ODT). A full text export
is in `docs/WEST-DOSSIER-2026-1109.md`.

## The four-stage pipeline

1. **Deterministic Identity Resolution (Pre-CVE → Post-CVE).** Incoming
   GOLD EAGLE disclosures (`GE-2026-XXXXX`) are keyed in Redis and STIX 2.1
   using a deterministic UUIDv5 derived from the target component's Package
   URL (PURL) and the root-cause SARIF AST hash — not mutable tracking
   strings. When NVD assigns an official CVE weeks later, Neo4j `MERGE`
   logic re-keys the master node in place, preserving historical edges,
   indicator relationships, and audit trails without duplicate graph
   entities.
2. **VEX & SSVC Pre-Execution Gating.** Raw feeds are filtered through
   CSAF/OpenVEX exploitability states (`affected`, `not_affected`,
   `under_investigation`) and CISA SSVC decisions (`Track`, `Attend`,
   `Act`) embedded in a custom STIX 2.1 property extension
   (`x-gold-eagle-vex-ext`). Non-reachable flaws (`not_affected`) are
   logged to immutable storage and suppressed from analyst queues.
3. **Autonomous External Surface Recon (Shodan + PostGIS).** When a
   sandbox-verified flaw enters OpenCTI with `vex_status == "affected"`
   and `ssvc_decision == "Act"`, an async Python enrichment worker extracts
   the target CPE, queries Shodan for exposed internet-facing instances,
   and cross-references host IPs against PostGIS critical-infrastructure
   boundary polygons (5 km proximity radius).
4. **Closed-Loop STIX 2.1 Indicator Injection.** Verified external
   exposures near critical sectors are written back into OpenCTI as
   high-confidence STIX 2.1 Indicator objects
   (`[ipv4-addr:value = 'X.X.X.X' AND network-traffic:dst_port = YYYY]`)
   linked via an `indicates` relationship to the parent vulnerability node.

Federal routing boundaries in the dossier: GOLD EAGLE for large-scale
AI-discovered disclosures; VINCE for traditional single-instance/human
CVD; JCDC for adversary use of AI; CISA Central for active intrusions.

## Contents

| Path | What it is |
|---|---|
| `src/stix_transformer.py` | Module A — CSAF/VEX + GOLD EAGLE → STIX 2.1 deterministic transformer (`transform_goldeagle_vex_to_stix`, `generate_deterministic_vuln_id`) |
| `src/neo4j_gold_eagle.cypher` | Module B — Neo4j graph orchestration & Pre-CVE → Post-CVE state machine (3 stages: ingest/update, component assignment, Post-CVE transition) |
| `src/opencti_enrichment_worker.py` | Module C — OpenCTI enrichment worker: Shodan exposure lookup + PostGIS spatial correlation, gated on `Act` / `affected` |
| `examples/stix_example_ge-2026-08914.json` | STIX 2.1 bundle example from the dossier (GE-2026-08914, Pre-CVE; heap buffer overflow in an industrial Modbus TCP parser; `libmodbus-rtu-gw` 3.1.8) |
| `docs/WEST-DOSSIER-2026-1109.md` | Full dossier text export |
| `docs/WEST-DOSSIER-2026-1109__GOLD_EAGLE_…_0_gt9m.odt` | Original source dossier (unmodified copy) |
| `requirements.txt` | Python dependencies |

## Configuration — environment variables only, no secrets in this repo

```sh
export SHODAN_API_KEY="…"   # Shodan API key for Module C
export POSTGIS_DSN="…"       # PostgreSQL/PostGIS DSN for Module C
```

Both Python modules read credentials only from environment variables.
No API key, token, password, or other secret is stored anywhere in this
repository (verified by scan: no literal key assignments, no `ghp_` /
`github_pat_` strings). The OpenCTI connector helper in Module C reads
its own configuration from the environment as usual for `pycti`.

## Deployment checklist (from the dossier, §5)

- STIX 2.1 / VEX Transformer: deploy `transform_goldeagle_vex_to_stix()`
  to the primary intake worker.
- Neo4j Graph State Machine: execute the 3-stage Cypher `MERGE`
  constraints on the production graph instance.
- OpenCTI Shodan/PostGIS Worker: configure `SHODAN_API_KEY` and
  `POSTGIS_DSN` in the container stack.
- Federal Clearinghouse Channel: direct large-scale AI vulnerability
  coordination to `clearinghouse@cisa.dhs.gov`.

## Verification notes (extraction, Nov 9, 2026)

- All Python files pass `python3 -m py_compile`. The STIX example
  validates with `python3 -m json.tool`.
- Code was extracted from the ODT with indentation preserved (the ODT
  encodes leading spaces as `<text:s>` runs; a flat text extraction
  drops them and would not compile). Extracted code is verbatim apart
  from that indentation recovery — no logic was rewritten.
- **Not runtime-tested:** `stix2`, `pycti`, `httpx`, and `asyncpg` were
  not installed in the extraction environment, and no OpenCTI / Neo4j /
  Shodan / PostGIS instance was available, so the modules have not been
  executed end-to-end. Deploy on a sensor/integration instance first.
- Module A imports `hashlib` but never uses it (as in the source).
- Module C has no `__main__` entry point / event-loop runner — it is a
  worker library as written in the dossier; the host connector supplies
  the loop. `OpenCTIConnectorHelper()` is constructed at import time,
  so importing the module requires a configured OpenCTI environment.
- Module B, stage 3, sets the vulnerability status to `"Resolved"` when
  a CVE is assigned (source wording, kept verbatim) — confirm that is
  the intended state name before running it on a production graph.
- The STIX example bundle references the `x-gold-eagle-vex-ext`
  extension-definition ID but does not include an `extension-definition`
  object itself in the bundle (as in the source).
- The dossier's GOLD EAGLE / Executive Order 14409 / VINCE claims are
  reproduced as written; they were **not** independently verified
  against CISA / federal sources before extraction.
