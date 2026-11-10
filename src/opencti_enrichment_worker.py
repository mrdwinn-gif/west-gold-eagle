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
