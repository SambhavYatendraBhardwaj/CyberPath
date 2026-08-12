from backend.database import get_driver


START_ASSET = "Employee-Laptop-07"


def analyze_risk(start_asset=START_ASSET):

    driver = get_driver()

    

    with driver.session() as session:

            # ------------------------------------------
            # Find reachable assets
            # ------------------------------------------

            result = session.run("""
                MATCH path =
                    (start:Device {name: $start})
                    -[:CONNECTS_TO|CAN_ACCESS*1..6]->
                    (asset)

                WHERE asset:Server OR asset:Database

                RETURN
                    asset.name AS asset,
                    labels(asset) AS asset_type,
                    coalesce(
                        asset.criticality,
                        asset.sensitivity,
                        'Unknown'
                    ) AS criticality,
                    min(length(path)) AS hops
            """,
            start=start_asset
            )

            records = list(result)

            assets = {}

            for record in records:

                name = record["asset"]

                assets[name] = {
                    "type": record["asset_type"],
                    "criticality": record["criticality"],
                    "hops": record["hops"]
                }

            # ------------------------------------------
            # Asset statistics
            # ------------------------------------------

            total_assets = len(assets)

            critical_assets = [
                asset
                for asset in assets.values()
                if asset["criticality"] == "Critical"
            ]

            high_assets = [
                asset
                for asset in assets.values()
                if asset["criticality"] == "High"
            ]

            maximum_hops = max(
                [asset["hops"] for asset in assets.values()],
                default=0
            )

            # ------------------------------------------
            # Reachable vulnerabilities
            # ------------------------------------------

            vulnerability_result = session.run("""
                MATCH path =
                    (start:Device {name: $start})
                    -[:CONNECTS_TO|CAN_ACCESS*1..6]->
                    (server:Server)

                MATCH (server)-[:HAS_VULNERABILITY]->(v:Vulnerability)

                RETURN DISTINCT
                    v.id AS id,
                    v.severity AS severity,
                    server.name AS server
            """,
            start=start_asset
            )

            vulnerabilities = []

            for record in vulnerability_result:

                vulnerabilities.append({
                    "id": record["id"],
                    "severity": record["severity"],
                    "server": record["server"]
                })

            vulnerability_count = len(vulnerabilities)

            # ------------------------------------------
            # Risk scoring
            # ------------------------------------------

            score = 0

            score += len(critical_assets) * 15
            score += len(high_assets) * 10

            for vulnerability in vulnerabilities:

                severity = vulnerability["severity"]

                if severity == "Critical":
                    score += 15

                elif severity == "High":
                    score += 10

                elif severity == "Medium":
                    score += 5

                elif severity == "Low":
                    score += 2

            score += maximum_hops * 5

            score = min(score, 100)

            # ------------------------------------------
            # Risk level
            # ------------------------------------------

            if score >= 80:
                risk_level = "CRITICAL"

            elif score >= 60:
                risk_level = "HIGH"

            elif score >= 30:
                risk_level = "MEDIUM"

            else:
                risk_level = "LOW"

            # ------------------------------------------
            # Critical asset details
            # ------------------------------------------

            critical_asset_details = []

            for name, asset in assets.items():

                if asset["criticality"] == "Critical":

                    critical_asset_details.append({
                        "name": name,
                        "hops": asset["hops"]
                    })

            # ------------------------------------------
            # Return API result
            # ------------------------------------------

            return {

                "entry_point": start_asset,

                "risk_score": score,

                "risk_level": risk_level,

                "impact_summary": {

                    "total_reachable_assets": total_assets,

                    "critical_assets": len(critical_assets),

                    "high_risk_assets": len(high_assets),

                    "known_vulnerabilities": vulnerability_count,

                    "maximum_attack_path": maximum_hops
                },

                "critical_assets": critical_asset_details,

                "vulnerabilities": vulnerabilities
            }

    


# ------------------------------------------
# Run directly from terminal
# ------------------------------------------

if __name__ == "__main__":

    result = analyze_risk()

    print("\n")
    print("=" * 60)
    print("          CYBERPATH RISK ANALYSIS")
    print("=" * 60)

    print("\nEntry Point:")
    print(result["entry_point"])

    print("\nRisk Level:")
    print(result["risk_level"])

    print("\nRisk Score:")
    print(f'{result["risk_score"]}/100')

    summary = result["impact_summary"]

    print("\nImpact Summary")
    print("-" * 60)

    print(
        "Total Reachable Assets:",
        summary["total_reachable_assets"]
    )

    print(
        "Critical Assets:",
        summary["critical_assets"]
    )

    print(
        "High-Risk Assets:",
        summary["high_risk_assets"]
    )

    print(
        "Known Vulnerabilities:",
        summary["known_vulnerabilities"]
    )

    print(
        "Maximum Attack Path:",
        summary["maximum_attack_path"],
        "hops"
    )

    print("\nCritical Assets")
    print("-" * 60)

    for asset in result["critical_assets"]:

        print(
            f'{asset["name"]} '
            f'({asset["hops"]} hops)'
        )

    print("\nKnown Vulnerabilities")
    print("-" * 60)

    for vulnerability in result["vulnerabilities"]:

        print(
            f'{vulnerability["id"]} '
            f'- {vulnerability["severity"]} '
            f'[{vulnerability["server"]}]'
        )

    print("\n")