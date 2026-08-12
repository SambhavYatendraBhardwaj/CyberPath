from backend.database import get_driver


START_ASSET = "Employee-Laptop-07"
from backend.database import get_driver


def analyze_impact(start_asset="Employee-Laptop-07"):

    driver = get_driver()

   
       
    with driver.session() as session:

            # existing impact analysis query/code

            ...

 

def analyze_impact(start_asset=START_ASSET):

    driver = get_driver()

  

    with driver.session() as session:

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
                    [node IN nodes(path) |
                        coalesce(node.name, node.id)
                    ] AS path_nodes,
                    length(path) AS hops

                ORDER BY hops ASC
            """,
            start=start_asset
            )

            records = list(result)

            assets = {}
            
            for record in records:

                asset_name = record["asset"]

                if asset_name not in assets:

                    assets[asset_name] = {
                        "name": asset_name,
                        "type": record["asset_type"],
                        "criticality": record["criticality"],
                        "path": record["path_nodes"],
                        "hops": record["hops"]
                    }

            critical_assets = [
                asset
                for asset in assets.values()
                if asset["criticality"] == "Critical"
            ]

            high_risk_assets = [
                asset
                for asset in assets.values()
                if asset["criticality"] == "High"
            ]

            return {
                "entry_point": start_asset,
                "total_reachable_assets": len(assets),
                "critical_assets": len(critical_assets),
                "high_risk_assets": len(high_risk_assets),
                "maximum_attack_path": max(
                    [asset["hops"] for asset in assets.values()],
                    default=0
                ),
                "affected_assets": list(assets.values())
            }

  


if __name__ == "__main__":

    result = analyze_impact()

    print("\n")
    print("=" * 60)
    print("          CYBERPATH IMPACT ANALYSIS")
    print("=" * 60)

    print("\nCompromised Entry Point:")
    print(result["entry_point"])

    print("\nTotal Reachable Assets:")
    print(result["total_reachable_assets"])

    print("Critical Assets:")
    print(result["critical_assets"])

    print("High-Risk Assets:")
    print(result["high_risk_assets"])

    print("Maximum Attack Path:")
    print(result["maximum_attack_path"], "hops")

    print("\nReachable Assets")
    print("-" * 60)

    for asset in result["affected_assets"]:

        print("\nAsset:", asset["name"])
        print("Type:", ", ".join(asset["type"]))
        print("Criticality:", asset["criticality"])
        print("Path:")
        print(" -> ".join(asset["path"]))
        print("Hops:", asset["hops"])

    print("\n")