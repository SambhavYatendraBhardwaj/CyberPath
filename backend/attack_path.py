from backend.database import get_driver

START_ASSET = "Employee-Laptop-07"


def find_attack_paths(start_asset=START_ASSET):

    driver = get_driver()

    with driver.session() as session:

        result = session.run("""
            MATCH path =
                (start:Device {name: $start})
                -[:CONNECTS_TO*1..5]->
                (server:Server)
                -[:CAN_ACCESS]->
                (database:Database)

            RETURN
                database.name AS target,
                length(path) AS hops,
                [node IN nodes(path) | node.name] AS path_nodes

            ORDER BY hops ASC
        """,
        start=start_asset
        )

        paths = []

        for record in result:

            paths.append({
                "target": record["target"],
                "hops": record["hops"],
                "path": record["path_nodes"]
            })

        return {
            "entry_point": start_asset,
            "total_paths": len(paths),
            "paths": paths
        }


if __name__ == "__main__":

    result = find_attack_paths()

    print("\n")
    print("=" * 60)
    print("             CYBERPATH ATTACK PATHS")
    print("=" * 60)

    print("\nEntry Point:")
    print(result["entry_point"])

    print("\nTotal Attack Paths:")
    print(result["total_paths"])

    print("\nAttack Paths")
    print("-" * 60)

    for attack_path in result["paths"]:

        print(f'\nTarget: {attack_path["target"]}')
        print(f'Hops: {attack_path["hops"]}')

        print(
            "Path:",
            " -> ".join(attack_path["path"])
        )

    print("\n")