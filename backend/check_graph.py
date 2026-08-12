from database import get_driver


driver = get_driver()

with driver.session() as session:

    result = session.run("""
        MATCH (n)
        RETURN labels(n) AS labels, n.name AS name
        ORDER BY labels
    """)

    for record in result:
        print(record["labels"], "->", record["name"])

driver.close()