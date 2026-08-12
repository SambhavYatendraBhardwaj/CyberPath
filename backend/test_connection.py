import os
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

URI = os.getenv("COGNODB_URI")
USERNAME = os.getenv("COGNODB_USERNAME")
PASSWORD = os.getenv("COGNODB_PASSWORD")

print("DEBUG URI:", repr(URI))
print("DEBUG USERNAME:", repr(USERNAME))

driver = GraphDatabase.driver(
    URI,
    auth=(USERNAME, PASSWORD)
)

try:
    driver.verify_connectivity()
    print("✅ Successfully connected to CognoDB")

    with driver.session() as session:
        result = session.run("RETURN 1 AS test")
        record = result.single()
        print("Cypher test result:", record["test"])

except Exception as e:
    print("❌ Connection failed")
    print(e)

finally:
    driver.close()