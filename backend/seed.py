from database import get_driver


def seed_database():
    driver = get_driver()

    with driver.session() as session:

        # ==========================================
        # CLEAR EXISTING GRAPH
        # ==========================================

        session.run("MATCH (n) DETACH DELETE n")

        # ==========================================
        # THREAT ACTOR
        # ==========================================

        session.run("""
            CREATE (:ThreatActor {
                name: 'External-Attacker',
                type: 'External',
                sophistication: 'Medium'
            })
        """)

        # ==========================================
        # DEVICES
        # ==========================================

        session.run("""
            CREATE (:Device {
                name: 'Employee-Laptop-07',
                os: 'Windows 11',
                ip: '10.0.1.27',
                status: 'Compromised'
            })
        """)

        # ==========================================
        # SERVERS
        # ==========================================

        session.run("""
            CREATE (:Server {
                name: 'Web-Server-01',
                type: 'Web Server',
                criticality: 'Medium'
            })
        """)

        session.run("""
            CREATE (:Server {
                name: 'App-Server-01',
                type: 'Application Server',
                criticality: 'High'
            })
        """)

        session.run("""
            CREATE (:Server {
                name: 'DB-Server-01',
                type: 'Database Server',
                criticality: 'Critical'
            })
        """)

        session.run("""
            CREATE (:Server {
                name: 'File-Server-01',
                type: 'File Server',
                criticality: 'High'
            })
        """)

        # ==========================================
        # DATABASES
        # ==========================================

        session.run("""
            CREATE (:Database {
                name: 'Customer-DB',
                sensitivity: 'Critical',
                data_type: 'Customer Information'
            })
        """)

        session.run("""
            CREATE (:Database {
                name: 'HR-Database',
                sensitivity: 'Critical',
                data_type: 'Employee Information'
            })
        """)

        # ==========================================
        # VULNERABILITIES
        # ==========================================

        session.run("""
            CREATE (:Vulnerability {
                id: 'CVE-DEMO-001',
                severity: 'Critical',
                description: 'Example remote code execution vulnerability'
            })
        """)

        session.run("""
            CREATE (:Vulnerability {
                id: 'CVE-DEMO-002',
                severity: 'High',
                description: 'Example credential exposure vulnerability'
            })
        """)

        # ==========================================
        # ATTACK TECHNIQUES
        # ==========================================

        session.run("""
            CREATE (:AttackTechnique {
                name: 'Privilege Escalation',
                category: 'Privilege Escalation'
            })
        """)

        session.run("""
            CREATE (:AttackTechnique {
                name: 'Credential Theft',
                category: 'Credential Access'
            })
        """)

        # ==========================================
        # THREAT ACTOR → DEVICE
        # ==========================================

        session.run("""
            MATCH (a:ThreatActor {name: 'External-Attacker'}),
                  (d:Device {name: 'Employee-Laptop-07'})
            CREATE (a)-[:COMPROMISES]->(d)
        """)

        # ==========================================
        # NETWORK CONNECTIONS
        # ==========================================

        session.run("""
            MATCH (d:Device {name: 'Employee-Laptop-07'}),
                  (w:Server {name: 'Web-Server-01'})
            CREATE (d)-[:CONNECTS_TO]->(w)
        """)

        session.run("""
            MATCH (w:Server {name: 'Web-Server-01'}),
                  (a:Server {name: 'App-Server-01'})
            CREATE (w)-[:CONNECTS_TO]->(a)
        """)

        # App Server → DB Server
        session.run("""
            MATCH (a:Server {name: 'App-Server-01'}),
                  (dbs:Server {name: 'DB-Server-01'})
            CREATE (a)-[:CONNECTS_TO]->(dbs)
        """)

        # App Server → File Server
        session.run("""
            MATCH (a:Server {name: 'App-Server-01'}),
                  (f:Server {name: 'File-Server-01'})
            CREATE (a)-[:CONNECTS_TO]->(f)
        """)

        # ==========================================
        # SERVER → DATABASE ACCESS
        # ==========================================

        session.run("""
            MATCH (dbs:Server {name: 'DB-Server-01'}),
                  (db:Database {name: 'Customer-DB'})
            CREATE (dbs)-[:CAN_ACCESS]->(db)
        """)

        session.run("""
            MATCH (f:Server {name: 'File-Server-01'}),
                  (db:Database {name: 'HR-Database'})
            CREATE (f)-[:CAN_ACCESS]->(db)
        """)

        # ==========================================
        # VULNERABILITY → SERVER
        # ==========================================

        session.run("""
            MATCH (a:Server {name: 'App-Server-01'}),
                  (v:Vulnerability {id: 'CVE-DEMO-001'})
            CREATE (a)-[:HAS_VULNERABILITY]->(v)
        """)

        session.run("""
            MATCH (f:Server {name: 'File-Server-01'}),
                  (v:Vulnerability {id: 'CVE-DEMO-002'})
            CREATE (f)-[:HAS_VULNERABILITY]->(v)
        """)

        # ==========================================
        # VULNERABILITY → TECHNIQUE
        # ==========================================

        session.run("""
            MATCH (v:Vulnerability {id: 'CVE-DEMO-001'}),
                  (t:AttackTechnique {name: 'Privilege Escalation'})
            CREATE (v)-[:ENABLES]->(t)
        """)

        session.run("""
            MATCH (v:Vulnerability {id: 'CVE-DEMO-002'}),
                  (t:AttackTechnique {name: 'Credential Theft'})
            CREATE (v)-[:ENABLES]->(t)
        """)

        # ==========================================
        # ATTACKER → TECHNIQUES
        # ==========================================

        session.run("""
            MATCH (a:ThreatActor {name: 'External-Attacker'}),
                  (t:AttackTechnique {name: 'Privilege Escalation'})
            CREATE (a)-[:USES]->(t)
        """)

        session.run("""
            MATCH (a:ThreatActor {name: 'External-Attacker'}),
                  (t:AttackTechnique {name: 'Credential Theft'})
            CREATE (a)-[:USES]->(t)
        """)

    driver.close()

    print("✅ CyberPath graph seeded successfully!")


if __name__ == "__main__":
    seed_database()