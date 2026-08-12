# CyberPath — Graph-Based Attack Path & Risk Analyzer
![alt text](<Screenshot 2026-08-12 083628.png>)
Demo Link- http://127.0.0.1:8000/dashboard/
CyberPath is a security analysis tool that models an organization's IT infrastructure as a graph — devices, servers, databases, and the connections between them — and answers a question relational databases struggle with: **"If this laptop gets compromised, what can an attacker reach, and how?"**

It traces multi-hop attack paths from a compromised entry point to critical assets (like customer or HR databases), scores overall risk, and shows the blast radius of a breach.

---

## Why a graph database?

The core question this tool answers — *"what is reachable from a compromised device, through how many hops, and via which path?"* — is a **variable-length path traversal** problem. This is exactly what graph databases are built for.

In a relational database, answering "what can Employee-Laptop-07 reach in up to 5 hops?" requires a self-join for every possible hop depth (1-hop join, 2-hop join, 3-hop join...), or a recursive CTE that gets slow and hard to read as the network grows. In CognoDB (Neo4j-compatible, openCypher), it's a single, natural query:

```cypher
MATCH path = (start:Device {name: $start})
    -[:CONNECTS_TO*1..5]->(server:Server)
    -[:CAN_ACCESS]->(database:Database)
RETURN database.name, length(path), [n IN nodes(path) | n.name]
ORDER BY length(path) ASC
```

Relationships (`CONNECTS_TO`, `CAN_ACCESS`, `USES`) are first-class citizens with their own properties, so traversal cost stays proportional to the actual size of the attack surface — not to the number of rows in a joined table. As the network grows (more devices, more segments, more attack techniques), the graph model scales naturally while the equivalent relational schema gets exponentially more painful to query.

---

## Data model

**Nodes:**
- `Device` — endpoint (e.g. employee laptops)
- `Server` — web/app/file servers (has a `criticality` property: Low / Medium / High / Critical)
- `Database` — sensitive data stores (e.g. Customer-DB, HR-Database)
- `ThreatActor` — attacker profile (e.g. External-Attacker)
- `AttackTechnique` — MITRE-style technique (e.g. Credential Theft)

**Relationships:**
- `(Device)-[:CONNECTS_TO]->(Server)` — network connectivity
- `(Server)-[:CONNECTS_TO]->(Server)` — lateral movement between tiers
- `(Server)-[:CAN_ACCESS]->(Database)` — data access path
- `(ThreatActor)-[:USES]->(AttackTechnique)` — technique used by an actor

**Example traversal (seeded data):**

```
Employee-Laptop-07 → Web-Server-01 → App-Server-01 → DB-Server-01 → Customer-DB   (4 hops)
Employee-Laptop-07 → Web-Server-01 → App-Server-01 → File-Server-01 → HR-Database (4 hops)
```

---

## Tech stack

- **Backend:** Python, FastAPI
- **Database:** CognoDB Cloud (Neo4j-compatible, Bolt protocol) via the official `neo4j` Python driver
- **Frontend:** Static HTML/CSS/JS dashboard served by FastAPI (`StaticFiles`)
- **Config:** Environment variables via `python-dotenv` — no credentials committed to the repo

---

## Project structure
![alt text](<Screenshot 2026-08-12 083449.png>)
```
cyberpath/
├── backend/
│   ├── main.py              # FastAPI app + routes
│   ├── database.py          # CognoDB driver setup (reads .env)
│   ├── attack_path.py       # Multi-hop attack path query
│   ├── risk_anlaysis.py     # Risk scoring
│   ├── impact_analysis.py   # Blast-radius / affected-assets analysis
│   ├── seed.py               # Seeds sample graph data into CognoDB
│   └── .env                 # COGNODB_URI / USERNAME / PASSWORD (not committed)
├── frontend/
│   └── index.html            # Dashboard UI
└── requirements.txt
```

---

## Setup & run instructions

### 1. Create a CognoDB Cloud instance
1. Sign up at [console.cognodb.com](https://console.cognodb.com/signup) (free, no credit card).
2. Create a free (c0) instance and pick a region.
3. Copy the connection URI (`bolt+s://<instance-id>.databases.cognodb.cloud`) and the generated password for user `cognodb` — the password is shown only once.

### 2. Configure environment variables
Create `backend/.env`:

```
COGNODB_URI=bolt+s://<your-instance-id>.databases.cognodb.cloud
COGNODB_USERNAME=cognodb
COGNODB_PASSWORD=<your-password>
```

### 3. Install dependencies

```bash
python -m venv venv
.\venv\Scripts\Activate.ps1      # Windows
pip install -r requirements.txt
```

### 4. Seed the database

```bash
python backend\seed.py
```

### 5. Run the API server

```bash
python -m uvicorn backend.main:app
```

### 6. Open the dashboard

```
http://127.0.0.1:8000/dashboard
```

---

## API endpoints

| Endpoint | Description |
|---|---|
| `GET /api/attack-path` | Returns all multi-hop attack paths from the entry point to reachable databases |
| `GET /api/risk-analysis` | Returns an overall risk score and breakdown |
| `GET /api/impact-analysis` | Returns the blast radius — all assets reachable from the compromised entry point, with criticality and hop count |

**Error handling:** each endpoint fails gracefully with a clear error response if CognoDB is unreachable, instead of crashing the server.

---

## Screenshots

*(add dashboard screenshots here — e.g. `docs/dashboard.png`)*

![CyberPath Dashboard](docs/dashboard.png)

---

## Demo

- **Hosted demo:** `<add your hosted link here>`
- **Screen recording:** `<add your recording link here>`
