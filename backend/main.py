from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from backend.risk_anlaysis import analyze_risk
from backend.attack_path import find_attack_paths
from backend.impact_analysis import analyze_impact


app = FastAPI(
    title="CyberPath API",
    description="Graph-Based Attack Path & Risk Analyzer",
    version="1.0.0"
)

app.mount(
    "/dashboard",
    StaticFiles(directory="frontend", html=True),
    name="frontend"
)

@app.get("/")
def root():

    return {
        "message": "CyberPath API is running"
    }


@app.get("/api/health")
def health():

    return {
        "status": "healthy"
    }


@app.get("/api/risk-analysis")
def risk_analysis():

    return analyze_risk()


@app.get("/api/attack-path")
def attack_path():

    return find_attack_paths()


@app.get("/api/impact-analysis")
def impact_analysis():

    return analyze_impact()