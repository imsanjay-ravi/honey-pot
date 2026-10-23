"""
dashboard/app.py — FastAPI Application for Ubuntu Analysis Dashboard.

Serves:
- REST API under /api
- Static frontend UI assets (HTML/CSS/JS) under /
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from dashboard.routes import router as api_router
from simulator.routes import router as simulator_router

STATIC_DIR = Path(__file__).resolve().parent / "static"
SIMULATOR_STATIC_DIR = Path(__file__).resolve().parent.parent / "simulator" / "static"

app = FastAPI(
    title="AI Adaptive Cyber Deception Dashboard & Simulator",
    description="Browser-based Analysis Dashboard and Attacker Simulator for Fictional World State",
    version="1.0.0",
)

# Enable CORS for local testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount REST APIs
app.include_router(api_router)
app.include_router(simulator_router)

# Mount Simulator Static UI under /simulator
if SIMULATOR_STATIC_DIR.exists():
    app.mount("/simulator", StaticFiles(directory=str(SIMULATOR_STATIC_DIR), html=True), name="simulator_static")

# Mount Dashboard Static UI under /
if STATIC_DIR.exists():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
