"""
simulator/app.py — Standalone FastAPI Application for Linux Attacker Simulator.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from simulator.routes import router as simulator_router

STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(
    title="Linux Attacker Simulator",
    description="Controlled Browser-Based Attacker Simulator for AI Adaptive Cyber Deception",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(simulator_router)

if STATIC_DIR.exists():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
