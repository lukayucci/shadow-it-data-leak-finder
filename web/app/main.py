"""
Aplicación FastAPI principal - ZERO
"""
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from pathlib import Path

from web.app.core.database import init_db
from web.app.core.config import settings
from web.app.routers import auth, dashboard, reports, intro

app = FastAPI(
    title="ZERO",
    version=settings.APP_VERSION,
    description="ZERO - Shadow IT & Data Leak Intelligence Platform"
)

BASE_DIR = Path(__file__).parent.parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app.include_router(intro.router, tags=["Intro"])
app.include_router(auth.router, tags=["Auth"])
app.include_router(dashboard.router, tags=["Dashboard"])
app.include_router(reports.router, tags=["Reports"])

@app.on_event("startup")
async def startup_event():
    print("⚡ ZERO - Initializing...")
    init_db()
    print("⚡ ZERO - Online")

@app.get("/health")
async def health():
    return {"status": "online", "system": "ZERO"}
