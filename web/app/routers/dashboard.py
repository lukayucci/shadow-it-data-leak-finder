"""
Router de Dashboard
"""
import asyncio
import re
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Request, Form, BackgroundTasks
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from web.app.core.database import get_db
from web.app.core.config import settings
from web.app.deps.auth import get_current_user
from web.app.models.user import User
from web.app.models.report import Report
from web.app.services.scanner_service import ScannerService
from web.app.core.limiter import limiter
from modules.checks.ssrf_guard import validate_host

router = APIRouter()
templates = Jinja2Templates(directory=str(settings.TEMPLATES_DIR))

HOST_RE = re.compile(r"(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}")


def _target_host(raw: str) -> str:
    return (
        raw.strip()
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
        .split("?")[0]
        .split("#")[0]
        .split("@")[-1]
        .split(":")[0]
        .strip()
        .strip(".")
    )


def _valid_target(raw: str) -> bool:
    return bool(HOST_RE.fullmatch(_target_host(raw)))


def _render_dashboard(request: Request, db: Session, user: User, error: str | None = None):
    reports = db.query(Report).filter(Report.user_id == user.id).order_by(Report.created_at.desc()).limit(10).all()
    context = {"user": user, "reports": reports}
    if error:
        context["error"] = error
    return templates.TemplateResponse(request, "dashboard/index.html", context, status_code=200)

@router.get("/dashboard")
async def dashboard(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    reports = db.query(Report).filter(Report.user_id == user.id).order_by(Report.created_at.desc()).limit(10).all()
    return templates.TemplateResponse(request, "dashboard/index.html", {"user": user, "reports": reports})

@router.post("/dashboard/scan")
@limiter.limit("5/minute")
async def create_scan(request: Request, background_tasks: BackgroundTasks, target_organization: str = Form(default=""), user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    target = (target_organization or "").strip()
    if not target:
        try:
            form = await request.form()
            target = (form.get('target_organization') or "").strip()
        except Exception:
            pass
    if not target or not _valid_target(target):
        return _render_dashboard(request, db, user, "Ingresa un dominio válido.")
    safe, reason = await asyncio.to_thread(validate_host, _target_host(target))
    if not safe:
        return _render_dashboard(
            request, db, user,
            "Dominio no permitido. Debe ser un dominio público (no IPs ni redes internas).",
        )
    if user.credits <= 0:
        return _render_dashboard(request, db, user, "No tienes créditos disponibles.")

    recent_window = datetime.utcnow() - timedelta(minutes=5)
    active = (
        db.query(Report)
        .filter(
            Report.user_id == user.id,
            Report.status.in_(["pending", "processing"]),
            Report.created_at >= recent_window,
        )
        .first()
    )
    if active:
        return _render_dashboard(request, db, user, "Ya tenés un escaneo en curso. Esperá a que finalice.")

    report = Report(user_id=user.id, title=f"Audit - {target}", target_organization=target, status="pending")
    db.add(report)
    db.commit()
    db.refresh(report)

    background_tasks.add_task(ScannerService.run_scan_for_user, None, user, target, report.id)
    return RedirectResponse(url="/dashboard?scan_started=1", status_code=303)
