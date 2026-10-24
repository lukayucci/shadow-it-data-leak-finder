"""
Router de Dashboard
"""
from fastapi import APIRouter, Depends, Request, Form, BackgroundTasks
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from datetime import datetime

from web.app.core.database import get_db
from web.app.core.config import settings
from web.app.deps.auth import get_current_user
from web.app.models.user import User
from web.app.models.report import Report
from web.app.services.scanner_service import ScannerService

router = APIRouter()
templates = Jinja2Templates(directory=str(settings.TEMPLATES_DIR))

@router.get("/dashboard")
async def dashboard(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Dashboard principal"""
    reports = db.query(Report).filter(Report.user_id == user.id).order_by(Report.created_at.desc()).limit(10).all()
    
    return templates.TemplateResponse("dashboard/index.html", {
        "request": request,
        "user": user,
        "reports": reports
    })

@router.post("/dashboard/scan")
async def create_scan(
    request: Request,
    background_tasks: BackgroundTasks,
    target_organization: str = Form(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Crear nuevo escaneo"""
    if user.credits <= 0:
        return templates.TemplateResponse("dashboard/index.html", {
            "request": request,
            "user": user,
            "reports": db.query(Report).filter(Report.user_id == user.id).order_by(Report.created_at.desc()).limit(10).all(),
            "error": "No tienes créditos disponibles. Actualiza tu plan."
        })
    
    # Crear registro de reporte
    report = Report(
        user_id=user.id,
        title=f"Audit - {target_organization}",
        target_organization=target_organization,
        status="pending"
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    
    # Ejecutar en background
    background_tasks.add_task(ScannerService.run_scan_for_user, db, user, target_organization, report.id)
    
    return RedirectResponse(url="/dashboard", status_code=303)
