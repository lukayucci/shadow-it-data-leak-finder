"""
Router de Reportes
"""
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pathlib import Path

from web.app.core.database import get_db
from web.app.core.config import settings
from web.app.deps.auth import get_current_user
from web.app.models.user import User
from web.app.models.report import Report

router = APIRouter()
templates = Jinja2Templates(directory=str(settings.TEMPLATES_DIR))
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent

@router.get("/reports/{report_id}")
async def view_report(
    report_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Ver reporte"""
    report = db.query(Report).filter(Report.id == report_id, Report.user_id == user.id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    
    return templates.TemplateResponse("reports/view.html", {
        "request": request,
        "user": user,
        "report": report
    })

@router.get("/reports/{report_id}/download/md")
async def download_markdown(
    report_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Descargar reporte Markdown"""
    report = db.query(Report).filter(Report.id == report_id, Report.user_id == user.id).first()
    if not report or not report.markdown_file:
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    
    file_path = PROJECT_ROOT / "outputs" / report.markdown_file
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Archivo no existe")
    
    return FileResponse(
        path=file_path,
        filename=f"ShadowIT_Audit_{report.target_organization}.md",
        media_type="text/markdown"
    )

@router.get("/reports/{report_id}/download/json")
async def download_json(
    report_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Descargar reporte JSON"""
    report = db.query(Report).filter(Report.id == report_id, Report.user_id == user.id).first()
    if not report or not report.json_file:
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    
    file_path = PROJECT_ROOT / "outputs" / report.json_file
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Archivo no existe")
    
    return FileResponse(
        path=file_path,
        filename=f"ShadowIT_Audit_{report.target_organization}.json",
        media_type="application/json"
    )
