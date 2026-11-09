"""
Router de Reportes
"""
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import FileResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pathlib import Path
import json
import sys

from web.app.core.database import get_db
from web.app.core.config import settings
from web.app.deps.auth import get_current_user
from web.app.models.user import User
from web.app.models.report import Report

router = APIRouter()
templates = Jinja2Templates(directory=str(settings.TEMPLATES_DIR))

# Add project root to path for config
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from config.settings import settings as main_settings

@router.get("/reports/{report_id}")
async def view_report(request: Request, report_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id, Report.user_id == user.id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    
    findings = []
    
    # Intentar cargar desde JSON
    if report.json_file:
        try:
            json_path = Path(main_settings.OUTPUT_DIR) / report.json_file
            if json_path.exists():
                with open(json_path) as f:
                    data = json.load(f)
                analysis = data.get('analysis', data)
                raw_findings = analysis.get('findings', [])
                for f in raw_findings:
                    findings.append({
                        'id': f.get('id'),
                        'title': f.get('title'),
                        'category': f.get('category'),
                        'severity': type('obj', (object,), {'value': (f.get('severity','info') or 'info').lower()})(),
                        'description': f.get('risk_description') or f.get('description') or '',
                        'evidence': json.dumps(f.get('evidence', [])),
                        'recommendation': '\n'.join(f.get('remediation', []) if isinstance(f.get('remediation'), list) else [str(f.get('remediation',''))]) if f.get('remediation') else '',
                        'verification': f.get('verification'),
                        'get_verification': f.get('verification')
                    })
        except Exception as e:
            print(f"Error loading from JSON: {e}")
    
    return templates.TemplateResponse(request, "reports/view.html", {"user": user, "report": report, "findings": findings})

@router.get("/reports/{report_id}/download/{format}")
async def download_report(report_id: int, format: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id, Report.user_id == user.id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    
    if format == "md" and report.markdown_file:
        file_path = Path(main_settings.OUTPUT_DIR) / report.markdown_file
        if file_path.exists():
            return FileResponse(path=file_path, filename=report.markdown_file, media_type='text/markdown')
    elif format == "json" and report.json_file:
        file_path = Path(main_settings.OUTPUT_DIR) / report.json_file
        if file_path.exists():
            return FileResponse(path=file_path, filename=report.json_file, media_type='application/json')
    
    raise HTTPException(status_code=404, detail="Archivo no encontrado")
