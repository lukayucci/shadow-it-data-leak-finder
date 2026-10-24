"""
Servicio de escaneo - Integra con el motor existente
"""
import asyncio
import os
import sys
from pathlib import Path
from datetime import datetime
from sqlalchemy.orm import Session

# Añadir path del proyecto principal
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from main import ShadowITFinderOrchestrator
from web.app.models.report import Report
from web.app.models.user import User

class ScannerService:
    """Servicio para ejecutar escaneos usando el motor existente"""
    
    @staticmethod
    async def run_scan_for_user(db: Session, user: User, target_org: str, report_id: int):
        """Ejecuta escaneo para un usuario"""
        report = db.query(Report).filter(Report.id == report_id).first()
        if not report:
            return
        
        try:
            report.status = "processing"
            db.commit()
            
            # Crear orquestador con target específico
            orchestrator = ShadowITFinderOrchestrator(target_org=target_org)
            
            # Ejecutar ciclo de auditoría
            success = await orchestrator.run_audit_cycle()
            
            if success:
                # Buscar el último reporte generado
                outputs_dir = PROJECT_ROOT / "outputs"
                reports = sorted(outputs_dir.glob(f"shadowit_audit_{target_org.replace('.', '_')}*.md"), key=os.path.getmtime, reverse=True)
                
                if reports:
                    md_file = reports[0]
                    json_file = md_file.with_suffix('.json')
                    
                    report.markdown_file = str(md_file.name)
                    if json_file.exists():
                        report.json_file = str(json_file.name)
                    
                    report.status = "completed"
                    report.completed_at = datetime.utcnow()
                    
                    # Extraer contadores si hay JSON
                    if json_file.exists():
                        import json
                        try:
                            with open(json_file) as f:
                                data = json.load(f)
                            analysis = data.get('analysis', {})
                            exec_sum = analysis.get('executive_summary', {})
                            report.findings_count = exec_sum.get('total_findings', 0)
                            report.critical_count = exec_sum.get('critical_count', 0)
                            report.high_count = exec_sum.get('high_count', 0)
                            report.analysis_data = analysis
                        except:
                            pass
                    
                    # Descontar crédito
                    user.credits -= 1
                    db.commit()
                else:
                    report.status = "failed"
                    db.commit()
            else:
                report.status = "failed"
                db.commit()
                
        except Exception as e:
            print(f"Error en scan: {e}")
            report.status = "failed"
            db.commit()
