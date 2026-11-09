"""
Servicio de escaneo - Usa modo REAL PASIVO unificado con mejoras
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

from modules.recon.real_passive import RealPassiveCollector
from modules.checks.http_inspector import HTTPInspector
from modules.checks.tls_inspector import TLSInspector
from modules.checks.ssrf_guard import validate_host
from modules.reports.report_generator import ReportGenerator
from config.settings import settings
from web.app.core.database import SessionLocal
from web.app.models.report import Report
from web.app.models.user import User

class ScannerService:
    """Servicio para ejecutar escaneos usando modo REAL unificado"""
    
    @staticmethod
    async def run_scan_for_user(db: Session, user: User, target_org: str, report_id: int):
        """Ejecuta escaneo unificado REAL para un usuario"""
        # Crear sesión propia para evitar problemas con background tasks
        db = SessionLocal()
        try:
            report = db.query(Report).filter(Report.id == report_id).first()
            user_id = getattr(user, "id", None); user = db.query(User).filter(User.id == user_id).first() if user_id else None
            if not report:
                return
            
            report.status = "processing"
            db.commit()
            
            target = target_org.replace('https://','').replace('http://','').replace('www.','').split('/')[0].split('?')[0]
            if not target:
                target = target_org

            safe, reason = validate_host(target)
            if not safe:
                raise ValueError(f"Objetivo no permitido: {reason}")

            # Usar modo real pasivo unificado
            rpc = RealPassiveCollector()
            data = await rpc.collect_real(target)
            
            hinsp = HTTPInspector()
            http_findings = hinsp.inspect(data['live_hosts'])
            
            tins = TLSInspector()
            tls = tins.inspect(target)
            
            findings = []
            fid = 1
            
            # Procesar hallazgos del inspector
            for hf in http_findings:
                if hf['type'] == 'MISSING_SECURITY_HEADERS':
                    findings.append({
                        "id": f"FIND-{fid:03d}",
                        "title": "Configuración de seguridad faltante - Cabeceras HTTP",
                        "category": "MISCONFIGURATION",
                        "severity": "MEDIO",
                        "cvss_score": 5.3,
                        "risk_description": "Faltan cabeceras de seguridad recomendadas. Se pueden verificar públicamente con curl o DevTools.",
                        "evidence": [hf['evidence']],
                        "affected_assets": [hf['url']],
                        "impact": "Reduce la protección contra ataques del lado cliente.",
                        "likelihood": "MEDIA",
                        "immediate_actions": ["Revisar cabeceras HTTP en servidor/proxy/CDN"],
                        "remediation": ["Añadir las cabeceras faltantes con valores correctos"],
                        "prevention": ["Hardening de cabeceras HTTP", "Revisiones periódicas"],
                        "verification": {
                            "manual_verifiable": True,
                            "method": f"curl -I https://{target}",
                            "how_to_check": "Abrir DevTools (F12) > Network > Request > Response Headers o ejecutar curl -I"
                        },
                        "priority": fid
                    })
                    fid += 1
                elif hf['type'] == 'INSECURE_COOKIE':
                    findings.append({
                        "id": f"FIND-{fid:03d}",
                        "title": "Cookie con atributos de seguridad faltantes",
                        "category": "MISCONFIGURATION",
                        "severity": "MEDIO",
                        "cvss_score": 5.4,
                        "risk_description": "Algunas cookies no tienen HttpOnly/Secure/SameSite. Si existe XSS, cookies sin HttpOnly pueden ser leídas por JavaScript.",
                        "evidence": [hf['evidence'], f"Issues: {', '.join(hf.get('issues',[]))}"],
                        "affected_assets": [hf['url']],
                        "impact": "Aumenta el impacto si existe una vulnerabilidad XSS.",
                        "likelihood": "MEDIA",
                        "immediate_actions": ["Revisar configuración de cookies"],
                        "remediation": ["Añadir HttpOnly, Secure, SameSite según corresponda"],
                        "prevention": ["Hardening de configuración de sesiones"],
                        "verification": {
                            "manual_verifiable": True,
                            "method": f"curl -I https://{target} | grep -i set-cookie",
                            "how_to_check": "Ver Set-Cookie en DevTools > Network > Response Headers o con curl"
                        },
                        "priority": fid
                    })
                    fid += 1
                elif hf['type'] == 'REDIRECT_CHAIN':
                    findings.append({
                        "id": f"FIND-{fid:03d}",
                        "title": "Cadena de redirecciones detectada",
                        "category": "INFORMATIONAL",
                        "severity": "INFORMATIVO",
                        "cvss_score": 0.0,
                        "risk_description": "Cadena de redirecciones HTTP detectada.",
                        "evidence": [hf['evidence']],
                        "affected_assets": [hf['url']],
                        "impact": "Informativo. Verificar que termina en HTTPS.",
                        "likelihood": "BAJA",
                        "immediate_actions": ["Verificar redirecciones"],
                        "remediation": ["Forzar HTTPS directamente"],
                        "prevention": ["Configurar correctamente"],
                        "verification": {
                            "manual_verifiable": True,
                            "method": f"curl -I -L https://{target}",
                            "how_to_check": "Seguir la cadena con curl -I -L"
                        },
                        "priority": fid
                    })
                    fid += 1
                elif hf['type'] == 'ROBOTS_TXT_PRESENT':
                    findings.append({
                        "id": f"FIND-{fid:03d}",
                        "title": "robots.txt accesible públicamente",
                        "category": "INFORMATIONAL",
                        "severity": "INFORMATIVO",
                        "cvss_score": 0.0,
                        "risk_description": "robots.txt accesible públicamente. Puede revelar rutas.",
                        "evidence": [hf['evidence']],
                        "affected_assets": [f"https://{target}/robots.txt"],
                        "impact": "Informativo.",
                        "likelihood": "BAJA",
                        "immediate_actions": ["Revisar contenido"],
                        "remediation": ["No revelar rutas sensibles"],
                        "prevention": ["Revisión periódica"],
                        "verification": {
                            "manual_verifiable": True,
                            "method": f"curl https://{target}/robots.txt",
                            "how_to_check": "Accesible desde navegador o curl"
                        },
                        "priority": fid
                    })
                    fid += 1
                elif hf['type'] == 'SECURITY_TXT_PRESENT':
                    findings.append({
                        "id": f"FIND-{fid:03d}",
                        "title": "security.txt presente (Buena práctica)",
                        "category": "INFORMATIONAL",
                        "severity": "INFORMATIVO",
                        "cvss_score": 0.0,
                        "risk_description": "security.txt presente siguiendo RFC 9116.",
                        "evidence": [hf['evidence']],
                        "affected_assets": [f"https://{target}/.well-known/security.txt"],
                        "impact": "Positivo.",
                        "likelihood": "BAJA",
                        "immediate_actions": ["Verificar actualizado"],
                        "remediation": ["Mantener actualizado"],
                        "prevention": ["Incluir en proceso"],
                        "verification": {
                            "manual_verifiable": True,
                            "method": f"curl https://{target}/.well-known/security.txt",
                            "how_to_check": "Verificable públicamente"
                        },
                        "priority": fid
                    })
                    fid += 1
                elif hf['type'] == 'CSP_WEAKNESS':
                    findings.append({
                        "id": f"FIND-{fid:03d}",
                        "title": "Content-Security-Policy con directivas débiles",
                        "category": "MISCONFIGURATION",
                        "severity": "MEDIO",
                        "cvss_score": 4.3,
                        "risk_description": "CSP presente pero permite directivas potencialmente débiles.",
                        "evidence": [hf['evidence']],
                        "affected_assets": [hf['url']],
                        "impact": "Reduce efectividad de CSP contra XSS.",
                        "likelihood": "MEDIA",
                        "immediate_actions": ["Revisar política CSP"],
                        "remediation": ["Eliminar unsafe-inline/unsafe-eval si es posible", "Usar nonces o hashes"],
                        "prevention": ["CSP estricto"],
                        "verification": {
                            "manual_verifiable": True,
                            "method": f"curl -I https://{target} | grep -i content-security-policy",
                            "how_to_check": "Revisar valor completo de CSP"
                        },
                        "priority": fid
                    })
                    fid += 1
            
            # TLS
            if tls and tls.get('valid'):
                findings.append({
                    "id": f"FIND-{fid:03d}",
                    "title": "Certificado TLS verificado",
                    "category": "INFORMATIONAL",
                    "severity": "INFORMATIVO",
                    "cvss_score": 0.0,
                    "risk_description": "Certificado TLS válido.",
                    "evidence": [f"Emisor: {tls.get('issuer')}, Vence: {tls.get('not_after')}, SANs: {tls.get('san')}"],
                    "affected_assets": [target],
                    "impact": "Configuración correcta.",
                    "likelihood": "BAJA",
                    "immediate_actions": ["Monitorear expiración"],
                    "remediation": ["Renovar a tiempo"],
                    "prevention": ["Renovación automática"],
                    "verification": {
                        "manual_verifiable": True,
                        "method": f"openssl s_client -connect {target}:443 -servername {target}",
                        "how_to_check": "Verificable con openssl o navegador"
                    },
                    "priority": fid
                })
                fid += 1
            
            # Subdominios
            if data.get('subdomains'):
                findings.append({
                    "id": f"FIND-{fid:03d}",
                    "title": "Subdominios públicos detectados (crt.sh)",
                    "category": "SHADOW_IT",
                    "severity": "INFORMATIVO",
                    "cvss_score": 0.0,
                    "risk_description": "Subdominios en certificados TLS públicos.",
                    "evidence": [f"{len(data['subdomains'])} subdominios: {', '.join(data['subdomains'][:12])}"],
                    "affected_assets": data['subdomains'][:15],
                    "impact": "Mayor superficie de ataque.",
                    "likelihood": "BAJA",
                    "immediate_actions": ["Inventariar"],
                    "remediation": ["Descomisionar no usados"],
                    "prevention": ["Gestión de DNS"],
                    "verification": {
                        "manual_verifiable": True,
                        "method": f"https://crt.sh/?q=%.{target}",
                        "how_to_check": f"Buscar en crt.sh con %.{target}"
                    },
                    "priority": fid
                })
                fid += 1
            
            if not findings:
                findings.append({
                    "id": f"FIND-{fid:03d}",
                    "title": "Sin exposiciones públicas obvias detectadas",
                    "category": "INFORMATIONAL",
                    "severity": "INFORMATIVO",
                    "cvss_score": 0.0,
                    "risk_description": "Sin hallazgos evidentes con reconocimiento pasivo.",
                    "evidence": [f"crt.sh consultado, {len(data.get('live_hosts',[]))} hosts vivos"],
                    "affected_assets": [target],
                    "impact": "Sin hallazgos críticos visibles pasivamente.",
                    "likelihood": "BAJA",
                    "immediate_actions": ["Mantener monitoreo"],
                    "remediation": ["Buenas prácticas"],
                    "prevention": ["Auditorías periódicas"],
                    "verification": {"manual_verifiable": True, "method": "crt.sh + curl", "how_to_check": "Verificable públicamente"},
                    "priority": 99
                })
            
            crit = sum(1 for f in findings if f['severity']=='CRITICO')
            high = sum(1 for f in findings if f['severity']=='ALTO')
            med = sum(1 for f in findings if f['severity']=='MEDIO')
            low = sum(1 for f in findings if f['severity']=='BAJO')
            info = sum(1 for f in findings if f['severity']=='INFORMATIVO')
            actionable = len([f for f in findings if f['severity'] not in ['INFORMATIVO']])
            
            analysis_result = {
                "executive_summary": {
                    "overall_risk": "ALTO" if high else "MEDIO" if med else "BAJO",
                    "total_findings": actionable,
                    "critical_count": crit,
                    "high_count": high,
                    "medium_count": med,
                    "low_count": low,
                    "info_count": info,
                    "key_concern": "Hallazgos verificables públicamente" if med else "Superficie revisada pasivamente"
                },
                "findings": findings,
                "attack_surface_summary": {
                    "exposed_subdomains": len(data.get('subdomains', [])),
                    "public_buckets": 0,
                    "exposed_configs": 0,
                    "dev_servers": 0,
                    "potential_credentials": 0
                },
                "recommendations": {
                    "immediate": ["Corregir cabeceras faltantes", "Revisar cookies"],
                    "short_term": ["Endurecer CSP", "Inventariar subdominios"],
                    "long_term": ["Monitoreo continuo de exposición"]
                },
                "compliance_notes": "Análisis 100% PASIVO. Todos los hallazgos verificables manualmente."
            }
            
            report_generator = ReportGenerator(settings.OUTPUT_DIR)
            saved_files = report_generator.save_report(analysis_result, target, formats=["markdown", "json"])
            
            report.markdown_file = Path(saved_files['markdown']).name
            if 'json' in saved_files:
                report.json_file = Path(saved_files['json']).name
            
            report.status = "completed"
            report.completed_at = datetime.utcnow()
            report.findings_count = actionable
            report.critical_count = crit
            report.high_count = high
            report.medium_count = med
            report.low_count = low
            report.info_count = info
            report.analysis_data = analysis_result
            
            try:
                if user and user.credits > 0:
                    user.credits -= 1
            except:
                pass
            db.commit()
                
        except Exception as e:
            print(f"Error en scan: {e}")
            try:
                report = db.query(Report).filter(Report.id == report_id).first()
                if report:
                    report.status = "failed"
                    db.commit()
            except:
                pass
        finally:
            db.close()
