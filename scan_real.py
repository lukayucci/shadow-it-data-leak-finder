#!/usr/bin/env python3
import asyncio
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from modules.recon.real_passive import RealPassiveCollector
from modules.checks.http_inspector import HTTPInspector
from modules.checks.tls_inspector import TLSInspector
from modules.reports.report_generator import ReportGenerator
from config.settings import settings

async def main():
    if len(sys.argv) < 2:
        print("Usage: python scan_real.py example.com")
        sys.exit(1)
    target = sys.argv[1].replace('https://','').replace('http://','').replace('www.','').split('/')[0]
    print(f"🎯 ZERO - PASSIVE REAL SCAN | {target}")
    print("="*60)
    
    rpc = RealPassiveCollector()
    data = await rpc.collect_real(target)
    
    hinsp = HTTPInspector()
    http_findings = hinsp.inspect(data['live_hosts'])
    
    tins = TLSInspector()
    tls = tins.inspect(target)
    print(f"[TLS] {tls}")
    
    findings = []
    fid = 1
    # Map real findings
    for hf in http_findings:
        sev = hf['severity_hint']
        if sev == 'MEDIUM':
            findings.append({
                "id": f"FIND-{fid:03d}",
                "title": f"Configuración de seguridad faltante - {hf['type']}",
                "category": "MISCONFIGURATION",
                "severity": "MEDIO",
                "cvss_score": 5.3,
                "risk_description": "Faltan cabeceras de seguridad recomendadas o hay configuraciones inseguras visibles públicamente.",
                "evidence": [hf['evidence']],
                "affected_assets": [hf['url']],
                "impact": "Reduce la protección contra ataques del lado cliente (clickjacking, MIME sniffing, etc).",
                "likelihood": "MEDIA",
                "immediate_actions": ["Revisar cabeceras HTTP en servidor/proxy/CDN"],
                "remediation": ["Añadir las cabeceras faltantes con valores correctos"],
                "prevention": ["Hardening de cabeceras HTTP", "Revisiones periódicas"],
                "priority": fid
            })
            fid += 1
    
    if not findings and not data['live_hosts']:
        findings.append({
            "id": f"FIND-{fid:03d}",
            "title": "Sin exposiciones públicas obvias detectadas (pasivo)",
            "category": "INFORMATIONAL",
            "severity": "INFORMATIVO",
            "cvss_score": 0.0,
            "risk_description": "Con reconocimiento pasivo únicamente no se encontraron subdominios vivos expuestos con configuraciones problemáticas evidentes.",
            "evidence": [f"crt.sh consultado, {len(data['live_hosts'])} hosts vivos verificados con HEAD"],
            "affected_assets": [target],
            "impact": "Sin hallazgos críticos visibles desde internet con métodos pasivos.",
            "likelihood": "BAJA",
            "immediate_actions": ["Mantener monitoreo de exposición"],
            "remediation": ["Continuar con buenas prácticas actuales"],
            "prevention": ["Auditorías pasivas periódicas"],
            "priority": 99
        })
    
    crit = sum(1 for f in findings if f['severity']=='CRITICO')
    high = sum(1 for f in findings if f['severity']=='ALTO')
    med = sum(1 for f in findings if f['severity']=='MEDIO')
    info = sum(1 for f in findings if f['severity']=='INFORMATIVO')
    
    result = {
        "executive_summary": {
            "overall_risk": "ALTO" if high else "MEDIO" if med else "BAJO" if findings else "BAJO",
            "total_findings": len(findings),
            "critical_count": crit,
            "high_count": high,
            "medium_count": med,
            "low_count": 0,
            "info_count": info,
            "key_concern": "Exposiciones o malas configuraciones visibles públicamente" if findings and crit+high else "Sin hallazgos críticos con reconocimiento pasivo"
        },
        "findings": findings,
        "attack_surface_summary": {
            "exposed_subdomains": len([h for h in data['live_hosts']]),
            "public_buckets": 0,
            "exposed_configs": 0,
            "dev_servers": 0,
            "potential_credentials": 0
        },
        "recommendations": {
            "immediate": ["Verificar hallazgos con evidencia mostrada"] if findings else ["Mantener configuración actual"],
            "short_term": ["Corregir cabeceras faltantes", "Revisar configuración CORS/cookies"] if http_findings else ["Monitorear subdominios nuevos"],
            "long_term": ["Automatizar auditorías pasivas", "Gestionar inventario de subdominios"]
        },
        "compliance_notes": f"PASSIVE EXPOSURE ASSESSMENT ONLY. Sources: {', '.join(data['source'])}. Evidence-based, no active exploitation."
    }
    
    rg = ReportGenerator(settings.OUTPUT_DIR)
    saved = rg.save_report(result, target)
    print("\n" + "="*60)
    print("✅ REAL PASSIVE SCAN COMPLETE")
    for k,v in saved.items():
        print(f"{k}: {v}")
    print("="*60)

asyncio.run(main())
