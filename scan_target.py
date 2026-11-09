#!/usr/bin/env python3
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from config.settings import settings
from config.logging_config import setup_logging
from modules.recon.osint_mock import OSINTMockCollector
from modules.ai.prompt_engine import PromptEngine
from modules.api.opencode_client import OpenCodeBigPickleClient
from modules.reports.report_generator import ReportGenerator

logger = setup_logging(settings.LOG_LEVEL)

async def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "example-corp.com"
    target = target.replace('https://','').replace('http://','').replace('www.','').split('/')[0]
    print(f"🎯 SCANNING: {target}")
    
    recon = OSINTMockCollector()
    prompt_engine = PromptEngine()
    api_client = OpenCodeBigPickleClient()
    report_gen = ReportGenerator(settings.OUTPUT_DIR)
    
    raw_intel = await recon.collect_raw_intel(target)
    summary = recon.collect_summary(raw_intel)
    print(f"📊 Collect: {summary}")
    
    messages = prompt_engine.create_analysis_prompt(raw_intel, target)
    
    try:
        result = await api_client.analyze_with_big_pickle(messages)
    except Exception as e:
        print(f"⚠️  Fallback: {e}")
        # fallback
        findings = []
        if summary.get('potential_creds',0)>0:
            findings.append({"id":"FIND-001","title":"Posibles credenciales expuestas","category":"CREDENTIAL_LEAK","severity":"CRITICO","cvss_score":9.8,"risk_description":"Credenciales detectadas en archivos expuestos","evidence":["Patrones detectados"],"affected_assets":["Archivos de configuración"],"impact":"Compromiso de cuentas","likelihood":"ALTA","immediate_actions":["Rotar credenciales YA"],"remediation":["Eliminar de archivos públicos","Migrar a gestor de secretos"],"prevention":["Secret scanning en CI/CD"],"priority":1})
        if summary.get('buckets',0)>0:
            findings.append({"id":"FIND-002","title":"Buckets públicos","category":"OPEN_BUCKET","severity":"ALTO","cvss_score":8.1,"risk_description":"Buckets con acceso público","evidence":["Buckets identificados"],"affected_assets":["Storage buckets"],"impact":"Exposición de datos","likelihood":"ALTA","immediate_actions":["Restringir acceso público"],"remediation":["Aplicar mínimo privilegio"],"prevention":["CSPM"],"priority":2})
        if summary.get('dev_servers',0)>0:
            findings.append({"id":"FIND-003","title":"Servidores dev expuestos","category":"DEV_SERVER","severity":"MEDIO","cvss_score":5.8,"risk_description":"Entornos dev accesibles desde internet","evidence":["Servidores dev detectados"],"affected_assets":["Dev/Staging"],"impact":"Reconocimiento","likelihood":"MEDIA","immediate_actions":["Restringir por VPN/IP"],"remediation":["Aislar en red privada"],"prevention":["Inventario Shadow IT"],"priority":3})
        crit = sum(1 for f in findings if f['severity']=='CRITICO')
        high = sum(1 for f in findings if f['severity']=='ALTO')
        med = sum(1 for f in findings if f['severity']=='MEDIO')
        result = {
            "executive_summary":{"overall_risk":"CRITICO" if crit else "ALTO" if high else "MEDIO","total_findings":len(findings),"critical_count":crit,"high_count":high,"medium_count":med,"low_count":0,"info_count":0,"key_concern":"Exposición de Shadow IT con riesgo de filtración"},
            "findings":findings,
            "attack_surface_summary":{"exposed_subdomains":summary.get('subdomains',0),"public_buckets":summary.get('buckets',0),"exposed_configs":summary.get('exposed_files',0),"dev_servers":summary.get('dev_servers',0),"potential_credentials":summary.get('potential_creds',0)},
            "recommendations":{"immediate":["Rotar credenciales expuestas","Restringir buckets públicos","Aislar servidores dev"],"short_term":["Implementar gestión de secretos","Política Shadow IT"],"long_term":["Zero Trust","Monitoreo continuo"]},
            "compliance_notes":"Análisis defensivo basado en recolección OSINT."
        }
    
    saved = report_gen.save_report(result, target, formats=["markdown","json"])
    print("\n✅ DONE")
    for k,v in saved.items():
        print(f"{k}: {v}")

if __name__ == '__main__':
    asyncio.run(main())
