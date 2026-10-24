"""
Módulo de Reconocimiento OSINT - Simulación de fuentes de inteligencia
"""
import json
import random
from datetime import datetime, timedelta
from typing import Dict, List, Any

class OSINTMockCollector:
    """Recolector simulado de inteligencia OSINT para Shadow IT"""
    
    def __init__(self):
        self.sources = [
            "certificate_transparency_logs",
            "dns_zone_transfers_mock",
            "search_engine_dorks",
            "cloud_storage_enumeration",
            "github_code_search_mock",
            "pastebin_monitor_mock"
        ]
    
    async def collect_raw_intel(self, target_org: str = "example-corp.com") -> str:
        """
        Recolecta inteligencia cruda simulada de infraestructura expuesta
        Retorna datos en formato texto crudo para análisis por IA
        """
        intel_data = []
        timestamp = datetime.now().isoformat()
        
        # Header informativo
        intel_data.append(f"# OSINT INTELLIGENCE GATHERING REPORT - {timestamp}")
        intel_data.append(f"# Target Organization: {target_org}")
        intel_data.append(f"# Collection Method: Automated Mock Scanner")
        intel_data.append("=" * 80)
        intel_data.append("")
        
        # 1. Subdominios expuestos
        intel_data.append("## DISCOVERED SUBDOMAINS")
        subdomains = [
            f"dev.{target_org}",
            f"staging.{target_org}",
            f"test.{target_org}",
            f"api-dev.{target_org}",
            f"jenkins.{target_org}",
            f"grafana.{target_org}",
            f"admin-portal.{target_org}"
        ]
        for sub in subdomains:
            intel_data.append(f"SUBDOMAIN|{sub}|{random.choice(['A', 'CNAME'])}|{random.choice(['80', '443', '8080', '3000'])}")
        intel_data.append("")
        
        # 2. Buckets de almacenamiento cloud expuestos
        intel_data.append("## CLOUD STORAGE BUCKETS")
        buckets = [
            f"s3://{target_org.replace('.', '-')}-backup-prod/",
            f"s3://{target_org.replace('.', '-')}-dev-assets/",
            f"gs://{target_org.replace('.', '-')}-logs-public/",
            f"s3://{target_org.replace('.', '-')}-config-files/"
        ]
        for bucket in buckets:
            intel_data.append(f"BUCKET|{bucket}|{random.choice(['public-read', 'public-read-write', 'authenticated-read'])}|LISTABLE:{random.choice(['true', 'false'])}")
        intel_data.append("")
        
        # 3. Logs o archivos con posibles credenciales
        intel_data.append("## EXPOSED FILES & CONFIGURATIONS")
        exposed_files = [
            f"https://dev.{target_org}/.env",
            f"https://staging.{target_org}/config/database.yml",
            f"https://jenkins.{target_org}/scriptText",
            f"https://api-dev.{target_org}/.git/config",
            f"https://test.{target_org}/phpinfo.php"
        ]
        for ef in exposed_files:
            intel_data.append(f"EXPOSED_FILE|{ef}|{random.choice(['HTTP 200', 'HTTP 403', 'HTTP 200 - INDEXABLE'])}|SIZE:{random.randint(100, 50000)}bytes")
        intel_data.append("")
        
        # 4. Posibles credenciales en texto plano (SIMULADO)
        intel_data.append("## POTENTIAL CREDENTIALS IN PLAIN TEXT")
        creds = [
            f"DB_PASSWORD=ProdPass{random.randint(1000,9999)}! in https://dev.{target_org}/.env",
            f"AWS_ACCESS_KEY_ID=AKIA{random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')*16} in backup config",
            f"API_TOKEN=sk_live_{random.choice('abcdefghijklmnopqrstuvwxyz0123456789')*32} found in javascript",
            f"ADMIN_USER:admin / ADMIN_PASS:Temp{random.randint(100,999)} found in config file"
        ]
        for c in creds:
            intel_data.append(f"CRED_LEAK|{c}|CONFIDENCE:{random.randint(70,95)}%")
        intel_data.append("")
        
        # 5. Servidores de desarrollo indexados
        intel_data.append("## DEVELOPMENT SERVERS INDEXED")
        dev_servers = [
            f"dev.{target_org}:3000 - React Dev Server - No Auth",
            f"staging.{target_org}:8080 - Tomcat Manager - Default Credentials Possible",
            f"jenkins.{target_org}:8080 - Jenkins - Anonymous Access Enabled",
            f"grafana.{target_org}:3000 - Grafana - Default admin/admin"
        ]
        for ds in dev_servers:
            intel_data.append(f"DEV_SERVER|{ds}|EXPOSED_TO_INTERNET|TECH:{random.choice(['Node.js', 'Java/Tomcat', 'Jenkins', 'Grafana'])}")
        intel_data.append("")
        
        # 6. Headers y configuraciones inseguras
        intel_data.append("## SECURITY MISCONFIGURATIONS")
        misconfigs = [
            f"Access-Control-Allow-Origin: * on https://api-dev.{target_org}",
            f"X-Powered-By: Express/4.17.1 revealing tech stack",
            f"Server: Apache/2.4.49 with known version",
            f"Missing Security Headers on multiple endpoints"
        ]
        for mc in misconfigs:
            intel_data.append(f"MISCONFIG|{mc}|SEVERITY_HINT:{random.choice(['MEDIUM', 'HIGH'])}")
        intel_data.append("")
        
        intel_data.append("=" * 80)
        intel_data.append(f"# END OF RAW INTEL - Total entries: {len(intel_data)}")
        
        raw_text = "\n".join(intel_data)
        return raw_text
    
    def get_summary(self, raw_data: str) -> Dict[str, Any]:
        """Obtiene resumen de datos recolectados"""
        lines = raw_data.split('\n')
        return {
            "total_lines": len(lines),
            "subdomains": sum(1 for l in lines if l.startswith("SUBDOMAIN|")),
            "buckets": sum(1 for l in lines if l.startswith("BUCKET|")),
            "exposed_files": sum(1 for l in lines if l.startswith("EXPOSED_FILE|")),
            "potential_creds": sum(1 for l in lines if l.startswith("CRED_LEAK|")),
            "dev_servers": sum(1 for l in lines if l.startswith("DEV_SERVER|")),
            "misconfigs": sum(1 for l in lines if l.startswith("MISCONFIG|")),
            "collected_at": datetime.now().isoformat()
        }
