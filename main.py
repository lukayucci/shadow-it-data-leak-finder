#!/usr/bin/env python3
"""
Shadow IT & Data Leak Finder - Main Orchestrator
Herramienta SaaS de auditoría defensiva automatizada

Ejecuta flujo completo: OSINT Mock -> Análisis Big Pickle -> Reporte Corporativo
Diseñado para correr 24/7 en Render/Railway como Background Worker
"""
import asyncio
import json
import signal
import sys
from datetime import datetime
from pathlib import Path

from config.settings import settings
from config.logging_config import setup_logging
from modules.recon.osint_mock import OSINTMockCollector
from modules.ai.prompt_engine import PromptEngine
from modules.api.opencode_client import OpenCodeBigPickleClient
from modules.reports.report_generator import ReportGenerator
from utils.exceptions import (
    ShadowITFinderError, 
    APIConnectionError, 
    RateLimitError, 
    APIResponseError,
    NetworkError
)

# Setup logging
logger = setup_logging(settings.LOG_LEVEL)

class ShadowITFinderOrchestrator:
    """Orquestador principal del sistema"""
    
    def __init__(self, target_org: str = "example-corp.com"):
        self.target_org = target_org
        self.recon_collector = OSINTMockCollector()
        self.prompt_engine = PromptEngine()
        self.api_client = OpenCodeBigPickleClient()
        self.report_generator = ReportGenerator(settings.OUTPUT_DIR)
        self.running = True
        
        # Configurar manejo de señales para shutdown graceful
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Manejador de señales para shutdown graceful"""
        logger.info(f"🛑 Señal {signum} recibida. Iniciando shutdown graceful...")
        self.running = False
    
    async def run_audit_cycle(self) -> bool:
        """Ejecuta un ciclo completo de auditoría"""
        try:
            logger.info("=" * 80)
            logger.info("🚀 INICIANDO CICLO DE AUDITORÍA - Shadow IT & Data Leak Finder")
            logger.info("=" * 80)
            logger.info(f"🎯 Objetivo: {self.target_org}")
            logger.info(f"⏰ Timestamp: {datetime.now().isoformat()}")
            
            # 1. VALIDACIÓN DE CONFIGURACIÓN
            logger.info("\n[1/5] Validando configuración...")
            if not settings.validate():
                logger.warning("⚠️  Configuración incompleta. Continuando con modo limitado...")
            else:
                logger.info("✅ Configuración válida")
            
            # 2. RECONOCIMIENTO OSINT
            logger.info("\n[2/5] Recolectando inteligencia OSINT...")
            raw_intel = await self.recon_collector.collect_raw_intel(self.target_org)
            summary = self.recon_collector.get_summary(raw_intel)
            logger.info(f"✅ Inteligencia recolectada:")
            logger.info(f"   • Subdominios: {summary['subdomains']}")
            logger.info(f"   • Buckets: {summary['buckets']}")
            logger.info(f"   • Archivos expuestos: {summary['exposed_files']}")
            logger.info(f"   • Credenciales potenciales: {summary['potential_creds']}")
            logger.info(f"   • Servidores dev: {summary['dev_servers']}")
            logger.info(f"   • Malconfiguraciones: {summary['misconfigs']}")
            logger.info(f"   • Total líneas: {summary['total_lines']}")
            
            # 3. PREPARACIÓN DE PROMPT PARA BIG PICKLE
            logger.info("\n[3/5] Preparando análisis con Big Pickle (SOC Defensivo)...")
            messages = self.prompt_engine.create_analysis_prompt(raw_intel, self.target_org)
            logger.info("✅ Prompt SOC defensivo generado")
            
            # 4. ANÁLISIS CON IA
            logger.info("\n[4/5] Enviando datos a Big Pickle para análisis...")
            try:
                # Health check opcional
                if settings.OPENCODE_API_KEY:
                    health = await self.api_client.health_check()
                    if health:
                        logger.info("✅ Conexión con API verificada")
                
                analysis_result = await self.api_client.analyze_with_big_pickle(messages)
                
                # Validar respuesta
                if not self.prompt_engine.validate_response_schema(analysis_result):
                    logger.error("❌ Respuesta de IA no cumple con esquema esperado")
                    return False
                
                logger.info("✅ Análisis completado por Big Pickle")
                exec_sum = analysis_result.get('executive_summary', {})
                logger.info(f"   • Riesgo General: {exec_sum.get('overall_risk')}")
                logger.info(f"   • Total Hallazgos: {exec_sum.get('total_findings')}")
                logger.info(f"   • Críticos: {exec_sum.get('critical_count')} | Altos: {exec_sum.get('high_count')} | Medios: {exec_sum.get('medium_count')}")
                
            except RateLimitError as e:
                logger.warning(f"⏳ Rate limit alcanzado: {e}")
                if e.retry_after:
                    logger.info(f"⏸️  Esperando {e.retry_after} segundos antes de reintentar...")
                    await asyncio.sleep(e.retry_after)
                    # Reintentar una vez
                    analysis_result = await self.api_client.analyze_with_big_pickle(messages)
                else:
                    raise
            except (APIConnectionError, NetworkError) as e:
                logger.error(f"🌐 Error de conexión: {e}")
                logger.warning("⚠️  Continuando sin análisis de IA. Generando reporte con datos crudos...")
                # Crear análisis mínimo de fallback
                analysis_result = self._create_fallback_analysis(summary)
            except APIResponseError as e:
                logger.error(f"❌ Error de API: {e}")
                logger.warning("⚠️  Generando reporte con análisis de fallback...")
                analysis_result = self._create_fallback_analysis(summary)
            except Exception as e:
                logger.error(f"❌ Error inesperado en análisis: {e}")
                logger.warning("⚠️  Generando reporte con análisis de fallback...")
                analysis_result = self._create_fallback_analysis(summary)
            
            # 5. GENERACIÓN DE REPORTES
            logger.info("\n[5/5] Generando reportes corporativos...")
            saved_files = self.report_generator.save_report(analysis_result, self.target_org, formats=["markdown", "json"])
            
            logger.info("\n" + "=" * 80)
            logger.info("✅ CICLO DE AUDITORÍA COMPLETADO EXITOSAMENTE")
            logger.info("=" * 80)
            for fmt, path in saved_files.items():
                logger.info(f"📄 {fmt.upper()}: {path}")
            logger.info("=" * 80)
            
            return True
            
        except ShadowITFinderError as e:
            logger.error(f"❌ Error del sistema: {e}")
            return False
        except Exception as e:
            logger.error(f"❌ Error crítico no esperado: {e}", exc_info=True)
            return False
    
    def _create_fallback_analysis(self, summary: dict) -> dict:
        """Crea análisis de fallback cuando API no está disponible"""
        logger.info("📝 Generando análisis de fallback basado en datos recolectados...")
        
        total_creds = summary.get('potential_creds', 0)
        total_buckets = summary.get('buckets', 0)
        total_dev = summary.get('dev_servers', 0)
        
        findings = []
        finding_id = 1
        
        if total_creds > 0:
            findings.append({
                "id": f"FIND-{finding_id:03d}",
                "title": "Posibles credenciales expuestas en archivos de configuración",
                "category": "CREDENTIAL_LEAK",
                "severity": "CRITICO" if total_creds >= 3 else "ALTO",
                "cvss_score": 9.8 if total_creds >= 3 else 8.5,
                "risk_description": "Se detectaron referencias a credenciales en texto plano en archivos potencialmente accesibles.",
                "evidence": ["Patrones de credenciales detectados en archivos .env y configuraciones"],
                "affected_assets": ["Archivos de configuración expuestos"],
                "impact": "Compromiso completo de cuentas, acceso no autorizado a sistemas y bases de datos",
                "likelihood": "ALTA",
                "immediate_actions": ["Rotar TODAS las credenciales inmediatamente", "Revisar logs de acceso", "Verificar compromiso"],
                "remediation": ["Eliminar credenciales de archivos expuestos", "Migrar a gestor de secretos (Vault/AWS Secrets Manager)", "Implementar variables de entorno seguras"],
                "prevention": ["Escaneo automático de secretos en CI/CD", "Pre-commit hooks con detección de secretos", "Política de gestión de secretos"],
                "priority": 1
            })
            finding_id += 1
        
        if total_buckets > 0:
            findings.append({
                "id": f"FIND-{finding_id:03d}",
                "title": "Buckets de almacenamiento con permisos públicos",
                "category": "OPEN_BUCKET",
                "severity": "ALTO",
                "cvss_score": 7.5,
                "risk_description": "Buckets de cloud storage con permisos potencialmente públicos que podrían exponer datos.",
                "evidence": [f"{total_buckets} buckets identificados con configuración permisiva"],
                "affected_assets": ["S3/Google Cloud Storage buckets"],
                "impact": "Exposición de datos sensibles, filtración de información corporativa",
                "likelihood": "MEDIA",
                "immediate_actions": ["Verificar permisos de cada bucket", "Restringir acceso público"],
                "remediation": ["Aplicar principio de mínimo privilegio", "Habilitar bloqueo de acceso público", "Revisar políticas IAM"],
                "prevention": ["Cloud Security Posture Management (CSPM)", "Auditorías periódicas de permisos"],
                "priority": 2
            })
            finding_id += 1
        
        if total_dev > 0:
            findings.append({
                "id": f"FIND-{finding_id:03d}",
                "title": "Servidores de desarrollo/staging expuestos a Internet",
                "category": "DEV_SERVER",
                "severity": "MEDIO",
                "cvss_score": 5.3,
                "risk_description": "Entornos de desarrollo expuestos que pueden contener código incompleto o configuraciones inseguras.",
                "evidence": [f"{total_dev} servidores de desarrollo identificados"],
                "affected_assets": ["Entornos de desarrollo y staging"],
                "impact": "Reconocimiento, acceso a información de desarrollo, posible vector de ataque",
                "likelihood": "MEDIA",
                "immediate_actions": ["Restringir acceso por IP/VPN", "Deshabilitar si no es necesario"],
                "remediation": ["Mover a red privada/VPN", "Implementar autenticación", "Usar túneles seguros"],
                "prevention": ["Inventario de Shadow IT", "Política de exposición de entornos"],
                "priority": 3
            })
            finding_id += 1
        
        critical = sum(1 for f in findings if f['severity'] == 'CRITICO')
        high = sum(1 for f in findings if f['severity'] == 'ALTO')
        medium = sum(1 for f in findings if f['severity'] == 'MEDIO')
        
        return {
            "executive_summary": {
                "overall_risk": "CRITICO" if critical > 0 else "ALTO" if high > 0 else "MEDIO",
                "total_findings": len(findings),
                "critical_count": critical,
                "high_count": high,
                "medium_count": medium,
                "low_count": 0,
                "info_count": 0,
                "key_concern": "Exposición de activos de Shadow IT con potencial filtración de datos" if findings else "Sin hallazgos críticos en datos analizados"
            },
            "findings": findings,
            "attack_surface_summary": {
                "exposed_subdomains": summary.get('subdomains', 0),
                "public_buckets": summary.get('buckets', 0),
                "exposed_configs": summary.get('exposed_files', 0),
                "dev_servers": summary.get('dev_servers', 0),
                "potential_credentials": summary.get('potential_creds', 0)
            },
            "recommendations": {
                "immediate": [
                    "Realizar inventario completo de activos expuestos",
                    "Rotar credenciales identificadas como potencialmente expuestas",
                    "Restringir acceso a buckets y servidores de desarrollo"
                ],
                "short_term": [
                    "Implementar programa de gestión de Shadow IT",
                    "Desplegar solución de detección de secretos",
                    "Revisar políticas de exposición a Internet"
                ],
                "long_term": [
                    "Implementar Zero Trust Architecture",
                    "Automatizar monitoreo continuo de exposición",
                    "Establecer proceso de respuesta a filtraciones"
                ]
            },
            "compliance_notes": "Análisis basado en recolección OSINT simulada. Se recomienda validación con fuentes autorizadas."
        }
    
    async def run_continuous(self, interval_minutes: int = None):
        """Ejecuta auditorías de forma continua (24/7)"""
        interval_minutes = interval_minutes or settings.SCAN_INTERVAL_MINUTES
        logger.info(f"🔄 Modo continuo activado - Intervalo: {interval_minutes} minutos")
        logger.info("💡 Presiona Ctrl+C para detener")
        
        while self.running:
            try:
                await self.run_audit_cycle()
                
                if not self.running:
                    break
                
                wait_seconds = interval_minutes * 60
                logger.info(f"\n⏳ Siguiente ciclo en {interval_minutes} minutos...")
                await asyncio.sleep(wait_seconds)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"❌ Error en ciclo continuo: {e}", exc_info=True)
                logger.info("⏳ Reintentando en 5 minutos...")
                await asyncio.sleep(300)

async def main():
    """Función principal"""
    logger.info("🛡️  SHADOW IT & DATA LEAK FINDER v1.0")
    logger.info("Arquitectura modular | Análisis SOC Defensivo | Powered by Big Pickle")
    logger.info("")
    
    # Configurar target (puede venir de env)
    import os
    target_org = os.getenv("TARGET_ORGANIZATION", "example-corp.com")
    
    orchestrator = ShadowITFinderOrchestrator(target_org=target_org)
    
    # Verificar modo de ejecución
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        # Ejecución única
        await orchestrator.run_audit_cycle()
    else:
        # Ejecución continua 24/7
        await orchestrator.run_continuous()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\n👋 Shadow IT & Data Leak Finder detenido por usuario")
    except Exception as e:
        logger.error(f"💥 Error fatal: {e}", exc_info=True)
        sys.exit(1)
