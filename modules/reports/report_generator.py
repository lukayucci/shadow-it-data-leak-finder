"""
Generador de Reportes Corporativos
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

class ReportGenerator:
    """Generador de reportes limpios en formato Markdown para clientes corporativos"""
    
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("./outputs")
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_markdown_report(self, analysis_data: Dict[str, Any], target_org: str = "Unknown") -> str:
        """Genera reporte en formato Markdown corporativo"""
        timestamp = datetime.now()
        report_id = timestamp.strftime("%Y%m%d_%H%M%S")
        
        report_lines = []
        
        # Header
        report_lines.append(f"# SHADOW IT & DATA LEAK FINDER - SECURITY AUDIT REPORT")
        report_lines.append(f"")
        report_lines.append(f"**Report ID:** `AUDIT-{report_id}`")
        report_lines.append(f"**Target Organization:** {target_org}")
        report_lines.append(f"**Assessment Date:** {timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report_lines.append(f"**Report Type:** Defensive Security Assessment")
        report_lines.append(f"**Analyst:** Automated SOC Analysis (Big Pickle AI)")
        report_lines.append(f"")
        report_lines.append(f"---")
        report_lines.append(f"")
        
        # Executive Summary
        exec_sum = analysis_data.get("executive_summary", {})
        report_lines.append(f"## EXECUTIVE SUMMARY")
        report_lines.append(f"")
        report_lines.append(f"**Overall Risk Level:** `{exec_sum.get('overall_risk', 'UNKNOWN')}`")
        report_lines.append(f"")
        report_lines.append(f"**Key Concern:** {exec_sum.get('key_concern', 'N/A')}")
        report_lines.append(f"")
        report_lines.append(f"### Findings Distribution")
        report_lines.append(f"")
        report_lines.append(f"| Severity | Count |")
        report_lines.append(f"|----------|-------|")
        report_lines.append(f"| 🔴 CRITICAL | {exec_sum.get('critical_count', 0)} |")
        report_lines.append(f"| 🟠 HIGH | {exec_sum.get('high_count', 0)} |")
        report_lines.append(f"| 🟡 MEDIUM | {exec_sum.get('medium_count', 0)} |")
        report_lines.append(f"| 🔵 LOW | {exec_sum.get('low_count', 0)} |")
        report_lines.append(f"| ⚪ INFO | {exec_sum.get('info_count', 0)} |")
        report_lines.append(f"| **TOTAL** | **{exec_sum.get('total_findings', 0)}** |")
        report_lines.append(f"")
        report_lines.append(f"---")
        report_lines.append(f"")
        
        # Attack Surface Summary
        attack_surface = analysis_data.get("attack_surface_summary", {})
        report_lines.append(f"## ATTACK SURFACE SUMMARY")
        report_lines.append(f"")
        report_lines.append(f"| Component | Count |")
        report_lines.append(f"|-----------|-------|")
        report_lines.append(f"| Exposed Subdomains | {attack_surface.get('exposed_subdomains', 0)} |")
        report_lines.append(f"| Public/Listable Buckets | {attack_surface.get('public_buckets', 0)} |")
        report_lines.append(f"| Exposed Config Files | {attack_surface.get('exposed_configs', 0)} |")
        report_lines.append(f"| Development Servers | {attack_surface.get('dev_servers', 0)} |")
        report_lines.append(f"| Potential Credentials Exposed | {attack_surface.get('potential_credentials', 0)} |")
        report_lines.append(f"")
        report_lines.append(f"---")
        report_lines.append(f"")
        
        # Detailed Findings
        findings = analysis_data.get("findings", [])
        report_lines.append(f"## DETAILED FINDINGS")
        report_lines.append(f"")
        
        if not findings:
            report_lines.append(f"*No findings detected in the analyzed data.*")
            report_lines.append(f"")
        else:
            for finding in sorted(findings, key=lambda x: x.get('priority', 99)):
                severity = finding.get('severity', 'UNKNOWN')
                severity_emoji = {
                    'CRITICO': '🔴',
                    'ALTO': '🟠',
                    'MEDIO': '🟡',
                    'BAJO': '🔵',
                    'INFORMATIVO': '⚪'
                }.get(severity, '⚪')
                
                report_lines.append(f"### {severity_emoji} {finding.get('id', 'FIND-XXX')}: {finding.get('title', 'Untitled')}")
                report_lines.append(f"")
                report_lines.append(f"**Category:** `{finding.get('category', 'N/A')}` | **Severity:** `{severity}` | **CVSS Score:** `{finding.get('cvss_score', 0.0)}` | **Priority:** `{finding.get('priority', 'N/A')}`")
                report_lines.append(f"")
                report_lines.append(f"#### Risk Description")
                report_lines.append(f"{finding.get('risk_description', 'N/A')}")
                report_lines.append(f"")
                report_lines.append(f"#### Impact")
                report_lines.append(f"{finding.get('impact', 'N/A')}")
                report_lines.append(f"")
                report_lines.append(f"**Likelihood:** {finding.get('likelihood', 'N/A')}")
                report_lines.append(f"")
                
                if finding.get('evidence'):
                    report_lines.append(f"#### Evidence")
                    for ev in finding['evidence']:
                        report_lines.append(f"- {ev}")
                    report_lines.append(f"")
                
                if finding.get('affected_assets'):
                    report_lines.append(f"#### Affected Assets")
                    for asset in finding['affected_assets']:
                        report_lines.append(f"- `{asset}`")
                    report_lines.append(f"")
                
                report_lines.append(f"#### ⚡ Immediate Actions")
                for action in finding.get('immediate_actions', []):
                    report_lines.append(f"- [ ] {action}")
                report_lines.append(f"")
                
                report_lines.append(f"#### 🔧 Remediation Steps")
                for step in finding.get('remediation', []):
                    report_lines.append(f"- {step}")
                report_lines.append(f"")
                
                report_lines.append(f"#### 🛡️ Prevention Controls")
                for prev in finding.get('prevention', []):
                    report_lines.append(f"- {prev}")
                report_lines.append(f"")
                report_lines.append(f"---")
                report_lines.append(f"")
        
        # Recommendations
        recommendations = analysis_data.get("recommendations", {})
        report_lines.append(f"## STRATEGIC RECOMMENDATIONS")
        report_lines.append(f"")
        
        report_lines.append(f"### 🚨 Immediate (0-24 Hours)")
        for rec in recommendations.get('immediate', []):
            report_lines.append(f"- {rec}")
        report_lines.append(f"")
        
        report_lines.append(f"### ⏱️ Short-Term (24-72 Hours)")
        for rec in recommendations.get('short_term', []):
            report_lines.append(f"- {rec}")
        report_lines.append(f"")
        
        report_lines.append(f"### 📈 Long-Term (1-4 Weeks)")
        for rec in recommendations.get('long_term', []):
            report_lines.append(f"- {rec}")
        report_lines.append(f"")
        
        # Compliance Notes
        if analysis_data.get('compliance_notes'):
            report_lines.append(f"## COMPLIANCE NOTES")
            report_lines.append(f"")
            report_lines.append(f"{analysis_data['compliance_notes']}")
            report_lines.append(f"")
        
        # Footer
        report_lines.append(f"---")
        report_lines.append(f"")
        report_lines.append(f"**DISCLAIMER:** This report has been generated for defensive security purposes only. ")
        report_lines.append(f"It identifies potential security exposures and provides remediation guidance. ")
        report_lines.append(f"All findings should be validated in a controlled environment.")
        report_lines.append(f"")
        report_lines.append(f"**Generated by:** Shadow IT & Data Leak Finder | Powered by OpenCode Big Pickle AI")
        report_lines.append(f"**Classification:** CONFIDENTIAL - For authorized recipients only")
        
        return "\n".join(report_lines)
    
    def save_report(self, analysis_data: Dict[str, Any], target_org: str = "Unknown", formats: list = None) -> Dict[str, str]:
        """Guarda reporte en múltiples formatos"""
        if formats is None:
            formats = ["markdown", "json"]
        
        timestamp = datetime.now()
        report_id = timestamp.strftime("%Y%m%d_%H%M%S")
        base_name = f"shadowit_audit_{target_org.replace('.', '_')}_{report_id}"
        
        saved_files = {}
        
        if "markdown" in formats:
            md_content = self.generate_markdown_report(analysis_data, target_org)
            md_path = self.output_dir / f"{base_name}.md"
            with open(md_path, 'w', encoding='utf-8') as f:
                f.write(md_content)
            saved_files["markdown"] = str(md_path)
            print(f"✅ Reporte Markdown guardado: {md_path}")
        
        if "json" in formats:
            json_data = {
                "report_metadata": {
                    "report_id": f"AUDIT-{report_id}",
                    "target_organization": target_org,
                    "generated_at": timestamp.isoformat(),
                    "generator": "Shadow IT & Data Leak Finder v1.0"
                },
                "analysis": analysis_data
            }
            json_path = self.output_dir / f"{base_name}.json"
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
            saved_files["json"] = str(json_path)
            print(f"✅ Reporte JSON guardado: {json_path}")
        
        return saved_files
