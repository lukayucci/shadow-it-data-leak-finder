"""
Inspector TLS PASIVO
"""
import ssl, socket
from datetime import datetime
from typing import Dict, Any

from modules.checks.ssrf_guard import validate_host

class TLSInspector:
    def inspect(self, domain: str, port: int = 443) -> Dict[str, Any]:
        safe, reason = validate_host(domain)
        if not safe:
            return {"valid": False, "error": f"SSRF bloqueado: {reason}"}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    not_after = cert.get('notAfter')
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    return {
                        "valid": True,
                        "not_after": not_after,
                        "issuer": issuer.get('organizationName') or issuer.get('commonName'),
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "san": [x[1] for x in cert.get('subjectAltName', []) if x[0]=='DNS']
                    }
        except Exception as e:
            return {"valid": False, "error": str(e)}
