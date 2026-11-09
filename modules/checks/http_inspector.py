"""
Inspector HTTP pasivo - Analiza cabeceras, cookies, redirecciones, robots.txt, security.txt
"""
import asyncio
import aiohttp
from typing import Dict, List
from urllib.parse import urlparse

from modules.checks.ssrf_guard import validate_url

class HTTPInspector:
    """Inspección 100% pasiva de respuestas HTTP"""
    
    SECURITY_HEADERS = [
        'strict-transport-security',
        'content-security-policy',
        'x-content-type-options',
        'x-frame-options',
        'referrer-policy',
        'permissions-policy',
        'cross-origin-opener-policy',
        'cross-origin-resource-policy',
        'cross-origin-embedder-policy'
    ]
    
    async def inspect_url(self, url: str) -> Dict:
        safe, reason = validate_url(url)
        if not safe:
            return {'url': url, 'error': f'SSRF bloqueado: {reason}', 'findings': [],
                    'redirect_chain': [], 'headers': {}, 'cookies': [],
                    'missing_headers': [], 'present_headers': [], 'robots': None,
                    'securitytxt': None, 'csp_analysis': None}
        result = {
            'url': url,
            'headers': {},
            'cookies': [],
            'missing_headers': [],
            'present_headers': [],
            'findings': [],
            'redirect_chain': [],
            'robots': None,
            'securitytxt': None,
            'csp_analysis': None
        }
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                current = url
                chain = []
                for _ in range(10):
                    try:
                        async with session.head(current, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=False) as resp:
                            chain.append({'url': current, 'status': resp.status, 'location': resp.headers.get('Location','')})
                            if resp.status in (301,302,303,307,308) and resp.headers.get('Location'):
                                loc = resp.headers.get('Location')
                                if loc.startswith('/'):
                                    parsed = urlparse(current)
                                    current = f"{parsed.scheme}://{parsed.netloc}{loc}"
                                elif loc.startswith('http'):
                                    current = loc
                                else:
                                    parsed = urlparse(current)
                                    current = f"{parsed.scheme}://{parsed.netloc}/{loc}"
                                redirect_safe, redirect_reason = validate_url(current)
                                if not redirect_safe:
                                    chain.append({'url': current, 'status': 'BLOCKED', 'location': redirect_reason})
                                    break
                                continue
                            else:
                                for k,v in resp.headers.items():
                                    kl = k.lower()
                                    result['headers'][kl] = v
                                    if kl in self.SECURITY_HEADERS:
                                        result['present_headers'].append(kl)
                                    if kl == 'set-cookie':
                                        result['cookies'].append(v)
                                break
                    except:
                        break
                result['redirect_chain'] = chain
                
                try:
                    parsed = urlparse(url)
                    base = f"{parsed.scheme}://{parsed.netloc}"
                    async with session.get(f"{base}/robots.txt", timeout=aiohttp.ClientTimeout(total=8), allow_redirects=False) as r:
                        if r.status == 200:
                            txt = await r.text()
                            result['robots'] = txt[:500]
                except:
                    pass
                
                try:
                    parsed = urlparse(url)
                    base = f"{parsed.scheme}://{parsed.netloc}"
                    for path in ['/.well-known/security.txt', '/security.txt']:
                        try:
                            async with session.get(f"{base}{path}", timeout=aiohttp.ClientTimeout(total=8), allow_redirects=False) as r:
                                if r.status == 200:
                                    txt = await r.text()
                                    result['securitytxt'] = txt[:500]
                                    break
                        except:
                            continue
                except:
                    pass
                
                csp = result['headers'].get('content-security-policy','')
                if csp:
                    issues = []
                    if "'unsafe-inline'" in csp:
                        issues.append('unsafe-inline')
                    if "'unsafe-eval'" in csp:
                        issues.append('unsafe-eval')
                    if 'data:' in csp:
                        issues.append('data: allowed')
                    if '*' in csp:
                        issues.append('wildcard (*) present')
                    result['csp_analysis'] = {'raw': csp[:300], 'issues': issues}
                
                for c in result['cookies']:
                    cl = c.lower()
                    findings = []
                    if 'httponly' not in cl:
                        findings.append('MISSING_Httponly')
                    if 'secure' not in cl:
                        findings.append('MISSING_Secure')
                    if 'samesite' not in cl:
                        findings.append('MISSING_SameSite')
                    if findings:
                        result['findings'].append({
                            'type': 'INSECURE_COOKIE',
                            'evidence': c[:150],
                            'issues': findings
                        })
                
                for h in self.SECURITY_HEADERS:
                    if h not in result['headers']:
                        result['missing_headers'].append(h)
                
                if result['missing_headers']:
                    result['findings'].append({
                        'type': 'MISSING_SECURITY_HEADERS',
                        'evidence': f"missing: {', '.join(result['missing_headers'])}",
                        'missing': result['missing_headers']
                    })
        except Exception as e:
            result['error'] = str(e)
        return result
    
    def inspect(self, live_hosts: List[str]) -> List[Dict]:
        findings = []
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        
        for url in live_hosts[:10]:
            if loop and loop.is_running():
                # Si ya hay un loop corriendo (FastAPI), crear uno nuevo en thread
                import concurrent.futures
                def _run(u):
                    new_loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(new_loop)
                    try:
                        return new_loop.run_until_complete(self.inspect_url(u))
                    finally:
                        new_loop.close()
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    res = ex.submit(_run, url).result(timeout=60)
            else:
                res = asyncio.get_event_loop().run_until_complete(self.inspect_url(url))
            
            for f in res.get('findings', []):
                if f['type'] == 'MISSING_SECURITY_HEADERS':
                    findings.append({
                        'type': 'MISSING_SECURITY_HEADERS',
                        'url': url,
                        'evidence': f['evidence'],
                        'severity_hint': 'MEDIUM'
                    })
                elif f['type'] == 'INSECURE_COOKIE':
                    findings.append({
                        'type': 'INSECURE_COOKIE',
                        'url': url,
                        'evidence': f['evidence'],
                        'issues': f.get('issues',[]),
                        'severity_hint': 'MEDIUM'
                    })
            if res.get('redirect_chain') and len(res['redirect_chain']) > 1:
                chain_str = ' -> '.join([f"{c['status']}:{c['url']}" for c in res['redirect_chain']])
                findings.append({
                    'type': 'REDIRECT_CHAIN',
                    'url': url,
                    'evidence': chain_str,
                    'severity_hint': 'INFO'
                })
            if res.get('robots'):
                findings.append({
                    'type': 'ROBOTS_TXT_PRESENT',
                    'url': url,
                    'evidence': res['robots'][:200],
                    'severity_hint': 'INFO'
                })
            if res.get('securitytxt'):
                findings.append({
                    'type': 'SECURITY_TXT_PRESENT',
                    'url': url,
                    'evidence': res['securitytxt'][:200],
                    'severity_hint': 'INFO'
                })
            if res.get('csp_analysis') and res['csp_analysis'].get('issues'):
                findings.append({
                    'type': 'CSP_WEAKNESS',
                    'url': url,
                    'evidence': f"CSP issues: {', '.join(res['csp_analysis']['issues'])} | {res['csp_analysis']['raw']}",
                    'severity_hint': 'MEDIUM'
                })
        return findings
