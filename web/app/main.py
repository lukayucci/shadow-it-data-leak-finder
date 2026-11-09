"""
Aplicación FastAPI principal - ZERO
"""
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from web.app.core.database import init_db
from web.app.core.limiter import limiter
from web.app.core.config import settings
from web.app.routers import auth, dashboard, reports, intro

CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com data:; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


def _netloc(value: str) -> str:
    try:
        return (urlparse(value).netloc or "").lower()
    except Exception:
        return ""


def _trusted_hosts(request: Request) -> set[str]:
    hosts = set()
    for header in ("host", "x-forwarded-host"):
        value = request.headers.get(header)
        if value:
            hosts.add(value.split(",")[0].strip().lower())
    return hosts


app = FastAPI(
    title="ZERO",
    version=settings.APP_VERSION,
    description="ZERO - Shadow IT & Data Leak Intelligence Platform",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # CSRF básico: si el navegador envía Origin/Referer, debe coincidir con el host.
    if request.method not in SAFE_METHODS:
        source = request.headers.get("origin") or request.headers.get("referer")
        if source:
            source_host = _netloc(source)
            if source_host and source_host not in _trusted_hosts(request):
                return JSONResponse({"detail": "Origen no permitido"}, status_code=403)

    response = await call_next(request)

    headers = response.headers
    headers.setdefault("X-Content-Type-Options", "nosniff")
    headers.setdefault("X-Frame-Options", "DENY")
    headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    headers.setdefault("Content-Security-Policy", CSP)
    if request.url.path.startswith("/static/"):
        headers.setdefault("Cache-Control", "public, max-age=86400")
    if settings.SECURE_COOKIES and settings.ENVIRONMENT in ("production", "prod"):
        headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    accept = (request.headers.get("accept") or "").lower()
    if "text/html" in accept and request.url.path != "/health":
        msg = "Demasiadas solicitudes. Intentá de nuevo en unos minutos."
        html = f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Rate limit</title>
        <style>body{{background:#050a12;color:#e6eef8;font-family:system-ui;padding:40px}}.box{{max-width:520px;margin:auto;border:1px solid rgba(0,170,255,.25);padding:20px;border-radius:10px;background:#0b1220}}a{{color:#00e5ff}}</style></head>
        <body><div class='box'><h2>[RATE LIMIT]</h2><p>{msg}</p><p><a href='/dashboard'>Volver</a> · <a href='/login'>Login</a></p></div></body></html>"""
        return HTMLResponse(html, status_code=429)
    return JSONResponse({"detail": "Rate limit exceeded"}, status_code=429)


BASE_DIR = Path(__file__).parent.parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app.include_router(intro.router, tags=["Intro"])
app.include_router(auth.router, tags=["Auth"])
app.include_router(dashboard.router, tags=["Dashboard"])
app.include_router(reports.router, tags=["Reports"])


@app.on_event("startup")
async def startup_event():
    print("⚡ ZERO - Initializing...")
    init_db()
    print("⚡ ZERO - Online")


@app.get("/health")
async def health():
    return {"status": "online", "system": "ZERO"}
