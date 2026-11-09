from slowapi import Limiter
from starlette.requests import Request


def client_key(request: Request) -> str:
    """Rate-limit key that works behind Cloudflare Tunnel / reverse proxies."""
    for header in ("cf-connecting-ip", "x-real-ip"):
        value = request.headers.get(header)
        if value:
            return value.strip()
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


limiter = Limiter(key_func=client_key, default_limits=[])
