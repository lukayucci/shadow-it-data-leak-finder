"""
Router para intro/landing
"""
from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from web.app.core.config import settings
from web.app.deps.auth import get_current_user_optional
from web.app.core.database import SessionLocal

router = APIRouter()
templates = Jinja2Templates(directory=str(settings.TEMPLATES_DIR))

@router.get("/")
async def intro(request: Request):
    db = SessionLocal()
    try:
        user = await get_current_user_optional(request, db)
        if user:
            return RedirectResponse(url="/dashboard")
        return templates.TemplateResponse(request, "intro.html")
    finally:
        db.close()
