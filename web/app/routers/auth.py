"""
Router de autenticación
"""
from fastapi import APIRouter, Depends, Request, Form, Response
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from datetime import timedelta

from web.app.core.database import get_db
from web.app.core.security import get_password_hash, verify_password, create_access_token
from web.app.core.config import settings
from web.app.models.user import User

router = APIRouter()
templates = Jinja2Templates(directory=str(settings.TEMPLATES_DIR))

@router.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse(request, "auth/login.html")

@router.post("/login")
async def login(request: Request, response: Response, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(request, "auth/login.html", {"error": "Invalid credentials"})
    if not user.is_active:
        return templates.TemplateResponse(request, "auth/login.html", {"error": "Account disabled"})
    access_token = create_access_token(data={"sub": str(user.id)}, expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    resp = RedirectResponse(url="/dashboard", status_code=302)
    resp.set_cookie(key="access_token", value=access_token, httponly=True, max_age=settings.SESSION_MAX_AGE, samesite="lax")
    return resp

@router.get("/register")
async def register_page(request: Request):
    return templates.TemplateResponse(request, "auth/register.html")

@router.post("/register")
async def register(request: Request, email: str = Form(...), username: str = Form(...), full_name: str = Form(""), password: str = Form(...), confirm_password: str = Form(...), db: Session = Depends(get_db)):
    if password != confirm_password:
        return templates.TemplateResponse(request, "auth/register.html", {"error": "Passwords do not match"})
    if db.query(User).filter(User.email == email).first():
        return templates.TemplateResponse(request, "auth/register.html", {"error": "Email already registered"})
    if db.query(User).filter(User.username == username).first():
        return templates.TemplateResponse(request, "auth/register.html", {"error": "Username taken"})
    new_user = User(email=email, username=username, full_name=full_name or None, hashed_password=get_password_hash(password), credits=settings.FREE_CREDITS)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return templates.TemplateResponse(request, "auth/login.html", {"success": "Account created. Authenticate."})

@router.get("/logout")
async def logout():
    resp = RedirectResponse(url="/login", status_code=302)
    resp.delete_cookie("access_token")
    return resp
