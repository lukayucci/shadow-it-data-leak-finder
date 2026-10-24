"""
Configuración del backend web
"""
import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True, extra="ignore")
    
    APP_NAME: str = "ZERO"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    SECRET_KEY: str = os.getenv("WEB_SECRET_KEY", "zero-corp-super-secret-key-change-in-production-32chars")
    
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./shadowit_saas.db")
    
    SESSION_COOKIE_NAME: str = "zero_session"
    SESSION_MAX_AGE: int = 60 * 60 * 24 * 7
    
    BASE_DIR: Path = Path(__file__).parent.parent.parent
    PROJECT_ROOT: Path = Path(__file__).parent.parent.parent.parent
    UPLOAD_DIR: Path = BASE_DIR / "static" / "reports"
    TEMPLATES_DIR: Path = BASE_DIR / "templates"
    
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7
    
    FREE_CREDITS: int = 3
    PRO_CREDITS: int = 50
    ENTERPRISE_CREDITS: int = 999999
    
    LEMONSQUEEZY_API_KEY: str = ""
    LEMONSQUEEZY_STORE_ID: str = ""
    LEMONSQUEEZY_WEBHOOK_SECRET: str = ""

settings = Settings()
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
