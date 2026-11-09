"""
Configuración del backend web
"""
import secrets
from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True, extra="ignore")

    APP_NAME: str = "ZERO"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"

    # En producción WEB_SECRET_KEY es obligatoria (ver validación abajo).
    # Se acepta WEB_SECRET_KEY o SECRET_KEY como variable de entorno.
    SECRET_KEY: str = Field(
        default="",
        validation_alias=AliasChoices("WEB_SECRET_KEY", "SECRET_KEY"),
    )

    DATABASE_URL: str = "sqlite:///./shadowit_saas.db"

    SESSION_COOKIE_NAME: str = "zero_session"
    SESSION_MAX_AGE: int = 60 * 60 * 24 * 7

    # Cookies Secure solo sobre HTTPS; se fuerza en producción.
    SECURE_COOKIES: bool = False

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

if settings.ENVIRONMENT in ("production", "prod"):
    settings.SECURE_COOKIES = True

if not settings.SECRET_KEY:
    if settings.ENVIRONMENT in ("production", "prod"):
        raise RuntimeError(
            "WEB_SECRET_KEY es obligatoria en producción. "
            "Definí una clave aleatoria de al menos 32 caracteres."
        )
    settings.SECRET_KEY = secrets.token_urlsafe(48)
    print("⚠️  WEB_SECRET_KEY no definida: usando clave aleatoria de desarrollo (las sesiones se invalidan al reiniciar).")

settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
