"""
Configuración centralizada del sistema
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

class Settings:
    """Configuración global de la aplicación"""
    
    # Rutas
    BASE_DIR = Path(__file__).parent.parent
    OUTPUT_DIR = BASE_DIR / os.getenv("OUTPUT_DIR", "./outputs")
    
    # API OpenCode/Big Pickle
    OPENCODE_API_ENDPOINT = os.getenv("OPENCODE_API_ENDPOINT", "https://api.opencode.ai/v1/chat/completions")
    OPENCODE_API_KEY = os.getenv("OPENCODE_API_KEY", "")
    BIG_PICKLE_MODEL = os.getenv("BIG_PICKLE_MODEL", "big-pickle")
    MODEL_NAME = os.getenv("MODEL_NAME", "big-pickle")
    
    # Configuración de requests
    REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "120"))
    MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
    RETRY_BACKOFF_BASE = int(os.getenv("RETRY_BACKOFF_BASE", "2"))
    RATE_LIMIT_WAIT = int(os.getenv("RATE_LIMIT_WAIT", "60"))
    
    # Configuración de aplicación
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    SCAN_INTERVAL_MINUTES = int(os.getenv("SCAN_INTERVAL_MINUTES", "60"))
    MAX_RAW_DATA_SIZE_MB = int(os.getenv("MAX_RAW_DATA_SIZE_MB", "10"))
    ENVIRONMENT = os.getenv("ENVIRONMENT", "production")
    
    def __init__(self):
        # Crear directorios necesarios
        self.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    def validate(self) -> bool:
        """Valida configuración crítica"""
        if not self.OPENCODE_API_KEY:
            print("⚠️  ADVERTENCIA: OPENCODE_API_KEY no configurado en .env")
            return False
        return True

settings = Settings()
