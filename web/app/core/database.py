"""
Configuración de base de datos SQLAlchemy
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from web.app.core.config import settings

SQLALCHEMY_DATABASE_URL = settings.DATABASE_URL

# Configurar engine
connect_args = {}
if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args=connect_args,
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    """Dependency para obtener sesión de DB"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Inicializar base de datos"""
    from web.app import models
    Base.metadata.create_all(bind=engine)
    print("✅ Base de datos inicializada")
