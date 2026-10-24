"""
Modelo de Usuario
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from web.app.core.database import Base
import enum

class PlanType(enum.Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)
    
    plan = Column(Enum(PlanType), default=PlanType.FREE)
    credits = Column(Integer, default=3)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relaciones
    reports = relationship("Report", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User {self.email}>"
