"""
Modelo de Reporte
"""
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from web.app.core.database import Base

class Report(Base):
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    title = Column(String, nullable=False)
    target_organization = Column(String, nullable=False)
    
    status = Column(String, default="pending")  # pending, processing, completed, failed
    
    # Archivos generados
    markdown_file = Column(String, nullable=True)
    json_file = Column(String, nullable=True)
    
    # Datos del análisis
    analysis_data = Column(JSON, nullable=True)
    
    # Metadata
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relaciones
    user = relationship("User", back_populates="reports")
    
    def __repr__(self):
        return f"<Report {self.title}>"
