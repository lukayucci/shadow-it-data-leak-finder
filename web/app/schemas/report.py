"""
Schemas de Reporte
"""
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime

class ReportCreate(BaseModel):
    target_organization: str

class ReportResponse(BaseModel):
    id: int
    user_id: int
    title: str
    target_organization: str
    status: str
    markdown_file: Optional[str] = None
    json_file: Optional[str] = None
    findings_count: int
    critical_count: int
    high_count: int
    created_at: datetime
    completed_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True
