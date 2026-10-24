#!/usr/bin/env python3
"""
Script para arrancar el servidor web SaaS
"""
import uvicorn
import sys
from pathlib import Path

# Añadir path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

if __name__ == "__main__":
    uvicorn.run(
        "web.app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )
