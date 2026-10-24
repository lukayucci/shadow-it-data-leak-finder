"""
Configuración de logging estructurado
"""
import logging
import sys
from datetime import datetime
from rich.logging import RichHandler

def setup_logging(log_level: str = "INFO"):
    """Configura logging con formato estructurado"""
    
    # Formato personalizado
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    
    # Configurar handlers
    handlers = [
        RichHandler(rich_tracebacks=True, markup=True),
        logging.FileHandler(
            f"shadow_it_finder_{datetime.now().strftime('%Y%m%d')}.log",
            encoding='utf-8'
        )
    ]
    
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format=log_format,
        datefmt=date_format,
        handlers=handlers,
        force=True
    )
    
    # Reducir ruido de librerías externas
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    
    return logging.getLogger("ShadowITFinder")
