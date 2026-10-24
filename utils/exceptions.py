"""
Excepciones personalizadas para Shadow IT & Data Leak Finder
"""

class ShadowITFinderError(Exception):
    """Excepción base del sistema"""
    pass

class APIConnectionError(ShadowITFinderError):
    """Error de conexión con API"""
    pass

class RateLimitError(ShadowITFinderError):
    """Error por límite de rate limit"""
    def __init__(self, message: str, retry_after: int = None):
        super().__init__(message)
        self.retry_after = retry_after

class APIResponseError(ShadowITFinderError):
    """Error en respuesta de API"""
    def __init__(self, message: str, status_code: int = None):
        super().__init__(message)
        self.status_code = status_code

class InvalidDataError(ShadowITFinderError):
    """Datos inválidos o mal formateados"""
    pass

class NetworkError(ShadowITFinderError):
    """Error de red"""
    pass
