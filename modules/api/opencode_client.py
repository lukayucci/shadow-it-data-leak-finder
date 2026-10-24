"""
Cliente asíncrono para API de OpenCode/Big Pickle
"""
import asyncio
import json
import aiohttp
from typing import Dict, Any, Optional
from config.settings import settings
from utils.exceptions import APIConnectionError, RateLimitError, APIResponseError, NetworkError
from utils.retry import async_retry

class OpenCodeBigPickleClient:
    """Cliente robusto para interactuar con Big Pickle vía API OpenCode"""
    
    def __init__(self):
        self.endpoint = settings.OPENCODE_API_ENDPOINT
        self.api_key = settings.OPENCODE_API_KEY
        self.model = settings.BIG_PICKLE_MODEL
        self.timeout = settings.REQUEST_TIMEOUT
        self.max_retries = settings.MAX_RETRIES
        
        self.headers = {
            "Content-Type": "application/json",
            "User-Agent": "ShadowIT-DataLeakFinder/1.0"
        }
        
        if self.api_key:
            self.headers["Authorization"] = f"Bearer {self.api_key}"
    
    @async_retry(max_retries=3, base_delay=2, exceptions=(aiohttp.ClientError, asyncio.TimeoutError))
    async def analyze_with_big_pickle(self, messages: list, **kwargs) -> Dict[str, Any]:
        """
        Envía datos al modelo Big Pickle para análisis SOC defensivo
        Formato compatible con API de chat completions
        """
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", 0.1),  # Baja temperatura para análisis preciso
            "max_tokens": kwargs.get("max_tokens", 4000),
            "top_p": kwargs.get("top_p", 0.9),
            "stream": False
        }
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        try:
            async with aiohttp.ClientSession(timeout=timeout, headers=self.headers) as session:
                async with session.post(self.endpoint, json=payload) as response:
                    # Manejo de rate limit
                    if response.status == 429:
                        retry_after = response.headers.get('Retry-After', settings.RATE_LIMIT_WAIT)
                        try:
                            retry_after_int = int(retry_after)
                        except:
                            retry_after_int = settings.RATE_LIMIT_WAIT
                        raise RateLimitError(
                            f"Rate limit alcanzado. Reintentando después de {retry_after_int}s",
                            retry_after=retry_after_int
                        )
                    
                    # Manejo de errores de autenticación
                    if response.status == 401:
                        raise APIResponseError("Autenticación fallida. Verifica OPENCODE_API_KEY", status_code=401)
                    
                    # Manejo de errores del servidor
                    if response.status >= 500:
                        raise APIResponseError(f"Error del servidor API: {response.status}", status_code=response.status)
                    
                    # Manejo de errores del cliente
                    if response.status >= 400:
                        error_text = await response.text()
                        raise APIResponseError(f"Error en solicitud: {response.status} - {error_text}", status_code=response.status)
                    
                    # Respuesta exitosa
                    response_data = await response.json()
                    return self._parse_response(response_data)
                    
        except aiohttp.ClientConnectorError as e:
            raise APIConnectionError(f"Error de conexión con API OpenCode: {e}")
        except asyncio.TimeoutError as e:
            raise NetworkError(f"Timeout en solicitud a API ({self.timeout}s): {e}")
        except json.JSONDecodeError as e:
            raise APIResponseError(f"Respuesta inválida (no JSON): {e}")
    
    def _parse_response(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parsea respuesta de API y extrae contenido JSON"""
        try:
            # Formato OpenAI compatible
            if "choices" in response_data and len(response_data["choices"]) > 0:
                content = response_data["choices"][0].get("message", {}).get("content", "")
            elif "content" in response_data:
                content = response_data["content"]
            else:
                raise APIResponseError("Formato de respuesta inesperado")
            
            # Intentar parsear JSON del contenido
            # Limpiar posibles markdown code blocks
            content_cleaned = content.strip()
            if content_cleaned.startswith("```json"):
                content_cleaned = content_cleaned[7:]
            if content_cleaned.startswith("```"):
                content_cleaned = content_cleaned[3:]
            if content_cleaned.endswith("```"):
                content_cleaned = content_cleaned[:-3]
            content_cleaned = content_cleaned.strip()
            
            analysis_result = json.loads(content_cleaned)
            return analysis_result
            
        except json.JSONDecodeError as e:
            raise APIResponseError(f"Respuesta de IA no es JSON válido: {e}. Contenido: {content[:200]}...")
        except KeyError as e:
            raise APIResponseError(f"Clave faltante en respuesta: {e}")
    
    async def health_check(self) -> bool:
        """Verifica conectividad con API"""
        try:
            if not self.api_key:
                print("⚠️  Sin API key configurada")
                return False
            
            # Test simple
            test_messages = [
                {"role": "system", "content": "Respond only with 'OK'"},
                {"role": "user", "content": "test"}
            ]
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout, headers=self.headers) as session:
                payload = {"model": self.model, "messages": test_messages, "max_tokens": 5}
                async with session.post(self.endpoint, json=payload) as response:
                    return response.status < 500
        except:
            return False
