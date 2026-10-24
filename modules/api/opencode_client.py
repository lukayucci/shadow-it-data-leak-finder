"""
Cliente asíncrono para API de OpenCode/Big Pickle
"""
import asyncio
import json
import aiohttp
from typing import Dict, Any
from config.settings import settings
from utils.exceptions import APIConnectionError, RateLimitError, APIResponseError, NetworkError
from utils.retry import async_retry

class OpenCodeBigPickleClient:
    """Cliente robusto para interactuar con Big Pickle vía API OpenCode"""
    
    def __init__(self):
        self.api_key = settings.OPENCODE_API_KEY
        self.model = settings.BIG_PICKLE_MODEL or settings.MODEL_NAME or "big-pickle"
        self.timeout = settings.REQUEST_TIMEOUT
        self.session_id = None
        
        # Posibles endpoints a probar
        self.endpoints_to_try = []
        
        # 1. Servidor local opencode serve
        self.endpoints_to_try.append({
            "type": "local_session",
            "base_url": "http://127.0.0.1:4096"
        })
        
        # 2. Endpoint configurado en .env
        if settings.OPENCODE_API_ENDPOINT:
            ep = settings.OPENCODE_API_ENDPOINT
            if '/chat/completions' in ep:
                self.endpoints_to_try.append({
                    "type": "chat_completions",
                    "url": ep,
                    "base_url": ep.replace('/v1/chat/completions', '').replace('/chat/completions', '')
                })
            else:
                self.endpoints_to_try.append({
                    "type": "local_session",
                    "base_url": ep.rstrip('/')
                })
        
        # 3. API remota OpenCode
        self.endpoints_to_try.append({
            "type": "chat_completions",
            "url": "https://api.opencode.ai/v1/chat/completions",
            "base_url": "https://api.opencode.ai"
        })
        
        self.headers = {
            "Content-Type": "application/json",
            "User-Agent": "ShadowIT-DataLeakFinder/1.0"
        }
        if self.api_key:
            self.headers["Authorization"] = f"Bearer {self.api_key}"
    
    @async_retry(max_retries=2, base_delay=2, exceptions=(aiohttp.ClientError, asyncio.TimeoutError))
    async def analyze_with_big_pickle(self, messages: list, **kwargs) -> Dict[str, Any]:
        """Intenta conectar con Big Pickle usando múltiples estrategias"""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        last_error = None
        
        for idx, endpoint_cfg in enumerate(self.endpoints_to_try):
            try:
                async with aiohttp.ClientSession(timeout=timeout, headers=self.headers) as session:
                    if endpoint_cfg["type"] == "local_session":
                        result = await self._try_local_session(session, endpoint_cfg["base_url"], messages)
                        if result:
                            return result
                    elif endpoint_cfg["type"] == "chat_completions":
                        result = await self._try_chat_completions(session, endpoint_cfg["url"], messages)
                        if result:
                            return result
            except RateLimitError:
                raise
            except Exception as e:
                last_error = e
                continue
        
        if last_error:
            raise last_error
        raise APIConnectionError("No se pudo conectar a ningún endpoint de OpenCode/Big Pickle")
    
    async def _try_local_session(self, session, base_url, messages):
        try:
            # Crear sesión
            if not self.session_id:
                async with session.post(f"{base_url}/session", json={"title": "ShadowIT-Audit"}) as resp:
                    if resp.status in [200, 201]:
                        data = await resp.json()
                        self.session_id = data.get('id') or data.get('sessionID')
                    elif resp.status == 404:
                        return None
                    else:
                        return None
            
            system_msg = ""
            user_msg = ""
            for m in messages:
                if m['role'] == 'system':
                    system_msg = m['content']
                elif m['role'] == 'user':
                    user_msg = m['content']
            
            combined = f"{system_msg}\n\n{user_msg}" if system_msg else user_msg
            payload = {"parts": [{"type": "text", "text": combined}], "model": self.model}
            
            async with session.post(f"{base_url}/session/{self.session_id}/message", json=payload) as response:
                if response.status == 200:
                    resp_data = await response.json()
                    return self._parse_response(resp_data)
                return None
        except:
            return None
    
    async def _try_chat_completions(self, session, url, messages):
        try:
            payload = {
                "model": self.model,
                "messages": messages,
                "temperature": 0.1,
                "max_tokens": 4000,
                "stream": False
            }
            async with session.post(url, json=payload) as response:
                if response.status == 429:
                    retry_after = response.headers.get('Retry-After', settings.RATE_LIMIT_WAIT)
                    raise RateLimitError(f"Rate limit", retry_after=int(retry_after) if retry_after.isdigit() else settings.RATE_LIMIT_WAIT)
                if response.status in [200, 201]:
                    resp_data = await response.json()
                    return self._parse_response(resp_data)
                if response.status == 404:
                    return None
                if response.status >= 500:
                    raise APIResponseError(f"Error servidor: {response.status}")
                error_text = await response.text()
                raise APIResponseError(f"Error: {response.status} - {error_text[:100]}")
        except (RateLimitError, APIResponseError):
            raise
        except:
            return None
    
    def _parse_response(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        content = ""
        if "parts" in response_data:
            for part in response_data["parts"]:
                if isinstance(part, dict) and part.get("type") == "text":
                    content += part.get("text", "")
        elif "info" in response_data and isinstance(response_data.get("parts"), list):
            for part in response_data["parts"]:
                if isinstance(part, dict) and part.get("type") == "text":
                    content += part.get("text", "")
        elif "choices" in response_data and response_data["choices"]:
            choice = response_data["choices"][0]
            if isinstance(choice.get("message"), dict):
                content = choice["message"].get("content", "")
            elif isinstance(choice.get("delta"), dict):
                content = choice["delta"].get("content", "")
        elif "message" in response_data:
            msg = response_data["message"]
            if isinstance(msg, dict):
                if isinstance(msg.get("parts"), list):
                    for part in msg["parts"]:
                        if isinstance(part, dict) and part.get("type") == "text":
                            content += part.get("text", "")
                else:
                    content = msg.get("content", "")
        elif "content" in response_data:
            content = response_data["content"]
        
        if not content:
            raise APIResponseError("Sin contenido en respuesta")
        
        content_cleaned = content.strip()
        for marker in ["```json", "```JSON", "```"]:
            if content_cleaned.startswith(marker):
                content_cleaned = content_cleaned[len(marker):]
            if content_cleaned.endswith("```"):
                content_cleaned = content_cleaned[:-3]
        content_cleaned = content_cleaned.strip()
        
        try:
            return json.loads(content_cleaned)
        except json.JSONDecodeError as e:
            raise APIResponseError(f"JSON inválido: {e}")
    
    async def health_check(self) -> bool:
        try:
            timeout = aiohttp.ClientTimeout(total=3)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get("http://127.0.0.1:4096/global/health") as resp:
                    if resp.status == 200:
                        return True
        except:
            pass
        return False
