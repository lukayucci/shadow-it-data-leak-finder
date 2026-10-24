"""
Lógica de reintentos con backoff exponencial
"""
import asyncio
import random
from functools import wraps
from typing import Callable, Any

async def exponential_backoff(attempt: int, base: int = 2, max_wait: int = 300) -> int:
    """Calcula tiempo de espera con backoff exponencial + jitter"""
    wait_time = min(base ** attempt + random.uniform(0, 1), max_wait)
    return int(wait_time)

def async_retry(max_retries: int = 3, base_delay: int = 2, exceptions: tuple = (Exception,)):
    """Decorador para reintentos asíncronos"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt == max_retries - 1:
                        raise
                    delay = await exponential_backoff(attempt, base_delay)
                    print(f"⚠️  Reintento {attempt + 1}/{max_retries} en {delay}s tras error: {e}")
                    await asyncio.sleep(delay)
            raise last_exception
        return wrapper
    return decorator
