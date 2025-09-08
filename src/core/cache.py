"""
Redis cache implementation
"""

import json
import pickle
import redis
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
import logging

from .base import Cache, Device

logger = logging.getLogger(__name__)


class RedisCache(Cache):
    """Redis-based caching implementation"""
    
    def __init__(self, host='localhost', port=6379, db=0, 
                 password=None, prefix='sync', ttl_hours=24):
        """
        Initialize Redis cache
        
        Args:
            host: Redis host
            port: Redis port
            db: Redis database number
            password: Redis password
            prefix: Key prefix for namespacing
            ttl_hours: Default TTL in hours
        """
        self.prefix = prefix
        self.ttl_seconds = ttl_hours * 3600
        
        try:
            # Создаем подключение без пароля если он не указан или пустой
            if password and password.strip():  # Проверяем что пароль не пустой
                self.client = redis.Redis(
                    host=host,
                    port=port,
                    db=db,
                    password=password,
                    decode_responses=False
                )
            else:
                # Подключение без пароля
                self.client = redis.Redis(
                    host=host,
                    port=port,
                    db=db,
                    decode_responses=False
                )
            
            # Test connection
            self.client.ping()
            logger.info(f"Connected to Redis at {host}:{port}")
        except redis.ConnectionError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    def _make_key(self, key: str) -> str:
        """Create namespaced key"""
        return f"{self.prefix}:{key}"
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        full_key = self._make_key(key)
        try:
            value = self.client.get(full_key)
            if value:
                # Try to deserialize as JSON first
                try:
                    return json.loads(value)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    # Fall back to pickle for complex objects
                    try:
                        return pickle.loads(value)
                    except:
                        # Return as string
                        return value.decode('utf-8')
            return None
        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache"""
        full_key = self._make_key(key)
        ttl = ttl or self.ttl_seconds
        
        try:
            # Serialize value
            if isinstance(value, (dict, list, str, int, float, bool)):
                serialized = json.dumps(value, default=str)
            else:
                # Use pickle for complex objects
                serialized = pickle.dumps(value)
            
            result = self.client.setex(full_key, ttl, serialized)
            return bool(result)
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """Delete value from cache"""
        full_key = self._make_key(key)
        try:
            result = self.client.delete(full_key)
            return bool(result)
        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {e}")
            return False
    
    def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        full_key = self._make_key(key)
        try:
            return bool(self.client.exists(full_key))
        except Exception as e:
            logger.error(f"Cache exists error for key {key}: {e}")
            return False
    
    def get_all_keys(self, pattern: str = "*") -> List[str]:
        """Get all keys matching pattern"""
        full_pattern = self._make_key(pattern)
        try:
            keys = self.client.keys(full_pattern)
            # Remove prefix from keys
            prefix_len = len(self.prefix) + 1
            return [key.decode('utf-8')[prefix_len:] for key in keys]
        except Exception as e:
            logger.error(f"Cache get_all_keys error: {e}")
            return []
    
    def clear(self, pattern: str = "*") -> int:
        """Clear cache entries matching pattern"""
        full_pattern = self._make_key(pattern)
        try:
            keys = self.client.keys(full_pattern)
            if keys:
                return self.client.delete(*keys)
            return 0
        except Exception as e:
            logger.error(f"Cache clear error: {e}")
            return 0
    
    # Additional methods for device-specific operations
    
    def get_device(self, device_name: str) -> Optional[Device]:
        """Get cached device"""
        key = f"device:{device_name}"
        return self.get(key)
    
    def set_device(self, device: Device, ttl: Optional[int] = None) -> bool:
        """Cache device"""
        key = f"device:{device.name}"
        return self.set(key, device, ttl)
    
    def get_device_hash(self, device_name: str) -> Optional[str]:
        """Get cached device hash"""
        key = f"hash:{device_name}"
        return self.get(key)
    
    def set_device_hash(self, device_name: str, hash_value: str, 
                        ttl: Optional[int] = None) -> bool:
        """Cache device hash"""
        key = f"hash:{device_name}"
        return self.set(key, hash_value, ttl)
    
    def get_last_sync(self, source: str = None) -> Optional[datetime]:
        """Get last sync timestamp"""
        key = f"last_sync:{source}" if source else "last_sync"
        timestamp = self.get(key)
        if timestamp:
            return datetime.fromisoformat(timestamp)
        return None
    
    def set_last_sync(self, timestamp: datetime, source: str = None) -> bool:
        """Set last sync timestamp"""
        key = f"last_sync:{source}" if source else "last_sync"
        return self.set(key, timestamp.isoformat())
    
    def get_sync_stats(self) -> Optional[Dict]:
        """Get sync statistics"""
        return self.get("stats:latest")
    
    def set_sync_stats(self, stats: Dict) -> bool:
        """Set sync statistics"""
        stats['timestamp'] = datetime.now().isoformat()
        return self.set("stats:latest", stats)
    
    def add_to_failed_devices(self, device_name: str, error: str) -> bool:
        """Add device to failed list"""
        key = f"failed:{datetime.now().strftime('%Y%m%d')}"
        failed_list = self.get(key) or []
        failed_list.append({
            'device': device_name,
            'error': error,
            'timestamp': datetime.now().isoformat()
        })
        return self.set(key, failed_list, ttl=86400 * 7)  # Keep for 7 days
    
    def get_failed_devices(self, date: Optional[str] = None) -> List[Dict]:
        """Get list of failed devices"""
        if date:
            key = f"failed:{date}"
        else:
            key = f"failed:{datetime.now().strftime('%Y%m%d')}"
        return self.get(key) or []


class MemoryCache(Cache):
    """In-memory cache implementation (fallback when Redis unavailable)"""
    
    def __init__(self, ttl_hours=24):
        self.cache = {}
        self.ttl = timedelta(hours=ttl_hours)
        logger.warning("Using in-memory cache (Redis not available)")
    
    def _is_expired(self, item):
        """Check if cache item is expired"""
        return datetime.now() > item['expires']
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if key in self.cache:
            item = self.cache[key]
            if not self._is_expired(item):
                return item['value']
            else:
                del self.cache[key]
        return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache"""
        expires = datetime.now() + (timedelta(seconds=ttl) if ttl else self.ttl)
        self.cache[key] = {
            'value': value,
            'expires': expires
        }
        return True
    
    def delete(self, key: str) -> bool:
        """Delete value from cache"""
        if key in self.cache:
            del self.cache[key]
            return True
        return False
    
    def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        if key in self.cache:
            if not self._is_expired(self.cache[key]):
                return True
            else:
                del self.cache[key]
        return False
    
    def get_all_keys(self, pattern: str = "*") -> List[str]:
        """Get all keys matching pattern"""
        import fnmatch
        
        # Clean expired items first
        expired_keys = [k for k, v in self.cache.items() if self._is_expired(v)]
        for key in expired_keys:
            del self.cache[key]
        
        if pattern == "*":
            return list(self.cache.keys())
        
        return [k for k in self.cache.keys() if fnmatch.fnmatch(k, pattern)]
    
    def clear(self, pattern: str = "*") -> int:
        """Clear cache entries matching pattern"""
        keys_to_delete = self.get_all_keys(pattern)
        for key in keys_to_delete:
            del self.cache[key]
        return len(keys_to_delete)
    
    # Additional methods for device-specific operations (for compatibility)
    
    def get_device(self, device_name: str) -> Optional[Device]:
        """Get cached device"""
        return self.get(f"device:{device_name}")
    
    def set_device(self, device: Device, ttl: Optional[int] = None) -> bool:
        """Cache device"""
        return self.set(f"device:{device.name}", device, ttl)
    
    def get_device_hash(self, device_name: str) -> Optional[str]:
        """Get cached device hash"""
        return self.get(f"hash:{device_name}")
    
    def set_device_hash(self, device_name: str, hash_value: str, 
                        ttl: Optional[int] = None) -> bool:
        """Cache device hash"""
        return self.set(f"hash:{device_name}", hash_value, ttl)
    
    def get_last_sync(self, source: str = None) -> Optional[datetime]:
        """Get last sync timestamp"""
        key = f"last_sync:{source}" if source else "last_sync"
        timestamp = self.get(key)
        if timestamp:
            return datetime.fromisoformat(timestamp)
        return None
    
    def set_last_sync(self, timestamp: datetime, source: str = None) -> bool:
        """Set last sync timestamp"""
        key = f"last_sync:{source}" if source else "last_sync"
        return self.set(key, timestamp.isoformat())
    
    def get_sync_stats(self) -> Optional[Dict]:
        """Get sync statistics"""
        return self.get("stats:latest")
    
    def set_sync_stats(self, stats: Dict) -> bool:
        """Set sync statistics"""
        stats['timestamp'] = datetime.now().isoformat()
        return self.set("stats:latest", stats)
    
    def add_to_failed_devices(self, device_name: str, error: str) -> bool:
        """Add device to failed list"""
        key = f"failed:{datetime.now().strftime('%Y%m%d')}"
        failed_list = self.get(key) or []
        failed_list.append({
            'device': device_name,
            'error': error,
            'timestamp': datetime.now().isoformat()
        })
        return self.set(key, failed_list, ttl=86400 * 7)
    
    def get_failed_devices(self, date: Optional[str] = None) -> List[Dict]:
        """Get list of failed devices"""
        if date:
            key = f"failed:{date}"
        else:
            key = f"failed:{datetime.now().strftime('%Y%m%d')}"
        return self.get(key) or []