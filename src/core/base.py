"""
Base classes and interfaces for the sync system
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import hashlib
import json


class DeviceType(Enum):
    """Types of devices to sync"""
    NETWORK = "network"
    SERVER = "server"
    STORAGE = "storage"
    UNKNOWN = "unknown"


class SyncStatus(Enum):
    """Status of sync operation"""
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    UPDATED = "updated"
    CREATED = "created"


@dataclass
class Device:
    """Universal device representation"""
    name: str
    device_type: DeviceType
    source_id: str  # ID in source system
    data: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def __hash__(self):
        """Generate hash for caching"""
        data_str = json.dumps(self.data, sort_keys=True, default=str)
        return hashlib.md5(f"{self.name}:{data_str}".encode()).hexdigest()
    
    def has_changed(self, other: 'Device') -> bool:
        """Check if device data has changed"""
        return self.__hash__() != other.__hash__()


@dataclass
class SyncResult:
    """Result of a sync operation"""
    device_name: str
    status: SyncStatus
    message: str = ""
    old_data: Optional[Dict] = None
    new_data: Optional[Dict] = None
    error: Optional[Exception] = None
    timestamp: datetime = field(default_factory=datetime.now)


class DataSource(ABC):
    """Abstract base class for data sources"""
    
    @abstractmethod
    def connect(self) -> bool:
        """Establish connection to the source"""
        pass
    
    @abstractmethod
    def disconnect(self) -> None:
        """Close connection to the source"""
        pass
    
    @abstractmethod
    def get_devices(self, device_type: DeviceType, 
                   group: Optional[str] = None) -> List[Device]:
        """Retrieve devices from the source"""
        pass
    
    @abstractmethod
    def get_device_by_id(self, device_id: str) -> Optional[Device]:
        """Retrieve a single device by ID"""
        pass
    
    @abstractmethod
    def test_connection(self) -> Tuple[bool, str]:
        """Test connection to the source"""
        pass


class DataTarget(ABC):
    """Abstract base class for data targets"""
    
    @abstractmethod
    def connect(self) -> bool:
        """Establish connection to the target"""
        pass
    
    @abstractmethod
    def disconnect(self) -> None:
        """Close connection to the target"""
        pass
    
    @abstractmethod
    def device_exists(self, device: Device) -> bool:
        """Check if device exists in target"""
        pass
    
    @abstractmethod
    def create_device(self, device: Device) -> SyncResult:
        """Create a new device in target"""
        pass
    
    @abstractmethod
    def update_device(self, device: Device) -> SyncResult:
        """Update existing device in target"""
        pass
    
    @abstractmethod
    def delete_device(self, device: Device) -> SyncResult:
        """Delete device from target"""
        pass
    
    @abstractmethod
    def get_device(self, name: str) -> Optional[Dict]:
        """Get device data from target"""
        pass
    
    @abstractmethod
    def mark_device_offline(self, device_name: str, 
                           last_seen: datetime) -> bool:
        """Mark device as offline with last seen timestamp"""
        pass


class DataProcessor(ABC):
    """Abstract base class for data processors"""
    
    @abstractmethod
    def process(self, device: Device) -> Device:
        """Process and transform device data"""
        pass
    
    @abstractmethod
    def validate(self, device: Device) -> Tuple[bool, List[str]]:
        """Validate device data"""
        pass
    
    @abstractmethod
    def map_fields(self, device: Device, mapping: Dict) -> Dict:
        """Map fields according to configuration"""
        pass


class Cache(ABC):
    """Abstract base class for caching"""
    
    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        pass
    
    @abstractmethod
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache"""
        pass
    
    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete value from cache"""
        pass
    
    @abstractmethod
    def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        pass
    
    @abstractmethod
    def get_all_keys(self, pattern: str = "*") -> List[str]:
        """Get all keys matching pattern"""
        pass
    
    @abstractmethod
    def clear(self, pattern: str = "*") -> int:
        """Clear cache entries matching pattern"""
        pass


class Synchronizer(ABC):
    """Abstract base class for synchronization logic"""
    
    @abstractmethod
    def sync_device(self, device: Device) -> SyncResult:
        """Sync a single device"""
        pass
    
    @abstractmethod
    def sync_batch(self, devices: List[Device]) -> List[SyncResult]:
        """Sync a batch of devices"""
        pass
    
    @abstractmethod
    def sync_all(self) -> Dict[str, Any]:
        """Perform full synchronization"""
        pass
    
    @abstractmethod
    def sync_incremental(self, since: datetime) -> Dict[str, Any]:
        """Perform incremental synchronization"""
        pass