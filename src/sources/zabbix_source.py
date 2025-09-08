"""
Zabbix data source implementation
"""

import logging
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
from pyzabbix import ZabbixAPI
import urllib3

from ..core.base import DataSource, Device, DeviceType

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class ZabbixSource(DataSource):
    """Zabbix API data source"""
    
    def __init__(self, url: str, username: str, password: str, 
                 timeout: int = 30, verify_ssl: bool = False):
        """
        Initialize Zabbix source
        
        Args:
            url: Zabbix API URL
            username: Zabbix username
            password: Zabbix password
            timeout: API timeout in seconds
            verify_ssl: Verify SSL certificates
        """
        self.url = url
        self.username = username
        self.password = password
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.api = None
        self._connected = False
    
    def connect(self) -> bool:
        """Establish connection to Zabbix"""
        try:
            self.api = ZabbixAPI(self.url)
            self.api.session.verify = self.verify_ssl
            self.api.timeout = self.timeout
            self.api.login(self.username, self.password)
            self._connected = True
            logger.info(f"Connected to Zabbix at {self.url}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Zabbix: {e}")
            self._connected = False
            return False
    
    def disconnect(self) -> None:
        """Close connection to Zabbix"""
        if self.api and self._connected:
            try:
                self.api.user.logout()
                logger.info("Disconnected from Zabbix")
            except Exception as e:
                logger.warning(f"Error during Zabbix logout: {e}")
            finally:
                self._connected = False
                self.api = None
    
    def test_connection(self) -> Tuple[bool, str]:
        """Test connection to Zabbix"""
        try:
            if not self._connected:
                if not self.connect():
                    return False, "Failed to connect"
            
            # Test API call
            version = self.api.api_version()
            host_count = self.api.host.get(countOutput=True)
            
            message = f"Zabbix API v{version}, {host_count} hosts"
            return True, message
        except Exception as e:
            return False, str(e)
    
    def get_devices(self, device_type: DeviceType, 
                   group: Optional[str] = None) -> List[Device]:
        """
        Retrieve devices from Zabbix
        
        Args:
            device_type: Type of devices to retrieve
            group: Host group name to filter
            
        Returns:
            List of Device objects
        """
        if not self._connected:
            if not self.connect():
                return []
        
        devices = []
        
        try:
            # Build query parameters
            params = {
                "output": "extend",
                "selectInventory": "extend",
                "selectInterfaces": "extend",
                "selectGroups": "extend",
                "selectTags": "extend",
                "selectMacros": "extend"
            }
            
            # Filter by group if specified
            if group:
                groups = self.api.hostgroup.get(filter={"name": group})
                if groups:
                    params["groupids"] = groups[0]["groupid"]
                    logger.info(f"Filtering by group: {group}")
                else:
                    logger.warning(f"Group not found: {group}")
                    return []
            
            # Get hosts from Zabbix
            hosts = self.api.host.get(**params)
            logger.info(f"Retrieved {len(hosts)} hosts from Zabbix")
            
            # Convert to Device objects
            for host in hosts:
                device = self._host_to_device(host, device_type)
                if device:
                    devices.append(device)
            
            logger.info(f"Processed {len(devices)} devices of type {device_type.value}")
            
        except Exception as e:
            logger.error(f"Error retrieving devices from Zabbix: {e}")
        
        return devices
    
    def get_device_by_id(self, device_id: str) -> Optional[Device]:
        """Retrieve a single device by ID"""
        if not self._connected:
            if not self.connect():
                return None
        
        try:
            hosts = self.api.host.get(
                hostids=device_id,
                output="extend",
                selectInventory="extend",
                selectInterfaces="extend",
                selectGroups="extend",
                selectTags="extend",
                selectMacros="extend"
            )
            
            if hosts:
                # Try to determine device type
                device_type = self._determine_device_type(hosts[0])
                return self._host_to_device(hosts[0], device_type)
            
        except Exception as e:
            logger.error(f"Error retrieving device {device_id}: {e}")
        
        return None
    
    def _host_to_device(self, host: Dict[str, Any], 
                       device_type: DeviceType) -> Optional[Device]:
        """Convert Zabbix host to Device object"""
        try:
            # Extract basic info
            device_data = {
                "hostid": host.get("hostid"),
                "host": host.get("host"),
                "name": host.get("name"),
                "status": host.get("status"),
                "description": host.get("description"),
                "inventory": host.get("inventory", {}),
                "interfaces": host.get("interfaces", []),
                "groups": host.get("groups", []),
                "tags": host.get("tags", []),
                "macros": host.get("macros", [])
            }
            
            # Add metadata
            metadata = {
                "source": "zabbix",
                "retrieved_at": datetime.now().isoformat(),
                "group_names": [g.get("name", "") for g in host.get("groups", [])]
            }
            
            # Create Device object
            device = Device(
                name=host.get("host"),
                device_type=device_type,
                source_id=host.get("hostid"),
                data=device_data,
                metadata=metadata
            )
            
            return device
            
        except Exception as e:
            logger.error(f"Error converting host {host.get('host')} to Device: {e}")
            return None
    
    def _determine_device_type(self, host: Dict[str, Any]) -> DeviceType:
        """Determine device type from host data"""
        groups = host.get("groups", [])
        group_names = [g.get("name", "").lower() for g in groups]
        
        # Check group names
        for group_name in group_names:
            if "network" in group_name:
                return DeviceType.NETWORK
            elif "server" in group_name or "vmware" in group_name:
                return DeviceType.SERVER
            elif "storage" in group_name or "datastore" in group_name:
                return DeviceType.STORAGE
        
        # Check tags
        tags = host.get("tags", [])
        for tag in tags:
            tag_name = tag.get("tag", "").lower()
            if "network" in tag_name:
                return DeviceType.NETWORK
            elif "server" in tag_name or "hypervisor" in tag_name:
                return DeviceType.SERVER
            elif "storage" in tag_name:
                return DeviceType.STORAGE
        
        # Check inventory
        inventory = host.get("inventory", {})
        hw_type = inventory.get("type", "").lower()
        if "switch" in hw_type or "router" in hw_type:
            return DeviceType.NETWORK
        elif "server" in hw_type:
            return DeviceType.SERVER
        
        return DeviceType.UNKNOWN
    
    def get_hosts_by_group(self, group_name: str) -> List[Dict]:
        """Get all hosts in a specific group"""
        if not self._connected:
            if not self.connect():
                return []
        
        try:
            # Get group ID
            groups = self.api.hostgroup.get(filter={"name": group_name})
            if not groups:
                logger.warning(f"Group not found: {group_name}")
                return []
            
            group_id = groups[0]["groupid"]
            
            # Get hosts
            hosts = self.api.host.get(
                groupids=group_id,
                output="extend",
                selectInventory="extend",
                selectInterfaces="extend",
                selectTags="extend"
            )
            
            return hosts
            
        except Exception as e:
            logger.error(f"Error getting hosts for group {group_name}: {e}")
            return []
    
    def get_all_groups(self) -> List[Dict]:
        """Get all host groups"""
        if not self._connected:
            if not self.connect():
                return []
        
        try:
            groups = self.api.hostgroup.get(output=["groupid", "name"])
            return groups
        except Exception as e:
            logger.error(f"Error getting groups: {e}")
            return []
    
    def get_host_updates_since(self, timestamp: datetime) -> List[Dict]:
        """Get hosts updated since a specific timestamp"""
        if not self._connected:
            if not self.connect():
                return []
        
        try:
            # Convert timestamp to Unix time
            unix_time = int(timestamp.timestamp())
            
            # Get hosts with recent changes
            # Note: This requires history.get which may not be efficient
            # Alternative: track changes via lastclock or other fields
            
            hosts = self.api.host.get(
                output="extend",
                selectInventory="extend",
                selectInterfaces="extend",
                selectTags="extend",
                filter={
                    "lastclock": {"$gte": unix_time}
                }
            )
            
            return hosts
            
        except Exception as e:
            logger.error(f"Error getting host updates: {e}")
            return []