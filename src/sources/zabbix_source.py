"""
Zabbix data source implementation with VMware discovery support
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
            group: Host group name to filter (or discovery rule name for VMware)
            
        Returns:
            List of Device objects
        """
        if not self._connected:
            if not self.connect():
                return []
        
        devices = []
        
        try:
            # Check if this is a VMware discovery group
            if group and "VMware" in group:
                devices = self._get_vmware_hosts(group, device_type)
            else:
                devices = self._get_hosts_by_group(group, device_type)
            
            logger.info(f"Processed {len(devices)} devices of type {device_type.value}")
            
        except Exception as e:
            logger.error(f"Error retrieving devices from Zabbix: {e}")
        
        return devices
    
    def _get_vmware_hosts(self, discovery_name: str, device_type: DeviceType) -> List[Device]:
        """Get hosts discovered by VMware discovery"""
        devices = []
        
        try:
            # Определяем паттерны поиска по датацентру
            search_patterns = []
            if "Karaganda" in discovery_name:
                search_patterns = ["krg", "karaganda", "az01edge", "az01comp"]
            elif "Almaty" in discovery_name:
                search_patterns = ["alm", "almaty", "ala"]
            elif "Atyrau" in discovery_name:
                search_patterns = ["atr", "atyrau"]
            elif "Konaeva" in discovery_name:
                search_patterns = ["ast", "konaeva", "az01"]
            elif "Kabanbay" in discovery_name:
                search_patterns = ["kabanbay", "az02"]
            
            # Получаем все хосты с расширенной информацией
            params = {
                "output": "extend",
                "selectInventory": "extend",
                "selectInterfaces": "extend",
                "selectGroups": "extend",
                "selectTags": "extend",
                "selectMacros": "extend",
                "selectParentTemplates": ["templateid", "name"]
            }
            
            hosts = self.api.host.get(**params)
            logger.info(f"Retrieved {len(hosts)} total hosts from Zabbix")
            
            for host in hosts:
                # Проверяем, является ли это VMware хостом
                is_vmware = False
                host_name_lower = host.get("host", "").lower()
                
                # Проверка по шаблонам
                templates = host.get("parentTemplates", [])
                if templates:  # Проверяем что templates не пустой
                    for template in templates:
                        if isinstance(template, dict):  # Проверяем что это словарь
                            template_name = template.get("name", "").lower()
                            if "vmware" in template_name or "hypervisor" in template_name or "esxi" in template_name:
                                is_vmware = True
                                logger.debug(f"Host {host.get('host')} matched by template: {template.get('name')}")
                                break
                
                # Проверка по группам
                if not is_vmware:
                    groups = host.get("groups", [])
                    if groups:  # Проверяем что groups не пустой
                        for group in groups:
                            if isinstance(group, dict):  # Проверяем что это словарь
                                group_name = group.get("name", "").lower()
                                if "all-servers" in group_name or "hypervisor" in group_name:
                                    is_vmware = True
                                    logger.debug(f"Host {host.get('host')} matched by group: {group.get('name')}")
                                    break
                
                # Проверка по инвентарным данным
                if not is_vmware:
                    inventory = host.get("inventory", {})
                    if inventory and isinstance(inventory, dict):
                        os = inventory.get("os", "").lower()
                        software = inventory.get("software", "").lower()
                        hardware = inventory.get("hardware", "").lower()
                        
                        if "vmware" in os or "esxi" in os or "vmware" in software or "hypervisor" in hardware:
                            is_vmware = True
                            logger.debug(f"Host {host.get('host')} matched by inventory")
                
                # Проверка по паттернам имени для конкретного ДЦ
                location_match = False
                if search_patterns:
                    for pattern in search_patterns:
                        if pattern in host_name_lower:
                            location_match = True
                            break
                else:
                    # Если нет специфичных паттернов, берем все VMware хосты
                    location_match = True
                
                # Если это VMware хост и подходит по локации
                if is_vmware and location_match:
                    device = self._host_to_device(host, DeviceType.SERVER)
                    if device:
                        devices.append(device)
                        logger.debug(f"Added VMware host: {host.get('host')}")
            
            logger.info(f"Found {len(devices)} VMware hosts for {discovery_name}")
            
        except Exception as e:
            logger.error(f"Error getting VMware hosts: {e}", exc_info=True)
        
        return devices
    
    def _get_hosts_by_group(self, group_name: str, device_type: DeviceType) -> List[Device]:
        """Get hosts by group name (standard approach)"""
        devices = []
        
        try:
            # Build query parameters
            params = {
                "output": "extend",
                "selectInventory": "extend",
                "selectInterfaces": "extend",
                "selectGroups": "extend",
                "selectTags": "extend",
                "selectMacros": "extend",
                "selectParentTemplates": ["templateid", "name"]
            }
            
            # Filter by group if specified
            if group_name:
                groups = self.api.hostgroup.get(filter={"name": group_name})
                if groups:
                    params["groupids"] = groups[0]["groupid"]
                    logger.info(f"Filtering by group: {group_name}")
                else:
                    logger.warning(f"Group not found: {group_name}")
                    return []
            
            # Get hosts from Zabbix
            hosts = self.api.host.get(**params)
            logger.info(f"Retrieved {len(hosts)} hosts from group {group_name}")
            
            # Convert to Device objects
            for host in hosts:
                device = self._host_to_device(host, device_type)
                if device:
                    devices.append(device)
            
        except Exception as e:
            logger.error(f"Error retrieving devices by group: {e}")
        
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
                selectMacros="extend",
                selectParentTemplates="extend"
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
                "macros": host.get("macros", []),
                "templates": host.get("parentTemplates", [])
            }
            
            # Add metadata
            metadata = {
                "source": "zabbix",
                "retrieved_at": datetime.now().isoformat(),
                "group_names": [g.get("name", "") for g in host.get("groups", []) if isinstance(g, dict)],
                "template_names": [t.get("name", "") for t in host.get("parentTemplates", []) if isinstance(t, dict)]
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
        # Check templates first (most reliable for VMware)
        templates = host.get("parentTemplates", [])
        if templates and isinstance(templates, list):
            for template in templates:
                if isinstance(template, dict):
                    template_name = template.get("name", "").lower()
                    if "vmware" in template_name or "hypervisor" in template_name or "esxi" in template_name:
                        return DeviceType.SERVER
                    elif "network" in template_name or "switch" in template_name or "router" in template_name:
                        return DeviceType.NETWORK
                    elif "storage" in template_name or "datastore" in template_name:
                        return DeviceType.STORAGE
        
        # Check groups
        groups = host.get("groups", [])
        if groups and isinstance(groups, list):
            group_names = [g.get("name", "").lower() for g in groups if isinstance(g, dict)]
            
            for group_name in group_names:
                if "network" in group_name:
                    return DeviceType.NETWORK
                elif "server" in group_name or "vmware" in group_name or "hypervisor" in group_name:
                    return DeviceType.SERVER
                elif "storage" in group_name or "datastore" in group_name:
                    return DeviceType.STORAGE
        
        # Check inventory
        inventory = host.get("inventory", {})
        if inventory and isinstance(inventory, dict):
            hw_type = inventory.get("type", "").lower()
            os = inventory.get("os", "").lower()
            
            if "switch" in hw_type or "router" in hw_type:
                return DeviceType.NETWORK
            elif "server" in hw_type or "vmware" in os or "esxi" in os:
                return DeviceType.SERVER
        
        return DeviceType.UNKNOWN
    
    def get_hosts_by_group(self, group_name: str) -> List[Dict]:
        """Get all hosts in a specific group"""
        if not self._connected:
            if not self.connect():
                return []
        
        try:
            # Если это VMware discovery группа, используем другой подход
            if "VMware" in group_name:
                devices = self._get_vmware_hosts(group_name, DeviceType.SERVER)
                # Конвертируем обратно в формат хостов для совместимости
                hosts = []
                for device in devices:
                    hosts.append(device.data)
                return hosts
            
            # Стандартный подход для обычных групп
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
            
            # Добавим виртуальные группы для VMware discovery
            vmware_groups = [
                {"groupid": "vmware-krg", "name": "VMware hypervisor discovery: DC-Karaganda"},
                {"groupid": "vmware-alm", "name": "VMware hypervisor discovery: DC-Almaty"},
                {"groupid": "vmware-atr", "name": "VMware hypervisor discovery: DC-Atyrau"},
                {"groupid": "vmware-ast-konaeva", "name": "VMware hypervisor discovery: DC-Astana-Konaeva"},
                {"groupid": "vmware-ast-kabanbay", "name": "VMware hypervisor discovery: DC-Astana-Kabanbay"},
            ]
            
            groups.extend(vmware_groups)
            
            return groups
        except Exception as e:
            logger.error(f"Error getting groups: {e}")
            return []
    
    def get_all_vmware_hosts(self) -> List[Dict]:
        """Get all VMware/ESXi hosts from Zabbix"""
        if not self._connected:
            if not self.connect():
                return []
        
        try:
            # Получаем все хосты с шаблонами
            hosts = self.api.host.get(
                output="extend",
                selectInventory="extend",
                selectInterfaces="extend",
                selectGroups="extend",
                selectTags="extend",
                selectParentTemplates="extend"
            )
            
            vmware_hosts = []
            for host in hosts:
                is_vmware = False
                
                # Проверяем по шаблонам
                templates = host.get("parentTemplates", [])
                if templates and isinstance(templates, list):
                    for template in templates:
                        if isinstance(template, dict):
                            template_name = template.get("name", "").lower()
                            if "vmware" in template_name or "esxi" in template_name or "hypervisor" in template_name:
                                is_vmware = True
                                break
                
                # Проверяем по группам
                if not is_vmware:
                    groups = host.get("groups", [])
                    if groups and isinstance(groups, list):
                        for group in groups:
                            if isinstance(group, dict):
                                group_name = group.get("name", "").lower()
                                if "all-servers" in group_name or "hypervisor" in group_name:
                                    is_vmware = True
                                    break
                
                # Проверяем по OS в инвентаре
                if not is_vmware:
                    inventory = host.get("inventory", {})
                    if inventory and isinstance(inventory, dict):
                        os = inventory.get("os", "").lower()
                        if "vmware" in os or "esxi" in os:
                            is_vmware = True
                
                if is_vmware:
                    vmware_hosts.append(host)
            
            logger.info(f"Found {len(vmware_hosts)} VMware hosts total")
            return vmware_hosts
            
        except Exception as e:
            logger.error(f"Error getting VMware hosts: {e}", exc_info=True)
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