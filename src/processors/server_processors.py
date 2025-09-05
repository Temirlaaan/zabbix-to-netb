logger.error(f"Error processing server device {device.name}: {e}")
        
        return device
    
    def validate(self, device: Device) -> Tuple[bool, List[str]]:
        """Validate server device data"""
        errors = []
        data = device.data
        
        # Required fields
        if not data.get('name'):
            errors.append("Device name is required")
        
        if not data.get('site'):
            errors.append("Site is required")
        
        if not data.get('device_role'):
            errors.append("Device role is required")
        
        # Validate IP if present
        if data.get('primary_ip'):
            if not self._is_valid_ip(data['primary_ip']):
                errors.append(f"Invalid IP address: {data['primary_ip']}")
        
        is_valid = len(errors) == 0
        return is_valid, errors
    
    def map_fields(self, device: Device, mapping: Dict) -> Dict:
        """Map fields according to configuration"""
        mapped_data = {}
        
        for target_field, source_config in mapping.items():
            if isinstance(source_config, str):
                # Simple mapping
                value = self._get_nested_value(device.data, source_config)
            elif isinstance(source_config, dict):
                # Complex mapping with transformations
                source = source_config.get('source')
                transform = source_config.get('transform')
                default = source_config.get('default')
                
                if source == '_computed':
                    # Compute value
                    compute_func = source_config.get('compute')
                    value = self._compute_value(device, compute_func)
                elif source == '_static':
                    # Static value
                    value = source_config.get('value')
                else:
                    # Get value from source
                    value = self._get_nested_value(device.data, source)
                
                # Apply transformation
                if transform and value is not None:
                    value = self._apply_transform(value, transform)
                
                # Apply default if needed
                if value is None and default is not None:
                    value = default
            else:
                value = None
            
            if value is not None:
                mapped_data[target_field] = value
        
        return mapped_data
    
    def _extract_manufacturer(self, inventory: Dict) -> str:
        """Extract manufacturer from inventory"""
        vendor = inventory.get('vendor', '')
        if vendor:
            # Clean up vendor name
            vendor = vendor.strip()
            # Map common variations
            vendor_map = {
                'dell': 'Dell Technologies',
                'hp': 'Hewlett Packard Enterprise',
                'hpe': 'Hewlett Packard Enterprise',
                'lenovo': 'Lenovo',
                'cisco': 'Cisco Systems',
                'vmware': 'VMware'
            }
            vendor_lower = vendor.lower()
            for key, value in vendor_map.items():
                if key in vendor_lower:
                    return value
            return vendor
        return 'Unknown'
    
    def _extract_device_type(self, inventory: Dict) -> str:
        """Extract device type from inventory"""
        hardware = inventory.get('hardware', '')
        if hardware:
            # Clean up hardware description
            hardware = hardware.strip()
            # Try to extract model
            if 'PowerEdge' in hardware:
                # Dell server
                match = re.search(r'PowerEdge\s+(\S+)', hardware)
                if match:
                    return f"PowerEdge {match.group(1)}"
            elif 'ProLiant' in hardware:
                # HP server
                match = re.search(r'ProLiant\s+(\S+)', hardware)
                if match:
                    return f"ProLiant {match.group(1)}"
            elif 'ThinkSystem' in hardware:
                # Lenovo server
                match = re.search(r'ThinkSystem\s+(\S+)', hardware)
                if match:
                    return f"ThinkSystem {match.group(1)}"
            return hardware
        return 'Generic Server'
    
    def _extract_platform(self, inventory: Dict) -> str:
        """Extract platform/OS from inventory"""
        os_full = inventory.get('os', '')
        os_short = inventory.get('os_short', '')
        
        if os_short:
            return os_short
        elif os_full:
            # Extract first part of OS name
            parts = os_full.split()
            if parts:
                return parts[0]
        return 'Unknown'
    
    def _determine_role(self, data: Dict) -> str:
        """Determine server role based on name and tags"""
        host_name = data.get('host', '').lower()
        tags = data.get('tags', [])
        
        # Check tags first
        for tag in tags:
            tag_name = tag.get('tag', '').lower()
            tag_value = tag.get('value', '').lower()
            
            # Check if tag defines role
            if tag_name in ['role', 'device_role', 'type']:
                return tag_value
            
            # Check tag name for role patterns
            for pattern, role in self.role_mapping.get('patterns', {}).items():
                if pattern in tag_name:
                    return role
        
        # Check hostname patterns
        for pattern, role in self.role_mapping.get('patterns', {}).items():
            if pattern in host_name:
                return role
        
        # Check for VMware specific patterns
        if 'edge' in host_name:
            return 'Edge-Server'
        elif 'comp' in host_name:
            return 'Compute-Server'
        elif 'mgmt' in host_name or 'management' in host_name:
            return 'MGMT-Server'
        elif 'backup' in host_name:
            return 'Backup-Server'
        
        # Default role for servers
        return self.role_mapping.get('default', 'VMware-Hypervisor')
    
    def _determine_site(self, data: Dict) -> str:
        """Determine site from various sources"""
        host_name = data.get('host', '').lower()
        groups = data.get('groups', [])
        tags = data.get('tags', [])
        
        # Check tags for site
        for tag in tags:
            tag_name = tag.get('tag', '').lower()
            tag_value = tag.get('value', '').lower()
            
            if tag_name in ['site', 'location', 'datacenter', 'dc']:
                # Map tag value to site
                for prefix, site in self.location_mapping.get('prefixes', {}).items():
                    if prefix in tag_value:
                        return site
        
        # Check group names
        for group in groups:
            group_name = group.get('name', '').lower()
            for prefix, site in self.location_mapping.get('prefixes', {}).items():
                if prefix in group_name:
                    return site
        
        # Check hostname for location patterns
        location_patterns = [
            (r'-krg-|-karagand', 'DC Karaganda'),
            (r'-atr-|-atyrau', 'DC Atyrau'),
            (r'-ast-|-astana', 'DC Astana'),
            (r'-konaeva', 'DC Konaeva10'),
            (r'-kabanbay', 'DC Kabanbay-Batyr28'),
            (r'-alm-|-ala-|-almaty', 'DC Almaty'),
        ]
        
        for pattern, site in location_patterns:
            if re.search(pattern, host_name):
                return site
        
        # Special handling for az01/az02 patterns
        if host_name.startswith('az01'):
            return 'DC Konaeva10'  # Assuming az01 is Konaeva
        elif host_name.startswith('az02'):
            return 'DC Kabanbay-Batyr28'  # Assuming az02 is Kabanbay
        
        # Default site
        return self.location_mapping.get('default', 'DC Almaty')
    
    def _determine_location(self, data: Dict) -> str:
        """Determine physical location within site"""
        site = self._determine_site(data)
        
        # Map site to physical location
        physical_locations = {
            'DC Atyrau': 'city Atyrau street XXX',
            'DC Almaty': 'city Almaty street Karasay Batyr 55',
            'DC Kabanbay-Batyr28': 'city Astana street Kabanbay batyr 28',
            'DC Konaeva10': 'city Astana street Konaeva 10',
            'DC Karaganda': 'city Karaganda street 132-й учетный квартал',
        }
        
        return physical_locations.get(site, site)
    
    def _extract_primary_ip(self, data: Dict) -> str:
        """Extract primary IP from interfaces"""
        interfaces = data.get('interfaces', [])
        
        # Look for agent interface
        for interface in interfaces:
            if interface.get('type') == '1':  # Agent interface
                ip = interface.get('ip', '')
                if ip and ip != '0.0.0.0':
                    return ip
        
        # Look for any interface with IP
        for interface in interfaces:
            ip = interface.get('ip', '')
            if ip and ip != '0.0.0.0':
                return ip
        
        return ''
    
    def _build_comments(self, inventory: Dict) -> str:
        """Build comments from inventory data"""
        comments_parts = []
        
        # Add alias if present
        if inventory.get('alias'):
            comments_parts.append(f"Alias: {inventory['alias']}")
        
        # Add OS info
        if inventory.get('os_short'):
            comments_parts.append(f"OS: {inventory['os_short']}")
        elif inventory.get('os'):
            comments_parts.append(f"OS: {inventory['os']}")
        
        # Add software info
        if inventory.get('software_app_a'):
            comments_parts.append(f"Software: {inventory['software_app_a']}")
        
        return ' | '.join(comments_parts)
    
    def _build_custom_fields(self, data: Dict) -> Dict:
        """Build custom fields for NetBox"""
        custom_fields = {
            'zabbix_hostid': data.get('hostid', ''),
            'last_seen_in_zabbix': datetime.now().isoformat(),
            'sync_source': 'zabbix',
            'hypervisor_type': 'VMware ESXi'
        }
        
        # Extract cluster name from group
        groups = data.get('groups', [])
        for group in groups:
            group_name = group.get('name', '')
            if 'VMware hypervisor discovery' in group_name:
                cluster_name = group_name.replace('VMware hypervisor discovery: ', '')
                custom_fields['cluster_name'] = cluster_name
                break
        
        return custom_fields
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address"""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _get_nested_value(self, data: Dict, path: str) -> Any:
        """Get value from nested dictionary using dot notation"""
        keys = path.split('.')
        value = data
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        return value
    
    def _compute_value(self, device: Device, compute_func: str) -> Any:
        """Compute value using specified function"""
        # Implement compute functions as needed
        compute_functions = {
            'location_from_context': lambda: self._determine_site(device.data),
            'role_from_context': lambda: self._determine_role(device.data),
        }
        
        func = compute_functions.get(compute_func)
        if func:
            return func()
        return None
    
    def _apply_transform(self, value: Any, transform: str) -> Any:
        """Apply transformation to value"""
        # Implement transformations
        if transform == 'uppercase':
            return str(value).upper()
        elif transform == 'lowercase':
            return str(value).lower()
        elif transform == 'strip_domain':
            return str(value).split('.')[0]
        
        return value"""
Server device processor
"""

import logging
import re
from typing import Any, Dict, List, Tuple
from datetime import datetime

from ..core.base import DataProcessor, Device, DeviceType

logger = logging.getLogger(__name__)


class ServerProcessor(DataProcessor):
    """Processor for server devices"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize server processor
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.location_mapping = config.get('location_mapping', {})
        self.role_mapping = config.get('role_mapping', {}).get('servers', {})
        self.field_mapping = config.get('mapping', {}).get('servers', {})
    
    def process(self, device: Device) -> Device:
        """Process and transform server device data"""
        try:
            # Extract raw data
            raw_data = device.data
            inventory = raw_data.get('inventory', {})
            
            # Process basic fields
            processed_data = {
                'name': raw_data.get('host', ''),
                'status': raw_data.get('status', '1'),
                'manufacturer': self._extract_manufacturer(inventory),
                'device_type': self._extract_device_type(inventory),
                'serial_number': inventory.get('serialno_a', ''),
                'platform': self._extract_platform(inventory),
                'device_role': self._determine_role(raw_data),
                'site': self._determine_site(raw_data),
                'location': self._determine_location(raw_data),
                'primary_ip': self._extract_primary_ip(raw_data),
                'comments': self._build_comments(inventory),
                'custom_fields': self._build_custom_fields(raw_data)
            }
            
            # Update device with processed data
            device.data = processed_data
            device.metadata['processed_at'] = datetime.now().isoformat()
            
            logger.debug(f"Processed server device: {device.name}")
            
        except Exception as e:
            logger.error(f