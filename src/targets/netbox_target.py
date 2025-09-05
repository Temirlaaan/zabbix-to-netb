"""
NetBox target implementation
"""

import logging
from typing import Any, Dict, List, Optional
from datetime import datetime
import pynetbox
from pynetbox.core.response import Record

from ..core.base import DataTarget, Device, SyncResult, SyncStatus, DeviceType

logger = logging.getLogger(__name__)


class NetBoxTarget(DataTarget):
    """NetBox API target"""
    
    def __init__(self, url: str, token: str, verify_ssl: bool = False):
        """
        Initialize NetBox target
        
        Args:
            url: NetBox API URL
            token: NetBox API token
            verify_ssl: Verify SSL certificates
        """
        self.url = url
        self.token = token
        self.verify_ssl = verify_ssl
        self.nb = None
        self._connected = False
        
        # Cache for frequently used objects
        self._cache = {
            'sites': {},
            'locations': {},
            'roles': {},
            'manufacturers': {},
            'device_types': {},
            'platforms': {}
        }
    
    def connect(self) -> bool:
        """Establish connection to NetBox"""
        try:
            self.nb = pynetbox.api(self.url, token=self.token)
            self.nb.http_session.verify = self.verify_ssl
            
            # Test connection
            self.nb.status()
            self._connected = True
            logger.info(f"Connected to NetBox at {self.url}")
            
            # Preload common data
            self._preload_cache()
            
            return True
        except Exception as e:
            logger.error(f"Failed to connect to NetBox: {e}")
            self._connected = False
            return False
    
    def disconnect(self) -> None:
        """Close connection to NetBox"""
        self._connected = False
        self.nb = None
        self._cache.clear()
        logger.info("Disconnected from NetBox")
    
    def _preload_cache(self):
        """Preload frequently used objects"""
        try:
            # Load sites
            for site in self.nb.dcim.sites.all():
                self._cache['sites'][site.name] = site
            
            # Load device roles
            for role in self.nb.dcim.device_roles.all():
                self._cache['roles'][role.name] = role
            
            # Load manufacturers
            for mfg in self.nb.dcim.manufacturers.all():
                self._cache['manufacturers'][mfg.name] = mfg
            
            logger.debug(f"Cached {len(self._cache['sites'])} sites, "
                        f"{len(self._cache['roles'])} roles, "
                        f"{len(self._cache['manufacturers'])} manufacturers")
        except Exception as e:
            logger.warning(f"Error preloading cache: {e}")
    
    def device_exists(self, device: Device) -> bool:
        """Check if device exists in NetBox"""
        if not self._connected:
            return False
        
        try:
            devices = self.nb.dcim.devices.filter(name=device.name)
            return len(list(devices)) > 0
        except Exception as e:
            logger.error(f"Error checking device existence: {e}")
            return False
    
    def create_device(self, device: Device) -> SyncResult:
        """Create a new device in NetBox"""
        if not self._connected:
            return SyncResult(
                device_name=device.name,
                status=SyncStatus.FAILED,
                message="Not connected to NetBox"
            )
        
        try:
            # Prepare device data
            netbox_data = self._prepare_device_data(device)
            
            # Create device
            nb_device = self.nb.dcim.devices.create(**netbox_data)
            
            # Add custom fields
            if device.data.get('custom_fields'):
                self._update_custom_fields(nb_device, device.data['custom_fields'])
            
            logger.info(f"Created device: {device.name}")
            
            return SyncResult(
                device_name=device.name,
                status=SyncStatus.CREATED,
                message="Device created successfully",
                new_data=netbox_data
            )
            
        except Exception as e:
            logger.error(f"Error creating device {device.name}: {e}")
            return SyncResult(
                device_name=device.name,
                status=SyncStatus.FAILED,
                message=str(e),
                error=e
            )
    
    def update_device(self, device: Device) -> SyncResult:
        """Update existing device in NetBox"""
        if not self._connected:
            return SyncResult(
                device_name=device.name,
                status=SyncStatus.FAILED,
                message="Not connected to NetBox"
            )
        
        try:
            # Get existing device
            nb_devices = list(self.nb.dcim.devices.filter(name=device.name))
            if not nb_devices:
                return self.create_device(device)
            
            nb_device = nb_devices[0]
            old_data = dict(nb_device)
            
            # Prepare updated data
            netbox_data = self._prepare_device_data(device)
            
            # Check if update is needed
            needs_update = False
            for key, value in netbox_data.items():
                if hasattr(nb_device, key):
                    current_value = getattr(nb_device, key)
                    if isinstance(current_value, Record):
                        current_value = current_value.id
                    if current_value != value:
                        needs_update = True
                        break
            
            if not needs_update:
                return SyncResult(
                    device_name=device.name,
                    status=SyncStatus.SKIPPED,
                    message="No changes needed"
                )
            
            # Update device
            for key, value in netbox_data.items():
                setattr(nb_device, key, value)
            nb_device.save()
            
            # Update custom fields
            if device.data.get('custom_fields'):
                self._update_custom_fields(nb_device, device.data['custom_fields'])
            
            logger.info(f"Updated device: {device.name}")
            
            return SyncResult(
                device_name=device.name,
                status=SyncStatus.UPDATED,
                message="Device updated successfully",
                old_data=old_data,
                new_data=netbox_data
            )
            
        except Exception as e:
            logger.error(f"Error updating device {device.name}: {e}")
            return SyncResult(
                device_name=device.name,
                status=SyncStatus.FAILED,
                message=str(e),
                error=e
            )
    
    def delete_device(self, device: Device) -> SyncResult:
        """Delete device from NetBox"""
        if not self._connected:
            return SyncResult(
                device_name=device.name,
                status=SyncStatus.FAILED,
                message="Not connected to NetBox"
            )
        
        try:
            nb_devices = list(self.nb.dcim.devices.filter(name=device.name))
            if not nb_devices:
                return SyncResult(
                    device_name=device.name,
                    status=SyncStatus.SKIPPED,
                    message="Device not found"
                )
            
            nb_device = nb_devices[0]
            nb_device.delete()
            
            logger.info(f"Deleted device: {device.name}")
            
            return SyncResult(
                device_name=device.name,
                status=SyncStatus.SUCCESS,
                message="Device deleted successfully"
            )
            
        except Exception as e:
            logger.error(f"Error deleting device {device.name}: {e}")
            return SyncResult(
                device_name=device.name,
                status=SyncStatus.FAILED,
                message=str(e),
                error=e
            )
    
    def get_device(self, name: str) -> Optional[Dict]:
        """Get device data from NetBox"""
        if not self._connected:
            return None
        
        try:
            devices = list(self.nb.dcim.devices.filter(name=name))
            if devices:
                return dict(devices[0])
            return None
        except Exception as e:
            logger.error(f"Error getting device {name}: {e}")
            return None
    
    def mark_device_offline(self, device_name: str, 
                           last_seen: datetime) -> bool:
        """Mark device as offline with last seen timestamp"""
        if not self._connected:
            return False
        
        try:
            nb_devices = list(self.nb.dcim.devices.filter(name=device_name))
            if not nb_devices:
                return False
            
            nb_device = nb_devices[0]
            nb_device.status = 'offline'
            
            # Update custom field if configured
            if hasattr(nb_device, 'custom_fields'):
                nb_device.custom_fields['last_seen_in_zabbix'] = last_seen.isoformat()
            
            nb_device.save()
            logger.info(f"Marked device {device_name} as offline")
            return True
            
        except Exception as e:
            logger.error(f"Error marking device offline: {e}")
            return False
    
    def _prepare_device_data(self, device: Device) -> Dict[str, Any]:
        """Prepare device data for NetBox"""
        data = device.data
        
        # Get or create required objects
        site = self._get_or_create_site(data.get('site', 'Unknown'))
        role = self._get_or_create_role(data.get('device_role'), device.device_type)
        device_type = self._get_or_create_device_type(
            data.get('device_type', 'Unknown'),
            data.get('manufacturer', 'Unknown')
        )
        
        # Build NetBox device data
        netbox_data = {
            'name': device.name,
            'device_type': device_type.id,
            'device_role': role.id,
            'site': site.id,
            'status': self._map_status(data.get('status', '1'))
        }
        
        # Add optional fields
        if data.get('serial_number'):
            netbox_data['serial'] = data['serial_number']
        
        if data.get('asset_tag'):
            netbox_data['asset_tag'] = data['asset_tag']
        
        if data.get('location'):
            location = self._get_or_create_location(data['location'], site.id)
            if location:
                netbox_data['location'] = location.id
        
        if data.get('platform'):
            platform = self._get_or_create_platform(data['platform'])
            if platform:
                netbox_data['platform'] = platform.id
        
        if data.get('comments'):
            netbox_data['comments'] = data['comments']
        
        return netbox_data
    
    def _map_status(self, zabbix_status: str) -> str:
        """Map Zabbix status to NetBox status"""
        status_map = {
            '0': 'active',
            '1': 'offline',
            'active': 'active',
            'offline': 'offline'
        }
        return status_map.get(str(zabbix_status), 'offline')
    
    def _get_or_create_site(self, site_name: str) -> Any:
        """Get or create site in NetBox"""
        if site_name in self._cache['sites']:
            return self._cache['sites'][site_name]
        
        try:
            sites = list(self.nb.dcim.sites.filter(name=site_name))
            if sites:
                site = sites[0]
            else:
                slug = self._create_slug(site_name)
                site = self.nb.dcim.sites.create(
                    name=site_name,
                    slug=slug,
                    status='active'
                )
                logger.info(f"Created site: {site_name}")
            
            self._cache['sites'][site_name] = site
            return site
            
        except Exception as e:
            logger.error(f"Error creating site {site_name}: {e}")
            # Return default site
            return self._get_or_create_site("Unknown")
    
    def _get_or_create_location(self, location_name: str, site_id: int) -> Optional[Any]:
        """Get or create location in NetBox"""
        cache_key = f"{site_id}:{location_name}"
        if cache_key in self._cache['locations']:
            return self._cache['locations'][cache_key]
        
        try:
            locations = list(self.nb.dcim.locations.filter(
                name=location_name,
                site_id=site_id
            ))
            
            if locations:
                location = locations[0]
            else:
                slug = self._create_slug(location_name)
                location = self.nb.dcim.locations.create(
                    name=location_name,
                    slug=slug,
                    site=site_id,
                    status='active'
                )
                logger.info(f"Created location: {location_name}")
            
            self._cache['locations'][cache_key] = location
            return location
            
        except Exception as e:
            logger.error(f"Error creating location {location_name}: {e}")
            return None
    
    def _get_or_create_role(self, role_name: str, device_type: DeviceType) -> Any:
        """Get or create device role in NetBox"""
        if not role_name:
            # Default role based on device type
            role_name = {
                DeviceType.NETWORK: "network-device",
                DeviceType.SERVER: "server",
                DeviceType.STORAGE: "storage-device"
            }.get(device_type, "unknown")
        
        if role_name in self._cache['roles']:
            return self._cache['roles'][role_name]
        
        try:
            roles = list(self.nb.dcim.device_roles.filter(name=role_name))
            if roles:
                role = roles[0]
            else:
                slug = self._create_slug(role_name)
                color = {
                    'network': '0066cc',
                    'server': '00cc00',
                    'storage': 'cc6600'
                }.get(device_type.value, '666666')
                
                role = self.nb.dcim.device_roles.create(
                    name=role_name,
                    slug=slug,
                    color=color
                )
                logger.info(f"Created role: {role_name}")
            
            self._cache['roles'][role_name] = role
            return role
            
        except Exception as e:
            logger.error(f"Error creating role {role_name}: {e}")
            return self._get_or_create_role("unknown", DeviceType.UNKNOWN)
    
    def _get_or_create_manufacturer(self, manufacturer_name: str) -> Any:
        """Get or create manufacturer in NetBox"""
        if manufacturer_name in self._cache['manufacturers']:
            return self._cache['manufacturers'][manufacturer_name]
        
        try:
            manufacturers = list(self.nb.dcim.manufacturers.filter(name=manufacturer_name))
            if manufacturers:
                manufacturer = manufacturers[0]
            else:
                slug = self._create_slug(manufacturer_name)
                manufacturer = self.nb.dcim.manufacturers.create(
                    name=manufacturer_name,
                    slug=slug
                )
                logger.info(f"Created manufacturer: {manufacturer_name}")
            
            self._cache['manufacturers'][manufacturer_name] = manufacturer
            return manufacturer
            
        except Exception as e:
            logger.error(f"Error creating manufacturer {manufacturer_name}: {e}")
            return self._get_or_create_manufacturer("Unknown")
    
    def _get_or_create_device_type(self, model: str, manufacturer_name: str) -> Any:
        """Get or create device type in NetBox"""
        cache_key = f"{manufacturer_name}:{model}"
        if cache_key in self._cache['device_types']:
            return self._cache['device_types'][cache_key]
        
        manufacturer = self._get_or_create_manufacturer(manufacturer_name)
        
        try:
            device_types = list(self.nb.dcim.device_types.filter(
                model=model,
                manufacturer_id=manufacturer.id
            ))
            
            if device_types:
                device_type = device_types[0]
            else:
                slug = self._create_slug(f"{manufacturer_name}-{model}")
                device_type = self.nb.dcim.device_types.create(
                    manufacturer=manufacturer.id,
                    model=model,
                    slug=slug
                )
                logger.info(f"Created device type: {model}")
            
            self._cache['device_types'][cache_key] = device_type
            return device_type
            
        except Exception as e:
            logger.error(f"Error creating device type {model}: {e}")
            return self._get_or_create_device_type("Unknown", "Unknown")
    
    def _get_or_create_platform(self, platform_name: str) -> Optional[Any]:
        """Get or create platform in NetBox"""
        if not platform_name or platform_name == "Unknown":
            return None
        
        if platform_name in self._cache['platforms']:
            return self._cache['platforms'][platform_name]
        
        try:
            platforms = list(self.nb.dcim.platforms.filter(name=platform_name))
            if platforms:
                platform = platforms[0]
            else:
                slug = self._create_slug(platform_name)
                platform = self.nb.dcim.platforms.create(
                    name=platform_name,
                    slug=slug
                )
                logger.info(f"Created platform: {platform_name}")
            
            self._cache['platforms'][platform_name] = platform
            return platform
            
        except Exception as e:
            logger.error(f"Error creating platform {platform_name}: {e}")
            return None
    
    def _create_slug(self, text: str) -> str:
        """Create a valid slug from text"""
        import re
        slug = text.lower()
        slug = re.sub(r'[^a-z0-9-]', '-', slug)
        slug = re.sub(r'-+', '-', slug)
        slug = slug.strip('-')
        return slug[:50]  # Max length 50
    
    def _update_custom_fields(self, nb_device: Any, custom_fields: Dict) -> None:
        """Update custom fields on a device"""
        try:
            for field, value in custom_fields.items():
                if hasattr(nb_device, 'custom_fields'):
                    nb_device.custom_fields[field] = value
            nb_device.save()
        except Exception as e:
            logger.warning(f"Error updating custom fields: {e}")