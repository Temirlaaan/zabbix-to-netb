"""
Main synchronizer implementation
"""

import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

from ..core.base import (
    Device, DeviceType, SyncResult, SyncStatus, 
    DataSource, DataTarget, DataProcessor, Cache, Synchronizer
)
from ..core.cache import RedisCache, MemoryCache
from ..sources.zabbix_source import ZabbixSource
from ..targets.netbox_target import NetBoxTarget
from ..processors.server_processor import ServerProcessor

logger = logging.getLogger(__name__)


class ZabbixNetBoxSynchronizer(Synchronizer):
    """Main synchronizer for Zabbix to NetBox"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize synchronizer
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.source = None
        self.target = None
        self.cache = None
        self.processors = {}
        
        self.stats = {
            'total': 0,
            'processed': 0,
            'created': 0,
            'updated': 0,
            'skipped': 0,
            'failed': 0,
            'errors': []
        }
        
        self.dry_run = config.get('sync', {}).get('dry_run', False)
        self.continue_on_error = config.get('sync', {}).get('continue_on_error', True)
        self.batch_size = config.get('sync', {}).get('batch_size', 50)
        self.max_workers = config.get('sync', {}).get('max_workers', 5)
        
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize all components"""
        # Initialize cache
        try:
            redis_config = self.config.get('redis', {})
            self.cache = RedisCache(
                host=redis_config.get('host', 'localhost'),
                port=redis_config.get('port', 6379),
                db=redis_config.get('db', 0),
                password=redis_config.get('password'),
                prefix=redis_config.get('key_prefix', 'zabbix_netbox_sync'),
                ttl_hours=redis_config.get('ttl_hours', 24)
            )
            logger.info("Using Redis cache")
        except Exception as e:
            logger.warning(f"Failed to initialize Redis cache: {e}")
            self.cache = MemoryCache()
            logger.info("Using in-memory cache")
        
        # Initialize source
        zabbix_config = self.config.get('zabbix', {})
        self.source = ZabbixSource(
            url=zabbix_config.get('url'),
            username=zabbix_config.get('username'),
            password=zabbix_config.get('password'),
            timeout=zabbix_config.get('timeout', 30),
            verify_ssl=zabbix_config.get('verify_ssl', False)
        )
        
        # Initialize target
        netbox_config = self.config.get('netbox', {})
        self.target = NetBoxTarget(
            url=netbox_config.get('url'),
            token=netbox_config.get('token'),
            verify_ssl=netbox_config.get('verify_ssl', False)
        )
        
        # Initialize processors
        self.processors = {
            DeviceType.SERVER: ServerProcessor(self.config),
            # Add other processors as needed
            # DeviceType.NETWORK: NetworkProcessor(self.config),
            # DeviceType.STORAGE: StorageProcessor(self.config),
        }
    
    def sync_device(self, device: Device) -> SyncResult:
        """Sync a single device"""
        try:
            # Get processor for device type
            processor = self.processors.get(device.device_type)
            if not processor:
                logger.warning(f"No processor for device type: {device.device_type}")
                return SyncResult(
                    device_name=device.name,
                    status=SyncStatus.SKIPPED,
                    message=f"No processor for type {device.device_type}"
                )
            
            # Process device
            processed_device = processor.process(device)
            
            # Validate device
            is_valid, errors = processor.validate(processed_device)
            if not is_valid:
                logger.error(f"Device {device.name} validation failed: {errors}")
                return SyncResult(
                    device_name=device.name,
                    status=SyncStatus.FAILED,
                    message=f"Validation failed: {', '.join(errors)}"
                )
            
            # Check cache for changes
            cached_hash = self.cache.get_device_hash(device.name)
            current_hash = device.__hash__()
            
            if cached_hash == current_hash:
                logger.debug(f"Device {device.name} unchanged, skipping")
                return SyncResult(
                    device_name=device.name,
                    status=SyncStatus.SKIPPED,
                    message="No changes detected"
                )
            
            # Perform sync operation
            if self.dry_run:
                logger.info(f"[DRY RUN] Would sync device: {device.name}")
                result = SyncResult(
                    device_name=device.name,
                    status=SyncStatus.SUCCESS,
                    message="Dry run - no changes made"
                )
            else:
                if self.target.device_exists(processed_device):
                    result = self.target.update_device(processed_device)
                else:
                    result = self.target.create_device(processed_device)
            
            # Update cache on success
            if result.status in [SyncStatus.SUCCESS, SyncStatus.CREATED, SyncStatus.UPDATED]:
                self.cache.set_device_hash(device.name, current_hash)
                self.cache.set_device(processed_device)
            
            return result
            
        except Exception as e:
            logger.error(f"Error syncing device {device.name}: {e}")
            return SyncResult(
                device_name=device.name,
                status=SyncStatus.FAILED,
                message=str(e),
                error=e
            )
    
    def sync_batch(self, devices: List[Device]) -> List[SyncResult]:
        """Sync a batch of devices"""
        results = []
        
        if self.max_workers > 1:
            # Parallel processing
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_device = {
                    executor.submit(self.sync_device, device): device 
                    for device in devices
                }
                
                for future in as_completed(future_to_device):
                    device = future_to_device[future]
                    try:
                        result = future.result()
                        results.append(result)
                        self._update_stats(result)
                    except Exception as e:
                        logger.error(f"Error processing device {device.name}: {e}")
                        if not self.continue_on_error:
                            raise
                        results.append(SyncResult(
                            device_name=device.name,
                            status=SyncStatus.FAILED,
                            message=str(e),
                            error=e
                        ))
                        self.stats['failed'] += 1
        else:
            # Sequential processing
            for device in devices:
                try:
                    result = self.sync_device(device)
                    results.append(result)
                    self._update_stats(result)
                except Exception as e:
                    logger.error(f"Error processing device {device.name}: {e}")
                    if not self.continue_on_error:
                        raise
                    results.append(SyncResult(
                        device_name=device.name,
                        status=SyncStatus.FAILED,
                        message=str(e),
                        error=e
                    ))
                    self.stats['failed'] += 1
        
        return results
    
    def sync_all(self) -> Dict[str, Any]:
        """Perform full synchronization"""
        start_time = datetime.now()
        logger.info("Starting full synchronization")
        
        # Connect to source and target
        if not self.source.connect():
            logger.error("Failed to connect to source")
            return self._build_summary(start_time, success=False)
        
        if not self.target.connect():
            logger.error("Failed to connect to target")
            return self._build_summary(start_time, success=False)
        
        try:
            # Get configured groups
            sources_config = self.config.get('sources', {}).get('zabbix_groups', {})
            all_devices = []
            
            # Process servers
            for group in sources_config.get('servers', []):
                logger.info(f"Processing server group: {group}")
                devices = self.source.get_devices(DeviceType.SERVER, group)
                all_devices.extend(devices)
            
            # Process network devices
            for group in sources_config.get('network', []):
                logger.info(f"Processing network group: {group}")
                devices = self.source.get_devices(DeviceType.NETWORK, group)
                all_devices.extend(devices)
            
            # Process storage devices
            for group in sources_config.get('storage', []):
                logger.info(f"Processing storage group: {group}")
                devices = self.source.get_devices(DeviceType.STORAGE, group)
                all_devices.extend(devices)
            
            self.stats['total'] = len(all_devices)
            logger.info(f"Found {self.stats['total']} devices to sync")
            
            # Process in batches
            all_results = []
            for i in range(0, len(all_devices), self.batch_size):
                batch = all_devices[i:i+self.batch_size]
                logger.info(f"Processing batch {i//self.batch_size + 1} "
                           f"({len(batch)} devices)")
                
                results = self.sync_batch(batch)
                all_results.extend(results)
            
            # Mark devices offline if not seen
            self._mark_offline_devices(all_devices)
            
            # Update last sync time
            self.cache.set_last_sync(datetime.now())
            
            # Save statistics
            self.cache.set_sync_stats(self.stats)
            
        finally:
            # Disconnect
            self.source.disconnect()
            self.target.disconnect()
        
        return self._build_summary(start_time, success=True)
    
    def sync_incremental(self, since: datetime) -> Dict[str, Any]:
        """Perform incremental synchronization"""
        start_time = datetime.now()
        logger.info(f"Starting incremental sync since {since}")
        
        # Connect to source and target
        if not self.source.connect():
            logger.error("Failed to connect to source")
            return self._build_summary(start_time, success=False)
        
        if not self.target.connect():
            logger.error("Failed to connect to target")
            return self._build_summary(start_time, success=False)
        
        try:
            # Get updated devices
            # Note: This depends on Zabbix capabilities
            # May need to track changes differently
            updated_hosts = self.source.get_host_updates_since(since)
            
            all_devices = []
            for host_data in updated_hosts:
                device_type = self.source._determine_device_type(host_data)
                device = self.source._host_to_device(host_data, device_type)
                if device:
                    all_devices.append(device)
            
            self.stats['total'] = len(all_devices)
            logger.info(f"Found {self.stats['total']} updated devices")
            
            # Process devices
            all_results = []
            for i in range(0, len(all_devices), self.batch_size):
                batch = all_devices[i:i+self.batch_size]
                results = self.sync_batch(batch)
                all_results.extend(results)
            
            # Update last sync time
            self.cache.set_last_sync(datetime.now())
            
            # Save statistics
            self.cache.set_sync_stats(self.stats)
            
        finally:
            # Disconnect
            self.source.disconnect()
            self.target.disconnect()
        
        return self._build_summary(start_time, success=True)
    
    def _update_stats(self, result: SyncResult):
        """Update statistics based on sync result"""
        self.stats['processed'] += 1
        
        if result.status == SyncStatus.CREATED:
            self.stats['created'] += 1
        elif result.status == SyncStatus.UPDATED:
            self.stats['updated'] += 1
        elif result.status == SyncStatus.SKIPPED:
            self.stats['skipped'] += 1
        elif result.status == SyncStatus.FAILED:
            self.stats['failed'] += 1
            self.stats['errors'].append({
                'device': result.device_name,
                'error': result.message,
                'timestamp': result.timestamp.isoformat()
            })
            # Add to failed devices cache
            self.cache.add_to_failed_devices(result.device_name, result.message)
    
    def _mark_offline_devices(self, current_devices: List[Device]):
        """Mark devices as offline if not seen in current sync"""
        try:
            # Get all device names from current sync
            current_names = {d.name for d in current_devices}
            
            # Get all cached device keys
            cached_keys = self.cache.get_all_keys("device:*")
            
            # Find devices not in current sync
            mark_offline_days = self.config.get('sync', {}).get('mark_offline_days', 7)
            cutoff_date = datetime.now() - timedelta(days=mark_offline_days)
            
            for key in cached_keys:
                device_name = key.replace("device:", "")
                if device_name not in current_names:
                    # Check last seen
                    cached_device = self.cache.get_device(device_name)
                    if cached_device:
                        device_timestamp = datetime.fromisoformat(
                            cached_device.metadata.get('retrieved_at', 
                                                      datetime.now().isoformat())
                        )
                        if device_timestamp < cutoff_date:
                            logger.info(f"Marking device {device_name} as offline")
                            self.target.mark_device_offline(device_name, device_timestamp)
                    
        except Exception as e:
            logger.error(f"Error marking offline devices: {e}")
    
    def _build_summary(self, start_time: datetime, success: bool) -> Dict[str, Any]:
        """Build sync summary"""
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        summary = {
            'success': success,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_seconds': duration,
            'dry_run': self.dry_run,
            'statistics': self.stats,
            'configuration': {
                'batch_size': self.batch_size,
                'max_workers': self.max_workers,
                'continue_on_error': self.continue_on_error
            }
        }
        
        return summary