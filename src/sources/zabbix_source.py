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