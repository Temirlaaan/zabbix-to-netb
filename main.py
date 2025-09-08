#!/usr/bin/env python3
"""
Zabbix to NetBox Synchronization Tool
Main CLI entry point
"""

import os
import sys
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
import click
from tabulate import tabulate
from dotenv import load_dotenv

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.sync.synchronizer import ZabbixNetBoxSynchronizer
from src.core.cache import RedisCache

# Load environment variables
load_dotenv()

# Setup logging
def setup_logging(level: str = 'INFO', log_file: str = None):
    """Setup logging configuration"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    handlers = [logging.StreamHandler()]
    
    if log_file:
        # Create logs directory if needed
        log_dir = Path(log_file).parent
        log_dir.mkdir(exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format=log_format,
        handlers=handlers
    )


def load_config(config_file: str) -> dict:
    """Load configuration from file"""
    config_path = Path(config_file)
    
    if not config_path.exists():
        click.echo(f"Error: Configuration file not found: {config_file}", err=True)
        sys.exit(1)
    
    with open(config_path) as f:
        config = json.load(f)
    
    # Replace environment variables
    def replace_env_vars(obj):
        if isinstance(obj, dict):
            return {k: replace_env_vars(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [replace_env_vars(v) for v in obj]
        elif isinstance(obj, str):
            # Replace ${VAR} or ${VAR:default}
            import re
            pattern = r'\$\{([^}:]+)(?::([^}]+))?\}'
            
            def replacer(match):
                var_name = match.group(1)
                default_value = match.group(2)
                return os.getenv(var_name, default_value or '')
            
            return re.sub(pattern, replacer, obj)
        return obj
    
    config = replace_env_vars(config)
    return config


@click.group()
@click.option('--config', '-c', default='config/config.json', 
              help='Configuration file path')
@click.option('--log-level', '-l', default='INFO',
              type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']),
              help='Logging level')
@click.option('--log-file', '-f', help='Log file path')
@click.pass_context
def cli(ctx, config, log_level, log_file):
    """Zabbix to NetBox Synchronization Tool"""
    # Setup logging
    if log_file:
        log_file = log_file.replace('{date}', datetime.now().strftime('%Y%m%d'))
    setup_logging(log_level, log_file)
    
    # Load configuration
    ctx.ensure_object(dict)
    ctx.obj['config'] = load_config(config)
    ctx.obj['config_file'] = config


@cli.command()
@click.option('--dry-run', is_flag=True, help='Perform a dry run without making changes')
@click.option('--group', '-g', multiple=True, help='Specific group(s) to sync')
@click.option('--device-type', '-t', 
              type=click.Choice(['network', 'server', 'storage', 'all']),
              default='all', help='Type of devices to sync')
@click.option('--batch-size', '-b', type=int, help='Override batch size')
@click.option('--workers', '-w', type=int, help='Number of parallel workers')
@click.pass_context
def sync(ctx, dry_run, group, device_type, batch_size, workers):
    """Perform full synchronization"""
    config = ctx.obj['config'].copy()
    
    # Override configuration with CLI options
    if dry_run:
        config['sync']['dry_run'] = True
    
    if batch_size:
        config['sync']['batch_size'] = batch_size
    
    if workers:
        config['sync']['max_workers'] = workers
    
    # Filter groups if specified
    if group:
        sources = config.get('sources', {}).get('zabbix_groups', {})
        if device_type in ['network', 'all']:
            sources['network'] = [g for g in sources.get('network', []) if g in group]
        if device_type in ['server', 'all']:
            sources['servers'] = [g for g in sources.get('servers', []) if g in group]
        if device_type in ['storage', 'all']:
            sources['storage'] = [g for g in sources.get('storage', []) if g in group]
    
    # Initialize synchronizer
    click.echo("Initializing synchronizer...")
    synchronizer = ZabbixNetBoxSynchronizer(config)
    
    # Perform sync
    click.echo(f"Starting {'dry run' if dry_run else 'synchronization'}...")
    result = synchronizer.sync_all()
    
    # Display results
    if result['success']:
        click.echo(click.style("\n✓ Synchronization completed successfully!", fg='green'))
    else:
        click.echo(click.style("\n✗ Synchronization failed!", fg='red'))
    
    # Display statistics
    stats = result['statistics']
    click.echo("\nStatistics:")
    stats_table = [
        ['Total Devices', stats['total']],
        ['Processed', stats['processed']],
        ['Created', stats['created']],
        ['Updated', stats['updated']],
        ['Skipped', stats['skipped']],
        ['Failed', stats['failed']]
    ]
    click.echo(tabulate(stats_table, headers=['Metric', 'Count'], tablefmt='grid'))
    
    # Display errors if any
    if stats['errors']:
        click.echo(click.style("\nErrors encountered:", fg='red'))
        for error in stats['errors'][:10]:  # Show first 10 errors
            click.echo(f"  • {error['device']}: {error['error']}")
        if len(stats['errors']) > 10:
            click.echo(f"  ... and {len(stats['errors']) - 10} more errors")
    
    # Display summary
    click.echo(f"\nDuration: {result['duration_seconds']:.2f} seconds")
    
    if dry_run:
        click.echo(click.style("\nThis was a dry run - no changes were made.", fg='yellow'))


@cli.command()
@click.option('--since', '-s', help='Sync changes since (ISO datetime or "1h", "1d", etc.)')
@click.option('--dry-run', is_flag=True, help='Perform a dry run without making changes')
@click.pass_context
def update(ctx, since, dry_run):
    """Perform incremental synchronization"""
    config = ctx.obj['config'].copy()
    
    if dry_run:
        config['sync']['dry_run'] = True
    
    # Parse since parameter
    if since:
        # Parse relative time
        if since.endswith('h'):
            hours = int(since[:-1])
            since_dt = datetime.now() - timedelta(hours=hours)
        elif since.endswith('d'):
            days = int(since[:-1])
            since_dt = datetime.now() - timedelta(days=days)
        else:
            since_dt = datetime.fromisoformat(since)
    else:
        # Get last sync time from cache
        try:
            cache_config = config.get('redis', {})
            cache = RedisCache(
                host=cache_config.get('host', 'localhost'),
                port=cache_config.get('port', 6379),
                db=cache_config.get('db', 0),
                password=cache_config.get('password'),
                prefix=cache_config.get('key_prefix', 'zabbix_netbox_sync')
            )
            since_dt = cache.get_last_sync()
            if not since_dt:
                click.echo("No previous sync found, performing full sync")
                ctx.invoke(sync, dry_run=dry_run)
                return
        except Exception as e:
            click.echo(f"Error getting last sync time: {e}", err=True)
            return
    
    click.echo(f"Syncing changes since {since_dt}")
    
    # Initialize synchronizer
    synchronizer = ZabbixNetBoxSynchronizer(config)
    
    # Perform incremental sync
    result = synchronizer.sync_incremental(since_dt)
    
    # Display results (similar to full sync)
    if result['success']:
        click.echo(click.style("\n✓ Incremental sync completed!", fg='green'))
    else:
        click.echo(click.style("\n✗ Incremental sync failed!", fg='red'))
    
    stats = result['statistics']
    click.echo(f"\nProcessed {stats['processed']} devices")
    click.echo(f"Created: {stats['created']}, Updated: {stats['updated']}, "
              f"Skipped: {stats['skipped']}, Failed: {stats['failed']}")


@cli.command()
@click.pass_context
def test(ctx):
    """Test connections to Zabbix and NetBox"""
    config = ctx.obj['config']
    
    click.echo("Testing connections...")
    
    # Test Zabbix
    click.echo("\n1. Testing Zabbix connection...")
    try:
        from src.sources.zabbix_source import ZabbixSource
        zabbix_config = config.get('zabbix', {})
        source = ZabbixSource(
            url=zabbix_config.get('url'),
            username=zabbix_config.get('username'),
            password=zabbix_config.get('password')
        )
        if source.connect():
            success, message = source.test_connection()
            if success:
                click.echo(click.style(f"   ✓ {message}", fg='green'))
            else:
                click.echo(click.style(f"   ✗ {message}", fg='red'))
        else:
            click.echo(click.style("   ✗ Failed to connect", fg='red'))
        source.disconnect()
    except Exception as e:
        click.echo(click.style(f"   ✗ Error: {e}", fg='red'))
    
    # Test NetBox
    click.echo("\n2. Testing NetBox connection...")
    try:
        from src.targets.netbox_target import NetBoxTarget
        netbox_config = config.get('netbox', {})
        target = NetBoxTarget(
            url=netbox_config.get('url'),
            token=netbox_config.get('token')
        )
        if target.connect():
            click.echo(click.style(f"   ✓ Connected to NetBox", fg='green'))
        else:
            click.echo(click.style("   ✗ Failed to connect", fg='red'))
        target.disconnect()
    except Exception as e:
        click.echo(click.style(f"   ✗ Error: {e}", fg='red'))
    
    # Test Redis
    click.echo("\n3. Testing Redis connection...")
    try:
        redis_config = config.get('redis', {})
        password = redis_config.get('password')
        if password == '':
            password = None
        cache = RedisCache(
            host=redis_config.get('host', 'localhost'),
            port=redis_config.get('port', 6379),
            db=redis_config.get('db', 0),
            password=password
        )
        cache.set('test_key', 'test_value')
        if cache.get('test_key') == 'test_value':
            click.echo(click.style(f"   ✓ Redis is working", fg='green'))
            cache.delete('test_key')
        else:
            click.echo(click.style("   ✗ Redis test failed", fg='red'))
    except Exception as e:
        click.echo(click.style(f"   ✗ Error: {e}", fg='red'))


@cli.command()
@click.option('--clear', is_flag=True, help='Clear all cache entries')
@click.option('--show-stats', is_flag=True, help='Show sync statistics')
@click.option('--show-failed', is_flag=True, help='Show failed devices')
@click.option('--date', help='Date for failed devices (YYYYMMDD)')
@click.pass_context
def cache(ctx, clear, show_stats, show_failed, date):
    """Manage cache"""
    config = ctx.obj['config']
    
    try:
        redis_config = config.get('redis', {})
        cache_obj = RedisCache(
            host=redis_config.get('host', 'localhost'),
            port=redis_config.get('port', 6379),
            db=redis_config.get('db', 0),
            password=redis_config.get('password'),
            prefix=redis_config.get('key_prefix', 'zabbix_netbox_sync')
        )
        
        if clear:
            count = cache_obj.clear()
            click.echo(f"Cleared {count} cache entries")
        
        if show_stats:
            stats = cache_obj.get_sync_stats()
            if stats:
                click.echo("\nLatest sync statistics:")
                click.echo(json.dumps(stats, indent=2))
            else:
                click.echo("No statistics available")
        
        if show_failed:
            failed = cache_obj.get_failed_devices(date)
            if failed:
                click.echo(f"\nFailed devices ({date or 'today'}):")
                for item in failed:
                    click.echo(f"  • {item['device']}: {item['error']}")
            else:
                click.echo("No failed devices")
        
        # Show cache info
        if not any([clear, show_stats, show_failed]):
            keys = cache_obj.get_all_keys()
            click.echo(f"Cache entries: {len(keys)}")
            
            last_sync = cache_obj.get_last_sync()
            if last_sync:
                click.echo(f"Last sync: {last_sync}")
            
    except Exception as e:
        click.echo(f"Error accessing cache: {e}", err=True)


@cli.command()
@click.argument('group')
@click.pass_context
def list_devices(ctx, group):
    """List devices in a Zabbix group"""
    config = ctx.obj['config']
    
    click.echo(f"Listing devices in group: {group}")
    
    try:
        from src.sources.zabbix_source import ZabbixSource
        zabbix_config = config.get('zabbix', {})
        source = ZabbixSource(
            url=zabbix_config.get('url'),
            username=zabbix_config.get('username'),
            password=zabbix_config.get('password')
        )
        
        if not source.connect():
            click.echo("Failed to connect to Zabbix", err=True)
            return
        
        hosts = source.get_hosts_by_group(group)
        
        if not hosts:
            click.echo(f"No hosts found in group {group}")
            return
        
        # Display hosts
        table_data = []
        for host in hosts[:20]:  # Show first 20
            inventory = host.get('inventory', {})
            table_data.append([
                host.get('host'),
                'Active' if host.get('status') == '0' else 'Inactive',
                inventory.get('vendor', 'N/A'),
                inventory.get('hardware', 'N/A')[:30]
            ])
        
        click.echo(tabulate(
            table_data,
            headers=['Host', 'Status', 'Vendor', 'Hardware'],
            tablefmt='grid'
        ))
        
        if len(hosts) > 20:
            click.echo(f"\n... and {len(hosts) - 20} more devices")
        
        click.echo(f"\nTotal: {len(hosts)} devices")
        
        source.disconnect()
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@cli.command()
@click.pass_context
def list_groups(ctx):
    """List all Zabbix host groups"""
    config = ctx.obj['config']
    
    click.echo("Listing Zabbix host groups...")
    
    try:
        from src.sources.zabbix_source import ZabbixSource
        zabbix_config = config.get('zabbix', {})
        source = ZabbixSource(
            url=zabbix_config.get('url'),
            username=zabbix_config.get('username'),
            password=zabbix_config.get('password')
        )
        
        if not source.connect():
            click.echo("Failed to connect to Zabbix", err=True)
            return
        
        groups = source.get_all_groups()
        
        # Filter and display groups
        click.echo("\nConfigured groups:")
        sources_config = config.get('sources', {}).get('zabbix_groups', {})
        configured = []
        configured.extend(sources_config.get('network', []))
        configured.extend(sources_config.get('servers', []))
        configured.extend(sources_config.get('storage', []))
        
        for group in configured:
            if any(g['name'] == group for g in groups):
                click.echo(click.style(f"  ✓ {group}", fg='green'))
            else:
                click.echo(click.style(f"  ✗ {group} (not found)", fg='red'))
        
        # Show other relevant groups
        click.echo("\nOther available groups:")
        relevant_keywords = ['network', 'server', 'vmware', 'datastore', 'datacenter']
        other_groups = []
        
        for group in groups:
            name = group['name']
            if name not in configured:
                if any(keyword in name.lower() for keyword in relevant_keywords):
                    other_groups.append(name)
        
        for group in sorted(other_groups)[:20]:
            click.echo(f"  • {group}")
        
        if len(other_groups) > 20:
            click.echo(f"  ... and {len(other_groups) - 20} more")
        
        source.disconnect()
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


if __name__ == '__main__':
    cli()