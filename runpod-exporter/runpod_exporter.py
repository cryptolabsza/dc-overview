#!/usr/bin/env python3
"""
RunPod Prometheus Exporter

Exposes RunPod host metrics for Prometheus scraping.
Supports multiple API keys for hosts with multiple accounts.

Metrics exposed:
- runpod_host_balance: Current host balance
- runpod_machine_gpu_earnings: GPU earnings per machine
- runpod_machine_disk_earnings: Disk earnings per machine
- runpod_machine_total_earnings: Total earnings per machine
- runpod_machine_gpu_total: Total GPUs per machine
- runpod_machine_gpu_rented: Rented GPUs per machine
- runpod_machine_uptime_percent: Uptime percentage (1w, 4w, 12w)
- runpod_machine_listed: Whether machine is listed (1=yes, 0=no)
- runpod_machine_verified: Whether machine is verified (1=yes, 0=no)
- runpod_active_pods: Number of active pods on machine
- runpod_machine_disk_total_gb: Total disk space
- runpod_machine_disk_reserved_gb: Reserved disk space
- runpod_machine_memory_total_gb: Total memory
- runpod_machine_download_mbps: Download speed
- runpod_machine_upload_mbps: Upload speed
"""

import argparse
import json
import logging
import os
import sys
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Optional, Any
import urllib.request
import urllib.error
import ssl

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# RunPod GraphQL endpoint
RUNPOD_API_URL = "https://api.runpod.io/graphql"

# GraphQL query for host metrics
HOST_METRICS_QUERY = """
query {
    myself {
        id
        email
        hostBalance
        machines {
            id
            name
            gpuTypeId
            gpuType {
                displayName
                memoryInGb
            }
            gpuTotal
            gpuReserved
            diskTotal
            diskReserved
            memoryTotal
            memoryReserved
            downloadMbps
            uploadMbps
            listed
            verified
            location
            uptimePercentListedOneWeek
            uptimePercentListedFourWeek
            uptimePercentListedTwelveWeek
            machineBalance {
                hostDiskEarnings
                hostGpuEarnings
                hostTotalEarnings
            }
            pods {
                id
                desiredStatus
                gpuCount
            }
        }
        machineEarnings {
            name
            machineId
            date
            hostTotalEarnings
            hostGpuEarnings
            hostDiskEarnings
        }
    }
}
"""


class RunPodClient:
    """Client for RunPod GraphQL API"""
    
    def __init__(self, api_key: str, account_name: str = "default"):
        self.api_key = api_key
        self.account_name = account_name
        
    def query(self, query: str) -> Optional[Dict[str, Any]]:
        """Execute a GraphQL query"""
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "RunPod-Exporter/1.0 (CryptoLabs DC-Overview)"
        }
        
        data = json.dumps({"query": query}).encode('utf-8')
        
        req = urllib.request.Request(
            RUNPOD_API_URL,
            data=data,
            headers=headers,
            method='POST'
        )
        
        # Create SSL context
        ctx = ssl.create_default_context()
        
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=30) as response:
                result = json.loads(response.read().decode('utf-8'))
                if 'errors' in result:
                    logger.error(f"GraphQL errors for {self.account_name}: {result['errors']}")
                    return None
                return result.get('data')
        except urllib.error.HTTPError as e:
            logger.error(f"HTTP error for {self.account_name}: {e.code} - {e.reason}")
            return None
        except urllib.error.URLError as e:
            logger.error(f"URL error for {self.account_name}: {e.reason}")
            return None
        except Exception as e:
            logger.error(f"Error querying RunPod API for {self.account_name}: {e}")
            return None
    
    def get_host_metrics(self) -> Optional[Dict[str, Any]]:
        """Get host metrics from RunPod API"""
        return self.query(HOST_METRICS_QUERY)


class MetricsCollector:
    """Collects metrics from multiple RunPod accounts"""
    
    def __init__(self, api_keys: List[tuple]):
        """
        Initialize collector with API keys
        
        Args:
            api_keys: List of (account_name, api_key) tuples
        """
        self.clients = [
            RunPodClient(api_key, account_name) 
            for account_name, api_key in api_keys
        ]
        self.metrics_cache = {}
        self.last_update = 0
        self.cache_ttl = 60  # Cache for 60 seconds
        self.lock = threading.Lock()
    
    def collect(self) -> str:
        """Collect metrics from all accounts and return Prometheus format"""
        now = time.time()
        
        with self.lock:
            # Use cache if still valid
            if now - self.last_update < self.cache_ttl and self.metrics_cache:
                return self._format_metrics(self.metrics_cache)
            
            # Collect fresh metrics
            all_metrics = {
                'host_balance': [],
                'machines': [],
                'earnings_today': [],
            }
            
            for client in self.clients:
                try:
                    data = client.get_host_metrics()
                    if not data or 'myself' not in data:
                        logger.warning(f"No data for account {client.account_name}")
                        continue
                    
                    myself = data['myself']
                    account = client.account_name
                    
                    # Host balance
                    if myself.get('hostBalance') is not None:
                        all_metrics['host_balance'].append({
                            'account': account,
                            'value': myself['hostBalance']
                        })
                    
                    # Machine metrics
                    for machine in myself.get('machines', []):
                        machine['_account'] = account
                        all_metrics['machines'].append(machine)
                    
                    # Today's earnings
                    for earning in myself.get('machineEarnings', []):
                        earning['_account'] = account
                        all_metrics['earnings_today'].append(earning)
                        
                except Exception as e:
                    logger.error(f"Error collecting metrics for {client.account_name}: {e}")
            
            self.metrics_cache = all_metrics
            self.last_update = now
            
            return self._format_metrics(all_metrics)
    
    def _format_metrics(self, metrics: Dict) -> str:
        """Format metrics in Prometheus exposition format"""
        lines = []
        
        # Add header
        lines.append("# RunPod Exporter Metrics")
        lines.append("")
        
        # Host balance
        lines.append("# HELP runpod_host_balance Current host balance in USD")
        lines.append("# TYPE runpod_host_balance gauge")
        for item in metrics.get('host_balance', []):
            lines.append(f'runpod_host_balance{{account="{item["account"]}"}} {item["value"]}')
        
        # Machine metrics
        lines.append("")
        lines.append("# HELP runpod_machine_gpu_total Total GPUs on machine")
        lines.append("# TYPE runpod_machine_gpu_total gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            if m.get('gpuTotal') is not None:
                lines.append(f'runpod_machine_gpu_total{{{labels}}} {m["gpuTotal"]}')
        
        lines.append("")
        lines.append("# HELP runpod_machine_gpu_rented Rented GPUs on machine")
        lines.append("# TYPE runpod_machine_gpu_rented gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            rented = m.get('gpuReserved', 0) or 0
            lines.append(f'runpod_machine_gpu_rented{{{labels}}} {rented}')
        
        lines.append("")
        lines.append("# HELP runpod_machine_gpu_idle Idle GPUs on machine")
        lines.append("# TYPE runpod_machine_gpu_idle gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            total = m.get('gpuTotal', 0) or 0
            rented = m.get('gpuReserved', 0) or 0
            idle = max(0, total - rented)
            lines.append(f'runpod_machine_gpu_idle{{{labels}}} {idle}')
        
        lines.append("")
        lines.append("# HELP runpod_machine_listed Machine listing status (1=listed, 0=unlisted)")
        lines.append("# TYPE runpod_machine_listed gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            listed = 1 if m.get('listed') else 0
            lines.append(f'runpod_machine_listed{{{labels}}} {listed}')
        
        lines.append("")
        lines.append("# HELP runpod_machine_verified Machine verification status (1=verified, 0=unverified)")
        lines.append("# TYPE runpod_machine_verified gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            verified = 1 if m.get('verified') else 0
            lines.append(f'runpod_machine_verified{{{labels}}} {verified}')
        
        lines.append("")
        lines.append("# HELP runpod_machine_uptime_percent_1w Uptime percentage over 1 week (0-100)")
        lines.append("# TYPE runpod_machine_uptime_percent_1w gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            uptime = m.get('uptimePercentListedOneWeek')
            if uptime is not None:
                # API returns 0-1 fraction, convert to 0-100 percentage
                uptime_pct = max(0, float(uptime) * 100)
                lines.append(f'runpod_machine_uptime_percent_1w{{{labels}}} {uptime_pct}')
        
        lines.append("")
        lines.append("# HELP runpod_machine_uptime_percent_4w Uptime percentage over 4 weeks (0-100)")
        lines.append("# TYPE runpod_machine_uptime_percent_4w gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            uptime = m.get('uptimePercentListedFourWeek')
            if uptime is not None:
                # API returns 0-1 fraction, convert to 0-100 percentage
                uptime_pct = max(0, float(uptime) * 100)
                lines.append(f'runpod_machine_uptime_percent_4w{{{labels}}} {uptime_pct}')
        
        lines.append("")
        lines.append("# HELP runpod_machine_uptime_percent_12w Uptime percentage over 12 weeks (0-100)")
        lines.append("# TYPE runpod_machine_uptime_percent_12w gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            uptime = m.get('uptimePercentListedTwelveWeek')
            if uptime is not None:
                # API returns 0-1 fraction, convert to 0-100 percentage
                uptime_pct = max(0, float(uptime) * 100)
                lines.append(f'runpod_machine_uptime_percent_12w{{{labels}}} {uptime_pct}')
        
        lines.append("")
        lines.append("# HELP runpod_machine_disk_total_gb Total disk space in GB")
        lines.append("# TYPE runpod_machine_disk_total_gb gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            if m.get('diskTotal') is not None:
                lines.append(f'runpod_machine_disk_total_gb{{{labels}}} {m["diskTotal"]}')
        
        lines.append("")
        lines.append("# HELP runpod_machine_disk_reserved_gb Reserved disk space in GB")
        lines.append("# TYPE runpod_machine_disk_reserved_gb gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            reserved = m.get('diskReserved', 0) or 0
            lines.append(f'runpod_machine_disk_reserved_gb{{{labels}}} {reserved}')
        
        lines.append("")
        lines.append("# HELP runpod_machine_memory_total_gb Total memory in GB")
        lines.append("# TYPE runpod_machine_memory_total_gb gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            if m.get('memoryTotal') is not None:
                lines.append(f'runpod_machine_memory_total_gb{{{labels}}} {m["memoryTotal"]}')
        
        lines.append("")
        lines.append("# HELP runpod_machine_download_mbps Download speed in Mbps")
        lines.append("# TYPE runpod_machine_download_mbps gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            if m.get('downloadMbps') is not None:
                lines.append(f'runpod_machine_download_mbps{{{labels}}} {m["downloadMbps"]}')
        
        lines.append("")
        lines.append("# HELP runpod_machine_upload_mbps Upload speed in Mbps")
        lines.append("# TYPE runpod_machine_upload_mbps gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            if m.get('uploadMbps') is not None:
                lines.append(f'runpod_machine_upload_mbps{{{labels}}} {m["uploadMbps"]}')
        
        # Earnings from machineBalance
        lines.append("")
        lines.append("# HELP runpod_machine_gpu_earnings GPU earnings for machine (today)")
        lines.append("# TYPE runpod_machine_gpu_earnings gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            balance = m.get('machineBalance', {}) or {}
            earnings = balance.get('hostGpuEarnings', 0) or 0
            lines.append(f'runpod_machine_gpu_earnings{{{labels}}} {earnings}')
        
        lines.append("")
        lines.append("# HELP runpod_machine_disk_earnings Disk earnings for machine (today)")
        lines.append("# TYPE runpod_machine_disk_earnings gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            balance = m.get('machineBalance', {}) or {}
            earnings = balance.get('hostDiskEarnings', 0) or 0
            lines.append(f'runpod_machine_disk_earnings{{{labels}}} {earnings}')
        
        lines.append("")
        lines.append("# HELP runpod_machine_total_earnings Total earnings for machine (today)")
        lines.append("# TYPE runpod_machine_total_earnings gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            balance = m.get('machineBalance', {}) or {}
            earnings = balance.get('hostTotalEarnings', 0) or 0
            lines.append(f'runpod_machine_total_earnings{{{labels}}} {earnings}')
        
        # Active pods per machine
        lines.append("")
        lines.append("# HELP runpod_machine_active_pods Number of active pods on machine")
        lines.append("# TYPE runpod_machine_active_pods gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            pods = m.get('pods', []) or []
            active = sum(1 for p in pods if p.get('desiredStatus') == 'RUNNING')
            lines.append(f'runpod_machine_active_pods{{{labels}}} {active}')
        
        # GPU utilization (pods using GPUs)
        lines.append("")
        lines.append("# HELP runpod_machine_gpus_in_use GPUs currently in use by pods")
        lines.append("# TYPE runpod_machine_gpus_in_use gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            pods = m.get('pods', []) or []
            gpus_in_use = sum(p.get('gpuCount', 0) or 0 for p in pods if p.get('desiredStatus') == 'RUNNING')
            lines.append(f'runpod_machine_gpus_in_use{{{labels}}} {gpus_in_use}')
        
        # Total machines and GPUs per account
        lines.append("")
        lines.append("# HELP runpod_account_machines_total Total machines per account")
        lines.append("# TYPE runpod_account_machines_total gauge")
        account_machines = {}
        account_gpus = {}
        for m in metrics.get('machines', []):
            account = m.get('_account', 'default')
            account_machines[account] = account_machines.get(account, 0) + 1
            account_gpus[account] = account_gpus.get(account, 0) + (m.get('gpuTotal', 0) or 0)
        for account, count in account_machines.items():
            lines.append(f'runpod_account_machines_total{{account="{account}"}} {count}')
        
        lines.append("")
        lines.append("# HELP runpod_account_gpus_total Total GPUs per account")
        lines.append("# TYPE runpod_account_gpus_total gauge")
        for account, count in account_gpus.items():
            lines.append(f'runpod_account_gpus_total{{account="{account}"}} {count}')
        
        lines.append("")
        return "\n".join(lines)
    
    def _machine_labels(self, machine: Dict) -> str:
        """Generate Prometheus labels for a machine"""
        account = machine.get('_account', 'default')
        machine_id = machine.get('id', 'unknown')
        name = machine.get('name', '') or machine_id
        gpu_type = ''
        if machine.get('gpuType') and machine['gpuType'].get('displayName'):
            gpu_type = machine['gpuType']['displayName']
        location = machine.get('location', '') or ''
        
        # Escape quotes in labels
        name = name.replace('"', '\\"')
        gpu_type = gpu_type.replace('"', '\\"')
        location = location.replace('"', '\\"')
        
        return f'account="{account}",machine_id="{machine_id}",name="{name}",gpu_type="{gpu_type}",location="{location}"'


class AccountManager:
    """Manages RunPod API key accounts with file persistence."""
    
    CONFIG_FILE = "/data/accounts.json"
    
    def __init__(self, collector: MetricsCollector):
        self.collector = collector
        self.lock = threading.Lock()
        self._mgmt_token = os.environ.get('MGMT_TOKEN', '')
    
    def _save(self):
        """Save accounts to config file."""
        try:
            config_dir = os.path.dirname(self.CONFIG_FILE)
            os.makedirs(config_dir, exist_ok=True)
            accounts = []
            for client in self.collector.clients:
                accounts.append({
                    'name': client.account_name,
                    'key': client.api_key
                })
            with open(self.CONFIG_FILE, 'w') as f:
                json.dump({'accounts': accounts, 'version': 1}, f, indent=2)
            logger.info(f"Saved {len(accounts)} account(s) to {self.CONFIG_FILE}")
        except Exception as e:
            logger.error(f"Failed to save accounts: {e}")
    
    def load_from_file(self) -> List[tuple]:
        """Load accounts from config file. Returns list of (name, key) tuples."""
        try:
            if os.path.exists(self.CONFIG_FILE):
                with open(self.CONFIG_FILE, 'r') as f:
                    data = json.load(f)
                accounts = data.get('accounts', [])
                keys = [(a['name'], a['key']) for a in accounts if a.get('key')]
                if keys:
                    logger.info(f"Loaded {len(keys)} account(s) from {self.CONFIG_FILE}")
                return keys
        except Exception as e:
            logger.error(f"Failed to load accounts from {self.CONFIG_FILE}: {e}")
        return []
    
    def check_auth(self, token: str) -> bool:
        """Check management API auth token."""
        if not self._mgmt_token:
            return True  # No token configured = no auth (internal network only)
        return token == self._mgmt_token
    
    def list_accounts(self) -> List[Dict]:
        """List accounts with masked keys and status."""
        result = []
        with self.lock:
            for client in self.collector.clients:
                key = client.api_key
                masked = key[:6] + '...' + key[-4:] if len(key) > 14 else '***'
                
                # Quick status check via GraphQL
                data = client.get_host_metrics()
                if data and 'myself' in data:
                    myself = data['myself']
                    balance = myself.get('hostBalance', 0) or 0
                    machines = myself.get('machines', []) or []
                    status = 'connected'
                else:
                    balance = None
                    machines = []
                    status = 'error'
                
                result.append({
                    'name': client.account_name,
                    'key_masked': masked,
                    'status': status,
                    'balance': balance,
                    'machine_count': len(machines)
                })
        return result
    
    def add_account(self, name: str, key: str) -> Dict:
        """Add a new API key account."""
        with self.lock:
            # Check for duplicate name
            for client in self.collector.clients:
                if client.account_name == name:
                    return {'error': f'Account "{name}" already exists', 'status': 409}
            
            # Verify the key works
            test_client = RunPodClient(key, name)
            data = test_client.get_host_metrics()
            if not data or 'myself' not in data:
                return {'error': 'API key validation failed - could not connect to RunPod', 'status': 400}
            
            # Add to collector
            self.collector.clients.append(test_client)
            
            # Invalidate metrics cache
            self.collector.last_update = 0
            self.collector.metrics_cache = {}
            
            # Save to file
            self._save()
            
            balance = data['myself'].get('hostBalance', 0) or 0
            machine_count = len(data['myself'].get('machines', []) or [])
            logger.info(f"Added account '{name}' (balance: ${balance}, machines: {machine_count})")
            return {
                'name': name,
                'balance': balance,
                'machine_count': machine_count,
                'status': 'connected'
            }
    
    def remove_account(self, name: str) -> Dict:
        """Remove an API key account."""
        with self.lock:
            for i, client in enumerate(self.collector.clients):
                if client.account_name == name:
                    self.collector.clients.pop(i)
                    
                    # Invalidate metrics cache
                    self.collector.last_update = 0
                    self.collector.metrics_cache = {}
                    
                    # Save to file
                    self._save()
                    
                    logger.info(f"Removed account '{name}'")
                    return {'success': True, 'name': name}
            
            return {'error': f'Account "{name}" not found', 'status': 404}
    
    def test_account(self, name: str) -> Dict:
        """Test connectivity for a specific account."""
        with self.lock:
            for client in self.collector.clients:
                if client.account_name == name:
                    data = client.get_host_metrics()
                    if data and 'myself' in data:
                        myself = data['myself']
                        machines = myself.get('machines', []) or []
                        return {
                            'name': name,
                            'status': 'connected',
                            'balance': myself.get('hostBalance', 0) or 0,
                            'machine_count': len(machines),
                            'machines': [
                                {
                                    'name': m.get('name', 'unknown'),
                                    'gpu_total': m.get('gpuTotal', 0),
                                    'gpu_rented': m.get('gpuReserved', 0),
                                    'listed': m.get('listed', False),
                                    'location': m.get('location', '')
                                }
                                for m in machines
                            ]
                        }
                    else:
                        return {'name': name, 'status': 'error', 'error': 'Failed to connect'}
            
            return {'error': f'Account "{name}" not found', 'status': 404}


class MetricsHandler(BaseHTTPRequestHandler):
    """HTTP handler for /metrics and management API endpoints"""
    
    collector = None  # Set by main()
    account_manager = None  # Set by main()
    
    def _send_json(self, data: Dict, status: int = 200):
        """Send JSON response."""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))
    
    def _read_body(self) -> Optional[Dict]:
        """Read and parse JSON request body."""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                body = self.rfile.read(content_length)
                return json.loads(body.decode('utf-8'))
        except Exception:
            pass
        return None
    
    def _check_mgmt_auth(self) -> bool:
        """Check management API authorization."""
        token = self.headers.get('X-Mgmt-Token', '') or self.headers.get('Authorization', '').replace('Bearer ', '')
        if not self.account_manager.check_auth(token):
            self._send_json({'error': 'Unauthorized'}, 401)
            return False
        return True
    
    def do_GET(self):
        if self.path == '/metrics':
            try:
                metrics = self.collector.collect()
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.end_headers()
                self.wfile.write(metrics.encode('utf-8'))
            except Exception as e:
                logger.error(f"Error serving metrics: {e}")
                self.send_error(500, str(e))
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK')
        elif self.path == '/api/accounts':
            if not self._check_mgmt_auth():
                return
            accounts = self.account_manager.list_accounts()
            self._send_json({'accounts': accounts})
        elif self.path.startswith('/api/accounts/') and self.path.endswith('/test'):
            if not self._check_mgmt_auth():
                return
            name = self.path.split('/')[3]
            result = self.account_manager.test_account(name)
            status = result.pop('status', 200) if 'error' in result else 200
            self._send_json(result, status)
        elif self.path == '/api/status':
            # Quick status without auth - used for health monitoring
            self._send_json({
                'accounts': len(self.collector.clients),
                'cache_age': int(time.time() - self.collector.last_update) if self.collector.last_update else None,
                'cache_ttl': self.collector.cache_ttl
            })
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        if self.path == '/api/accounts':
            if not self._check_mgmt_auth():
                return
            data = self._read_body()
            if not data or not data.get('key'):
                self._send_json({'error': 'key is required (name is optional)'}, 400)
                return
            name = data.get('name', 'default')
            key = data['key']
            result = self.account_manager.add_account(name, key)
            status = result.pop('status', 201) if 'error' in result else 201
            self._send_json(result, status)
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_DELETE(self):
        if self.path.startswith('/api/accounts/'):
            if not self._check_mgmt_auth():
                return
            name = self.path.split('/')[3]
            if not name:
                self._send_json({'error': 'Account name required'}, 400)
                return
            result = self.account_manager.remove_account(name)
            status = result.pop('status', 200) if 'error' in result else 200
            self._send_json(result, status)
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        # Suppress default logging
        pass


def parse_api_keys(key_args: List[str]) -> List[tuple]:
    """
    Parse API keys from command line arguments.
    
    Supports formats:
    - api_key (uses default account name)
    - account_name:api_key (named account)
    """
    keys = []
    for i, arg in enumerate(key_args):
        if ':' in arg and not arg.startswith('rpa_'):
            # Format: account_name:api_key
            parts = arg.split(':', 1)
            account_name = parts[0]
            api_key = parts[1]
        else:
            # Just the API key, generate account name
            account_name = f"account_{i + 1}" if len(key_args) > 1 else "default"
            api_key = arg
        keys.append((account_name, api_key))
    return keys


def main():
    parser = argparse.ArgumentParser(
        description='RunPod Prometheus Exporter - Exposes RunPod host metrics',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single API key
  runpod-exporter -api-key rpa_XXXXX

  # Multiple API keys (for hosts with multiple accounts)
  runpod-exporter -api-key RunpodCCC:rpa_KEY1 -api-key Brickbox:rpa_KEY2

  # Using environment variable
  export RUNPOD_API_KEYS="RunpodCCC:rpa_KEY1,Brickbox:rpa_KEY2"
  runpod-exporter
"""
    )
    parser.add_argument(
        '-api-key', '--api-key',
        action='append',
        dest='api_keys',
        help='RunPod API key (format: [account_name:]api_key). Can be specified multiple times.'
    )
    parser.add_argument(
        '-port', '--port',
        type=int,
        default=8623,
        help='Port to listen on (default: 8623)'
    )
    parser.add_argument(
        '-interval', '--interval',
        type=int,
        default=60,
        help='Metrics cache TTL in seconds (default: 60)'
    )
    
    args = parser.parse_args()
    
    # Get API keys from arguments or environment
    api_keys = []
    if args.api_keys:
        api_keys = parse_api_keys(args.api_keys)
    elif os.environ.get('RUNPOD_API_KEYS'):
        keys_str = os.environ['RUNPOD_API_KEYS']
        key_list = [k.strip() for k in keys_str.split(',') if k.strip()]
        api_keys = parse_api_keys(key_list)
    elif os.environ.get('RUNPOD_API_KEY'):
        api_keys = [('default', os.environ['RUNPOD_API_KEY'])]
    
    # Create collector (may start empty - accounts can be added via API)
    collector = MetricsCollector(api_keys)
    collector.cache_ttl = args.interval
    
    # Create account manager (handles persistence + API)
    account_manager = AccountManager(collector)
    
    # If no keys from env/args, try loading from config file
    if not api_keys:
        file_keys = account_manager.load_from_file()
        if file_keys:
            api_keys = file_keys
            collector.clients = [
                RunPodClient(api_key, account_name)
                for account_name, api_key in file_keys
            ]
    
    if not api_keys:
        logger.warning("No API keys configured. Add accounts via the management API:")
        logger.warning(f"  POST http://localhost:{args.port}/api/accounts")
        logger.warning("  Body: {\"name\": \"MyAccount\", \"key\": \"rpa_XXXXX\"}")
        logger.warning("The exporter will start and serve empty metrics until accounts are added.")
    else:
        logger.info(f"RunPod Exporter starting with {len(api_keys)} account(s): {[k[0] for k in api_keys]}")
        for name, key in api_keys:
            masked = key[:6] + '...' + key[-4:] if len(key) > 14 else '***'
            logger.info(f"  Account '{name}': key={masked}")
        
        # Save initial keys to config file (so they persist across restarts)
        account_manager._save()
        
        # Initial connectivity check
        logger.info("Performing initial API connectivity check...")
        for client in collector.clients:
            data = client.get_host_metrics()
            if data and 'myself' in data:
                myself = data['myself']
                balance = myself.get('hostBalance', 'N/A')
                machines = myself.get('machines', []) or []
                logger.info(f"  ✓ Account '{client.account_name}': connected (balance: ${balance}, {len(machines)} machine(s))")
                for m in machines:
                    name_str = m.get('name', 'unknown')
                    gpu_total = m.get('gpuTotal', 0)
                    gpu_rented = m.get('gpuReserved', 0) or 0
                    listed = m.get('listed', False)
                    logger.info(f"    - {name_str}: {gpu_total} GPUs ({gpu_rented} rented), listed={listed}")
            else:
                logger.error(f"  ✗ Account '{client.account_name}': FAILED to connect - check API key")
    
    # Wire up handler
    MetricsHandler.collector = collector
    MetricsHandler.account_manager = account_manager
    
    # Start HTTP server
    server = HTTPServer(('0.0.0.0', args.port), MetricsHandler)
    logger.info(f"RunPod Exporter listening on port {args.port}")
    logger.info(f"Metrics available at http://localhost:{args.port}/metrics")
    logger.info(f"Management API at http://localhost:{args.port}/api/accounts")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()


if __name__ == '__main__':
    main()
