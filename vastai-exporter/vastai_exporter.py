#!/usr/bin/env python3
"""
Vast.ai Prometheus Exporter

Exposes Vast.ai host metrics for Prometheus scraping.
Supports multiple API keys for hosts with multiple accounts.

Metrics exposed:
- vastai_account_balance: Current account balance
- vastai_machine_reliability: Machine reliability score (0-1)
- vastai_machine_listed: Whether machine is listed (1=yes, 0=no)
- vastai_machine_verified: Whether machine is verified (1=yes, 0=no)
- vastai_machine_num_gpus: Number of GPUs on machine
- vastai_machine_gpu_rented: Number of GPUs currently rented
- vastai_machine_disk_total_gb: Total disk space
- vastai_machine_disk_allocated_gb: Allocated disk space
- vastai_machine_inet_up_mbps: Upload speed
- vastai_machine_inet_down_mbps: Download speed
- vastai_machine_rentals_on_demand: Current on-demand rentals
- vastai_machine_rentals_bid: Current bid rentals
- vastai_machine_total_flops: Total TFLOPS of machine
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

# Vast.ai API endpoint
VASTAI_API_URL = "https://console.vast.ai/api/v0"


class VastAIClient:
    """Client for Vast.ai REST API"""
    
    def __init__(self, api_key: str, account_name: str = "default"):
        self.api_key = api_key
        self.account_name = account_name
        self._user_id = None
        
    def _request(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """Execute an API request"""
        url = f"{VASTAI_API_URL}{endpoint}"
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "VastAI-Exporter/1.0 (CryptoLabs DC-Overview)"
        }
        
        req = urllib.request.Request(url, headers=headers, method='GET')
        
        # Create SSL context
        ctx = ssl.create_default_context()
        
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=30) as response:
                return json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            logger.error(f"HTTP error for {self.account_name}: {e.code} - {e.reason}")
            return None
        except urllib.error.URLError as e:
            logger.error(f"URL error for {self.account_name}: {e.reason}")
            return None
        except Exception as e:
            logger.error(f"Error calling Vast.ai API for {self.account_name}: {e}")
            return None
    
    def get_user_id(self) -> Optional[str]:
        """Get current user ID from API key"""
        if self._user_id:
            return self._user_id
        
        # The /users/current endpoint returns current user info
        data = self._request("/users/current/")
        if data and 'id' in data:
            self._user_id = str(data['id'])
            return self._user_id
        return None
    
    def get_machines(self) -> Optional[List[Dict[str, Any]]]:
        """Get all machines for the authenticated user"""
        user_id = self.get_user_id()
        if not user_id:
            logger.error(f"Could not get user ID for {self.account_name}")
            return None
        
        data = self._request(f"/machines/?user_id={user_id}")
        if data and 'machines' in data:
            return data['machines']
        elif isinstance(data, list):
            return data
        return None
    
    def get_user_info(self) -> Optional[Dict[str, Any]]:
        """Get user account info including balance"""
        return self._request("/users/current/")


class MetricsCollector:
    """Collects metrics from multiple Vast.ai accounts"""
    
    def __init__(self, api_keys: List[tuple]):
        """
        Initialize collector with API keys
        
        Args:
            api_keys: List of (account_name, api_key) tuples
        """
        self.clients = [
            VastAIClient(api_key, account_name) 
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
                'accounts': [],
                'machines': [],
            }
            
            for client in self.clients:
                try:
                    # Get user info
                    user_info = client.get_user_info()
                    if user_info:
                        all_metrics['accounts'].append({
                            'account': client.account_name,
                            'balance': user_info.get('balance', 0) or 0,
                            'credit': user_info.get('credit', 0) or 0,
                        })
                    
                    # Get machines
                    machines = client.get_machines()
                    if machines:
                        for machine in machines:
                            machine['_account'] = client.account_name
                            all_metrics['machines'].append(machine)
                    
                except Exception as e:
                    logger.error(f"Error collecting metrics for {client.account_name}: {e}")
            
            self.metrics_cache = all_metrics
            self.last_update = now
            
            return self._format_metrics(all_metrics)
    
    def _format_metrics(self, metrics: Dict) -> str:
        """Format metrics in Prometheus exposition format"""
        lines = []
        
        # Add header
        lines.append("# Vast.ai Exporter Metrics (CryptoLabs)")
        lines.append("")
        
        # Account balance
        lines.append("# HELP vastai_account_balance Current account balance in USD")
        lines.append("# TYPE vastai_account_balance gauge")
        for item in metrics.get('accounts', []):
            lines.append(f'vastai_account_balance{{account="{item["account"]}"}} {item["balance"]}')
        
        lines.append("")
        lines.append("# HELP vastai_account_credit Current account credit in USD")
        lines.append("# TYPE vastai_account_credit gauge")
        for item in metrics.get('accounts', []):
            lines.append(f'vastai_account_credit{{account="{item["account"]}"}} {item["credit"]}')
        
        # Machine metrics
        lines.append("")
        lines.append("# HELP vastai_machine_num_gpus Number of GPUs on machine")
        lines.append("# TYPE vastai_machine_num_gpus gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            num_gpus = m.get('num_gpus', 0) or 0
            lines.append(f'vastai_machine_num_gpus{{{labels}}} {num_gpus}')
        
        lines.append("")
        lines.append("# HELP vastai_machine_reliability Machine reliability score (0-1)")
        lines.append("# TYPE vastai_machine_reliability gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            reliability = m.get('reliability2', m.get('reliability', 0)) or 0
            lines.append(f'vastai_machine_reliability{{{labels}}} {reliability}')
        
        lines.append("")
        lines.append("# HELP vastai_machine_listed Machine listing status (1=listed, 0=unlisted)")
        lines.append("# TYPE vastai_machine_listed gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            listed = 1 if m.get('listed') else 0
            lines.append(f'vastai_machine_listed{{{labels}}} {listed}')
        
        lines.append("")
        lines.append("# HELP vastai_machine_verified Machine verification status (1=verified, 0=unverified)")
        lines.append("# TYPE vastai_machine_verified gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            verified = 1 if m.get('verification') else 0
            lines.append(f'vastai_machine_verified{{{labels}}} {verified}')
        
        lines.append("")
        lines.append("# HELP vastai_machine_disk_total_gb Total disk space in GB")
        lines.append("# TYPE vastai_machine_disk_total_gb gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            disk = m.get('disk_space', 0) or 0
            lines.append(f'vastai_machine_disk_total_gb{{{labels}}} {disk}')
        
        lines.append("")
        lines.append("# HELP vastai_machine_disk_allocated_gb Allocated disk space in GB")
        lines.append("# TYPE vastai_machine_disk_allocated_gb gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            alloc = m.get('allocated_disk_space', m.get('disk_allocated', 0)) or 0
            lines.append(f'vastai_machine_disk_allocated_gb{{{labels}}} {alloc}')
        
        lines.append("")
        lines.append("# HELP vastai_machine_inet_up_mbps Upload speed in Mbps")
        lines.append("# TYPE vastai_machine_inet_up_mbps gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            up = m.get('inet_up', 0) or 0
            lines.append(f'vastai_machine_inet_up_mbps{{{labels}}} {up}')
        
        lines.append("")
        lines.append("# HELP vastai_machine_inet_down_mbps Download speed in Mbps")
        lines.append("# TYPE vastai_machine_inet_down_mbps gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            down = m.get('inet_down', 0) or 0
            lines.append(f'vastai_machine_inet_down_mbps{{{labels}}} {down}')
        
        lines.append("")
        lines.append("# HELP vastai_machine_total_flops Total TFLOPS of machine")
        lines.append("# TYPE vastai_machine_total_flops gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            flops = m.get('total_flops', 0) or 0
            lines.append(f'vastai_machine_total_flops{{{labels}}} {flops}')
        
        lines.append("")
        lines.append("# HELP vastai_machine_rentals_on_demand Current on-demand rentals")
        lines.append("# TYPE vastai_machine_rentals_on_demand gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            rentals = m.get('current_rentals_on_demand', 0) or 0
            lines.append(f'vastai_machine_rentals_on_demand{{{labels}}} {rentals}')
        
        lines.append("")
        lines.append("# HELP vastai_machine_rentals_bid Current bid rentals")
        lines.append("# TYPE vastai_machine_rentals_bid gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            rentals = m.get('current_rentals_bid', m.get('current_rentals_running', 0)) or 0
            lines.append(f'vastai_machine_rentals_bid{{{labels}}} {rentals}')
        
        lines.append("")
        lines.append("# HELP vastai_machine_timeout Machine timeout status (1=timed out)")
        lines.append("# TYPE vastai_machine_timeout gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            timeout = 1 if m.get('timeout') else 0
            lines.append(f'vastai_machine_timeout{{{labels}}} {timeout}')
        
        # Account-level aggregates
        lines.append("")
        lines.append("# HELP vastai_account_machines_total Total machines per account")
        lines.append("# TYPE vastai_account_machines_total gauge")
        account_machines = {}
        account_gpus = {}
        for m in metrics.get('machines', []):
            account = m.get('_account', 'default')
            account_machines[account] = account_machines.get(account, 0) + 1
            account_gpus[account] = account_gpus.get(account, 0) + (m.get('num_gpus', 0) or 0)
        for account, count in account_machines.items():
            lines.append(f'vastai_account_machines_total{{account="{account}"}} {count}')
        
        lines.append("")
        lines.append("# HELP vastai_account_gpus_total Total GPUs per account")
        lines.append("# TYPE vastai_account_gpus_total gauge")
        for account, count in account_gpus.items():
            lines.append(f'vastai_account_gpus_total{{account="{account}"}} {count}')
        
        lines.append("")
        return "\n".join(lines)
    
    def _machine_labels(self, machine: Dict) -> str:
        """Generate Prometheus labels for a machine"""
        account = machine.get('_account', 'default')
        machine_id = str(machine.get('id', 'unknown'))
        hostname = machine.get('hostname', '') or machine_id
        gpu_name = machine.get('gpu_name', '') or ''
        
        # Escape quotes in labels
        hostname = hostname.replace('"', '\\"')
        gpu_name = gpu_name.replace('"', '\\"')
        
        return f'account="{account}",machine_id="{machine_id}",hostname="{hostname}",gpu_name="{gpu_name}"'


class MetricsHandler(BaseHTTPRequestHandler):
    """HTTP handler for /metrics endpoint"""
    
    collector = None  # Set by main()
    
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
        if ':' in arg and len(arg.split(':')[0]) < 20:
            # Format: account_name:api_key (account names are short)
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
        description='Vast.ai Prometheus Exporter - Exposes Vast.ai host metrics',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single API key
  vastai-exporter -api-key YOUR_API_KEY

  # Multiple API keys (for hosts with multiple accounts)
  vastai-exporter -api-key Account1:KEY1 -api-key Account2:KEY2

  # Using environment variable
  export VASTAI_API_KEYS="Account1:KEY1,Account2:KEY2"
  vastai-exporter
"""
    )
    parser.add_argument(
        '-api-key', '--api-key',
        action='append',
        dest='api_keys',
        help='Vast.ai API key (format: [account_name:]api_key). Can be specified multiple times.'
    )
    parser.add_argument(
        '-port', '--port',
        type=int,
        default=8622,
        help='Port to listen on (default: 8622)'
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
    elif os.environ.get('VASTAI_API_KEYS'):
        keys_str = os.environ['VASTAI_API_KEYS']
        key_list = [k.strip() for k in keys_str.split(',') if k.strip()]
        api_keys = parse_api_keys(key_list)
    elif os.environ.get('VASTAI_API_KEY'):
        api_keys = [('default', os.environ['VASTAI_API_KEY'])]
    
    if not api_keys:
        print("Error: No API keys provided. Use -api-key or set VASTAI_API_KEYS env var.")
        sys.exit(1)
    
    logger.info(f"Configured {len(api_keys)} account(s): {[k[0] for k in api_keys]}")
    
    # Create collector
    collector = MetricsCollector(api_keys)
    collector.cache_ttl = args.interval
    MetricsHandler.collector = collector
    
    # Start HTTP server
    server = HTTPServer(('0.0.0.0', args.port), MetricsHandler)
    logger.info(f"Vast.ai Exporter listening on port {args.port}")
    logger.info(f"Metrics available at http://localhost:{args.port}/metrics")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()


if __name__ == '__main__':
    main()
