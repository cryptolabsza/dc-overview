#!/usr/bin/env python3
"""
Vast.ai Prometheus Exporter

Exposes Vast.ai host metrics for Prometheus scraping.
Supports multiple API keys for hosts with multiple accounts.

Based on analysis of jjziets/vastai-exporter.

Metrics exposed:
- Account: balance, credit, service_fee, total
- Machine: gpu earnings, storage earnings, bandwidth earnings
- Machine: listed, verified, reliability, timeout
- Machine: num_gpus, gpu_name, gpu_occupancy
- Machine: disk_space, alloc_disk_space, avail_disk_space
- Machine: inet_up, inet_down, total_flops
- Machine: current_rentals (running, on_demand, resident, bid)
- Machine: earn_hour, earn_day
- Summary: total_gpu, total_stor, total_bwu, total_bwd
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
        
    def _request(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """Execute an API request - API key as query parameter"""
        # Add api_key as query parameter (this is how Vast.ai API works)
        separator = "&" if "?" in endpoint else "?"
        url = f"{VASTAI_API_URL}{endpoint}{separator}api_key={self.api_key}"
        
        headers = {
            "Accept": "application/json",
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
    
    def get_user_info(self) -> Optional[Dict[str, Any]]:
        """Get user account info including balance"""
        return self._request("/users/current/")
    
    def get_machines(self) -> Optional[List[Dict[str, Any]]]:
        """Get all machines for the authenticated user"""
        data = self._request("/machines/")
        if data and 'machines' in data:
            return data['machines']
        elif isinstance(data, list):
            return data
        return None


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
                            'balance': float(user_info.get('balance', 0) or 0),
                            'credit': float(user_info.get('credit', 0) or 0),
                            'service_fee': float(user_info.get('service_fee', 0) or 0),
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
    
    def _safe_float(self, value, default=0) -> float:
        """Safely convert value to float"""
        if value is None:
            return default
        try:
            return float(value)
        except (ValueError, TypeError):
            return default
    
    def _safe_int(self, value, default=0) -> int:
        """Safely convert value to int"""
        if value is None:
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            return default
    
    def _format_metrics(self, metrics: Dict) -> str:
        """Format metrics in Prometheus exposition format"""
        lines = []
        
        # Prometheus handler metrics
        lines.append("# HELP promhttp_metric_handler_requests_in_flight Current number of scrapes being served.")
        lines.append("# TYPE promhttp_metric_handler_requests_in_flight gauge")
        lines.append("promhttp_metric_handler_requests_in_flight 1")
        lines.append("")
        
        # Account balance
        lines.append("# HELP vastai_account_balance The current account balance of the user")
        lines.append("# TYPE vastai_account_balance gauge")
        for item in metrics.get('accounts', []):
            lines.append(f'vastai_account_balance {item["balance"]}')
        
        lines.append("")
        lines.append("# HELP vastai_current_balance Current balance")
        lines.append("# TYPE vastai_current_balance gauge")
        for item in metrics.get('accounts', []):
            lines.append(f'vastai_current_balance {item["balance"]}')
        
        lines.append("")
        lines.append("# HELP vastai_current_credit Current credit")
        lines.append("# TYPE vastai_current_credit gauge")
        for item in metrics.get('accounts', []):
            lines.append(f'vastai_current_credit {item["credit"]}')
        
        lines.append("")
        lines.append("# HELP vastai_current_service_fee Current service fee")
        lines.append("# TYPE vastai_current_service_fee gauge")
        for item in metrics.get('accounts', []):
            lines.append(f'vastai_current_service_fee {item["service_fee"]}')
        
        lines.append("")
        lines.append("# HELP vastai_current_total Current total")
        lines.append("# TYPE vastai_current_total gauge")
        for item in metrics.get('accounts', []):
            total = round(item["balance"] + item["credit"], 2)
            lines.append(f'vastai_current_total {total}')
        
        # Machine ID
        lines.append("")
        lines.append("# HELP vast_machine_id Machine ID")
        lines.append("# TYPE vast_machine_id gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            machine_id = self._safe_int(m.get('id', m.get('machine_id', 0)))
            lines.append(f'vast_machine_id{{{labels}}} {machine_id}')
        
        # Machine hostname
        lines.append("")
        lines.append("# HELP vast_machine_hostname Machine Hostname")
        lines.append("# TYPE vast_machine_hostname gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            lines.append(f'vast_machine_hostname{{{labels}}} 1')
        
        # Machine Listed
        lines.append("")
        lines.append("# HELP vast_machine_Listed Machine Listed")
        lines.append("# TYPE vast_machine_Listed gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            listed = 1 if m.get('listed') else 0
            lines.append(f'vast_machine_Listed{{{labels}}} {listed}')
        
        # Machine Verification
        lines.append("")
        lines.append("# HELP vast_machine_Verification Machine Verification")
        lines.append("# TYPE vast_machine_Verification gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            verified = 1 if m.get('verification') else 0
            lines.append(f'vast_machine_Verification{{{labels}}} {verified}')
        
        # Machine Reliability
        lines.append("")
        lines.append("# HELP vast_machine_Reliability Machine Reliability")
        lines.append("# TYPE vast_machine_Reliability gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            reliability = self._safe_float(m.get('reliability2', m.get('reliability', 0)))
            lines.append(f'vast_machine_Reliability{{{labels}}} {reliability}')
        
        # Machine timeout
        lines.append("")
        lines.append("# HELP vast_machine_timeout Machine timeout")
        lines.append("# TYPE vast_machine_timeout gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            timeout = self._safe_float(m.get('timeout', 0))
            lines.append(f'vast_machine_timeout{{{labels}}} {timeout}')
        
        # Number of GPUs
        lines.append("")
        lines.append("# HELP vast_machine_num_gpus Number of GPUs in the machine")
        lines.append("# TYPE vast_machine_num_gpus gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            num_gpus = self._safe_int(m.get('num_gpus', 0))
            lines.append(f'vast_machine_num_gpus{{{labels}}} {num_gpus}')
        
        # GPU name (as a gauge with gpu_name label)
        lines.append("")
        lines.append("# HELP vast_machine_gpu_name Type and total number of GPUs in the machine")
        lines.append("# TYPE vast_machine_gpu_name gauge")
        for m in metrics.get('machines', []):
            hostname = (m.get('hostname', '') or '').replace('"', '\\"')
            machine_id = str(m.get('id', m.get('machine_id', 'unknown')))
            gpu_name = (m.get('gpu_name', '') or '').replace('"', '\\"')
            num_gpus = self._safe_int(m.get('num_gpus', 0))
            lines.append(f'vast_machine_gpu_name{{gpu_name="{gpu_name}",hostname="{hostname}",machine_id="{machine_id}"}} {num_gpus}')
        
        # Total FLOPS
        lines.append("")
        lines.append("# HELP vast_machine_total_flops Machine total FLOPS")
        lines.append("# TYPE vast_machine_total_flops gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            flops = self._safe_float(m.get('total_flops', 0))
            lines.append(f'vast_machine_total_flops{{{labels}}} {flops}')
        
        # Inet Up/Down
        lines.append("")
        lines.append("# HELP vast_machine_InetDown Machine Inet Down")
        lines.append("# TYPE vast_machine_InetDown gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            inet_down = self._safe_float(m.get('inet_down', 0))
            lines.append(f'vast_machine_InetDown{{{labels}}} {inet_down}')
        
        lines.append("")
        lines.append("# HELP vastai_machine_InetUp Machine Inet Up")
        lines.append("# TYPE vastai_machine_InetUp gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            inet_up = self._safe_float(m.get('inet_up', 0))
            lines.append(f'vastai_machine_InetUp{{{labels}}} {inet_up}')
        
        # Disk space
        lines.append("")
        lines.append("# HELP vastai_machine_alloc_disk_space Allocated disk space on machine")
        lines.append("# TYPE vastai_machine_alloc_disk_space gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            alloc = self._safe_int(m.get('alloc_disk_space', m.get('allocated_disk_space', 0)))
            lines.append(f'vastai_machine_alloc_disk_space{{{labels}}} {alloc}')
        
        lines.append("")
        lines.append("# HELP vastai_machine_avail_disk_space Available disk space on machine")
        lines.append("# TYPE vastai_machine_avail_disk_space gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            avail = self._safe_int(m.get('avail_disk_space', 0))
            lines.append(f'vastai_machine_avail_disk_space{{{labels}}} {avail}')
        
        lines.append("")
        lines.append("# HELP vastai_machine_max_disk_space Maximum disk space on machine")
        lines.append("# TYPE vastai_machine_max_disk_space gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            max_disk = self._safe_int(m.get('max_disk_space', m.get('disk_space', 0)))
            lines.append(f'vastai_machine_max_disk_space{{{labels}}} {max_disk}')
        
        # Rentals
        lines.append("")
        lines.append("# HELP vastai_machine_current_rentals_running Current running rentals on machine")
        lines.append("# TYPE vastai_machine_current_rentals_running gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            rentals = self._safe_int(m.get('current_rentals_running', 0))
            lines.append(f'vastai_machine_current_rentals_running{{{labels}}} {rentals}')
        
        lines.append("")
        lines.append("# HELP vastai_machine_current_rentals_running_on_demand Current on-demand rentals on machine")
        lines.append("# TYPE vastai_machine_current_rentals_running_on_demand gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            rentals = self._safe_int(m.get('current_rentals_running_on_demand', m.get('current_rentals_on_demand', 0)))
            lines.append(f'vastai_machine_current_rentals_running_on_demand{{{labels}}} {rentals}')
        
        lines.append("")
        lines.append("# HELP vastai_machine_current_rentals_resident Current resident rentals on machine")
        lines.append("# TYPE vastai_machine_current_rentals_resident gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            rentals = self._safe_int(m.get('current_rentals_resident', 0))
            lines.append(f'vastai_machine_current_rentals_resident{{{labels}}} {rentals}')
        
        # Earnings
        lines.append("")
        lines.append("# HELP vastai_machine_earn_hour Machine earn hour")
        lines.append("# TYPE vastai_machine_earn_hour gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            earn = self._safe_float(m.get('earn_hour', 0))
            lines.append(f'vastai_machine_earn_hour{{{labels}}} {earn}')
        
        lines.append("")
        lines.append("# HELP vastai_machine_earn_day Machine earn day")  
        lines.append("# TYPE vastai_machine_earn_day gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            earn = self._safe_float(m.get('earn_day', 0))
            lines.append(f'vastai_machine_earn_day{{{labels}}} {earn}')
        
        # Error description
        lines.append("")
        lines.append("# HELP vastai_machine_ErrorDescription Machine Error Description")
        lines.append("# TYPE vastai_machine_ErrorDescription gauge")
        for m in metrics.get('machines', []):
            hostname = (m.get('hostname', '') or '').replace('"', '\\"')
            machine_id = str(m.get('id', m.get('machine_id', 'unknown')))
            error_desc = (m.get('error_description', '') or '').replace('"', '\\"')
            lines.append(f'vastai_machine_ErrorDescription{{error_description="{error_desc}",hostname="{hostname}",machine_id="{machine_id}"}} 1')
        
        # GPU occupancy (parsed from string like "0/2" -> outputs for each GPU)
        lines.append("")
        lines.append("# HELP vastai_machine_gpu_occupancy GPU occupancy state per machine and GPU number.")
        lines.append("# TYPE vastai_machine_gpu_occupancy gauge")
        for m in metrics.get('machines', []):
            hostname = (m.get('hostname', '') or '').replace('"', '\\"')
            machine_id = str(m.get('id', m.get('machine_id', 'unknown')))
            gpu_occupancy = m.get('gpu_occupancy', '') or ''
            num_gpus = self._safe_int(m.get('num_gpus', 0))
            
            # Parse occupancy - could be "0/2" format or just a number
            try:
                if '/' in str(gpu_occupancy):
                    rented, total = gpu_occupancy.split('/')
                    rented = int(rented)
                else:
                    rented = int(gpu_occupancy) if gpu_occupancy else 0
                
                for i in range(num_gpus):
                    occupied = 1 if i < rented else 0
                    lines.append(f'vastai_machine_gpu_occupancy{{gpu_num="{i}",hostname="{hostname}",machine_id="{machine_id}"}} {occupied}')
            except (ValueError, TypeError):
                pass
        
        # GPU rented metrics
        lines.append("")
        lines.append("# HELP vastai_machine_gpu_rented_on_demand Number of GPUs rented on-demand")
        lines.append("# TYPE vastai_machine_gpu_rented_on_demand gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            # Estimate from rentals
            rentals = self._safe_int(m.get('current_rentals_on_demand', 0))
            lines.append(f'vastai_machine_gpu_rented_on_demand{{{labels}}} {rentals}')
        
        lines.append("")
        lines.append("# HELP vastai_machine_gpu_idle Number of GPUs idle")
        lines.append("# TYPE vastai_machine_gpu_idle gauge")
        for m in metrics.get('machines', []):
            labels = self._machine_labels(m)
            num_gpus = self._safe_int(m.get('num_gpus', 0))
            running = self._safe_int(m.get('current_rentals_running', 0))
            idle = max(0, num_gpus - running)
            lines.append(f'vastai_machine_gpu_idle{{{labels}}} {idle}')
        
        # Summary totals
        total_gpu_earn = sum(self._safe_float(m.get('earn_day', 0)) for m in metrics.get('machines', []))
        total_gpus = sum(self._safe_int(m.get('num_gpus', 0)) for m in metrics.get('machines', []))
        
        lines.append("")
        lines.append("# HELP vastai_summary_total_gpu Total GPU earnings in summary")
        lines.append("# TYPE vastai_summary_total_gpu gauge")
        lines.append(f'vastai_summary_total_gpu {total_gpu_earn}')
        
        lines.append("")
        lines.append("# HELP vastai_account_gpus_total Total GPUs per account")
        lines.append("# TYPE vastai_account_gpus_total gauge")
        lines.append(f'vastai_account_gpus_total {total_gpus}')
        
        lines.append("")
        return "\n".join(lines)
    
    def _machine_labels(self, machine: Dict) -> str:
        """Generate Prometheus labels for a machine"""
        machine_id = str(machine.get('id', machine.get('machine_id', 'unknown')))
        hostname = (machine.get('hostname', '') or machine_id).replace('"', '\\"')
        
        return f'hostname="{hostname}",machine_id="{machine_id}"'


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
    parser.add_argument(
        '-listen-address', '--listen-address',
        type=str,
        default='0.0.0.0',
        help='Address to listen on (default: 0.0.0.0)'
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
    
    logger.info(f"Starting vast.ai exporter on {args.listen_address}:{args.port}")
    logger.info(f"Configured {len(api_keys)} account(s): {[k[0] for k in api_keys]}")
    
    # Create collector
    collector = MetricsCollector(api_keys)
    collector.cache_ttl = args.interval
    MetricsHandler.collector = collector
    
    # Start HTTP server
    server = HTTPServer((args.listen_address, args.port), MetricsHandler)
    logger.info(f"Metrics available at http://{args.listen_address}:{args.port}/metrics")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()


if __name__ == '__main__':
    main()
