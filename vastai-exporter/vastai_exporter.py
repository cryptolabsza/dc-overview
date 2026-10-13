#!/usr/bin/env python3
# TRACEWEAVER: file-role=earnings-exporter; req=REQ-EARN-001; trace=TRACE-EARN-001; ver=VER-EARN-001
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

Daily observation gauges: canonical account/machine GPU, storage, upload and
download amounts for the previous completed UTC day. Reports are revisable;
unknown components are absent, and explicit zero/signed adjustments survive.
The background worker publishes atomic snapshots; scrapes never fetch earnings.
"""

import argparse
import json
import logging
import math
import re
import os
import sys
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Optional, Any
import urllib.request
import urllib.error
import urllib.parse
import ssl

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Vast.ai API endpoint
VASTAI_API_URL = "https://console.vast.ai/api/v0"
GPU_OCCUPANCY_STATES = {"x": 0, "I": 1, "D": 2, "R": 3}


class _RejectEarningsRedirect(urllib.request.HTTPRedirectHandler):
    """Keep bearer authentication on the exact canonical request only."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


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

# TRACEWEAVER: entrypoint=get_earnings; req=REQ-EARN-001; trace=TRACE-EARN-001; ver=VER-EARN-001
    def get_earnings(self, start_day: int, end_day: int) -> Optional[Dict[str, Any]]:
        """Fetch a bounded single-day report without a global opener change.

        The socket timeout and cooperative read budget cannot enforce an
        absolute OS/DNS/network deadline. Redirects are rejected, including
        same-origin redirects: the canonical endpoint already has its slash.
        """
        started = time.monotonic()
        query = urllib.parse.urlencode({'owner': 'me', 'sday': start_day, 'eday': end_day})
        request = urllib.request.Request(
            f'{VASTAI_API_URL}/users/me/machine-earnings/?{query}',
            headers={'Authorization': f'Bearer {self.api_key}', 'Accept': 'application/json'},
            method='GET',
        )
        limit = 1024 * 1024
        try:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ssl.create_default_context()),
                _RejectEarningsRedirect(),
            )
            with opener.open(request, timeout=15) as response:
                body = bytearray()
                while True:
                    if time.monotonic() - started > 30:
                        raise ValueError('cooperative read budget exceeded')
                    chunk = response.read(min(65536, limit + 1 - len(body)))
                    if time.monotonic() - started > 30:
                        raise ValueError('cooperative read budget exceeded')
                    if not chunk:
                        break
                    body.extend(chunk)
                    if len(body) > limit:
                        raise ValueError('response body limit exceeded')
                data = json.loads(body)
                return data if isinstance(data, dict) else None
        except Exception as error:
            if isinstance(error, urllib.error.HTTPError):
                error.close()
            # Do not log provider bodies, authenticated URLs or exception text.
            logger.warning('Historical earnings unavailable for %s (%s)',
                           self.account_name, type(error).__name__)
            return None
    
class MetricsCollector:
    """Collects metrics from multiple Vast.ai accounts"""
    
    def __init__(self, api_keys: List[tuple], *, wall_clock=None, monotonic_clock=None):
        """
        Initialize collector with API keys
        
        Args:
            api_keys: List of (account_name, api_key) tuples
        """
        self._wall_clock = wall_clock or time.time
        self._monotonic_clock = monotonic_clock or time.monotonic
        self._earnings_lock = threading.Lock()
        self._generation = 0
        self._clients = ()
        self._earnings = {}
        self._last_attempt = float('-inf')
        self._refreshing = False
        self._worker = None
        self._stop_event = threading.Event()
        self.metrics_cache = {}
        self.last_update = 0
        self.cache_ttl = 60
        self.lock = threading.Lock()
        self.replace_clients([VastAIClient(key, name) for name, key in api_keys])

    @property
    def clients(self):
        # A copied view prevents mutations bypassing generation invalidation.
        with self._earnings_lock:
            return list(self._clients)

    @clients.setter
    def clients(self, clients):
        self.replace_clients(clients)

# TRACEWEAVER: entrypoint=replace_clients; req=REQ-EARN-006; trace=TRACE-EARN-006; ver=VER-EARN-006
    def replace_clients(self, clients):
        """Replace account configuration and invalidate outstanding reports."""
        clients = tuple(clients)
        with self._earnings_lock:
            self._generation += 1
            self._clients = clients
            self._earnings = {
                id(client): {'account': client.account_name, 'provider': None,
                             'status': 0, 'next_attempt': float('-inf'),
                             'identity_retry': float('-inf'), 'report': None}
                for client in clients
            }
            self.metrics_cache = {}
            self.last_update = 0

    @staticmethod
    def _provider_identifier(value):
        if type(value) is int and value > 0:
            return str(value)
        if isinstance(value, str) and re.fullmatch(r'[1-9][0-9]*', value):
            return value
        return None

    @staticmethod
# TRACEWEAVER: entrypoint=_normalize_earnings; req=REQ-EARN-003; trace=TRACE-EARN-003; ver=VER-EARN-003
    def _normalize_earnings(response, target_day):
        if not isinstance(response, dict):
            raise ValueError('invalid report')
        days = response.get('per_day')
        rows = response.get('per_machine')
        if (not isinstance(days, list) or len(days) != 1
                or not isinstance(days[0], dict)
                or type(days[0].get('day')) is not int
                or days[0]['day'] != target_day or not isinstance(rows, list)):
            raise ValueError('unproved report day or machine list')
        normalized = {}
        partial = False
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError('invalid machine row')
            machine = MetricsCollector._provider_identifier(row.get('machine_id'))
            if machine is None or machine in normalized:
                raise ValueError('invalid or duplicate machine identifier')
            amounts = {}
            for component in ('gpu_earn', 'sto_earn', 'bwu_earn', 'bwd_earn'):
                value = row.get(component)
                if type(value) in (int, float):
                    try:
                        if math.isfinite(value):
                            amounts[component] = value
                    except OverflowError:
                        pass
                if component not in amounts:
                    partial = True
            normalized[machine] = amounts
        return normalized, (3 if not rows else 2 if partial else 1)

# TRACEWEAVER: entrypoint=refresh_earnings_once; req=REQ-EARN-007; trace=TRACE-EARN-007; ver=VER-EARN-007
    def refresh_earnings_once(self):
        """Attempt at most one eligible account; never hold a lock over I/O."""
        with self._earnings_lock:
            if self._refreshing or self._stop_event.is_set():
                return
            self._refreshing = True
            clients, generation = self._clients, self._generation
        try:
            # Resolve every new identity before choosing a source, so duplicates
            # fail closed even if only one earnings request is due this tick.
            for client in clients:
                with self._earnings_lock:
                    if generation != self._generation:
                        return
                    state = self._earnings[id(client)]
                    needs_identity = (state['provider'] is None and
                                      self._monotonic_clock() >= state['identity_retry'])
                if needs_identity:
                    try:
                        user = client.get_user_info()
                        provider = self._provider_identifier(user.get('id')) if isinstance(user, dict) else None
                    except Exception:
                        provider = None
                    with self._earnings_lock:
                        if generation != self._generation:
                            return
                        state['provider'] = provider
                        state['status'] = 0 if provider else 6
                        state['identity_retry'] = self._monotonic_clock() + 300
            with self._earnings_lock:
                if generation != self._generation or self._stop_event.is_set():
                    return
                states = [self._earnings[id(client)] for client in clients]
                for state in states:
                    duplicate = (sum(s['account'] == state['account'] for s in states) > 1
                                 or (state['provider'] is not None and
                                     sum(s['provider'] == state['provider'] for s in states) > 1))
                    if duplicate or state['provider'] is None:
                        state['status'] = 6
                        state['report'] = None
                now = self._monotonic_clock()
                if now - self._last_attempt < 2:
                    return
                eligible = [c for c in clients if self._earnings[id(c)]['status'] != 6
                            and self._earnings[id(c)]['next_attempt'] <= now]
                if not eligible:
                    return
                client = min(eligible, key=lambda c: self._earnings[id(c)]['next_attempt'])
                state = self._earnings[id(client)]
                provider = state['provider']
                target_day = int(self._wall_clock() // 86400) - 1
                self._last_attempt = now
                state['next_attempt'] = now + 300
            try:
                response = client.get_earnings(target_day, target_day)
                rows, status = self._normalize_earnings(response, target_day)
            except Exception:
                rows, status = None, 4
            with self._earnings_lock:
                if (generation != self._generation or self._stop_event.is_set()
                        or target_day != int(self._wall_clock() // 86400) - 1
                        or state['provider'] != provider):
                    return
                state['status'] = status
                state['next_attempt'] = self._monotonic_clock() + (3600 if rows is not None else 300)
                if rows is not None:
                    state['report'] = (target_day, self._wall_clock(), self._monotonic_clock(), rows)
        finally:
            with self._earnings_lock:
                self._refreshing = False

# TRACEWEAVER: entrypoint=start_earnings_worker; req=REQ-EARN-007; trace=TRACE-EARN-007; ver=VER-EARN-007
    def start_earnings_worker(self):
        """Start one explicit daemon after account loading."""
        with self._earnings_lock:
            if self._worker is not None and self._worker.is_alive():
                return
            self._stop_event.clear()
            event = self._stop_event
            def run():
                while not event.is_set():
                    try:
                        self.refresh_earnings_once()
                    except Exception:
                        logger.warning('Historical earnings worker attempt failed')
                    event.wait(1)
            self._worker = threading.Thread(target=run, name='vast-earnings', daemon=True)
            self._worker.start()

# TRACEWEAVER: entrypoint=stop_earnings_worker; req=REQ-EARN-007; trace=TRACE-EARN-007; ver=VER-EARN-007
    def stop_earnings_worker(self):
        """Invalidate publication and wait at most two seconds for the daemon."""
        with self._earnings_lock:
            self._stop_event.set()
            self._generation += 1
            self._earnings = {}
            worker = self._worker
        if worker is not None and worker is not threading.current_thread():
            worker.join(2)
            if worker.is_alive():
                logger.warning('Earnings daemon still waiting for provider I/O after bounded join')

    @staticmethod
    def _earnings_label(value):
        return str(value).replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')

# TRACEWEAVER: entrypoint=_format_earnings; req=REQ-EARN-005; trace=TRACE-EARN-005; ver=VER-EARN-005
    def _format_earnings(self):
        with self._earnings_lock:
            states = [dict(state) for state in self._earnings.values()]
        day = int(self._wall_clock() // 86400) - 1
        now = self._monotonic_clock()
        families = {name: [] for name in (
            'vastai_per_machine_gpu_earn', 'vastai_per_machine_sto_earn',
            'vastai_per_machine_bwu_earn', 'vastai_per_machine_bwd_earn',
            'vastai_earnings_report_day_timestamp_seconds',
            'vastai_earnings_last_success_timestamp_seconds',
            'vastai_earnings_report_valid', 'vastai_earnings_status')}
        for state in states:
            labels = f'account="{self._earnings_label(state["account"])}"'
            if state['provider'] is not None:
                labels = f'provider_account_id="{state["provider"]}",' + labels
            report, status = state['report'], state['status']
            valid = False
            if report is not None:
                report_day, success, accepted_mono, rows = report
                valid = report_day == day and 0 <= now - accepted_mono <= 7200 and status != 6
                if not valid:
                    status = 5
                families['vastai_earnings_report_day_timestamp_seconds'].append(f'{{{labels}}} {report_day * 86400}')
                families['vastai_earnings_last_success_timestamp_seconds'].append(f'{{{labels}}} {success}')
                if valid:
                    for machine, amounts in rows.items():
                        for component, amount in amounts.items():
                            families['vastai_per_machine_' + component].append(f'{{{labels},machine_id="{machine}"}} {amount}')
            if state['provider'] is not None:
                families['vastai_earnings_report_valid'].append(f'{{{labels}}} {int(valid)}')
            families['vastai_earnings_status'].append(f'{{{labels}}} {status}')
        lines = []
        for name, samples in families.items():
            lines.extend([f'# HELP {name} As-reported previous UTC day earnings or readiness metadata.', f'# TYPE {name} gauge'])
            # Invalid duplicate configurations may share an identical metadata
            # label set; expose one configuration-error sample for that identity.
            lines.extend(dict.fromkeys(name + sample for sample in samples))
        return lines

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
                        # Log machine fields on first fetch for diagnostics
                        if not self.metrics_cache and machines:
                            sample = machines[0]
                            logger.info(f"Machine fields for {client.account_name}: {sorted(sample.keys())}")
                            # Log occupancy-related fields specifically
                            for field in ['gpu_occupancy', 'current_rentals_running',
                                          'current_rentals_running_on_demand', 'current_rentals_on_demand',
                                          'current_rentals_resident', 'current_rentals_bid',
                                          'gpu_lanes', 'rentals', 'instances', 'num_gpus']:
                                if field in sample:
                                    logger.info(f"  {field} = {sample[field]}")
                        
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
            lines.append(f'vastai_account_balance{{account="{item["account"]}"}} {item["balance"]}')
        
        lines.append("")
        lines.append("# HELP vastai_current_balance Current balance")
        lines.append("# TYPE vastai_current_balance gauge")
        for item in metrics.get('accounts', []):
            lines.append(f'vastai_current_balance{{account="{item["account"]}"}} {item["balance"]}')
        
        lines.append("")
        lines.append("# HELP vastai_current_credit Current credit")
        lines.append("# TYPE vastai_current_credit gauge")
        for item in metrics.get('accounts', []):
            lines.append(f'vastai_current_credit{{account="{item["account"]}"}} {item["credit"]}')
        
        lines.append("")
        lines.append("# HELP vastai_current_service_fee Current service fee")
        lines.append("# TYPE vastai_current_service_fee gauge")
        for item in metrics.get('accounts', []):
            lines.append(f'vastai_current_service_fee{{account="{item["account"]}"}} {item["service_fee"]}')
        
        lines.append("")
        lines.append("# HELP vastai_current_total Current total")
        lines.append("# TYPE vastai_current_total gauge")
        for item in metrics.get('accounts', []):
            total = round(item["balance"] + item["credit"], 2)
            lines.append(f'vastai_current_total{{account="{item["account"]}"}} {total}')
        
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
            verified = self._verification_value(m.get('verification'))
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
            account = m.get('_account', 'default')
            hostname = (m.get('hostname', '') or '').replace('"', '\\"')
            machine_id = str(m.get('id', m.get('machine_id', 'unknown')))
            gpu_name = (m.get('gpu_name', '') or '').replace('"', '\\"')
            num_gpus = self._safe_int(m.get('num_gpus', 0))
            lines.append(f'vast_machine_gpu_name{{account="{account}",gpu_name="{gpu_name}",hostname="{hostname}",machine_id="{machine_id}"}} {num_gpus}')
        
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
            account = m.get('_account', 'default')
            hostname = (m.get('hostname', '') or '').replace('"', '\\"')
            machine_id = str(m.get('id', m.get('machine_id', 'unknown')))
            error_desc = (m.get('error_description', '') or '').replace('"', '\\"')
            lines.append(f'vastai_machine_ErrorDescription{{account="{account}",error_description="{error_desc}",hostname="{hostname}",machine_id="{machine_id}"}} 1')
        
        # GPU occupancy (per-GPU rental state)
        # Values: -1=Unknown, 0=Idle, 1=Rented(Bid/Interruptible),
        # 2=Rented(On-Demand), 3=Reserved/Resident.
        #
        # Vast supplies the only provider source that identifies individual GPU slots:
        # gpu_occupancy glyphs. Rental counters identify rentals, not GPUs, so they
        # cannot be expanded or assigned to arbitrary slots.
        lines.append("")
        lines.append("# HELP vastai_machine_gpu_occupancy GPU occupancy state per machine and GPU slot. -1=Unknown 0=Idle 1=Bid 2=OnDemand 3=Reserved")
        lines.append("# TYPE vastai_machine_gpu_occupancy gauge")
        machine_gpu_capacity = []
        for m in metrics.get('machines', []):
            account = m.get('_account', 'default')
            hostname = (m.get('hostname', '') or '').replace('"', '\\"')
            machine_id = str(m.get('id', m.get('machine_id', 'unknown')))
            num_gpus = self._safe_int(m.get('num_gpus', 0))
            gpu_states, aggregates = self._gpu_occupancy(m, num_gpus)
            machine_gpu_capacity.append((m, gpu_states, aggregates))
            # Emit per-GPU metrics
            for i in range(num_gpus):
                lines.append(f'vastai_machine_gpu_occupancy{{account="{account}",gpu="{i}",Hostname="{hostname}",hostname="{hostname}",machine_id="{machine_id}"}} {gpu_states[i]}')
        
        # GPU capacity aggregates use the same authoritative state as the individual
        # slot metrics, including NaN when the provider data cannot prove capacity.
        lines.append("")
        lines.append("# HELP vastai_machine_gpu_rented_on_demand Number of GPUs rented on-demand")
        lines.append("# TYPE vastai_machine_gpu_rented_on_demand gauge")
        for m, _, aggregates in machine_gpu_capacity:
            labels = self._machine_labels(m)
            lines.append(f'vastai_machine_gpu_rented_on_demand{{{labels}}} {aggregates["on_demand"]}')

        lines.append("")
        lines.append("# HELP vastai_machine_gpu_rented_bid_demand Number of GPUs rented on bid demand")
        lines.append("# TYPE vastai_machine_gpu_rented_bid_demand gauge")
        for m, _, aggregates in machine_gpu_capacity:
            labels = self._machine_labels(m)
            lines.append(f'vastai_machine_gpu_rented_bid_demand{{{labels}}} {aggregates["bid_demand"]}')

        lines.append("")
        lines.append("# HELP vastai_machine_gpu_rented_on_reserved Number of reserved GPUs")
        lines.append("# TYPE vastai_machine_gpu_rented_on_reserved gauge")
        for m, _, aggregates in machine_gpu_capacity:
            labels = self._machine_labels(m)
            lines.append(f'vastai_machine_gpu_rented_on_reserved{{{labels}}} {aggregates["on_reserved"]}')
        
        lines.append("")
        lines.append("# HELP vastai_machine_gpu_idle Number of GPUs idle")
        lines.append("# TYPE vastai_machine_gpu_idle gauge")
        for m, _, aggregates in machine_gpu_capacity:
            labels = self._machine_labels(m)
            lines.append(f'vastai_machine_gpu_idle{{{labels}}} {aggregates["idle"]}')
        
        # Summary totals per account
        account_earnings = {}
        account_gpus = {}
        account_machines = {}
        for m in metrics.get('machines', []):
            account = m.get('_account', 'default')
            account_earnings[account] = account_earnings.get(account, 0) + self._safe_float(m.get('earn_day', 0))
            account_gpus[account] = account_gpus.get(account, 0) + self._safe_int(m.get('num_gpus', 0))
            account_machines[account] = account_machines.get(account, 0) + 1
        
        lines.append("")
        lines.append("# HELP vastai_summary_total_gpu Total GPU earnings in summary")
        lines.append("# TYPE vastai_summary_total_gpu gauge")
        for account, earn in account_earnings.items():
            lines.append(f'vastai_summary_total_gpu{{account="{account}"}} {earn}')
        
        lines.append("")
        lines.append("# HELP vastai_account_gpus_total Total GPUs per account")
        lines.append("# TYPE vastai_account_gpus_total gauge")
        for account, gpus in account_gpus.items():
            lines.append(f'vastai_account_gpus_total{{account="{account}"}} {gpus}')
        
        lines.append("")
        lines.append("# HELP vastai_account_machines_total Total machines per account")
        lines.append("# TYPE vastai_account_machines_total gauge")
        for account, count in account_machines.items():
            lines.append(f'vastai_account_machines_total{{account="{account}"}} {count}')
        
        lines.append("")
        lines.extend(self._format_earnings())
        return "\n".join(lines)
    
    def _machine_labels(self, machine: Dict) -> str:
        """Generate Prometheus labels for a machine"""
        account = machine.get('_account', 'default')
        machine_id = str(machine.get('id', machine.get('machine_id', 'unknown')))
        hostname = (machine.get('hostname', '') or machine_id).replace('"', '\\"')
        
        return f'account="{account}",hostname="{hostname}",machine_id="{machine_id}"'

    def _verification_value(self, value) -> str:
        """Map only documented verification states to Prometheus values."""
        if value is True or value == 1 and not isinstance(value, str):
            return "1"
        if value is False or value == 0 and not isinstance(value, str):
            return "0"
        if isinstance(value, str):
            status = value.strip().lower()
            if status == "verified":
                return "1"
            if status in ("unverified", "deverified"):
                return "0"
        return "NaN"

    def _gpu_occupancy(self, machine: Dict, num_gpus: int):
        """Return trusted per-slot states and aggregates, or unknown values."""
        unknown = {"on_demand": "NaN", "bid_demand": "NaN", "on_reserved": "NaN", "idle": "NaN"}
        running = self._known_nonnegative_int(machine.get('current_rentals_running'))
        if running == 0:
            return [0] * num_gpus, {"on_demand": 0, "bid_demand": 0, "on_reserved": 0, "idle": num_gpus}

        glyphs = machine.get('gpu_occupancy')
        symbols = glyphs.split() if isinstance(glyphs, str) else []
        if running is None or len(symbols) != num_gpus or not all(symbol in GPU_OCCUPANCY_STATES for symbol in symbols):
            return [-1] * num_gpus, unknown

        states = [GPU_OCCUPANCY_STATES[symbol] for symbol in symbols]
        occupied = [state for state in states if state != 0]
        occupied_types = len({state for state in occupied})
        if not occupied_types <= running <= len(occupied):
            return [-1] * num_gpus, unknown
        return states, {
            "on_demand": states.count(2),
            "bid_demand": states.count(1),
            "on_reserved": states.count(3),
            "idle": states.count(0),
        }

    def _known_nonnegative_int(self, value) -> Optional[int]:
        """Accept provider integer counters without turning missing data into zero."""
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value if value >= 0 else None
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
        return None

class AccountManager:
    """Manages Vast.ai API key accounts with file persistence."""
    
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
                masked = key[:4] + '...' + key[-4:] if len(key) > 12 else '***'
                
                # Quick status check
                user_info = client.get_user_info()
                status = 'connected' if user_info else 'error'
                balance = float(user_info.get('balance', 0) or 0) if user_info else None
                machines_data = client.get_machines()
                machine_count = len(machines_data) if machines_data else 0
                
                result.append({
                    'name': client.account_name,
                    'key_masked': masked,
                    'status': status,
                    'balance': balance,
                    'machine_count': machine_count
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
            test_client = VastAIClient(key, name)
            user_info = test_client.get_user_info()
            if not user_info:
                return {'error': f'API key validation failed - could not connect to Vast.ai', 'status': 400}
            
            # Add to collector
            self.collector.replace_clients(self.collector.clients + [test_client])
            
            # Invalidate metrics cache to pick up new account
            self.collector.last_update = 0
            self.collector.metrics_cache = {}
            
            # Save to file
            self._save()
            
            balance = float(user_info.get('balance', 0) or 0)
            logger.info(f"Added account '{name}' (balance: ${balance})")
            return {
                'name': name,
                'balance': balance,
                'status': 'connected'
            }
    
    def remove_account(self, name: str) -> Dict:
        """Remove an API key account."""
        with self.lock:
            for i, client in enumerate(self.collector.clients):
                if client.account_name == name:
                    self.collector.replace_clients([c for c in self.collector.clients if c is not client])
                    
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
                    user_info = client.get_user_info()
                    machines = client.get_machines()
                    if user_info:
                        return {
                            'name': name,
                            'status': 'connected',
                            'balance': float(user_info.get('balance', 0) or 0),
                            'machine_count': len(machines) if machines else 0,
                            'machines': [
                                {
                                    'hostname': m.get('hostname', 'unknown'),
                                    'num_gpus': m.get('num_gpus', 0),
                                    'gpu_occupancy': m.get('gpu_occupancy', 'N/A'),
                                    'listed': m.get('listed', False)
                                }
                                for m in (machines or [])
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
    cli_env_keys = []
    if args.api_keys:
        cli_env_keys = parse_api_keys(args.api_keys)
    elif os.environ.get('VASTAI_API_KEYS'):
        keys_str = os.environ['VASTAI_API_KEYS']
        key_list = [k.strip() for k in keys_str.split(',') if k.strip()]
        cli_env_keys = parse_api_keys(key_list)
    elif os.environ.get('VASTAI_API_KEY'):
        cli_env_keys = [('default', os.environ['VASTAI_API_KEY'])]
    
    # Create collector (may start empty - accounts can be added via API)
    # We start empty and populate below based on the right source
    collector = MetricsCollector([])
    collector.cache_ttl = args.interval
    
    # Create account manager (handles persistence + API)
    account_manager = AccountManager(collector)
    
    # Determine which keys to use:
    # 1. Always prefer accounts.json if it exists (it contains accounts added
    #    via the management API and should not be overwritten by CLI/env args)
    # 2. Fall back to CLI/env args only when no config file exists (first run)
    api_keys = []
    file_keys = account_manager.load_from_file()
    if file_keys:
        api_keys = file_keys
        collector.clients = [
            VastAIClient(api_key, account_name)
            for account_name, api_key in file_keys
        ]
        logger.info(f"Loaded {len(file_keys)} account(s) from persistent config")
    elif cli_env_keys:
        api_keys = cli_env_keys
        collector.clients = [
            VastAIClient(api_key, account_name)
            for account_name, api_key in cli_env_keys
        ]
        # Save CLI/env keys to config file for future restarts
        account_manager._save()
        logger.info(f"Initialized {len(cli_env_keys)} account(s) from CLI/environment args")
    
    if not api_keys:
        logger.warning("No API keys configured. Add accounts via the management API:")
        logger.warning(f"  POST http://localhost:{args.port}/api/accounts")
        logger.warning("  Body: {\"name\": \"MyAccount\", \"key\": \"your-api-key\"}")
        logger.warning("The exporter will start and serve empty metrics until accounts are added.")
    else:
        logger.info(f"Starting vast.ai exporter on {args.listen_address}:{args.port}")
        logger.info(f"Configured {len(api_keys)} account(s): {[k[0] for k in api_keys]}")
        for name, key in api_keys:
            masked = key[:4] + '...' + key[-4:] if len(key) > 12 else '***'
            logger.info(f"  Account '{name}': key={masked}")
        
        # Initial connectivity check
        logger.info("Performing initial API connectivity check...")
        for client in collector.clients:
            user_info = client.get_user_info()
            if user_info:
                balance = user_info.get('balance', 'N/A')
                logger.info(f"  ✓ Account '{client.account_name}': connected (balance: ${balance})")
            else:
                logger.error(f"  ✗ Account '{client.account_name}': FAILED to connect - check API key")
        
            machines = client.get_machines()
            if machines:
                logger.info(f"  ✓ Account '{client.account_name}': found {len(machines)} machine(s)")
                for m in machines:
                    hostname = m.get('hostname', 'unknown')
                    num_gpus = m.get('num_gpus', 0)
                    gpu_occ = m.get('gpu_occupancy', 'N/A')
                    listed = m.get('listed', False)
                    logger.info(f"    - {hostname}: {num_gpus} GPUs, occupancy={gpu_occ}, listed={listed}")
            else:
                logger.warning(f"  ⚠ Account '{client.account_name}': no machines returned")
    
    # Wire up handler
    MetricsHandler.collector = collector
    MetricsHandler.account_manager = account_manager
    
    # Start HTTP server
    server = HTTPServer((args.listen_address, args.port), MetricsHandler)
    logger.info(f"Metrics available at http://{args.listen_address}:{args.port}/metrics")
    logger.info(f"Management API at http://{args.listen_address}:{args.port}/api/accounts")
    
    collector.start_earnings_worker()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()
    finally:
        collector.stop_earnings_worker()


if __name__ == '__main__':
    main()
