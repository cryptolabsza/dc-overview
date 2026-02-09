#!/usr/bin/env python3
"""
DC Overview - GPU Datacenter Monitoring Web Application

A Flask-based dashboard for managing GPU datacenter monitoring with Prometheus & Grafana.
Provides server management, exporter deployment, and monitoring status.

GitHub: https://github.com/cryptolabsza/dc-overview
License: MIT
"""

from flask import Flask, render_template_string, jsonify, request, Response, session, redirect, url_for, g
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
from prometheus_client import Gauge, Counter, generate_latest, CONTENT_TYPE_LATEST, CollectorRegistry
import subprocess
import threading
import time
import json
import yaml
import os
import socket
import secrets
import re
import ipaddress
import shlex
from pathlib import Path
import requests as http_requests
from werkzeug.security import generate_password_hash, check_password_hash

from . import __version__

app = Flask(__name__)

# =============================================================================
# CONFIGURATION
# =============================================================================

def get_data_dir():
    """Get data directory from environment or default."""
    if os.environ.get('DC_OVERVIEW_DATA'):
        return os.environ['DC_OVERVIEW_DATA']
    if os.geteuid() == 0:
        return '/var/lib/dc-overview'
    return os.path.expanduser('~/.config/dc-overview')

DATA_DIR = get_data_dir()
os.makedirs(DATA_DIR, exist_ok=True)

# Flask configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DATA_DIR}/dc_overview.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'true').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Application settings
APPLICATION_ROOT = os.environ.get('APPLICATION_ROOT', '/dc')
GRAFANA_URL = os.environ.get('GRAFANA_URL', 'http://grafana:3000')
PROMETHEUS_URL = os.environ.get('PROMETHEUS_URL', 'http://prometheus:9090')
DC_OVERVIEW_PORT = int(os.environ.get('DC_OVERVIEW_PORT', '5001'))

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================

# Trusted proxy IPs - only accept X-Fleet-* headers from these sources
# Docker internal network IPs, localhost, and configurable via environment
TRUSTED_PROXY_IPS = set(
    os.environ.get('TRUSTED_PROXY_IPS', '127.0.0.1,172.17.0.1,172.18.0.1,172.19.0.1,172.20.0.1').split(',')
)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiter
def get_client_ip():
    """Get client IP, respecting X-Forwarded-For from trusted proxies."""
    if request.remote_addr in TRUSTED_PROXY_IPS:
        forwarded = request.headers.get('X-Forwarded-For', '')
        if forwarded:
            return forwarded.split(',')[0].strip()
    return request.remote_addr

limiter = Limiter(
    key_func=get_client_ip,
    app=app,
    default_limits=["200 per minute", "50 per second"],
    storage_uri="memory://",
)

# Input validation patterns
VALID_IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
VALID_USERNAME_PATTERN = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$')
VALID_HOSTNAME_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$')

def validate_ip_address(ip_str):
    """Validate and return IP address or raise ValueError."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return str(ip)
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip_str}")

def validate_ssh_username(username):
    """Validate SSH username format."""
    if not username:
        return 'root'
    username = username.strip()
    if not VALID_USERNAME_PATTERN.match(username):
        raise ValueError(f"Invalid SSH username: {username}. Must be alphanumeric, starting with letter or underscore.")
    return username


def get_watchdog_api_key() -> str:
    """Get DC Watchdog API key from environment or config files.
    
    Searches in order:
    1. WATCHDOG_API_KEY environment variable
    2. /etc/dc-overview/.secrets.yaml (watchdog_api_key or ipmi_ai_license)
    3. /etc/dc-overview/fleet-config.yaml (watchdog.api_key)
    """
    # 1. Check environment variable first
    api_key = os.environ.get('WATCHDOG_API_KEY', '')
    if api_key:
        return api_key
    
    # 2. Check .secrets.yaml (has the actual keys)
    secrets_path = '/etc/dc-overview/.secrets.yaml'
    if os.path.exists(secrets_path):
        try:
            with open(secrets_path) as f:
                secrets = yaml.safe_load(f) or {}
                api_key = secrets.get('watchdog_api_key') or secrets.get('ipmi_ai_license')
                if api_key:
                    return api_key
        except Exception:
            pass
    
    # 3. Check fleet-config.yaml (legacy location)
    config_paths = ['/etc/dc-overview/fleet-config.yaml', '/etc/dc-overview/config.yaml']
    for config_path in config_paths:
        if os.path.exists(config_path):
            try:
                with open(config_path) as f:
                    cfg = yaml.safe_load(f) or {}
                    api_key = cfg.get('watchdog', {}).get('api_key', '')
                    if not api_key:
                        api_key = cfg.get('ipmi_monitor', {}).get('ai_license_key', '')
                    if api_key:
                        return api_key
            except Exception:
                pass
    
    return ''

def get_site_id() -> str:
    """Get the site_id for this deployment (multi-site support).
    
    Derives site_id from fleet config domain or master_ip.
    Consistent with what's written to agent.yaml during deployment.
    """
    # Check fleet config for domain or master_ip
    config_paths = ['/etc/dc-overview/fleet-config.yaml', '/etc/dc-overview/config.yaml']
    for config_path in config_paths:
        if os.path.exists(config_path):
            try:
                with open(config_path) as f:
                    cfg = yaml.safe_load(f) or {}
                    domain = cfg.get('domain', '')
                    if domain:
                        return domain
                    master_ip = cfg.get('master_ip', '')
                    if master_ip:
                        return master_ip
            except Exception:
                pass
    
    # Fallback to SITE_NAME env var (shared with ipmi-monitor) or hostname
    return os.environ.get('SITE_NAME', os.environ.get('HOSTNAME', 'default'))


# DC Watchdog API integration - fetch agent status via HTTP instead of SSH
WATCHDOG_URL = os.environ.get('WATCHDOG_URL', 'https://watchdog.cryptolabs.co.za')

# Cache for watchdog API results (avoid hammering the API)
_watchdog_api_cache = {'ts': 0, 'data': None}
_WATCHDOG_CACHE_TTL = 30  # seconds


def get_watchdog_agents_from_api() -> dict:
    """Fetch per-agent status from the dc-watchdog server API.
    
    Returns a dict keyed by worker_id (lowercase) with agent info,
    or empty dict if unavailable. Uses cached results for 30s.
    
    This is the same method the Fleet Management dashboard uses.
    """
    import time
    now = time.time()
    
    if _watchdog_api_cache['data'] is not None and (now - _watchdog_api_cache['ts']) < _WATCHDOG_CACHE_TTL:
        return _watchdog_api_cache['data']
    
    api_key = get_watchdog_api_key()
    if not api_key:
        return {}
    
    try:
        resp = http_requests.get(
            f'{WATCHDOG_URL}/api/agents/status',
            params={'api_key': api_key},
            timeout=5
        )
        if resp.ok:
            data = resp.json()
            # Build lookup dict by worker_id (lowercase for case-insensitive matching)
            agents_map = {}
            for agent in data.get('agents', []):
                wid = (agent.get('worker_id') or '').lower()
                if wid:
                    agents_map[wid] = agent
            
            _watchdog_api_cache['ts'] = now
            _watchdog_api_cache['data'] = agents_map
            return agents_map
    except Exception as e:
        app.logger.debug(f"Could not fetch watchdog agent status: {e}")
    
    return _watchdog_api_cache.get('data') or {}


def validate_hostname(hostname):
    """Validate hostname/server name format."""
    if not hostname:
        raise ValueError("Hostname cannot be empty")
    hostname = hostname.strip()
    if not VALID_HOSTNAME_PATTERN.match(hostname):
        raise ValueError(f"Invalid hostname: {hostname}. Must be alphanumeric with dots, dashes, underscores.")
    return hostname

def validate_port(port, default=22):
    """Validate port number."""
    try:
        port = int(port) if port else default
        if not 1 <= port <= 65535:
            raise ValueError()
        return port
    except (ValueError, TypeError):
        raise ValueError(f"Invalid port: {port}. Must be 1-65535.")

db = SQLAlchemy(app)

# CSRF error handler
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Handle CSRF validation errors."""
    app.logger.warning(f"CSRF validation failed: {e.description} from {get_client_ip()}")
    return jsonify({'error': 'CSRF token missing or invalid'}), 400

# Security headers
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # XSS protection (legacy but still useful)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Content Security Policy (basic)
    if 'text/html' in response.content_type:
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self'"
        )
    return response

# =============================================================================
# DATABASE MODELS
# =============================================================================

class Server(db.Model):
    """GPU worker server to monitor."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    server_ip = db.Column(db.String(50), nullable=False)
    ssh_user = db.Column(db.String(50), default='root')
    ssh_port = db.Column(db.Integer, default=22)
    ssh_key_id = db.Column(db.Integer, db.ForeignKey('ssh_key.id'), nullable=True)
    # Password-based SSH auth (alternative to key-based)
    # If both key and password are set, key takes priority
    ssh_password = db.Column(db.String(500), nullable=True)
    
    # Exporter installation status
    node_exporter_installed = db.Column(db.Boolean, default=False)
    dc_exporter_installed = db.Column(db.Boolean, default=False)
    dcgm_exporter_installed = db.Column(db.Boolean, default=False)
    
    # Exporter enabled state (controls Prometheus scraping)
    node_exporter_enabled = db.Column(db.Boolean, default=True)
    dc_exporter_enabled = db.Column(db.Boolean, default=True)
    dcgm_exporter_enabled = db.Column(db.Boolean, default=False)
    
    # Exporter version tracking
    node_exporter_version = db.Column(db.String(50), nullable=True)
    dc_exporter_version = db.Column(db.String(50), nullable=True)
    dcgm_exporter_version = db.Column(db.String(50), nullable=True)
    
    # Auto-update preferences
    node_exporter_auto_update = db.Column(db.Boolean, default=True)
    dc_exporter_auto_update = db.Column(db.Boolean, default=True)
    dcgm_exporter_auto_update = db.Column(db.Boolean, default=False)
    exporter_update_branch = db.Column(db.String(20), default='main')  # 'main' or 'dev'
    
    # DC Watchdog agent status
    watchdog_agent_installed = db.Column(db.Boolean, default=False)
    watchdog_agent_enabled = db.Column(db.Boolean, default=True)
    watchdog_agent_version = db.Column(db.String(50), nullable=True)
    watchdog_agent_last_seen = db.Column(db.DateTime, nullable=True)
    
    # Monitoring status
    last_seen = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='unknown')  # online, offline, unknown
    gpu_count = db.Column(db.Integer, default=0)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    ssh_key = db.relationship('SSHKey', backref='servers')


class SSHKey(db.Model):
    """SSH key for worker authentication."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    key_path = db.Column(db.String(500), nullable=False)
    fingerprint = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AppSettings(db.Model):
    """Application settings stored in database."""
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# =============================================================================
# PROMETHEUS METRICS
# =============================================================================

# Custom registry to avoid conflicts
registry = CollectorRegistry()

# DC Overview metrics
dc_servers_total = Gauge('dc_overview_servers_total', 'Total number of monitored servers', registry=registry)
dc_servers_online = Gauge('dc_overview_servers_online', 'Number of online servers', registry=registry)
dc_exporters_installed = Gauge('dc_overview_exporters_installed', 'Exporters installed', 
                                ['server', 'exporter'], registry=registry)
dc_gpu_total = Gauge('dc_overview_gpu_total', 'Total GPUs across all servers', registry=registry)

# =============================================================================
# AUTHENTICATION
# =============================================================================

# Proxy authentication headers (set by cryptolabs-proxy)
PROXY_AUTH_HEADER_USER = 'X-Fleet-Auth-User'
PROXY_AUTH_HEADER_ROLE = 'X-Fleet-Auth-Role'
PROXY_AUTH_HEADER_TOKEN = 'X-Fleet-Auth-Token'
PROXY_AUTH_HEADER_FLAG = 'X-Fleet-Authenticated'

def get_setting(key, default=None):
    """Get a setting from database."""
    setting = AppSettings.query.filter_by(key=key).first()
    return setting.value if setting else default

def set_setting(key, value):
    """Set a setting in database."""
    setting = AppSettings.query.filter_by(key=key).first()
    if setting:
        setting.value = value
    else:
        setting = AppSettings(key=key, value=value)
        db.session.add(setting)
    db.session.commit()

def is_proxy_authenticated():
    """
    Check if request came through an authenticated proxy.
    
    When running behind cryptolabs-proxy with unified auth,
    the proxy forwards authentication headers that we can trust.
    
    SECURITY: Only trust headers from known proxy IPs to prevent
    header spoofing attacks from untrusted sources.
    """
    # SECURITY: First verify the request comes from a trusted proxy IP
    client_ip = request.remote_addr
    if client_ip not in TRUSTED_PROXY_IPS:
        # Log attempted header spoofing from untrusted source
        if request.headers.get(PROXY_AUTH_HEADER_FLAG) == 'true':
            app.logger.warning(
                f"SECURITY: Rejecting proxy auth headers from untrusted IP: {client_ip}. "
                f"User attempted: {request.headers.get(PROXY_AUTH_HEADER_USER, 'unknown')}"
            )
        return False
    
    # Check if the proxy auth flag is set (only from trusted IPs)
    if request.headers.get(PROXY_AUTH_HEADER_FLAG) == 'true':
        username = request.headers.get(PROXY_AUTH_HEADER_USER)
        if username:
            # Map proxy roles directly - preserve all role levels
            proxy_role = request.headers.get(PROXY_AUTH_HEADER_ROLE, 'readonly')
            # Valid roles: admin, readwrite, readonly
            role = proxy_role if proxy_role in ['admin', 'readwrite', 'readonly'] else 'readonly'
            
            # Auto-authenticate the session or update role if changed
            if not session.get('authenticated') or session.get('role') != role:
                session['authenticated'] = True
                session['username'] = username
                session['role'] = role
                session['auth_via'] = 'fleet_proxy'
            return True
    return False

def check_auth():
    """Check if user is authenticated (via session or proxy)."""
    # First check for proxy authentication
    if is_proxy_authenticated():
        return True
    # Then check session
    return session.get('authenticated', False)

def get_user_role():
    """Get the current user's role."""
    is_proxy_authenticated()  # Ensure session is updated
    return session.get('role', 'readonly')

def login_required(f):
    """Decorator for routes that require any authenticated user."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not check_auth():
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator for routes that require admin role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not check_auth():
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        
        role = get_user_role()
        if role != 'admin':
            if request.is_json:
                return jsonify({'error': 'Admin access required', 'your_role': role}), 403
            return "Admin access required", 403
        return f(*args, **kwargs)
    return decorated_function

def write_required(f):
    """Decorator for routes that require admin or readwrite role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not check_auth():
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        
        role = get_user_role()
        if role not in ['admin', 'readwrite']:
            if request.is_json:
                return jsonify({'error': 'Write access required', 'your_role': role}), 403
            return "Write access required", 403
        return f(*args, **kwargs)
    return decorated_function

def is_running_behind_proxy():
    """Check if we're running behind the fleet proxy."""
    return request.headers.get(PROXY_AUTH_HEADER_FLAG) == 'true'

# =============================================================================
# API ROUTES
# =============================================================================

@app.route('/api/health')
@csrf.exempt
def api_health():
    """Health check endpoint for Docker/proxy."""
    return jsonify({
        'status': 'ok',
        'service': 'dc-overview',
        'version': __version__,
        'timestamp': datetime.utcnow().isoformat()
    })

# =============================================================================
# MOBILE API (CL Fleety App)
# =============================================================================

class MobileApiKey(db.Model):
    """API key for mobile app (CL Fleety) read-only access."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, default='Mobile App')
    key_hash = db.Column(db.String(128), nullable=False, unique=True)
    key_prefix = db.Column(db.String(20), nullable=False)  # First 12 chars for display
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)


def verify_mobile_api_key():
    """Verify mobile API key from Authorization header. Returns True if valid."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer mob-'):
        return False
    
    token = auth_header.replace('Bearer ', '').strip()
    from werkzeug.security import check_password_hash
    
    # Check all active keys
    active_keys = MobileApiKey.query.filter_by(is_active=True).all()
    for key_record in active_keys:
        if check_password_hash(key_record.key_hash, token):
            key_record.last_used = datetime.utcnow()
            db.session.commit()
            return True
    return False


def mobile_auth_required(f):
    """Decorator for mobile API endpoints - accepts mobile API key OR session auth."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if verify_mobile_api_key() or check_auth():
            return f(*args, **kwargs)
        return jsonify({'error': 'Authentication required. Use a mobile API key.'}), 401
    return decorated_function


@app.route('/api/mobile/generate-key', methods=['POST'])
@admin_required
@csrf.exempt
def api_mobile_generate_key():
    """Generate a new mobile API key (admin only)."""
    import secrets as sec
    from werkzeug.security import generate_password_hash
    
    name = request.json.get('name', 'Mobile App') if request.is_json else 'Mobile App'
    raw_key = 'mob-' + sec.token_hex(24)
    key_hash = generate_password_hash(raw_key)
    
    new_key = MobileApiKey(
        name=name,
        key_hash=key_hash,
        key_prefix=raw_key[:12] + '...',
    )
    db.session.add(new_key)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'key': raw_key,
        'name': name,
        'id': new_key.id,
        'message': 'Save this key now - it cannot be shown again.',
    })


@app.route('/api/mobile/keys', methods=['GET'])
@admin_required
def api_mobile_list_keys():
    """List all mobile API keys (admin only, shows prefix only)."""
    keys = MobileApiKey.query.all()
    return jsonify([{
        'id': k.id,
        'name': k.name,
        'key_prefix': k.key_prefix,
        'created_at': k.created_at.isoformat() if k.created_at else None,
        'last_used': k.last_used.isoformat() if k.last_used else None,
        'is_active': k.is_active,
    } for k in keys])


@app.route('/api/mobile/keys/<int:key_id>', methods=['DELETE'])
@admin_required
@csrf.exempt
def api_mobile_delete_key(key_id):
    """Revoke a mobile API key (admin only)."""
    key = MobileApiKey.query.get_or_404(key_id)
    key.is_active = False
    db.session.commit()
    return jsonify({'success': True, 'message': f'Key "{key.name}" revoked.'})


@app.route('/api/mobile/status')
@csrf.exempt
@mobile_auth_required
def api_mobile_status():
    """
    Mobile-optimized server status endpoint.
    Returns server list with key metrics from Prometheus.
    """
    servers = Server.query.all()
    
    # Try to get live metrics from Prometheus
    metrics = _fetch_prometheus_metrics([s.server_ip for s in servers])
    
    server_list = []
    total_online = 0
    total_offline = 0
    
    for s in servers:
        is_online = s.status == 'online'
        if is_online:
            total_online += 1
        else:
            total_offline += 1
        
        server_data = {
            'id': s.id,
            'name': s.name,
            'ip': s.server_ip,
            'status': s.status,
            'gpu_count': s.gpu_count,
            'last_seen': s.last_seen.isoformat() if s.last_seen else None,
            'watchdog': s.watchdog_agent_installed and s.watchdog_agent_enabled,
        }
        
        # Add Prometheus metrics if available
        ip_metrics = metrics.get(s.server_ip, {})
        if ip_metrics:
            server_data['metrics'] = ip_metrics
        
        server_list.append(server_data)
    
    return jsonify({
        'instance': get_setting('site_name', 'DC Overview'),
        'version': __version__,
        'timestamp': datetime.utcnow().isoformat(),
        'summary': {
            'total': len(servers),
            'online': total_online,
            'offline': total_offline,
        },
        'servers': server_list,
    })


def _fetch_prometheus_metrics(server_ips):
    """Fetch key metrics from Prometheus for the given server IPs."""
    import requests as req
    
    result = {}
    if not server_ips:
        return result
    
    prom_url = PROMETHEUS_URL
    
    # Queries for key metrics (use last 2 minutes to catch recent data)
    queries = {
        'cpu_percent': '100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[2m])) * 100)',
        'ram_percent': '(1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100',
        'gpu_temp_max': 'max by (instance) (dcgm_gpu_temp)',
        'gpu_power_total': 'sum by (instance) (dcgm_power_usage)',
        'gpu_util_avg': 'avg by (instance) (dcgm_gpu_utilization)',
    }
    
    for metric_name, query in queries.items():
        try:
            resp = req.get(
                f'{prom_url}/api/v1/query',
                params={'query': query},
                timeout=3,
            )
            if resp.status_code == 200:
                data = resp.json().get('data', {}).get('result', [])
                for item in data:
                    instance = item.get('metric', {}).get('instance', '')
                    # Extract IP from instance label (format: "ip:port")
                    ip = instance.split(':')[0] if ':' in instance else instance
                    if ip in server_ips:
                        if ip not in result:
                            result[ip] = {}
                        value = item.get('value', [None, None])[1]
                        if value is not None:
                            try:
                                result[ip][metric_name] = round(float(value), 1)
                            except (ValueError, TypeError):
                                pass
        except Exception as e:
            app.logger.debug(f'Prometheus query failed for {metric_name}: {e}')
    
    return result


@app.route('/api/auth/status')
def api_auth_status():
    """Get current authentication status and user info."""
    is_authenticated = check_auth()
    return jsonify({
        'authenticated': is_authenticated,
        'username': session.get('username') if is_authenticated else None,
        'role': session.get('role') if is_authenticated else None,
        'auth_via': session.get('auth_via') if is_authenticated else None,
        'is_proxy_auth': is_running_behind_proxy(),
        'permissions': {
            'can_read': is_authenticated,
            'can_write': is_authenticated and session.get('role') in ['admin', 'readwrite'],
            'can_admin': is_authenticated and session.get('role') == 'admin'
        } if is_authenticated else {
            'can_read': False,
            'can_write': False,
            'can_admin': False
        }
    })

@app.route('/api/servers')
@login_required
def api_servers():
    """Get all monitored servers."""
    servers = Server.query.all()
    return jsonify([{
        'id': s.id,
        'name': s.name,
        'server_ip': s.server_ip,
        'status': s.status,
        'gpu_count': s.gpu_count,
        # Installation status
        'node_exporter': s.node_exporter_installed,
        'dc_exporter': s.dc_exporter_installed,
        'dcgm_exporter': s.dcgm_exporter_installed,
        # Enabled status (for Prometheus scraping)
        'node_exporter_enabled': s.node_exporter_enabled,
        'dc_exporter_enabled': s.dc_exporter_enabled,
        'dcgm_exporter_enabled': s.dcgm_exporter_enabled,
        # Version info
        'node_exporter_version': s.node_exporter_version,
        'dc_exporter_version': s.dc_exporter_version,
        'dcgm_exporter_version': s.dcgm_exporter_version,
        # Auto-update settings
        'node_exporter_auto_update': s.node_exporter_auto_update,
        'dc_exporter_auto_update': s.dc_exporter_auto_update,
        'dcgm_exporter_auto_update': s.dcgm_exporter_auto_update,
        'exporter_update_branch': s.exporter_update_branch,
        'last_seen': s.last_seen.isoformat() if s.last_seen else None,
        # DC Watchdog agent status
        'watchdog_agent': s.watchdog_agent_installed,
        'watchdog_agent_enabled': s.watchdog_agent_enabled,
        'watchdog_agent_version': s.watchdog_agent_version,
        'watchdog_agent_last_seen': s.watchdog_agent_last_seen.isoformat() if s.watchdog_agent_last_seen else None
    } for s in servers])

@app.route('/api/servers', methods=['POST'])
@csrf.exempt  # Exempt for internal API calls with X-Fleet-Auth headers
@write_required
def api_add_server():
    """Add a new server to monitor with input validation."""
    data = request.json
    
    if not data.get('name') or not data.get('server_ip'):
        return jsonify({'error': 'name and server_ip required'}), 400
    
    # SECURITY: Validate all inputs
    try:
        validated_name = validate_hostname(data['name'])
        validated_ip = validate_ip_address(data['server_ip'])
        validated_user = validate_ssh_username(data.get('ssh_user', 'root'))
        validated_port = validate_port(data.get('ssh_port', 22))
    except ValueError as e:
        app.logger.warning(f"Invalid server input from {get_client_ip()}: {e}")
        return jsonify({'error': str(e)}), 400
    
    # Check for duplicate
    existing = Server.query.filter(
        (Server.name == validated_name) | (Server.server_ip == validated_ip)
    ).first()
    if existing:
        return jsonify({'error': 'Server with this name or IP already exists'}), 409
    
    # Validate SSH key if provided
    ssh_key_id = data.get('ssh_key_id')
    if ssh_key_id:
        ssh_key_id = int(ssh_key_id)
        key = SSHKey.query.get(ssh_key_id)
        if not key:
            return jsonify({'error': 'SSH key not found'}), 404
    
    server = Server(
        name=validated_name,
        server_ip=validated_ip,
        ssh_user=validated_user,
        ssh_port=validated_port,
        ssh_key_id=ssh_key_id,
        ssh_password=data.get('ssh_password') or None
    )
    
    # Allow setting watchdog agent status (e.g., from quickstart after deploying agents)
    if data.get('watchdog_agent_installed'):
        server.watchdog_agent_installed = True
        server.watchdog_agent_enabled = True
    if data.get('watchdog_agent_version'):
        server.watchdog_agent_version = data['watchdog_agent_version']
    
    db.session.add(server)
    db.session.commit()
    
    app.logger.info(f"Server added: {validated_name} ({validated_ip}) by {session.get('username', 'unknown')}")
    
    # Update Prometheus config
    update_prometheus_targets()
    
    return jsonify({'id': server.id, 'message': 'Server added'}), 201

@app.route('/api/servers/<int:server_id>', methods=['DELETE'])
@write_required
def api_delete_server(server_id):
    """Remove a server from monitoring."""
    server = Server.query.get_or_404(server_id)
    db.session.delete(server)
    db.session.commit()
    
    # Update Prometheus config
    update_prometheus_targets()
    
    return jsonify({'message': 'Server removed'})

@app.route('/api/servers/<int:server_id>/check')
@login_required
def api_check_server(server_id):
    """Check server connectivity and exporter status."""
    from .exporters import get_exporter_version, check_for_updates, get_latest_exporter_version
    
    server = Server.query.get_or_404(server_id)
    
    results = {
        'server_ip': server.server_ip,
        'server_id': server.id,
        'server_name': server.name,
        'ssh': check_ssh_connection(server),
        'node_exporter': check_exporter(server.server_ip, 9100),
        'dc_exporter': check_exporter(server.server_ip, 9835),
        'dcgm_exporter': check_exporter(server.server_ip, 9400),
        'watchdog_agent': check_watchdog_agent(server)
    }
    
    # Update server status
    server.node_exporter_installed = results['node_exporter']['running']
    server.dc_exporter_installed = results['dc_exporter']['running']
    server.dcgm_exporter_installed = results['dcgm_exporter']['running']
    
    # Update watchdog DB state from the check result
    wd_result = results['watchdog_agent']
    if wd_result.get('source') != 'database':  # Don't re-save cached data as new data
        server.watchdog_agent_installed = wd_result.get('installed', False)
        server.watchdog_agent_enabled = wd_result.get('running', False)
        if wd_result.get('version'):
            server.watchdog_agent_version = wd_result['version']
    
    if any([results['node_exporter']['running'], results['dc_exporter']['running']]):
        server.status = 'online'
        server.last_seen = datetime.utcnow()
    else:
        server.status = 'offline'
    
    # Include status and last_seen in response
    results['status'] = server.status
    results['last_seen'] = server.last_seen.strftime('%Y-%m-%d %H:%M') if server.last_seen else None
    
    # Get GPU count from dc-exporter metrics
    gpu_count = get_gpu_count_from_exporter(server.server_ip)
    if gpu_count is not None:
        server.gpu_count = gpu_count
    results['gpu_count'] = server.gpu_count or 0
    
    # Detect exporter versions
    ssh_key_path = resolve_ssh_key_path(server)
    ssh_password = server.ssh_password
    
    if server.node_exporter_installed:
        version = get_exporter_version(server.server_ip, 'node_exporter', server.ssh_user, server.ssh_port, ssh_key_path, ssh_password)
        if version:
            server.node_exporter_version = version
            results['node_exporter']['version'] = version
    
    if server.dc_exporter_installed:
        version = get_exporter_version(server.server_ip, 'dc_exporter', server.ssh_user, server.ssh_port, ssh_key_path, ssh_password)
        if version:
            server.dc_exporter_version = version
            results['dc_exporter']['version'] = version
    
    if server.dcgm_exporter_installed:
        version = get_exporter_version(server.server_ip, 'dcgm_exporter', server.ssh_user, server.ssh_port, ssh_key_path, ssh_password)
        if version:
            server.dcgm_exporter_version = version
            results['dcgm_exporter']['version'] = version
    
    db.session.commit()
    
    # Check for auto-updates (async, non-blocking)
    results['auto_updates'] = check_and_apply_auto_updates(server)
    
    return jsonify(results)


def check_and_apply_auto_updates(server):
    """Check and apply auto-updates for exporters that have auto-update enabled."""
    from .exporters import check_for_updates
    
    updates_applied = []
    
    try:
        ssh_key_path = resolve_ssh_key_path(server)
        update_info = check_for_updates(
            server.server_ip,
            server.ssh_user,
            server.ssh_port,
            ssh_key_path,
            ssh_password=server.ssh_password,
            branch=server.exporter_update_branch or 'main'
        )
        
        # Check each exporter for auto-update
        exporters_to_check = [
            ('node_exporter', server.node_exporter_auto_update, server.node_exporter_installed),
            ('dc_exporter', server.dc_exporter_auto_update, server.dc_exporter_installed),
            ('dcgm_exporter', server.dcgm_exporter_auto_update, server.dcgm_exporter_installed),
        ]
        
        for exporter, auto_update, installed in exporters_to_check:
            if auto_update and installed:
                exp_info = update_info.get(exporter, {})
                if exp_info.get('update_available'):
                    # Apply update
                    latest_version = exp_info.get('latest')
                    success = update_exporter_remote(server, exporter, latest_version, server.exporter_update_branch or 'main')
                    if success:
                        # Update version in database
                        if exporter == 'node_exporter':
                            server.node_exporter_version = latest_version
                        elif exporter == 'dc_exporter':
                            server.dc_exporter_version = latest_version
                        elif exporter == 'dcgm_exporter':
                            server.dcgm_exporter_version = latest_version
                        
                        updates_applied.append({
                            'exporter': exporter,
                            'from_version': exp_info.get('installed'),
                            'to_version': latest_version
                        })
        
        if updates_applied:
            db.session.commit()
            
    except Exception:
        pass  # Non-critical operation
    
    return updates_applied


def get_gpu_count_from_exporter(server_ip):
    """Query dc-exporter to get GPU count."""
    import urllib.request
    import urllib.error
    
    try:
        url = f"http://{server_ip}:9835/metrics"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as response:
            metrics = response.read().decode('utf-8')
            # Count unique GPU entries from DCXP_GPU_SUPPORTED metric
            gpu_count = 0
            for line in metrics.split('\n'):
                if line.startswith('DCXP_GPU_SUPPORTED{'):
                    gpu_count += 1
            return gpu_count
    except:
        return None

@app.route('/api/servers/<int:server_id>/install-exporters', methods=['POST'])
@csrf.exempt  # Session-authenticated internal API
@write_required
def api_install_exporters(server_id):
    """Install exporters on a remote server."""
    server = Server.query.get_or_404(server_id)
    data = request.json or {}
    
    exporters = data.get('exporters', ['node_exporter', 'dc_exporter'])
    
    results = {}
    for exporter in exporters:
        success = install_exporter_remote(server, exporter)
        results[exporter] = 'installed' if success else 'failed'
    
    return jsonify(results)

@app.route('/api/servers/<int:server_id>/remove-exporters', methods=['POST'])
@csrf.exempt  # Session-authenticated internal API
@write_required
def api_remove_exporters(server_id):
    """Remove exporters from a remote server."""
    server = Server.query.get_or_404(server_id)
    data = request.json or {}
    
    exporters = data.get('exporters', ['node_exporter', 'dc_exporter'])
    
    results = {}
    for exporter in exporters:
        success = remove_exporter_remote(server, exporter)
        results[exporter] = 'removed' if success else 'failed'
        
        # Update server record
        if success:
            if exporter == 'node_exporter':
                server.node_exporter_installed = False
            elif exporter == 'dc_exporter':
                server.dc_exporter_installed = False
            elif exporter == 'dcgm_exporter':
                server.dcgm_exporter_installed = False
    
    db.session.commit()
    update_prometheus_targets()
    
    return jsonify(results)

# =============================================================================
# EXPORTER MANAGEMENT API
# =============================================================================

@app.route('/api/servers/<int:server_id>/exporters/versions')
@login_required
def api_get_exporter_versions(server_id):
    """Get versions of all exporters on a server."""
    from .exporters import get_all_exporter_versions, check_for_updates
    
    server = Server.query.get_or_404(server_id)
    
    # Get SSH credentials
    ssh_key_path = resolve_ssh_key_path(server)
    ssh_password = server.ssh_password
    
    # Get installed versions
    versions = get_all_exporter_versions(
        server.server_ip,
        server.ssh_user,
        server.ssh_port,
        ssh_key_path,
        ssh_password
    )
    
    # Check for updates
    updates = check_for_updates(
        server.server_ip,
        server.ssh_user,
        server.ssh_port,
        ssh_key_path,
        ssh_password=ssh_password,
        branch=server.exporter_update_branch
    )
    
    # Update version info in database
    if versions.get('node_exporter'):
        server.node_exporter_version = versions['node_exporter']
    if versions.get('dc_exporter'):
        server.dc_exporter_version = versions['dc_exporter']
    if versions.get('dcgm_exporter'):
        server.dcgm_exporter_version = versions['dcgm_exporter']
    
    db.session.commit()
    
    # Also get watchdog agent status
    watchdog_status = check_watchdog_agent(server)
    # Update DB unless we only got cached DB data back
    if watchdog_status.get('source') not in ('database', 'none'):
        server.watchdog_agent_installed = watchdog_status.get('installed', False)
        server.watchdog_agent_enabled = watchdog_status.get('running', False)
        if watchdog_status.get('version'):
            server.watchdog_agent_version = watchdog_status['version']
        db.session.commit()
    
    return jsonify({
        'server_id': server_id,
        'server_name': server.name,
        'versions': versions,
        'updates': updates,
        'watchdog_agent': {
            'installed': server.watchdog_agent_installed,
            'enabled': server.watchdog_agent_enabled,
            'version': server.watchdog_agent_version,
            'status': watchdog_status.get('status', 'unknown'),
            'source': watchdog_status.get('source')
        }
    })


@app.route('/api/servers/<int:server_id>/exporters/<exporter>/toggle', methods=['POST'])
@csrf.exempt  # Session-authenticated internal API
@write_required
def api_toggle_exporter(server_id, exporter):
    """Enable or disable an exporter on a server."""
    server = Server.query.get_or_404(server_id)
    
    if exporter not in ['node_exporter', 'dc_exporter', 'dcgm_exporter']:
        return jsonify({'error': f'Unknown exporter: {exporter}'}), 400
    
    data = request.json or {}
    enabled = data.get('enabled')
    
    # If enabled not specified, toggle current state
    if enabled is None:
        if exporter == 'node_exporter':
            enabled = not server.node_exporter_enabled
        elif exporter == 'dc_exporter':
            enabled = not server.dc_exporter_enabled
        elif exporter == 'dcgm_exporter':
            enabled = not server.dcgm_exporter_enabled
    
    # Control the service via SSH
    success = toggle_exporter_service(server, exporter, enabled)
    
    if success:
        # Update database
        if exporter == 'node_exporter':
            server.node_exporter_enabled = enabled
        elif exporter == 'dc_exporter':
            server.dc_exporter_enabled = enabled
        elif exporter == 'dcgm_exporter':
            server.dcgm_exporter_enabled = enabled
        
        db.session.commit()
        
        # Update Prometheus targets
        update_prometheus_targets()
        
        return jsonify({
            'success': True,
            'exporter': exporter,
            'enabled': enabled,
            'message': f'{exporter} {"enabled" if enabled else "disabled"}'
        })
    else:
        return jsonify({
            'success': False,
            'error': f'Failed to {"start" if enabled else "stop"} {exporter}'
        }), 500


@app.route('/api/servers/<int:server_id>/exporters/<exporter>/update', methods=['POST'])
@csrf.exempt  # Session-authenticated internal API
@write_required
def api_update_exporter(server_id, exporter):
    """Update an exporter to the latest version."""
    from .exporters import get_latest_exporter_version, get_exporter_download_url
    
    server = Server.query.get_or_404(server_id)
    
    if exporter not in ['node_exporter', 'dc_exporter', 'dcgm_exporter']:
        return jsonify({'error': f'Unknown exporter: {exporter}'}), 400
    
    data = request.json or {}
    branch = data.get('branch', server.exporter_update_branch or 'main')
    
    # Get latest version
    latest_version = get_latest_exporter_version(exporter, branch)
    if not latest_version:
        return jsonify({'error': 'Could not determine latest version'}), 500
    
    # Update the exporter
    success, error_msg = update_exporter_remote(server, exporter, latest_version, branch)
    
    if success:
        # Update version in database
        if exporter == 'node_exporter':
            server.node_exporter_version = latest_version
        elif exporter == 'dc_exporter':
            server.dc_exporter_version = latest_version
        elif exporter == 'dcgm_exporter':
            server.dcgm_exporter_version = latest_version
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'exporter': exporter,
            'version': latest_version,
            'message': f'{exporter} updated to {latest_version}'
        })
    else:
        return jsonify({
            'success': False,
            'error': f'Failed to update {exporter}: {error_msg or "Unknown error"}'
        }), 500


@app.route('/api/servers/<int:server_id>/exporters/settings', methods=['POST'])
@csrf.exempt  # Session-authenticated internal API
@write_required
def api_update_exporter_settings(server_id):
    """Update exporter settings (auto-update, branch)."""
    server = Server.query.get_or_404(server_id)
    data = request.json or {}
    
    # Update auto-update settings
    if 'node_exporter_auto_update' in data:
        server.node_exporter_auto_update = bool(data['node_exporter_auto_update'])
    if 'dc_exporter_auto_update' in data:
        server.dc_exporter_auto_update = bool(data['dc_exporter_auto_update'])
    if 'dcgm_exporter_auto_update' in data:
        server.dcgm_exporter_auto_update = bool(data['dcgm_exporter_auto_update'])
    
    # Update branch preference
    if 'exporter_update_branch' in data:
        branch = data['exporter_update_branch']
        if branch in ['main', 'dev']:
            server.exporter_update_branch = branch
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'settings': {
            'node_exporter_auto_update': server.node_exporter_auto_update,
            'dc_exporter_auto_update': server.dc_exporter_auto_update,
            'dcgm_exporter_auto_update': server.dcgm_exporter_auto_update,
            'exporter_update_branch': server.exporter_update_branch
        }
    })


# =============================================================================
# DC WATCHDOG AGENT API
# =============================================================================

@app.route('/api/servers/<int:server_id>/watchdog/status')
@login_required
def api_watchdog_status(server_id):
    """Get DC Watchdog agent status for a server."""
    server = Server.query.get_or_404(server_id)
    status = check_watchdog_agent(server)
    
    # Update server record unless we only got cached DB data back
    if status.get('source') != 'database' and status.get('source') != 'none':
        server.watchdog_agent_installed = status.get('installed', False)
        server.watchdog_agent_enabled = status.get('running', False)
        if status.get('version'):
            server.watchdog_agent_version = status['version']
        db.session.commit()
    
    return jsonify({
        'server_id': server.id,
        'server_name': server.name,
        'watchdog_agent': status,
        'last_seen': server.watchdog_agent_last_seen.isoformat() if server.watchdog_agent_last_seen else None
    })


@app.route('/api/servers/<int:server_id>/watchdog/toggle', methods=['POST'])
@csrf.exempt
@write_required
def api_toggle_watchdog(server_id):
    """Enable or disable DC Watchdog agent on a server."""
    server = Server.query.get_or_404(server_id)
    
    data = request.json or {}
    enabled = data.get('enabled')
    
    # If enabled not specified, toggle current state
    if enabled is None:
        enabled = not server.watchdog_agent_enabled
    
    # Control the service via SSH
    success = toggle_watchdog_service(server, enabled)
    
    if success:
        server.watchdog_agent_enabled = enabled
        db.session.commit()
        
        return jsonify({
            'success': True,
            'enabled': enabled,
            'message': f'DC Watchdog agent {"enabled" if enabled else "disabled"}'
        })
    else:
        return jsonify({
            'success': False,
            'error': f'Failed to {"start" if enabled else "stop"} watchdog agent'
        }), 500


def toggle_watchdog_service(server, enabled: bool) -> bool:
    """Start or stop dc-watchdog-agent service on a server via SSH."""
    try:
        cmd, env = build_ssh_cmd(server, timeout=10)
        
        if enabled:
            cmd.append('systemctl start dc-watchdog-agent')
        else:
            cmd.append('systemctl stop dc-watchdog-agent')
        
        run_env = {**os.environ, **env} if env else None
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15, env=run_env)
        return result.returncode == 0
    except Exception as e:
        app.logger.error(f"Error toggling watchdog agent on {server.name}: {e}")
        return False


# New watchdog-agent endpoints (for UI consistency)
@app.route('/api/servers/<int:server_id>/watchdog-agent/toggle', methods=['POST'])
@csrf.exempt
@write_required
def api_toggle_watchdog_agent(server_id):
    """Toggle DC Watchdog agent on a server (alias for /watchdog/toggle)."""
    return api_toggle_watchdog(server_id)


@app.route('/api/servers/<int:server_id>/watchdog-agent/install', methods=['POST'])
@csrf.exempt
@write_required
def api_install_watchdog_agent(server_id):
    """Install DC Watchdog agent on a server."""
    server = Server.query.get_or_404(server_id)
    
    # Get watchdog API key from settings or environment
    api_key = get_watchdog_api_key()
    
    if not api_key:
        return jsonify({
            'success': False,
            'error': 'DC Watchdog API key not configured'
        }), 400
    
    success, error = install_watchdog_agent_remote(server, api_key)
    
    if success:
        server.watchdog_agent_installed = True
        server.watchdog_agent_enabled = True
        db.session.commit()
        return jsonify({'success': True, 'message': 'DC Watchdog agent installed'})
    else:
        return jsonify({'success': False, 'error': error}), 500


@app.route('/api/servers/<int:server_id>/watchdog-agent/reinstall', methods=['POST'])
@csrf.exempt
@write_required
def api_reinstall_watchdog_agent(server_id):
    """Reinstall DC Watchdog agent on a server."""
    server = Server.query.get_or_404(server_id)
    
    # First remove, then install
    remove_watchdog_agent_remote(server)
    
    # Get API key and reinstall
    api_key = get_watchdog_api_key()
    
    if not api_key:
        return jsonify({
            'success': False,
            'error': 'DC Watchdog API key not configured'
        }), 400
    
    success, error = install_watchdog_agent_remote(server, api_key)
    
    if success:
        server.watchdog_agent_installed = True
        server.watchdog_agent_enabled = True
        db.session.commit()
        return jsonify({'success': True, 'message': 'DC Watchdog agent reinstalled'})
    else:
        return jsonify({'success': False, 'error': error}), 500


@app.route('/api/servers/<int:server_id>/watchdog-agent/remove', methods=['POST'])
@csrf.exempt
@write_required
def api_remove_watchdog_agent(server_id):
    """Remove DC Watchdog agent from a server."""
    server = Server.query.get_or_404(server_id)
    
    success = remove_watchdog_agent_remote(server)
    
    if success:
        server.watchdog_agent_installed = False
        server.watchdog_agent_enabled = False
        db.session.commit()
        return jsonify({'success': True, 'message': 'DC Watchdog agent removed'})
    else:
        return jsonify({'success': False, 'error': 'Failed to remove agent'}), 500


@app.route('/api/watchdog-agent/latest')
@login_required
def api_watchdog_latest_release():
    """Get the latest DC Watchdog agent release from GitHub."""
    release = get_watchdog_latest_release()
    if release:
        return jsonify({
            'success': True,
            'version': release.get('version', ''),
            'tag': release.get('tag', ''),
            'name': release.get('name', '')
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Could not fetch latest release from GitHub'
        }), 502


@app.route('/api/watchdog-agents/deploy-all', methods=['POST'])
@csrf.exempt
@write_required
def api_deploy_watchdog_agents_all():
    """Deploy DC Watchdog agents to all configured servers.
    
    This endpoint is called from the Fleet Management landing page
    to deploy agents to all servers in bulk.
    """
    # Get watchdog API key from settings or environment
    api_key = get_watchdog_api_key()
    
    if not api_key:
        return jsonify({
            'success': False,
            'error': 'No API key configured. Set WATCHDOG_API_KEY or configure in yaml.'
        }), 400
    
    # Get all servers
    servers = Server.query.all()
    if not servers:
        return jsonify({
            'success': False,
            'error': 'No servers configured. Add servers first.'
        }), 400
    
    results = {
        'total': len(servers),
        'installed': 0,
        'failed': 0,
        'skipped': 0,
        'details': []
    }
    
    for server in servers:
        # Skip if already installed
        if server.watchdog_agent_installed:
            results['skipped'] += 1
            results['details'].append({
                'server': server.name,
                'status': 'skipped',
                'message': 'Already installed'
            })
            continue
        
        success, error = install_watchdog_agent_remote(server, api_key)
        
        if success:
            server.watchdog_agent_installed = True
            server.watchdog_agent_enabled = True
            results['installed'] += 1
            results['details'].append({
                'server': server.name,
                'status': 'installed',
                'message': 'Agent installed successfully'
            })
        else:
            results['failed'] += 1
            results['details'].append({
                'server': server.name,
                'status': 'failed',
                'message': error or 'Unknown error'
            })
    
    db.session.commit()
    
    results['success'] = results['failed'] == 0
    results['message'] = f"Installed: {results['installed']}, Skipped: {results['skipped']}, Failed: {results['failed']}"
    
    return jsonify(results)


@app.route('/api/watchdog-agents/status', methods=['GET'])
@csrf.exempt
def api_watchdog_agents_status():
    """Get status of DC Watchdog agents across all servers.
    
    Returns summary for the Fleet Management dashboard.
    Also syncs agent status from the dc-watchdog server API.
    """
    # First, sync status from watchdog API (same method as Fleet Management dashboard)
    _sync_watchdog_status_from_api()
    
    servers = Server.query.all()
    
    installed = sum(1 for s in servers if s.watchdog_agent_installed)
    enabled = sum(1 for s in servers if s.watchdog_agent_installed and s.watchdog_agent_enabled)
    
    # Check if API key is configured
    api_key = get_watchdog_api_key()
    
    return jsonify({
        'configured': bool(api_key),
        'has_api_key': bool(api_key),
        'total_servers': len(servers),
        'installed': installed,
        'enabled': enabled,
        'not_installed': len(servers) - installed,
        'site_id': get_site_id(),
    })


@app.route('/api/watchdog-agents/sync', methods=['POST', 'GET'])
@csrf.exempt
def api_watchdog_agents_sync():
    """Sync watchdog agent status from dc-watchdog server API.
    
    Updates all server records with live heartbeat data from the
    dc-watchdog server. This is more reliable than SSH checks.
    """
    updated = _sync_watchdog_status_from_api()
    return jsonify({'synced': updated, 'message': f'Updated {updated} server records'})


def _sync_watchdog_status_from_api():
    """Sync watchdog agent status from the dc-watchdog server API into the database.
    
    Matches agents by worker_id to server name (case-insensitive).
    Returns the number of servers updated.
    """
    agents_map = get_watchdog_agents_from_api()
    if not agents_map:
        return 0
    
    servers = Server.query.all()
    updated = 0
    
    for server in servers:
        agent_info = agents_map.get(server.name.lower())
        if agent_info:
            server.watchdog_agent_installed = True
            server.watchdog_agent_enabled = agent_info.get('online', False)
            if agent_info.get('version'):
                server.watchdog_agent_version = agent_info['version']
            # Update last_seen from heartbeat data
            server.watchdog_agent_last_seen = datetime.utcnow()
            updated += 1
    
    if updated > 0:
        db.session.commit()
    
    return updated


def get_watchdog_latest_release() -> dict:
    """Query GitHub API for the latest dc-watchdog agent release.
    
    Returns dict with 'version' (e.g. '1.0.2') and 'tag' (e.g. 'v1.0.2'),
    or empty dict if the API is unreachable.
    Uses a 10-minute cache to avoid hammering the API.
    """
    cache_key = '_watchdog_release_cache'
    cache = getattr(get_watchdog_latest_release, cache_key, None)
    if cache and (datetime.utcnow() - cache['fetched_at']).total_seconds() < 600:
        return cache['data']
    
    try:
        import requests as req
        resp = req.get(
            'https://api.github.com/repos/cryptolabsza/dc-watchdog/releases/latest',
            headers={'Accept': 'application/vnd.github.v3+json'},
            timeout=10
        )
        if resp.ok:
            data = resp.json()
            tag = data.get('tag_name', '')
            version = tag.lstrip('v') if tag else ''
            result = {'version': version, 'tag': tag, 'name': data.get('name', '')}
            setattr(get_watchdog_latest_release, cache_key, {
                'data': result, 'fetched_at': datetime.utcnow()
            })
            return result
    except Exception as e:
        app.logger.warning(f"Could not fetch latest watchdog release: {e}")
    
    return {}


def install_watchdog_agent_remote(server, api_key: str) -> tuple:
    """Install DC Watchdog Go agent on a remote server via SSH.
    
    Downloads the Go binary from the latest GitHub release. No bash fallback -
    the Go binary is required for:
    - Health endpoint on port 9878 for Fleet Management probing
    - Prometheus metrics at /metrics
    - GPU, RAID, network (MTR), and service monitoring
    - Proper version reporting
    
    Security: Instead of storing the API key on the worker, we first request
    a worker-specific token from dc-watchdog. This token:
    - Is unique to this worker
    - Cannot be used to access the API key
    - Can be revoked without changing the API key
    - If compromised, only affects this specific worker
    """
    WATCHDOG_URL = os.environ.get('DC_WATCHDOG_URL', 'https://watchdog.cryptolabs.co.za')
    GITHUB_REPO = "cryptolabsza/dc-watchdog"
    
    try:
        # Step 1: Request a worker token from dc-watchdog
        import requests as req
        
        worker_token = None
        try:
            token_resp = req.post(
                f'{WATCHDOG_URL}/api/worker/register',
                json={'worker_id': server.name},
                params={'api_key': api_key},
                timeout=30
            )
            
            if token_resp.ok:
                token_data = token_resp.json()
                if token_data.get('success'):
                    worker_token = token_data.get('worker_token')
                    app.logger.info(f"Worker token obtained for {server.name}")
                else:
                    return False, token_data.get('error', 'Failed to get worker token')
            else:
                app.logger.warning(f"Could not get worker token (status {token_resp.status_code}), using API key")
        except req.RequestException as e:
            app.logger.warning(f"Could not reach dc-watchdog for token: {e}, using API key")
        
        # Check latest release version for logging
        latest = get_watchdog_latest_release()
        latest_ver = latest.get('version', 'unknown')
        app.logger.info(f"Installing watchdog agent on {server.name} (latest release: {latest_ver})")
        
        # Step 2: Build SSH command and deploy the Go agent
        cmd, ssh_env = build_ssh_cmd(server, timeout=60)
        
        # Use worker token if available, otherwise API key directly
        auth_key = worker_token if worker_token else api_key
        
        install_script = f'''
set -e

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/dc-watchdog"
GITHUB_REPO="{GITHUB_REPO}"

echo "[+] Installing DC-Watchdog Agent (Go binary)..."

# Stop existing agent if running
systemctl stop dc-watchdog-agent 2>/dev/null || true

# Create directories
mkdir -p "$CONFIG_DIR"

# Install dependencies (mtr for network diagnostics)
echo "[+] Installing dependencies..."
if command -v apt-get &> /dev/null; then
    apt-get update -qq 2>/dev/null || true
    apt-get install -y -qq mtr-tiny curl 2>/dev/null || true
elif command -v yum &> /dev/null; then
    yum install -y -q mtr curl 2>/dev/null || true
elif command -v dnf &> /dev/null; then
    dnf install -y -q mtr curl 2>/dev/null || true
fi

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)  ARCH_SUFFIX="linux-amd64" ;;
    aarch64) ARCH_SUFFIX="linux-arm64" ;;
    *)
        echo "INSTALL_FAILED: Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Download Go agent binary (required - no bash fallback)
echo "[+] Downloading Go agent for $ARCH_SUFFIX..."
DOWNLOAD_OK=false

# Primary: Download from DC Watchdog server
AGENT_URL="{WATCHDOG_URL}/agent/dc-watchdog-agent-$ARCH_SUFFIX"
if curl -fsSL "$AGENT_URL" -o "$INSTALL_DIR/dc-watchdog-agent.tmp" 2>/dev/null; then
    if [ -s "$INSTALL_DIR/dc-watchdog-agent.tmp" ]; then
        mv "$INSTALL_DIR/dc-watchdog-agent.tmp" "$INSTALL_DIR/dc-watchdog-agent"
        chmod +x "$INSTALL_DIR/dc-watchdog-agent"
        if "$INSTALL_DIR/dc-watchdog-agent" -version 2>/dev/null; then
            DOWNLOAD_OK=true
            echo "[+] Go agent downloaded from watchdog server"
        fi
    fi
fi

# Fallback: Try GitHub releases (always fetches latest)
if [ "$DOWNLOAD_OK" = "false" ]; then
    echo "[+] Trying GitHub releases (latest)..."
    RELEASE_URL="https://github.com/$GITHUB_REPO/releases/latest/download/dc-watchdog-agent-$ARCH_SUFFIX"
    if curl -fsSL "$RELEASE_URL" -o "$INSTALL_DIR/dc-watchdog-agent.tmp" 2>/dev/null; then
        if [ -s "$INSTALL_DIR/dc-watchdog-agent.tmp" ]; then
            mv "$INSTALL_DIR/dc-watchdog-agent.tmp" "$INSTALL_DIR/dc-watchdog-agent"
            chmod +x "$INSTALL_DIR/dc-watchdog-agent"
            if "$INSTALL_DIR/dc-watchdog-agent" -version 2>/dev/null; then
                DOWNLOAD_OK=true
                echo "[+] Go agent downloaded from GitHub releases"
            fi
        fi
    fi
fi

rm -f "$INSTALL_DIR/dc-watchdog-agent.tmp" 2>/dev/null

# Fail if we couldn't get the Go binary - no bash fallback
if [ "$DOWNLOAD_OK" = "false" ]; then
    echo "INSTALL_FAILED: Could not download Go agent binary from watchdog server or GitHub releases"
    exit 1
fi

# Detect GPU availability
HAS_GPU=false
if command -v nvidia-smi &> /dev/null; then
    if timeout 5 nvidia-smi -L &> /dev/null; then
        HAS_GPU=true
    fi
fi

# Set monitoring level based on GPU availability
if [ "$HAS_GPU" = "true" ]; then
    MONITOR_LEVEL="standard"
else
    MONITOR_LEVEL="basic"
fi

# Create YAML configuration for Go agent
echo "[+] Creating configuration..."
cat > "$CONFIG_DIR/agent.yaml" << YAMLEOF
# DC-Watchdog Agent Configuration
server_url: "{WATCHDOG_URL}"
api_key: "{auth_key}"
worker_name: "{server.name}"
heartbeat_interval: 30s
level: $MONITOR_LEVEL

# Health endpoint for Fleet Management probing (port 9878)
health_port: 9878

gpu:
  enabled: $HAS_GPU
  check_driver_health: true
  detect_vm_passthrough: true
  timeout_seconds: 5

network:
  mtr:
    enabled: true
    interval: 10
    hops: 15

raid:
  enabled: true
  interval: 1
  alert_on_degraded: true

log_level: info
YAMLEOF
chmod 600 "$CONFIG_DIR/agent.yaml"

# Clean up any old bash fallback agent
rm -f /opt/dc-watchdog/dc-watchdog-agent.sh 2>/dev/null

# Create systemd service (Go binary only)
echo "[+] Creating systemd service..."
cat > /etc/systemd/system/dc-watchdog-agent.service << 'SVCEOF'
[Unit]
Description=DC-Watchdog Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/dc-watchdog-agent -config /etc/dc-watchdog/agent.yaml
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal
MemoryLimit=128M

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable dc-watchdog-agent
systemctl restart dc-watchdog-agent

# Verify agent starts and stays running
sleep 3
if ! systemctl is-active --quiet dc-watchdog-agent; then
    echo "INSTALL_FAILED: Agent crashed on startup"
    journalctl -u dc-watchdog-agent -n 5 --no-pager 2>/dev/null || true
    exit 1
fi

sleep 3
if ! systemctl is-active --quiet dc-watchdog-agent; then
    echo "INSTALL_FAILED: Agent crashed after startup"
    journalctl -u dc-watchdog-agent -n 5 --no-pager 2>/dev/null || true
    exit 1
fi

VERSION=$("$INSTALL_DIR/dc-watchdog-agent" -version 2>&1 | head -1 || echo "unknown")
echo "AGENT_VERSION=$VERSION"
echo "INSTALL_SUCCESS"
'''
        cmd.append(install_script)
        
        run_env = {**os.environ, **ssh_env} if ssh_env else None
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180, env=run_env)
        
        if result.returncode == 0 and 'INSTALL_SUCCESS' in result.stdout:
            # Extract version if reported
            for line in result.stdout.splitlines():
                if line.startswith('AGENT_VERSION='):
                    version_str = line.split('=', 1)[1].strip()
                    # Parse "dc-watchdog-agent version 1.0.2" or just "1.0.2"
                    import re
                    ver_match = re.search(r'(\d+\.\d+\.\d+)', version_str)
                    if ver_match:
                        server.watchdog_agent_version = ver_match.group(1)
            return True, None
        else:
            error = result.stderr.strip() or result.stdout.strip() or 'Unknown error'
            return False, error[:300]
    except subprocess.TimeoutExpired:
        return False, 'SSH connection timed out (180s)'
    except Exception as e:
        app.logger.exception(f"Error installing watchdog agent on {server.name}")
        return False, str(e)[:200]


def remove_watchdog_agent_remote(server) -> bool:
    """Remove DC Watchdog agent from a remote server via SSH."""
    try:
        cmd, env = build_ssh_cmd(server, timeout=15)
        
        remove_script = '''
systemctl stop dc-watchdog-agent 2>/dev/null || true
systemctl disable dc-watchdog-agent 2>/dev/null || true
rm -f /etc/systemd/system/dc-watchdog-agent.service
rm -f /usr/local/bin/dc-watchdog-agent
rm -rf /etc/dc-watchdog
rm -rf /opt/dc-watchdog
systemctl daemon-reload
echo "REMOVE_SUCCESS"
'''
        cmd.append(remove_script)
        
        run_env = {**os.environ, **env} if env else None
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=run_env)
        return result.returncode == 0 and 'REMOVE_SUCCESS' in result.stdout
    except Exception as e:
        app.logger.error(f"Error removing watchdog agent on {server.name}: {e}")
        return False


@app.route('/api/exporters/updates')
@login_required
def api_check_all_updates():
    """Check all servers for exporter updates."""
    from .exporters import get_all_latest_versions, get_exporter_version
    
    servers = Server.query.all()
    latest = get_all_latest_versions('main')  # Get main branch versions
    
    updates = []
    for server in servers:
        server_updates = {
            'server_id': server.id,
            'server_name': server.name,
            'exporters': {}
        }
        
        ssh_key_path = resolve_ssh_key_path(server)
        
        for exporter, latest_ver in latest.items():
            # Get installed attribute name
            installed_attr = f'{exporter}_installed'
            version_attr = f'{exporter}_version'
            
            is_installed = getattr(server, installed_attr, False)
            current_ver = getattr(server, version_attr, None)
            
            if is_installed and latest_ver:
                # Check if update available
                update_available = False
                if current_ver and current_ver not in ('running', 'unknown'):
                    try:
                        curr_parts = [int(x) for x in current_ver.split('.')[:3]]
                        lat_parts = [int(x) for x in latest_ver.split('.')[:3]]
                        update_available = lat_parts > curr_parts
                    except ValueError:
                        update_available = current_ver != latest_ver
                
                if update_available:
                    server_updates['exporters'][exporter] = {
                        'installed': current_ver,
                        'latest': latest_ver
                    }
        
        if server_updates['exporters']:
            updates.append(server_updates)
    
    return jsonify({
        'updates_available': len(updates) > 0,
        'servers': updates,
        'latest_versions': latest
    })


def toggle_exporter_service(server, exporter: str, enabled: bool) -> bool:
    """Start or stop an exporter service on a remote server via SSH."""
    service_names = {
        'node_exporter': 'node_exporter',
        'dc_exporter': 'dc-exporter',
        'dcgm_exporter': 'dcgm-exporter'  # Docker container
    }
    
    service = service_names.get(exporter)
    if not service:
        return False
    
    try:
        ssh_cmd, env = build_ssh_cmd(server, timeout=10)
        
        if exporter == 'dcgm_exporter':
            # Docker container
            if enabled:
                ssh_cmd.append(f"docker start {service} 2>/dev/null || echo 'not found'")
            else:
                ssh_cmd.append(f"docker stop {service} 2>/dev/null || echo 'not found'")
        else:
            # Systemd service
            action = 'start' if enabled else 'stop'
            ssh_cmd.append(f"systemctl {action} {service}")
        
        run_env = {**os.environ, **env} if env else None
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30, env=run_env)
        return result.returncode == 0
        
    except Exception:
        return False


def update_exporter_remote(server, exporter: str, version: str, branch: str = 'main') -> tuple:
    """Update an exporter on a remote server to a specific version.
    
    Returns:
        tuple: (success: bool, error_message: str or None)
    """
    from .exporters import get_exporter_download_url
    
    download_url = get_exporter_download_url(exporter, version, branch)
    if not download_url:
        return False, f"Could not get download URL for {exporter} v{version}"
    
    try:
        # Build SSH command with proper auth (key or password)
        ssh_cmd, ssh_env = build_ssh_cmd(server, timeout=15, extra_opts=['-o', 'ServerAliveInterval=10'])
        
        if exporter == 'node_exporter':
            # Download, extract, and replace binary
            update_script = f'''
set -e
cd /tmp
curl -sL "{download_url}" -o node_exporter.tar.gz
tar xzf node_exporter.tar.gz
systemctl stop node_exporter 2>/dev/null || true
cp node_exporter-*/node_exporter /usr/local/bin/
chmod +x /usr/local/bin/node_exporter
systemctl start node_exporter
rm -rf node_exporter*
echo "UPDATE_SUCCESS"
'''
            ssh_cmd.append(update_script)
            
        elif exporter == 'dc_exporter':
            # Download binary directly
            update_script = f'''
set -e
systemctl stop dc-exporter 2>/dev/null || true
curl -sL "{download_url}" -o /usr/local/bin/dc-exporter-rs
chmod +x /usr/local/bin/dc-exporter-rs
systemctl start dc-exporter
echo "UPDATE_SUCCESS"
'''
            ssh_cmd.append(update_script)
            
        elif exporter == 'dcgm_exporter':
            # Update Docker image
            update_script = f'''
set -e
docker stop dcgm-exporter 2>/dev/null || true
docker rm dcgm-exporter 2>/dev/null || true
docker pull {download_url}
docker run -d --name dcgm-exporter --gpus all -p 9400:9400 --restart unless-stopped {download_url}
echo "UPDATE_SUCCESS"
'''
            ssh_cmd.append(update_script)
        else:
            return False, f"Unknown exporter type: {exporter}"
        
        app.logger.info(f"[Exporter Update] Running: ssh -p {server.ssh_port or 22} {server.ssh_user or 'root'}@{server.server_ip}")
        run_env = {**os.environ, **ssh_env} if ssh_env else None
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=180, env=run_env)
        
        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip() or f"SSH command failed with code {result.returncode}"
            app.logger.error(f"[Exporter Update] Failed for {server.server_ip}: {error_msg[:200]}")
            return False, error_msg[:200]
        
        if 'UPDATE_SUCCESS' in result.stdout:
            app.logger.info(f"[Exporter Update] Successfully updated {exporter} on {server.server_ip}")
            return True, None
        else:
            return False, f"Update script did not complete successfully: {result.stdout[:200]}"
        
    except subprocess.TimeoutExpired:
        return False, "SSH connection timed out (180s)"
    except Exception as e:
        app.logger.exception(f"[Exporter Update] Exception updating {exporter} on {server.server_ip}")
        return False, str(e)[:200]


@app.route('/api/prometheus/targets')
@login_required
def api_prometheus_targets():
    """Get current Prometheus scrape targets."""
    servers = Server.query.all()
    targets = []
    
    for server in servers:
        server_targets = []
        if server.node_exporter_installed:
            server_targets.append(f"{server.server_ip}:9100")
        if server.dc_exporter_installed:
            server_targets.append(f"{server.server_ip}:9835")
        if server.dcgm_exporter_installed:
            server_targets.append(f"{server.server_ip}:9400")
        
        if server_targets:
            targets.append({
                'targets': server_targets,
                'labels': {
                    'instance': server.name,
                    '__meta_dc_server': server.name
                }
            })
    
    return jsonify(targets)

@app.route('/api/prometheus/targets.json')
@csrf.exempt
@limiter.limit("10 per minute")  # Rate limit unauthenticated endpoint
def api_prometheus_file_sd():
    """
    File-based service discovery for Prometheus.
    Can be used with file_sd_configs in prometheus.yml
    Note: This endpoint exposes server IPs - consider adding authentication in production.
    """
    servers = Server.query.all()
    targets = []
    
    for server in servers:
        # Node exporter targets
        if server.node_exporter_installed:
            targets.append({
                'targets': [f"{server.server_ip}:9100"],
                'labels': {
                    'instance': server.name,
                    'job': 'node-exporter'
                }
            })
        
        # DC exporter targets (VRAM, hotspot temps)
        if server.dc_exporter_installed:
            targets.append({
                'targets': [f"{server.server_ip}:9835"],
                'labels': {
                    'instance': server.name,
                    'job': 'dc-exporter'
                }
            })
        
        # DCGM exporter targets
        if server.dcgm_exporter_installed:
            targets.append({
                'targets': [f"{server.server_ip}:9400"],
                'labels': {
                    'instance': server.name,
                    'job': 'dcgm-exporter'
                }
            })
    
    return jsonify(targets)

@app.route('/api/ssh-keys')
@login_required
def api_ssh_keys():
    """List SSH keys."""
    keys = SSHKey.query.all()
    return jsonify([{
        'id': k.id,
        'name': k.name,
        'key_path': k.key_path,
        'fingerprint': k.fingerprint,
        'created_at': k.created_at.isoformat()
    } for k in keys])


@app.route('/api/ssh-keys', methods=['POST'])
@csrf.exempt  # Exempt for internal API calls with X-Fleet-Auth headers
@admin_required
def api_add_ssh_key():
    """Add a new SSH key."""
    data = request.json
    
    if not data.get('name') or not data.get('key_path'):
        return jsonify({'error': 'name and key_path required'}), 400
    
    # Check for duplicate name
    existing = SSHKey.query.filter_by(name=data['name']).first()
    if existing:
        return jsonify({'error': 'SSH key with this name already exists', 'id': existing.id}), 409
    
    # Calculate fingerprint if we can access the key
    fingerprint = data.get('fingerprint')
    if not fingerprint:
        try:
            result = subprocess.run(
                ['ssh-keygen', '-lf', data['key_path']],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                # Format: 2048 SHA256:xyz... comment (RSA)
                fingerprint = result.stdout.split()[1] if result.stdout else None
        except Exception:
            pass
    
    key = SSHKey(
        name=data['name'],
        key_path=data['key_path'],
        fingerprint=fingerprint
    )
    db.session.add(key)
    db.session.commit()
    
    return jsonify({
        'id': key.id,
        'name': key.name,
        'key_path': key.key_path,
        'fingerprint': key.fingerprint
    }), 201


@app.route('/api/ssh-keys/<int:key_id>', methods=['DELETE'])
@admin_required
def api_delete_ssh_key(key_id):
    """Delete an SSH key."""
    key = SSHKey.query.get_or_404(key_id)
    
    # Check if any servers are using this key
    servers_using = Server.query.filter_by(ssh_key_id=key_id).count()
    if servers_using > 0:
        return jsonify({'error': f'SSH key is in use by {servers_using} server(s)'}), 400
    
    db.session.delete(key)
    db.session.commit()
    
    return jsonify({'success': True})


@app.route('/api/servers/<int:server_id>/ssh-key', methods=['POST'])
@admin_required
def api_set_server_ssh_key(server_id):
    """Set the SSH key for a server."""
    server = Server.query.get_or_404(server_id)
    data = request.json or {}
    
    key_id = data.get('ssh_key_id')
    
    if key_id:
        # Verify the key exists
        key = SSHKey.query.get(key_id)
        if not key:
            return jsonify({'error': 'SSH key not found'}), 404
        server.ssh_key_id = key_id
    else:
        server.ssh_key_id = None
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'server_id': server.id,
        'ssh_key_id': server.ssh_key_id
    })

# =============================================================================
# SSH CONFIGURATION API
# =============================================================================

@app.route('/api/servers/<int:server_id>/ssh-config', methods=['GET'])
@login_required
def api_get_server_ssh_config(server_id):
    """Get SSH configuration for a server."""
    server = Server.query.get_or_404(server_id)
    ssh_keys = SSHKey.query.all()
    
    return jsonify({
        'server_id': server.id,
        'server_name': server.name,
        'ssh_user': server.ssh_user or 'root',
        'ssh_port': server.ssh_port or 22,
        'ssh_key_id': server.ssh_key_id,
        'ssh_key_name': server.ssh_key.name if server.ssh_key else None,
        'has_password': bool(server.ssh_password),
        'auth_method': 'key' if (server.ssh_key_id or resolve_ssh_key_path(server)) else ('password' if server.ssh_password else 'none'),
        'available_keys': [{
            'id': k.id,
            'name': k.name,
            'fingerprint': k.fingerprint
        } for k in ssh_keys]
    })


@app.route('/api/servers/<int:server_id>/ssh-config', methods=['POST'])
@csrf.exempt
@admin_required
def api_update_server_ssh_config(server_id):
    """Update SSH configuration for a server.
    
    Accepts:
        ssh_user: string
        ssh_port: int
        ssh_key_id: int or null (to use a registered key)
        ssh_password: string or null (for password-based auth)
    """
    server = Server.query.get_or_404(server_id)
    data = request.json or {}
    
    if 'ssh_user' in data:
        server.ssh_user = data['ssh_user'] or 'root'
    if 'ssh_port' in data:
        server.ssh_port = int(data['ssh_port']) if data['ssh_port'] else 22
    if 'ssh_key_id' in data:
        key_id = data['ssh_key_id']
        if key_id:
            key = SSHKey.query.get(key_id)
            if not key:
                return jsonify({'error': 'SSH key not found'}), 404
            server.ssh_key_id = key_id
        else:
            server.ssh_key_id = None
    if 'ssh_password' in data:
        # Set or clear the password
        server.ssh_password = data['ssh_password'] if data['ssh_password'] else None
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'server_id': server.id,
        'ssh_user': server.ssh_user,
        'ssh_port': server.ssh_port,
        'ssh_key_id': server.ssh_key_id,
        'has_password': bool(server.ssh_password)
    })


@app.route('/api/servers/<int:server_id>/ssh-test', methods=['POST'])
@csrf.exempt
@login_required
def api_test_server_ssh(server_id):
    """Test SSH connection to a server and return detailed results."""
    server = Server.query.get_or_404(server_id)
    
    result = check_ssh_connection(server)
    
    # Add auth method info
    ssh_key_path = resolve_ssh_key_path(server)
    if ssh_key_path:
        result['auth_method'] = 'key'
        result['key_path'] = ssh_key_path
    elif server.ssh_password:
        result['auth_method'] = 'password'
    else:
        result['auth_method'] = 'none'
    
    result['ssh_user'] = server.ssh_user or 'root'
    result['ssh_port'] = server.ssh_port or 22
    result['server_ip'] = server.server_ip
    
    return jsonify(result)


# =============================================================================
# VAST.AI ACCOUNT MANAGEMENT
# =============================================================================

VAST_EXPORTER_URL = os.environ.get('VAST_EXPORTER_URL', 'http://vastai-exporter:8622')

def _vast_mgmt_token() -> str:
    """Read the Vast exporter management token."""
    token_paths = [
        '/data/.vast-mgmt-token',  # Inside dc-overview container (injected by fleet_manager)
        '/etc/dc-overview/.vast-mgmt-token',
        os.path.join(get_data_dir(), '.vast-mgmt-token'),
    ]
    for path in token_paths:
        try:
            with open(path, 'r') as f:
                return f.read().strip()
        except (FileNotFoundError, PermissionError):
            continue
    return os.environ.get('VAST_MGMT_TOKEN', '')


def _vast_api_request(method: str, path: str, data: dict = None, timeout: int = 30) -> tuple:
    """Make a request to the Vast exporter management API.
    
    Returns (response_dict, status_code) tuple.
    """
    url = f"{VAST_EXPORTER_URL}{path}"
    headers = {
        'Content-Type': 'application/json',
        'X-Mgmt-Token': _vast_mgmt_token()
    }
    
    try:
        if method == 'GET':
            resp = http_requests.get(url, headers=headers, timeout=timeout)
        elif method == 'POST':
            resp = http_requests.post(url, headers=headers, json=data, timeout=timeout)
        elif method == 'DELETE':
            resp = http_requests.delete(url, headers=headers, timeout=timeout)
        else:
            return {'error': f'Unsupported method: {method}'}, 400
        
        try:
            result = resp.json()
        except Exception:
            result = {'raw': resp.text}
        
        return result, resp.status_code
    
    except http_requests.ConnectionError:
        return {'error': 'Vast.ai exporter is not running or not reachable'}, 503
    except http_requests.Timeout:
        return {'error': 'Vast.ai exporter request timed out'}, 504
    except Exception as e:
        return {'error': f'Failed to contact Vast.ai exporter: {str(e)}'}, 500


@app.route('/api/vast/accounts')
@login_required
def api_vast_accounts():
    """List Vast.ai accounts from the exporter."""
    result, status = _vast_api_request('GET', '/api/accounts')
    return jsonify(result), status


@app.route('/api/vast/accounts', methods=['POST'])
@csrf.exempt
@admin_required
def api_vast_add_account():
    """Add a Vast.ai API key account."""
    data = request.json
    if not data or not data.get('key'):
        return jsonify({'error': 'API key is required'}), 400
    
    payload = {
        'name': data.get('name', 'default'),
        'key': data['key']
    }
    
    result, status = _vast_api_request('POST', '/api/accounts', data=payload)
    return jsonify(result), status


@app.route('/api/vast/accounts/<account_name>', methods=['DELETE'])
@admin_required
def api_vast_delete_account(account_name):
    """Remove a Vast.ai API key account."""
    result, status = _vast_api_request('DELETE', f'/api/accounts/{account_name}')
    return jsonify(result), status


@app.route('/api/vast/accounts/<account_name>/test')
@login_required
def api_vast_test_account(account_name):
    """Test connectivity for a Vast.ai account."""
    result, status = _vast_api_request('GET', f'/api/accounts/{account_name}/test', timeout=30)
    return jsonify(result), status


@app.route('/api/vast/status')
@login_required
def api_vast_status():
    """Get Vast.ai exporter status."""
    result, status = _vast_api_request('GET', '/api/status')
    return jsonify(result), status


# =============================================================================
# RUNPOD ACCOUNT MANAGEMENT
# =============================================================================

RUNPOD_EXPORTER_URL = os.environ.get('RUNPOD_EXPORTER_URL', 'http://runpod-exporter:8623')

def _runpod_mgmt_token() -> str:
    """Read the RunPod exporter management token."""
    token_paths = [
        '/data/.runpod-mgmt-token',  # Inside dc-overview container
        '/etc/dc-overview/.runpod-mgmt-token',
        os.path.join(get_data_dir(), '.runpod-mgmt-token'),
    ]
    for path in token_paths:
        try:
            with open(path, 'r') as f:
                return f.read().strip()
        except (FileNotFoundError, PermissionError):
            continue
    return os.environ.get('RUNPOD_MGMT_TOKEN', '')


def _runpod_api_request(method: str, path: str, data: dict = None, timeout: int = 30) -> tuple:
    """Make a request to the RunPod exporter management API.
    
    Returns (response_dict, status_code) tuple.
    """
    url = f"{RUNPOD_EXPORTER_URL}{path}"
    headers = {
        'Content-Type': 'application/json',
        'X-Mgmt-Token': _runpod_mgmt_token()
    }
    
    try:
        if method == 'GET':
            resp = http_requests.get(url, headers=headers, timeout=timeout)
        elif method == 'POST':
            resp = http_requests.post(url, headers=headers, json=data, timeout=timeout)
        elif method == 'DELETE':
            resp = http_requests.delete(url, headers=headers, timeout=timeout)
        else:
            return {'error': f'Unsupported method: {method}'}, 400
        
        try:
            result = resp.json()
        except Exception:
            result = {'raw': resp.text}
        
        return result, resp.status_code
    
    except http_requests.ConnectionError:
        return {'error': 'RunPod exporter is not running or not reachable'}, 503
    except http_requests.Timeout:
        return {'error': 'RunPod exporter request timed out'}, 504
    except Exception as e:
        return {'error': f'Failed to contact RunPod exporter: {str(e)}'}, 500


@app.route('/api/runpod/accounts')
@login_required
def api_runpod_accounts():
    """List RunPod accounts from the exporter."""
    result, status = _runpod_api_request('GET', '/api/accounts')
    return jsonify(result), status


@app.route('/api/runpod/accounts', methods=['POST'])
@csrf.exempt
@admin_required
def api_runpod_add_account():
    """Add a RunPod API key account."""
    data = request.json
    if not data or not data.get('key'):
        return jsonify({'error': 'API key is required'}), 400
    
    payload = {
        'name': data.get('name', 'default'),
        'key': data['key']
    }
    
    result, status = _runpod_api_request('POST', '/api/accounts', data=payload)
    return jsonify(result), status


@app.route('/api/runpod/accounts/<account_name>', methods=['DELETE'])
@admin_required
def api_runpod_delete_account(account_name):
    """Remove a RunPod API key account."""
    result, status = _runpod_api_request('DELETE', f'/api/accounts/{account_name}')
    return jsonify(result), status


@app.route('/api/runpod/accounts/<account_name>/test')
@login_required
def api_runpod_test_account(account_name):
    """Test connectivity for a RunPod account."""
    result, status = _runpod_api_request('GET', f'/api/accounts/{account_name}/test', timeout=30)
    return jsonify(result), status


@app.route('/api/runpod/status')
@login_required
def api_runpod_status():
    """Get RunPod exporter status."""
    result, status = _runpod_api_request('GET', '/api/status')
    return jsonify(result), status


# =============================================================================
# GRAFANA ROLE SYNC
# =============================================================================

GRAFANA_ROLE_MAP = {
    'admin': 'Admin',
    'readwrite': 'Editor', 
    'readonly': 'Viewer'
}

@app.route('/api/grafana/sync-role', methods=['POST'])
@login_required
def api_grafana_sync_role():
    """Sync current user's role to Grafana via API."""
    import requests
    
    username = session.get('username')
    role = session.get('role', 'readonly')
    grafana_role = GRAFANA_ROLE_MAP.get(role, 'Viewer')
    
    try:
        # Get Grafana admin credentials from environment
        grafana_password = os.environ.get('GRAFANA_PASSWORD', 'admin')
        
        # Find user in Grafana
        search_resp = requests.get(
            f"{GRAFANA_URL}/api/users/lookup?loginOrEmail={username}",
            auth=('admin', grafana_password),
            timeout=5
        )
        
        if search_resp.status_code == 200:
            user_data = search_resp.json()
            user_id = user_data.get('id')
            
            # Update user's org role
            update_resp = requests.patch(
                f"{GRAFANA_URL}/api/org/users/{user_id}",
                json={'role': grafana_role},
                auth=('admin', grafana_password),
                timeout=5
            )
            
            if update_resp.status_code == 200:
                return jsonify({
                    'success': True,
                    'username': username,
                    'grafana_role': grafana_role,
                    'message': f'User role synced to Grafana as {grafana_role}'
                })
            else:
                return jsonify({
                    'success': False,
                    'error': f'Failed to update Grafana role: {update_resp.text}'
                }), 500
        else:
            return jsonify({
                'success': False,
                'error': f'User not found in Grafana (may need to login first)',
                'details': search_resp.text
            }), 404
            
    except requests.exceptions.RequestException as e:
        return jsonify({
            'success': False,
            'error': f'Failed to connect to Grafana: {str(e)}'
        }), 500

@app.route('/api/grafana/sync-all-roles', methods=['POST'])
@admin_required
def api_grafana_sync_all_roles():
    """Sync all Fleet users to Grafana (admin only)."""
    import requests
    
    try:
        grafana_password = os.environ.get('GRAFANA_PASSWORD', 'admin')
        
        # Get all users from Grafana
        users_resp = requests.get(
            f"{GRAFANA_URL}/api/users",
            auth=('admin', grafana_password),
            timeout=10
        )
        
        if users_resp.status_code != 200:
            return jsonify({
                'success': False,
                'error': f'Failed to get Grafana users: {users_resp.text}'
            }), 500
        
        grafana_users = users_resp.json()
        synced = []
        errors = []
        
        # For each Grafana user, try to get their Fleet role and sync
        # This is a placeholder - in production, you'd query the proxy's user database
        for user in grafana_users:
            username = user.get('login')
            if username == 'admin':
                continue  # Skip built-in admin
            
            # Default to Viewer for users not in Fleet
            grafana_role = 'Viewer'
            
            try:
                update_resp = requests.patch(
                    f"{GRAFANA_URL}/api/org/users/{user['id']}",
                    json={'role': grafana_role},
                    auth=('admin', grafana_password),
                    timeout=5
                )
                
                if update_resp.status_code == 200:
                    synced.append({'username': username, 'role': grafana_role})
                else:
                    errors.append({'username': username, 'error': update_resp.text})
            except Exception as e:
                errors.append({'username': username, 'error': str(e)})
        
        return jsonify({
            'success': True,
            'synced': synced,
            'errors': errors,
            'total_synced': len(synced),
            'total_errors': len(errors)
        })
        
    except requests.exceptions.RequestException as e:
        return jsonify({
            'success': False,
            'error': f'Failed to connect to Grafana: {str(e)}'
        }), 500

@app.route('/metrics')
@csrf.exempt
@limiter.limit("30 per minute")  # Rate limit metrics scraping
def prometheus_metrics():
    """Prometheus metrics endpoint."""
    # Update metrics
    servers = Server.query.all()
    dc_servers_total.set(len(servers))
    dc_servers_online.set(len([s for s in servers if s.status == 'online']))
    
    total_gpus = sum(s.gpu_count for s in servers)
    dc_gpu_total.set(total_gpus)
    
    for server in servers:
        dc_exporters_installed.labels(server=server.name, exporter='node').set(
            1 if server.node_exporter_installed else 0)
        dc_exporters_installed.labels(server=server.name, exporter='dc').set(
            1 if server.dc_exporter_installed else 0)
        dc_exporters_installed.labels(server=server.name, exporter='dcgm').set(
            1 if server.dcgm_exporter_installed else 0)
        dc_exporters_installed.labels(server=server.name, exporter='watchdog').set(
            1 if server.watchdog_agent_installed else 0)
    
    return Response(generate_latest(registry), mimetype=CONTENT_TYPE_LATEST)

# =============================================================================
# WEB ROUTES
# =============================================================================

@app.route('/')
@app.route('/dashboard')
def index():
    """Main dashboard."""
    if not check_auth():
        return redirect(url_for('login'))
    
    servers = Server.query.all()
    online_count = len([s for s in servers if s.status == 'online'])
    total_gpus = sum(s.gpu_count for s in servers)
    
    return render_template_string(DASHBOARD_TEMPLATE,
        servers=servers,
        online_count=online_count,
        total_gpus=total_gpus,
        version=__version__,
        grafana_url=GRAFANA_URL,
        prometheus_url=PROMETHEUS_URL
    )

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", error_message="Too many login attempts. Please wait.")
@csrf.exempt  # Login form has its own CSRF handling
def login():
    """Login page with rate limiting."""
    error = None
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        stored_hash = get_setting('admin_password_hash')
        
        # First run - set password
        if not stored_hash:
            # Enforce stronger password requirements
            if len(password) >= 8:
                if not re.search(r'[A-Za-z]', password) or not re.search(r'[0-9]', password):
                    error = 'Password must contain both letters and numbers'
                else:
                    set_setting('admin_password_hash', generate_password_hash(password))
                    session['authenticated'] = True
                    session['role'] = 'admin'
                    session['username'] = 'admin'
                    app.logger.info(f"Initial admin password set from {get_client_ip()}")
                    return redirect(url_for('index'))
            else:
                error = 'Password must be at least 8 characters with letters and numbers'
        else:
            if check_password_hash(stored_hash, password):
                session['authenticated'] = True
                session['role'] = 'admin'
                session['username'] = 'admin'
                app.logger.info(f"Admin login from {get_client_ip()}")
                return redirect(url_for('index'))
            else:
                app.logger.warning(f"Failed login attempt from {get_client_ip()}")
                error = 'Invalid password'
    
    first_run = get_setting('admin_password_hash') is None
    
    return render_template_string(LOGIN_TEMPLATE, error=error, first_run=first_run)

@app.route('/logout')
def logout():
    """Logout."""
    session.pop('authenticated', None)
    return redirect(url_for('login'))

@app.route('/servers')
@login_required
def servers_page():
    """Server management page."""
    servers = Server.query.all()
    ssh_keys = SSHKey.query.all()
    
    return render_template_string(SERVERS_TEMPLATE,
        servers=servers,
        ssh_keys=ssh_keys,
        version=__version__
    )

@app.route('/settings')
@admin_required
def settings_page():
    """Settings page."""
    ssh_keys = SSHKey.query.all()
    
    return render_template_string(SETTINGS_TEMPLATE,
        ssh_keys=ssh_keys,
        grafana_url=GRAFANA_URL,
        prometheus_url=PROMETHEUS_URL,
        version=__version__
    )

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def resolve_ssh_key_path(server):
    """Resolve the SSH key path for a server, with fallback to default fleet key.
    
    Priority:
    1. Server's explicitly associated SSH key (from database)
    2. Default fleet key at /etc/dc-overview/ssh_keys/fleet_key
    3. Default user key at ~/.ssh/id_rsa
    """
    if server.ssh_key and server.ssh_key.key_path:
        key_path = server.ssh_key.key_path
        if os.path.exists(key_path):
            return key_path
        # Key path in DB doesn't exist on disk - fall through to defaults
        app.logger.warning(f"SSH key for {server.name} not found at {key_path}, trying defaults")
    
    # Try default locations
    default_keys = ['/etc/dc-overview/ssh_keys/fleet_key',
                    os.path.expanduser('~/.ssh/id_rsa')]
    for key_path in default_keys:
        if os.path.exists(key_path):
            return key_path
    
    return None


def build_ssh_cmd(server, timeout=10, batch_mode=True, extra_opts=None):
    """Build a complete SSH command for a server, handling both key and password auth.
    
    Returns (cmd_prefix, env) where:
    - cmd_prefix: list of command parts (may include 'sshpass' for password auth)
    - env: dict of extra environment variables (for SSHPASS)
    
    Usage:
        cmd, env = build_ssh_cmd(server)
        cmd.append('echo ok')
        result = subprocess.run(cmd, capture_output=True, text=True, env={**os.environ, **env})
    """
    env = {}
    cmd = []
    
    # Determine auth method: key takes priority over password
    ssh_key_path = resolve_ssh_key_path(server)
    ssh_password = getattr(server, 'ssh_password', None)
    
    if ssh_key_path:
        # Key-based authentication
        cmd = [
            'ssh',
            '-o', f'ConnectTimeout={timeout}',
            '-o', 'StrictHostKeyChecking=no',
        ]
        if batch_mode:
            cmd.extend(['-o', 'BatchMode=yes'])
        cmd.extend(['-p', str(server.ssh_port or 22)])
        cmd.extend(['-i', ssh_key_path])
    elif ssh_password:
        # Password-based authentication via sshpass
        cmd = [
            'sshpass', '-e',  # Read password from SSHPASS env var
            'ssh',
            '-o', f'ConnectTimeout={timeout}',
            '-o', 'StrictHostKeyChecking=no',
            '-p', str(server.ssh_port or 22),
        ]
        env['SSHPASS'] = ssh_password
    else:
        # No credentials configured - basic SSH (will likely fail)
        cmd = [
            'ssh',
            '-o', f'ConnectTimeout={timeout}',
            '-o', 'StrictHostKeyChecking=no',
        ]
        if batch_mode:
            cmd.extend(['-o', 'BatchMode=yes'])
        cmd.extend(['-p', str(server.ssh_port or 22)])
    
    if extra_opts:
        cmd.extend(extra_opts)
    
    cmd.append(f'{server.ssh_user or "root"}@{server.server_ip}')
    
    return cmd, env


def check_ssh_connection(server):
    """Test SSH connection to a server. Supports both key and password auth."""
    try:
        cmd, env = build_ssh_cmd(server, timeout=5)
        cmd.append('echo ok')
        
        run_env = {**os.environ, **env} if env else None
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, env=run_env)
        return {'connected': result.returncode == 0}
    except Exception as e:
        return {'connected': False, 'error': str(e)}

def check_exporter(ip, port):
    """Check if an exporter is running on given port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, port))
        sock.close()
        return {'running': result == 0, 'port': port}
    except Exception as e:
        return {'running': False, 'port': port, 'error': str(e)}

def check_watchdog_health_port(ip, port=9878):
    """Check the dc-watchdog-agent health endpoint via HTTP.
    
    The agent exposes /health on port 9878 (configurable) with JSON status.
    This is a fast, consistent check — same pattern as checking exporters
    on 9100, 9835, 9400 — no SSH required.
    
    Returns dict with status or None if the health endpoint is unreachable.
    """
    import http.client
    try:
        conn = http.client.HTTPConnection(ip, port, timeout=3)
        conn.request("GET", "/health")
        resp = conn.getresponse()
        if resp.status == 200:
            import json
            data = json.loads(resp.read().decode())
            return {
                'running': True,
                'installed': True,
                'status': 'running',
                'version': data.get('version'),
                'last_heartbeat_ok': data.get('last_heartbeat_ok', False),
                'heartbeat_count': data.get('heartbeat_count', 0),
                'uptime_seconds': data.get('uptime_seconds', 0),
                'source': 'health_port'
            }
        conn.close()
    except Exception:
        pass
    return None


def check_watchdog_agent(server):
    """Check if dc-watchdog-agent is running for this server.
    
    Uses a consistent, fast checking strategy (no SSH):
    1. Primary: Query the dc-watchdog server API (HTTP, cached, bulk)
    2. Secondary: Probe the agent's local health port (9878) — same
       pattern as checking node_exporter (9100), dc_exporter (9835), etc.
    3. Last resort: Use database cached state
    
    SSH is NOT used here. SSH connectivity is verified separately
    by check_ssh_connection() and shown as its own status.
    """
    # Method 1: Check via dc-watchdog server API (fast — uses 30s cache)
    agents_map = get_watchdog_agents_from_api()
    if agents_map:
        # Match by server name (case-insensitive)
        server_name_lower = server.name.lower()
        agent_info = agents_map.get(server_name_lower)
        
        if agent_info:
            is_online = agent_info.get('online', False)
            version = agent_info.get('version') or None
            last_seen = agent_info.get('last_seen', '')
            return {
                'running': is_online,
                'installed': True,
                'status': 'running' if is_online else 'stopped',
                'version': version,
                'last_seen': last_seen,
                'source': 'watchdog_api'
            }
    
    # Method 2: Probe the agent's local health port (fast HTTP check, ~3s timeout)
    health_result = check_watchdog_health_port(server.server_ip)
    if health_result:
        return health_result
    
    # If health port is unreachable, the agent is either not installed,
    # stopped, or running an older version without the health endpoint.
    # Check TCP port to distinguish "not listening" from "not reachable".
    port_check = check_exporter(server.server_ip, 9878)
    if port_check.get('running'):
        # Port open but /health failed — old agent version without health endpoint
        return {
            'running': True,
            'installed': True,
            'status': 'running',
            'version': None,
            'source': 'health_port_tcp'
        }
    
    # Method 3: Fall back to database cached state
    db_installed = getattr(server, 'watchdog_agent_installed', False)
    db_enabled = getattr(server, 'watchdog_agent_enabled', False)
    db_version = getattr(server, 'watchdog_agent_version', None)
    
    if db_installed:
        return {
            'running': db_enabled,
            'installed': True,
            'status': 'running (cached)' if db_enabled else 'stopped (cached)',
            'version': db_version,
            'source': 'database'
        }
    return {'running': False, 'installed': False, 'status': 'not_installed', 'version': None, 'source': 'none'}

def install_exporter_remote(server, exporter_name):
    """Install an exporter on a remote server via SSH."""
    try:
        if exporter_name == 'node_exporter':
            script = """
            if ! systemctl is-active node_exporter >/dev/null 2>&1; then
                cd /tmp
                curl -sLO https://github.com/prometheus/node_exporter/releases/download/v1.7.0/node_exporter-1.7.0.linux-amd64.tar.gz
                tar xzf node_exporter-1.7.0.linux-amd64.tar.gz
                cp node_exporter-1.7.0.linux-amd64/node_exporter /usr/local/bin/
                useradd -r -s /bin/false node_exporter 2>/dev/null || true
                cat > /etc/systemd/system/node_exporter.service << 'EOF'
[Unit]
Description=Node Exporter
After=network.target

[Service]
Type=simple
User=node_exporter
ExecStart=/usr/local/bin/node_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOF
                systemctl daemon-reload
                systemctl enable node_exporter
                systemctl start node_exporter
            fi
            """
        elif exporter_name == 'dc_exporter':
            script = """
            # Download dc-exporter-rs (Rust version)
            curl -L https://github.com/cryptolabsza/dc-exporter-releases/releases/latest/download/dc-exporter-rs -o /usr/local/bin/dc-exporter-rs
            chmod +x /usr/local/bin/dc-exporter-rs
            
            # Create systemd service
            cat > /etc/systemd/system/dc-exporter.service << 'EOF'
[Unit]
Description=DC Exporter - GPU Metrics for Prometheus (Rust)
Documentation=https://github.com/cryptolabsza/dc-exporter-rs
After=network.target nvidia-persistenced.service

[Service]
Type=simple
ExecStart=/usr/local/bin/dc-exporter-rs --port 9835
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable dc-exporter
            systemctl start dc-exporter
            """
        else:
            return False
        
        cmd, env = build_ssh_cmd(server, timeout=10, batch_mode=False)
        cmd.append(f'bash -c "{script}"')
        
        run_env = {**os.environ, **env} if env else None
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=run_env)
        return result.returncode == 0
    except Exception:
        return False

def remove_exporter_remote(server, exporter_name):
    """Remove an exporter from a remote server via SSH."""
    try:
        if exporter_name == 'node_exporter':
            script = """
            systemctl stop node_exporter 2>/dev/null || true
            systemctl disable node_exporter 2>/dev/null || true
            rm -f /etc/systemd/system/node_exporter.service
            rm -f /usr/local/bin/node_exporter
            systemctl daemon-reload
            echo "node_exporter removed"
            """
        elif exporter_name == 'dc_exporter':
            script = """
            systemctl stop dc-exporter 2>/dev/null || true
            systemctl disable dc-exporter 2>/dev/null || true
            rm -f /etc/systemd/system/dc-exporter.service
            rm -f /usr/local/bin/dc-exporter-collector
            rm -f /usr/local/bin/dc-exporter-server
            rm -rf /etc/dc-exporter
            systemctl daemon-reload
            echo "dc-exporter removed"
            """
        elif exporter_name == 'dcgm_exporter':
            script = """
            systemctl stop dcgm-exporter 2>/dev/null || true
            systemctl disable dcgm-exporter 2>/dev/null || true
            rm -f /etc/systemd/system/dcgm-exporter.service
            systemctl daemon-reload
            docker rm -f dcgm-exporter 2>/dev/null || true
            echo "dcgm-exporter removed"
            """
        else:
            return False
        
        cmd, env = build_ssh_cmd(server, timeout=10, batch_mode=False)
        cmd.append(f'bash -c "{script}"')
        
        run_env = {**os.environ, **env} if env else None
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=run_env)
        return result.returncode == 0
    except Exception:
        return False

def update_prometheus_targets():
    """Update Prometheus targets file for file-based service discovery.
    
    Only includes exporters that are both installed AND enabled.
    """
    try:
        targets_file = Path(DATA_DIR) / 'prometheus_targets.json'
        servers = Server.query.all()
        targets = []
        
        for server in servers:
            # Only include exporters that are BOTH installed AND enabled
            if server.node_exporter_installed and server.node_exporter_enabled:
                targets.append({
                    'targets': [f"{server.server_ip}:9100"],
                    'labels': {'instance': server.name, 'job': 'node-exporter'}
                })
            if server.dc_exporter_installed and server.dc_exporter_enabled:
                targets.append({
                    'targets': [f"{server.server_ip}:9835"],
                    'labels': {'instance': server.name, 'job': 'dc-exporter'}
                })
            if server.dcgm_exporter_installed and server.dcgm_exporter_enabled:
                targets.append({
                    'targets': [f"{server.server_ip}:9400"],
                    'labels': {'instance': server.name, 'job': 'dcgm-exporter'}
                })
            # DC Watchdog agent health/metrics (port 9878)
            if server.watchdog_agent_installed and server.watchdog_agent_enabled:
                targets.append({
                    'targets': [f"{server.server_ip}:9878"],
                    'labels': {'instance': server.name, 'job': 'dc-watchdog-agent'}
                })
        
        targets_file.write_text(json.dumps(targets, indent=2))
        
        # Also update the main prometheus.yml if it exists
        prometheus_yml = Path('/etc/dc-overview/prometheus.yml')
        if prometheus_yml.exists():
            update_prometheus_yml_targets(servers)
            
    except Exception:
        pass  # Non-critical operation


def update_prometheus_yml_targets(servers):
    """Update the prometheus.yml scrape targets to match enabled exporters."""
    import yaml
    
    prometheus_yml = Path('/etc/dc-overview/prometheus.yml')
    if not prometheus_yml.exists():
        return
    
    try:
        with open(prometheus_yml, 'r') as f:
            config = yaml.safe_load(f)
        
        if not config or 'scrape_configs' not in config:
            return
        
        # Update each server's scrape config
        for server in servers:
            # Find or update the server's job
            for scrape_config in config['scrape_configs']:
                if scrape_config.get('job_name') == server.name:
                    # Build targets list based on enabled exporters
                    targets = []
                    if server.node_exporter_installed and server.node_exporter_enabled:
                        targets.append(f"{server.server_ip}:9100")
                    if server.dc_exporter_installed and server.dc_exporter_enabled:
                        targets.append(f"{server.server_ip}:9835")
                    if server.dcgm_exporter_installed and server.dcgm_exporter_enabled:
                        targets.append(f"{server.server_ip}:9400")
                    
                    if targets and scrape_config.get('static_configs'):
                        scrape_config['static_configs'][0]['targets'] = targets
                    break
        
        # Write updated config
        with open(prometheus_yml, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        
        # Reload Prometheus config
        reload_prometheus()
        
    except Exception:
        pass


def reload_prometheus():
    """Reload Prometheus configuration."""
    try:
        # Try Docker container first
        subprocess.run(['docker', 'exec', 'prometheus', 'kill', '-HUP', '1'],
                      capture_output=True, timeout=10)
    except Exception:
        try:
            # Try systemd service
            subprocess.run(['systemctl', 'reload', 'prometheus'],
                          capture_output=True, timeout=10)
        except Exception:
            pass

# =============================================================================
# HTML TEMPLATES
# =============================================================================

BASE_STYLE = """
<style>
    :root {
        --bg-primary: #0a0a0f;
        --bg-secondary: #12121a;
        --bg-card: #1a1a24;
        --text-primary: #f0f0f0;
        --text-secondary: #888;
        --accent-cyan: #00d4ff;
        --accent-green: #4ade80;
        --accent-yellow: #fbbf24;
        --accent-red: #ef4444;
        --border-color: #2a2a3a;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background: var(--bg-primary);
        color: var(--text-primary);
        min-height: 100vh;
    }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    .header {
        display: flex; justify-content: space-between; align-items: center;
        padding: 20px 0; border-bottom: 1px solid var(--border-color); margin-bottom: 30px;
    }
    .header h1 {
        background: linear-gradient(135deg, var(--accent-cyan), #00ff88);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    }
    .nav { display: flex; gap: 15px; align-items: center; }
    .nav a {
        color: var(--text-secondary); text-decoration: none; padding: 8px 16px;
        border-radius: 8px; transition: all 0.2s;
    }
    .nav a:hover, .nav a.active { color: var(--text-primary); background: var(--bg-card); }
    .nav a.nav-home {
        color: var(--accent-cyan); border: 1px solid var(--accent-cyan);
        padding: 6px 14px; font-size: 0.85rem;
    }
    .nav a.nav-home:hover { background: rgba(0, 212, 255, 0.1); color: var(--accent-cyan); }
    .nav .nav-sep { color: var(--border-color); font-size: 1.2rem; user-select: none; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
    .stat-card {
        background: var(--bg-card); border: 1px solid var(--border-color);
        border-radius: 12px; padding: 20px; text-align: center;
    }
    .stat-value { font-size: 2.5rem; font-weight: 700; color: var(--accent-cyan); }
    .stat-label { color: var(--text-secondary); margin-top: 5px; }
    .card {
        background: var(--bg-card); border: 1px solid var(--border-color);
        border-radius: 12px; padding: 20px; margin-bottom: 20px;
    }
    .card h2 { margin-bottom: 15px; font-size: 1.25rem; }
    .btn {
        display: inline-block; padding: 10px 20px; border-radius: 8px;
        text-decoration: none; font-weight: 500; cursor: pointer; border: none;
        transition: all 0.2s;
    }
    .btn-primary { background: var(--accent-cyan); color: #000; }
    .btn-primary:hover { transform: scale(1.05); }
    .btn-secondary { background: var(--bg-secondary); color: var(--text-primary); border: 1px solid var(--border-color); }
    .btn-warning { background: var(--accent-yellow); color: #000; }
    .btn-danger { background: var(--accent-red); color: #fff; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 12px; text-align: left; border-bottom: 1px solid var(--border-color); }
    th { color: var(--text-secondary); font-weight: 500; }
    .status-dot {
        display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 8px;
    }
    .status-online { background: var(--accent-green); box-shadow: 0 0 8px var(--accent-green); }
    .status-offline { background: var(--accent-red); }
    .status-unknown { background: var(--text-secondary); }
    input, select {
        background: var(--bg-secondary); border: 1px solid var(--border-color);
        color: var(--text-primary); padding: 10px 15px; border-radius: 8px;
        width: 100%; margin-bottom: 15px;
    }
    input:focus { outline: none; border-color: var(--accent-cyan); }
    .form-group { margin-bottom: 15px; }
    .form-group label { display: block; margin-bottom: 5px; color: var(--text-secondary); }
    .version { color: var(--text-secondary); font-size: 0.8rem; margin-top: 30px; text-align: center; }
    .checking-spinner { display: inline-block; animation: spin 1s linear infinite; }
    @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
</style>
"""

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html><head>
    <title>Server Manager - Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    """ + BASE_STYLE + """
</head>
<body>
    <div class="container" style="max-width: 400px; margin-top: 100px;">
        <div class="card">
            <h2 style="text-align: center; margin-bottom: 20px;">
                🖥️ Server Manager
            </h2>
            {% if first_run %}
            <p style="color: var(--accent-yellow); margin-bottom: 20px; text-align: center;">
                Welcome! Set your admin password to get started.
            </p>
            {% endif %}
            {% if error %}
            <p style="color: var(--accent-red); margin-bottom: 15px;">{{ error }}</p>
            {% endif %}
            <form method="POST">
                <div class="form-group">
                    <label>{% if first_run %}Set Password{% else %}Password{% endif %}</label>
                    <input type="password" name="password" required autofocus>
                </div>
                <button type="submit" class="btn btn-primary" style="width: 100%;">
                    {% if first_run %}Set Password{% else %}Login{% endif %}
                </button>
            </form>
        </div>
    </div>
</body></html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html><head>
    <title>Server Manager - Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    """ + BASE_STYLE + """
    <style>
        .exporter-badge {
            display: inline-flex;
            align-items: center;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 11px;
            margin-right: 4px;
        }
        .exporter-badge.enabled {
            background: rgba(74, 222, 128, 0.2);
            color: var(--accent-green);
        }
        .exporter-badge.disabled {
            background: rgba(100, 100, 100, 0.2);
            color: #888;
        }
        .exporter-badge.not-installed {
            background: rgba(239, 68, 68, 0.1);
            color: #666;
        }
        .version-tag {
            font-size: 10px;
            color: var(--text-secondary);
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Server Manager</h1>
            <div class="nav">
                <a href="/" class="nav-home">Home</a>
                <span class="nav-sep">|</span>
                <a href="/dashboard" class="active" data-nav>Dashboard</a>
                <a href="/servers" data-nav>Servers</a>
                <a href="/settings" data-nav>Settings</a>
                <a href="/logout" data-nav>Logout</a>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{{ servers|length }}</div>
                <div class="stat-label">Total Servers</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--accent-green);">{{ online_count }}</div>
                <div class="stat-label">Online</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ total_gpus }}</div>
                <div class="stat-label">Total GPUs</div>
            </div>
        </div>
        
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h2>GPU Workers</h2>
                <div id="checkingIndicator" style="display: none; color: var(--accent-cyan); font-size: 14px;">
                    <span class="checking-spinner">⟳</span> Checking servers...
                </div>
            </div>
            {% if servers %}
            <table>
                <thead>
                    <tr>
                        <th>Server</th>
                        <th>IP</th>
                        <th>Status</th>
                        <th>GPUs</th>
                        <th>Exporters</th>
                        <th>Last Seen</th>
                    </tr>
                </thead>
                <tbody id="serversTableBody">
                    {% for server in servers %}
                    <tr data-id="{{ server.id }}">
                        <td><strong>{{ server.name }}</strong></td>
                        <td>{{ server.server_ip }}</td>
                        <td class="status-cell">
                            <span class="status-dot status-{{ server.status }}"></span>
                            {{ server.status }}
                        </td>
                        <td class="gpu-cell">{{ server.gpu_count }}</td>
                        <td class="exporter-cell">
                            <span class="exporter-badge {% if server.node_exporter_installed and server.node_exporter_enabled %}enabled{% elif server.node_exporter_installed %}disabled{% else %}not-installed{% endif %}">
                                node{% if server.node_exporter_version %} <span class="version-tag">{{ server.node_exporter_version }}</span>{% endif %}
                            </span>
                            <span class="exporter-badge {% if server.dc_exporter_installed and server.dc_exporter_enabled %}enabled{% elif server.dc_exporter_installed %}disabled{% else %}not-installed{% endif %}">
                                dc{% if server.dc_exporter_version %} <span class="version-tag">{{ server.dc_exporter_version }}</span>{% endif %}
                            </span>
                            <span class="exporter-badge {% if server.dcgm_exporter_installed and server.dcgm_exporter_enabled %}enabled{% elif server.dcgm_exporter_installed %}disabled{% else %}not-installed{% endif %}">
                                dcgm{% if server.dcgm_exporter_version %} <span class="version-tag">{{ server.dcgm_exporter_version }}</span>{% endif %}
                            </span>
                            <span class="exporter-badge {% if server.watchdog_agent_installed and server.watchdog_agent_enabled %}enabled{% elif server.watchdog_agent_installed %}disabled{% else %}not-installed{% endif %}" title="DC Watchdog Agent (external uptime)">
                                wd{% if server.watchdog_agent_version %} <span class="version-tag">{{ server.watchdog_agent_version }}</span>{% endif %}
                            </span>
                        </td>
                        <td class="lastseen-cell">{{ server.last_seen.strftime('%Y-%m-%d %H:%M') if server.last_seen else '—' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <p style="color: var(--text-secondary);">No servers configured. <a href="/servers" style="color: var(--accent-cyan);">Add servers →</a></p>
            {% endif %}
        </div>
        
        <p class="version">Server Manager v{{ version }}</p>
    </div>
    <script>
    // Get base path for API calls - extract /dc from any subpath like /dc/servers
    const basePath = window.location.pathname.match(/^(\/[^\/]+)/)?.[1] || '';
    
    // Fix nav links to include base path (e.g. /dc/servers instead of /servers)
    document.querySelectorAll('.nav a[data-nav]').forEach(a => {
        a.href = basePath + a.getAttribute('href');
    });
    
    // Check user permissions and adjust UI
    async function checkUserPermissions() {
        try {
            const response = await fetch(`${basePath}/api/auth/status`);
            const data = await response.json();
            const permissions = data.permissions || {};
            
            // Hide Settings link for non-admin users
            if (!permissions.can_admin) {
                document.querySelectorAll('.nav a').forEach(link => {
                    if (link.textContent.includes('Settings')) link.style.display = 'none';
                });
            }
            
            // Show role indicator
            const roleIndicator = document.createElement('span');
            roleIndicator.style.cssText = 'background: var(--bg-card); padding: 4px 10px; border-radius: 4px; font-size: 12px; margin-left: 10px;';
            roleIndicator.textContent = data.role || 'unknown';
            const nav = document.querySelector('.nav');
            if (nav) nav.appendChild(roleIndicator);
        } catch (e) {
            console.error('Failed to check permissions:', e);
        }
    }
    
    // Update a single server row with check results
    function updateDashboardRow(row, result) {
        // Status cell
        const statusCell = row.querySelector('.status-cell');
        if (statusCell && result.status) {
            statusCell.innerHTML = `<span class="status-dot status-${result.status}"></span>${result.status}`;
        }
        
        // GPU count cell
        const gpuCell = row.querySelector('.gpu-cell');
        if (gpuCell && result.gpu_count !== undefined) {
            gpuCell.textContent = result.gpu_count;
        }
        
        // Exporter cell
        const exporterCell = row.querySelector('.exporter-cell');
        if (exporterCell) {
            const nodeClass = result.node_exporter?.running ? 'enabled' : 'not-installed';
            const dcClass = result.dc_exporter?.running ? 'enabled' : 'not-installed';
            const dcgmClass = result.dcgm_exporter?.running ? 'enabled' : 'not-installed';
            const wdClass = result.watchdog_agent?.running ? 'enabled' : (result.watchdog_agent?.installed ? 'disabled' : 'not-installed');
            
            exporterCell.innerHTML = `
                <span class="exporter-badge ${nodeClass}">node${result.node_exporter?.version ? ` <span class="version-tag">${result.node_exporter.version}</span>` : ''}</span>
                <span class="exporter-badge ${dcClass}">dc${result.dc_exporter?.version ? ` <span class="version-tag">${result.dc_exporter.version}</span>` : ''}</span>
                <span class="exporter-badge ${dcgmClass}">dcgm${result.dcgm_exporter?.version ? ` <span class="version-tag">${result.dcgm_exporter.version}</span>` : ''}</span>
                <span class="exporter-badge ${wdClass}" title="DC Watchdog Agent (external uptime)">wd${result.watchdog_agent?.version ? ` <span class="version-tag">${result.watchdog_agent.version}</span>` : ''}</span>
            `;
        }
        
        // Last seen cell
        const lastSeenCell = row.querySelector('.lastseen-cell');
        if (lastSeenCell) {
            lastSeenCell.textContent = result.last_seen || '\u2014';
        }
    }
    
    // Refresh all servers without page reload
    async function refreshDashboard() {
        const indicator = document.getElementById('checkingIndicator');
        const rows = document.querySelectorAll('#serversTableBody tr[data-id]');
        
        if (!rows.length) return;
        
        if (indicator) indicator.style.display = 'block';
        
        for (const row of rows) {
            const id = row.dataset.id;
            try {
                const response = await fetch(`${basePath}/api/servers/${id}/check`);
                if (response.ok) {
                    const result = await response.json();
                    updateDashboardRow(row, result);
                }
            } catch (e) {
                console.error(`Failed to check server ${id}:`, e);
            }
        }
        
        if (indicator) indicator.style.display = 'none';
    }
    
    async function syncWatchdogStatus() {
        // Sync WD agent status from dc-watchdog server API (same method as Fleet Management)
        try {
            await fetch(`${basePath}/api/watchdog-agents/sync`, {method: 'POST'});
        } catch (e) {
            console.log('Watchdog sync not available:', e.message);
        }
    }
    
    document.addEventListener('DOMContentLoaded', async () => {
        await checkUserPermissions();
        // Sync WD status from watchdog API first, then refresh all servers
        await syncWatchdogStatus();
        await refreshDashboard();
        // Set up periodic refresh every 30 seconds
        setInterval(async () => {
            await syncWatchdogStatus();
            await refreshDashboard();
        }, 30000);
    });
    </script>
</body></html>
"""

SERVERS_TEMPLATE = """
<!DOCTYPE html>
<html><head>
    <title>Server Manager - Servers</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    """ + BASE_STYLE + """
    <style>
        .exporter-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 12px;
            margin: 8px 0;
        }
        .exporter-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        .exporter-name {
            font-weight: bold;
            color: var(--text-primary);
        }
        .toggle-switch {
            position: relative;
            width: 44px;
            height: 24px;
        }
        .toggle-switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }
        .toggle-slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #444;
            transition: .3s;
            border-radius: 24px;
        }
        .toggle-slider:before {
            position: absolute;
            content: "";
            height: 18px;
            width: 18px;
            left: 3px;
            bottom: 3px;
            background-color: white;
            transition: .3s;
            border-radius: 50%;
        }
        input:checked + .toggle-slider {
            background-color: var(--accent-green);
        }
        input:checked + .toggle-slider:before {
            transform: translateX(20px);
        }
        .version-info {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 12px;
            color: var(--text-secondary);
        }
        .version-badge {
            padding: 2px 8px;
            border-radius: 4px;
            background: var(--bg-card);
            font-family: monospace;
        }
        .update-badge {
            padding: 2px 8px;
            border-radius: 4px;
            background: var(--accent-yellow);
            color: #000;
            font-size: 11px;
            cursor: pointer;
        }
        .update-badge:hover {
            background: #e5ac00;
        }
        .auto-update-row {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-top: 8px;
            font-size: 12px;
            color: var(--text-secondary);
        }
        .auto-update-row input[type="checkbox"] {
            width: 16px;
            height: 16px;
        }
        .branch-select {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
        }
        .modal-tabs {
            display: flex;
            gap: 0;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 20px;
        }
        .modal-tab {
            padding: 10px 20px;
            cursor: pointer;
            border: none;
            background: none;
            color: var(--text-secondary);
            font-size: 14px;
            font-weight: 500;
            border-bottom: 2px solid transparent;
            transition: all 0.2s;
        }
        .modal-tab:hover {
            color: var(--text-primary);
            background: rgba(255,255,255,0.03);
        }
        .modal-tab.active {
            color: var(--accent-cyan);
            border-bottom-color: var(--accent-cyan);
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .ssh-config-group {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-bottom: 15px;
        }
        .ssh-config-group .form-group {
            margin-bottom: 0;
        }
        .ssh-config-group select,
        .ssh-config-group input {
            width: 100%;
            padding: 8px 10px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
            background: var(--bg-secondary);
            color: var(--text-primary);
            font-size: 13px;
        }
        .ssh-status-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 500;
        }
        .ssh-status-ok {
            background: rgba(46, 204, 113, 0.15);
            color: var(--accent-green);
        }
        .ssh-status-fail {
            background: rgba(231, 76, 60, 0.15);
            color: var(--accent-red);
        }
        .ssh-status-testing {
            background: rgba(0, 212, 255, 0.15);
            color: var(--accent-cyan);
        }
        .server-detail-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        .modal-content {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 24px;
            max-width: 600px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
        }
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .modal-close {
            background: none;
            border: none;
            color: var(--text-secondary);
            font-size: 24px;
            cursor: pointer;
        }
        .status-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 6px;
        }
        .status-enabled { background: var(--accent-green); }
        .status-disabled { background: #666; }
        .status-not-installed { background: var(--accent-red); }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Server Manager</h1>
            <div class="nav">
                <a href="/" class="nav-home">Home</a>
                <span class="nav-sep">|</span>
                <a href="/dashboard" data-nav>Dashboard</a>
                <a href="/servers" class="active" data-nav>Servers</a>
                <a href="/settings" data-nav>Settings</a>
                <a href="/logout" data-nav>Logout</a>
            </div>
        </div>
        
        <div class="card">
            <h2>Add Server</h2>
            <form id="addServerForm">
                <div style="display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 15px;">
                    <div class="form-group">
                        <label>Server Name</label>
                        <input type="text" name="name" placeholder="gpu-worker-01" required>
                    </div>
                    <div class="form-group">
                        <label>Server IP</label>
                        <input type="text" name="server_ip" placeholder="192.168.1.101" required>
                    </div>
                    <div class="form-group">
                        <label>SSH User</label>
                        <input type="text" name="ssh_user" value="root">
                    </div>
                    <div class="form-group">
                        <label>SSH Port</label>
                        <input type="number" name="ssh_port" value="22" min="1" max="65535">
                    </div>
                </div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-top: 10px;">
                    <div class="form-group">
                        <label>SSH Key <small style="color:var(--text-secondary)">(or use password below)</small></label>
                        <select name="ssh_key_id" id="addServerKeySelect" style="width:100%; padding:8px; border-radius:6px; border:1px solid var(--border-color); background:var(--bg-secondary); color:var(--text-primary);">
                            <option value="">Default (fleet key)</option>
                            {% for key in ssh_keys %}
                            <option value="{{ key.id }}">{{ key.name }} {% if key.fingerprint %}({{ key.fingerprint[:20] }}...){% endif %}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="form-group">
                        <label>SSH Password <small style="color:var(--text-secondary)">(optional, key preferred)</small></label>
                        <input type="password" name="ssh_password" placeholder="Leave empty to use SSH key">
                    </div>
                </div>
                <button type="submit" class="btn btn-primary">Add Server</button>
            </form>
        </div>
        
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                <h2>Managed Servers</h2>
                <div style="display: flex; align-items: center; gap: 15px;">
                    <span id="checkingIndicator" style="display: none; color: var(--accent-cyan); font-size: 14px;">
                        <span style="display: inline-block; animation: spin 1s linear infinite;">⟳</span> Checking...
                    </span>
                    <button class="btn btn-secondary" onclick="checkAllUpdates()">Check for Updates</button>
                </div>
            </div>
            <style>@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }</style>
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>IP</th>
                        <th>SSH</th>
                        <th>Exporters</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="serversTable">
                    {% for server in servers %}
                    <tr data-id="{{ server.id }}">
                        <td><strong>{{ server.name }}</strong></td>
                        <td>{{ server.server_ip }}</td>
                        <td>
                            {{ server.ssh_user }}@:{{ server.ssh_port }}
                            {% if server.ssh_key %}
                            <br><small style="color: var(--accent-green);" title="{{ server.ssh_key.name }}">key: {{ server.ssh_key.name }}</small>
                            {% elif server.ssh_password %}
                            <br><small style="color: var(--accent-cyan);">password</small>
                            {% else %}
                            <br><small style="color: var(--text-secondary);">default key</small>
                            {% endif %}
                        </td>
                        <td class="exporter-status">
                            <span class="status-indicator {% if server.node_exporter_installed and server.node_exporter_enabled %}status-enabled{% elif server.node_exporter_installed %}status-disabled{% else %}status-not-installed{% endif %}"></span>node
                            <span class="status-indicator {% if server.dc_exporter_installed and server.dc_exporter_enabled %}status-enabled{% elif server.dc_exporter_installed %}status-disabled{% else %}status-not-installed{% endif %}" style="margin-left:8px"></span>dc
                            <span class="status-indicator {% if server.dcgm_exporter_installed and server.dcgm_exporter_enabled %}status-enabled{% elif server.dcgm_exporter_installed %}status-disabled{% else %}status-not-installed{% endif %}" style="margin-left:8px"></span>dcgm
                            <span class="status-indicator {% if server.watchdog_agent_installed and server.watchdog_agent_enabled %}status-enabled{% elif server.watchdog_agent_installed %}status-disabled{% else %}status-not-installed{% endif %}" style="margin-left:8px" title="DC Watchdog Agent"></span>wd
                        </td>
                        <td>
                            <button class="btn btn-secondary" onclick="openServerDetail({{ server.id }}, '{{ server.name }}')">Manage</button>
                            <button class="btn btn-secondary" onclick="checkServer({{ server.id }})">Check</button>
                            <button class="btn btn-danger" onclick="deleteServer({{ server.id }})">Delete</button>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <p class="version">Server Manager v{{ version }}</p>
    </div>
    
    <!-- Server Detail Modal -->
    <div id="serverDetailModal" class="server-detail-modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 id="modalServerName">Server Details</h2>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-tabs">
                <button class="modal-tab active" onclick="switchTab('exporters')" id="tab-exporters">Exporters</button>
                <button class="modal-tab" onclick="switchTab('ssh')" id="tab-ssh">SSH Configuration</button>
            </div>
            <div id="tab-content-exporters" class="tab-content active">
                <div id="modalContent">
                    <!-- Dynamic exporter content -->
                </div>
            </div>
            <div id="tab-content-ssh" class="tab-content">
                <div id="sshConfigContent">
                    <!-- Dynamic SSH config content -->
                </div>
            </div>
        </div>
    </div>
    
    <script>
    // Get base path for API calls - extract /dc from any subpath like /dc/servers
    const basePath = window.location.pathname.match(/^(\/[^\/]+)/)?.[1] || '';
    
    // Fix nav links to include base path (e.g. /dc/servers instead of /servers)
    document.querySelectorAll('.nav a[data-nav]').forEach(a => {
        a.href = basePath + a.getAttribute('href');
    });
    
    let currentServerId = null;
    let userPermissions = { can_read: false, can_write: false, can_admin: false };
    
    // Check user permissions and adjust UI
    async function checkUserPermissions() {
        try {
            const response = await fetch(`${basePath}/api/auth/status`);
            const data = await response.json();
            userPermissions = data.permissions || { can_read: false, can_write: false, can_admin: false };
            
            // Hide "Add Server" form for readonly users
            const addServerCard = document.querySelector('.card:has(#addServerForm)');
            if (addServerCard && !userPermissions.can_write) {
                addServerCard.style.display = 'none';
            }
            
            // Hide delete buttons for readonly users
            if (!userPermissions.can_write) {
                document.querySelectorAll('.btn-danger').forEach(btn => {
                    if (btn.textContent.includes('Delete')) btn.style.display = 'none';
                });
            }
            
            // Hide Settings link for non-admin users
            if (!userPermissions.can_admin) {
                document.querySelectorAll('.nav a').forEach(link => {
                    if (link.textContent.includes('Settings')) link.style.display = 'none';
                });
            }
            
            // Show role indicator
            const roleIndicator = document.createElement('span');
            roleIndicator.className = 'role-badge';
            roleIndicator.style.cssText = 'background: var(--bg-card); padding: 4px 10px; border-radius: 4px; font-size: 12px; margin-left: 10px;';
            roleIndicator.textContent = data.role || 'unknown';
            const nav = document.querySelector('.nav');
            if (nav) nav.appendChild(roleIndicator);
        } catch (e) {
            console.error('Failed to check permissions:', e);
        }
    }
    
    async function syncWatchdogStatus() {
        // Sync WD agent status from dc-watchdog server API (same method as Fleet Management)
        try {
            await fetch(`${basePath}/api/watchdog-agents/sync`, {method: 'POST'});
        } catch (e) {
            console.log('Watchdog sync not available:', e.message);
        }
    }
    
    // Run permission check on load, then auto-check all servers
    document.addEventListener('DOMContentLoaded', async () => {
        await checkUserPermissions();
        // Sync WD status from watchdog API first, then check all servers
        await syncWatchdogStatus();
        await checkAllServersQuietly();
        // Set up periodic refresh every 30 seconds
        setInterval(async () => {
            await syncWatchdogStatus();
            await checkAllServersQuietly();
        }, 30000);
    });
    
    async function checkAllServersQuietly() {
        // Check all servers and update table without showing alerts
        const indicator = document.getElementById('checkingIndicator');
        const rows = document.querySelectorAll('#serversTable tr[data-id]');
        
        if (indicator && rows.length > 0) indicator.style.display = 'inline';
        
        for (const row of rows) {
            const id = row.dataset.id;
            try {
                const response = await fetch(`${basePath}/api/servers/${id}/check`);
                if (response.ok) {
                    const result = await response.json();
                    updateServerRow(row, result);
                }
            } catch (e) {
                console.error(`Failed to check server ${id}:`, e);
            }
        }
        
        if (indicator) indicator.style.display = 'none';
    }
    
    function updateServerRow(row, result) {
        // Update all columns in the table row
        const cells = row.querySelectorAll('td');
        if (cells.length < 5) return;  // Expect: Name, IP, SSH, Exporters, Actions
        
        // Exporter status column (index 3)
        const exporterCell = cells[3];
        if (exporterCell) {
            let html = '';
            html += `<span class="status-indicator ${result.node_exporter?.running ? 'status-enabled' : 'status-not-installed'}"></span>node`;
            if (result.node_exporter?.version) html += ` ${result.node_exporter.version}`;
            html += `<span class="status-indicator ${result.dc_exporter?.running ? 'status-enabled' : 'status-not-installed'}" style="margin-left:8px"></span>dc`;
            if (result.dc_exporter?.version) html += ` ${result.dc_exporter.version}`;
            html += `<span class="status-indicator ${result.dcgm_exporter?.running ? 'status-enabled' : 'status-not-installed'}" style="margin-left:8px"></span>dcgm`;
            if (result.dcgm_exporter?.version) html += ` ${result.dcgm_exporter.version}`;
            const wdStatus = result.watchdog_agent?.running ? 'status-enabled' : (result.watchdog_agent?.installed ? 'status-disabled' : 'status-not-installed');
            html += `<span class="status-indicator ${wdStatus}" style="margin-left:8px" title="DC Watchdog Agent"></span>wd`;
            if (result.watchdog_agent?.version) html += ` ${result.watchdog_agent.version}`;
            exporterCell.innerHTML = html;
        }
        
        // Last Seen column (index 5)
        const lastSeenCell = cells[5];
        if (lastSeenCell && result.last_seen) {
            lastSeenCell.textContent = result.last_seen;
        } else if (lastSeenCell && result.status === 'offline') {
            lastSeenCell.textContent = '\u2014';  // em dash
        }
    }
    
    document.getElementById('addServerForm').onsubmit = async (e) => {
        e.preventDefault();
        const form = e.target;
        const data = {
            name: form.name.value,
            server_ip: form.server_ip.value,
            ssh_user: form.ssh_user.value,
            ssh_port: parseInt(form.ssh_port.value) || 22
        };
        
        // Include SSH key if selected
        if (form.ssh_key_id.value) {
            data.ssh_key_id = parseInt(form.ssh_key_id.value);
        }
        
        // Include password if provided
        if (form.ssh_password.value) {
            data.ssh_password = form.ssh_password.value;
        }
        
        const response = await fetch(`${basePath}/api/servers`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
        
        if (response.ok) {
            location.reload();
        } else {
            const result = await response.json();
            alert(result.error || 'Failed to add server');
        }
    };
    
    function switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.modal-tab').forEach(t => t.classList.remove('active'));
        document.getElementById(`tab-${tabName}`).classList.add('active');
        
        // Update tab content
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        document.getElementById(`tab-content-${tabName}`).classList.add('active');
        
        // Load SSH config on first switch
        if (tabName === 'ssh' && currentServerId) {
            loadSSHConfig(currentServerId);
        }
    }
    
    async function openServerDetail(id, name) {
        currentServerId = id;
        document.getElementById('modalServerName').textContent = name + ' - Server Management';
        document.getElementById('serverDetailModal').style.display = 'flex';
        document.getElementById('modalContent').innerHTML = '<p>Loading...</p>';
        document.getElementById('sshConfigContent').innerHTML = '<p style="color:var(--text-secondary)">Switch to this tab to load SSH configuration.</p>';
        
        // Reset to exporters tab
        switchTab('exporters');
        
        // Fetch exporter versions
        const response = await fetch(`${basePath}/api/servers/${id}/exporters/versions`);
        const data = await response.json();
        
        renderExporterManagement(data);
    }
    
    async function loadSSHConfig(serverId) {
        const container = document.getElementById('sshConfigContent');
        container.innerHTML = '<p>Loading SSH configuration...</p>';
        
        try {
            const response = await fetch(`${basePath}/api/servers/${serverId}/ssh-config`);
            const data = await response.json();
            renderSSHConfig(data);
        } catch (e) {
            container.innerHTML = `<p style="color: var(--accent-red);">Failed to load SSH config: ${e.message}</p>`;
        }
    }
    
    function renderSSHConfig(data) {
        const canWrite = userPermissions.can_write;
        const container = document.getElementById('sshConfigContent');
        
        let keyOptions = '<option value="">Default (fleet key)</option>';
        for (const key of (data.available_keys || [])) {
            const selected = key.id === data.ssh_key_id ? 'selected' : '';
            const fp = key.fingerprint ? ` (${key.fingerprint.substring(0, 20)}...)` : '';
            keyOptions += `<option value="${key.id}" ${selected}>${key.name}${fp}</option>`;
        }
        
        const authBadge = data.auth_method === 'key' 
            ? '<span class="ssh-status-badge ssh-status-ok">Key-based auth</span>'
            : data.auth_method === 'password'
            ? '<span class="ssh-status-badge ssh-status-ok">Password auth</span>'
            : '<span class="ssh-status-badge ssh-status-fail">No credentials configured</span>';
        
        let html = `
        <div style="margin-bottom: 20px;">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 15px;">
                <div>
                    <strong>Current Auth:</strong> ${authBadge}
                </div>
                <div id="sshTestResult"></div>
            </div>
            <button class="btn btn-secondary" onclick="testSSHConnection()" id="testSSHBtn">Test SSH Connection</button>
        </div>
        
        <div style="border-top: 1px solid var(--border-color); padding-top: 15px;">
            <h3 style="margin-bottom: 12px;">Connection Settings</h3>
            ${!canWrite ? '<p style="color: var(--accent-yellow); font-size: 12px; margin-bottom: 10px;">Read-only mode: You cannot modify SSH settings.</p>' : ''}
            
            <div class="ssh-config-group">
                <div class="form-group">
                    <label>SSH User</label>
                    <input type="text" id="sshConfigUser" value="${data.ssh_user || 'root'}" ${canWrite ? '' : 'disabled'}>
                </div>
                <div class="form-group">
                    <label>SSH Port</label>
                    <input type="number" id="sshConfigPort" value="${data.ssh_port || 22}" min="1" max="65535" ${canWrite ? '' : 'disabled'}>
                </div>
            </div>
            
            <h3 style="margin-bottom: 12px; margin-top: 20px;">Authentication</h3>
            <div class="ssh-config-group">
                <div class="form-group">
                    <label>SSH Key</label>
                    <select id="sshConfigKeyId" ${canWrite ? '' : 'disabled'}>
                        ${keyOptions}
                    </select>
                </div>
                <div class="form-group">
                    <label>SSH Password <small style="color:var(--text-secondary)">(key takes priority)</small></label>
                    <input type="password" id="sshConfigPassword" placeholder="${data.has_password ? '••••••••' : 'No password set'}" ${canWrite ? '' : 'disabled'}>
                </div>
            </div>
            
            <p style="font-size: 11px; color: var(--text-secondary); margin-top: 4px;">
                If both a key and password are configured, key-based auth is tried first. Password uses <code>sshpass</code> on the server.
            </p>
            
            ${canWrite ? `
            <div style="margin-top: 20px; display: flex; gap: 10px;">
                <button class="btn btn-primary" onclick="saveSSHConfig()">Save SSH Config</button>
                ${data.has_password ? '<button class="btn btn-danger btn-sm" onclick="clearSSHPassword()">Clear Password</button>' : ''}
            </div>
            ` : ''}
        </div>
        `;
        
        container.innerHTML = html;
    }
    
    async function testSSHConnection() {
        const btn = document.getElementById('testSSHBtn');
        const resultDiv = document.getElementById('sshTestResult');
        btn.disabled = true;
        btn.textContent = 'Testing...';
        resultDiv.innerHTML = '<span class="ssh-status-badge ssh-status-testing">Testing connection...</span>';
        
        try {
            const response = await fetch(`${basePath}/api/servers/${currentServerId}/ssh-test`, {method: 'POST'});
            const result = await response.json();
            
            if (result.connected) {
                resultDiv.innerHTML = `<span class="ssh-status-badge ssh-status-ok">Connected (${result.auth_method})</span>`;
            } else {
                resultDiv.innerHTML = `<span class="ssh-status-badge ssh-status-fail">Failed: ${result.error || 'Connection refused'}</span>`;
            }
        } catch (e) {
            resultDiv.innerHTML = `<span class="ssh-status-badge ssh-status-fail">Error: ${e.message}</span>`;
        }
        
        btn.disabled = false;
        btn.textContent = 'Test SSH Connection';
    }
    
    async function saveSSHConfig() {
        const data = {
            ssh_user: document.getElementById('sshConfigUser').value,
            ssh_port: parseInt(document.getElementById('sshConfigPort').value) || 22,
            ssh_key_id: document.getElementById('sshConfigKeyId').value || null,
        };
        
        // Only include password if the field was actually changed (not the placeholder dots)
        const passwordField = document.getElementById('sshConfigPassword');
        if (passwordField.value && passwordField.value !== '') {
            data.ssh_password = passwordField.value;
        }
        
        try {
            const response = await fetch(`${basePath}/api/servers/${currentServerId}/ssh-config`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data)
            });
            
            const result = await response.json();
            
            if (result.success) {
                // Reload config to show updated state
                loadSSHConfig(currentServerId);
                // Update the server table SSH column
                const row = document.querySelector(`#serversTable tr[data-id="${currentServerId}"]`);
                if (row) {
                    const cells = row.querySelectorAll('td');
                    if (cells[2]) cells[2].textContent = `${data.ssh_user}@:${data.ssh_port}`;
                }
                alert('SSH configuration saved successfully');
            } else {
                alert('Failed to save: ' + (result.error || 'Unknown error'));
            }
        } catch (e) {
            alert('Error saving SSH config: ' + e.message);
        }
    }
    
    async function clearSSHPassword() {
        if (!confirm('Clear the SSH password for this server? Key-based auth will be used instead.')) return;
        
        try {
            const response = await fetch(`${basePath}/api/servers/${currentServerId}/ssh-config`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ssh_password: null})
            });
            
            const result = await response.json();
            if (result.success) {
                loadSSHConfig(currentServerId);
            }
        } catch (e) {
            alert('Error: ' + e.message);
        }
    }
    
    function renderExporterManagement(data) {
        const exporters = [
            { key: 'node_exporter', name: 'Node Exporter', port: 9100 },
            { key: 'dc_exporter', name: 'DC Exporter', port: 9835 },
            { key: 'dcgm_exporter', name: 'DCGM Exporter', port: 9400 },
            { key: 'watchdog_agent', name: 'DC Watchdog Agent', port: null, isWatchdog: true }
        ];
        
        const canWrite = userPermissions.can_write;
        let html = '';
        
        // Show read-only notice for readonly users
        if (!canWrite) {
            html += `<div style="background: var(--accent-yellow); color: #000; padding: 10px; border-radius: 8px; margin-bottom: 15px;">
                <strong>Read-only mode:</strong> You don't have permission to modify exporters.
            </div>`;
        }
        
        for (const exp of exporters) {
            const version = data.versions[exp.key];
            const updateInfo = data.updates[exp.key];
            const hasUpdate = updateInfo && updateInfo.update_available;
            
            // Special handling for DC Watchdog agent
            if (exp.isWatchdog) {
                const watchdogData = data.watchdog_agent || {};
                const isInstalled = watchdogData.installed || false;
                const isEnabled = watchdogData.enabled !== false;
                const wdVersion = watchdogData.version || null;
                const sshError = watchdogData.ssh_error || null;
                
                let statusText, statusStyle;
                if (sshError && isInstalled) {
                    // SSH failed but DB says installed - show cached state
                    statusText = isEnabled ? 'Running (cached)' : 'Stopped (cached)';
                    statusStyle = 'background: var(--accent-yellow); color: #000;';
                } else if (isInstalled) {
                    statusText = isEnabled ? 'Running' : 'Stopped';
                    statusStyle = isEnabled ? 'background: var(--accent-green);' : '';
                } else {
                    statusText = 'Not installed';
                    statusStyle = '';
                }
                
                html += `
                <div class="exporter-card" data-exporter="${exp.key}" style="border-color: var(--accent-cyan); background: linear-gradient(135deg, var(--bg-card), rgba(0, 212, 255, 0.05));">
                    <div class="exporter-header">
                        <span class="exporter-name">📡 ${exp.name} <small style="color:var(--text-secondary)">(Go binary)</small></span>
                        <label class="toggle-switch">
                            <input type="checkbox" ${isInstalled && isEnabled ? 'checked' : ''} ${canWrite && isInstalled ? '' : 'disabled'} onchange="toggleWatchdogAgent(this.checked)">
                            <span class="toggle-slider" style="${canWrite && isInstalled ? '' : 'opacity: 0.5; cursor: not-allowed;'}"></span>
                        </label>
                    </div>
                    <div class="version-info">
                        <span>Status:</span>
                        <span class="version-badge" style="${statusStyle}">${statusText}</span>
                        ${wdVersion ? `<span style="color: var(--text-secondary); margin-left: 8px;">v${wdVersion}</span>` : ''}
                        <span id="wd-latest-version" style="color: var(--text-secondary); margin-left: 8px; font-size: 11px;"></span>
                    </div>
                    ${sshError ? `<div style="margin-top: 6px; font-size: 11px; color: var(--accent-yellow);">SSH check failed - showing last known state</div>` : ''}
                    ${canWrite ? `
                    <div style="margin-top: 10px; display: flex; gap: 8px;">
                        ${!isInstalled ? `<button class="btn btn-primary btn-sm" onclick="installWatchdogAgent()">Install Agent</button>` : ''}
                        ${isInstalled ? `<button class="btn btn-secondary btn-sm" onclick="reinstallWatchdogAgent()">Reinstall (Latest)</button>` : ''}
                        ${isInstalled ? `<button class="btn btn-warning btn-sm" onclick="removeWatchdogAgent()">Remove</button>` : ''}
                    </div>
                    ` : ''}
                </div>
                `;
                
                // Fetch latest version from GitHub and compare
                fetch(\`\${basePath}/api/watchdog-agent/latest\`)
                    .then(r => r.json())
                    .then(latestData => {
                        const el = document.getElementById('wd-latest-version');
                        if (el && latestData.success && latestData.version) {
                            if (wdVersion && wdVersion !== latestData.version) {
                                el.innerHTML = \`<span style="color: var(--accent-yellow);">⬆ Update available: v\${latestData.version}</span>\`;
                            } else if (wdVersion) {
                                el.innerHTML = '<span style="color: var(--accent-green);">✓ Up to date</span>';
                            } else {
                                el.innerHTML = \`Latest: v\${latestData.version}\`;
                            }
                        }
                    }).catch(() => {});
            } else {
                html += `
                <div class="exporter-card" data-exporter="${exp.key}">
                    <div class="exporter-header">
                        <span class="exporter-name">${exp.name} <small style="color:var(--text-secondary)">(port ${exp.port})</small></span>
                        <label class="toggle-switch">
                            <input type="checkbox" ${version ? 'checked' : ''} ${canWrite ? '' : 'disabled'} onchange="toggleExporter('${exp.key}', this.checked)">
                            <span class="toggle-slider" style="${canWrite ? '' : 'opacity: 0.5; cursor: not-allowed;'}"></span>
                        </label>
                    </div>
                    <div class="version-info">
                        <span>Version:</span>
                        <span class="version-badge">${version || 'Not installed'}</span>
                        ${hasUpdate && canWrite ? `<span class="update-badge" onclick="updateExporter('${exp.key}')">Update to ${updateInfo.latest}</span>` : ''}
                        ${hasUpdate && !canWrite ? `<span style="color: var(--accent-yellow); font-size: 11px;">Update available: ${updateInfo.latest}</span>` : ''}
                    </div>
                    <div class="auto-update-row">
                        <input type="checkbox" id="auto-${exp.key}" ${canWrite ? '' : 'disabled'} onchange="updateAutoSetting('${exp.key}', this.checked)">
                        <label for="auto-${exp.key}">Auto-update</label>
                    </div>
                </div>
                `;
            }
        }
        
        html += `
        <div style="margin-top: 20px; padding-top: 15px; border-top: 1px solid var(--border-color);">
            <div style="display: flex; align-items: center; gap: 12px;">
                <label>Update Branch:</label>
                <select class="branch-select" id="branchSelect" ${canWrite ? '' : 'disabled'} onchange="updateBranch(this.value)">
                    <option value="main">main (stable)</option>
                    <option value="dev">dev (latest)</option>
                </select>
            </div>
            ${canWrite ? `
            <div style="margin-top: 15px; display: flex; gap: 10px;">
                <button class="btn btn-secondary" onclick="installExporters(currentServerId)">Install All</button>
                <button class="btn btn-warning" onclick="removeExporters(currentServerId)">Remove All</button>
            </div>
            ` : ''}
        </div>
        `;
        
        document.getElementById('modalContent').innerHTML = html;
    }
    
    function closeModal() {
        document.getElementById('serverDetailModal').style.display = 'none';
        currentServerId = null;
    }
    
    async function toggleExporter(exporter, enabled) {
        const response = await fetch(`${basePath}/api/servers/${currentServerId}/exporters/${exporter}/toggle`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({enabled})
        });
        
        const result = await response.json();
        if (!result.success) {
            alert('Failed to toggle exporter: ' + (result.error || 'Unknown error'));
            // Reload to reset state
            openServerDetail(currentServerId, document.getElementById('modalServerName').textContent.split(' - ')[0]);
        }
    }
    
    async function updateExporter(exporter) {
        if (!confirm(`Update ${exporter} to latest version?`)) return;
        
        const branch = document.getElementById('branchSelect').value;
        
        const response = await fetch(`${basePath}/api/servers/${currentServerId}/exporters/${exporter}/update`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({branch})
        });
        
        const result = await response.json();
        if (result.success) {
            alert(`${exporter} updated to ${result.version}`);
            openServerDetail(currentServerId, document.getElementById('modalServerName').textContent.split(' - ')[0]);
        } else {
            alert('Update failed: ' + (result.error || 'Unknown error'));
        }
    }
    
    async function updateAutoSetting(exporter, enabled) {
        const data = {};
        data[`${exporter}_auto_update`] = enabled;
        
        await fetch(`${basePath}/api/servers/${currentServerId}/exporters/settings`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
    }
    
    async function updateBranch(branch) {
        await fetch(`${basePath}/api/servers/${currentServerId}/exporters/settings`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({exporter_update_branch: branch})
        });
    }
    
    // DC Watchdog Agent management functions
    async function toggleWatchdogAgent(enabled) {
        const response = await fetch(`${basePath}/api/servers/${currentServerId}/watchdog-agent/toggle`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({enabled})
        });
        
        const result = await response.json();
        if (!result.success) {
            alert('Failed to toggle watchdog agent: ' + (result.error || 'Unknown error'));
            openServerDetail(currentServerId, document.getElementById('modalServerName').textContent.split(' - ')[0]);
        }
    }
    
    async function installWatchdogAgent() {
        if (!confirm('Install DC Watchdog agent on this server?\\n\\nThis will enable external uptime monitoring from watchdog.cryptolabs.co.za')) return;
        
        const btn = event.target;
        btn.disabled = true;
        btn.textContent = 'Installing...';
        
        const response = await fetch(`${basePath}/api/servers/${currentServerId}/watchdog-agent/install`, {
            method: 'POST'
        });
        
        const result = await response.json();
        if (result.success) {
            alert('DC Watchdog agent installed successfully');
            openServerDetail(currentServerId, document.getElementById('modalServerName').textContent.split(' - ')[0]);
        } else {
            alert('Installation failed: ' + (result.error || 'Unknown error'));
            btn.disabled = false;
            btn.textContent = 'Install Agent';
        }
    }
    
    async function reinstallWatchdogAgent() {
        if (!confirm('Reinstall DC Watchdog agent? This will stop and reinstall the agent.')) return;
        
        const btn = event.target;
        btn.disabled = true;
        btn.textContent = 'Reinstalling...';
        
        const response = await fetch(`${basePath}/api/servers/${currentServerId}/watchdog-agent/reinstall`, {
            method: 'POST'
        });
        
        const result = await response.json();
        if (result.success) {
            alert('DC Watchdog agent reinstalled successfully');
            openServerDetail(currentServerId, document.getElementById('modalServerName').textContent.split(' - ')[0]);
        } else {
            alert('Reinstall failed: ' + (result.error || 'Unknown error'));
            btn.disabled = false;
            btn.textContent = 'Reinstall';
        }
    }
    
    async function removeWatchdogAgent() {
        if (!confirm('Remove DC Watchdog agent from this server?\\n\\nThe server will no longer be monitored for uptime.')) return;
        
        const btn = event.target;
        btn.disabled = true;
        btn.textContent = 'Removing...';
        
        const response = await fetch(`${basePath}/api/servers/${currentServerId}/watchdog-agent/remove`, {
            method: 'POST'
        });
        
        const result = await response.json();
        if (result.success) {
            alert('DC Watchdog agent removed');
            openServerDetail(currentServerId, document.getElementById('modalServerName').textContent.split(' - ')[0]);
        } else {
            alert('Removal failed: ' + (result.error || 'Unknown error'));
            btn.disabled = false;
            btn.textContent = 'Remove';
        }
    }
    
    async function checkAllUpdates() {
        const btn = event.target;
        btn.textContent = 'Checking...';
        btn.disabled = true;
        
        const response = await fetch(`${basePath}/api/exporters/updates`);
        const result = await response.json();
        
        btn.textContent = 'Check for Updates';
        btn.disabled = false;
        
        if (result.updates_available) {
            let msg = 'Updates available:\\n\\n';
            for (const server of result.servers) {
                msg += `${server.server_name}:\\n`;
                for (const [exp, info] of Object.entries(server.exporters)) {
                    msg += `  - ${exp}: ${info.installed} -> ${info.latest}\\n`;
                }
            }
            alert(msg);
        } else {
            alert('All exporters are up to date!');
        }
    }
    
    async function checkServer(id) {
        const btn = event.target;
        btn.textContent = 'Checking...';
        btn.disabled = true;
        
        const response = await fetch(`${basePath}/api/servers/${id}/check`);
        const result = await response.json();
        
        const wdStatus = result.watchdog_agent ? 
            (result.watchdog_agent.running ? 'Running' : (result.watchdog_agent.installed ? 'Stopped' : 'Not installed')) : 
            'Unknown';
        const wdVersion = result.watchdog_agent?.version ? ` (v${result.watchdog_agent.version})` : '';
        const wdSource = result.watchdog_agent?.source ? ` [${result.watchdog_agent.source}]` : '';
        
        alert(`SSH: ${result.ssh.connected ? 'OK' : 'Failed'}
Node Exporter: ${result.node_exporter.running ? 'Running' : 'Not running'}
DC Exporter: ${result.dc_exporter.running ? 'Running' : 'Not running'}
DCGM Exporter: ${result.dcgm_exporter.running ? 'Running' : 'Not running'}
DC Watchdog Agent: ${wdStatus}${wdVersion}${wdSource}`);
        
        location.reload();
    }
    
    async function installExporters(id) {
        if (!confirm('Install node_exporter and dc-exporter on this server?')) return;
        
        const response = await fetch(`${basePath}/api/servers/${id}/install-exporters`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({exporters: ['node_exporter', 'dc_exporter']})
        });
        
        const result = await response.json();
        alert(`node_exporter: ${result.node_exporter}
dc_exporter: ${result.dc_exporter}`);
        
        location.reload();
    }
    
    async function removeExporters(id) {
        if (!confirm('Remove exporters from this server?')) return;
        
        const response = await fetch(`${basePath}/api/servers/${id}/remove-exporters`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({exporters: ['node_exporter', 'dc_exporter']})
        });
        
        const result = await response.json();
        alert(`node_exporter: ${result.node_exporter}
dc_exporter: ${result.dc_exporter}`);
        
        location.reload();
    }
    
    async function deleteServer(id) {
        if (!confirm('Remove this server from monitoring?')) return;
        
        await fetch(`${basePath}/api/servers/${id}`, {method: 'DELETE'});
        location.reload();
    }
    
    // Close modal when clicking outside
    document.getElementById('serverDetailModal').addEventListener('click', function(e) {
        if (e.target === this) closeModal();
    });
    </script>
</body></html>
"""

SETTINGS_TEMPLATE = """
<!DOCTYPE html>
<html><head>
    <title>Server Manager - Settings</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    """ + BASE_STYLE + """
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Server Manager</h1>
            <div class="nav">
                <a href="/" class="nav-home">Home</a>
                <span class="nav-sep">|</span>
                <a href="/dashboard" data-nav>Dashboard</a>
                <a href="/servers" data-nav>Servers</a>
                <a href="/settings" class="active" data-nav>Settings</a>
                <a href="/logout" data-nav>Logout</a>
            </div>
        </div>
        
        <div class="card">
            <h2>Integration URLs</h2>
            <div class="form-group">
                <label>Grafana URL</label>
                <input type="text" value="{{ grafana_url }}" readonly>
            </div>
            <div class="form-group">
                <label>Prometheus URL</label>
                <input type="text" value="{{ prometheus_url }}" readonly>
            </div>
        </div>
        
        <div class="card">
            <h2>SSH Keys</h2>
            {% if ssh_keys %}
            <table>
                <thead>
                    <tr><th>Name</th><th>Path</th><th>Fingerprint</th><th>Actions</th></tr>
                </thead>
                <tbody id="sshKeysTable">
                    {% for key in ssh_keys %}
                    <tr data-id="{{ key.id }}">
                        <td>{{ key.name }}</td>
                        <td style="font-family: monospace; font-size: 0.85rem;">{{ key.key_path }}</td>
                        <td style="font-family: monospace; font-size: 0.85rem;">{{ key.fingerprint or '—' }}</td>
                        <td>
                            <button class="btn btn-danger btn-sm" onclick="deleteSSHKey({{ key.id }})">Delete</button>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <p style="color: var(--text-secondary);">No SSH keys configured.</p>
            {% endif %}
            
            <div style="margin-top: 20px; padding-top: 15px; border-top: 1px solid var(--border-color);">
                <h3>Add SSH Key</h3>
                <form id="addSSHKeyForm">
                    <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 15px;">
                        <div class="form-group">
                            <label>Key Name</label>
                            <input type="text" name="name" placeholder="my-ssh-key" required>
                        </div>
                        <div class="form-group">
                            <label>Key Path (inside container)</label>
                            <input type="text" name="key_path" placeholder="/etc/dc-overview/ssh_keys/id_rsa" required>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary">Add SSH Key</button>
                </form>
            </div>
        </div>
        
        <div class="card">
            <h2>Vast.ai Accounts</h2>
            <p style="color: var(--text-secondary); margin-bottom: 15px;">
                Manage Vast.ai API keys for the metrics exporter. Accounts are validated on add and persisted across restarts.
            </p>
            <div id="vastAccountsLoading" style="color: var(--text-secondary);">Loading accounts...</div>
            <table id="vastAccountsTable" style="display:none;">
                <thead>
                    <tr><th>Account</th><th>API Key</th><th>Status</th><th>Balance</th><th>Machines</th><th>Actions</th></tr>
                </thead>
                <tbody id="vastAccountsBody"></tbody>
            </table>
            <div id="vastAccountsEmpty" style="display:none; color: var(--text-secondary);">
                No Vast.ai accounts configured. Add one below.
            </div>
            <div id="vastAccountsError" style="display:none; color: #e74c3c;"></div>
            
            <div style="margin-top: 20px; padding-top: 15px; border-top: 1px solid var(--border-color);">
                <h3>Add Vast.ai Account</h3>
                <form id="addVastAccountForm">
                    <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 15px;">
                        <div class="form-group">
                            <label>Account Name</label>
                            <input type="text" name="name" placeholder="MyVastAccount" required>
                        </div>
                        <div class="form-group">
                            <label>API Key</label>
                            <input type="text" name="key" placeholder="Vast.ai API key from Account > API Keys" required>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary" id="addVastBtn">Add Account</button>
                    <span id="addVastStatus" style="margin-left: 10px; font-size: 0.9rem;"></span>
                </form>
            </div>
        </div>
        
        <div class="card">
            <h2>RunPod Accounts</h2>
            <p style="color: var(--text-secondary); margin-bottom: 15px;">
                Manage RunPod API keys for the metrics exporter. Accounts are validated on add and persisted across restarts.
            </p>
            <div id="runpodAccountsLoading" style="color: var(--text-secondary);">Loading accounts...</div>
            <table id="runpodAccountsTable" style="display:none;">
                <thead>
                    <tr><th>Account</th><th>API Key</th><th>Status</th><th>Balance</th><th>Machines</th><th>Actions</th></tr>
                </thead>
                <tbody id="runpodAccountsBody"></tbody>
            </table>
            <div id="runpodAccountsEmpty" style="display:none; color: var(--text-secondary);">
                No RunPod accounts configured. Add one below.
            </div>
            <div id="runpodAccountsError" style="display:none; color: #e74c3c;"></div>
            
            <div style="margin-top: 20px; padding-top: 15px; border-top: 1px solid var(--border-color);">
                <h3>Add RunPod Account</h3>
                <form id="addRunpodAccountForm">
                    <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 15px;">
                        <div class="form-group">
                            <label>Account Name</label>
                            <input type="text" name="name" placeholder="MyRunPodAccount" required>
                        </div>
                        <div class="form-group">
                            <label>API Key</label>
                            <input type="text" name="key" placeholder="rpa_XXXXX (from RunPod Settings > API Keys)" required>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary" id="addRunpodBtn">Add Account</button>
                    <span id="addRunpodStatus" style="margin-left: 10px; font-size: 0.9rem;"></span>
                </form>
            </div>
        </div>
        
        <div class="card">
            <h2>API Endpoints</h2>
            <table>
                <tr><td><code>/api/health</code></td><td>Health check</td></tr>
                <tr><td><code>/api/servers</code></td><td>List/manage servers</td></tr>
                <tr><td><code>/api/ssh-keys</code></td><td>List/manage SSH keys</td></tr>
                <tr><td><code>/api/vast/accounts</code></td><td>List/manage Vast.ai accounts</td></tr>
                <tr><td><code>/api/runpod/accounts</code></td><td>List/manage RunPod accounts</td></tr>
                <tr><td><code>/api/prometheus/targets.json</code></td><td>Prometheus file_sd targets</td></tr>
                <tr><td><code>/metrics</code></td><td>Prometheus metrics</td></tr>
            </table>
        </div>
        
        <p class="version">Server Manager v{{ version }}</p>
    </div>
    
    <script>
    // Get base path for API calls - extract /dc from any subpath like /dc/settings
    const basePath = window.location.pathname.match(/^(\/[^\/]+)/)?.[1] || '';
    
    // Fix nav links to include base path (e.g. /dc/servers instead of /servers)
    document.querySelectorAll('.nav a[data-nav]').forEach(a => {
        a.href = basePath + a.getAttribute('href');
    });
    
    // ---- SSH Keys ----
    document.getElementById('addSSHKeyForm').onsubmit = async (e) => {
        e.preventDefault();
        const form = e.target;
        const data = {
            name: form.name.value,
            key_path: form.key_path.value
        };
        
        const response = await fetch(`${basePath}/api/ssh-keys`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
        
        if (response.ok) {
            location.reload();
        } else {
            const result = await response.json();
            alert(result.error || 'Failed to add SSH key');
        }
    };
    
    async function deleteSSHKey(id) {
        if (!confirm('Delete this SSH key?')) return;
        
        const response = await fetch(`${basePath}/api/ssh-keys/${id}`, {method: 'DELETE'});
        
        if (response.ok) {
            location.reload();
        } else {
            const result = await response.json();
            alert(result.error || 'Failed to delete SSH key');
        }
    }
    
    // ---- Vast.ai Accounts ----
    async function loadVastAccounts() {
        const loading = document.getElementById('vastAccountsLoading');
        const table = document.getElementById('vastAccountsTable');
        const tbody = document.getElementById('vastAccountsBody');
        const empty = document.getElementById('vastAccountsEmpty');
        const errorDiv = document.getElementById('vastAccountsError');
        
        try {
            const response = await fetch(`${basePath}/api/vast/accounts`);
            loading.style.display = 'none';
            
            if (!response.ok) {
                const result = await response.json().catch(() => ({}));
                errorDiv.textContent = result.error || 'Failed to load accounts (exporter may not be running)';
                errorDiv.style.display = 'block';
                return;
            }
            
            const data = await response.json();
            const accounts = data.accounts || [];
            
            if (accounts.length === 0) {
                empty.style.display = 'block';
                return;
            }
            
            tbody.innerHTML = '';
            for (const acct of accounts) {
                const statusColor = acct.status === 'connected' ? '#2ecc71' : '#e74c3c';
                const statusIcon = acct.status === 'connected' ? '✓' : '✗';
                const balance = acct.balance !== null ? `$${acct.balance.toFixed(2)}` : '—';
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><strong>${acct.name}</strong></td>
                    <td style="font-family: monospace; font-size: 0.85rem;">${acct.key_masked}</td>
                    <td style="color: ${statusColor};">${statusIcon} ${acct.status}</td>
                    <td>${balance}</td>
                    <td>${acct.machine_count}</td>
                    <td>
                        <button class="btn btn-sm" onclick="testVastAccount('${acct.name}')" style="margin-right:5px;">Test</button>
                        <button class="btn btn-danger btn-sm" onclick="deleteVastAccount('${acct.name}')">Remove</button>
                    </td>
                `;
                tbody.appendChild(tr);
            }
            table.style.display = '';
            
        } catch (e) {
            loading.style.display = 'none';
            errorDiv.textContent = 'Could not connect to Vast.ai exporter: ' + e.message;
            errorDiv.style.display = 'block';
        }
    }
    
    document.getElementById('addVastAccountForm').onsubmit = async (e) => {
        e.preventDefault();
        const form = e.target;
        const btn = document.getElementById('addVastBtn');
        const status = document.getElementById('addVastStatus');
        
        btn.disabled = true;
        status.textContent = 'Validating API key...';
        status.style.color = 'var(--text-secondary)';
        
        try {
            const response = await fetch(`${basePath}/api/vast/accounts`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    name: form.name.value,
                    key: form.key.value
                })
            });
            
            const result = await response.json();
            
            if (response.ok) {
                status.textContent = `✓ Added (balance: $${result.balance?.toFixed(2) || 'N/A'})`;
                status.style.color = '#2ecc71';
                form.reset();
                setTimeout(() => loadVastAccounts(), 500);
            } else {
                status.textContent = '✗ ' + (result.error || 'Failed to add account');
                status.style.color = '#e74c3c';
            }
        } catch (e) {
            status.textContent = '✗ Connection error: ' + e.message;
            status.style.color = '#e74c3c';
        }
        
        btn.disabled = false;
    };
    
    async function deleteVastAccount(name) {
        if (!confirm(`Remove Vast.ai account "${name}"? Metrics for this account will stop.`)) return;
        
        const response = await fetch(`${basePath}/api/vast/accounts/${encodeURIComponent(name)}`, {method: 'DELETE'});
        
        if (response.ok) {
            loadVastAccounts();
        } else {
            const result = await response.json().catch(() => ({}));
            alert(result.error || 'Failed to remove account');
        }
    }
    
    async function testVastAccount(name) {
        const btn = event.target;
        btn.disabled = true;
        btn.textContent = 'Testing...';
        
        try {
            const response = await fetch(`${basePath}/api/vast/accounts/${encodeURIComponent(name)}/test`);
            const result = await response.json();
            
            if (result.status === 'connected') {
                let msg = `Account: ${name}\\nStatus: Connected\\nBalance: $${result.balance?.toFixed(2)}\\nMachines: ${result.machine_count}`;
                if (result.machines && result.machines.length > 0) {
                    msg += '\\n\\nMachines:';
                    for (const m of result.machines) {
                        msg += `\\n  ${m.hostname}: ${m.num_gpus} GPUs, occupancy=${m.gpu_occupancy}, listed=${m.listed}`;
                    }
                }
                alert(msg);
            } else {
                alert(`Account "${name}" test failed: ${result.error || 'Unknown error'}`);
            }
        } catch (e) {
            alert('Connection error: ' + e.message);
        }
        
        btn.disabled = false;
        btn.textContent = 'Test';
    }
    
    // ---- RunPod Accounts ----
    async function loadRunpodAccounts() {
        const loading = document.getElementById('runpodAccountsLoading');
        const table = document.getElementById('runpodAccountsTable');
        const tbody = document.getElementById('runpodAccountsBody');
        const empty = document.getElementById('runpodAccountsEmpty');
        const errorDiv = document.getElementById('runpodAccountsError');
        
        try {
            const response = await fetch(`${basePath}/api/runpod/accounts`);
            loading.style.display = 'none';
            
            if (!response.ok) {
                const result = await response.json().catch(() => ({}));
                errorDiv.textContent = result.error || 'Failed to load accounts (exporter may not be running)';
                errorDiv.style.display = 'block';
                return;
            }
            
            const data = await response.json();
            const accounts = data.accounts || [];
            
            if (accounts.length === 0) {
                empty.style.display = 'block';
                return;
            }
            
            tbody.innerHTML = '';
            for (const acct of accounts) {
                const statusColor = acct.status === 'connected' ? '#2ecc71' : '#e74c3c';
                const statusIcon = acct.status === 'connected' ? '✓' : '✗';
                const balance = acct.balance !== null ? `$${Number(acct.balance).toFixed(2)}` : '—';
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><strong>${acct.name}</strong></td>
                    <td style="font-family: monospace; font-size: 0.85rem;">${acct.key_masked}</td>
                    <td style="color: ${statusColor};">${statusIcon} ${acct.status}</td>
                    <td>${balance}</td>
                    <td>${acct.machine_count}</td>
                    <td>
                        <button class="btn btn-sm" onclick="testRunpodAccount('${acct.name}')" style="margin-right:5px;">Test</button>
                        <button class="btn btn-danger btn-sm" onclick="deleteRunpodAccount('${acct.name}')">Remove</button>
                    </td>
                `;
                tbody.appendChild(tr);
            }
            table.style.display = '';
            
        } catch (e) {
            loading.style.display = 'none';
            errorDiv.textContent = 'Could not connect to RunPod exporter: ' + e.message;
            errorDiv.style.display = 'block';
        }
    }
    
    document.getElementById('addRunpodAccountForm').onsubmit = async (e) => {
        e.preventDefault();
        const form = e.target;
        const btn = document.getElementById('addRunpodBtn');
        const status = document.getElementById('addRunpodStatus');
        
        btn.disabled = true;
        status.textContent = 'Validating API key...';
        status.style.color = 'var(--text-secondary)';
        
        try {
            const response = await fetch(`${basePath}/api/runpod/accounts`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    name: form.name.value,
                    key: form.key.value
                })
            });
            
            const result = await response.json();
            
            if (response.ok) {
                status.textContent = `✓ Added (balance: $${Number(result.balance || 0).toFixed(2)}, ${result.machine_count || 0} machine(s))`;
                status.style.color = '#2ecc71';
                form.reset();
                setTimeout(() => loadRunpodAccounts(), 500);
            } else {
                status.textContent = '✗ ' + (result.error || 'Failed to add account');
                status.style.color = '#e74c3c';
            }
        } catch (e) {
            status.textContent = '✗ Connection error: ' + e.message;
            status.style.color = '#e74c3c';
        }
        
        btn.disabled = false;
    };
    
    async function deleteRunpodAccount(name) {
        if (!confirm(`Remove RunPod account "${name}"? Metrics for this account will stop.`)) return;
        
        const response = await fetch(`${basePath}/api/runpod/accounts/${encodeURIComponent(name)}`, {method: 'DELETE'});
        
        if (response.ok) {
            loadRunpodAccounts();
        } else {
            const result = await response.json().catch(() => ({}));
            alert(result.error || 'Failed to remove account');
        }
    }
    
    async function testRunpodAccount(name) {
        const btn = event.target;
        btn.disabled = true;
        btn.textContent = 'Testing...';
        
        try {
            const response = await fetch(`${basePath}/api/runpod/accounts/${encodeURIComponent(name)}/test`);
            const result = await response.json();
            
            if (result.status === 'connected') {
                let msg = `Account: ${name}\\nStatus: Connected\\nBalance: $${Number(result.balance || 0).toFixed(2)}\\nMachines: ${result.machine_count}`;
                if (result.machines && result.machines.length > 0) {
                    msg += '\\n\\nMachines:';
                    for (const m of result.machines) {
                        msg += `\\n  ${m.name}: ${m.gpu_total} GPUs (${m.gpu_rented} rented), listed=${m.listed}`;
                    }
                }
                alert(msg);
            } else {
                alert(`Account "${name}" test failed: ${result.error || 'Unknown error'}`);
            }
        } catch (e) {
            alert('Connection error: ' + e.message);
        }
        
        btn.disabled = false;
        btn.textContent = 'Test';
    }
    
    // Load accounts on page load
    loadVastAccounts();
    loadRunpodAccounts();
    </script>
</body></html>
"""

# =============================================================================
# INITIALIZATION
# =============================================================================

def init_db():
    """Initialize database and run safe migrations for new columns."""
    with app.app_context():
        db.create_all()
        
        # Safe migrations: add columns that may not exist on older databases
        _run_safe_migrations()


def _run_safe_migrations():
    """Add missing columns to existing tables (safe for re-runs)."""
    from sqlalchemy import inspect as sa_inspect
    inspector = sa_inspect(db.engine)
    
    # Migrations for 'server' table
    server_columns = {col['name'] for col in inspector.get_columns('server')}
    
    if 'ssh_password' not in server_columns:
        app.logger.info("Migration: Adding ssh_password column to server table")
        db.session.execute(db.text('ALTER TABLE server ADD COLUMN ssh_password VARCHAR(500)'))
        db.session.commit()


# Initialize on import
init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=DC_OVERVIEW_PORT, debug=True)
