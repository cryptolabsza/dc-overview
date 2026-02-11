#!/usr/bin/env python3
"""
DC Overview - GPU Datacenter Monitoring Web Application

A Flask-based dashboard for managing GPU datacenter monitoring with Prometheus & Grafana.
Provides server management, exporter deployment, and monitoring status.

GitHub: https://github.com/cryptolabsza/dc-overview
License: MIT
"""

from flask import Flask, render_template, jsonify, request, Response, session, redirect, url_for, g
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
import secrets
import re
import ipaddress
from pathlib import Path
import requests as http_requests
from werkzeug.security import generate_password_hash, check_password_hash

from . import __version__

# Import extracted utility modules
from .proxy import get_proxy_config, push_proxy_config, _get_internal_api_token
from .ssh_helpers import resolve_ssh_key_path, build_ssh_cmd, check_ssh_connection
from .web_exporters import (
    check_exporter, install_exporter_remote, remove_exporter_remote,
    toggle_exporter_service, update_exporter_remote,
)
from .web_watchdog import (
    get_watchdog_api_key, get_site_id, get_watchdog_agents_from_api,
    check_watchdog_health_port, check_watchdog_agent, toggle_watchdog_service,
    get_watchdog_latest_release, install_watchdog_agent_remote,
    remove_watchdog_agent_remote, WATCHDOG_URL,
    _watchdog_api_cache, _WATCHDOG_CACHE_TTL,
)
from .web_prometheus import update_prometheus_targets as _update_prometheus_targets
from .web_prometheus import reload_prometheus

app = Flask(__name__, template_folder='web_templates')

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


def update_prometheus_targets():
    """Thin wrapper: queries the DB and delegates to web_prometheus module."""
    try:
        servers = Server.query.all()
        _update_prometheus_targets(servers, DATA_DIR)
    except Exception:
        pass  # Non-critical


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
    
    # Allow setting watchdog agent status (e.g., from setup after deploying agents)
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
    
    # Sync installed/enabled state with actual port checks
    for exp_key in ['node_exporter', 'dc_exporter', 'dcgm_exporter']:
        is_running = results[exp_key].get('running', False)
        if is_running:
            setattr(server, f'{exp_key}_installed', True)
            setattr(server, f'{exp_key}_enabled', True)
        else:
            # Not responding — clear enabled flag so UI shows correct state
            setattr(server, f'{exp_key}_enabled', False)
    
    # Update watchdog DB state from the check result
    wd_result = results['watchdog_agent']
    if wd_result.get('source') != 'database':  # Don't re-save cached data as new data
        server.watchdog_agent_installed = wd_result.get('installed', False)
        server.watchdog_agent_enabled = wd_result.get('running', False)
        if wd_result.get('version'):
            server.watchdog_agent_version = wd_result['version']
    
    # Server is online if any exporter responds OR SSH is reachable
    is_online = any([
        results['node_exporter']['running'],
        results['dc_exporter']['running'],
        results['ssh'].get('connected', False),
    ])
    if is_online:
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
    
    # Update the live-check timestamp so the Manage modal knows data is fresh
    ts_key = f'_exporter_check_ts_{server_id}'
    ts_setting = AppSettings.query.filter_by(key=ts_key).first()
    ts_val = datetime.utcnow().isoformat()
    if ts_setting:
        ts_setting.value = ts_val
    else:
        db.session.add(AppSettings(key=ts_key, value=ts_val))
    
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

def _build_exporter_response(server, versions=None, updates=None, source='cached'):
    """Build the standard exporter versions response from DB state.
    
    Args:
        server: Server model instance
        versions: dict of detected versions (None = use DB cached versions)
        updates: dict of update info (None = empty)
        source: 'cached' (DB only) or 'live' (freshly checked)
    """
    if versions is None:
        # Build versions from DB cached values.
        # Only include version if the exporter is actually running (enabled).
        # If installed but stopped, version stays out so the UI shows "Stopped"
        # rather than a green version badge.
        versions = {}
        if server.node_exporter_enabled and server.node_exporter_version:
            versions['node_exporter'] = server.node_exporter_version
        if server.dc_exporter_enabled and server.dc_exporter_version:
            versions['dc_exporter'] = server.dc_exporter_version
        if server.dcgm_exporter_enabled and server.dcgm_exporter_version:
            versions['dcgm_exporter'] = server.dcgm_exporter_version
    
    # For cached responses, only claim "installed" if also "enabled" (was running
    # at last check). This avoids showing stale "Stopped" for exporters that are
    # actually not installed. The background live check will correct the state.
    if source == 'cached':
        installed = {
            'node_exporter': server.node_exporter_enabled,
            'dc_exporter': server.dc_exporter_enabled,
            'dcgm_exporter': server.dcgm_exporter_enabled,
        }
    else:
        installed = {
            'node_exporter': server.node_exporter_installed,
            'dc_exporter': server.dc_exporter_installed,
            'dcgm_exporter': server.dcgm_exporter_installed,
        }
    
    return {
        'server_id': server.id,
        'server_name': server.name,
        'versions': versions,
        'updates': updates or {},
        'installed': installed,
        'enabled': {
            'node_exporter': server.node_exporter_enabled,
            'dc_exporter': server.dc_exporter_enabled,
            'dcgm_exporter': server.dcgm_exporter_enabled,
        },
        'watchdog_agent': {
            'installed': server.watchdog_agent_installed,
            'enabled': server.watchdog_agent_enabled,
            'version': server.watchdog_agent_version,
            'status': 'running' if server.watchdog_agent_enabled else ('stopped' if server.watchdog_agent_installed else 'not_installed'),
            'source': source
        },
        'source': source,
    }


def _do_live_exporter_check(server_id):
    """Run actual port checks + SSH version detection and update the DB.
    
    Designed to run in a background thread. Creates its own app context.
    """
    from .exporters import get_all_exporter_versions, check_for_updates
    
    with app.app_context():
        server = Server.query.get(server_id)
        if not server:
            return
        
        ssh_key_path = resolve_ssh_key_path(server)
        ssh_password = server.ssh_password
        
        # Get installed versions via SSH
        versions = get_all_exporter_versions(
            server.server_ip,
            server.ssh_user,
            server.ssh_port,
            ssh_key_path,
            ssh_password
        )
        
        # Port checks are the source of truth for running state
        port_checks = {
            'node_exporter': check_exporter(server.server_ip, 9100),
            'dc_exporter': check_exporter(server.server_ip, 9835),
            'dcgm_exporter': check_exporter(server.server_ip, 9400),
        }
        
        for exp_key, port_result in port_checks.items():
            is_running = port_result.get('running', False)
            has_version = bool(versions.get(exp_key))
            
            if has_version or is_running:
                setattr(server, f'{exp_key}_installed', True)
                setattr(server, f'{exp_key}_enabled', True)
                if has_version:
                    setattr(server, f'{exp_key}_version', versions[exp_key])
            else:
                setattr(server, f'{exp_key}_enabled', False)
        
        # Also check watchdog agent
        watchdog_status = check_watchdog_agent(server)
        if watchdog_status.get('source') not in ('database', 'none'):
            server.watchdog_agent_installed = watchdog_status.get('installed', False)
            server.watchdog_agent_enabled = watchdog_status.get('running', False)
            if watchdog_status.get('version'):
                server.watchdog_agent_version = watchdog_status['version']
        
        # Check for updates
        updates = check_for_updates(
            server.server_ip,
            server.ssh_user,
            server.ssh_port,
            ssh_key_path,
            ssh_password=ssh_password,
            branch=server.exporter_update_branch
        )
        
        # Store update info as JSON in a lightweight cache
        import json
        cache_key = f'_exporter_updates_{server_id}'
        setting = AppSettings.query.filter_by(key=cache_key).first()
        update_data = json.dumps(updates) if updates else '{}'
        if setting:
            setting.value = update_data
        else:
            db.session.add(AppSettings(key=cache_key, value=update_data))
        
        # Mark last live check timestamp
        ts_key = f'_exporter_check_ts_{server_id}'
        ts_setting = AppSettings.query.filter_by(key=ts_key).first()
        ts_val = datetime.utcnow().isoformat()
        if ts_setting:
            ts_setting.value = ts_val
        else:
            db.session.add(AppSettings(key=ts_key, value=ts_val))
        
        db.session.commit()


@app.route('/api/servers/<int:server_id>/exporters/versions')
@login_required
def api_get_exporter_versions(server_id):
    """Get exporter versions for a server.
    
    Returns DB-cached state instantly and kicks off a background thread to do
    live port checks + SSH version detection. The response includes 'source':
    'cached' or 'live' so the frontend knows whether to poll again.
    
    The background thread writes a timestamp when it finishes. Subsequent
    calls within 30s return 'live' source (fresh data) without re-checking.
    """
    server = Server.query.get_or_404(server_id)
    
    # Check if a recent live check has already updated the DB
    last_check = get_setting(f'_exporter_check_ts_{server_id}')
    is_fresh = False
    if last_check:
        try:
            ts = datetime.fromisoformat(last_check)
            age_seconds = (datetime.utcnow() - ts).total_seconds()
            is_fresh = age_seconds < 30
        except Exception:
            pass
    
    # Include any cached update info
    import json as _json
    cached_updates = {}
    update_setting = get_setting(f'_exporter_updates_{server_id}')
    if update_setting:
        try:
            cached_updates = _json.loads(update_setting)
        except Exception:
            pass
    
    source = 'live' if is_fresh else 'cached'
    response = _build_exporter_response(server, updates=cached_updates, source=source)
    
    # Kick off background live check if data is not fresh
    if not is_fresh:
        thread = threading.Thread(
            target=_do_live_exporter_check,
            args=(server_id,),
            daemon=True
        )
        thread.start()
    
    return jsonify(response)


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
    
    # Check if exporter is currently installed
    is_installed = False
    if exporter == 'node_exporter':
        is_installed = server.node_exporter_installed
    elif exporter == 'dc_exporter':
        is_installed = server.dc_exporter_installed
    elif exporter == 'dcgm_exporter':
        is_installed = server.dcgm_exporter_installed
    
    # If enabling a not-installed exporter, install it first
    if enabled and not is_installed:
        app.logger.info(f"Auto-installing {exporter} on {server.name} (toggled on but not installed)")
        install_ok = install_exporter_remote(server, exporter)
        if not install_ok:
            return jsonify({
                'success': False,
                'error': f'Failed to install {exporter}',
                'detail': 'Installation via SSH failed. Check server connectivity and permissions.'
            }), 500
        
        # Mark as installed and enabled
        if exporter == 'node_exporter':
            server.node_exporter_installed = True
            server.node_exporter_enabled = True
        elif exporter == 'dc_exporter':
            server.dc_exporter_installed = True
            server.dc_exporter_enabled = True
        elif exporter == 'dcgm_exporter':
            server.dcgm_exporter_installed = True
            server.dcgm_exporter_enabled = True
        
        db.session.commit()
        update_prometheus_targets()
        
        return jsonify({
            'success': True,
            'exporter': exporter,
            'enabled': True,
            'installed': True,
            'message': f'{exporter} installed and started'
        })
    
    # If disabling (stop) — even if not marked installed, try to stop gracefully
    # Control the service via SSH
    success, error_msg = toggle_exporter_service(server, exporter, enabled)
    
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
            'error': f'Failed to {"start" if enabled else "stop"} {exporter}',
            'detail': error_msg or 'Unknown error'
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
    
    # If enabling and agent is not installed (or was removed), auto-install
    if enabled and not server.watchdog_agent_enabled:
        # Quick check: is the service actually available?
        success = toggle_watchdog_service(server, True)
        if not success:
            # Service didn't start — likely not installed. Try installing.
            api_key = get_watchdog_api_key()
            if not api_key:
                return jsonify({
                    'success': False,
                    'error': 'DC Watchdog API key not configured. Link your account via SSO first.'
                }), 400
            
            app.logger.info(f"Auto-installing watchdog agent on {server.name} (toggle on but service not available)")
            install_ok, install_err = install_watchdog_agent_remote(server, api_key)
            if install_ok:
                server.watchdog_agent_installed = True
                server.watchdog_agent_enabled = True
                db.session.commit()
                return jsonify({
                    'success': True,
                    'enabled': True,
                    'installed': True,
                    'message': 'DC Watchdog agent installed and started'
                })
            else:
                return jsonify({
                    'success': False,
                    'error': f'Failed to install watchdog agent: {install_err or "Unknown error"}'
                }), 500
        else:
            # Service started successfully
            server.watchdog_agent_enabled = True
            db.session.commit()
            return jsonify({
                'success': True,
                'enabled': True,
                'message': 'DC Watchdog agent enabled'
            })
    
    # Disabling — just stop the service
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
        
        # Sync with watchdog API after a brief delay to pick up the heartbeat
        import time
        time.sleep(3)
        try:
            _sync_watchdog_status_from_api()
        except Exception:
            pass
        
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
    
    # Wait for agents to send their first heartbeat, then sync status from API
    if results['installed'] > 0:
        import time
        time.sleep(5)  # Give agents time to start and send first heartbeat
        try:
            synced = _sync_watchdog_status_from_api()
            results['synced'] = synced
        except Exception as e:
            results['sync_error'] = str(e)
    
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
    
    return render_template('dashboard.html',
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
    
    return render_template('login.html', error=error, first_run=first_run)

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
    
    return render_template('servers.html',
        servers=servers,
        ssh_keys=ssh_keys,
        version=__version__
    )

@app.route('/settings')
@admin_required
def settings_page():
    """Settings page."""
    ssh_keys = SSHKey.query.all()
    
    return render_template('settings.html',
        ssh_keys=ssh_keys,
        grafana_url=GRAFANA_URL,
        prometheus_url=PROMETHEUS_URL,
        version=__version__
    )

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
