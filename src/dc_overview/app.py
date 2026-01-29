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
        'last_seen': s.last_seen.isoformat() if s.last_seen else None
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
    
    server = Server(
        name=validated_name,
        server_ip=validated_ip,
        ssh_user=validated_user,
        ssh_port=validated_port,
        ssh_key_id=data.get('ssh_key_id')
    )
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
        'ssh': check_ssh_connection(server),
        'node_exporter': check_exporter(server.server_ip, 9100),
        'dc_exporter': check_exporter(server.server_ip, 9835),
        'dcgm_exporter': check_exporter(server.server_ip, 9400)
    }
    
    # Update server status
    server.node_exporter_installed = results['node_exporter']['running']
    server.dc_exporter_installed = results['dc_exporter']['running']
    server.dcgm_exporter_installed = results['dcgm_exporter']['running']
    
    if any([results['node_exporter']['running'], results['dc_exporter']['running']]):
        server.status = 'online'
        server.last_seen = datetime.utcnow()
    else:
        server.status = 'offline'
    
    # Get GPU count from dc-exporter metrics
    gpu_count = get_gpu_count_from_exporter(server.server_ip)
    if gpu_count is not None:
        server.gpu_count = gpu_count
        results['gpu_count'] = gpu_count
    
    # Detect exporter versions
    ssh_key_path = server.ssh_key.key_path if server.ssh_key else None
    
    if server.node_exporter_installed:
        version = get_exporter_version(server.server_ip, 'node_exporter', server.ssh_user, server.ssh_port, ssh_key_path)
        if version:
            server.node_exporter_version = version
            results['node_exporter']['version'] = version
    
    if server.dc_exporter_installed:
        version = get_exporter_version(server.server_ip, 'dc_exporter', server.ssh_user, server.ssh_port, ssh_key_path)
        if version:
            server.dc_exporter_version = version
            results['dc_exporter']['version'] = version
    
    if server.dcgm_exporter_installed:
        version = get_exporter_version(server.server_ip, 'dcgm_exporter', server.ssh_user, server.ssh_port, ssh_key_path)
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
        ssh_key_path = server.ssh_key.key_path if server.ssh_key else None
        update_info = check_for_updates(
            server.server_ip,
            server.ssh_user,
            server.ssh_port,
            ssh_key_path,
            server.exporter_update_branch or 'main'
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
    
    # Get SSH key path if available
    ssh_key_path = server.ssh_key.key_path if server.ssh_key else None
    
    # Get installed versions
    versions = get_all_exporter_versions(
        server.server_ip,
        server.ssh_user,
        server.ssh_port,
        ssh_key_path
    )
    
    # Check for updates
    updates = check_for_updates(
        server.server_ip,
        server.ssh_user,
        server.ssh_port,
        ssh_key_path,
        server.exporter_update_branch
    )
    
    # Update version info in database
    if versions.get('node_exporter'):
        server.node_exporter_version = versions['node_exporter']
    if versions.get('dc_exporter'):
        server.dc_exporter_version = versions['dc_exporter']
    if versions.get('dcgm_exporter'):
        server.dcgm_exporter_version = versions['dcgm_exporter']
    
    db.session.commit()
    
    return jsonify({
        'server_id': server_id,
        'server_name': server.name,
        'versions': versions,
        'updates': updates
    })


@app.route('/api/servers/<int:server_id>/exporters/<exporter>/toggle', methods=['POST'])
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
    success = update_exporter_remote(server, exporter, latest_version, branch)
    
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
            'error': f'Failed to update {exporter}'
        }), 500


@app.route('/api/servers/<int:server_id>/exporters/settings', methods=['POST'])
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
        
        ssh_key_path = server.ssh_key.key_path if server.ssh_key else None
        
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
        ssh_cmd = [
            'ssh',
            '-o', 'ConnectTimeout=10',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'BatchMode=yes',
            '-p', str(server.ssh_port)
        ]
        
        if server.ssh_key:
            ssh_cmd.extend(['-i', server.ssh_key.key_path])
        
        ssh_cmd.append(f'{server.ssh_user}@{server.server_ip}')
        
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
        
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
        return result.returncode == 0
        
    except Exception:
        return False


def update_exporter_remote(server, exporter: str, version: str, branch: str = 'main') -> bool:
    """Update an exporter on a remote server to a specific version."""
    from .exporters import get_exporter_download_url
    
    download_url = get_exporter_download_url(exporter, version, branch)
    if not download_url:
        return False
    
    try:
        ssh_cmd = [
            'ssh',
            '-o', 'ConnectTimeout=10',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'BatchMode=yes',
            '-p', str(server.ssh_port)
        ]
        
        if server.ssh_key:
            ssh_cmd.extend(['-i', server.ssh_key.key_path])
        
        ssh_cmd.append(f'{server.ssh_user}@{server.server_ip}')
        
        if exporter == 'node_exporter':
            # Download, extract, and replace binary
            update_script = f'''
cd /tmp &&
curl -sL "{download_url}" -o node_exporter.tar.gz &&
tar xzf node_exporter.tar.gz &&
systemctl stop node_exporter &&
cp node_exporter-*/node_exporter /usr/local/bin/ &&
chmod +x /usr/local/bin/node_exporter &&
systemctl start node_exporter &&
rm -rf node_exporter* &&
echo "OK"
'''
            ssh_cmd.append(update_script)
            
        elif exporter == 'dc_exporter':
            # Download binary directly
            update_script = f'''
systemctl stop dc-exporter 2>/dev/null || true
curl -sL "{download_url}" -o /usr/local/bin/dc-exporter-rs &&
chmod +x /usr/local/bin/dc-exporter-rs &&
systemctl start dc-exporter &&
echo "OK"
'''
            ssh_cmd.append(update_script)
            
        elif exporter == 'dcgm_exporter':
            # Update Docker image
            update_script = f'''
docker stop dcgm-exporter 2>/dev/null || true
docker rm dcgm-exporter 2>/dev/null || true
docker pull {download_url} &&
docker run -d --name dcgm-exporter --gpus all -p 9400:9400 --restart unless-stopped {download_url} &&
echo "OK"
'''
            ssh_cmd.append(update_script)
        
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=120)
        return 'OK' in result.stdout
        
    except Exception:
        return False


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
    
    return Response(generate_latest(registry), mimetype=CONTENT_TYPE_LATEST)

# =============================================================================
# WEB ROUTES
# =============================================================================

@app.route('/')
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

def check_ssh_connection(server):
    """Test SSH connection to a server."""
    try:
        cmd = [
            'ssh', '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=no',
            '-o', 'BatchMode=yes', '-p', str(server.ssh_port)
        ]
        
        if server.ssh_key:
            cmd.extend(['-i', server.ssh_key.key_path])
        
        cmd.extend([f'{server.ssh_user}@{server.server_ip}', 'echo ok'])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
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
        
        cmd = [
            'ssh', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=no',
            '-p', str(server.ssh_port)
        ]
        
        if server.ssh_key:
            cmd.extend(['-i', server.ssh_key.key_path])
        
        cmd.extend([f'{server.ssh_user}@{server.server_ip}', f'bash -c "{script}"'])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
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
        
        cmd = [
            'ssh', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=no',
            '-p', str(server.ssh_port)
        ]
        
        if server.ssh_key:
            cmd.extend(['-i', server.ssh_key.key_path])
        
        cmd.extend([f'{server.ssh_user}@{server.server_ip}', f'bash -c "{script}"'])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
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
    .nav { display: flex; gap: 15px; }
    .nav a {
        color: var(--text-secondary); text-decoration: none; padding: 8px 16px;
        border-radius: 8px; transition: all 0.2s;
    }
    .nav a:hover, .nav a.active { color: var(--text-primary); background: var(--bg-card); }
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
                <a href="/" class="active">Dashboard</a>
                <a href="/servers">Servers</a>
                <a href="/settings">Settings</a>
                <a href="/logout">Logout</a>
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
                <tbody>
                    {% for server in servers %}
                    <tr>
                        <td><strong>{{ server.name }}</strong></td>
                        <td>{{ server.server_ip }}</td>
                        <td>
                            <span class="status-dot status-{{ server.status }}"></span>
                            {{ server.status }}
                        </td>
                        <td>{{ server.gpu_count }}</td>
                        <td>
                            <span class="exporter-badge {% if server.node_exporter_installed and server.node_exporter_enabled %}enabled{% elif server.node_exporter_installed %}disabled{% else %}not-installed{% endif %}">
                                node{% if server.node_exporter_version %} <span class="version-tag">{{ server.node_exporter_version }}</span>{% endif %}
                            </span>
                            <span class="exporter-badge {% if server.dc_exporter_installed and server.dc_exporter_enabled %}enabled{% elif server.dc_exporter_installed %}disabled{% else %}not-installed{% endif %}">
                                dc{% if server.dc_exporter_version %} <span class="version-tag">{{ server.dc_exporter_version }}</span>{% endif %}
                            </span>
                            <span class="exporter-badge {% if server.dcgm_exporter_installed and server.dcgm_exporter_enabled %}enabled{% elif server.dcgm_exporter_installed %}disabled{% else %}not-installed{% endif %}">
                                dcgm{% if server.dcgm_exporter_version %} <span class="version-tag">{{ server.dcgm_exporter_version }}</span>{% endif %}
                            </span>
                        </td>
                        <td>{{ server.last_seen.strftime('%Y-%m-%d %H:%M') if server.last_seen else '—' }}</td>
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
    
    // Refresh dashboard data by reloading
    async function refreshDashboard() {
        try {
            // Silently refresh the page data every 30 seconds
            const response = await fetch(`${basePath}/api/servers`);
            if (response.ok) {
                // Data has been updated via the check endpoints, so reload
                window.location.reload();
            }
        } catch (e) {
            console.error('Failed to refresh dashboard:', e);
        }
    }
    
    document.addEventListener('DOMContentLoaded', async () => {
        await checkUserPermissions();
        // Auto-check all servers on first load, then reload to show updated status
        const indicator = document.getElementById('checkingIndicator');
        try {
            const response = await fetch(`${basePath}/api/servers`);
            const servers = await response.json();
            if (servers && servers.length > 0) {
                // Show checking indicator
                if (indicator) indicator.style.display = 'block';
                // Check each server silently
                for (const server of servers) {
                    try {
                        await fetch(`${basePath}/api/servers/${server.id}/check`);
                    } catch (e) {}
                }
                // Hide indicator
                if (indicator) indicator.style.display = 'none';
                // Reload to show updated status (skip if we just reloaded)
                const lastReload = parseInt(sessionStorage.getItem('dashboard_reload_time') || '0');
                const now = Date.now();
                if (now - lastReload > 10000) { // Only reload if >10 seconds since last reload
                    sessionStorage.setItem('dashboard_reload_time', now.toString());
                    window.location.reload();
                }
            }
        } catch (e) {
            console.error('Failed to auto-check servers:', e);
            if (indicator) indicator.style.display = 'none';
        }
        // Set up periodic refresh every 60 seconds
        setInterval(refreshDashboard, 60000);
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
                <a href="/">Dashboard</a>
                <a href="/servers" class="active">Servers</a>
                <a href="/settings">Settings</a>
                <a href="/logout">Logout</a>
            </div>
        </div>
        
        <div class="card">
            <h2>Add Server</h2>
            <form id="addServerForm">
                <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px;">
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
                        <td>{{ server.ssh_user }}@:{{ server.ssh_port }}</td>
                        <td class="exporter-status">
                            <span class="status-indicator {% if server.node_exporter_installed and server.node_exporter_enabled %}status-enabled{% elif server.node_exporter_installed %}status-disabled{% else %}status-not-installed{% endif %}"></span>node
                            <span class="status-indicator {% if server.dc_exporter_installed and server.dc_exporter_enabled %}status-enabled{% elif server.dc_exporter_installed %}status-disabled{% else %}status-not-installed{% endif %}" style="margin-left:8px"></span>dc
                            <span class="status-indicator {% if server.dcgm_exporter_installed and server.dcgm_exporter_enabled %}status-enabled{% elif server.dcgm_exporter_installed %}status-disabled{% else %}status-not-installed{% endif %}" style="margin-left:8px"></span>dcgm
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
            <div id="modalContent">
                <!-- Dynamic content -->
            </div>
        </div>
    </div>
    
    <script>
    // Get base path for API calls - extract /dc from any subpath like /dc/servers
    const basePath = window.location.pathname.match(/^(\/[^\/]+)/)?.[1] || '';
    
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
    
    // Run permission check on load, then auto-check all servers
    document.addEventListener('DOMContentLoaded', async () => {
        await checkUserPermissions();
        // Auto-check all servers on page load (silent, no alerts)
        await checkAllServersQuietly();
        // Set up periodic refresh every 30 seconds
        setInterval(checkAllServersQuietly, 30000);
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
        // Update the exporter status indicators
        const statusCell = row.querySelector('.exporter-status');
        if (!statusCell) return;
        
        const indicators = statusCell.querySelectorAll('.status-indicator');
        if (indicators.length >= 3) {
            // node exporter
            indicators[0].className = 'status-indicator ' + 
                (result.node_exporter?.running ? 'status-enabled' : 'status-not-installed');
            // dc exporter  
            indicators[1].className = 'status-indicator ' + 
                (result.dc_exporter?.running ? 'status-enabled' : 'status-not-installed');
            // dcgm exporter
            indicators[2].className = 'status-indicator ' + 
                (result.dcgm_exporter?.running ? 'status-enabled' : 'status-not-installed');
        }
        
        // Add version info if available
        const nodeSpan = statusCell.innerHTML.match(/node<br>([^<]*)/);
        let html = '';
        html += `<span class="status-indicator ${result.node_exporter?.running ? 'status-enabled' : 'status-not-installed'}"></span>node`;
        if (result.node_exporter?.version) html += `<br><small>${result.node_exporter.version}</small>`;
        html += `<span class="status-indicator ${result.dc_exporter?.running ? 'status-enabled' : 'status-not-installed'}" style="margin-left:8px"></span>dc`;
        if (result.dc_exporter?.version) html += `<br><small>${result.dc_exporter.version}</small>`;
        html += `<span class="status-indicator ${result.dcgm_exporter?.running ? 'status-enabled' : 'status-not-installed'}" style="margin-left:8px"></span>dcgm`;
        if (result.dcgm_exporter?.version) html += `<br><small>${result.dcgm_exporter.version}</small>`;
        statusCell.innerHTML = html;
    }
    
    document.getElementById('addServerForm').onsubmit = async (e) => {
        e.preventDefault();
        const form = e.target;
        const data = {
            name: form.name.value,
            server_ip: form.server_ip.value,
            ssh_user: form.ssh_user.value
        };
        
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
    
    async function openServerDetail(id, name) {
        currentServerId = id;
        document.getElementById('modalServerName').textContent = name + ' - Exporter Management';
        document.getElementById('serverDetailModal').style.display = 'flex';
        document.getElementById('modalContent').innerHTML = '<p>Loading...</p>';
        
        // Fetch exporter versions
        const response = await fetch(`${basePath}/api/servers/${id}/exporters/versions`);
        const data = await response.json();
        
        renderExporterManagement(data);
    }
    
    function renderExporterManagement(data) {
        const exporters = [
            { key: 'node_exporter', name: 'Node Exporter', port: 9100 },
            { key: 'dc_exporter', name: 'DC Exporter', port: 9835 },
            { key: 'dcgm_exporter', name: 'DCGM Exporter', port: 9400 }
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
        
        alert(`SSH: ${result.ssh.connected ? 'OK' : 'Failed'}
Node Exporter: ${result.node_exporter.running ? 'Running' : 'Not running'}
DC Exporter: ${result.dc_exporter.running ? 'Running' : 'Not running'}
DCGM Exporter: ${result.dcgm_exporter.running ? 'Running' : 'Not running'}`);
        
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
                <a href="/">Dashboard</a>
                <a href="/servers">Servers</a>
                <a href="/settings" class="active">Settings</a>
                <a href="/logout">Logout</a>
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
            <h2>API Endpoints</h2>
            <table>
                <tr><td><code>/api/health</code></td><td>Health check</td></tr>
                <tr><td><code>/api/servers</code></td><td>List/manage servers</td></tr>
                <tr><td><code>/api/ssh-keys</code></td><td>List/manage SSH keys</td></tr>
                <tr><td><code>/api/prometheus/targets.json</code></td><td>Prometheus file_sd targets</td></tr>
                <tr><td><code>/metrics</code></td><td>Prometheus metrics</td></tr>
            </table>
        </div>
        
        <p class="version">Server Manager v{{ version }}</p>
    </div>
    
    <script>
    // Get base path for API calls - extract /dc from any subpath like /dc/settings
    const basePath = window.location.pathname.match(/^(\/[^\/]+)/)?.[1] || '';
    
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
    </script>
</body></html>
"""

# =============================================================================
# INITIALIZATION
# =============================================================================

def init_db():
    """Initialize database."""
    with app.app_context():
        db.create_all()

# Initialize on import
init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=DC_OVERVIEW_PORT, debug=True)
