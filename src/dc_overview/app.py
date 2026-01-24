#!/usr/bin/env python3
"""
DC Overview - GPU Datacenter Monitoring Web Application

A Flask-based dashboard for managing GPU datacenter monitoring with Prometheus & Grafana.
Provides server management, exporter deployment, and monitoring status.

GitHub: https://github.com/cryptolabsza/dc-overview
License: MIT
"""

from flask import Flask, render_template_string, jsonify, request, Response, session, redirect, url_for
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from prometheus_client import Gauge, Counter, generate_latest, CONTENT_TYPE_LATEST, CollectorRegistry
import subprocess
import threading
import time
import json
import os
import socket
import secrets
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

# Application settings
APPLICATION_ROOT = os.environ.get('APPLICATION_ROOT', '/dc')
GRAFANA_URL = os.environ.get('GRAFANA_URL', 'http://grafana:3000')
PROMETHEUS_URL = os.environ.get('PROMETHEUS_URL', 'http://prometheus:9090')
DC_OVERVIEW_PORT = int(os.environ.get('DC_OVERVIEW_PORT', '5001'))

db = SQLAlchemy(app)

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
    
    # Exporter status
    node_exporter_installed = db.Column(db.Boolean, default=False)
    dc_exporter_installed = db.Column(db.Boolean, default=False)
    dcgm_exporter_installed = db.Column(db.Boolean, default=False)
    
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
    """
    # Check if the proxy auth flag is set
    if request.headers.get(PROXY_AUTH_HEADER_FLAG) == 'true':
        username = request.headers.get(PROXY_AUTH_HEADER_USER)
        if username:
            # Auto-authenticate the session
            if not session.get('authenticated'):
                session['authenticated'] = True
                session['username'] = username
                session['role'] = request.headers.get(PROXY_AUTH_HEADER_ROLE, 'admin')
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

def login_required(f):
    """Decorator for routes that require authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not check_auth():
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def is_running_behind_proxy():
    """Check if we're running behind the fleet proxy."""
    return request.headers.get(PROXY_AUTH_HEADER_FLAG) == 'true'

# =============================================================================
# API ROUTES
# =============================================================================

@app.route('/api/health')
def api_health():
    """Health check endpoint for Docker/proxy."""
    return jsonify({
        'status': 'ok',
        'service': 'dc-overview',
        'version': __version__,
        'timestamp': datetime.utcnow().isoformat()
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
        'node_exporter': s.node_exporter_installed,
        'dc_exporter': s.dc_exporter_installed,
        'dcgm_exporter': s.dcgm_exporter_installed,
        'last_seen': s.last_seen.isoformat() if s.last_seen else None
    } for s in servers])

@app.route('/api/servers', methods=['POST'])
@login_required
def api_add_server():
    """Add a new server to monitor."""
    data = request.json
    
    if not data.get('name') or not data.get('server_ip'):
        return jsonify({'error': 'name and server_ip required'}), 400
    
    # Check for duplicate
    existing = Server.query.filter(
        (Server.name == data['name']) | (Server.server_ip == data['server_ip'])
    ).first()
    if existing:
        return jsonify({'error': 'Server with this name or IP already exists'}), 409
    
    server = Server(
        name=data['name'],
        server_ip=data['server_ip'],
        ssh_user=data.get('ssh_user', 'root'),
        ssh_port=data.get('ssh_port', 22),
        ssh_key_id=data.get('ssh_key_id')
    )
    db.session.add(server)
    db.session.commit()
    
    # Update Prometheus config
    update_prometheus_targets()
    
    return jsonify({'id': server.id, 'message': 'Server added'}), 201

@app.route('/api/servers/<int:server_id>', methods=['DELETE'])
@login_required
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
    
    db.session.commit()
    
    return jsonify(results)

@app.route('/api/servers/<int:server_id>/install-exporters', methods=['POST'])
@login_required
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
def api_prometheus_file_sd():
    """
    File-based service discovery for Prometheus.
    Can be used with file_sd_configs in prometheus.yml
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
        'fingerprint': k.fingerprint,
        'created_at': k.created_at.isoformat()
    } for k in keys])

@app.route('/metrics')
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
def login():
    """Login page."""
    error = None
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        stored_hash = get_setting('admin_password_hash')
        
        # First run - set password
        if not stored_hash:
            if len(password) >= 4:
                set_setting('admin_password_hash', generate_password_hash(password))
                session['authenticated'] = True
                return redirect(url_for('index'))
            else:
                error = 'Password must be at least 4 characters'
        else:
            if check_password_hash(stored_hash, password):
                session['authenticated'] = True
                return redirect(url_for('index'))
            else:
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
@login_required
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
            wget -q https://github.com/cryptolabsza/dc-exporter/releases/latest/download/dc-exporter-collector -O /usr/local/bin/dc-exporter-collector
            wget -q https://github.com/cryptolabsza/dc-exporter/releases/latest/download/dc-exporter-server -O /usr/local/bin/dc-exporter-server
            chmod +x /usr/local/bin/dc-exporter-collector /usr/local/bin/dc-exporter-server
            mkdir -p /etc/dc-exporter
            cat > /etc/systemd/system/dc-exporter.service << 'EOF'
[Unit]
Description=DC Exporter - GPU VRAM Temperature Monitor
After=network.target

[Service]
Type=simple
WorkingDirectory=/etc/dc-exporter
ExecStart=/bin/bash -c "/usr/local/bin/dc-exporter-collector --no-console & /usr/local/bin/dc-exporter-server"
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

def update_prometheus_targets():
    """Update Prometheus targets file for file-based service discovery."""
    try:
        targets_file = Path(DATA_DIR) / 'prometheus_targets.json'
        servers = Server.query.all()
        targets = []
        
        for server in servers:
            if server.node_exporter_installed:
                targets.append({
                    'targets': [f"{server.server_ip}:9100"],
                    'labels': {'instance': server.name, 'job': 'node-exporter'}
                })
            if server.dc_exporter_installed:
                targets.append({
                    'targets': [f"{server.server_ip}:9835"],
                    'labels': {'instance': server.name, 'job': 'dc-exporter'}
                })
            if server.dcgm_exporter_installed:
                targets.append({
                    'targets': [f"{server.server_ip}:9400"],
                    'labels': {'instance': server.name, 'job': 'dcgm-exporter'}
                })
        
        targets_file.write_text(json.dumps(targets, indent=2))
    except Exception:
        pass  # Non-critical operation

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
</style>
"""

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html><head>
    <title>DC Overview - Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    """ + BASE_STYLE + """
</head>
<body>
    <div class="container" style="max-width: 400px; margin-top: 100px;">
        <div class="card">
            <h2 style="text-align: center; margin-bottom: 20px;">
                📊 DC Overview
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
    <title>DC Overview - Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    """ + BASE_STYLE + """
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 DC Overview</h1>
            <div class="nav">
                <a href="/" class="active">Dashboard</a>
                <a href="/servers">Servers</a>
                <a href="/settings">Settings</a>
                <a href="{{ grafana_url }}" target="_blank">Grafana ↗</a>
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
            <h2>GPU Workers</h2>
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
                            {% if server.node_exporter_installed %}✓ node {% endif %}
                            {% if server.dc_exporter_installed %}✓ dc {% endif %}
                            {% if server.dcgm_exporter_installed %}✓ dcgm {% endif %}
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
        
        <div class="card">
            <h2>Quick Links</h2>
            <div style="display: flex; gap: 15px; flex-wrap: wrap;">
                <a href="{{ grafana_url }}" target="_blank" class="btn btn-primary">📈 Open Grafana</a>
                <a href="{{ prometheus_url }}/targets" target="_blank" class="btn btn-secondary">🔍 Prometheus Targets</a>
                <a href="/api/prometheus/targets.json" target="_blank" class="btn btn-secondary">📋 Targets JSON</a>
            </div>
        </div>
        
        <p class="version">DC Overview v{{ version }}</p>
    </div>
</body></html>
"""

SERVERS_TEMPLATE = """
<!DOCTYPE html>
<html><head>
    <title>DC Overview - Servers</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    """ + BASE_STYLE + """
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 DC Overview</h1>
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
            <h2>Managed Servers</h2>
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
                            {% if server.node_exporter_installed %}✓ node {% endif %}
                            {% if server.dc_exporter_installed %}✓ dc {% endif %}
                            {% if server.dcgm_exporter_installed %}✓ dcgm {% endif %}
                            {% if not server.node_exporter_installed and not server.dc_exporter_installed %}—{% endif %}
                        </td>
                        <td>
                            <button class="btn btn-secondary" onclick="checkServer({{ server.id }})">Check</button>
                            <button class="btn btn-secondary" onclick="installExporters({{ server.id }})">Install</button>
                            <button class="btn btn-danger" onclick="deleteServer({{ server.id }})">Delete</button>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <p class="version">DC Overview v{{ version }}</p>
    </div>
    
    <script>
    document.getElementById('addServerForm').onsubmit = async (e) => {
        e.preventDefault();
        const form = e.target;
        const data = {
            name: form.name.value,
            server_ip: form.server_ip.value,
            ssh_user: form.ssh_user.value
        };
        
        const response = await fetch('/api/servers', {
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
    
    async function checkServer(id) {
        const btn = event.target;
        btn.textContent = 'Checking...';
        btn.disabled = true;
        
        const response = await fetch(`/api/servers/${id}/check`);
        const result = await response.json();
        
        alert(`SSH: ${result.ssh.connected ? 'OK' : 'Failed'}
Node Exporter: ${result.node_exporter.running ? 'Running' : 'Not running'}
DC Exporter: ${result.dc_exporter.running ? 'Running' : 'Not running'}
DCGM Exporter: ${result.dcgm_exporter.running ? 'Running' : 'Not running'}`);
        
        location.reload();
    }
    
    async function installExporters(id) {
        if (!confirm('Install node_exporter and dc-exporter on this server?')) return;
        
        const btn = event.target;
        btn.textContent = 'Installing...';
        btn.disabled = true;
        
        const response = await fetch(`/api/servers/${id}/install-exporters`, {
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
        
        await fetch(`/api/servers/${id}`, {method: 'DELETE'});
        location.reload();
    }
    </script>
</body></html>
"""

SETTINGS_TEMPLATE = """
<!DOCTYPE html>
<html><head>
    <title>DC Overview - Settings</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    """ + BASE_STYLE + """
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 DC Overview</h1>
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
                    <tr><th>Name</th><th>Fingerprint</th><th>Created</th></tr>
                </thead>
                <tbody>
                    {% for key in ssh_keys %}
                    <tr>
                        <td>{{ key.name }}</td>
                        <td style="font-family: monospace; font-size: 0.85rem;">{{ key.fingerprint or '—' }}</td>
                        <td>{{ key.created_at.strftime('%Y-%m-%d') }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <p style="color: var(--text-secondary);">No SSH keys configured.</p>
            {% endif %}
        </div>
        
        <div class="card">
            <h2>API Endpoints</h2>
            <table>
                <tr><td><code>/api/health</code></td><td>Health check</td></tr>
                <tr><td><code>/api/servers</code></td><td>List/manage servers</td></tr>
                <tr><td><code>/api/prometheus/targets.json</code></td><td>Prometheus file_sd targets</td></tr>
                <tr><td><code>/metrics</code></td><td>Prometheus metrics</td></tr>
            </table>
        </div>
        
        <p class="version">DC Overview v{{ version }}</p>
    </div>
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
