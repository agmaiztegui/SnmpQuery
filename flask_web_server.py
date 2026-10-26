"""
Flask Web Interface for Network Query System
============================================

This is a starting point that integrates with your existing functions.py.
Adapt the imports and paths to match your actual project structure.

Requirements:
    pip install flask flask-login

File structure expected:
    your_project/
    ├── functions.py          # Your SQL query functions
    ├── webServer.py          # This file
    ├── templates/
    │   ├── base.html
    │   ├── login.html
    │   ├── dashboard.html
    │   └── results.html
    └── static/
        └── style.css


SnmpQuery - Network Discovery and Monitoring Tool
Copyright (C) 2025 Agustin Garcia Maiztegui

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""



from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
import sqlite3
from datetime import datetime
import pathlib
import funciones
from api_command import api_bp

# ============================================================================
# CONFIGURATION
# ============================================================================

app = Flask(__name__)
app.secret_key = 'change-this-to-something-random-and-secure'  # CHANGE THIS!
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Programmatic JSON API (token-protected POST /command). See api_command.py.
app.register_blueprint(api_bp)

# Paths - ADJUST THESE to match your setup
RAMDISK_DB = "/ramdisk/snmpqserver.db"
BASE_DIR = pathlib.Path(__file__).resolve().parent
histDBPath = BASE_DIR / "historicaldata.db"
histDB = sqlite3.connect(histDBPath, isolation_level=None)
HISTORIC_DB = str(histDBPath)  # Adjust to your BASE_DIR / "historicaldata.db"


# Simple user database (replace with your own system)
USERS = {
    'admin': 'xxxx',  # username: password - CHANGE THESE!
    'operator': 'xxxx'
}

# Color mapping for web (translated from your CLI colors)
WEB_COLORS = {
    "hostip": "#99ff99",
    "mac": "#CCff99",
    "name": "#00dd00",
    "vendor": "#99ff99",
    "vlan": "#ff5555",
    "swip": "#a288ff",
    "swmac": "#c8a2ff",
    "port": "#a288ff",
    "swname": "#a288ff",
    "lineas": "#bbbbbb",
    "comand": "#999999",
    "tooltip": "#898989",
    "warn_bg": "#ff5555",
    "warn_fg": "#000000"
}

# ============================================================================
# USER MANAGEMENT (Flask-Login)
# ============================================================================

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    if user_id in USERS:
        return User(user_id)
    return None


# ============================================================================
# QUERY PARSER (adapted from your interpretarDireccion)
# ============================================================================

def parse_query(query_string):
    """
    Parses user input and returns (command_name, params, error)
    Similar to your queryServer.py logic
    
    Returns:
        (command_name, params, None) on success
        (None, None, error_message) on failure
    """
    query_string = query_string.strip()
    if not query_string:
        return (None, None, "Empty query")
    
    parts = query_string.split()
    cmd = parts[0].lower()
    params = parts[1:]
    
    # Import COMMANDS from your functions.py
    # TODO: Replace this with: from functions import COMMANDS
    # For now, using a local definition
    AVAILABLE_COMMANDS = ['status', 'switchport', 'map', 'report', 'ip', 'mac']
    
    # Check if it's a direct command
    if cmd in AVAILABLE_COMMANDS:
        return (cmd, params if params else None, None)
    
    # Not a command - try to interpret as IP/MAC (your interpretarDireccion logic)
    interpreted_cmd, interpreted_params = interpretarDireccion(query_string)
    
    if interpreted_cmd == 'ip':
        return ('ip', interpreted_params, None)
    elif interpreted_cmd == 'mac':
        return ('mac', interpreted_params, None)
    
    return (None, None, f"Unknown command or invalid input: '{query_string}'")

def interpretarDireccion(cmd):
    """Your existing IP/MAC detection logic"""
    # 1. Is it an IP?
    octetos = cmd.split(".")
    if len(octetos) == 4:
        try:
            octetos = [int(o) for o in octetos]
            if all(0 <= o <= 255 for o in octetos):
                return ("ip", (cmd,))
        except ValueError:
            pass
    
    # 2. Is it a full MAC?
    posibleMac = funciones.sanitizeMAC(cmd)
    mac_address_std = funciones.standarizeFullMAC(posibleMac)
    if mac_address_std:
        return ("mac", (mac_address_std,))
    
    # 3. Is it a partial MAC?
    if funciones.validarMacParcial(posibleMac):
        return ("mac", (posibleMac,))
    
    return (None, None)

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def format_timestamp(timestamp_str):
    """Convert Unix timestamp string to human-readable format"""
    try:
        ts = float(timestamp_str)
        dt = datetime.fromtimestamp(ts)
        now = datetime.now()
        diff = now - dt
        
        if diff.total_seconds() < 60:
            segundos = int(diff.total_seconds())
            return f"just now ({segundos}s)"
        elif diff.total_seconds() < 3600:
            mins = int(diff.total_seconds() / 60)
            return f"{mins} min{'s' if mins != 1 else ''} ago"
        elif diff.total_seconds() < 86400:
            hours = int(diff.total_seconds() / 3600)
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        else:
            return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return timestamp_str

def get_query_history():
    """Get current user's query history from session"""
    return session.get('query_history', [])

def add_to_history(query):
    """Add query to current user's history (keep last 20)"""
    history = get_query_history()
    if query not in history:
        history.insert(0, query)
        history = history[:20]  # Keep only last 20
        session['query_history'] = history

# ============================================================================
# ROUTES
# ============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in USERS and USERS[username] == password:
            user = User(username)
            login_user(user, remember=True)
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid credentials")
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def dashboard():
    """Main dashboard - shows funciones.status() by default"""
    try:
        switches = funciones.status()
        
        if request.method == 'POST':
            print(request.form.get('netflow_window_dash'))
            print("METHOD:", request.method)
            print("FORM:", request.form)
        
        
        netflow_minutes = float(request.form.get('netflow_window_dash', 5))
        netflow_stats = funciones.netflow_global_stats(minutes=netflow_minutes)
        # netflow_stats = funciones.netflow_global_stats(minutes=5)
        return render_template('dashboard.html', 
                             switches=switches,
                             netflow_stats=netflow_stats,
                             history=get_query_history(),
                             colors=WEB_COLORS,
                             format_timestamp=format_timestamp)
    except Exception as e:
        return render_template('dashboard.html', 
                             error=f"Error loading switches: {e}",
                             history=get_query_history())

@app.route('/query', methods=['POST'])
@login_required
def query():
    """Handle query submissions"""
    query_string = request.form.get('query', '').strip()
    auto_refresh = request.form.get('auto_refresh') == 'on'
    refresh_interval = int(request.form.get('refresh_interval', 5))
    
    if not query_string:
        return redirect(url_for('dashboard'))
    
    # Parse query to get command name and params
    cmd_name, params, error = parse_query(query_string)
    
    if error:
        return render_template('results.html',
                             error=error,
                             query=query_string,
                             history=get_query_history())
    
    try:
        # TODO: Import COMMANDS from your functions.py
        # from functions import COMMANDS
        
        # For now, create a mapping (replace this after importing)
        COMMAND_MAP = {
            'status': funciones.status,
            'switchport': funciones.switchport,
            'map': funciones.mapSwitch,
            'report': funciones.report,
            'ip': funciones.ipSearch,
            'mac': lambda mac: funciones.macSearch(mac) if funciones.standarizeFullMAC(mac) else funciones.macSearchPart(mac)
        }
        
        # Execute the command
        func = COMMAND_MAP.get(cmd_name)
        if not func:
            raise ValueError(f"Unknown command: {cmd_name}")
        
        if params:
            result = func(*params)
        else:
            result = func()

        # Sort Results.
        show_netflow = False
        netflow_data = None
        if (cmd_name == "ip" or cmd_name == "mac"):
            # es ip, mac ó mac parcial.
            devices, aps = result
            devices = sorted( devices, key=lambda d: (d[1], int(d[2])) )
            result = (devices, aps)
            #
            if(devices is not None):
                if len(devices) == 1:
                    show_netflow = True
                    host_ip = devices[0][5]  # IP address is at index 5
                    netflow_minutes = float(request.form.get('netflow_window', 5))
                    netflow_data = funciones.netflow_host_stats(host_ip, minutes=netflow_minutes)
        
        elif cmd_name == "switchport":
            # Show NetFlow if only one device on port
            switch_info, devices = result
            if(devices is not None):
                if len(devices) == 1:
                    show_netflow = True
                    host_ip = devices[0][3]  # IP at index 3 in switchport result
                    netflow_minutes = float(request.form.get('netflow_window', 5))
                    netflow_data = funciones.netflow_host_stats(host_ip, minutes=netflow_minutes)
        
        
        # Add to history
        add_to_history(query_string)
        
        # Map command names to query types for template rendering
        query_type_map = {
            'status': 'status',
            'switchport': 'switchport',
            'map': 'mapSwitch',
            'report': 'report',
            'ip': 'ipSearch',
            'mac': 'macSearch'
        }
        return render_template('results.html',
                             query=query_string,
                             query_type=query_type_map.get(cmd_name, cmd_name),
                             result=result,
                             show_netflow=show_netflow,
                             netflow_data=netflow_data,
                             history=get_query_history(),
                             auto_refresh=auto_refresh,
                             refresh_interval=refresh_interval,
                             colors=WEB_COLORS,
                             format_timestamp=format_timestamp)
    
    except Exception as e:
        return render_template('results.html',
                             error=f"Query execution error: {e}",
                             query=query_string,
                             history=get_query_history())

@app.route('/api/query', methods=['POST'])
@login_required
def api_query():
    """API endpoint for AJAX queries (for auto-refresh)"""
    data = request.get_json()
    query_string = data.get('query', '')
    
    func, params, error = parse_query(query_string)
    
    if error:
        return jsonify({'error': error}), 400
    
    try:
        if params:
            result = func(*params)
        else:
            result = func()
        
        # Convert result to JSON-serializable format
        return jsonify({
            'success': True,
            'query_type': func.__name__,
            'result': result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    # Run on all interfaces so it's accessible on LAN
    # Use debug=False in production!
    app.run(host='0.0.0.0', port=5000, debug=True)
