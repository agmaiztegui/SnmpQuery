"""
api_command.py - Programmatic JSON API for SnmpQuery
====================================================

A small Flask Blueprint that exposes the existing query commands over a
token-protected POST endpoint, returning structured JSON built from the raw
data objects (the tuples/lists the funciones.py queries return) BEFORE any
table/HTML formatting.

Every value is emitted as an object:

    {"field": "<name>", "value": <value>, "color_tag": "<palette key>"}

  - field:     what the value is (e.g. "switch_ip", "mac", "timestamp"), so
               the receiver never has to infer meaning from position.
  - value:     the raw value from the query.
  - color_tag: which palette entry colours it (same tags the web UI uses),
               or None for the default foreground colour.

The colour palette itself is included once per response under "palette" so a
consumer resolves color_tag -> hex without the per-field hex overhead.

Design goals
------------
- Does NOT touch the existing web interface. Register the blueprint and you
  get a new POST /command endpoint alongside everything else.
- Reuses funciones.* directly (same objects the web UI uses).
- Static-token auth via the "X-API-Token" header. Token is read from the
  [api] section of the ini file (key: token), with env var
  SNMPQUERY_API_TOKEN as a fallback.

Wiring (2 lines in flask_web_server.py, after `app = Flask(__name__)`):

    from api_command import api_bp
    app.register_blueprint(api_bp)

Usage:

    curl -s -X POST http://127.0.0.1:5000/command \
         -H "Content-Type: application/json" \
         -H "X-API-Token: YOURTOKEN" \
         -d '{"command": "192.168.0.2"}'


SnmpQuery - Network Discovery and Monitoring Tool
Copyright (C) 2025 Agustin Garcia Maiztegui

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import os
import pathlib
from functools import wraps

from flask import Blueprint, request, jsonify

import funciones


# ============================================================================
# COLOUR PALETTE  (kept identical to WEB_COLORS in flask_web_server.py)
# Included once per response so the JSON is self-contained.
# ============================================================================

WEB_COLORS = {
    "hostip":  "#99ff99",
    "mac":     "#CCff99",
    "name":    "#00dd00",
    "vendor":  "#99ff99",
    "vlan":    "#ff5555",
    "swip":    "#a288ff",
    "swmac":   "#c8a2ff",
    "port":    "#a288ff",
    "swname":  "#a288ff",
    "lineas":  "#bbbbbb",
    "comand":  "#999999",
    "tooltip": "#898989",
    "warn_bg": "#ff5555",
    "warn_fg": "#000000",
}
# Fields that the web templates render without a colour class get tag=None in
# the JSON; a consumer shows those in the default/foreground colour, exactly as
# the web UI does.


# ============================================================================
# TOKEN LOADING
# ============================================================================

BASE_DIR = pathlib.Path(__file__).resolve().parent


def _load_api_token():
    """
    Resolve the API token.

    Priority:
      1. Env var SNMPQUERY_API_TOKEN  (overrides everything)
      2. An  API_TOKEN=...  line in snmpQuery.ini

    snmpQuery.ini is the project's flat KEY=VALUE file (no [section] headers,
    same format read by snmpPyServer.leerPreferencias), so we parse it the same
    way: find the line that starts with API_TOKEN= and take the rest. Lines
    beginning with '#' are comments.

    Returns the token string, or None if none configured (endpoint then 503s).
    """
    env = os.environ.get("SNMPQUERY_API_TOKEN")
    if env:
        return env.strip()

    ini_path = BASE_DIR / "snmpQuery.ini"
    if ini_path.exists():
        try:
            with open(ini_path, "r") as fh:
                for line in fh:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    if stripped.startswith("API_TOKEN="):
                        tok = stripped.split("=", 1)[1].strip()
                        if tok:
                            return tok
        except OSError:
            pass
    return None


API_TOKEN = _load_api_token()


# ============================================================================
# TAG HELPERS
# ============================================================================

def cell(field, value, color_tag):
    """
    One value, fully described:
      - field:     the semantic name of this column (what the value IS),
                   e.g. "switch_ip", "mac", "timestamp".
      - value:     the raw value from the query.
      - color_tag: which palette entry colours it, or None for the default
                   foreground colour (the web UI renders those columns plain).
    """
    return {"field": field, "value": value, "color_tag": color_tag}


def tagged_row(values, specs):
    """
    Pair a sequence of values with a parallel sequence of (field, color_tag)
    specs. Shorter 'values' is fine (trailing specs ignored); extras ignored.
    """
    return [cell(field, v, color_tag) for v, (field, color_tag) in zip(values, specs)]


# ============================================================================
# PER-COMMAND SERIALISERS
# Each turns a raw funciones.* return into tagged JSON. One place to edit if a
# query's column order ever changes - keeps web UI and API in agreement.
#
# Each 'specs' list is (field_name, color_tag) per column, in the exact order
# the query returns. field_name = what the value is; color_tag = how the web
# UI colours it (None = no colour class, shown in the default foreground).
# ============================================================================

def ser_status(rows):
    """
    status() -> list of:
      (switchIP, switchDesc, switchStatus, trunks, access, switchMAC, vendor, stamp)
    """
    specs = [
        ("switch_ip",     "swip"),
        ("switch_desc",   "swip"),
        ("switch_status", "swip"),
        ("trunks",        "swip"),
        ("access",        "swip"),
        ("switch_mac",    "swmac"),
        ("vendor",        "swip"),
        ("timestamp",     "tooltip"),
    ]
    return {"switches": [tagged_row(r, specs) for r in (rows or [])]}


def ser_switchport(result):
    """
    switchport() -> (datosSwitch, resultados)
      datosSwitch: (portType, switchDesc, switchMAC)
      resultados:  [(stamp, mac, vlan, ip, vendor, hostname), ...]
    """
    switch_info, devices = result
    switch_specs = [
        ("port_type",   "port"),
        ("switch_desc", "swip"),
        ("switch_mac",  "swmac"),
    ]
    dev_specs = [
        ("timestamp", "tooltip"),
        ("mac",       "mac"),
        ("vlan",      "vlan"),
        ("ip",        "hostip"),
        ("vendor",    "vendor"),
        ("hostname",  "name"),
    ]
    return {
        "switch": tagged_row(switch_info, switch_specs) if switch_info else None,
        "devices": [tagged_row(d, dev_specs) for d in (devices or [])],
    }


def ser_hostlist(result):
    """
    ipSearch / macSearch / macSearchPart -> (devolver, unAP)
      devolver: (stamp, switchIP, port, mac, vlan, ip, vendor, hostname,
                 switchDesc, switchMAC)
      unAP:     [(apMac, apName), ...]
    Field names mirror the unpacking in results.html.
    """
    devices, aps = result
    dev_specs = [
        ("timestamp",   "tooltip"),
        ("switch_ip",   "swip"),
        ("port",        "port"),
        ("mac",         "mac"),
        ("vlan",        "vlan"),
        ("ip",          "hostip"),
        ("vendor",      "vendor"),
        ("hostname",    "name"),
        ("location",    "swname"),
        ("switch_mac",  "swmac"),
    ]
    ap_specs = [("ap_mac", "mac"), ("ap_name", "name")]
    return {
        "devices": [tagged_row(d, dev_specs) for d in (devices or [])],
        "access_points": [tagged_row(a, ap_specs) for a in (aps or [])],
    }


def ser_map(rows):
    """
    mapSwitch() -> [(upstream_port, switchIP, downstream_port), ...]
    First tuple is the queried switch (upstream_port None); last is ROOT
    (downstream_port None). Emitted as a uniform list of cell-rows so every
    command parses the same way.
    """
    specs = [
        ("upstream_port",   "port"),
        ("switch_ip",       "swip"),
        ("downstream_port", "port"),
    ]
    return {"hops": [tagged_row(r, specs) for r in (rows or [])]}


def ser_report(result):
    """
    report() -> (cabecera, puertos)
      cabecera: same shape as one status() row (list with 1 row)
      puertos : (port, portDesc, type, role, mac, ip, host, vendor, vlan,
                 swHijo, prtHijo(deprecated), swPadre, prtPadre, hijoRoot)
    portDesc, type, role, child_port_deprecated, parent_port and
    child_root_port have no colour class in results.html -> color_tag None.
    """
    header, ports = result
    header_specs = [
        ("switch_ip",     "swip"),
        ("switch_desc",   "swip"),
        ("switch_status", "swip"),
        ("trunks",        "swip"),
        ("access",        "swip"),
        ("switch_mac",    "swmac"),
        ("vendor",        "swip"),
        ("timestamp",     "tooltip"),
    ]
    port_specs = [
        ("port",                  "port"),
        ("port_desc",             None),
        ("type",                  None),
        ("role",                  None),
        ("mac",                   "mac"),
        ("ip",                    "hostip"),
        ("hostname",              "name"),
        ("vendor",                "vendor"),
        ("vlan",                  "vlan"),
        ("child_switch",          "swip"),
        ("child_port_deprecated", None),
        ("parent_switch",         "swip"),
        ("parent_port",           None),
        ("child_root_port",       None),
    ]
    return {
        "header": [tagged_row(h, header_specs) for h in (header or [])],
        "ports": [tagged_row(p, port_specs) for p in (ports or [])],
    }


def ser_macswitch(result):
    """
    macSwitch(mac, switch) -> (devolver, unAP, error)
      devolver: (stamp, switchIP, port, mac, vlan, switchDesc, switchMAC,
                 portType, isRoot)
      unAP:     [(apMac, apName), ...]
      error:    None, or a message string (handled by the caller)
    portType / isRoot rendered plain (color_tag None), like report's type/role.
    """
    devices, aps, _err = result
    dev_specs = [
        ("timestamp",   "tooltip"),
        ("switch_ip",   "swip"),
        ("port",        "port"),
        ("mac",         "mac"),
        ("vlan",        "vlan"),
        ("switch_desc", "swname"),
        ("switch_mac",  "swmac"),
        ("port_type",   None),
        ("is_root",     None),
    ]
    ap_specs = [("ap_mac", "mac"), ("ap_name", "name")]
    return {
        "devices": [tagged_row(d, dev_specs) for d in (devices or [])],
        "access_points": [tagged_row(a, ap_specs) for a in (aps or [])],
    }


# ============================================================================
# COMMAND REGISTRY
# Maps a command name to (callable, arity, serialiser).
# arity: exact number of positional params the command needs.
#        'status' is special (0 or 1).
# ============================================================================

def _run_mac(mac):
    """ip/mac shortcut: full MAC -> macSearch, partial -> macSearchPart."""
    if funciones.standarizeFullMAC(mac):
        return funciones.macSearch(mac)
    return funciones.macSearchPart(mac)


COMMANDS = {
    # name:        (func,                     arity, serialiser,     type_label)
    "status":      (funciones.status,         None,  ser_status,     "status"),
    "switchport":  (funciones.switchport,     2,     ser_switchport, "switchport"),
    "map":         (funciones.mapSwitch,      1,     ser_map,        "map"),
    "report":      (funciones.report,         1,     ser_report,     "report"),
    "ip":          (funciones.ipSearch,       1,     ser_hostlist,   "ipSearch"),
    "mac":         (_run_mac,                 1,     ser_hostlist,   "macSearch"),
    # NEW: does switch <ip> see full-MAC <mac>?  (works on trunk ports too)
    "macswitch":   (funciones.macSwitch,      2,     ser_macswitch,  "macSwitch"),
}


# ============================================================================
# PARSER  (mirrors flask_web_server.parse_query / interpretarDireccion so the
# bare-IP / bare-MAC shortcuts behave exactly like the web UI)
# ============================================================================

def parse_command(query_string):
    """
    Returns (cmd_name, params_tuple, error).
      - On a recognised command: (name, params, None)
      - On a bare IP/MAC/partial: ('ip'|'mac', (value,), None)
      - On failure: (None, None, "message")
    """
    query_string = (query_string or "").strip()
    if not query_string:
        return (None, None, "Empty command")

    parts = query_string.split()
    cmd = parts[0].lower()
    params = tuple(parts[1:])

    if cmd in COMMANDS:
        return (cmd, params, None)

    # Not a named command: try to read it as an address (bare IP / MAC / partial)
    interpreted_cmd, interpreted_params = _interpretar_direccion(query_string)
    if interpreted_cmd == "ip":
        return ("ip", interpreted_params, None)
    if interpreted_cmd == "mac":
        return ("mac", interpreted_params, None)

    return (None, None, f"Unknown command or invalid input: '{query_string}'")


def _interpretar_direccion(cmd):
    """IP / full-MAC / partial-MAC detection (same logic as the web UI)."""
    octetos = cmd.split(".")
    if len(octetos) == 4:
        try:
            nums = [int(o) for o in octetos]
            if all(0 <= o <= 255 for o in nums):
                return ("ip", (cmd,))
        except ValueError:
            pass

    posible_mac = funciones.sanitizeMAC(cmd)
    mac_std = funciones.standarizeFullMAC(posible_mac)
    if mac_std:
        return ("mac", (mac_std,))

    if funciones.validarMacParcial(posible_mac):
        return ("mac", (posible_mac,))

    return (None, None)


# ============================================================================
# EXECUTION
# ============================================================================

def execute_command(query_string):
    """
    Parse + run + serialise. Returns a dict ready to jsonify (the 'ok'/'error'
    envelope and HTTP status are decided by the caller based on 'ok').
    """
    cmd_name, params, error = parse_command(query_string)
    if error:
        return {"ok": False, "command": query_string, "error": error}, 400

    func, arity, serialiser, type_label = COMMANDS[cmd_name]

    # Arity check (status is the only variadic one: 0 or 1)
    if cmd_name == "status":
        if len(params) not in (0, 1):
            return ({"ok": False, "command": query_string,
                     "error": "status takes 0 or 1 parameters"}, 400)
    elif len(params) != arity:
        return ({"ok": False, "command": query_string,
                 "error": f"'{cmd_name}' expects {arity} parameter(s), "
                          f"got {len(params)}"}, 400)

    try:
        result = func(*params)
    except Exception as e:
        return ({"ok": False, "command": query_string,
                 "error": f"Execution error: {e}"}, 500)

    # macSwitch carries its own in-band error string as the 3rd element.
    if cmd_name == "macswitch":
        if result is None:
            return ({"ok": False, "command": query_string,
                     "error": "macSwitch returned no result"}, 500)
        _dev, _aps, mac_err = result
        if mac_err:
            return ({"ok": False, "command": query_string,
                     "error": mac_err, "type": type_label}, 404)

    # Functions that signal "not found" with (None, None) or None.
    if result is None or (isinstance(result, tuple) and all(x is None for x in result)):
        return ({"ok": False, "command": query_string,
                 "error": "No results (switch offline or not found)",
                 "type": type_label}, 404)

    data = serialiser(result)

    return ({"ok": True,
             "command": query_string,
             "type": type_label,
             "data": data,
             "palette": WEB_COLORS}, 200)


# ============================================================================
# BLUEPRINT
# ============================================================================

api_bp = Blueprint("api_command", __name__)


def _require_token(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not API_TOKEN:
            return jsonify({"ok": False,
                            "error": "API token not configured on server"}), 503
        supplied = request.headers.get("X-API-Token", "")
        # constant-time-ish compare
        if not supplied or supplied != API_TOKEN:
            return jsonify({"ok": False, "error": "Invalid or missing API token"}), 401
        return f(*args, **kwargs)
    return wrapper


@api_bp.route("/command", methods=["POST"])
@_require_token
def command():
    """
    Body: {"command": "<command string>"}
    Returns tagged JSON built from the raw data objects.
    """
    payload = request.get_json(silent=True)
    if payload is None or "command" not in payload:
        return jsonify({"ok": False,
                        "error": "JSON body must contain a 'command' field"}), 400

    body, status = execute_command(payload["command"])
    return jsonify(body), status


@api_bp.route("/command/commands", methods=["GET"])
@_require_token
def list_commands():
    """Discovery helper: list the command names this API accepts."""
    return jsonify({"ok": True, "commands": sorted(COMMANDS.keys())}), 200
