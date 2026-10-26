"""

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

# MAIN and Auxiliary Functions.
import subprocess
from subprocess import PIPE
import re
import time
import os
import sqlite3
from html import escape
from services import get_service_name





vendors_regex = re.compile(r'^([0-9A-Fa-f\-]+)\s*\(hex\)\s*(.+)$')


# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------


def seg(elemento):
    # Safe value-to-string conversion.
    # elemento gets back as string, OR [ ERROR-SEG: es None ]" / "[ ERROR-SEG: value ]"
    if(elemento is None):
        return "[ ERR-SEG: None ]"
    try:
        devolver = str(elemento)
        return devolver
    except Exception:
        return "[ ERR-SEG: value ]"


# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------



def getGatewayMAC(laDB):
    localCur = laDB.cursor()
    # fetchs gateway IP address from siteData table.
    gwMAC = None
    for row in localCur.execute("""
        SELECT DISTINCT arp.macaddr, arp.ipaddr
        FROM arp
        WHERE arp.ipaddr IN (
            SELECT valor
            FROM siteData
            WHERE parametro = 'gateway'
            )
    """):
        gwMAC = row[0]
    return gwMAC



# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------



def rootSwitchFinder(laDB):
    localCur = laDB.cursor()
    """
    Identifying Root Switch.
    It's the switch that matches the following:
    - Sees all known Switches' MAC addresses (except its own)
    - All those MAC addresses are seen on NON a GateWayPort.
    - GateWayPort is the port on which a Switch sees the GateWay MAC address.
    """
    switches = []
    switchPuntos = []
    for row in localCur.execute("""
        SELECT DISTINCT switch.switchIP
            FROM switch 
            WHERE switch.switchStatus LIKE "%ONLINE%"
        """):
        switches.append(row)
    #
    for cadaSwitch in switches:
        puntos = 0
        for row2 in localCur.execute("""
            SELECT DISTINCT switchPort.portNum
                FROM switchPort
                WHERE switchPort.switchIP = ?
            """, (cadaSwitch)):
            # We're iterating that switch ports.
            puntos = puntos + len(aQuienVes(laDB, cadaSwitch[0], row2[0]))
        switchPuntos.append((cadaSwitch[0],puntos),)
    # We've got a list of switches and amount of SONS they see (switchPuntos).
    elRoot = None
    elMayorPuntaje = 0
    for tupla in switchPuntos:
        if( tupla[1] > elMayorPuntaje ):
            elMayorPuntaje = tupla[1]
            elRoot = tupla[0]
    return (elRoot,elMayorPuntaje)
    


# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------



def aQuienVes(laDB, switchMaster, portMaster):
    # Gets Switch (IP) and Port Number. Returns list of switches it sees on that port.
    localCur = laDB.cursor()
    hijosDeUnSwitchPort = []
    for rowSwitch in localCur.execute("""
        SELECT switch.switchIP, switch.switchDesc, hijoMAC, hijoPORT
        FROM switch JOIN (
            SELECT DISTINCT macaddress.switchIP, macaddress.unaMac AS hijoMAC, macaddress.unPuerto AS hijoPORT
            FROM macaddress
            WHERE macaddress.switchIP = ?
                AND macaddress.unPuerto = ?
                AND macaddress.unaMac IN (
                    SELECT switch2.switchMAC
                    FROM switch AS switch2
                )
                AND (macaddress.switchIP, macaddress.unPuerto) IN (
                    SELECT switchIP, portNum
                    FROM switchPort
                    WHERE switchPort.portType == "TRUNK" AND switchPort.isRoot != "ROOT"
                    )
            ) AS descendientes ON descendientes.hijoMAC = switch.switchMAC
        WHERE switchStatus LIKE "%ONLINE%"
        """, (switchMaster, portMaster)):
        # [DOWNLINK_IP][DOWNLINK_nombre][DOWNLINK_MAC][DOWNLINK_PORT]
        hijosDeUnSwitchPort.append(rowSwitch)
    return hijosDeUnSwitchPort



# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------



def isOnline(laDB, unSwitch):
    diskCur = laDB.cursor()
    lasCosas = []
    for row in diskCur.execute("""
    SELECT switchIP
            FROM switch
            WHERE switch.switchIP = ?
        """, (unSwitch,)):
        lasCosas.append(row)
    if( len(lasCosas) == 0 ):
        return False
    estado = None
    for row in diskCur.execute("""
    SELECT switchStatus
            FROM switch
            WHERE switch.switchIP = ?
        """, (unSwitch,)):
        estado = row[0]
    if(estado != "OFFLINE"):
        return True
    else:
        return False
    
    
    
  
# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------
  
  
    

def getStrategy(laDB, elSwitch):
    localCur = laDB.cursor()
    devolver = None
    for row in localCur.execute("""
        SELECT *
        FROM snmpStrategy
        WHERE switchIP LIKE ?
    """,(elSwitch,)):
        devolver = row
    return devolver


def setStrategy(laDB, theStrategy):
    localCur = laDB.cursor()
    localCur.execute("BEGIN IMMEDIATE")
    localCur.execute("DELETE FROM snmpStrategy WHERE switchIP LIKE ?",(theStrategy[0],))
    try:
        localCur.executemany("""INSERT INTO snmpStrategy
            (
            switchIP,
            usePaso1,
            usePaso2,
            usePaso3,
            usePaso4,
            condicionP1aP2,
            condicionP2aP3,
            condicionP3aP4,
            condicionP2aP4,
            condicionP1aP3,
            condicionP1aP4,
            portNum_table,
            portNum_field
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", [theStrategy])
        laDB.commit()
    except Exception:
        laDB.rollback()
        print("----------------------------------")
        print(theStrategy)
        print(type(theStrategy))
        print(len(theStrategy))
        print("----------------------------------")
    
'''
CREATE TABLE IF NOT EXISTS snmpStrategy (
   0 switchIP TEXT,
    usePaso1 TEXT,
    usePaso2 TEXT,
    usePaso3 TEXT,
    usePaso4 TEXT,
    
   5 condicionP1aP2 TEXT,
    condicionP2aP3 TEXT,
    condicionP3aP4 TEXT,
    condicionP2aP4 TEXT,
    condicionP1aP3 TEXT,
    condicionP1aP4 TEXT,
    portNum_table TEXT,
    portNum_field TEXT
)



if( usePaso2 == "yes" and usePaso3 == "yes" ):
    # the 4 tables will do.
    joinConditions = " INNER JOIN paso2 ON "+condicionP1aP2+" "
    joinConditions = joinConditions + "INNER JOIN paso3 ON "+condicionP2aP3+" "
    joinConditions = joinConditions + "INNER JOIN paso4 ON "+condicionP3aP4+" "
if( usePaso2 == "no" and usePaso3 == "yes" ):
    # paso1+paso2+paso4
    joinConditions = " INNER JOIN paso2 ON "+condicionP1aP2+" "
    joinConditions = joinConditions + "INNER JOIN paso4 ON "+condicionP2aP4+" "
if( usePaso2 == "yes" and usePaso3 == "no" ):
    # paso1+paso3+paso4
    joinConditions = " INNER JOIN paso3 ON "+condicionP1aP3+" "
    joinConditions = joinConditions + "INNER JOIN paso4 ON "+condicionP3aP4+" "
'''



def validateStrategy(strategy):
    if(strategy is None):
        return False
    if(strategy[0] is None):
        return False
    if(strategy[11] is None):
        return False
    if(len(strategy[11]) == 0):
        return False
    if(strategy[12] is None):
        return False
    if(len(strategy[12]) == 0):
            return False
    if( strategy[2] and strategy[3] ):
        # all 4.
        if( strategy[5] is None ):
            return False
        if( strategy[6] is None ):
            return False
        if( strategy[7] is None ):
            return False
    if( not strategy[2] and strategy[3] ):
        # paso1-paso2-paso4
        if( strategy[8] is None ):
            return False
    if( strategy[2] and not strategy[3] ):
        # paso1-paso3-paso4
        if( strategy[9] is None ):
            return False
    if( not strategy[2] and not strategy[3] ):
        # paso1-paso4
        if( strategy[10] is None ):
            return False
    return True


# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------
  
    
    
def getSwitchesAll(laDB):
    localCur = laDB.cursor()
    HOSTS = []
    for row in localCur.execute("""
        SELECT switchIP from switch
        """):
        HOSTS.append(row[0])
    return HOSTS
    


def get_SWITCHES_with_STRATS(laDB):
    # We deliver a list of [HOST,[host's Strategy]]
    
    losHosts = getSwitchesAll(laDB)
    devolver = []
    for cadaH in losHosts:
        laStrat = getStrategy(laDB, cadaH)
        devolver.append((cadaH,laStrat))
    return devolver




# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


    
def getGateway(laDB):
    localCur = laDB.cursor()
    for row in localCur.execute("""
        SELECT valor
        FROM siteData
        WHERE parametro = 'gateway'
        """):
        elRouter = row[0]
    return elRouter




# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------



def countSwitchesOnline(laDB):
    localCur = laDB.cursor()
    laCant = 0
    for row in localCur.execute("""
        SELECT COUNT (switch.switchIP)
            FROM switch 
            WHERE switch.switchStatus LIKE "%ONLINE%"
        """):
        laCant = row[0]
    return laCant




# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


def isAP(laDB, unaMAC):
    localCur = laDB.cursor()
    elAP = None
    for row in localCur.execute("""
        SELECT apNombre
            FROM accessPoints 
            WHERE apMac = ?
        """, (unaMAC,)):
        elAP = row[0]
    return elAP




# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


def isSwitch(laDB, unaIP):
    localCur = laDB.cursor()
    elSwitch = None
    for row in localCur.execute("""
        SELECT switchDesc
            FROM switch
            WHERE switchIP = ?
        """, (unaIP,)):
        elSwitch = row[0]
    return elSwitch



# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------



def sanitizeMAC(algoMac):
    if(algoMac is not None):
        algoMac = algoMac.lower()
        algoMac = algoMac.replace(":","-")
        return algoMac
    else:
        return None



# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------



def validarMacParcial(unaParte):
    unaParte = unaParte.replace(":", "-")
    chars_unaParte = list(unaParte)
    ilegales = 0
    for unChar in chars_unaParte:
        if unChar not in ('a','b','c','d','e','f','0','1','2','3','4','5','6','7','8','9', '-'):
            ilegales = 1
    if (ilegales == 1):
        return False
    lst_mask = []
    for unChar in chars_unaParte:
        if (unChar != "-"):
            lst_mask.append("a")
        else:
            lst_mask.append("-")
    str_mask = ""
    for unChar in lst_mask:
        str_mask = str_mask + unChar[0]
    if( (str_mask in "aa-aa-aa-aa-aa-aa") or (str_mask in "aaaa-aaaa-aaaa") ):
        return True
    else:
        return False



# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


def standarizeFullMAC(posibleMac):
    # First, standarize ":"/"-", UPPER/LOWER, 3 or 6 parts. Returns standarized, if valid.
    # If not valid MAC address, returns None.
    posibleMac = sanitizeMAC(posibleMac)
    hexPairs = []
    if( "-" in posibleMac):
        hexPairs = posibleMac.split("-")
    # tiene caracteres válidos?
    hexasValidos = 1
    caracteres = list(posibleMac)
    cantidad = 0
    for caracter in caracteres:
        if caracter not in ('a','b','c','d','e','f','0','1','2','3','4','5','6','7','8','9', '-'):
            hexasValidos = 0
        if caracter in ('a','b','c','d','e','f','0','1','2','3','4','5','6','7','8','9'):
            cantidad = cantidad + 1
    # If there are not exactly 12 alphanumeric chars, this is NOT a whole MAC address.
    if (cantidad != 12):
        return None
    mac_address_std = None
    if( hexasValidos == 1):
        cantPairs = len(hexPairs)
        if(cantPairs == 6):
            # MAC may look like aa-bb-cc-dd-ee-ff
            mac_address_std = posibleMac
        if(cantPairs == 3):
            # MAC may look like aabb-ccdd-eeff
            caracteresSueltos = []
            for cosa in hexPairs:
                losChars = list(cosa)
                for unChar in losChars:
                    caracteresSueltos.append(unChar)
            mac_address_std = '-'.join(''.join(caracteresSueltos[i:i+2]) for i in range(0, len(caracteresSueltos), 2))
        return mac_address_std
    else:
        return None



# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------



def updateVendors(laDB):
    localCur = laDB.cursor()
    comando = "wget -P /ramdisk/ https://standards-oui.ieee.org/"
    try:
        os.remove("/ramdisk/index.html")
        print("index.html (vendors) deleted.")
    except Exception:
        print("index.html not deleted.")
        pass
    proceso2 = subprocess.Popen(comando, shell=True, close_fds=True, stdout=PIPE)
    proceso2.communicate()[0]
    with open("/ramdisk/index.html","r") as volatil:
        bodoque = volatil.readlines()
        lineasHex = []
        for cadaRenglon in bodoque:
            if("(hex)" in cadaRenglon):
                escapada = escape(cadaRenglon)
                lineasHex.append(escapada)
    if(len(lineasHex)>50):
        # We've got the 'hex' lines:
        # A0-59-11   (hex)		Cisco Meraki
        # 8-31-39   (hex)		zte corporation
        lasRows = []
        for linea in lineasHex:
            elMatch = vendors_regex.match(linea)
            if elMatch:
                hex_part = elMatch.group(1)
                description = elMatch.group(2)
                lasRows.append((hex_part.lower(), description))
        localCur.execute("BEGIN")
        localCur.execute("DELETE FROM vendor")
        localCur.executemany("""
            INSERT INTO vendor (halfMac, elVendor)
            VALUES (?, ?)
        """, lasRows)
        laDB.commit()
        



# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------



def extraerVariable(linea):
    caracteres = 0
    while( (linea[caracteres:caracteres+1] != '=') and (caracteres < 100) ):
        caracteres = caracteres + 1
    if(caracteres > 99):
        # "=" not found.
        return None
    variable = linea[:caracteres]
    valor = linea[caracteres+1:]
    valor = valor.rstrip()
    return [(variable),(valor)]



# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


def leerDBenSQL(laDB, variable):
    localCur = laDB.cursor()    
    elValor = None
    for row in localCur.execute("""
        SELECT valor
        FROM siteData
        WHERE parametro = ?
        """, (variable,)):
        elValor = row[0]
    return elValor



# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------



def crearTablasHistoricas(histDB):
    localCur = histDB.cursor()
    #
    localCur.execute("""
        CREATE TABLE IF NOT EXISTS arp (
            stamp TEXT,
            ifNameA TEXT,
            laVlan TEXT,
            ipaddr TEXT,
            macaddr TEXT
        )
    """)
    localCur.execute("""
        CREATE TABLE IF NOT EXISTS hostname (
            stamp TEXT,
            ipaddr TEXT,
            hostname TEXT
        )
    """)
    localCur.execute("""
        CREATE TABLE IF NOT EXISTS switch (
            stamp TEXT,
            switchIP TEXT,
            switchMAC TEXT,
            switchDesc TEXT,
            switchStatus TEXT
        )
    """)
    localCur.execute("""
        CREATE TABLE IF NOT EXISTS macaddress (
            stamp TEXT,
            switchIP TEXT,
            unaVLAN TEXT,
            unaMAC TEXT,
            unPuerto TEXT
        )
    """)
    localCur.execute("""
        CREATE TABLE IF NOT EXISTS switchHijosPadre (
            stamp TEXT,
            switchPadre TEXT,
            portPadre TEXT,
            switchHijo TEXT
        )
    """)
    localCur.execute("""
        CREATE TABLE IF NOT EXISTS siteData (
            stamp TEXT,
            parametro TEXT,
            valor TEXT
        )
    """)
    localCur.execute("""
        CREATE TABLE IF NOT EXISTS accessPoints (
            stamp TEXT,
            apMac TEXT,
            apNombre TEXT
        )
    """)
    localCur.execute("""
        CREATE TABLE IF NOT EXISTS switchPort (
            stamp TEXT,
            switchIP TEXT,
            portNum TEXT,
            portDesc TEXT,
            portType TEXT,
            isRoot TEXT
        )
    """)



# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------



def report(elSwitch):
    diskDB = sqlite3.connect("/ramdisk/snmpqserver.db", isolation_level=None)
    diskDB.execute("PRAGMA journal_mode=WAL;")
    diskDB.execute("PRAGMA synchronous=NORMAL;")
    diskCur = diskDB.cursor()
    # HEADER: switch information. We get it using the "status" function.
    # The rest: port by port, except trunks, what does it see there. State uplinks and downlinks.
    # 
    losPuertos = []
    estado = None
    for row in diskCur.execute("""
        SELECT switchStatus FROM switch WHERE switchIP = ?
        """, (elSwitch,)):
        estado = row[0]
    if( estado is None ):
        print("switch inexistente")
        return (None,None)
    if( estado == "OFFLINE" ):
        print("switch offline!")
        return (None,None)
    # From now on we're working with a switch that is ONLINE.
    for row in diskCur.execute("""
        SELECT switchPort.portNum, switchPort.portDesc, switchPort.portType, switchPort.isRoot, mAccess.unaMac, arp.ipaddr, hst.hostname, v.elVendor, mAccess.unaVlan, shp.switchHijo, shp.portPadre, shp2.switchPadre, shp2.portPadre, rr.hijoRoot
        FROM switchPort LEFT JOIN (
                SELECT DISTINCT *
                FROM macaddress
                WHERE (macaddress.switchIP, macaddress.unPuerto) IN (
                    SELECT DISTINCT sp2.switchIP, sp2.portNum
                    FROM switchPort AS sp2
                    WHERE portType == "ACCESS"
                )
            ) AS mAccess ON (switchPort.switchIP = mAccess.switchIP and mAccess.unPuerto = switchPort.portNum)
            LEFT JOIN switchHijosPadre as shp ON (switchPort.switchIP = shp.switchPadre AND switchport.portNum = shp.portPadre)
            LEFT JOIN switchHijosPadre as shp2 ON (switchPort.switchIP = shp2.switchHijo AND switchPort.isROOT = 'ROOT')
            LEFT JOIN arp ON mAccess.unaMac = arp.macAddr
            LEFT JOIN hostname AS hst ON arp.ipaddr = hst.ipaddr
            LEFT JOIN vendor AS v ON mAccess.unaMac LIKE v.halfMac || '%'
            LEFT JOIN (SELECT switchIP AS hijo, portNum AS hijoRoot
                FROM switchPort
                WHERE isRoot = 'ROOT'
            ) AS rr ON (rr.hijo = shp.switchHijo)
        WHERE switchPort.switchIP = ?
        ORDER BY CAST(switchPort.portNum AS INTEGER)
        """, (elSwitch,)):
        losPuertos.append(row)
    # prt, prtDsc, type, root, mac, ip, host, vend, vlan, swHijo, prtHijo, swPadre, prtPadre
    """
    0	prt
    1	prtDsc
    2	type
    3	root
    4	mac
    5	ip
    6	host
    7	vend
    8	vlan
    9	swHijo
    10	prtHijo
    11	swPadre
    12	prtPadre
    13	hijoRoot
    """
    
    cabecera = []
    cabecera = status(elSwitch)
    devolver = []
    for unRow in losPuertos:
        # We iterate row by row to update the hostname field. WORK IN PROGRESS. AVAYA module not ready.
        telefono = extensionCheck(unRow[4], diskDB)
        if(telefono is not None):
            campoHOSTNAME = telefono
        else:
            campoHOSTNAME = unRow[6]
        auxRow = unRow[:6] + (campoHOSTNAME,) + unRow[7:]
        devolver.append(auxRow)
    return (cabecera, devolver)



# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------



def status(elSwitchIP=None):
    diskDB = sqlite3.connect("/ramdisk/snmpqserver.db", isolation_level=None)
    diskDB.execute("PRAGMA journal_mode=WAL;")
    diskDB.execute("PRAGMA synchronous=NORMAL;")
    diskCur = diskDB.cursor()
    # We want: A list of switches with IP, Description, Ports with MACs, Trunks,
    # No# of MACs / OFFLINE, and vendor.
    swData = []
    if(elSwitchIP is not None):
        opcional = "WHERE switch.switchIP = '"+elSwitchIP+"'"
    else:
        opcional = "ORDER BY switch.switchIP"
    
    for row in diskCur.execute("""
        SELECT switch.switchIP, switch.switchDesc, switch.switchStatus, COALESCE(troncos.troncales, 0), COALESCE(terminales.accesos,0), swVend.switchMAC, swVend.elVendor, switch.stamp
        FROM switch
            LEFT JOIN (
                SELECT switch.switchIP, vendor.elVendor, switch.switchDesc, switch.switchMAC
                FROM switch LEFT JOIN vendor ON switch.switchMAC LIKE vendor.halfMac || '%'
            ) AS swVend ON switch.switchIP = swVend.switchIP
            LEFT JOIN (
                SELECT switchPort.switchIP, COUNT(switchPort.switchIP) as troncales
                FROM switchPort
                WHERE switchPort.portType = "TRUNK"
                GROUP BY switchPort.switchIP
            ) AS troncos ON switch.switchIP = troncos.switchIP
            LEFT JOIN (
                SELECT switchPort.switchIP, COUNT(switchPort.switchIP) as accesos
                FROM switchPort
                WHERE switchPort.portType = "ACCESS"
                GROUP BY switchPort.switchIP
            ) AS terminales ON switch.switchIP = terminales.switchIP
        """+opcional
        ):
            swData.append(row)
    return swData



# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


def macSwitch2(unaMac, unSwitch):
    diskDB = sqlite3.connect("/ramdisk/snmpqserver.db", isolation_level=None)
    diskDB.execute("PRAGMA journal_mode=WAL;")
    diskDB.execute("PRAGMA synchronous=NORMAL;")
    diskCur = diskDB.cursor()
    
    # NOT implemented yet. Does a Switch see a MAC address? If so, on which port?
    
    # 1. MAC exists?
    # 2. Is the Switch ONLINE? Is it a switch on the first place?
    
    for row in diskCur.execute("""
            SELECT COUNT(unaMAC)
            FROM macaddress
            WHERE unaMac = ?
        """, (unaMac,)):
        if( row[0] == 0 ):
            return None,None,"No se encuentra la MAC en la base de datos"
    rowExists = []
    for row in diskCur.execute("""
            SELECT switchDesc, switchStatus
            FROM switch
            WHERE switchIP = ?
        """, (unSwitch,)):
        rowExists.append(row)
    if( len(rowExists) == 0 ):
        return None,None,"No se reconoce el switch."
    for unRow in rowExists:
        if( unRow[1] == "OFFLINE" ):
            return None,None,"El switch "+unRow[0]+" está OFFLINE."
    # We're here, so the MAC does exist, and the Switch does exist. We can expect results.
    elQuery = """
        SELECT DISTINCT macaddress.stamp, macaddress.switchIP,
            macaddress.unPuerto, macaddress.unaMAC, macaddress.unaVLAN,
            switch.switchDesc, switch.switchMac, switchport.portType, switchPort.isRoot
        FROM macaddress 
            JOIN switch ON macaddress.switchIP = switch.switchIP
            JOIN switchPort ON macaddress.switchIP = switchport.switchIP and macaddress.unPuerto = switchPort.portNum
            WHERE macaddress.switchIP = ?
            AND macaddress.unaMac = ?
        """
    # We want: SWITCH, MAC, VLAN, HOSTNAME, VENDOR
    devolver = []
    unAP = []
    elSwitch = None
    elPuerto = None
    for row in diskCur.execute(elQuery, (unSwitch, unaMac)):
        devolver.append(row)
        elSwitch = row[1]
        elPuerto = row[2]
    # Let's search for Access Points on that port.
    for row2 in diskCur.execute("""
        SELECT apMac, apNombre
        FROM accessPoints
        WHERE apMac IN (
            SELECT unaMac
            FROM macaddress
            WHERE switchIP = ?
                AND unPuerto = ?
                AND (macaddress.switchIP, macaddress.unPuerto) IN (
                    SELECT switchIP, portNum
                    FROM switchPort
                    WHERE portType = "ACCESS"
                )
            )
        """, (elSwitch,elPuerto)):
        unAP.append(row2)
    return devolver,unAP, None




# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------


def macSearchPart(unaParte):
    diskDB = sqlite3.connect("/ramdisk/snmpqserver.db", isolation_level=None)
    diskDB.execute("PRAGMA journal_mode=WAL;")
    diskDB.execute("PRAGMA synchronous=NORMAL;")
    diskCur = diskDB.cursor()
    
    # We get a partial MAC address.
    # We want: SWITCH, MAC, VLAN, HOSTNAME, VENDOR
    devolver = []
    unAP = []
    elSwitch = None
    elPuerto = None
    for row in diskCur.execute("""
        SELECT DISTINCT macaddress.stamp, macaddress.switchIP,
            macaddress.unPuerto, macaddress.unaMAC, macaddress.unaVLAN,
            arp.ipaddr, vendor.elVendor, hostname.hostname, switch.switchDesc, switch.switchMac
        FROM macaddress LEFT JOIN arp ON macaddress.unaMAC = arp.macaddr
            LEFT JOIN vendor ON macaddress.unaMAC LIKE vendor.halfMac || '%'
            LEFT JOIN hostname ON arp.ipaddr = hostname.ipaddr
            JOIN switch ON macaddress.switchIP = switch.switchIP
        WHERE macaddress.unaMac LIKE ?
            AND (macaddress.switchIP, macaddress.unPuerto) IN (
                SELECT switchIP, portNum
                FROM switchPort
                WHERE portType = "ACCESS"
            )
        """, (f"%{unaParte}%",)):
        if(row[6] is None):
            campoVENDOR = "N/A"
        else:
            campoVENDOR = row[6]
        
        if(row[7] is None):
            campoHOSTNAME = "N/A"
        else:
            campoHOSTNAME = row[7]
        # AVAYA en el row[5] está la IP. Mando a ver si no es un teléfono interno!
        telefono = extensionCheck(row[2], diskDB)
        if(telefono is not None):
            campoHOSTNAME = telefono
        auxRow = row[:6] + (campoVENDOR,) + (campoHOSTNAME,) + row[8:]
        devolver.append(auxRow)
        elSwitch = row[1]
        elPuerto = row[2]
    # Let's search for Access Points on that port.
    for row2 in diskCur.execute("""
        SELECT apMac, apNombre
        FROM accessPoints
        WHERE apMac IN (
            SELECT unaMac
            FROM macaddress
            WHERE switchIP = ?
                AND unPuerto = ?
            )
        """, (elSwitch,elPuerto)):
        unAP.append(row2)
    return devolver,unAP



# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------


def macSearch(unaMac):
    diskDB = sqlite3.connect("/ramdisk/snmpqserver.db", isolation_level=None)
    diskDB.execute("PRAGMA journal_mode=WAL;")
    diskDB.execute("PRAGMA synchronous=NORMAL;")
    diskCur = diskDB.cursor()

    # The MAC could be Whole or partial. We only know it has valid characters.
    # standarizeFullMac returns None if not a Whole MAC.
    if( standarizeFullMAC(unaMac) is not None ):
        elWHERE = "WHERE macaddress.unaMac = ?"
    else:
        unaMac = "%"+unaMac+"%"
        elWHERE =  "WHERE macaddress.unaMac LIKE ?"
        
    elQuery = """
        SELECT DISTINCT macaddress.stamp, macaddress.switchIP,
            macaddress.unPuerto, macaddress.unaMAC, macaddress.unaVLAN,
            arp.ipaddr, vendor.elVendor, hostname.hostname, switch.switchDesc, switch.switchMac
        FROM macaddress LEFT JOIN arp ON macaddress.unaMAC = arp.macaddr
            LEFT JOIN vendor ON macaddress.unaMAC LIKE vendor.halfMac || '%'
            LEFT JOIN hostname ON arp.ipaddr = hostname.ipaddr
            JOIN switch ON macaddress.switchIP = switch.switchIP """+elWHERE+"""
            AND (macaddress.switchIP, macaddress.unPuerto) IN (
                SELECT switchIP, portNum
                FROM switchPort
                WHERE portType = "ACCESS"
            )
            ORDER BY macaddress.switchIP, macaddress.unPuerto
        """
    # We want: SWITCH, MAC, VLAN, HOSTNAME, VENDOR
    devolver = []
    unAP = []
    elSwitch = None
    elPuerto = None
    for row in diskCur.execute(elQuery, (unaMac,)):
        if(row[6] is None):
            campoVENDOR = "N/A"
        else:
            campoVENDOR = row[6]
        if(row[7] is None):
            campoHOSTNAME = "N/A"
        else:
            campoHOSTNAME = row[7]
        # AVAYA en el row[5] está la IP. Mando a ver si no es un teléfono interno!
        telefono = extensionCheck(row[2], diskDB)
        if(telefono is not None):
            campoHOSTNAME = telefono
        auxRow = row[:6] + (campoVENDOR,) + (campoHOSTNAME,) + row[8:]
        devolver.append(auxRow)
        elSwitch = row[1]
        elPuerto = row[2]
    # Let's search for Access Points on that port.
    for row2 in diskCur.execute("""
        SELECT apMac, apNombre
        FROM accessPoints
        WHERE apMac IN (
            SELECT unaMac
            FROM macaddress
            WHERE switchIP = ?
                AND unPuerto = ?
            )
        """, (elSwitch,elPuerto)):
        unAP.append(row2)
    return devolver,unAP, None



# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------


def macSwitch(unaMac, unSwitch):
    diskDB = sqlite3.connect("/ramdisk/snmpqserver.db", isolation_level=None)
    diskDB.execute("PRAGMA journal_mode=WAL;")
    diskDB.execute("PRAGMA synchronous=NORMAL;")
    diskCur = diskDB.cursor()

    # The MAC could be Whole or partial. We only know it has valid characters.
    # standarizeFullMac returns None if not a Whole MAC.
    
    laMac = standarizeFullMAC(unaMac)
    
    if( laMac is not None ):
        elWHERE = "WHERE macaddress.unaMac = ? AND switch.switchIP = '"+unSwitch+"'"
    else:
        elWHERE =  "WHERE macaddress.unaMac LIKE 'functionDisabled' AND switch.switchIP = '"+unSwitch+"'"
        
    elQuery = """
        SELECT DISTINCT macaddress.stamp, macaddress.switchIP,
            macaddress.unPuerto, macaddress.unaMAC, macaddress.unaVLAN,
            arp.ipaddr, vendor.elVendor, hostname.hostname, switch.switchDesc, switch.switchMac
        FROM macaddress LEFT JOIN arp ON macaddress.unaMAC = arp.macaddr
            LEFT JOIN vendor ON macaddress.unaMAC LIKE vendor.halfMac || '%'
            LEFT JOIN hostname ON arp.ipaddr = hostname.ipaddr
            JOIN switch ON macaddress.switchIP = switch.switchIP """+elWHERE+"""
            ORDER BY macaddress.switchIP, macaddress.unPuerto
        """
    # We want: SWITCH, MAC, VLAN, HOSTNAME, VENDOR
    devolver = []
    unAP = []
    elSwitch = None
    elPuerto = None
    for row in diskCur.execute(elQuery, (laMac,)):
        if(row[6] is None):
            campoVENDOR = "N/A"
        else:
            campoVENDOR = row[6]
        if(row[7] is None):
            campoHOSTNAME = "N/A"
        else:
            campoHOSTNAME = row[7]
        # AVAYA en el row[5] está la IP. Mando a ver si no es un teléfono interno!
        telefono = extensionCheck(row[2], diskDB)
        if(telefono is not None):
            campoHOSTNAME = telefono
        auxRow = row[:6] + (campoVENDOR,) + (campoHOSTNAME,) + row[8:]
        devolver.append(auxRow)
        elSwitch = row[1]
        elPuerto = row[2]
    # Let's search for Access Points on that port.
    for row2 in diskCur.execute("""
        SELECT apMac, apNombre
        FROM accessPoints
        WHERE apMac IN (
            SELECT unaMac
            FROM macaddress
            WHERE switchIP = ?
                AND unPuerto = ?
            )
        """, (elSwitch,elPuerto)):
        # unAP.append(row2)
        pass
    return devolver,unAP





# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------



def mapSwitch(elSwitch):
    diskDB = sqlite3.connect("/ramdisk/snmpqserver.db", isolation_level=None)
    diskDB.execute("PRAGMA journal_mode=WAL;")
    diskDB.execute("PRAGMA synchronous=NORMAL;")
    diskCur = diskDB.cursor()
    elRoot = rootSwitchFinder(diskDB)
    #
    # Is is ONLINE?
    if( not isOnline(diskDB, elSwitch) ):
        print("switch OFFLINE o inexistente")
        return None
    arbolito = []
    ### We can add the first switch (the one being queried).
    # LEFT [switch_buscado][root-port]
    puertoRoot = None
    for row in diskCur.execute("""
        SELECT portNum
        FROM switchPort
        WHERE switchIP = ?
            AND isRoot = "ROOT"
        """, (elSwitch,)):
            puertoRoot = row[0]
    arbolito.append((None,elSwitch,puertoRoot))
    hijoIterable = elSwitch
    puertoIterable = None
    flagFin = 0
    while ( flagFin == 0 ):
        # We keep going as long as the "hijoIterable" is not the Root switch.
        for row in diskCur.execute("""
            SELECT switchPadre, portPadre
            FROM switchHijosPadre
            WHERE switchHijo = ?
            """, (hijoIterable,)):
                hijoIterable = row[0]
                puertoIterable = row[1]
                ### We can go to the CENTERED position.:
                # CENTER [puertoIterable][hijoIterable][root-port]
                #  We find the root-port of that switch.
        puertoRoot = None
        if( hijoIterable == elRoot[0] ):
            flagFin = 1
        else:
            for row in diskCur.execute("""
                SELECT portNum
                FROM switchPort
                WHERE switchIP = ?
                    AND isRoot = "ROOT"
                """, (hijoIterable,)):
                    puertoRoot = row[0]
        arbolito.append((puertoIterable,hijoIterable,puertoRoot))
    # Done
    if( len(arbolito) == 0 ):
        return None
    else:
        return arbolito
    
    


# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------


def ipSearch(unaIP):
    diskDB = sqlite3.connect("/ramdisk/snmpqserver.db", isolation_level=None)
    diskDB.execute("PRAGMA journal_mode=WAL;")
    diskDB.execute("PRAGMA synchronous=NORMAL;")
    diskCur = diskDB.cursor()

    # We Want: SWITCH, MAC, VLAN, HOSTNAME, VENDOR
    """
    switch: a.b.c.d ( Living Room Switch )
    Puerto, VLAN: PORT 50 [ VLAN 123 ]
    <Optional, in red>PORT SHARED WITH: [ PEPITO ] [ a.b.c.d ]
    IP, MAC, name: [10.1.2.3] [aa-bb-cc-dd-ee-ff] [ Gaming_rig1 ]
    VENDOR: [ Cyrix Instead ]
    """
    devolver = []
    unAP = []
    elSwitch = None
    elPuerto = None
    for row in diskCur.execute("""
        SELECT DISTINCT macaddress.stamp, macaddress.switchIP,
            macaddress.unPuerto, macaddress.unaMAC, macaddress.unaVLAN,
            arp.ipaddr, vendor.elVendor, hostname.hostname, switch.switchDesc, switch.switchMac
        FROM macaddress LEFT JOIN arp ON macaddress.unaMAC = arp.macaddr
            LEFT JOIN vendor ON macaddress.unaMAC LIKE vendor.halfMac || '%'
            LEFT JOIN hostname ON arp.ipaddr = hostname.ipaddr
            JOIN switch ON macaddress.switchIP = switch.switchIP
        WHERE macaddress.unaMac IN (
            SELECT macaddr
            FROM arp
            WHERE ipaddr = ?
            )
            AND (macaddress.switchIP, macaddress.unPuerto) IN (
                SELECT switchIP, portNum
                FROM switchPort
                WHERE portType = "ACCESS"
            )
        """, (unaIP,)):
        if(row[6] is None):
            campoVENDOR = "N/A"
        else:
            campoVENDOR = row[6]
        if(row[7] is None):
            campoHOSTNAME = "N/A"
        else:
            campoHOSTNAME = row[7]
        # AVAYA en el row[5] está la IP. Mando a ver si no es un teléfono interno!
        telefono = extensionCheck(row[2], diskDB)
        if(telefono is not None):
            campoHOSTNAME = telefono
        auxRow = row[:6] + (campoVENDOR,) + (campoHOSTNAME,) + row[8:]
        devolver.append(auxRow)
        elSwitch = row[1]
        elPuerto = row[2]
    # Let's search for Access Points on that port.
    for row2 in diskCur.execute("""
        SELECT apMac, apNombre
        FROM accessPoints
        WHERE apMac IN (
            SELECT unaMac
            FROM macaddress
            WHERE switchIP = ?
                AND unPuerto = ?
            )
        """, (elSwitch,elPuerto)):
        unAP.append(row2)
    return devolver,unAP



# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------


def switchport(elSwitch, elPuerto):
    diskDB = sqlite3.connect("/ramdisk/snmpqserver.db", isolation_level=None)
    diskDB.execute("PRAGMA journal_mode=WAL;")
    diskDB.execute("PRAGMA synchronous=NORMAL;")
    diskCur = diskDB.cursor()
    # Switch INFO:
    datosSwitch = []
    encontrado = 0
    for row in diskCur.execute("""
        SELECT DISTINCT switchPort.portType, switch.switchDesc, switch.switchMAC
        FROM switchPort JOIN switch ON switchPort.switchIP = switch.switchIP
        WHERE switchPort.switchIP IN (
            SELECT switchIP
            FROM switch
            WHERE switchStatus LIKE "%ONLINE%"
            )
            AND switch.switchIP = ?
            AND switchPort.portNum = ?
        """, (elSwitch, elPuerto)):
        datosSwitch = row
        encontrado = 1
    if(encontrado == 0):
        return(None,None)
    # MAC table with additional detail.
    resultados = []
    for row in diskCur.execute("""
        SELECT DISTINCT macaddress.stamp, macaddress.unaMAC, macaddress.unaVLAN, arp.ipaddr, vendor.elVendor, hostname.hostname
        FROM macaddress LEFT JOIN arp ON macaddress.unaMAC = arp.macaddr
            LEFT JOIN vendor ON macaddress.unaMAC LIKE vendor.halfMac || '%'
            LEFT JOIN hostname ON arp.ipaddr = hostname.ipaddr
        WHERE macaddress.switchIP IN (
            SELECT switchIP
            FROM switch
            WHERE switchStatus LIKE "%ONLINE%"
            )
            AND macaddress.switchIP = ?
            AND macaddress.unPuerto = ?
        """, (elSwitch, elPuerto)):
        # May or may not have IP addresss (ARP & LEFT JOIN!)
        if(row[3] is None):
            campoIP = "N/A"
        else:
            campoIP = row[3]
        if(row[4] is None):
            campoVENDOR = "N/A"
        else:
            campoVENDOR = row[4]
        if(row[5] is None):
            campoHOSTNAME = "N/A"
        else:
            campoHOSTNAME = row[5]
        auxRow = row[:3] + (campoIP,) + (campoVENDOR,) + (campoHOSTNAME,)
        resultados.append(auxRow)
    return(datosSwitch,resultados)
    

# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------



# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------
# NETFLOW !
# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------

# NetFlow database path
NETFLOW_DB = "/ramdisk/netflow.db"

# Protocol mapping
PROTOCOL_MAP = {
    "tcp": "TCP",
    "udp": "UDP",
    "icmp": "ICMP",
    "1": "ICMP",
    "6": "TCP",
    "17": "UDP"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def format_bytes(bytes_val):
    """
    Convert bytes to human-readable format (KB/MB/GB)
    Stays in smaller unit if value < 1.0 of next unit
    
    Returns: (value, unit) tuple
    Example: 1500000 -> (1.43, "MB")
    """
    try:
        bytes_val = float(bytes_val)
    except (ValueError, TypeError):
        return (0.0, "B")
    if bytes_val < 1024:
        return (bytes_val, "B")
    kb = bytes_val / 1024
    if kb < 1024:
        return (kb, "KB")
    mb = kb / 1024
    if mb < 1024:
        return (mb, "MB")
    gb = mb / 1024
    return (gb, "GB")



def format_bits(bytes_val):
    """
    Convert bytes to human-readable format (KB/MB/GB)
    Stays in smaller unit if value < 1.0 of next unit
    
    Returns: (value, unit) tuple
    Example: 1500000 -> (1.43, "MB")
    """
    try:
        bytes_val = float(bytes_val)
        bytes_val = bytes_val * 8
    except (ValueError, TypeError):
        return (0.0, "b")
    if bytes_val < 1024:
        return (bytes_val, "b")
    kb = bytes_val / 1024
    if kb < 1024:
        return (kb, "Kb")
    mb = kb / 1024
    if mb < 1024:
        return (mb, "Mb")
    gb = mb / 1024
    return (gb, "Gb")



def calculate_speed(total_bytes, time_seconds):
    """
    Calculate speed in bytes per second
    
    Returns: (value, unit) tuple for display
    Example: (1.5, "MB/s")
    """
    if time_seconds == 0:
        return (0.0, "bps")
    
    bytes_per_sec = total_bytes / time_seconds
    value, unit = format_bits(bytes_per_sec)
    return (value, f"{unit}ps")

def get_protocol_name(protocol_str):
    """Convert protocol string/number to readable name"""
    protocol_lower = str(protocol_str).lower()
    return PROTOCOL_MAP.get(protocol_lower, protocol_str.upper())

# ============================================================================
# GLOBAL NETFLOW STATISTICS
# ============================================================================

def netflow_global_stats(minutes=5):
    """
    Get global NetFlow statistics for all tables
    
    Args:
        minutes: Time window in minutes (default 5, min 20s=0.33, max 5)
    
    Returns:
        Dictionary with structure:
        {
            'time_window': minutes,
            'publicUS': {
                'total_bytes': int,
                'total_packets': int,
                'flow_count': int,
                'avg_speed': (value, unit),  # e.g., (1.5, "MB/s")
                'top5': [(dst_ip, dst_port, protocol, bytes, formatted_bytes), ...]
            },
            'publicDS': { ... same structure ... },
            'privateUS': { ... },
            'privateDS': { ... }
        }
    """
    conn = sqlite3.connect(NETFLOW_DB)
    cur = conn.cursor()
    
    # Clamp minutes to valid range
    minutes = max(0.33, min(5.0, minutes))  # 20s to 5m
    cutoff = time.time() - (minutes * 60)
    
    result = {
        'time_window': minutes,
        'publicUS': None,
        'publicDS': None,
        'privateUS': None,
        'privateDS': None
    }
    
    # Helper function to query one table
    def query_table(table_name, is_upload):
        # Get totals
        cur.execute(f"""
            SELECT 
                SUM(CAST(bytes AS INTEGER)) as total_bytes,
                SUM(CAST(packets AS INTEGER)) as total_packets,
                COUNT(*) as flow_count
            FROM {table_name}
            WHERE CAST(stamp AS REAL) > ?
        """, (cutoff,))
        
        row = cur.fetchone()
        total_bytes = row[0] or 0
        total_packets = row[1] or 0
        flow_count = row[2] or 0
        
        # Calculate average speed
        time_seconds = minutes * 60
        avg_speed = calculate_speed(total_bytes, time_seconds)
        
        # Get top 5 connections (by bytes)
        # For upload: group by destination, for download: group by source
        if is_upload:
            #group_field = "dstIP"
            group_field = "srcIP"
        else:
            #group_field = "srcIP"
            group_field = "dstIP"
        cur.execute(f"""
            SELECT 
                {group_field} as remote_ip,
                dstPort,
                protocol,
                SUM(CAST(bytes AS INTEGER)) as total_bytes
            FROM {table_name}
            WHERE CAST(stamp AS REAL) > ?
            GROUP BY {group_field}, dstPort, protocol
            ORDER BY total_bytes DESC
            LIMIT 5
        """, (cutoff,))
        
        top5_raw = cur.fetchall()
        
        # Format top5 with human-readable bytes and service names
        top5 = []
        for ip, port, proto, bytes_val in top5_raw:
            formatted = format_bytes(bytes_val)
            proto_name = get_protocol_name(proto)
            service_name = get_service_name(ip)
            
            
            top5.append((ip, port, proto_name, bytes_val, formatted, service_name))
        
        return {
            'total_bytes': total_bytes,
            'total_packets': total_packets,
            'flow_count': flow_count,
            'avg_speed': avg_speed,
            'formatted_bytes': format_bytes(total_bytes),
            'top5': top5
        }
    
    # Query all four tables
    try:
        result['publicUS'] = query_table('netflowPublicUS', True)
        result['publicDS'] = query_table('netflowPublicDS', False)
        result['privateUS'] = query_table('netflowPrivateUS', True)
        result['privateDS'] = query_table('netflowPrivateDS', False)
    except sqlite3.OperationalError:
        # Tables might not exist yet
        pass
    finally:
        conn.close()
    
    return result

# ============================================================================
# HOST-SPECIFIC NETFLOW STATISTICS
# ============================================================================

def netflow_host_stats(ip_address, minutes=5):
    """
    Get NetFlow statistics for a specific host IP
    
    Args:
        ip_address: Host IP to query
        minutes: Time window in minutes (default 5)
    
    Returns:
        Dictionary with structure:
        {
            'ip': str,
            'time_window': minutes,
            'publicUS': {
                'total_bytes': int,
                'total_packets': int,
                'flow_count': int,
                'avg_speed': (value, unit),
                'formatted_bytes': (value, unit),
                'top5': [(dst_ip, dst_port, protocol, bytes, formatted), ...]
            },
            'publicDS': { ... },
            'privateUS': { ... },
            'privateDS': { ... }
        }
        
        Returns None if no NetFlow data found for this host
    """
    conn = sqlite3.connect(NETFLOW_DB)
    cur = conn.cursor()
    
    # Clamp minutes
    minutes = max(0.33, min(5.0, minutes))
    cutoff = time.time() - (minutes * 60)
    
    result = {
        'ip': ip_address,
        'time_window': minutes,
        'publicUS': None,
        'publicDS': None,
        'privateUS': None,
        'privateDS': None
    }
    
    has_data = False
    time_seconds = minutes * 60
    
    # Helper function for upload tables (srcIP = host)
    def query_upload_table(table_name):
        nonlocal has_data
        
        # Get totals
        cur.execute(f"""
            SELECT 
                SUM(CAST(bytes AS INTEGER)),
                SUM(CAST(packets AS INTEGER)),
                COUNT(*)
            FROM {table_name}
            WHERE srcIP = ? AND CAST(stamp AS REAL) > ?
        """, (ip_address, cutoff))
        
        row = cur.fetchone()
        total_bytes = row[0] or 0
        total_packets = row[1] or 0
        flow_count = row[2] or 0
        
        if flow_count > 0:
            has_data = True
        
        # Top 5 destinations
        cur.execute(f"""
            SELECT 
                dstIP,
                dstPort,
                protocol,
                SUM(CAST(bytes AS INTEGER)) as total_bytes
            FROM {table_name}
            WHERE srcIP = ? AND CAST(stamp AS REAL) > ?
            GROUP BY dstIP, dstPort, protocol
            ORDER BY total_bytes DESC
            LIMIT 5
        """, (ip_address, cutoff))
        
        top5_raw = cur.fetchall()
        top5 = []
        for ip, port, proto, bytes_val in top5_raw:
            formatted = format_bytes(bytes_val)
            proto_name = get_protocol_name(proto)
            service_name = get_service_name(ip)
            top5.append((ip, port, proto_name, bytes_val, formatted, service_name))
        
        return {
            'total_bytes': total_bytes,
            'total_packets': total_packets,
            'flow_count': flow_count,
            'avg_speed': calculate_speed(total_bytes, time_seconds),
            'formatted_bytes': format_bytes(total_bytes),
            'top5': top5
        }
    
    # Helper function for download tables (dstIP = host)
    def query_download_table(table_name):
        nonlocal has_data
        
        # Get totals
        cur.execute(f"""
            SELECT 
                SUM(CAST(bytes AS INTEGER)),
                SUM(CAST(packets AS INTEGER)),
                COUNT(*)
            FROM {table_name}
            WHERE dstIP = ? AND CAST(stamp AS REAL) > ?
        """, (ip_address, cutoff))
        
        row = cur.fetchone()
        total_bytes = row[0] or 0
        total_packets = row[1] or 0
        flow_count = row[2] or 0
        
        if flow_count > 0:
            has_data = True
        
        # Top 5 sources
        cur.execute(f"""
            SELECT 
                srcIP,
                srcPort,
                protocol,
                SUM(CAST(bytes AS INTEGER)) as total_bytes
            FROM {table_name}
            WHERE dstIP = ? AND CAST(stamp AS REAL) > ?
            GROUP BY srcIP, srcPort, protocol
            ORDER BY total_bytes DESC
            LIMIT 5
        """, (ip_address, cutoff))
        
        top5_raw = cur.fetchall()
        top5 = []
        for ip, port, proto, bytes_val in top5_raw:
            formatted = format_bytes(bytes_val)
            proto_name = get_protocol_name(proto)
            service_name = get_service_name(ip)
            top5.append((ip, port, proto_name, bytes_val, formatted, service_name))
        
        return {
            'total_bytes': total_bytes,
            'total_packets': total_packets,
            'flow_count': flow_count,
            'avg_speed': calculate_speed(total_bytes, time_seconds),
            'formatted_bytes': format_bytes(total_bytes),
            'top5': top5
        }
    
    # Query all four tables
    try:
        result['publicUS'] = query_upload_table('netflowPublicUS')
        result['publicDS'] = query_download_table('netflowPublicDS')
        result['privateUS'] = query_upload_table('netflowPrivateUS')
        result['privateDS'] = query_download_table('netflowPrivateDS')
    except sqlite3.OperationalError:
        # Tables don't exist yet
        pass
    finally:
        conn.close()
    
    # Return None if no data found for this host
    if not has_data:
        return None
    
    return result





# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------


def extensionCheck(unaIP, unaDB):
    diskCur = unaDB.cursor()
    try:
        for row in diskCur.execute("""
            SELECT propuesta 
            FROM extensiones
            WHERE macAddress = ?
            """, (unaIP,)):
            valor = row[0]
            if(len(valor)>0):
                return valor
        return None
    except Exception:
        return None
        
    

# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------



def systemStatus():
    diskDB = sqlite3.connect("/ramdisk/snmpqserver.db", isolation_level=None)
    diskDB.execute("PRAGMA journal_mode=WAL;")
    diskDB.execute("PRAGMA synchronous=NORMAL;")
    diskCur = diskDB.cursor()
    #
    losStamps = []
    aux = None
    for row in diskCur.execute("""
        SELECT MAX(CAST(stamp AS REAL))
        FROM statistics
        """):
        aux = row
    losStamps.append(aux)
    aux = None
    for row in diskCur.execute("""
        SELECT MAX(CAST(stamp AS REAL))
        FROM arp
        """):
        aux = row
    losStamps.append(aux)
    aux = None
    for row in diskCur.execute("""
        SELECT MAX(CAST(stamp AS REAL))
        FROM hostname
        """):
        aux = row
    losStamps.append(aux)
    aux = None
    for row in diskCur.execute("""
        SELECT MAX(CAST(stamp AS REAL))
        FROM switch
        """):
        aux = row
    losStamps.append(aux)
    aux = None
    for row in diskCur.execute("""
        SELECT MAX(CAST(stamp AS REAL))
        FROM macaddress
        """):
        aux = row
    losStamps.append(aux)
    aux = None
    for row in diskCur.execute("""
        SELECT MAX(CAST(stamp AS REAL))
        FROM switchHijosPadre
        """):
        aux = row
    losStamps.append(aux)
    return losStamps

