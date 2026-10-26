# coding=utf-8
#!/usr/bin/python -tt

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

snmpPyServer.py - gets data from switches & router, maintains and updates a database.
"""



from datetime import datetime
import time
import os
import sys
import subprocess
from subprocess import PIPE
import shutil
import fcntl
import multiprocessing
from multiprocessing import Pool
import sqlite3
import re
import traceback
import pathlib
import funciones
from collections import deque


###################################################################################################
###  1. VARIABLES ###


BASE_DIR = pathlib.Path(__file__).resolve().parent

# This file must be present for the service to run.
archivoOperacion = BASE_DIR / "snmpPiServer.running"
# Name of the file used to mimic a "singleton" mechanic. (IF this file is present, this script will detect it and asume another instance is already running)
archivoControl = "/ramdisk/LOCK_snmpPiServer.txt"
archivoLog = BASE_DIR / "syslog_core.txt"
logFlag = BASE_DIR / "logging.enabled"
settingsFile = BASE_DIR / "snmpQuery.ini"
systemEnabled = 1
global_community = ""
# HISTORICOS:
histDBPath = BASE_DIR / "historicaldata.db"
lastHistoric = 0.0
histDBperiod = 1800 # how often to aggregate data to the historical database (DB not in use yet)
haltFlag = 0

# armo las regex para NetSNMP.
oid1_regex = re.compile(
    r"dot1qTpFdbPort\[(\d+)\]\[STRING:\s*([0-9a-f:]+)\]\s*=\s*INTEGER:\s*(\d+)",
    re.IGNORECASE
)
oid2_regex = re.compile(r"dot1dStpPort\[(\d+)\]\s*=\s*INTEGER:\s*(\d+)")
oid3_regex = re.compile(r"dot1dBasePortIfIndex\[(\d+)\]\s*=\s*INTEGER:\s*(\d+)")
oid4_regex = re.compile(r"ifDescr\[(\d+)\]\s*=\s*STRING:\s*(.+)")
nbtscan_regex = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)")


# Debug & helper vars
global_offline = 0
elTTL = 0
maxLogs = 150
elStack = deque(maxlen=maxLogs)


# statistics
global_stats_perf = 0
global_stats_switches = 0

###################################################################################################

### 1. Operation check ###

if os.path.exists(archivoOperacion):
    print("snmpPyServer is Operating. Proceeding with script")
else:
    print("snmpPyServer is DISABLED. Operation Flag not found.")
    print("File must be present. Check "+archivoOperacion)
    time.sleep(3)
    sys.exit(0)
    
###################################################################################################
###################################################################################################
###################################################################################################

def loguear(texto):
    global archivoLog
    ahora = datetime.now()
    elStamp = ahora.strftime("%d/%m/%Y %H:%M:%S - ")
    escribir = elStamp + texto + "\n"
    try:
        if os.path.exists(logFlag):
            with open(archivoLog,"a") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                f.write(escribir)
                f.flush()
                fcntl.flock(f, fcntl.LOCK_UN)
        return 0
    except Exception as e:
        print("There was an error attempting to read/write the syslog (!)")
        print(e)
        return -1
    
    
def stackear(texto):
    global elStack
    ahora = datetime.now()
    elStamp = ahora.strftime("%d/%m/%Y %H:%M:%S - ")
    escribir = elStamp + str(texto.rstrip())
    try:
        elStack.append(escribir)
        return 0
    except Exception as e:
        print("An error occurred trying to add text to the debugging stack.")
        print(e)
        return -1
###################################################################################################

### 2. SINGLETON ###
if os.path.exists(archivoControl):
    print("File exists! No need to run")
    luzVerde = 0
else:
    print("File not found! Attempting to generate the Lock file...")
    loguear("Starting snmpPyServer.py . . .")
    loguear("File not found! Attempting to generate the Lock file...")
    try:
        NewArchivoControl = open(archivoControl,"w")
        NewArchivoControl.close
        luzVerde = 1
    except IOError:
        luzVerde = 0
        
# Si luzVerde == 1 le doy para adelante. Sino finalizo.
if (luzVerde == 0):
    sys.exit("Sript already running!. Check "+archivoControl)
    # print("Continuo..")
# Si sigo aca es porque puedo continuar, efectivamente, con las lecturas al archivo intermediario.

# DEBUG! para usar en development
os.remove(archivoControl)

# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


def extraerVariable(linea):
    caracteres = 0
    while( (linea[caracteres:caracteres+1] != '=') and (caracteres < 100) ):
        caracteres = caracteres + 1
    if(caracteres > 99):
        # no encontré el "=".
        return None
    variable = linea[:caracteres]
    valor = linea[caracteres+1:]
    valor = valor.rstrip()
    return [(variable),(valor)]


# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------

def leerPreferencias():
    localCur = diskDB.cursor()
    # abro el settingsFile
    flagSW = 0   # "START_SWITCHES" / "END_SWITCHES"
    elStamp = time.time()
    configs = []
    switches = []
    accesspoints = []
    try:
        with open(settingsFile,"r") as volatil:
            bodoque = volatil.readlines()
            for cadaRenglon in bodoque:
                if(len(cadaRenglon)>4):
                    # At this point Tuples might look like this: "variable=value" or
                    # ... "variable=value1=value2", or
                    # ... switch data "a.b.c.d=description"
                    if(cadaRenglon[:1]=="#"):
                        continue   # ignoring comments on the .ini file.
                    if("START_SWITCHES" in cadaRenglon):
                        flagSW = 1
                    if("END_SWITCHES" in cadaRenglon):
                        flagSW = 0
                    if(flagSW == 0):
                        tupla = extraerVariable(cadaRenglon)
                        if (tupla is None):
                            continue
                        if(tupla[0] == "AP"):
                            # Access Point, Line looks like this: "AP=aa:bb:cc:dd:ee:ff=APName".
                            # Here, tupla[0] is "AP", tupla[1] is "aa:bb:cc:dd:ee:ff=APName".
                            tempTupla = extraerVariable(tupla[1])
                            laMac = tempTupla[0].replace(":", "-")
                            accesspoints.append((laMac.lower(), tempTupla[1]),)
                            continue
                        elif(tupla[0] == "PORTQRY"):
                            continue # Legacy config, not used
                        elif(tupla[0] == "NAT"):
                            continue # Legacy config, not used
                        else:
                            # Here, the Line is a config parameter. For example:
                            # NETWORK=192.168.0.0
                            # THREADS=10
                            configs.append((tupla[0], tupla[1]),)
                            continue
                    else:
                        # Ok, this is a switch. "a.b.c.d=Switch-Name"
                        tupla = extraerVariable(cadaRenglon)
                        if (tupla is None):
                            continue
                        # tupla[0] is "a.b.c.d" (the switch's IP address).
                        # tupla[1] is "Switch-Name".
                        switches.append((elStamp, tupla[0], "unknown", tupla[1], "unknown"),)
        # We have: One with Switches, one with APs, and one with config parameters.
        try:
            # Accounting for added and removed switches from the config file.
            existentes = []
            for row in localCur.execute("""
                SELECT switchIP
                FROM switch
                """):
                   existentes.append(row[0])
            aEliminar = []
            aAgregar = []
            aActualizar = []
            switchesCfgIP = []
            for unSwitchCfg in switches:
                unSwitchCfgIP = unSwitchCfg[1]
                switchesCfgIP.append(unSwitchCfgIP)
                if(unSwitchCfgIP not in existentes):
                    # Switch is present in the .ini, not in the DB.
                    aAgregar.append(unSwitchCfg)
                else:
                    # Switch is present in .ini & DB, updating description.
                    aActualizar.append(unSwitchCfg)
            for unSwitchDB in existentes:
                if(unSwitchDB not in switchesCfgIP):
                    # Switch is present in DB, not in .ini
                    aEliminar.append(unSwitchDB)
            localCur.execute("BEGIN")
            if( len(aEliminar) > 0 ):
                for unaIP in aEliminar:
                    localCur.execute("DELETE FROM switch WHERE switchIP = ?",(unaIP,))
            if( len(aAgregar) > 0 ):
                for unSet in aAgregar:
                    localCur.execute(
                        "INSERT INTO switch (stamp, switchIP, switchMAC, switchDesc, switchStatus) VALUES (?, ?, ?, ?, ?)", unSet
                    )
            if( len(aActualizar) > 0 ):
                for unSet in aActualizar:
                    localCur.execute(
                        "UPDATE switch SET stamp = ?, switchDesc = ? WHERE switchIP = ?", (unSet[0], unSet[3], unSet[1])
                    )
            # ------------- parametro, valor
            localCur.execute("DELETE FROM siteData")
            localCur.executemany(
                "INSERT INTO siteData (parametro, valor) VALUES (?, ?)", configs
            )
            # ------------- apMac, apNombre
            localCur.execute("DELETE FROM accessPoints")
            localCur.executemany(
                "INSERT INTO accessPoints (apMac, apNombre) VALUES (?, ?)", accesspoints
            )
            diskDB.commit()
        except Exception as e:
            diskDB.rollback()
            print("error en transacción durante preferencias.")
            print(e)
            traceback.print_exc()
    except Exception as e:
        print(e)
        traceback.print_exc()



# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------



def familiarizar(elSwitchPadre, elPuertoPadre, elSwitchHijo):
    unString = "inicio familiarizar con (padre, puertoPadre, hijo): "+elSwitchPadre+", "+elPuertoPadre+", "+elSwitchHijo
    stackear(unString)
    localCur = diskDB.cursor()
    
    # We assume the father-son relationship exist, so we try to delete it.
    # HIJO(S) seen on X port are to be deleted, not the switchHijo.
    localCur.execute("BEGIN")
    localCur.execute("""
        DELETE FROM switchHijosPadre
        WHERE switchPadre = ?
            AND portPadre = ?
        """, (elSwitchPadre, elPuertoPadre))
    unStamp = time.time()
    localCur.execute("""
        INSERT INTO switchHijosPadre (stamp, switchPadre, portPadre, switchHijo)
        VALUES (?, ?, ?, ?)
        """, (unStamp, elSwitchPadre, elPuertoPadre, elSwitchHijo) )
    diskDB.commit()
    return






# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------

# def switchSewingRecursive(listaMinions, elMaster):
def switchSewingRecursive(listaMinions, elMaster, depth=0, max_depth=30):
    unString = "inicio switchSewingRecursive con elMaster: "+elMaster
    
    if(depth >= max_depth):
        loguear("switchSewingRecursive: Max Depth reached. Exiting")
        return -1
    
    stackear(unString)
    localCur = diskDB.cursor()
    
    # 1. For every port (elMaster) "aQuienVes()" is called, so:
        # 2. If a port sees other switches,
             # 3. For every one of those switches that port sees..
                 # 4A. If only one switch is seen on that port, a relationship can be established.
                 # 4B. If multiple switches are seen on that port:
                     # 5. We will check ALL possible combinations for sets of "elMaster" (say,
                     #    "elMasterDOS") and a new "listaMinions" (say, "losMinions").
                     #    For example, for switches "a,b,c":
                     #    ... "a" as elMasterDOS with "b,c" as losMinions, then..
                     #    ... "b" as elMasterDOS with "a,c" as losMinions, then..
                     #    ... "c" as elMasterDOS with "a,b" as losMinions.
                         # 6. If a given combination goes with losConoces():
                            # 7. "elMasterDOS" is the SON of "elMaster". Call to "familiarizar".
                            # 8. A recursive call is done, where "elMasterDOS" becomes "elMaster",
                            #    and "losMinions" become "listaMinions". The process repeats.
    
    # Getting "elMaster" ports:
    losPuertosMaster = []
    for rowSwitch in localCur.execute("""
        SELECT DISTINCT switchIP, portNum
        FROM switchPort
        WHERE switchIP = ?
        ORDER BY portNum
        """, (elMaster,)):
        # [switchIP][portNum]
        losPuertosMaster.append(rowSwitch)
    # iterating through the ports..
    elRetorno = 0
    for unPuertoMaster in losPuertosMaster:
        ### 1. For every port (elMaster) "aQuienVes()" is called, so:
        stackear("llamo aQuienVes con (laDB, "+elMaster+", "+unPuertoMaster[1]+")")
        switchesVisibles = funciones.aQuienVes(diskDB,elMaster,unPuertoMaster[1])
        stackear("volvi de aQuienVes.")
        # aQuienVes returns data like [(ip,desc,mac),(ip,desc,mac),(ip,desc,mac),(ip,desc,mac)]
        if(len(switchesVisibles)==1):
            ### 4A. If only one switch is seen on that port, a relationship can be established.
            # switchesVisibles looks: [DOWNLINK_IP][DOWNLINK_nombre][DOWNLINK_MAC][DOWNLINK_PORT]
            switchesVisiblesIP = []
            for cadaSwitch in switchesVisibles:
                switchesVisiblesIP.append(cadaSwitch[0])
            stackear("llamo a familiarizar.")
            familiarizar(elMaster, unPuertoMaster[1], switchesVisiblesIP[0])
            stackear("volvi de familiarizar.")
            
        if(len(switchesVisibles)>1):
            ### 4B. If multiple switches are seen on that port:
            # preparing switchesVisiblesIP
            switchesVisiblesIP = []
            for cadaSwitch in switchesVisibles:
                switchesVisiblesIP.append(cadaSwitch)
            ### 5. We will check ALL possible combinations for sets of "elMaster" (say,
            ###    "elMasterDOS") and a new "listaMinions" (say, "losMinions").
            elMasterDOS = None
            for cadaVisible in switchesVisiblesIP:
                laBolsa = embolsamiento(cadaVisible, switchesVisiblesIP)
                stackear("llamo a losConoces")
                if(losConoces(laBolsa, cadaVisible[0])):
                    elMasterDOS = cadaVisible[0]
                stackear("volvi de losConoces.")
            ### 6. If a given combination goes with losConoces():
            ### 7. "elMasterDOS" is the SON of "elMaster". Call to "familiarizar".
            if(elMasterDOS is not None):
                stackear("llamo a familiarizar 7.")
                familiarizar(elMaster, unPuertoMaster[1], elMasterDOS)
                stackear("volvi de familiarizar 7.")
                # Let's solve the remaining switches:
                ### 8. A recursive call is done, where "elMasterDOS" becomes "elMaster",
                ###    and "losMinions" become "listaMinions". The process repeats.
                stackear("hago llamada recursiva.")
                elRetorno = switchSewingRecursive(laBolsa, elMasterDOS, (depth+1), max_depth)
    return elRetorno


# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


def embolsamiento(individual, todos):
    laBolsa = []
    for unItem in todos:
        if(unItem != individual):
            laBolsa.append(unItem)
    return laBolsa


# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------



def losConoces(listaMinions, elMaster):
    unString = "inicio losConoces con (elMaster, [listaMinions] ): "+elMaster+", ["
    for minion in listaMinions:
        unString = unString + ", " + minion[0]
    unString = unString + "]"
    localCur = diskDB.cursor()
    hijosDelMaster = []
    for rowSwitch in localCur.execute("""
        SELECT switch.switchIP, switch.switchDesc, hijoMAC, hijoPORT
        FROM switch JOIN (
            SELECT DISTINCT macaddress.switchIP, macaddress.unaMac AS hijoMAC, macaddress.unPuerto AS hijoPORT
            FROM macaddress
            WHERE macaddress.switchIP = ?
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
        """, (elMaster,)):
        hijosDelMaster.append(rowSwitch)
    hijosDelMasterIP = []
    for cadaUno in hijosDelMaster:
        hijosDelMasterIP.append(cadaUno[0])
    encontrados = 0
    noEncontrados = 0
    for unMinion in listaMinions:
        if (unMinion[0] in hijosDelMasterIP):
            encontrados = encontrados + 1
        else:
            noEncontrados = noEncontrados + 1
    if(noEncontrados == 0):
        return True
    else:
        return False
    



# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------



def switchMapper():
    global haltFlag
    localCur = diskDB.cursor()
    # Need to find the ROOT and make a list with the switches.
    switches = []
    for row in localCur.execute("""
        SELECT switch.switchIP
            FROM switch 
            WHERE switch.switchStatus LIKE "%ONLINE%"
        """):
        switches.append(row)
    stackear("switchMapper: llamo a rootSwitchFinder.")
    elRoot = funciones.rootSwitchFinder(diskDB)
    stackear("switchMapper: elRoot es "+funciones.seg(elRoot[0]))
    # elRoot has [a.b.c.d][puntaje]
    unLog = "switchMapper: llamo a embolsamiento con elRoot y:"
    for cadaSw in switches:
        unLog = unLog + ", " + funciones.seg(cadaSw[0])
    stackear(unLog)
    laBolsa = embolsamiento(elRoot[0], switches)
    # CALL:
    stackear("switchMapper: llamo a switchSewingRecursive con laBolsa y elRoot.")
    try:
        switchSewingRecursive(laBolsa, elRoot[0])
    except Exception:
        loguear("Problema con llamada recursiva switchSewingRecursive")
        loguear("valores de switchMapper, (1) elRoot: "+elRoot[0])
        unString = "(2) switches: "
        for unSwitch in switches:
            unString = unString +", "+ unSwitch[0]
        loguear(unString)
        loguear(traceback.format_exc())
        haltFlag = 1
        stackear("switchMapper: hubo un problema y puse haltFlag en 1. revisar syslog.")
        loguear("vuelco del stack descriptivo:")
        for item in elStack:
            loguear(item.rstrip())
    
            


# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


    
    
    

# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------



# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------

def fetch_arp_table(host):
    ramDB = sqlite3.connect(":memory:")   # in-RAM DB
    unCur = ramDB.cursor()
    
    sinProcesar = netsnmpARP(host)
    rows_to_insert1 = []
    rows_to_insert2 = []
    
    # CREATING TEMPORAL/AUXILIARY TABLES:
    unCur.execute("""
    CREATE TABLE paso1 (
        ifIndexA TEXT,
        ifNameA TEXT,
        laVlan TEXT
    )
    """)
    # # #
    unCur.execute("""
    CREATE TABLE paso2 (
        ifIndexB TEXT,
        ip TEXT,
        mac TEXT
    )
    """)
    # # #
    unCur.execute("""
    CREATE TABLE tablaARP (
        interface TEXT,
        ip TEXT,
        mac TEXT
    )
    """)
    # # #
    
    temporal = []
    for varBind in sinProcesar:
        oid = tuple(varBind[0])
        if oid[:11] == (1,3,6,1,2,1,31,1,1,1,1):
            ifIndexA, ifNameA = parse_ifName(varBind)
            # from ifNameA we get the VLAN:
            laVlan = extract_vlan_from_ifname(ifNameA)
            if(laVlan is None):
                laVlan = "non-vlan"
            rows_to_insert1.append((ifIndexA, ifNameA, laVlan),)
        if oid[:10] == (1,3,6,1,2,1,3,1,1,2):
            ifIndexB, ip, mac = parse_ipNetToMedia(varBind)
            rows_to_insert2.append((ifIndexB,ip,mac),)
            temporal.append(oid)
    unCur.executemany(
        "INSERT INTO paso1 (ifIndexA, ifNameA, laVlan) VALUES (?, ?, ?)", rows_to_insert1
    )
    unCur.executemany(
        "INSERT INTO paso2 (ifIndexB, ip, mac) VALUES (?, ?, ?)", rows_to_insert2
    )
    elSelect = """
        SELECT paso1.ifNameA, paso1.laVlan, paso2.ip, paso2.mac
        FROM paso1
            JOIN paso2 on paso1.ifIndexA = paso2.ifIndexB
    """
    elMerge = []
    for row in unCur.execute(elSelect):
        elMerge.append((row[0], row[1], row[2], row[3].replace(':','-')),)
    return elMerge





# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------




def parse_dot1qTpFdbPort(varBind):
    oid = tuple(varBind[0])
    value = int(varBind[1])
    # dot1qTpFdbPort OID layout:
    # ... 1 (FdbId) . VLAN-ID . MAC1 . MAC2 . MAC3 . MAC4 . MAC5 . MAC6
    vlan_id = int(oid[-7])
    mac_bytes = oid[-6:]  # last 6 numbers
    mac = ':'.join(f"{b:02x}" for b in mac_bytes)
    port = value
    return vlan_id, mac, port

def parse_dot1dStpPort(varBind):
    # 1.3.6.1.2.1.17.2.15.1.1.<bridge_port> = <stp_port>
    oid = tuple(varBind[0])
    stp_port = int(varBind[1])
    bridge_port = oid[-1]
    return bridge_port, stp_port

def parse_dot1dBasePortIfIndex(varBind):
    # 1.3.6.1.2.1.17.1.4.1.2.<bridge_port> = <ifIndex>
    oid = tuple(varBind[0])
    ifindex = int(varBind[1])
    bridge_port = oid[-1]
    return bridge_port, ifindex


def parse_ifDescr(varBind):
    # 1.3.6.1.2.1.2.2.1.2.<ifIndex> = <ifDescr string>
    oid = tuple(varBind[0])
    descr = str(varBind[1])
    ifindex = oid[-1]
    return ifindex, descr

def parse_ipNetToMedia(varBind):
    oid = tuple(varBind[0])
    ifIndex = oid[-6]
    ip_bytes = oid[-4:]
    ip = ".".join(str(b) for b in ip_bytes)
    mac_bytes = bytes(varBind[1])
    mac = ":".join(f"{b:02x}" for b in mac_bytes)
    return ifIndex, ip, mac                

def parse_ifName(varBind):
    # 1.3.6.1.2.1.31.1.1.1.1.X = "PINDULFO COPPER 1/8" << X is ifIndex.
    oid = tuple(varBind[0])
    ifIndex = oid[-1]
    ifName = str(varBind[1])
    return ifIndex, ifName

def extract_vlan_from_ifname(ifname):
    if ifname.lower().startswith("vl"):
        try:
            return ifname[2:]
        except ValueError:
            return None
    return None



def normalize_value(value_str):
    value_str = value_str.strip()
    # INTEGER
    if value_str.startswith("INTEGER:"):
        return int(value_str.split(":", 1)[1].strip())
    # STRING
    if value_str.startswith("STRING:"):
        return value_str.split(":", 1)[1].strip().strip('"')
    # Hex-STRING: can have values >255
    if value_str.startswith("Hex-STRING:"):
        hex_part = value_str.split(":", 1)[1].strip()
        result_bytes = bytearray()
        try:
            for b in hex_part.split():
                num = int(b, 16)
                # Encode each number into minimum bytes needed
                length = (num.bit_length() + 7) // 8 or 1
                result_bytes.extend(num.to_bytes(length, "big"))
            return bytes(result_bytes)
        except Exception as e:
            loguear(str(e))
            loguear(value_str)
            loguear(traceback.format_exc())
            return value_str  # fallback to string
    # MAC address printed as 00:11:22:33:44:55
    if re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value_str):
        return bytes(int(b, 16) for b in value_str.split(":"))
    # Plain integer
    if value_str.isdigit():
        return int(value_str)
    # Fallback: string
    return value_str




def finalize_value(oid, value):
    TEXTUAL_OIDS = (
        (1,3,6,1,2,1,31,1,1,1,1),  # ifName
        (1,3,6,1,2,1,2,2,1,2),     # ifDescr
    )
    if isinstance(value, bytes):
        for prefix in TEXTUAL_OIDS:
            if oid[:len(prefix)] == prefix:
                try:
                    return value.decode("utf-8", errors="ignore")
                except Exception as e:
                    loguear(str(e))
                    loguear(traceback.format_exc())
                    return value
    return value




# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------




def netsnmpARP(host):
    salida = []
    # OIDS
    OID1 = "1.3.6.1.2.1.31.1.1.1.1"
    OID2 = "1.3.6.1.2.1.3.1.1.2"
    OIDS = [OID1, OID2]
    """
        -On     Numeric OIDs (faster, no MIB lookup)
        -Oqv    Values only (minimal output)
        -Oqn    incluye los OIDs en la respuesta pero sin el "=" (rompe)
        -Cr50   Bulk repetitions (tune per device)
        -Cc     Don’t check returned OIDs
        -Cq     Quiet
    """
    bulk = 50
    timeout = 2
    retries = 1
    for oid in OIDS:
        elComando = [
                "snmpbulkwalk",
                "-v2c",
                "-c", global_community,
                "-On",
                "-Ox",
                f"-Cr{bulk}",
                "-Cc",
                "-t", str(timeout),
                "-r", str(retries),
                host,
                oid,
            ]
        try:
            proc = subprocess.run(
                elComando,
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    # Example:
                    # .1.3.6.1.2.1.31.1.1.1.1.12 = GigabitEthernet0/12
                    oid_str, value_str = line.split(" = ", 1)

                    oid_tuple = tuple(
                        int(x) for x in oid_str.lstrip(".").split(".")
                    )
                    # Normalize value types to match pysnmp behavior
                    if value_str.isdigit():
                        value = int(value_str)
                    elif ":" in value_str and all(len(x) == 2 for x in value_str.split(":")):
                        # MAC address
                        value = bytes(int(b, 16) for b in value_str.split(":"))
                    else:
                        value = value_str.strip()
                    value = normalize_value(value_str)
                    value = finalize_value(oid_tuple, value)
                    salida.append((oid_tuple, value))
            else:
                print("returncode NO ES 0 (MAL!)")
                print("==== STDOUT ====")
                print(proc.stdout)
                print("==== STDERR ====")
                print(proc.stderr)
                print("Return code:", proc.returncode)                
            # return salida          
        except Exception as e:
            print(e)
    return salida





# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


def netsnmpSwitch(host, strategy):
    salida = []
    useStrategy = 0
    if(strategy is not None):
        useStrategy = 1
    # OIDS
    OID1 = "1.3.6.1.2.1.17.7.1.2.2.1.2"
    OID2 = "1.3.6.1.2.1.17.2.15.1.1"
    OID3 = "1.3.6.1.2.1.17.1.4.1.2"
    OID4 = "1.3.6.1.2.1.2.2.1.2"
    if(useStrategy==1):
        OIDS = []
        if(strategy[1] == "yes"):
            OIDS.append(OID1)
        if(strategy[2] == "yes"):
            OIDS.append(OID2)
        if(strategy[3] == "yes"):
            OIDS.append(OID3)
        if(strategy[4] == "yes"):
            OIDS.append(OID4)
    else:
        OIDS = [OID1, OID2, OID3, OID4]
    """
        -On     Numeric OIDs (faster, no MIB lookup)
        -Oqv    Values only (minimal output)
        -Oqn    incluye los OIDs en la respuesta.
        -Cr50   Bulk repetitions (tune per device)
        -Cc     Don’t check returned OIDs
        -Cq     Quiet
    """
    bulk = 50
    timeout = 4
    retries = 0
    for oid in OIDS:
        elComando = [
                "snmpbulkwalk",
                "-v2c",
                "-c", global_community,
                "-On",
                "-Ox",
                f"-Cr{bulk}",
                "-Cc",
                "-t", str(timeout),
                "-r", str(retries),
                host,
                oid,
            ]
        try:
            proc = subprocess.run(
                elComando,
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                rawLines1 = []
                parte = ""
                for line in proc.stdout.splitlines():
                        if(line.startswith(".1.")):
                            if(parte):
                                rawLines1.append(parte.strip())
                            parte = line
                        else:
                            parte = parte + line.strip()
                rawLines1.append(parte.strip())
                # In case OIDs don't exist, an error that says "No Such Object available on this agent at this OID"
                rawLines = []
                for cosa in rawLines1:
                    if("No Such" not in cosa):
                        rawLines.append(cosa)
                for line in rawLines:
                    # Example:
                    # .1.3.6.1.2.1.31.1.1.1.1.12 = GigabitEthernet0/12
                    oid_str, value_str = line.split(" = ", 1)
                    oid_tuple = tuple(
                        int(x) for x in oid_str.lstrip(".").split(".")
                    )
                    # Normalize value types to match pysnmp behavior
                    if value_str.isdigit():
                        value = int(value_str)
                    elif ":" in value_str and all(len(x) == 2 for x in value_str.split(":")):
                        # MAC address
                        value = bytes(int(b, 16) for b in value_str.split(":"))
                    else:
                        value = value_str.strip()
                    try:
                        value = normalize_value(value_str)
                        value = finalize_value(oid_tuple, value)
                        salida.append((oid_tuple, value))
                    except Exception as e:
                        print(str(e))
                        print(str(value_str))
                        cadena = ""
                        for cosa in oid_tuple:
                            cadena = cadena+"."+str(cosa)
                        print("CADENA: "+cadena)
                        print(traceback.format_exc())
            else:
                pass
                print(host+" OFFLINE!")
                return -1
        except Exception as e:
            print(e)
            traceback.print_exc()
            return salida
    return salida



# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------




def fetch_oid_fast(parametros):
    host, strategy = parametros
    ramDB = sqlite3.connect(":memory:")   # in-RAM DB
    unCur = ramDB.cursor()

    # TEMPORAL/AUXILIARY TABLES:
    unCur.execute("""
    CREATE TABLE paso1 (
        vlan TEXT,
        mac TEXT,
        pIndex1 TEXT
    )
    """)
    # dot1qTpFdbPort[1][STRING: dc:cd:2f:04:83:7d] = INTEGER: 8
    # dot1qTpFdbPort[1][STRING: e6:3f:f8:4b:78:32] = INTEGER: 8
    # ----
    unCur.execute("""
    CREATE TABLE paso2 (
        pIndex2 TEXT,
        pIndex1 TEXT
    )
    """)
    # dot1dStpPort[49153] = INTEGER: 1
    # dot1dStpPort[49154] = INTEGER: 2
    # ----
    unCur.execute("""
    CREATE TABLE paso3 (
        pIndex3 TEXT,
        pIndex2 TEXT
    )
    """)
    # dot1dBasePortIfIndex[49153] = INTEGER: 49153
    # dot1dBasePortIfIndex[49154] = INTEGER: 49154
    # ----
    unCur.execute("""
    CREATE TABLE paso4 (
        pIndex3 TEXT,
        portText TEXT
    )
    """)
    # ifDescr[3] = STRING: Vlan-interface3
    # ifDescr[49153] = STRING: gigabitEthernet 1/0/1 : copper
    # ---- TEMPORAL RESULTS TABLE.
    unCur.execute("""
    CREATE TABLE tempResults (
        vlan TEXT,
        mac TEXT,
        pIndex TEXT
    )
    """)
    # ----
    # OIDS
    useStrategy = 0
    if(funciones.validateStrategy(strategy)):
        # the process received a none blank strategy to try.
        useStrategy = 1
    time1 = time.time()
    success = 0
    attempts = 0
    # First, we will try to use the strategy. If it does not succeed, the
    #   full tests will be tried.
    debugStart = time.time()
    while ( (success == 0) and (attempts < 2) ):
        # OIDS to be used.
        OID1 = "1.3.6.1.2.1.17.7.1.2.2.1.2"
        OID2 = "1.3.6.1.2.1.17.2.15.1.1"
        OID3 = "1.3.6.1.2.1.17.1.4.1.2"
        OID4 = "1.3.6.1.2.1.2.2.1.2"
        if(useStrategy==1):
            OIDS = []
            if(strategy[1] == "yes"):
                OIDS.append(OID1)
            if(strategy[2] == "yes"):
                OIDS.append(OID2)
            if(strategy[3] == "yes"):
                OIDS.append(OID3)
            if(strategy[4] == "yes"):
                OIDS.append(OID4)
        else:
            OIDS = [OID1, OID2, OID3, OID4]
        ## --------------------------------------------
        rows_to_insert1 = []
        rows_to_insert2 = []
        rows_to_insert3 = []
        rows_to_insert4 = []
        intentosSnmp = 0
        resultadoOK = 0
        # We will attempt to get SNMP data and parse it into lists.
        while((intentosSnmp < 3) and (resultadoOK != 1)):
            try:
                rows_to_insert1.clear()
                rows_to_insert2.clear()
                rows_to_insert3.clear()
                rows_to_insert4.clear()
                count_validos1 = 0
                count_validos2a = 0
                count_validos2b = 0
                count_validos3a = 0
                count_validos3b = 0
                intentosSnmp = intentosSnmp + 1
                if(useStrategy!=1):
                    strategy = None
                sinProcesar = netsnmpSwitch(host,strategy)
                # If switch is ONLINE, the raw data will be on the list "sinProcesar"
                if(sinProcesar == -1):
                    # Switch OFFLINE!
                    #loguear("switch "+host+" offline")
                    return(host, 0.0, -1, None, None)
                for varBind in sinProcesar:
                    oid = tuple(varBind[0])
                    # dot1qTpFdbPort
                    if oid[:13] == (1,3,6,1,2,1,17,7,1,2,2,1,2):
                        vlan, mac, port = parse_dot1qTpFdbPort(varBind)
                        # Antaira switches usually have a "port 0" where it sees itself.
                        if(port>0):
                            rows_to_insert1.append((vlan, mac, port),)
                        if((port > 0 and port < 999)):
                            count_validos1 = count_validos1 + 1
                    # dot1dStpPort
                    if oid[:11] == (1,3,6,1,2,1,17,2,15,1,1):
                        bridge_port, stp_port = parse_dot1dStpPort(varBind)
                        rows_to_insert2.append((bridge_port, stp_port),)
                        if((stp_port > 0 and stp_port < 999)):
                            count_validos2b = count_validos2b + 1
                        if((bridge_port > 0 and bridge_port < 999)):
                            count_validos2a = count_validos2a + 1
                    # dot1dBasePortIfIndex
                    if oid[:11] == (1,3,6,1,2,1,17,1,4,1,2):
                        bridge_port, ifindex = parse_dot1dBasePortIfIndex(varBind)
                        rows_to_insert3.append((bridge_port, ifindex),)
                        if((ifindex > 0 and ifindex < 999)):
                            count_validos3b = count_validos3b + 1
                        if((bridge_port > 0 and bridge_port < 999)):
                            count_validos3a = count_validos3a + 1
                    # ifDescr
                    if oid[:10] == (1,3,6,1,2,1,2,2,1,2):
                        ifindex, descr = parse_ifDescr(varBind)
                        rows_to_insert4.append((ifindex, descr),)
                # resultadoOK = 1
                if( len(rows_to_insert1)>0 ):
                    resultadoOK = 1
            except Exception as e:
                # Something failed. Retrying.
                print(e)
                pass
        if(resultadoOK == 0):
            #loguear("switch "+host+" resultadoOK == 0")
            return(host, 0.0, -2, None, None)
        #
        #  
        time2 = time.time()
        if(useStrategy!=1):
            # We have the 4 OIDS (possibly). We need to find all valid indexes
            #   to be used as portNumber.
            # Any high credibilidad ( > 90% ) can be used as port Number.
            LportNum_table = []
            LportNum_field = []
            
            if(len(rows_to_insert1)>0):
                if( ( count_validos1/len(rows_to_insert1) ) > 0.9 ):
                    LportNum_table.append("paso1")
                    LportNum_field.append("pIndex1")
            if(len(rows_to_insert2)>0):
                if( ( count_validos2a/len(rows_to_insert2) ) > 0.9 ):
                    LportNum_table.append("paso2")
                    LportNum_field.append("pIndex1")
                if( ( count_validos2b/len(rows_to_insert2) ) > 0.9 ):
                    LportNum_table.append("paso2")
                    LportNum_field.append("pIndex2")
            if(len(rows_to_insert3)>0):
                if( ( count_validos3a/len(rows_to_insert3) ) > 0.9 ):
                    LportNum_table.append("paso3")
                    LportNum_field.append("pIndex2")
                if( ( count_validos3b/len(rows_to_insert3) ) > 0.9 ):
                    LportNum_table.append("paso3")
                    LportNum_field.append("pIndex3")
        #
        #
        #
        time3 = time.time()
        # Inserting rows to the temp tables so we can work with SQL joins.
        unCur.executemany(
            "INSERT INTO paso1 (vlan, mac, pIndex1) VALUES (?, ?, ?)", rows_to_insert1
        )
        unCur.executemany(
            "INSERT INTO paso2 (pIndex1, pIndex2) VALUES (?, ?)", rows_to_insert2
        )
        unCur.executemany(
            "INSERT INTO paso3 (pIndex2, pIndex3) VALUES (?, ?)", rows_to_insert3
        )
        unCur.executemany(
            "INSERT INTO paso4 (pIndex3, portText) VALUES (?, ?)", rows_to_insert4
        )
        # If we're using a strategy, we will skip ALL tests to save time. Else, ALL tests will be done.
        if(useStrategy!=1):
            # If paso2 does not exist, tests 1 through 6 will be FALSE.
            # tests 1 ~ 2 check paso1+paso2     FALSE if no paso2
            # tests 3 ~ 6 check paso2+paso3     FALSE if no paso2
            # tests 7 ~ 8 check paso3+paso4
            # tests 9 ~10 check paso2+paso4
            # tests 11~12 check paso1+paso3
            # tests 13~14 check paso1+paso4
            test1 = False
            test2 = False
            test3 = False
            test4 = False
            test5 = False
            test6 = False
            test7 = False
            test8 = False
            test9 = False
            test10 = False
            test11 = False
            test12 = False
            test13 = False
            condicionP1aP2 = ""
            condicionP2aP3 = ""
            condicionP3aP4 = ""
            condicionP2aP4 = ""
            condicionP1aP3 = ""
            condicionP1aP4 = ""
            # TEST1: Attempt to join paso1 with paso2 with paso2.pIndex2
            cantidad = 0
            for row in unCur.execute("""
                    SELECT COUNT(paso2.pIndex1)
                    FROM paso2 INNER JOIN paso1 ON paso1.pIndex1 = paso2.pIndex2
                """):
                cantidad = row[0]
            if(cantidad > len(rows_to_insert1)*0.75):
                test1 = True
                condicionP1aP2 = "paso1.pIndex1 = paso2.pIndex2"
            # TEST2: Attempt to join paso1 with paso2 with paso2.pIndex1
            test2 = False
            cantidad = 0
            for row in unCur.execute("""
                    SELECT COUNT(paso2.pIndex1)
                    FROM paso2 INNER JOIN paso1 ON paso1.pIndex1 = paso2.pIndex1
                """):
                cantidad = row[0]
            if(cantidad > len(rows_to_insert1)*0.75):
                test2 = True
                condicionP1aP2 = "paso1.pIndex1 = paso2.pIndex1"
            # a. We assume paso1 and paso4 always exist. paso2 and paso3 may or may not exist.
            # b. pasos [2, 3 and 4] have ~same~ #rows (same #N of interfaces w/ indexes,Descriptions)
            # TESTs 3~6: Attempt to join paso2 to paso3 (4 possible combinations)
            # TEST3:
            cantidad = 0
            for row in unCur.execute("""
                    SELECT COUNT(paso3.pIndex2)
                    FROM paso3 INNER JOIN paso2 ON paso2.pIndex1 = paso3.pIndex2
                """):
                cantidad = row[0]
            if(cantidad > len(rows_to_insert4)*0.75):
                test3 = True
                condicionP2aP3 = "paso2.pIndex1 = paso3.pIndex2"
            # TEST4:
            cantidad = 0
            for row in unCur.execute("""
                    SELECT COUNT(paso3.pIndex2)
                    FROM paso3 INNER JOIN paso2 ON paso2.pIndex2 = paso3.pIndex2
                """):
                cantidad = row[0]
            if(cantidad > len(rows_to_insert4)*0.75):
                test4 = True
                condicionP2aP3 = "paso2.pIndex2 = paso3.pIndex2"
            #
            # TEST5: inverting indexes for step3
            cantidad = 0
            for row in unCur.execute("""
                    SELECT COUNT(paso3.pIndex2)
                    FROM paso3 INNER JOIN paso2 ON paso2.pIndex1 = paso3.pIndex3
                """):
                cantidad = row[0]
            if(cantidad > len(rows_to_insert4)*0.75):
                test5 = True
                condicionP2aP3 = "paso2.pIndex1 = paso3.pIndex3"
            # TEST6:
            cantidad = 0
            for row in unCur.execute("""
                    SELECT COUNT(paso3.pIndex2)
                    FROM paso3 INNER JOIN paso2 ON paso2.pIndex2 = paso3.pIndex3
                """):
                cantidad = row[0]
            if(cantidad > len(rows_to_insert4)*0.75):
                test6 = True
                condicionP2aP3 = "paso2.pIndex2 = paso3.pIndex3"
            # We have test3,4,5,6 telling us how to join paso2 with paso3.
            # TESTs 7~8: We try to join paso3 and paso4.
            cantidad = 0
            for row in unCur.execute("""
                    SELECT COUNT(paso4.pIndex3)
                    FROM paso4 INNER JOIN paso3 ON paso3.pIndex2 = paso4.pIndex3
                """):
                cantidad = row[0]
            if(cantidad > len(rows_to_insert4)*0.75):
                test7 = True
                condicionP3aP4 = "paso3.pIndex2 = paso4.pIndex3"
            #
            cantidad = 0
            for row in unCur.execute("""
                    SELECT COUNT(paso4.pIndex3)
                    FROM paso4 INNER JOIN paso3 ON paso3.pIndex3 = paso4.pIndex3
                """):
                cantidad = row[0]
            if(cantidad > len(rows_to_insert4)*0.75):
                test8 = True
                condicionP3aP4 = "paso3.pIndex3 = paso4.pIndex3"
            # Test 9~10: paso2 and paso4
            # TEST9: inverting indexes for step3
            cantidad = 0
            for row in unCur.execute("""
                    SELECT COUNT(paso4.pIndex3)
                    FROM paso4 INNER JOIN paso2 ON paso2.pIndex1 = paso4.pIndex3
                """):
                cantidad = row[0]
            if(cantidad > len(rows_to_insert4)*0.75):
                test9 = True
                condicionP2aP4 = "paso2.pIndex1 = paso4.pIndex3"
            # TEST10:
            cantidad = 0
            for row in unCur.execute("""
                    SELECT COUNT(paso4.pIndex3)
                    FROM paso4 INNER JOIN paso2 ON paso2.pIndex2 = paso4.pIndex3
                """):
                cantidad = row[0]
            if(cantidad > len(rows_to_insert4)*0.75):
                test10 = True
                condicionP2aP4 = "paso2.pIndex2 = paso4.pIndex3"
            # Test 11~12: paso1 and paso3
            # TEST11:
            cantidad = 0
            for row in unCur.execute("""
                    SELECT COUNT(paso3.pIndex3)
                    FROM paso3 INNER JOIN paso1 ON paso1.pIndex1 = paso3.pIndex3
                """):
                cantidad = row[0]
            if(cantidad > len(rows_to_insert4)*0.75):
                test11 = True
                condicionP1aP3 = "paso1.pIndex1 = paso3.pIndex3"
            # TEST12:
            cantidad = 0
            for row in unCur.execute("""
                    SELECT COUNT(paso3.pIndex3)
                    FROM paso3 INNER JOIN paso1 ON paso1.pIndex1 = paso3.pIndex2
                """):
                cantidad = row[0]
            if(cantidad > len(rows_to_insert4)*0.75):
                test12 = True
                condicionP1aP3 = "paso1.pIndex1 = paso3.pIndex2"
            # Test 13: paso1 and paso4
            # TEST13:
            cantidad = 0
            for row in unCur.execute("""
                    SELECT COUNT(paso4.pIndex3)
                    FROM paso4 INNER JOIN paso1 ON paso1.pIndex1 = paso4.pIndex3
                """):
                cantidad = row[0]
            if(cantidad > len(rows_to_insert4)*0.75):
                test13 = True
                condicionP1aP4 = "paso1.pIndex1 = paso4.pIndex3"
            
            # All tests are done:
            # "if" tests ( [1|2] and [3|4|5|6] and [7|8] ), then ALL tables connect ok.
            # "elif" tests ( [1|2] and [9|10] ), then paso1-paso2-paso4 (paso3 is empty)
            # "elif" tests ( [11|12] and [7|8] ), then paso1-paso3-paso4 (paso2 is empty)
            # "elif" tests ( [13|14] ), then paso1-paso4 (paso2 and paso3 are empty)
            # "else", we only have paso1.
            
            # We should have a reliable portNum ( >0 and < 999) here:
            #    portNum_table & portNum_field
            elSelect = None
            
            # Trying to do the LEAST amount of work:
            # If paso1 or paso4 are in portNum_table, we can Attempt paso1-paso4
            #   directly. Else we skip paso2 or paso3, else we do the full path
            
            # 1.
            #
            # FIRST: We attempt to join paso1+paso4, if portNum_table is paso1 or 4.
                # ... if not possible:
            # SECOND: We attempt to join paso1+paso2+paso4, if portNum_table is paso2.
                # ... if not possible:
            # THIRD: We attempt to join paso1+paso3+paso4, if portNum_table is paso3.
                # ... if not possible:
            # FOURTH: We attempt to join paso1+paso2+paso3+paso4
            #
            if( (test13) and (("paso1" in LportNum_table) or ("paso4" in LportNum_table)) ):
                # paso1-paso4
                elSelect = """
                    SELECT paso1.vlan, paso1.mac, paso4.pIndex3, paso4.portText
                    FROM paso1
                        INNER JOIN paso4 ON """+condicionP1aP4+"""
                    """
                newStrategy = [host,"yes","no","no","yes",None,None,None,None,None,condicionP1aP4,"paso4","pIndex3"]
            # ----------------------------------------------------------------------
            elif( (test1 or test2) and (test9 or test10) and ("paso2" in LportNum_table) ):
                # paso1-paso2-paso4.
                # lets get portNum_table and porNum_field
                position = 0
                for item in LportNum_table:
                    if("paso2" == item):
                        break
                    position = position+1
                portNum_table = LportNum_table[position]
                portNum_field = LportNum_field[position]
                elSelect = f"""
                    SELECT paso1.vlan, paso1.mac, {portNum_table}.{portNum_field}, paso4.portText
                    FROM paso1
                        INNER JOIN paso2 ON """+condicionP1aP2+"""
                        INNER JOIN paso4 ON """+condicionP2aP4+"""
                    """
                newStrategy = [host,"yes","yes","no","yes",condicionP1aP2,None,None,condicionP2aP4,None,None,portNum_table,portNum_field]
            # ----------------------------------------------------------------------
            elif( (test11 or test12) and (test7 or test8) and ("paso3" in LportNum_table) ):
                # paso1-paso3-paso4. ANTAIRA!
                # lets get portNum_table and porNum_field
                position = 0
                for item in LportNum_table:
                    if("paso3" == item):
                        break
                    position = position+1
                portNum_table = LportNum_table[position]
                portNum_field = LportNum_field[position]
                elSelect = f"""
                    SELECT paso1.vlan, paso1.mac, {portNum_table}.{portNum_field}, paso4.portText
                    FROM paso1
                        INNER JOIN paso3 ON """+condicionP1aP3+"""
                        INNER JOIN paso4 ON """+condicionP3aP4+"""
                    """
                newStrategy = [host,"yes","no","yes","yes",None,None,condicionP3aP4,None,condicionP1aP3,None,portNum_table,portNum_field]
            # ----------------------------------------------------------------------
            elif( (test1 or test2) and (test3 or test4 or test5 or test6) and (test7 or test8) ):
                # The 4 tables will be joined.
                portNum_table = LportNum_table[0]
                portNum_field = LportNum_field[0]
                elSelect = f"""
                    SELECT paso1.vlan, paso1.mac, {portNum_table}.{portNum_field}, paso4.portText
                    FROM paso1
                        INNER JOIN paso2 ON """+condicionP1aP2+"""
                        INNER JOIN paso3 ON """+condicionP2aP3+"""
                        INNER JOIN paso4 ON """+condicionP3aP4+"""
                    """
                newStrategy = [host,"yes","yes","yes","yes",condicionP1aP2,condicionP2aP3,condicionP3aP4,None,None,None,portNum_table,portNum_field]
            # ----------------------------------------------------------------------
            # We went the full route, but now we know the shortest path for the next runs: newStrategy has the data.
        time4 = time.time()
        if(useStrategy==1):
            # We know a strategy we can use.
            portNum_table = strategy[11]
            portNum_field = strategy[12]
            usePaso2 = strategy[2]
            usePaso3 = strategy[3]
            condicionP1aP2 = strategy[5]
            condicionP2aP3 = strategy[6]
            condicionP3aP4 = strategy[7]
            condicionP2aP4 = strategy[8]
            condicionP1aP3 = strategy[9]
            condicionP1aP4 = strategy[10]
            #
            if(not funciones.validateStrategy(strategy)):
                loguear("Host "+host+". La estrategia no es valida. Deshabilitandola y reintentando.")
                useStrategy = 0
                continue
            #
            if( usePaso2 == "yes" and usePaso3 == "yes" ):
                # the 4 tables will do.
                joinConditions = " INNER JOIN paso2 ON "+condicionP1aP2+" "
                joinConditions = joinConditions + "INNER JOIN paso3 ON "+condicionP2aP3+" "
                joinConditions = joinConditions + "INNER JOIN paso4 ON "+condicionP3aP4+" "
            if( usePaso2 == "no" and usePaso3 == "yes" ):
                # paso1+paso3+paso4
                joinConditions = " INNER JOIN paso3 ON "+condicionP1aP3+" "
                joinConditions = joinConditions + "INNER JOIN paso4 ON "+condicionP3aP4+" "
            if( usePaso2 == "yes" and usePaso3 == "no" ):
                # paso1+paso2+paso4
                joinConditions = " INNER JOIN paso2 ON "+condicionP1aP2+" "
                joinConditions = joinConditions + "INNER JOIN paso4 ON "+condicionP2aP4+" "
            if( usePaso2 == "no" and usePaso3 == "no" ):
                # paso1+paso3+paso4
                joinConditions = " INNER JOIN paso4 ON "+condicionP1aP4+" "
            #########################################################################################
            elSelect = f"""
                SELECT paso1.vlan, paso1.mac, {portNum_table}.{portNum_field}, paso4.portText
                FROM paso1"""+joinConditions
        time5 = time.time()
        # either if we used a strategy or not, we should have some sort of SELECT defined.
        if(elSelect is None):
            return(host, 0.0, -2, None, None)
        elMerge = []
        try:
            for row in unCur.execute(elSelect):
                elMerge.append( (row[0], row[1].replace(':','-'), row[2], row[3] ) )
        except Exception as e:
            loguear(str(e))
            loguear(traceback.format_exc())
            loguear("")
            loguear("SELECT:")
            loguear(elSelect)
            # Strategy did not work.
            useStrategy = 0
            loguear(LportNum_table)
            loguear(LportNum_field)
        time6 = time.time()
            
        ################################################################### did it work?
        # [VLAN][MAC][pIndex?][portText]
        ### If the result is OK, we should return the strategy back along with the results.
        validos = 0
        # elMerge has many rows, each row has [vlan, mac, portNumber, PortDesc]
        for cosa in elMerge:
            if( int(cosa[2]) < 999 ):
                validos = validos + 1
        #
        # so, do we have a significant amount of rows and valid portNumers? 
        if( (len(elMerge) > (len(rows_to_insert1)*0.75) ) and (validos > (len(rows_to_insert1)*0.75) ) ):
            # success!
            success = 1
            if(useStrategy!=1):
                strategy = newStrategy
        else:
            # In case we had attempted a strategy, we will disable it to run
            #   all tests in the next attempt.
            useStrategy = 0
        #    
        time7 = time.time()
        losTiempos = None
        if( success == 1 ):
            strTiempos = "\n\n   TIEMPOS SWITCH "+host+"\n"
            strTiempos += f"      validateStrategy: {time1 - debugStart:.3f}\n"
            strTiempos += f"      snmp call & rows: {time2 - time1:.3f}\n"
            strTiempos += f"      portNum selected: {time3 - time2:.3f}\n"
            strTiempos += f"      13 TESTs + query: {time4 - time3:.3f}\n"
            strTiempos += f"      strategy + query: {time5 - time4:.3f}\n"
            strTiempos += f"      > executequery(): {time6 - time5:.3f}\n"
            strTiempos += f"      verif. resultado: {time7 - time6:.3f}\n"
            return host, 0.0, elMerge, losTiempos, strategy
            # Returned data looks like this:
            # [switchIP][time][ dataTable ][moreTimes][strategy]
            # [a.b.c.d][1.23455][ [vlan][mac][unPort][portDesc] ][ losTiempos ][ [][][][][][][][][][][][] ]
        else:
            attempts = attempts + 1
    # We run out of attempts.
    return(host, 0.0, -2, None, None)
    




# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------



def vendorLookup(unaMAC):
    localCur = diskDB.cursor()
    # Gets a MAC address, Gives VENDOR for it.
    devolver = None
    for row in localCur.execute("""
        SELECT elVendor
        FROM vendor
        WHERE ? LIKE halfMac || '%'
    """,(unaMAC,)):
        devolver = row[0]
    return devolver
    



# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------



def hostnameUpdateWorker(stop_event):
    diskDBworker = sqlite3.connect("/ramdisk/snmpqserver.db", isolation_level=None)
    diskDBworker.execute("PRAGMA journal_mode=WAL;")
    diskDBworker.execute("PRAGMA synchronous=NORMAL;")
    localCur = diskDBworker.cursor()
    
    
    # worker lives in an endless LOOP.
    ### 1. Operation check ###

    while not stop_event.is_set():
        try:
            laRedLocal = funciones.leerDBenSQL(diskDBworker, "NETWORK")
            maskbits = funciones.leerDBenSQL(diskDBworker, "MASKBITS")
            losHosts = []
            comando = "nbtscan -t 500 -l -q "+laRedLocal+"/"+maskbits
            proceso2 = subprocess.Popen(comando, shell=True, close_fds=True, stdout=PIPE)
            resultado = proceso2.communicate()[0]
            losHostnames = resultado
            losHostnames = losHostnames.splitlines()
            for unHostLinea in losHostnames:
                unHostLinea = unHostLinea.decode("utf-8")
                unHostLinea = unHostLinea.strip()
                unMatch = nbtscan_regex.match(unHostLinea)
                if unMatch:
                    unaIP, unHostname = unMatch.groups()
                    losHosts.append((unaIP,unHostname),)
            # We've got a list with hosts and IPs.
            unStamp = time.time()
            try:
                localCur.execute("BEGIN")
                for unPar in losHosts:
                    localCur.execute("DELETE FROM hostname WHERE ipaddr = ?", (unPar[0],))
                    localCur.execute("INSERT INTO hostname VALUES (?,?,?)", (unStamp,unPar[0],unPar[1]))
                diskDBworker.commit()
            except Exception as e:
                diskDBworker.rollback()
                print(e)
            time.sleep(2)
        except Exception:
            pass



# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------

def testearRequerimientos():
    if shutil.which("nbtscan") is None:
        print("ERROR: nbtscan no está instalado y es necesario para resolucion de nombres.")
        sys.exit(1)


# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------

def crearTablas():
    localCur = diskDB.cursor()
    
    # switch strategy for better performance:
    localCur.execute("""
        CREATE TABLE IF NOT EXISTS snmpStrategy (
            switchIP TEXT,
            usePaso1 TEXT,
            usePaso2 TEXT,
            usePaso3 TEXT,
            usePaso4 TEXT,
            condicionP1aP2 TEXT,
            condicionP2aP3 TEXT,
            condicionP3aP4 TEXT,
            condicionP2aP4 TEXT,
            condicionP1aP3 TEXT,
            condicionP1aP4 TEXT,
            portNum_table TEXT,
            portNum_field TEXT
        )
    """)
    
    
    # performance tracking:
    localCur.execute("""
        CREATE TABLE IF NOT EXISTS statistics (
            stamp TEXT,
            threads TEXT,
            secondsPerSwitch TEXT
        )
    """)
    # Tablas definitivas.
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
    # # vlan, mac, portIndex, portText
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
        CREATE TABLE IF NOT EXISTS vendor (
            halfMac TEXT,
            elVendor TEXT
        )
    """)
    localCur.execute("""
        CREATE TABLE IF NOT EXISTS siteData (
            parametro TEXT,
            valor TEXT
        )
    """)
    localCur.execute("""
        CREATE TABLE IF NOT EXISTS accessPoints (
            apMac TEXT,
            apNombre TEXT
        )
    """)
    localCur.execute("""
        CREATE TABLE IF NOT EXISTS switchPort (
            switchIP TEXT,
            portNum TEXT,
            portDesc TEXT,
            portType TEXT,
            isRoot TEXT
        )
    """)
    


# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


def crearTablasHistoricas(histDB):
    localCur = histDB.cursor()
    
    # Tables for NETFLOW data!
    diskCur.execute("""
        CREATE TABLE IF NOT EXISTS netflowPrivate (
            stamp TEXT,
            srcIP TEXT,
            dstIP TEXT,
            srcPort TEXT,
            dstPort TEXT,
            protocol TEXT,
            packets TEXT,
            bytes TEXT,
            tiempo TEXT
        )
    """)
    diskCur.execute("""
        CREATE TABLE IF NOT EXISTS netflowPublic (
            stamp TEXT,
            srcIP TEXT,
            dstIP TEXT,
            srcPort TEXT,
            dstPort TEXT,
            protocol TEXT,
            packets TEXT,
            bytes TEXT,
            tiempo TEXT
        )
    """)
    
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



def ARPrefresh():
    localCur = diskDB.cursor()
    elRouter = funciones.getGateway(diskDB)
    elStamp = time.time()
    auxTabla = fetch_arp_table(elRouter)
    laTabla = []
    for unRow in auxTabla:
        laTabla.append((elStamp,) + unRow)
    if( len(laTabla)>2 ):
        try:
            localCur.execute("BEGIN")
            localCur.execute("DELETE FROM arp")
            localCur.executemany(
                "INSERT INTO arp (stamp, ifNameA, laVlan, ipAddr, macAddr) VALUES (?, ?, ?, ?, ?)", laTabla
            )
            # We update the switches table, adding their management interface's MAC address.
            localCur.execute("""
                UPDATE switch
                    SET switchMAC = temp.unaMac
                    FROM (SELECT macaddr AS unaMac, ipaddr FROM arp) AS temp
                    WHERE temp.ipaddr = switch.switchIP
                """
            )
            diskDB.commit()
        except Exception:
            diskDB.rollback()




# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


def updateSwitchStatus(result):
    unStamp = time.time()
    switchOffline = 0
    if(result[2] == -1):
        # Switch OFFLINE
        elQuery = " UPDATE switch SET switchStatus = 'OFFLINE' WHERE switch.switchIP = '"+result[0]+"'"
        diskCur.execute(elQuery)
        switchOffline = 1
    if(switchOffline == 0):
        try:
            diskCur.execute("BEGIN")
            diskCur.execute("""
                UPDATE switch
                SET switchStatus = ?, stamp = ?
                WHERE switchIP = ?
            """, ("ONLINE ("+str(len(result[2]))+" MACs)", unStamp, result[0]) )
            diskDB.commit()
        except Exception:
            diskDB.rollback()







# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


def procesarMacAddresses(result):
    localCur = diskDB.cursor()
    # CACHE auxiliar
    ramDB = sqlite3.connect(":memory:")   # in-RAM DB
    ramCur = ramDB.cursor()
    ramCur.execute("""
                    CREATE TABLE IF NOT EXISTS macaddressAUX (
                        switchIP TEXT,
                        unPuerto TEXT,
                        unPuertoDesc TEXT
                    )
    """)
    unStamp = time.time()
    if( funciones.isOnline(diskDB, result[0]) and ( result[2] != -1 ) and ( result[2] != -2 ) ):
        # preparo las MACs.
        macInserts = []
        switchPortInserts = []
        for unRow in result[2]:
            # [vlan][mac][unPort][portDesc]
            # [stamp][switchip][vlan][mac][unPort]
            macInserts.append((unStamp,result[0],) + (unRow[0], unRow[1], unRow[2]))
            # [switchip][unPort][portDesc]
            switchPortInserts.append((result[0],) + (unRow[2], unRow[3]))
        # Temp table:
        ramCur.executemany("""
            INSERT INTO macaddressAUX (switchIP, unPuerto, unPuertoDesc)
                VALUES (?, ?, ?)
        """, switchPortInserts)
        switchPortInserts = []
        # We get a list, without repetitions.
        for row in ramCur.execute("""
            SELECT DISTINCT switchIP, unPuerto, unPuertoDesc
                FROM macaddressAUX
                ORDER BY switchIP, unPuerto
            """):
            switchPortInserts.append(row)
        ramDB.close()
        # updating tables.
        try:
            localCur.execute("BEGIN")
            elQuery = "DELETE FROM macaddress WHERE switchIP = '"+result[0]+"'"
            localCur.execute(elQuery)
            #
            elQuery = "DELETE FROM switchPort WHERE switchIP = '"+result[0]+"'"
            localCur.execute(elQuery)
            #
            localCur.executemany("""
                INSERT INTO macaddress (stamp, switchIP, unaVLAN, unaMAC, unPuerto)
                VALUES (?, ?, ?, ?, ?)
            """, macInserts)
            #
            localCur.executemany("""
                INSERT INTO switchPort (switchIP, portNum, portDesc, portType, isRoot)
                VALUES (?, ?, ?, NULL, NULL)
            """, switchPortInserts)
            # We discover ACCESS/TRUNK/ROOT ports while inside the SQL transaction.
            portTypeUpdater()
            diskDB.commit()
        except Exception:
            diskDB.rollback()
            print("hice rollback")




# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


def portTypeUpdater():
    localCur = diskDB.cursor()
    laGatewayMAC = funciones.getGatewayMAC(diskDB)
    elBypassString = None
    elBypassString = funciones.leerDBenSQL(diskDB,"bypass")
    if(elBypassString is not None):
        switchBypass,portBypass = extraerVariable(elBypassString)
    localCur.execute("""
        UPDATE switchport SET isRoot =
            CASE
                WHEN (switchIP, portNum) IN (
                    SELECT DISTINCT switchIP, unPuerto
                    FROM macaddress
                    WHERE unaMAC LIKE ?
                ) THEN 'ROOT'
                ELSE ''
            END;
        """, (laGatewayMAC,))
    localCur.execute("""
        UPDATE switchport SET portType =
            CASE
                WHEN (switchIP, portNum) IN (
                    SELECT DISTINCT switchIP, unPuerto
                    FROM macaddress
                    WHERE unaMAC IN (
                        SELECT switchMac
                        FROM switch 
                    )
                ) THEN 'TRUNK'
                WHEN (switchIP = ? AND portNum = ?) THEN 'TRUNK'
                ELSE 'ACCESS'
            END;
        """, (switchBypass,portBypass))
        




# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------



def persitirHistoricos(diskDB):
    global lastHistoric
    localCur = diskDB.cursor()
    #
    ahora = time.time()
    if( (ahora - lastHistoric) < histDBperiod ):
        return
    lastHistoric = ahora
    try:
        localCur.execute("ATTACH DATABASE ? AS history", (str(histDBPath),) )
        localCur.execute("BEGIN")
        # ARP table
        localCur.execute("""
            INSERT INTO history.arp (stamp, ifNameA, laVlan, ipaddr, macaddr)
            SELECT ?, ifNameA, laVlan, ipaddr, macaddr
            FROM main.arp
        """, (str(ahora),) )
        
        # hostname table
        localCur.execute("""
            INSERT INTO history.hostname (stamp, ipaddr, hostname)
            SELECT ?, ipaddr, hostname
            FROM main.hostname
        """, (str(ahora),) )
        # switch table
        localCur.execute("""
            INSERT INTO history.switch (stamp, switchIP, switchMAC, switchDesc, switchStatus)
            SELECT ?, switchIP, switchMAC, switchDesc, switchStatus
            FROM main.switch
        """, (str(ahora),) )
        # macaddress table
        localCur.execute("""
            INSERT INTO history.macaddress (stamp, switchIP, unaVLAN, unaMac, unPuerto)
            SELECT ?, switchIP, unaVLAN, unaMac, unPuerto
            FROM main.macaddress
        """, (str(ahora),) )
        # switchHijosPadre table
        localCur.execute("""
            INSERT INTO history.switchHijosPadre (stamp, switchPadre, portPadre, switchHijo)
            SELECT ?, switchPadre, portPadre, switchHijo
            FROM main.switchHijosPadre
        """, (str(ahora),) )
        # siteData table
        localCur.execute("""
            INSERT INTO history.siteData (stamp, parametro, valor)
            SELECT ?, parametro, valor
            FROM main.siteData
        """, (str(ahora),) )
        # accessPoints table
        localCur.execute("""
            INSERT INTO history.accessPoints (stamp, apMac, apNombre)
            SELECT ?, apMac, apNombre
            FROM main.accessPoints
        """, (str(ahora),) )
        # switchPort table
        localCur.execute("""
            INSERT INTO history.switchPort (stamp, switchIP, portNum, portDesc, portType, isRoot)
            SELECT ?, switchIP, portNum, portDesc, portType, isRoot
            FROM main.switchPort
        """, (str(ahora),) )
        diskDB.commit()
        localCur.execute("DETACH DATABASE history")
    except Exception as e:
        diskDB.rollback()
        print(e)
        traceback.print_exc()







# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------




































# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------

# --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---
# --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---


if __name__ == "__main__":
    testearRequerimientos()
    #
    diskDB = sqlite3.connect("/ramdisk/snmpqserver.db", isolation_level=None)
    diskDB.execute("PRAGMA journal_mode=WAL;")
    diskDB.execute("PRAGMA synchronous=NORMAL;")
    diskCur = diskDB.cursor()
    #
    histDB = sqlite3.connect(histDBPath, isolation_level=None)
    crearTablasHistoricas(histDB)
    # We attempt to create the database and tables.
    crearTablas()
    if(global_offline == 0):
        leerPreferencias()
    global_community = funciones.leerDBenSQL(diskDB, "community")
    # updating the VENDORS table
    if( not os.path.exists("/ramdisk/index.html") ):
        funciones.updateVendors(diskDB)
    # Starting an endless hostname updater process, completely independant.
    stop_event = multiprocessing.Event()
    process_hostnames = multiprocessing.Process(target=hostnameUpdateWorker, args=(stop_event,),)
    process_hostnames.start()
    # ---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#---#
    concurrentes = 10
    tiempoAnterior = 0
    lastEffect = None
    loguear("MAIN: Threads iniciados.")
    startingTime = time.time()
    time.sleep(2)
    if(elTTL > 0):
        runtime_secs = elTTL*3600
    else:
        runtime_secs = 3600
    
    while( ((time.time() - startingTime) < runtime_secs ) and (haltFlag == 0) ):
        # MAIN LOOP
        inicio = time.time()
        # We read the preferences file to get settings, switches, APs, etc.
        if(global_offline == 0):
            leerPreferencias()
        # HOSTS = getSwitchesAll(diskDB)
        HOSTS = funciones.get_SWITCHES_with_STRATS(diskDB)
        # We fetch the ARP Table from the router and update the switches' MAC addresses.
        if(global_offline == 0):
            ARPrefresh()
        if(len(HOSTS)==0):
            print("No hay switches en el sistema, verifique snmpQuery.ini")
            sys.exit(0)
        #
        # MULTIPROCESSING POOL for SNMP walks.
        if(global_offline == 0):    
            with Pool(processes=concurrentes) as pool:
                for result in pool.imap_unordered(fetch_oid_fast, HOSTS):
                    # result = [switchIP][time][ dataTable ][moreTimes][strategy]
                    # Update switches ONLINE/OFFLINE status.
                    updateSwitchStatus(result)
                    procesarMacAddresses(result)
                    if(result[4] is not None):
                        funciones.setStrategy(diskDB, result[4])
                    #
        # Now that we've got MACs and Ports for all switches, we can update switchPort
        # with ACCESS/TRUNK [ROOT] data.
        try:
            switchMapper()
        except Exception as e:
            loguear("Problema con switchMapper. Pongo haltFlag en 1.")
            loguear(str(e))
            loguear(traceback.format_exc())
            haltFlag = 1
            continue
        # HISTORICOS! not in use right now. Can be commented out.
        persitirHistoricos(diskDB)
        #
        fin = time.time()
        global_stats_switches = funciones.countSwitchesOnline(diskDB)
        tiempoCiclo = (fin-inicio)
        if(global_stats_switches>0):
            global_stats_perf = tiempoCiclo / global_stats_switches
        else:
            global_stats_perf = 0
        retencionDias = 30
        floatStampCorte = fin - (retencionDias*24*3600)
        diskDB.execute("""
            INSERT INTO statistics (stamp, threads, secondsPerSwitch) VALUES (?,?,?)
            """, (str(time.time()),str(concurrentes),str(global_stats_perf)))
        diskDB.execute("""
            DELETE FROM statistics
            WHERE CAST(stamp AS REAL) < ?
        """, (floatStampCorte,))
        #
        # PERFORMANCE AUTO-TUNNER: How many concurrent threads should we go for?
        #
        if(tiempoAnterior != 0):
            # if != 0, we've got a full cycle data.
            # si tiempoAnterior no es 0, es porque ya tengo un dato de un ciclo anterior.
            if( tiempoCiclo < tiempoAnterior ):
                # If times got BETTER...
                if(lastEffect == "MAS"):
                    # If it got BETTER by incrementing, we keep doing the same.
                    concurrentes = concurrentes + 1
                if(lastEffect == "MENOS"):
                    # If it got BETTER by decrementing, we keep doing the same.
                    concurrentes = concurrentes - 1
            else:
                # If times got WORSE, we change direction.
                if(lastEffect == "MAS"):
                    # If what made it WORSE was Incrementing, we Decrement:
                    concurrentes = concurrentes - 1
                    lastEffect = "MENOS"
                elif(lastEffect == "MENOS"):
                    # If what made it WORSE was Decrementing, we Increment:
                    concurrentes = concurrentes + 1
                    lastEffect = "MAS"
        else:
            # This is the first cycle.
            concurrentes = concurrentes + 1
            lastEffect = "MAS"
        # Safety limits (no less than 1 thread, no more than 100).
        if(concurrentes < 1):
            concurrentes = 1
        if(concurrentes > 100):
            concurrentes = 100
        tiempoAnterior = tiempoCiclo
        estadisticas = "tiempoBruto: "+str(fin-inicio)
        # - - - - - - - - - - - - - - - - - -
        # - - - - - - - - - - - - - - - - - - 
        if(elTTL == 0):
            # There is no run time limit. Always ON.
            startingTime = time.time()
        ### Operation check: Is the service still ENABLED? ###
        if not os.path.exists(archivoOperacion):
            systemEnabled = 0
            print("snmpPyServer was DISABLED. ")
            print("File ["+archivoOperacion+"] no longer present. exiting... ")
            haltFlag = 1
            loguear("snmpPyServer was DISABLED. ")
            loguear("File ["+archivoOperacion+"] no longer present. exiting... ")
        # loguear(estadisticas)
    
###################################################################################################
### 4. CLEAN EXIT ###
# Final task. Script finished gracefully so it must proceed to remove the "lock" file.

stop_event.set()
process_hostnames.join()
time.sleep(0.5)
try:
    os.remove(archivoControl)
except Exception:
    pass
print("END.")
loguear("END.")
# DEBUG. printing the debug stack:
for cosita in elStack:
    print(cosita)
sys.exit(0)
###################################################################################################
