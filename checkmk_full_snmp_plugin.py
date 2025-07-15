#!/usr/bin/env python3

import sys
import subprocess
import re

def snmpwalk(oid, community, host):
    """Führt snmpwalk aus und gibt das Ergebnis als String zurück."""
    try:
        result = subprocess.check_output(
            ['snmpwalk', '-v', '1', '-c', community, host, oid],
            stderr=subprocess.STDOUT
        )
        return result.decode('utf-8')
    except subprocess.CalledProcessError as e:
        print(f"Fehler bei snmpwalk: {e.output.decode('utf-8')}", file=sys.stderr)
        sys.exit(2)

# System Information
def get_sysdescr(community, host):
    """Gibt die sysDescr des Systems zurück."""
    oid = '.1.3.6.1.2.1.1.1.0'
    output = snmpwalk(oid, community, host)
    match = re.search(r'system.sysDescr.0 = "(.*?)"', output)
    return match.group(1) if match else "Unbekannt"

def get_syscontact(community, host):
    """Gibt den SysContact des Systems zurück."""
    oid = '.1.3.6.1.2.1.1.4.0'
    output = snmpwalk(oid, community, host)
    match = re.search(r'system.sysContact.0 = "(.*?)"', output)
    return match.group(1) if match else "Unbekannt"

def get_syslocation(community, host):
    """Gibt den SysLocation des Systems zurück."""
    oid = '.1.3.6.1.2.1.1.6.0'
    output = snmpwalk(oid, community, host)
    match = re.search(r'system.sysLocation.0 = "(.*?)"', output)
    return match.group(1) if match else "Unbekannt"

# Load average
def get_load(community, host):
    """Gibt die Load-1, Load-5 und Load-15 Werte zurück."""
    oid = '.1.3.6.1.4.1.2021.10'
    output = snmpwalk(oid, community, host)
    loads = {}
    for i in range(1, 4):
        match = re.search(rf'loadaveNames\.\d+ = "(Load-{i})"\s+loadaveLoad\.\d+ = "([\d\.]+)"', output)
        if match:
            loads[match.group(1)] = float(match.group(2))
    return loads

# Disk Usage
def get_disk_usage(community, host):
    """Gibt die Festplattennutzung zurück."""
    oid = '.1.3.6.1.4.1.2021.9'
    output = snmpwalk(oid, community, host)
    disks = []
    for match in re.finditer(r'diskPath\.\d+ = "(.*?)".*?diskAvail\.\d+ = (\d+)', output, re.DOTALL):
        path, avail = match.groups()
        disks.append((path, int(avail)))
    return disks

# Process Count
def get_process_count(community, host):
    """Gibt die Anzahl der laufenden Prozesse zurück."""
    oid = '.1.3.6.1.4.1.2021.2'  # OID für Prozess-Tabelle
    output = snmpwalk(oid, community, host)
    processes = []
    for match in re.finditer(r'prNames\.\d+ = "(.*?)"', output):
        processes.append(match.group(1))
    return processes

# Executable Output (Shell Script or Custom Output)
def get_exec_output(community, host):
    """Führt benutzerdefinierte Shell-Skripte aus und gibt die Ausgabe zurück."""
    oid = '.1.3.6.1.4.1.2021.50'  # OID für benutzerdefinierte Ausgaben
    output = snmpwalk(oid, community, host)
    execs = {}
    for match in re.finditer(r'extNames\.\d+ = "(.*?)"\s+extOutput\.\d+ = "(.*?)"', output, re.DOTALL):
        execs[match.group(1)] = match.group(2)
    return execs

# Network Configuration (Interfaces)
def get_network_interfaces(community, host):
    """Gibt die Netzwerkschnittstellen des Systems zurück."""
    oid = '.1.3.6.1.2.1.2.2.1.2'  # OID für Interfaces
    output = snmpwalk(oid, community, host)
    interfaces = []
    for match in re.finditer(r'ifDescr\.\d+ = "(.*?)"', output):
        interfaces.append(match.group(1))
    return interfaces

# Routing Table
def get_ip_routes(community, host):
    """Gibt die IP-Route-Tabelle des Systems zurück."""
    oid = '.1.3.6.1.2.1.4.21.1.1'  # OID für IP-Route
    output = snmpwalk(oid, community, host)
    routes = []
    for match in re.finditer(r'ipRouteDest\.\d+ = "(.*?)"', output):
        routes.append(match.group(1))
    return routes

# Check Load Average
def check_load(loads):
    """Überprüft die Load-Werte und gibt den Status zurück."""
    max_load = 12.0
    for load in loads.values():
        if load > max_load:
            return 2, f"CRITICAL - Load zu hoch: {load} > {max_load}"
    return 0, f"OK - Load-Werte: {loads}"

# Check Disk Usage
def check_disk_usage(disks):
    """Überprüft die Festplattennutzung und gibt den Status zurück."""
    min_disk_space = 10000  # Beispiel: 10MB
    for path, avail in disks:
        if avail < min_disk_space:
            return 2, f"CRITICAL - Wenig Speicher auf {path}: {avail} Bytes"
    return 0, "OK - Alle Festplatten haben genügend Speicher"

# Check Process Count
def check_process_count(processes):
    """Überprüft die Anzahl der laufenden Prozesse."""
    required_processes = ['mountd', 'ntalkd', 'sendmail']
    missing_processes = [proc for proc in required_processes if proc not in processes]
    if missing_processes:
        return 2, f"CRITICAL - Fehlende Prozesse: {', '.join(missing_processes)}"
    return 0, f"OK - Alle benötigten Prozesse sind aktiv"

# Check Executables (Custom Shell Scripts)
def check_execs(exec_outputs):
    """Überprüft die Ausgaben von benutzerdefinierten Shell-Skripten."""
    for name, output in exec_outputs.items():
        if "error" in output.lower():  # Beispielhafte Fehlererkennung in Ausgaben
            return 2, f"CRITICAL - Fehler bei {name}: {output}"
    return 0, "OK - Alle benutzerdefinierten Ausgaben sind erfolgreich"

# Main Function
def main():
    community = 'public'  # Community-String aus der snmpd.conf
    host = 'localhost'    # SNMP-Agent-Adresse (z.B. localhost)

    # Abfragen der Systembeschreibung (sysDescr)
    sysdescr = get_sysdescr(community, host)

    # Abfragen der Systemkontaktinformationen (sysContact)
    syscontact = get_syscontact(community, host)

    # Abfragen der Systemstandorte (sysLocation)
    syslocation = get_syslocation(community, host)

    # Abfragen der Systemlast (Load)
    loads = get_load(community, host)
    status, load_message = check_load(loads)

    # Abfragen der Festplattennutzung
    disks = get_disk_usage(community, host)
    disk_status, disk_message = check_disk_usage(disks)

    # Abfragen der laufenden Prozesse
    processes = get_process_count(community, host)
    process_status, process_message = check_process_count(processes)

    # Abfragen der benutzerdefinierten Skripte
    exec_outputs = get_exec_output(community, host)
    exec_status, exec_message = check_execs(exec_outputs)

    # Abfragen der Netzwerkschnittstellen
    interfaces = get_network_interfaces(community, host)

    # Abfragen der IP-Routen
    ip_routes = get_ip_routes(community, host)

    # Kombinierte Nachrichten und Status
    max_status = max(status, disk_status, process_status, exec_status)

    if max_status == 2:
        print(f"2 {load_message} | {disk_message} | {process_message} | {exec_message}")
        sys.exit(2)
    elif max_status == 1:
        print(f"1 {load_message} | {disk_message} | {process_message} | {exec_message}")
        sys.exit(1)
    else:
        print(f"0 {load_message} | {disk_message} | {process_message} | {exec_message}")
        sys.exit(0)

if __name__ == '__main__':
    main()
