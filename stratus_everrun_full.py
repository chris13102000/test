#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
#
# Checkmk plugin: stratus_everrun_full
# Monitors everRun system: Storage, vCPUs, Memory, VMs, Nodes, Alerts, Volumes
#

from .agent_based_api.v1 import *

# --- Helper parsing ---
def parse_int(val):
    try:
        return int(val)
    except:
        return None

# --- SNMP Sections ---
register.snmp_section(
    name="everrun_full",
    detect=startswith(".1.3.6.1.4.1.458.115"),
    fetch=[
        ".1.3.6.1.4.1.458.115.1.1",  # memory_available
        ".1.3.6.1.4.1.458.115.1.2",  # vcpus_total
        ".1.3.6.1.4.1.458.115.1.3",  # vcpus_used
        ".1.3.6.1.4.1.458.115.1.5",  # storage_total
        ".1.3.6.1.4.1.458.115.1.6",  # storage_used
        ".1.3.6.1.4.1.458.115.1.17.1.3",  # VM DisplayName
        ".1.3.6.1.4.1.458.115.1.17.1.6",  # VM StateNum
        ".1.3.6.1.4.1.458.115.1.19.1.3",  # Node DisplayName
        ".1.3.6.1.4.1.458.115.1.19.1.5",  # Node StateNum
        ".1.3.6.1.4.1.458.115.1.10.1.2",  # Alert Severity
        ".1.3.6.1.4.1.458.115.1.18.1.3",  # Volume DisplayName
        ".1.3.6.1.4.1.458.115.1.18.1.4",  # Volume SyncPercentage
    ],
)

# --- Discovery ---
def discover_everrun_full(section):
    yield Service(item="Storage")
    yield Service(item="Memory")
    yield Service(item="vCPUs")
    for k in section:
        if k.startswith(".1.3.6.1.4.1.458.115.1.17.1.3."):  # VMs
            name = section[k]
            yield Service(item=f"VM: {name}")
        if k.startswith(".1.3.6.1.4.1.458.115.1.19.1.3."):  # Nodes
            name = section[k]
            yield Service(item=f"Node: {name}")
        if k.startswith(".1.3.6.1.4.1.458.115.1.18.1.3."):  # Volumes
            name = section[k]
            yield Service(item=f"Volume: {name}")
    yield Service(item="Alert Count")

# --- Check ---
def check_everrun_full(item, params, section):
    if item == "Storage":
        used = parse_int(section.get(".1.3.6.1.4.1.458.115.1.6"))
        total = parse_int(section.get(".1.3.6.1.4.1.458.115.1.5"))
        if not used or not total:
            yield Result(state=State.UNKNOWN, summary="Storage info missing")
        else:
            pct = used / total * 100
            yield Metric("storage_used_percent", pct)
            yield Result(state=State.OK, summary=f"{used}/{total} GB used ({pct:.1f}%)")

    elif item == "Memory":
        mem = parse_int(section.get(".1.3.6.1.4.1.458.115.1.1"))
        if mem is None:
            yield Result(state=State.UNKNOWN, summary="Memory info missing")
        else:
            yield Metric("memory_available_gb", mem)
            yield Result(state=State.OK, summary=f"{mem} GB available")

    elif item == "vCPUs":
        used = parse_int(section.get(".1.3.6.1.4.1.458.115.1.3"))
        total = parse_int(section.get(".1.3.6.1.4.1.458.115.1.2"))
        if not used or not total:
            yield Result(state=State.UNKNOWN, summary="vCPU info missing")
        else:
            pct = used / total * 100
            yield Metric("vcpu_used_percent", pct)
            yield Result(state=State.OK, summary=f"{used}/{total} vCPUs used ({pct:.1f}%)")

    elif item == "Alert Count":
        alerts = [k for k in section if k.startswith(".1.3.6.1.4.1.458.115.1.10.1.2.")]
        yield Metric("alert_count", len(alerts))
        yield Result(state=State.OK, summary=f"{len(alerts)} alerts present")

    elif item.startswith("VM: "):
        name = item[4:]
        for k, v in section.items():
            if v == name and k.startswith(".1.3.6.1.4.1.458.115.1.17.1.3."):
                idx = k.split(".")[-1]
                state = section.get(f".1.3.6.1.4.1.458.115.1.17.1.6.{idx}")
                state_str = f"StateNum={state}" if state else "Unknown"
                yield Result(state=State.OK, summary=f"VM '{name}' state: {state_str}")
                break

    elif item.startswith("Node: "):
        name = item[6:]
        for k, v in section.items():
            if v == name and k.startswith(".1.3.6.1.4.1.458.115.1.19.1.3."):
                idx = k.split(".")[-1]
                state = section.get(f".1.3.6.1.4.1.458.115.1.19.1.5.{idx}")
                state_str = f"StateNum={state}" if state else "Unknown"
                yield Result(state=State.OK, summary=f"Node '{name}' state: {state_str}")
                break

    elif item.startswith("Volume: "):
        name = item[8:]
        for k, v in section.items():
            if v == name and k.startswith(".1.3.6.1.4.1.458.115.1.18.1.3."):
                idx = k.split(".")[-1]
                sync = section.get(f".1.3.6.1.4.1.458.115.1.18.1.4.{idx}")
                sync_str = f"{sync}%" if sync else "Unknown"
                yield Result(state=State.OK, summary=f"Volume '{name}' sync: {sync_str}")
                break

register.check_plugin(
    name="everrun_full",
    service_name="everRun %s",
    sections=["everrun_full"],
    check_function=check_everrun_full,
    discovery_function=discover_everrun_full,
)
