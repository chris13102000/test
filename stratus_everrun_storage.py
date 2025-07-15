#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
#
# Checkmk plugin: stratus_everrun_storage
# Monitors everRun storage usage via SNMP
#

from .agent_based_api.v1 import *

def parse_everrun_storage(section):
    used_oid = ".1.3.6.1.4.1.458.115.1.6"
    total_oid = ".1.3.6.1.4.1.458.115.1.5"
    try:
        used = int(section.get(used_oid))
        total = int(section.get(total_oid))
    except Exception:
        return None
    return {"used": used, "total": total}

def discover_everrun_storage(section):
    if parse_everrun_storage(section):
        yield Service()

def check_everrun_storage(params, section):
    data = parse_everrun_storage(section)
    if not data:
        yield Result(state=State.UNKNOWN, summary="Could not read storage values")
        return

    used = data["used"]
    total = data["total"]

    if total == 0:
        yield Result(state=State.UNKNOWN, summary="Total storage reported as 0 GB")
        return

    usage_pct = used / total * 100
    warn = params.get("warning", 80)
    crit = params.get("critical", 90)

    state = State.OK
    if usage_pct >= crit:
        state = State.CRIT
    elif usage_pct >= warn:
        state = State.WARN

    yield Result(
        state=state,
        summary=f"Used {used} GB of {total} GB ({usage_pct:.1f}%)"
    )
    yield Metric("storage_used_percent", usage_pct, boundaries=(warn, crit))

register.snmp_section(
    name="everrun_storage",
    detect=startswith(".1.3.6.1.4.1.458.115"),  # optional: refine with sysDescr match if needed
    fetch=[
        ".1.3.6.1.4.1.458.115.1.5",  # everRunStorageTotal
        ".1.3.6.1.4.1.458.115.1.6",  # everRunStorageUsed
    ],
)

register.check_plugin(
    name="everrun_storage",
    service_name="everRun Storage Usage",
    sections=["everrun_storage"],
    check_function=check_everrun_storage,
    discovery_function=discover_everrun_storage,
    default_parameters={"warning": 80, "critical": 90},
    check_ruleset_name="storage.usage",
)
