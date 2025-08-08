
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Centreon plugin: check_alcatel_stellar.py

Compatible avec les bornes OmniAccess Stellar AP1301 et AP1321 (et autres modèles similaires)
via auto-détection de sysObjectID -> sous-arbre MIB spécifique du modèle.

Mesures prises en charge :
- Uptime
- Nombre de clients (graphiques)
- Statistiques radios par radio (bande, canal, utilisation, tx/rx bytes) (graphiques)
- Ports Ethernet (statut et débit) via IF-MIB (graphiques)
- CPU / Mémoire (seuils)

Modifs par rapport au script 1321 fourni :
- Auto-détection de l'OID base (apInfo) depuis sysObjectID (SNMPv2-MIB::sysObjectID.0)
- Correctifs dans check_radios (suppression du bloc dupliqué + calcul débit toujours exécuté)
- OID apRadioIndex corrigé (colonne 1 au lieu de 2; on garde un fallback robuste)
- Paramètre --force-model pour forcer 1301/1321 si besoin

Dépendance : pysnmp
"""
import argparse
import json
import os
import sys
import time

try:
    from pysnmp.hlapi import (
        SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity, UsmUserData,
        usmNoAuthProtocol, usmNoPrivProtocol,
        usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
        usmHMAC128SHA224AuthProtocol, usmHMAC192SHA256AuthProtocol,
        usmHMAC256SHA384AuthProtocol, usmHMAC384SHA512AuthProtocol,
        usmDESPrivProtocol, usmAesCfb128Protocol, usmAesCfb192Protocol, usmAesCfb256Protocol,
        getCmd, nextCmd
    )
    from pysnmp.proto.rfc1902 import TimeTicks
except Exception as e:
    print(f"UNKNOWN: pysnmp not available ({e})")
    sys.exit(3)

DEBUG = False

def dprint(*a, **k):
    if DEBUG:
        try:
            print("[DEBUG]", *a, **k, file=sys.stderr)
        except Exception:
            pass

# --- globals initialisés dynamiquement ---
AP_INFO = None
AP_BASE = None
AP_RADIO_ENTRY = None
AP_CLIENT_ENTRY = None

OID_SYSNAME = None
OID_AP_IP = None
OID_GROUP = None
OID_MODEL = None
OID_SERIAL = None
OID_MEM_UTIL = None
OID_CPU_UTIL = None
OID_AP_UPTIME = None

OID_RADIO_INDEX = None
OID_RADIO_BAND = None
OID_RADIO_CHANNEL = None
OID_RADIO_TXPOWER = None
OID_RADIO_UTIL = None
OID_RADIO_TXBYTES = None
OID_RADIO_RXBYTES = None

OID_CLIENT_MAC = None

# IF-MIB
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"

OID_SYSOBJECTID = "1.3.6.1.2.1.1.2.0"  # SNMPv2-MIB::sysObjectID.0

STATE_DIR = "/tmp/check_alcatel_stellar"
os.makedirs(STATE_DIR, exist_ok=True)

AUTH_PROTO_MAP = {
    "NONE": usmNoAuthProtocol,
    "MD5": usmHMACMD5AuthProtocol,
    "SHA": usmHMACSHAAuthProtocol,
    "SHA224": usmHMAC128SHA224AuthProtocol,
    "SHA256": usmHMAC192SHA256AuthProtocol,
    "SHA384": usmHMAC256SHA384AuthProtocol,
    "SHA512": usmHMAC384SHA512AuthProtocol,
}

PRIV_PROTO_MAP = {
    "NONE": usmNoPrivProtocol,
    "DES": usmDESPrivProtocol,
    "AES": usmAesCfb128Protocol,
    "AES128": usmAesCfb128Protocol,
    "AES192": usmAesCfb192Protocol,
    "AES256": usmAesCfb256Protocol,
}

def _is_empty(v):
    if v is None:
        return True
    s = str(v).strip().strip("b'").strip('"').strip()
    return s == ""

def _to_int_any(v, default=None):
    if _is_empty(v):
        return default
    try:
        return int(v)
    except Exception:
        s = str(v)
        digits = "".join(ch for ch in s if ch.isdigit() or (ch == '-' and s.strip().startswith('-')))
        if digits in ("", "-"):
            return default
        try:
            return int(digits)
        except Exception:
            return default

def _to_float_any(v, default=None):
    if _is_empty(v):
        return default
    try:
        return float(v)
    except Exception:
        s = str(v)
        cleaned = "".join(ch for ch in s if (ch.isdigit() or ch in ".-"))
        if cleaned in ("", "-", ".", "-."):
            return default
        try:
            return float(cleaned)
        except Exception:
            return default

def _band_label(v):
    # Accepte entiers ou chaînes "2.4G"/"5G"/"6G"
    try:
        iv = int(v)
        return {1: "2.4G", 2: "5G", 3: "6G"}.get(iv, str(iv))
    except Exception:
        s = str(v).upper()
        if "6" in s:
            return "6G"
        if "5" in s:
            return "5G"
        if "2.4" in s or "24" in s or "2" in s:
            return "2.4G"
        return s

def build_auth(args):
    if args.version == '2c':
        if not args.community:
            print("UNKNOWN: SNMP v2c requires --community")
            sys.exit(3)
        return CommunityData(args.community, mpModel=1)  # v2c
    # v3
    auth_proto = AUTH_PROTO_MAP.get(args.auth_proto.upper(), usmHMACSHAAuthProtocol)
    priv_proto = PRIV_PROTO_MAP.get(args.priv_proto.upper(), usmNoPrivProtocol)
    if args.sec_level.lower() == "noauthnopriv":
        user = UsmUserData(args.username)
    elif args.sec_level.lower() == "authnopriv":
        if not args.auth_pass:
            print("UNKNOWN: --auth-pass required for authNoPriv")
            sys.exit(3)
        user = UsmUserData(args.username, authKey=args.auth_pass, authProtocol=auth_proto)
    else:  # authPriv
        if not args.auth_pass or not args.priv_pass:
            print("UNKNOWN: --auth-pass and --priv-pass required for authPriv")
            sys.exit(3)
        user = UsmUserData(args.username, authKey=args.auth_pass, authProtocol=auth_proto,
                           privKey=args.priv_pass, privProtocol=priv_proto)
    return user

def snmp_get(engine, auth, target, oid):
    dprint("GET", oid)
    errorIndication, errorStatus, errorIndex, varBinds = next(getCmd(
        engine, auth, target, ContextData(), ObjectType(ObjectIdentity(oid))
    ))
    if errorIndication or errorStatus:
        raise RuntimeError(f"SNMP GET failed: {errorIndication or errorStatus.prettyPrint()}")
    dprint("GET-RESULT", [(str(n), repr(v)) for n,v in varBinds])
    return varBinds[0][1]

def snmp_get_safe(engine, auth, target, oid):
    try:
        return snmp_get(engine, auth, target, oid)
    except Exception as e:
        dprint("GET-ERROR", oid, e)
        return None

def snmp_walk(engine, auth, target, oid_prefix, guard_seconds=None):
    dprint("WALK", oid_prefix)
    t0 = time.time()
    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        engine, auth, target, ContextData(), ObjectType(ObjectIdentity(oid_prefix)),
        lexicographicMode=False
    ):
        if guard_seconds is not None and (time.time() - t0) > guard_seconds:
            raise RuntimeError(f"SNMP WALK guard timeout after {guard_seconds}s on {oid_prefix}")
        if errorIndication:
            raise RuntimeError(f"SNMP WALK failed: {errorIndication}")
        if errorStatus:
            raise RuntimeError(f"SNMP WALK failed: {errorStatus.prettyPrint()}")
        for name, val in varBinds:
            dprint("WALK-ROW", str(name), repr(val))
            yield str(name), val

def load_state(host, suffix):
    fn = os.path.join(STATE_DIR, f"{host}_{suffix}.json")
    if os.path.exists(fn):
        try:
            import json
            return json.load(open(fn))
        except Exception:
            return {}
    return {}

def save_state(host, suffix, data):
    fn = os.path.join(STATE_DIR, f"{host}_{suffix}.json")
    import json
    json.dump(data, open(fn, "w"))

def fmt_perf(name, value, unit="", warn="", crit="", minv="", maxv=""):
    metric = name.replace(" ", "_")
    return f"{metric}={value}{unit};{warn};{crit};{minv};{maxv}"

def human_seconds(sec):
    sec = int(max(0, sec))
    days, rem = divmod(sec, 86400)
    hours, rem = divmod(rem, 3600)
    mins, s = divmod(rem, 60)
    out = []
    if days: out.append(f"{days}d")
    if hours: out.append(f"{hours}h")
    if mins: out.append(f"{mins}m")
    out.append(f"{s}s")
    return " ".join(out)

def set_base_from_apinfo(ap_info_oid):
    """Configure toutes les OIDs dérivées à partir de apInfo OID."""
    global AP_INFO, AP_BASE, AP_RADIO_ENTRY, AP_CLIENT_ENTRY
    global OID_SYSNAME, OID_AP_IP, OID_GROUP, OID_MODEL, OID_SERIAL, OID_MEM_UTIL, OID_CPU_UTIL, OID_AP_UPTIME
    global OID_RADIO_INDEX, OID_RADIO_BAND, OID_RADIO_CHANNEL, OID_RADIO_TXPOWER, OID_RADIO_UTIL, OID_RADIO_TXBYTES, OID_RADIO_RXBYTES
    global OID_CLIENT_MAC

    AP_INFO = ap_info_oid.strip('.')
    AP_BASE = AP_INFO + ".1"                # apBaseInfo
    AP_RADIO_ENTRY = AP_INFO + ".2.1.1"     # ApRadioInfoEntry
    AP_CLIENT_ENTRY = AP_INFO + ".4.1.1"    # ApClientInfoEntry

    OID_SYSNAME = f"{AP_BASE}.2.0"
    OID_AP_IP = f"{AP_BASE}.3.0"
    OID_GROUP = f"{AP_BASE}.4.0"
    OID_MODEL = f"{AP_BASE}.5.0"
    OID_SERIAL = f"{AP_BASE}.6.0"
    OID_MEM_UTIL = f"{AP_BASE}.7.0"
    OID_CPU_UTIL = f"{AP_BASE}.8.0"
    OID_AP_UPTIME = f"{AP_BASE}.9.0"

    # Colonnes de la radio (index = apRadioIndex)
    OID_RADIO_INDEX = AP_RADIO_ENTRY + ".1"      # apRadioIndex
    OID_RADIO_BAND = AP_RADIO_ENTRY + ".3"
    OID_RADIO_CHANNEL = AP_RADIO_ENTRY + ".4"
    OID_RADIO_TXPOWER = AP_RADIO_ENTRY + ".5"
    OID_RADIO_UTIL = AP_RADIO_ENTRY + ".6"
    OID_RADIO_TXBYTES = AP_RADIO_ENTRY + ".10"
    OID_RADIO_RXBYTES = AP_RADIO_ENTRY + ".15"

    # Clients (on compte les lignes)
    OID_CLIENT_MAC = AP_CLIENT_ENTRY + ".2"

def detect_apinfo(engine, auth, target, force_model=None):
    """
    Retourne l'OID 'apInfo' pour le modèle.
    - Si force_model == '1301' => 1.3.6.1.4.1.6486.802.1.1.2.1.2.19.1
    - Si force_model == '1321' => 1.3.6.1.4.1.6486.802.1.1.2.1.2.12.1
    - Sinon: lit sysObjectID.0 et ajoute ".1"
    """
    if force_model:
        fm = str(force_model).strip()
        if fm == "1301":
            return "1.3.6.1.4.1.6486.802.1.1.2.1.2.19.1"
        if fm == "1321":
            return "1.3.6.1.4.1.6486.802.1.1.2.1.2.12.1"

    val = snmp_get(engine, auth, target, OID_SYSOBJECTID)
    sys_obj = str(val)  # ex: 1.3.6.1.4.1.6486.802.1.1.2.1.2.19
    # apInfo = deviceOID + .1
    return sys_obj.strip('.') + ".1"

def check_uptime(engine, auth, target, host):
    try:
        val = snmp_get(engine, auth, target, OID_AP_UPTIME)
        # Integer32 ou TimeTicks suivant firmware
        if isinstance(val, TimeTicks):
            up_sec = int(int(val) / 100)  # hundredths of seconds
        else:
            up_int = _to_int_any(val, default=None)
            if up_int is None:
                raise RuntimeError("empty or non-numeric uptime value")
            up_sec = up_int
    except Exception as e:
        print(f"UNKNOWN: cannot read uptime ({e})")
        sys.exit(3)
    print(f"OK: Uptime {human_seconds(up_sec)} | {fmt_perf('uptime', up_sec, 's')}")
    sys.exit(0)

def check_clients(engine, auth, target, host):
    try:
        count = sum(1 for _ in snmp_walk(engine, auth, target, OID_CLIENT_MAC))
    except Exception as e:
        print(f"UNKNOWN: cannot read client table ({e})")
        sys.exit(3)
    print(f"OK: {count} clients connected | {fmt_perf('clients', count)}")
    sys.exit(0)

def check_radios(engine, auth, target, host, guard_seconds=15, bands_set=None):
    if bands_set is None:
        bands_set = {"2.4G", "5G"}

    # 1) Découverte des index (rapide): apRadioIndex; fallback sur apRadioBand
    indices = []
    try:
        for oid, val in snmp_walk(engine, auth, target, OID_RADIO_INDEX, guard_seconds):
            idx = oid.split('.')[-1]
            indices.append(idx)
    except Exception as e:
        dprint("INDEX-WALK-FAILED, fallback to BAND walk:", e)
        try:
            for oid, val in snmp_walk(engine, auth, target, OID_RADIO_BAND, guard_seconds):
                idx = oid.split('.')[-1]
                if idx not in indices:
                    indices.append(idx)
        except Exception as e2:
            print(f"UNKNOWN: cannot read radio indices ({e2})")
            sys.exit(3)

    indices = sorted(indices, key=lambda x: int(x))

    # 2) GET colonne par colonne pour éviter les blocages agent
    radios = {}
    for idx in indices:
        base = f"{AP_RADIO_ENTRY}"
        def coid(suffix): return f"{base}.{suffix}.{idx}"
        band = snmp_get_safe(engine, auth, target, coid('3'))
        channel = snmp_get_safe(engine, auth, target, coid('4'))
        txpower = snmp_get_safe(engine, auth, target, coid('5'))
        util = snmp_get_safe(engine, auth, target, coid('6'))
        txbytes = snmp_get_safe(engine, auth, target, coid('10'))
        rxbytes = snmp_get_safe(engine, auth, target, coid('15'))

        radios[idx] = {
            'band': _band_label(band) if band is not None else '?',
            'channel': _to_int_any(channel, 0) if channel is not None else 0,
            'txpower': _to_float_any(txpower, 0.0) if txpower is not None else 0.0,
            'util': _to_int_any(util, 0) if util is not None else 0,
            'txbytes': int(_to_int_any(txbytes, 0) or 0),
            'rxbytes': int(_to_int_any(rxbytes, 0) or 0),
        }

    # 3) Calcul des débits + sortie perf
    state = load_state(host, "radio")
    now = time.time()
    perfs = []
    summary = []
    for idx in indices:
        data = radios.get(idx, {})
        if data.get("band") not in bands_set:
            continue
        key = f"r{idx}"
        prev = state.get(key, {})
        dt = now - prev.get("t", now)
        txbps = rxbps = 0.0
        if dt > 0 and 'txbytes' in data and 'rxbytes' in data and 'txbytes' in prev and 'rxbytes' in prev:
            txbps = max(0, (data['txbytes'] - prev['txbytes']) * 8.0 / dt)
            rxbps = max(0, (data['rxbytes'] - prev['rxbytes']) * 8.0 / dt)
        state[key] = {'t': now, 'txbytes': data.get('txbytes', 0), 'rxbytes': data.get('rxbytes', 0)}
        summary.append(f"radio{idx} band={data.get('band','?')} ch={data.get('channel','?')} util={data.get('util','?')}%")
        perfs.extend([
            fmt_perf(f"radio{idx}_util", data.get('util', 0), "%"),
            fmt_perf(f"radio{idx}_tx_bps", f"{txbps:.0f}", "b"),
            fmt_perf(f"radio{idx}_rx_bps", f"{rxbps:.0f}", "b"),
        ])
    save_state(host, "radio", state)
    if not summary:
        print("WARNING: no radios found in requested bands")
        sys.exit(1)
    print(f"OK: " + "; ".join(summary) + " | " + " ".join(perfs))
    sys.exit(0)

def check_ports(engine, auth, target, host):
    descrs, oper, hs, in_oct, out_oct = {}, {}, {}, {}, {}
    try:
        for oid, val in snmp_walk(engine, auth, target, IF_DESCR):
            idx = oid.split('.')[-1]; descrs[idx] = str(val)
        for oid, val in snmp_walk(engine, auth, target, IF_OPER_STATUS):
            idx = oid.split('.')[-1]; oper[idx] = _to_int_any(val, 2)  # 1=up, 2=down
        for oid, val in snmp_walk(engine, auth, target, IF_HIGH_SPEED):
            idx = oid.split('.')[-1]; hs[idx] = _to_int_any(val, 0)
        for oid, val in snmp_walk(engine, auth, target, IF_HC_IN_OCTETS):
            idx = oid.split('.')[-1]; in_oct[idx] = _to_int_any(val, 0)
        for oid, val in snmp_walk(engine, auth, target, IF_HC_OUT_OCTETS):
            idx = oid.split('.')[-1]; out_oct[idx] = _to_int_any(val, 0)
    except Exception as e:
        print(f"UNKNOWN: cannot read IF-MIB ({e})")
        sys.exit(3)

    phys = [i for i, d in descrs.items() if any(k in d.lower() for k in ("eth", "ge", "gig", "2.5g", "1g", "lan", "ethernet"))]

    state = load_state(host, "ifmib")
    now = time.time()
    perfs = []
    summary_parts = []
    for idx in phys:
        name = descrs.get(idx, f"if{idx}")
        status = oper.get(idx, 2)
        speed_m = hs.get(idx, 0)
        prev = state.get(idx, {})
        dt = now - prev.get("t", now)
        in_bps = out_bps = 0.0
        if dt > 0 and idx in in_oct and idx in out_oct and 'in' in prev and 'out' in prev:
            in_bps = max(0, (in_oct[idx]-prev['in']) * 8.0 / dt)
            out_bps = max(0, (out_oct[idx]-prev['out']) * 8.0 / dt)
        state[idx] = {'t': now, 'in': in_oct.get(idx, 0), 'out': out_oct.get(idx, 0)}
        summary_parts.append(f"{name}:{'up' if status==1 else 'down'}@{speed_m}Mb")
        perfs.extend([
            fmt_perf(f"{name}_status", status),
            fmt_perf(f"{name}_speed_mbps", speed_m, "Mb"),
            fmt_perf(f"{name}_in_bps", f"{in_bps:.0f}", "b"),
            fmt_perf(f"{name}_out_bps", f"{out_bps:.0f}", "b"),
        ])
    save_state(host, "ifmib", state)
    if not phys:
        print("WARNING: no physical Ethernet interfaces detected (via ifDescr heuristic)")
        sys.exit(1)
    print("OK: " + ", ".join(summary_parts) + " | " + " ".join(perfs))
    sys.exit(0)

def check_health(engine, auth, target, host, warn=90, crit=95):
    try:
        cpu_raw = snmp_get(engine, auth, target, OID_CPU_UTIL)
        mem_raw = snmp_get(engine, auth, target, OID_MEM_UTIL)
        model = str(snmp_get(engine, auth, target, OID_MODEL))
        serial = str(snmp_get(engine, auth, target, OID_SERIAL))
    except Exception as e:
        print(f"UNKNOWN: cannot read base info ({e})")
        sys.exit(3)

    cpu = _to_int_any(cpu_raw, default=None)
    mem = _to_int_any(mem_raw, default=None)

    if cpu is None and mem is None:
        print("UNKNOWN: CPU/MEM values are empty or non-numeric")
        sys.exit(3)

    cpu = 0 if cpu is None else cpu
    mem = 0 if mem is None else mem

    status = 0
    if cpu >= crit or mem >= crit:
        status = 2
    elif cpu >= warn or mem >= warn:
        status = 1

    reasons = []
    if cpu >= warn: reasons.append(f"CPU {cpu}%")
    if mem >= warn: reasons.append(f"MEM {mem}%")
    msg = "OK" if status == 0 else ("WARNING" if status == 1 else "CRITICAL")
    perf = f"{fmt_perf('cpu', cpu, '%', warn, crit)} {fmt_perf('mem', mem, '%', warn, crit)}"
    reason_text = (" - " + ", ".join(reasons)) if reasons else ""
    print(f"{msg}: {model} SN:{serial}{reason_text} | {perf}")
    sys.exit(status)

def main():
    parser = argparse.ArgumentParser(description="Centreon plugin for Alcatel OAW-AP1301/1321 (SNMP)")
    parser.add_argument("--host", required=True, help="AP IP address or hostname")
    parser.add_argument("--version", choices=["2c", "3"], required=True, help="SNMP version")
    parser.add_argument("--community", default="public", help="SNMP community for v2c")
    parser.add_argument("--username", default="", help="SNMPv3 username")
    parser.add_argument("--auth-proto", default="SHA", help="SNMPv3 auth protocol (NONE, MD5, SHA, SHA224, SHA256, SHA384, SHA512)")
    parser.add_argument("--auth-pass", default="", help="SNMPv3 auth password")
    parser.add_argument("--priv-proto", default="NONE", help="SNMPv3 priv protocol (NONE, DES, AES, AES128, AES192, AES256)")
    parser.add_argument("--priv-pass", default="", help="SNMPv3 priv password")
    parser.add_argument("--sec-level", default="authPriv", choices=["noAuthNoPriv","authNoPriv","authPriv"], help="SNMPv3 security level")
    parser.add_argument("--timeout", type=int, default=20, help="SNMP timeout in seconds")
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--warn", type=int, default=90, help="Warning threshold for CPU/MEM (percent)")
    parser.add_argument("--crit", type=int, default=95, help="Critical threshold for CPU/MEM (percent)")
    parser.add_argument("--mode", required=True, choices=["uptime","clients","radios","ports","health"], help="Check mode")
    parser.add_argument("--bands", default="2.4G,5G", help="Comma-separated bands to include (e.g., 2.4G,5G,6G)")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug output to stderr")
    parser.add_argument("--radio-walk-guard", type=int, default=15, help="Abort radio walk after N seconds (to avoid agent stalls)")
    parser.add_argument("--force-model", choices=["1301","1321"], help="Force AP model if autodetection fails")
    args = parser.parse_args()

    target = UdpTransportTarget((args.host, 161), timeout=args.timeout, retries=args.retries)
    auth = build_auth(args)
    engine = SnmpEngine()

    host_tag = args.host.replace(":", "_")

    global DEBUG
    DEBUG = bool(args.debug)

    # Détection du sous-arbre MIB du modèle
    try:
        ap_info = detect_apinfo(engine, auth, target, force_model=args.force_model)
        set_base_from_apinfo(ap_info)
        # Sanity check : lire le modèle
        _ = snmp_get(engine, auth, target, OID_MODEL)
        dprint("AP_INFO=", AP_INFO)
    except Exception as e:
        print(f"UNKNOWN: cannot initialize AP MIB base ({e})")
        sys.exit(3)

    # Normalisation des bandes
    bands = set(b.strip().upper().replace(" ", "") for b in str(args.bands).split(",") if b.strip())
    norm = set()
    for b in bands:
        if b in {"2.4G", "2G", "2.4"}:
            norm.add("2.4G")
        elif b in {"5G", "5"}:
            norm.add("5G")
        elif b in {"6G", "6"}:
            norm.add("6G")
    if not norm:
        norm = {"2.4G", "5G"}

    if args.mode == "uptime":
        check_uptime(engine, auth, target, host_tag)
    elif args.mode == "clients":
        check_clients(engine, auth, target, host_tag)
    elif args.mode == "radios":
        check_radios(engine, auth, target, host_tag, args.radio_walk_guard, norm)
    elif args.mode == "ports":
        check_ports(engine, auth, target, host_tag)
    elif args.mode == "health":
        check_health(engine, auth, target, host_tag, args.warn, args.crit)

if __name__ == "__main__":
    main()
