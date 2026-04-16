#!/usr/bin/env python3
"""
udp_amp_monitor.py — UDP Amplification Attack Surface Monitor
Detecta serviços UDP vulneráveis a ataques de amplificação DDoS.
Author: Renzi

Usa SOCK_RAW IPPROTO_UDP (Layer 3) — funciona em qualquer ambiente
com root, sem libpcap, sem dependências externas além de Python 3.6+.

Uso:
    sudo python3 udp_amp_monitor.py targets.txt
    sudo python3 udp_amp_monitor.py targets.txt --ports 53,123,161
    sudo python3 udp_amp_monitor.py targets.txt --workers 200 --timeout 2.0
    sudo python3 udp_amp_monitor.py targets.txt --output-dir ./results
"""

import argparse
import csv
import ipaddress
import json
import logging
import os
import select
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# SERVIÇOS DE AMPLIFICAÇÃO E SUAS PORTAS
# ─────────────────────────────────────────────────────────────────────────────

AMP_SERVICES: dict[int, dict] = {
    19:    {"name": "Chargen",         "factor": "~358x"},
    53:    {"name": "DNS",             "factor": "~28-54x"},
    69:    {"name": "TFTP",            "factor": "~60x"},
    111:   {"name": "Portmap/RPCbind", "factor": "~7-28x"},
    123:   {"name": "NTP",             "factor": "~556x"},
    137:   {"name": "NetBIOS NS",      "factor": "~3.8x"},
    161:   {"name": "SNMP v1/v2",      "factor": "~650x"},
    389:   {"name": "CLDAP",           "factor": "~56-70x"},
    500:   {"name": "IKE/IPSec",       "factor": "variável"},
    520:   {"name": "RIP",             "factor": "~13x"},
    623:   {"name": "IPMI/RMCP",       "factor": "~9x"},
    1194:  {"name": "OpenVPN",         "factor": "variável"},
    1434:  {"name": "MSSQL",           "factor": "~250x"},
    1900:  {"name": "SSDP/UPnP",       "factor": "~30x"},
    3283:  {"name": "Apple ARD",       "factor": "~35x"},
    3702:  {"name": "WS-Discovery",    "factor": "~500x"},
    4500:  {"name": "IKEv2 NAT-T",     "factor": "variável"},
    5353:  {"name": "mDNS",            "factor": "~2-10x"},
    5683:  {"name": "CoAP",            "factor": "~34x"},
    6881:  {"name": "BitTorrent DHT",  "factor": "~4x"},
    11211: {"name": "Memcached",       "factor": "~50000x"},
    17185: {"name": "VXWORKS WDBRPC",  "factor": ">100x"},
    27015: {"name": "Steam",           "factor": "variável"},
    27960: {"name": "QuakeWorld",      "factor": "~63x"},
}

# ─────────────────────────────────────────────────────────────────────────────
# PROBES UDP POR SERVIÇO
# Pacotes mínimos que provocam resposta do serviço (confirmam porta aberta)
# ─────────────────────────────────────────────────────────────────────────────

PROBES: dict[int, bytes] = {
    # Chargen — qualquer byte provoca resposta
    19: b"\x00",

    # DNS — query TXT version.bind CH
    53: (
        b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07version\x04bind\x00\x00\x10\x00\x03"
    ),

    # TFTP — read request do arquivo "test"
    69: b"\x00\x01test\x00octet\x00",

    # Portmap/RPCbind — dump call
    111: bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x01, 0x86, 0xa0, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]),

    # NTP — client request modo 3
    123: b"\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00" + b"\x00" * 36,

    # NetBIOS Name Service — node status request
    137: (
        b"\xaa\xaa\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
        b"\x00\x21\x00\x01"
    ),

    # SNMP v1 — GetRequest sysDescr OID com community "public"
    161: bytes([
        0x30, 0x26, 0x02, 0x01, 0x00,
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
        0xa0, 0x19,
        0x02, 0x01, 0x01,
        0x02, 0x01, 0x00,
        0x02, 0x01, 0x00,
        0x30, 0x0e, 0x30, 0x0c,
        0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
        0x05, 0x00,
    ]),

    # CLDAP — RootDSE search sem autenticação
    389: bytes([
        0x30, 0x25, 0x02, 0x01, 0x01,
        0x63, 0x20, 0x04, 0x00,
        0xa0, 0x1b, 0xa3, 0x19,
        0x04, 0x17, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74,
        0x4e, 0x61, 0x6d, 0x69, 0x6e, 0x67, 0x43, 0x6f,
        0x6e, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00,
    ]),

    # IKE — main mode SA proposal
    500: bytes(
        [0x00] * 4
        + [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        + [0x01, 0x10, 0x02, 0x00]
        + [0x00] * 16
    ),

    # RIP v1 — request all
    520: bytes([0x01, 0x01, 0x00, 0x00] + [0x00] * 16),

    # IPMI/RMCP — Get Channel Authentication Capabilities
    623: bytes([
        0x06, 0x00, 0xff, 0x07,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
        0x20, 0x18, 0xc8, 0x81, 0x00, 0x38, 0x8e, 0x04, 0xb5,
    ]),

    # MSSQL — ping/discovery
    1434: b"\x02",

    # SSDP/UPnP — M-SEARCH
    1900: (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST:239.255.255.250:1900\r\n"
        b'MAN:"ssdp:discover"\r\n'
        b"MX:1\r\n"
        b"ST:ssdp:all\r\n\r\n"
    ),

    # WS-Discovery — Probe SOAP
    3702: (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
        b' xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
        b' xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        b"<soap:Body>"
        b'<wsd:Probe><wsd:Types/></wsd:Probe>'
        b"</soap:Body></soap:Envelope>"
    ),

    # mDNS — query _services._dns-sd._udp.local
    5353: bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x09, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,
        0x07, 0x5f, 0x64, 0x6e, 0x73, 0x2d, 0x73, 0x64,
        0x04, 0x5f, 0x75, 0x64, 0x70,
        0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
        0x00, 0x0c, 0x00, 0x01,
    ]),

    # CoAP — GET /.well-known/core
    5683: bytes([0x40, 0x01, 0x00, 0x01, 0xbb, 0x2e, 0x77, 0x65,
                 0x6c, 0x6c, 0x2d, 0x6b, 0x6e, 0x6f, 0x77, 0x6e,
                 0x04, 0x63, 0x6f, 0x72, 0x65]),

    # BitTorrent DHT — find_node
    6881: (
        b"d1:ad2:id20:"
        + b"\x00" * 20
        + b"6:target20:"
        + b"\x00" * 20
        + b"e1:q9:find_node1:t2:aa1:y1:qe"
    ),

    # Memcached — stats
    11211: b"stats\r\n",

    # VXWORKS WDBRPC — connection request
    17185: bytes([0x00] * 8),

    # Steam — Source Engine Query
    27015: b"\xff\xff\xff\xffTSource Engine Query\x00",

    # QuakeWorld — getinfo
    27960: b"\xff\xff\xff\xffgetstatus\x00",
}

DEFAULT_PROBE = b"\x00\x00\x00\x00"


# ─────────────────────────────────────────────────────────────────────────────
# CONSTRUÇÃO DE PACOTES RAW
# ─────────────────────────────────────────────────────────────────────────────

def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def build_udp_packet(
    src_ip: str, dst_ip: str,
    src_port: int, dst_port: int,
    payload: bytes,
) -> bytes:
    """Monta pacote IP+UDP completo com checksums corretos."""
    src_b = socket.inet_aton(src_ip)
    dst_b = socket.inet_aton(dst_ip)
    udp_len = 8 + len(payload)

    # UDP header (checksum = 0 para calcular)
    udp_h = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    pseudo = struct.pack("!4s4sBBH", src_b, dst_b, 0, 17, udp_len)
    udp_ck = _checksum(pseudo + udp_h + payload)
    udp_h  = struct.pack("!HHHH", src_port, dst_port, udp_len, udp_ck)

    # IP header
    ip_id  = (os.getpid() ^ dst_port ^ src_port) & 0xFFFF
    ip_h   = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | 5, 0, 20 + udp_len, ip_id,
        0, 64, 17, 0, src_b, dst_b,
    )
    ip_h = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | 5, 0, 20 + udp_len, ip_id,
        0, 64, 17, _checksum(ip_h), src_b, dst_b,
    )
    return ip_h + udp_h + payload


# ─────────────────────────────────────────────────────────────────────────────
# SCANNER UDP
# ─────────────────────────────────────────────────────────────────────────────

def get_local_ip() -> str:
    """Detecta o IP de saída da máquina local."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        # Fallback: lê /proc/net/route
        try:
            with open("/proc/net/route") as f:
                for line in f:
                    parts = line.split()
                    if parts[0] == "Iface":
                        continue
                    flags = int(parts[3], 16)
                    if (flags & 0x0002) and int(parts[1], 16) == 0:
                        # Lê IP da interface
                        iface = parts[0]
                        with open(f"/proc/net/if_inet6") as g:
                            pass  # IPv6, pula
        except Exception:
            pass
        return "0.0.0.0"


def scan_host(
    src_ip: str,
    dst_ip: str,
    ports: list[int],
    timeout: float = 1.5,
    retries: int = 2,
) -> list[int]:
    """
    Envia probes UDP para todos os ports de um host e retorna as portas abertas.
    Usa SOCK_RAW IPPROTO_UDP — sem libpcap, sem L2, funciona em VMs/containers.
    """
    open_ports: set[int] = set()

    for attempt in range(retries):
        try:
            send_s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            send_s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            recv_s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            recv_s.bind(('', 0))  # bind em todas as interfaces — src_ip pode não ser bindável
            recv_s.settimeout(timeout)
        except PermissionError:
            logging.critical("root necessário para raw sockets (execute com sudo)")
            sys.exit(1)
        except OSError as e:
            logging.error("Erro ao criar socket: %s", e)
            return []

        # Porta de origem base — única por tentativa para correlação
        base_sport = 40000 + (os.getpid() % 5000) + attempt * 1000

        # Envia todos os probes
        for i, port in enumerate(ports):
            payload = PROBES.get(port, DEFAULT_PROBE)
            sport   = base_sport + i
            pkt     = build_udp_packet(src_ip, dst_ip, sport, port, payload)
            try:
                send_s.sendto(pkt, (dst_ip, 0))
            except OSError:
                pass
        send_s.close()

        # Coleta respostas dentro do timeout
        deadline = time.monotonic() + timeout
        ports_set = set(ports)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                ready, _, _ = select.select([recv_s], [], [], remaining)
                if not ready:
                    break
                data, addr = recv_s.recvfrom(4096)
            except OSError:
                break

            if addr[0] != dst_ip or len(data) < 28:
                continue

            # Parse do cabeçalho IP para chegar no UDP
            ip_ihl = (data[0] & 0x0F) * 4
            proto  = data[9]
            if proto != 17:          # não é UDP
                continue
            if len(data) < ip_ihl + 8:
                continue

            # Porta de origem do pacote recebido = porta do serviço remoto
            src_port_resp = struct.unpack("!H", data[ip_ihl: ip_ihl + 2])[0]
            if src_port_resp in ports_set:
                open_ports.add(src_port_resp)

        recv_s.close()

        if open_ports:
            break  # encontrou algo — não precisa retentar

    return sorted(open_ports)


# ─────────────────────────────────────────────────────────────────────────────
# EXPANSÃO DE TARGETS
# ─────────────────────────────────────────────────────────────────────────────

def expand_targets(targets_file: str) -> list[str]:
    """Expande IPs, CIDRs e ranges para lista de IPs individuais."""
    ips: list[str] = []
    with open(targets_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
                if net.prefixlen == 32:
                    ips.append(str(net.network_address))
                else:
                    ips.extend(str(h) for h in net.hosts())
            except ValueError:
                # Tenta como IP simples
                try:
                    ipaddress.ip_address(line)
                    ips.append(line)
                except ValueError:
                    logging.warning("Entrada inválida ignorada: %s", line)
    return ips


# ─────────────────────────────────────────────────────────────────────────────
# SCAN PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

def run_scan(
    targets_file: str,
    ports: list[int],
    workers: int,
    timeout: float,
    retries: int,
    progress: bool = True,
) -> list[dict]:
    """
    Escaneia todos os hosts em paralelo.
    Retorna lista de dicts: {ip, port, service, factor}.
    """
    src_ip = get_local_ip()
    logging.info("IP de origem: %s", src_ip)

    hosts = expand_targets(targets_file)
    total = len(hosts)
    logging.info("%d hosts para escanear, %d portas cada", total, len(ports))

    results: list[dict] = []
    done   = 0
    start  = time.monotonic()

    def worker(ip: str):
        found = scan_host(src_ip, ip, ports, timeout=timeout, retries=retries)
        return ip, found

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(worker, ip): ip for ip in hosts}
        for future in as_completed(futures):
            ip, found_ports = future.result()
            done += 1

            for port in found_ports:
                svc   = AMP_SERVICES.get(port, {})
                entry = {
                    "ip":      ip,
                    "port":    port,
                    "service": svc.get("name", "Desconhecido"),
                    "factor":  svc.get("factor", "?"),
                    "status":  "open",
                }
                results.append(entry)
                logging.warning("[ABERTA] %s  UDP/%-6d  %s (%s)",
                                ip, port, entry["service"], entry["factor"])

            if progress and done % 100 == 0:
                elapsed = time.monotonic() - start
                rate    = done / elapsed if elapsed > 0 else 0
                eta     = (total - done) / rate if rate > 0 else 0
                logging.info("Progresso: %d/%d  (%.0f hosts/s  ETA %.0fs)",
                             done, total, rate, eta)

    elapsed = time.monotonic() - start
    logging.info("Scan concluído: %d hosts em %.1fs  →  %d achados",
                 total, elapsed, len(results))
    return results


# ─────────────────────────────────────────────────────────────────────────────
# RELATÓRIOS
# ─────────────────────────────────────────────────────────────────────────────

CRITICAL_PORTS = {11211, 123, 161, 389, 19, 3702}  # amplificação mais severa

# Cores ANSI
RED    = "\033[0;31m"
YELLOW = "\033[1;33m"
GREEN  = "\033[0;32m"
CYAN   = "\033[0;36m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def _color(text: str, code: str) -> str:
    if sys.stdout.isatty():
        return f"{code}{text}{RESET}"
    return text


def print_report(results: list[dict], threshold: int = 5) -> None:
    """Exibe relatório formatado no terminal."""
    unique_hosts  = {r["ip"] for r in results}
    total_hosts   = len(unique_hosts)
    total_findings = len(results)

    print("\n" + "=" * 62)
    print(f"  RELATÓRIO DE SUPERFÍCIE DE ATAQUE UDP — {datetime.now():%Y-%m-%d %H:%M:%S}")
    print("=" * 62)
    print(f"  Total de hosts com portas abertas : {_color(str(total_hosts), BOLD)}")
    print(f"  Total de achados (ip:porta)       : {_color(str(total_findings), BOLD)}")

    # Por serviço
    print("\n" + "-" * 62)
    print("  DETALHAMENTO POR SERVIÇO")
    print("-" * 62)
    from collections import Counter
    by_port = Counter(r["port"] for r in results)
    for port in sorted(AMP_SERVICES):
        count = by_port.get(port, 0)
        if count == 0:
            continue
        svc   = AMP_SERVICES[port]
        label = f"UDP/{port}"
        color = RED if port in CRITICAL_PORTS else YELLOW
        print(f"  {_color(label, color):<14}  {svc['name']:<22}  "
              f"fator {svc['factor']:<10}  {_color(str(count) + ' hosts', BOLD)}")

    # Top 20 hosts
    if results:
        print("\n" + "-" * 62)
        print("  HOSTS MAIS EXPOSTOS (Top 20)")
        print("-" * 62)
        from collections import Counter
        host_counts = Counter(r["ip"] for r in results)
        for ip, count in host_counts.most_common(20):
            bar = "█" * min(count, 40)
            print(f"  {ip:<18}  {count:>3} porta(s)  {_color(bar, CYAN)}")

    # Prioridade crítica
    critical = [r for r in results if r["port"] in CRITICAL_PORTS]
    if critical:
        print("\n" + "-" * 62)
        print(f"  {_color('⚠  PRIORIDADE CRÍTICA (amplificação severa)', RED)}")
        print("-" * 62)
        shown = set()
        for r in critical:
            key = (r["ip"], r["port"])
            if key in shown:
                continue
            shown.add(key)
            print(f"  {_color(r['ip'], RED):<20}  UDP/{r['port']:<8}  "
                  f"{r['service']}  (fator {r['factor']})")

    print("\n" + "=" * 62)

    if total_hosts >= threshold:
        print(_color(
            f"\n  ⚠  ATENÇÃO: {total_hosts} hosts com serviços de amplificação expostos!\n",
            RED + BOLD,
        ))
    else:
        print(_color(
            f"\n  ✔  Scan concluído. {total_hosts} hosts encontrados.\n",
            GREEN + BOLD,
        ))


def save_csv(results: list[dict], path: str) -> None:
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["ip", "port", "service", "factor", "status"])
        w.writeheader()
        w.writerows(results)
    logging.info("CSV salvo: %s", path)


def save_json(results: list[dict], path: str, elapsed: float) -> None:
    from collections import Counter, defaultdict

    by_port: dict[int, list[str]] = defaultdict(list)
    for r in results:
        by_port[r["port"]].append(r["ip"])

    services_summary = []
    for port in sorted(by_port):
        svc = AMP_SERVICES.get(port, {"name": "Desconhecido", "factor": "?"})
        services_summary.append({
            "port":    port,
            "service": svc["name"],
            "factor":  svc["factor"],
            "count":   len(by_port[port]),
            "hosts":   sorted(set(by_port[port])),
        })

    doc = {
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "scan_elapsed": round(elapsed, 2),
        "summary": {
            "total_hosts":    len({r["ip"] for r in results}),
            "total_findings": len(results),
        },
        "services": services_summary,
        "findings": results,
    }
    with open(path, "w") as f:
        json.dump(doc, f, indent=2)
    logging.info("JSON salvo: %s", path)


def save_txt(results: list[dict], path: str) -> None:
    from collections import Counter
    unique_hosts  = {r["ip"] for r in results}
    by_port = Counter(r["port"] for r in results)
    host_counts = Counter(r["ip"] for r in results)

    with open(path, "w") as f:
        f.write("=" * 62 + "\n")
        f.write(f"  RELATÓRIO DE SUPERFÍCIE DE ATAQUE UDP — {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        f.write("=" * 62 + "\n\n")
        f.write(f"  Total de hosts com portas abertas : {len(unique_hosts)}\n")
        f.write(f"  Total de achados (ip:porta)       : {len(results)}\n\n")

        f.write("-" * 62 + "\n")
        f.write("  DETALHAMENTO POR SERVIÇO\n")
        f.write("-" * 62 + "\n")
        for port in sorted(AMP_SERVICES):
            count = by_port.get(port, 0)
            if count == 0:
                continue
            svc = AMP_SERVICES[port]
            f.write(f"  UDP/{port:<8}  {svc['name']:<22}  fator {svc['factor']:<10}  {count} hosts\n")

        f.write("\n" + "-" * 62 + "\n")
        f.write("  HOSTS MAIS EXPOSTOS (Top 20)\n")
        f.write("-" * 62 + "\n")
        for ip, count in host_counts.most_common(20):
            f.write(f"  {ip:<20}  {count} porta(s)\n")

        f.write("\n" + "-" * 62 + "\n")
        f.write("  PRIORIDADE CRÍTICA\n")
        f.write("-" * 62 + "\n")
        for r in results:
            if r["port"] in CRITICAL_PORTS:
                f.write(f"  {r['ip']:<20}  UDP/{r['port']:<8}  {r['service']}  (fator {r['factor']})\n")

        f.write("\n" + "=" * 62 + "\n")
    logging.info("TXT salvo: %s", path)


# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────

def print_banner() -> None:
    banner = rf"""
{BOLD}{CYAN}
 ██╗   ██╗██████╗ ██████╗      █████╗ ███╗   ███╗██████╗
 ██║   ██║██╔══██╗██╔══██╗    ██╔══██╗████╗ ████║██╔══██╗
 ██║   ██║██║  ██║██████╔╝    ███████║██╔████╔██║██████╔╝
 ██║   ██║██║  ██║██╔═══╝     ██╔══██║██║╚██╔╝██║██╔═══╝
 ╚██████╔╝██████╔╝██║         ██║  ██║██║ ╚═╝ ██║██║
  ╚═════╝ ╚═════╝ ╚═╝         ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝
         UDP Amplification Attack Surface Monitor{RESET}
"""
    print(banner)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    default_ports = ",".join(str(p) for p in sorted(AMP_SERVICES))

    parser = argparse.ArgumentParser(
        description="UDP Amplification Attack Surface Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  sudo python3 udp_amp_monitor.py targets.txt
  sudo python3 udp_amp_monitor.py targets.txt --ports 53,123,161
  sudo python3 udp_amp_monitor.py targets.txt --workers 200 --timeout 2.0
  sudo python3 udp_amp_monitor.py targets.txt --output-dir ./resultados
  sudo python3 udp_amp_monitor.py targets.txt --threshold 10 --alert-email sec@empresa.com
        """,
    )
    parser.add_argument("targets",
                        help="Arquivo com IPs/CIDRs (um por linha, suporta #comentários)")
    parser.add_argument("--ports", default=default_ports,
                        help="Portas UDP separadas por vírgula (padrão: todos os serviços de amp.)")
    parser.add_argument("--workers", type=int, default=150,
                        help="Threads paralelas (padrão: 150)")
    parser.add_argument("--timeout", type=float, default=1.5,
                        help="Timeout por host em segundos (padrão: 1.5)")
    parser.add_argument("--retries", type=int, default=2,
                        help="Retentativas por host sem resposta (padrão: 2)")
    parser.add_argument("--output-dir", default="./udp_amp_results",
                        help="Diretório de saída (padrão: ./udp_amp_results)")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Limiar de alerta — hosts vulneráveis (padrão: 5)")
    parser.add_argument("--alert-email", default="",
                        help="Endereço de e-mail para alerta (requer mailutils)")
    parser.add_argument("--no-progress", action="store_true",
                        help="Desativa log de progresso percentual")
    parser.add_argument("--quiet", action="store_true",
                        help="Só exibe hosts encontrados (sem INFO)")
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# ALERTA POR E-MAIL
# ─────────────────────────────────────────────────────────────────────────────

def send_alert(email: str, count: int, report_path: str) -> None:
    import subprocess
    try:
        with open(report_path) as f:
            body = f.read()
        proc = subprocess.run(
            ["mail", "-s", f"[ALERTA] {count} hosts UDP vulneráveis detectados", email],
            input=body, text=True, capture_output=True, timeout=15,
        )
        if proc.returncode == 0:
            logging.info("Alerta enviado para %s", email)
        else:
            logging.warning("Falha ao enviar e-mail: %s", proc.stderr)
    except FileNotFoundError:
        logging.warning("'mail' não encontrado — instale mailutils para alertas por e-mail")
    except Exception as e:
        logging.warning("Erro ao enviar alerta: %s", e)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()

    # Logging
    log_level = logging.WARNING if args.quiet else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="[%(asctime)s] %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Verifica root
    if os.geteuid() != 0:
        logging.critical("Este script requer root (raw sockets UDP). Execute com sudo.")
        sys.exit(1)

    # Verifica arquivo de targets
    if not Path(args.targets).is_file():
        logging.critical("Arquivo não encontrado: %s", args.targets)
        sys.exit(1)
    if Path(args.targets).stat().st_size == 0:
        logging.critical("Arquivo de targets está vazio: %s", args.targets)
        sys.exit(1)

    # Parseia portas
    try:
        ports = sorted({int(p.strip()) for p in args.ports.split(",") if p.strip()})
    except ValueError as e:
        logging.critical("Erro ao parsear portas: %s", e)
        sys.exit(1)

    # Prepara output
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Configura file handler para log
    log_path = output_dir / "monitor.log"
    fh = logging.FileHandler(log_path)
    fh.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logging.getLogger().addHandler(fh)

    print_banner()

    logging.info("Targets  : %s", args.targets)
    logging.info("Portas   : %s", ports)
    logging.info("Workers  : %d", args.workers)
    logging.info("Timeout  : %.1fs", args.timeout)
    logging.info("Retries  : %d", args.retries)
    logging.info("Output   : %s", output_dir)

    # ── Scan ──────────────────────────────────────────────────────────────────
    t0 = time.monotonic()
    results = run_scan(
        targets_file=args.targets,
        ports=ports,
        workers=args.workers,
        timeout=args.timeout,
        retries=args.retries,
        progress=not args.no_progress,
    )
    elapsed = time.monotonic() - t0

    # ── Relatórios ────────────────────────────────────────────────────────────
    print_report(results, threshold=args.threshold)

    txt_path  = output_dir / f"report_{ts}.txt"
    csv_path  = output_dir / f"report_{ts}.csv"
    json_path = output_dir / f"report_{ts}.json"

    save_txt(results,  str(txt_path))
    save_csv(results,  str(csv_path))
    save_json(results, str(json_path), elapsed)

    # ── Alerta ────────────────────────────────────────────────────────────────
    unique_hosts = len({r["ip"] for r in results})
    if args.alert_email and unique_hosts >= args.threshold:
        send_alert(args.alert_email, unique_hosts, str(txt_path))

    sys.exit(0)


if __name__ == "__main__":
    main()
