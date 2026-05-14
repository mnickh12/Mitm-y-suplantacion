#!/usr/bin/env python3
from scapy.all import sniff, DNS, DNSQR
from collections import defaultdict
from datetime import datetime, timedelta

THRESHOLD = 10
INTERVAL = 5

nxdomain_queries = defaultdict(list)


def alert_dnssnooping(pkt):
    if DNS in pkt and DNSQR in pkt:
        qname = pkt[DNSQR].qname.decode()
        src_ip = pkt["IP"].src if "IP" in pkt else "localhost"

        # Detectamos todas las consultas DNS (no solo respuestas)
        now = datetime.now()
        nxdomain_queries[src_ip].append(now)

        nxdomain_queries[src_ip] = [
            t for t in nxdomain_queries[src_ip]
            if now - t < timedelta(seconds=INTERVAL)
        ]

        count = len(nxdomain_queries[src_ip])
        if count == 1:
            print(f"[*] Primera consulta detectada: {qname} desde {src_ip}")
        if count >= THRESHOLD:
            print(f"[!] ALERTA DNS SNOOPING: {count} consultas DNS "
                  f"en {INTERVAL}s desde {src_ip} (última: {qname})")
            nxdomain_queries[src_ip].clear()


if __name__ == "__main__":
    print("[*] Iniciando monitor DNS...")
    sniff(filter="udp port 53", prn=alert_dnssnooping, store=0)
