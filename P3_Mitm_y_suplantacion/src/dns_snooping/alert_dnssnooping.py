#!/usr/bin/env python3
"""
Detector de DNS Snooping / ataques Kaminsky.
Firma: ráfagas de consultas a subdominios inexistentes (NXDOMAIN).
"""

from scapy.all import sniff, DNS, DNSQR
from collections import defaultdict
from datetime import datetime, timedelta

# Configuración del umbral
THRESHOLD = 10       # nº de consultas sospechosas
INTERVAL = 5         # ventana de tiempo en segundos

nxdomain_queries = defaultdict(list)  # IP -> timestamps


def alert_dnssnooping(pkt):
    """Detecta ráfagas de consultas a subdominios inexistentes."""
    if DNS in pkt and DNSQR in pkt:
        qname = pkt[DNSQR].qname.decode()
        src_ip = pkt["IP"].src if "IP" in pkt else "localhost"

        if pkt[DNS].rcode == 3:  # NXDOMAIN
            now = datetime.now()
            nxdomain_queries[src_ip].append(now)

            # Limpiar timestamps antiguos fuera de la ventana
            nxdomain_queries[src_ip] = [
                t for t in nxdomain_queries[src_ip]
                if now - t < timedelta(seconds=INTERVAL)
            ]

            count = len(nxdomain_queries[src_ip])
            if count >= THRESHOLD:
                print(f"[!] ALERTA DNS SNOOPING: {count} consultas NXDOMAIN "
                      f"en {INTERVAL}s desde {src_ip} (última: {qname})")
                # Resetear para evitar spam de alertas
                nxdomain_queries[src_ip].clear()


if __name__ == "__main__":
    print("[*] Iniciando monitor DNS...")
    sniff(filter="udp port 53", prn=alert_dnssnooping, store=0)
