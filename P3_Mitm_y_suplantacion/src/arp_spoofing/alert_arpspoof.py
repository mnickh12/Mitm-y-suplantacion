#!/usr/bin/env python3
"""
Monitor de red para detección de ARP Spoofing.
Detecta anomalías cuando una misma IP responde con diferentes MACs.
"""

from scapy.all import sniff, ARP
from collections import defaultdict

# Tabla IP -> MAC conocida
arp_table = defaultdict(set)


def alert_arpspoof(pkt):
    """Detecta respuestas ARP sospechosas."""
    if ARP in pkt and pkt[ARP].op == 2:  # is-at (reply)
        ip_src = pkt[ARP].psrc
        mac_src = pkt[ARP].hwsrc
        real_mac = pkt[ARP].hwsrc

        arp_table[ip_src].add(mac_src)

        if len(arp_table[ip_src]) > 1:
            print(f"[!] ALERTA ARP SPOOFING: IP {ip_src} detectada con"
                  f" múltiples MACs: {', '.join(arp_table[ip_src])}")


if __name__ == "__main__":
    print("[*] Iniciando monitor ARP...")
    sniff(filter="arp", prn=alert_arpspoof, store=0)
