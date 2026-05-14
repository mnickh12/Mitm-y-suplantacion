#!/usr/bin/env python3
from scapy.all import sniff, ARP
from collections import defaultdict

arp_table = defaultdict(set)

def alert_arpspoof(pkt):
    # Mostrar todo paquete ARP que llegue
    if ARP in pkt:
        op = pkt[ARP].op
        ip_src = pkt[ARP].psrc
        mac_src = pkt[ARP].hwsrc
        print(f"[DEBUG] ARP recibido: op={op} IP={ip_src} MAC={mac_src}")

        if op == 2:  # is-at (reply)
            arp_table[ip_src].add(mac_src)
            if len(arp_table[ip_src]) > 1:
                print(f"[!] ALERTA ARP SPOOFING: IP {ip_src} con múltiples MACs: {', '.join(arp_table[ip_src])}")

if __name__ == "__main__":
    print("[*] Iniciando monitor ARP...")
    sniff(filter="arp", prn=alert_arpspoof, store=0)
