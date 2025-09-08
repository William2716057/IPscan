#!/usr/bin/env python3
import scapy.all as scapy
import netifaces

def get_local_ip():
    gateways = netifaces.gateways()
    default_iface = gateways['default'][netifaces.AF_INET][1]
    local_ip = netifaces.ifaddresses(default_iface)[netifaces.AF_INET][0]['addr']
    return local_ip, default_iface

def scan(ip_range, iface):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=2, iface=iface, verbose=False)[0]

    devices = []
    for _, received in answered:
        devices.append(received.psrc)
    return devices

if __name__ == "__main__":
    local_ip, iface = get_local_ip()
    ip_range = ".".join(local_ip.split(".")[:3]) + ".1/24"

    print(f"Using interface: {iface}...")
    print(f"Scanning network: {ip_range}...")

    devices = scan(ip_range, iface)
    print(f"\n[+] Devices found: {len(devices)}")
    for ip in devices:
        print(f" - {ip}")

