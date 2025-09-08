#!/usr/bin/env python3
import scapy.all as scapy
import netifaces

def get_local_ip():
    #Get local IP and default gateway interface (GUID)
    gateways = netifaces.gateways()
    default_iface = gateways['default'][netifaces.AF_INET][1]
    local_ip = netifaces.ifaddresses(default_iface)[netifaces.AF_INET][0]['addr']
    return local_ip

def detect_scapy_iface(local_ip):
    #Detect the correct Scapy interface (GUID) by matching local IP.
    #Returns a Scapy-compatible interface string.
    for iface in scapy.get_if_list():
        try:
            if scapy.get_if_addr(iface) == local_ip:
                return iface
        except Exception:
            continue
    return scapy.conf.iface

def scan(ip_range, iface):
    #Perform ARP scan on given IP range using the selected interface.
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=2, iface=iface, verbose=False)[0]

    devices = []
    for _, received in answered:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    return devices

if __name__ == "__main__":
    local_ip = get_local_ip()
    iface = detect_scapy_iface(local_ip)
    ip_range = ".".join(local_ip.split(".")[:3]) + ".1/24"

    print(f"Using interface: {iface}...")
    print(f"Scanning network: {ip_range}...")

    devices = scan(ip_range, iface)
    print(f"\n[+] Devices found: {len(devices)}")
    for dev in devices:
        print(f" - {dev['ip']}  |  {dev['mac']}")