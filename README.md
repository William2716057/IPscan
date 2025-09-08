# Python Network Scanner

A simple Python tool that scans your local network to discover connected devices.
It retrieves IP addresses, MAC addresses, vendor information, hostnames and attempts to guess the operating system based on TTL values.

## Features

- Detects active devices on the local network via ARP scanning.
- Retrieves MAC vendor information using the macvendors API
- Attempts hostname resolution via reverse DNS lookup.
- Guesses the device operating system based on ICMP TTL values.
- Automatically selects the correct network interface.

### Requirements
- Python 3.7+
- Install dependencies

```
  pip install scapy netifaces requests
```

### Usage

- Run the script with
```
python3 IPscan.py
```
It will automatically detect your local network and start scanning.
The scan repeats 5 times, updating the list of devices for better accuracy.

### Example Output

```
Using interface: Wi-Fi...
Scanning network: 192.168.1.1/24...
Devices found: 3
 - 192.168.1.1  |  a4:5e:60:12:34:56  |  Cisco Systems | Network device/Router (TTL 255) | router.local
 - 192.168.1.101  |  3c:22:fb:65:43:21  |  Apple, Inc.   | Unix/Linux (TTL 64) | macbook.local
 - 192.168.1.150  |  b8:27:eb:ab:cd:ef |  Raspberry Pi Foundation | Unix/Linux (TTL 64) | raspberrypi

Devices found: 2
 - 192.168.1.1  |  a4:5e:60:12:34:56  |  Cisco Systems | Network device/Router (TTL 255) | router.local
 - 192.168.1.101  |  3c:22:fb:65:43:21  |  Apple, Inc.   | Unix/Linux (TTL 64) | macbook.local
```

#### Notes

- Must be run with administrator/root privileges for ARP scanning to work.
- The TTL → OS mapping is heuristic and may not always be accurate.
- Some devices may not respond to hostname lookups or ICMP packets.
