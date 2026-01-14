# Scorpyon

**Scorpyon** is a network security testing framework written in Python. It provides ARP spoofing, DNS poisoning, and SSL stripping capabilities for man-in-the-middle attacks.

## Features


**ARP Spoofing** Layer 2 MITM attack to intercept traffic between target and gateway
**DNS Poisoning** Redirect DNS queries to attacker-controlled IP via NetfilterQueue
**SSL Stripping (Proxy)** Downgrade HTTPS to HTTP and proxy real site content
**SSL Stripping (Phishing)** Serve custom phishing pages over HTTPS
**Network Scanner** Discover active hosts with MAC addresses and vendor info

## Requirements

- **OS**: Linux (requires iptables and netfilter)
- **Privileges**: Root/sudo access required
- **Python**: 3.8+

### Dependencies

```bash
pip install scapy termcolor mac-vendor-lookup netfilterqueue
```

System packages (Debian/Ubuntu):
```bash
sudo apt install libnetfilter-queue-dev python3-dev openssl
```

## Usage

Run with root privileges:
```bash
sudo python3 Scorpyon.py
```

### Menu Options

```
[...Scorpyon...]
1. Start/Stop ARP spoofing
2. Start/Stop DNS poisoning  
3. Start/Stop SSL stripping
4. Scan network
5. Exit
```

## Attack Flows

### Basic MITM (ARP + DNS)
1. Start ARP spoofing → enter target IP
2. Start DNS poisoning → enter domain and redirect IP
3. Traffic from target will be intercepted and DNS queries spoofed

### SSL Stripping (Proxy Mode)
1. Start ARP spoofing → enter target IP
2. Start SSL stripping (option 3 when DNS is not running)
3. Enter target domain (e.g., `example.com`)
4. Script auto-starts DNS poisoning and HTTP proxy
5. Victim's HTTPS requests are downgraded to HTTP

### SSL Stripping (Phishing Mode)
1. Start ARP spoofing
2. Start DNS poisoning → redirect domain to your IP
3. Start SSL stripping (option 3 when DNS is already running)
4. Enter path to phishing content directory
5. Victim sees your fake HTTPS site (with certificate warning)

