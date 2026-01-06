# Scorpyon 🦂

**Scorpyon** is a lightweight Python framework for network security testing. It automates ARP spoofing and DNS poisoning attacks to intercept traffic on local networks.

> **⚠️ DISCLAIMER** > This tool is for **educational purposes only**. Usage on networks without explicit permission is illegal. The author assumes no liability for misuse.

## Features
- **ARP Spoofing:** Automates Layer 2 Man-in-the-Middle attacks.
- **DNS Poisoning:** Intercepts and redirects DNS queries via `NetfilterQueue`.
- **Network Scanner:** Identifies active hosts and vendors.
- **Safety First:** Auto-restores ARP tables and flushes firewall rules on exit.
