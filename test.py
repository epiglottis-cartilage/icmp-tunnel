from scapy.all import *

# Define a callback function to handle packets
def icmp_packet_callback(packet):
    if packet.haslayer(ICMP):
        ip_layer = packet.getlayer(IP)
        icmp_layer = packet.getlayer(ICMP)
        print(f"ICMP Packet: {ip_layer.src} -> {ip_layer.dst} | Type: {icmp_layer.type} | Code: {icmp_layer.code}")
        if icmp_layer.type == 8:  # Echo Request
            print(f"Payload: {packet[Raw].load}")

# Start sniffing for ICMP packets
print("Sniffing ICMP packets...")
sniff(filter="icmp", prn=icmp_packet_callback)

sr1(ETHER_BROADCAST()/IP(dst="8.8.8.8")/TCP(), timeout=1, verbose=0)