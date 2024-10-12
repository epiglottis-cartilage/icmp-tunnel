from scapy.all import *
from threading import Thread

HEADER = "Bro is here".encode()


# Define a callback function to handle packets
def icmp_packet_callback(packet, handler):
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        # Send an ICMP Echo Reply packet
        load: bytes | None = handler(packet)
        if load is None:
            return
        reply = (
            IP(dst=packet[IP].src, ttl=packet[IP].ttl)
            / ICMP(type=0, id=packet[ICMP].id, seq=packet[ICMP].seq)
            / load
        )
        send(reply, verbose=0)


class IcmpTunnel:
    def __init__(self):
        self.recv = {}
        self.listener = Thread(
            target=lambda: sniff(
                filter="icmp", prn=lambda p: icmp_packet_callback(p, self.__handler)
            ),
        )
        self.listener.start()
        self.sequence = 0

    def __handler(self, packet):
        src = packet[IP].src
        load = bytes(packet[Raw].load)
        if not load.startswith(HEADER):
            return load
        load = load[len(HEADER) :]
        print(f"{packet[IP].src}😙{load}")
        self.recv[packet[ICMP].seq] = load
        load = f"Will received {len(load)} bytes from {src}".encode()
        return HEADER + load

    def sr1(self, load: bytes, dst: str):
        sequence = self.sequence
        self.sequence += 1

        packet = (
            IP(dst=dst, ttl=114)
            / ICMP(type=8, id=54188, seq=sequence)
            / (HEADER + load)
        )
        send(packet, verbose=0)
        cnt = 0
        while sequence not in self.recv and cnt < 1000:
            time.sleep(0.001)
            cnt += 1
        if sequence not in self.recv:
            return None
        load = self.recv.pop(sequence)
        return load


obj = IcmpTunnel()
dst = input("Enter the destination IP address: ")
while True:
    load = input("Enter the data to send: ")
    load = obj.sr1(load.encode(), dst)
    if load is None:
        print("No response received.")
    else:
        print(f"Received response: {load.decode()}")
