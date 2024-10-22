#Deprecated
from scapy.all import IP, ICMP, Raw, send, AsyncSniffer
import random
import time
import socket
import threading

def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to reach the address actually
        s.connect(('10.254.254.254', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    print("Your IP is",ip)
    return ip

Local_ip = get_local_ip()
Local_ip_int = int.from_bytes(socket.inet_aton(Local_ip))

class IcmpData:
    ip:str
    code:int
    seq:int
    id:int
    load:bytes

    def __str__(self):
        return f"IP:{self.ip}, Code:{self.code}, Seq:{self.seq}, ID:{self.id}\n Load:{self.load}"
    
    def build_packet(self):
        packet = IP(dst=self.ip)/ICMP(type=0, code=self.code, id=self.id, seq=self.seq)/self.load
        print(packet.summary())
        return packet
    
class IcmpRecvFuture:
    ip:str
    id:int
    rand:int
    def __init__(self, ip:str, id:int, rand:int):
        self.ip = ip
        self.id = id
        self.rand = rand
    
class IcmpTunnel:
    response_future :dict[IcmpRecvFuture, tuple[bytes,float] | False]
    incoming_request:list[tuple[IcmpRecvFuture, bytes, float]]
    count:dict[str, int]

    ttl = 120

    def __init__(self):
        
        # self.listener = AsyncSniffer(prn=self.handle_income, filter=f"icmp")
        self.listener = AsyncSniffer(prn=self.handle_income, filter=f"icmp and (dst host {Local_ip})")
        self.listener.start()

        ttl_thread = threading.Thread(target=self.ttl_guild)
        ttl_thread.start()
        self.count = 0
        self.response_future = dict()

    def response(self, future:IcmpRecvFuture, load)->None:
        ip = future.ip
        ip_int = int.from_bytes(socket.inet_aton(ip))

        if self.count.get(ip) is None:
            self.count[ip] = 0

        count = self.count[ip]
        self.count[ip] += 1
        
        data = IcmpData()
        data.ip = ip
        data.id = ip_int & 0xff
        data.code = future.rand
        data.seq = count
        data.load = load

        send(data.build_packet(), verbose=0)
        return None
    
    def request(self, ip, load)->IcmpRecvFuture:
        ip_int = int.from_bytes(socket.inet_aton(ip))

        if self.count.get(ip) is None:
            self.count[ip] = 0

        count = self.count[ip]
        self.count[ip] += 1
        
        future = IcmpRecvFuture(ip=ip, id=count,rand=random.randint(0, 255))

        data = IcmpData()
        data.ip = future.ip
        data.id = ip_int & 0xff
        data.code = future.rand
        data.seq = future.id
        data.load = load

        send(data.build_packet(), verbose=0)
        self.response_future[ip] = self.response_future.get(ip, dict())
        return future
    
    def handle_income(self, packet):
        data = IcmpData()
        data.ip = packet[IP].src
        data.code = packet[ICMP].code
        data.seq = packet[ICMP].seq
        data.id = packet[ICMP].id
        data.load = packet[Raw].load

        if data.id == Local_ip_int & 0xffff:
            print("Recognized", data)

            future = IcmpRecvFuture(ip=data.ip, id=data.seq, rand=data.code)

            if self.response_future.get(data.ip) is None:
                self.incoming_request.append((future, data.load, time.time()))
            else:
                self.response_future[future] = (data.load, time.time())

        else:
            # print("Unrecognized", data)
            pass
    
    def check_recv(self, future:IcmpRecvFuture):
        if self.response_future.get(future.ip) is None or self.response_future[future.ip] is False:
            return None
        else:
            return self.response_future[future.ip].pop(future.id)
        
    def ttl_guild(self):
        while True:
            time.sleep(10)
            # retain only packets in past 120 sec
            for ip in self.response_future.keys():
                for id in self.response_future[ip].keys():
                    if time.time() - self.response_future[ip][id][1] > self.ttl:
                        self.response_future[ip].pop(id)
                if len(self.response_future[ip]) == 0:
                    self.response_future.pop(ip)

class PortTunnelRecvFuture:
    def __init__(self, seq):
        self.seq = seq

class PortTunnel:

    def __init__(self):
        self.host = IcmpTunnel()
        self.types = []
        self.seq = 0

        
        self.response_future :dict[IcmpRecvFuture, tuple[bytes,float] | False] 
        self.incoming_request:list[tuple[IcmpRecvFuture, bytes, float]]
    

    def request(self, dst:str, port:int, data:bytes) -> PortTunnelRecvFuture:
        count  = self.seq
        self.seq += 1

        if port not in self.types:
            raise ValueError("type not in types")
        port = self.types.index(port)
        self.host.request(dst, port.to_bytes(2, "big") + count + data)

        return 


    



    


if __name__ == "__main__":
    a = IcmpTunnel()
    for _ in range(10):
        a.send("10.161.0.1", b"114514")
    while True:
        pass