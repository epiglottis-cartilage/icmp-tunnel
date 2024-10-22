from multiprocessing import Pipe
import time
from typing import Optional, Callable
from scapy.all import IP, ICMP, Raw
import scapy.all
import socket
import threading
import select
import random

def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to reach the address actually
        s.connect(("10.254.254.254", 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    print("Your IP is", ip)
    return ip

Local_ip = get_local_ip()
Local_ip_int = int.from_bytes(socket.inet_aton(Local_ip))

LOAD_SIZE_LIMIT = 1415

class IcmpPacket:
    # 主要目的：
    # 1. 封装IP包
    # 2. 处理过大的数据包（分割和并）
    src_ip:str
    dst_ip:str

    # 对应由同一数据包分割而出的数据包
    # 拥有相同identifier
    identifier:int
    IDENTIFIER_BITS = 48

    # 由同一数据包分割而出的数据包
    # 拥有递增的slice_cnt
    # Start from 1
    # Ended with -len(data)
    slice_cnt:int
    SLICE_CNT_BITS = 64

    data:bytes


    LOAD_SIZE_LIMIT = 1415

    def __init__(self, src_ip:str, dst_ip:str, data:bytes) :
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.identifier = random.randint(0, 2**IcmpPacket.IDENTIFIER_BITS - 1)
        self.slice_cnt = -1
        self.data = data

    def split(self):
        if len(self.data) <= self.LOAD_SIZE_LIMIT:
            return [self]

        datas = [
            self.load[i : i + self.LOAD_SIZE_LIMIT]
            for i in range(0, len(self.load), self.LOAD_SIZE_LIMIT)
        ]
        res = []
        for i, data in enumerate(datas):
            pac = IcmpPacket(self.src_ip,self.dst_ip,data)
            # pac.src_ip = self.src_ip
            # pac.dst_ip = self.dst_ip
            pac.identifier = self.identifier
            # pac.data = data
            pac.slice_cnt = i + 1
            res.append(pac)

        res[-1].slice_cnt = -len(res)

        return res

    def merge(packets:list["IcmpPacket"]):
        packets.sort(key=lambda x: x.slice_cnt)

        identifier = packets[0].identifier
        for pac in packets:
            if pac.identifier != identifier:
                raise ValueError("Packets do not belong to the same data packet")
        
        if len(packets) != -packets[0].slice_cnt:
            raise ValueError("Packets are not complete")
        
        data = b""
        for pac in packets[1:]:
            data += pac.data

        res = IcmpPacket(packets[0].src_ip, packets[0].dst_ip, packets[0].data + data)
        # res.src_ip = packets[0].src_ip
        # res.dst_ip = packets[0].dst_ip
        res.identifier = packets[0].identifier
        # res.data = packets[0].data + data

        return res
    
    def build(self):
        if len(self.data) > LOAD_SIZE_LIMIT:
            raise ValueError("Data is too large, Split it first")

        data = (
            self.identifier.to_bytes(self.IDENTIFIER_BITS, "big")+
            self.slice_cnt.to_bytes(self.SLICE_CNT_BITS, "big", signed=True)+
            self.data
        )
        packet = (
            IP(dst=self.dst_ip)
            / ICMP(type=0, code=114, id=514, seq=self.identifier & 0xFFFF)
            / data
        )
        return packet
    
    def parse(packet:IP) -> Optional["IcmpPacket"]:
        if packet.haslayer(ICMP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            code = packet[ICMP].code
            id = packet[ICMP].id
            # seq = packet[ICMP].seq

            if not (int(code) == 114 and int(id) == 514):
                return None

            load = packet[Raw].load

            identifier = int.from_bytes(load[:IcmpPacket.IDENTIFIER_BITS], "big")
            slice_cnt = int.from_bytes(load[IcmpPacket.IDENTIFIER_BITS:IcmpPacket.IDENTIFIER_BITS+IcmpPacket.SLICE_CNT_BITS], "big", signed=True)

            res = IcmpPacket(src_ip,dst_ip, b"")
            # res.src_ip = src_ip
            # res.dst_ip = dst_ip
            res.identifier = identifier
            res.slice_cnt = slice_cnt
            res.data = load[IcmpPacket.IDENTIFIER_BITS+IcmpPacket.SLICE_CNT_BITS:]
            return res
        
        return None
    
    def build_and_send(self):
        for pack in self.split():
            scapy.all.send(pack.build(), verbose=0)


class IcmpCapture:
    """
    抓包
    """

    def __init__(self, send_to):
        self.send_to = send_to
        self.listener = threading.Thread(
            target=self.__start
        )

        self.listener.start()
    
    def __start(self):
        try: 
            scapy.all.sniff(
                prn=self.handle_income, filter=f"icmp and (dst host {Local_ip})"
            )
        except PermissionError:
            print("PermissionError, try sudo")
            exit(1)
        


    def new():
        r, w = Pipe()
        IcmpCapture(w)
        return r

    def handle_income(self, packet):
        data = IcmpPacket.parse(packet)
        # print("Icmp income:",data.src_ip,data.dst_ip,data.data)
        if data is not None:
            try:
                self.send_to.send(data)
            except Exception as e:
                print("IcmpCapture err:", e)
        

class IcmpDataMerger:
    """
    合并同一个 identifier 的数据包
    """

    def __init__(self, recv, send):
        self.recv = recv
        self.send = send
        self.buffer: dict[(str,int), tuple[int, list[IcmpPacket]]] = {}
        self.prase_to_tcp = False

        threading.Thread(target=self.merge_packets, daemon=True).start()

    def new(recv):
        r, w = Pipe()
        IcmpDataMerger(recv, w)
        return r

    def new_tp_tcp(recv):
        r, w = Pipe()
        IcmpDataMerger(recv, w).prase_to_tcp = True
        return r
    def merge_packets(
        self,
    ):
        while True:
            try:
                pack: IcmpPacket = self.recv.recv()
            except Exception as e:
                print("IcmpDataMerger ending:", e)
                break
            # print("Merger recv", pack)

            identifier_with_ip = (pack.src_ip, pack.identifier)

            if self.buffer.get(identifier_with_ip) is None:
                self.buffer[identifier_with_ip] = 0, []

            size, buffer = self.buffer[identifier_with_ip]

            if pack.slice_cnt < 0:
                size = -pack.slice_cnt

            buffer.append(pack)

            self.buffer[identifier_with_ip] = size, buffer

            if size > 0 and len(buffer) == size:
                try:
                    if self.prase_to_tcp:
                        self.send.send(TcpPacket.prase(IcmpPacket.merge(buffer)))
                    else:
                        self.send.send(IcmpPacket.merge(buffer))
                except Exception as e:
                    print("IcmpDataMerger err:", e)
                finally:
                    self.buffer.pop(identifier_with_ip)

class TcpPacketType:
    # 客户端发送
    CLIENT_WANT_CONNECT = 1
    # 服务器发送
    SERVER_OK_CONNECTED = 2
    # 客户端发送
    CONNECTED_CONFIRM = 3

    KILL_THIS = 4
    NORMAL = 255
        
class TcpPacket:
    src_ip:str
    dst_ip:str
    src_port: int
    dst_port: int
    PORT_BITS = 32

    pack_type: int

    data = bytes

    def __init__(self, src_ip:str, src_port: int, dst_ip: str, dst_port: int, data: bytes, type:int):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.data = data

        self.pack_type = type

    def build(self) -> IcmpPacket:
        return IcmpPacket(self.src_ip, self.dst_ip,(
            self.src_port.to_bytes(self.PORT_BITS, "big")+
            self.dst_port.to_bytes(self.PORT_BITS, "big")+
            self.pack_type.to_bytes(1, "big")+
            self.data
        ))
        
    def prase(packet:IcmpPacket) -> "TcpPacket":
        if len(packet.data) < TcpPacket.PORT_BITS * 2 + 1:
            raise ValueError("Invalid packet size")
        
        res = TcpPacket(src_ip=packet.src_ip,
                          dst_ip=packet.dst_ip,
                          src_port= int.from_bytes(packet.data[:TcpPacket.PORT_BITS], "big"),
                          dst_port=int.from_bytes(packet.data[TcpPacket.PORT_BITS:TcpPacket.PORT_BITS*2], "big"),
                          type=packet.data[TcpPacket.PORT_BITS*2],
                          data=packet.data[TcpPacket.PORT_BITS*2+1:]
                          )
        print("Tcp incoming:",res.src_ip, res.src_port,"->",res.dst_ip, res.dst_port,res.pack_type ,":", res.data)
        return res
    
    def identifier(self):
        if self.src_ip == Local_ip:
            return self.dst_ip,self.src_ip,str(self.dst_port),str(self.src_port)
        else:
            return self.src_ip,self.dst_ip,str(self.src_port),str(self.dst_port)
    
    def from_identifier(identifier, data, type):
        ip1, ip2, port1, port2 = identifier
        if ip1 == Local_ip:
            return TcpPacket(ip1, int(port1), ip2, int(port2), data, type)
        else:
            return TcpPacket(ip2, int(port2), ip1, int(port1), data, type)

    def build_and_send(self):
        self.build().build_and_send()

        
class TcpStream:
    def __init__(self, identifier, incoming_pipe, host:"TcpHost"):
        self.identifier = identifier
        self.incoming_pipe = incoming_pipe
        self.host = host

    def read(self)->bytes:
        return self.incoming_pipe.recv()
    def write(self,data):
        TcpPacket.from_identifier(self.identifier, data, TcpPacketType.NORMAL).build_and_send()
    def close(self):
        TcpPacket.from_identifier(self.identifier, b"close", TcpPacketType.KILL_THIS).build_and_send()
        self.host.connected_stream.pop(self.identifier)
        

class TcpHost:
    local_servers:dict
    connected_stream:dict[tuple,TcpStream]
    waiting_for_connect:set

    def __init__(self, recv):
        self.local_servers = dict()
        self.connected_stream = dict()
        self.waiting_for_connect = set()

        threading.Thread(target=self._handle_income, args=(recv,)).start()
    
    def _handle_income(self, recv):
        while True:
            try:
                pack:TcpPacket = recv.recv()
                if pack.pack_type == TcpPacketType.CLIENT_WANT_CONNECT:
                    if self.local_servers.get(pack.dst_port) is not None:
                        TcpPacket(pack.dst_ip, pack.dst_port, pack.src_ip, pack.src_port, b"200", TcpPacketType.SERVER_OK_CONNECTED).build_and_send()
                        self.waiting_for_connect.add(pack.identifier())
                    else:
                        TcpPacket(pack.dst_ip, pack.dst_port, pack.src_ip, pack.src_port, b"404", TcpPacketType.KILL_THIS).build_and_send()
                        
                    
                elif pack.pack_type == TcpPacketType.SERVER_OK_CONNECTED:
                    if pack.identifier() in self.waiting_for_connect:
                        self.waiting_for_connect.remove(pack.identifier())

                        r,w= Pipe()
                        stream = TcpStream(pack.identifier(),r,self)

                        self.connected_stream[pack.identifier()] = w
                        self.local_servers[pack.dst_port].send(stream)
                        TcpPacket(pack.dst_ip, pack.dst_port, pack.src_ip, pack.src_port, b"200", TcpPacketType.CONNECTED_CONFIRM).build_and_send()
                    else:
                        TcpPacket(pack.dst_ip, pack.dst_port, pack.src_ip, pack.src_port, b"405", TcpPacketType.KILL_THIS).build_and_send()
                
                elif pack.pack_type == TcpPacketType.CONNECTED_CONFIRM:
                    if pack.identifier() in self.waiting_for_connect:
                        self.waiting_for_connect.remove(pack.identifier())
                        
                        r,w= Pipe()
                        stream = TcpStream(pack.identifier(),r,self)

                        self.connected_stream[pack.identifier()] = w
                        self.local_servers[pack.dst_port].send(stream)
                    else:
                        TcpPacket(pack.dst_ip, pack.dst_port, pack.src_ip, pack.src_port, b"406", TcpPacketType.KILL_THIS).build_and_send()

                    
                elif pack.pack_type == TcpPacketType.KILL_THIS:
                    if self.connected_stream.get(pack.identifier()) is not None:
                        self.connected_stream.pop(pack.identifier())
                
                elif pack.pack_type == TcpPacketType.NORMAL:
                    if self.connected_stream.get(pack.identifier()) is not None:
                        self.connected_stream[pack.identifier()].send(pack.data)
                    else:
                        print("Tcp Unknown identifier", pack.identifier())
                        self.connected_stream[pack.identifier()].send(pack.data)
                        TcpPacket(pack.dst_ip, pack.dst_port, pack.src_ip, pack.src_port, b"407", TcpPacketType.KILL_THIS).build_and_send()
                        
            except Exception as e:
                print("TcpHost ending:", e)
                break
                

    def listen(self, port:int):
        if self.local_servers.get(port) is not None:
            raise ValueError(f"Port {port} already in use")
        r,w = Pipe()
        self.local_servers[port] = w
        return r

    def connect(self, dst_ip:str, dst_port:int):
        port = random.randint(1024, 2**TcpPacket.PORT_BITS - 1)

        while self.local_servers.get(port) is not None:
            port = random.randint(1024, 2**TcpPacket.PORT_BITS - 1)

        port_binder = self.listen(port)

        pack = TcpPacket(Local_ip, port, dst_ip, dst_port, b"0", TcpPacketType.CLIENT_WANT_CONNECT)
        self.waiting_for_connect.add(pack.identifier())
        pack.build_and_send()

        time_start = time.time()
        while pack.identifier() in self.waiting_for_connect and time.time() - time_start < 5:
            time.sleep(0.001)

        if self.connected_stream.get(pack.identifier()) is not None:
            stream:TcpStream = port_binder.recv()
            self.local_servers.pop(port)
            return stream
        if  pack.identifier() in self.waiting_for_connect:
            raise TimeoutError("Connect timeout")
        else:
            raise Exception("Unknown Error")
        


def echo_server(incoming_streams):
    while True:
        stream:TcpStream = incoming_streams.recv()
        try:
            while True:
                data = stream.read()
                stream.write(b">>>BACK<<<"+data)
        except Exception as e:
            pass
        finally:
            stream.close()

if __name__ == "__main__":
    host = TcpHost(IcmpDataMerger.new_tp_tcp(IcmpCapture.new()))
    threading.Thread(target=echo_server, args=(host.listen(666),)).start()

    if Local_ip == "192.168.43.22":
        while True:
            time.sleep(1)
    stream  = host.connect("192.168.43.22", 666)
    stream.write(b"Hello World")
    print(stream.read())
    stream.write(b"Goodbye World")
    print(stream.read())

    