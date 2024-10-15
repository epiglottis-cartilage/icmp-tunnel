from multiprocessing.connection import PipeConnection
from typing import Optional, Callable
from scapy.all import IP, ICMP, send, AsyncSniffer, sniff
from multiprocessing import Pipe

# import time
import socket
import threading
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

LOAD_SIZE_LIMIT = 1280


class IcmpPacketFuture:
    """
    由发送者管理
    服务端需要原样返回！
    """

    # 发送者ip
    ip: str
    # 目标端口
    port: int
    # 序列号
    sequence: int

    def __init__(self, ip: int, port: int, sequence: int):
        self.ip = ip
        self.port = port
        self.sequence = sequence

    def to_bytes(self):
        return (
            self.ip.encode()
            + b"%"
            + self.port.to_bytes(4, "big")
            + self.sequence.to_bytes(8, "big")
        )

    def from_bytes(data: bytes) -> tuple["IcmpPacketFuture", bytes]:
        ip, data = data.split(b"%", 1)
        ip = ip.decode()
        port = int.from_bytes(data[4:8], "big")
        sequence = int.from_bytes(data[8:16], "big")
        return IcmpPacketFuture(ip, port, sequence), data[16:]


class IcmpData:
    ip: str

    port: int

    identifier: IcmpPacketFuture

    data_slice_cnt: int
    load: bytes

    def __init__(self, ip: str, port: int, identifier: IcmpPacketFuture, load: bytes):
        self.ip = ip
        self.port = port
        self.identifier = identifier
        self.data_slice_cnt = -1
        self.load = bytes(load)

    def split(self):
        if len(self.load) <= LOAD_SIZE_LIMIT:
            return [self]

        datas = [
            self.load[i : i + LOAD_SIZE_LIMIT]
            for i in range(0, len(self.load), LOAD_SIZE_LIMIT)
        ]
        res = []
        for i, data in enumerate(datas):
            pac = IcmpData(self.ip, self.port, self.identifier, data)
            pac.data_slice_cnt = i + 1
            res.append(pac)

        res[-1].data_slice_cnt = -len(res)

        return res

    def shrink(packets: list["IcmpData"]):
        if len(packets) == 0:
            raise ValueError("empty packet list")
        packets.sort(key=lambda x: x.slice_cnt)
        if -packets[0].data_slice_cnt != len(packets):
            raise ValueError("packet list is not complete")

        res = IcmpData(packets[0].ip, packets[0].port, packets[0].identifier, b"")
        for pac in packets[1:]:
            res.load += pac.load
        res.load += packets[0].load

        return res

    def to_future(self) -> IcmpPacketFuture:
        return self.identifier

    def build(self):
        if len(self.load) > LOAD_SIZE_LIMIT:
            raise ValueError("build packet too large")

        load = (
            self.identifier.to_bytes()
            + self.data_slice_cnt.to_bytes(8, "big", signed=True)
            + self.load
        )
        packet = IP(dst=self.ip) / ICMP(type=0, code=114, id=514, seq=1919) / load
        # print(packet.summary())
        return packet

    def parse(packet) -> Optional["IcmpData"]:
        if packet.haslayer(ICMP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            code = packet[ICMP].code
            id = packet[ICMP].id
            seq = packet[ICMP].seq

            if not (int(code) == 114 and int(id) == 514 and int(seq) == 1919):
                return None

            icmp = packet[ICMP]

            indentifier, data = IcmpPacketFuture.from_bytes(icmp.data)
            slice_cnt = int.from_bytes(data[:8], "big", signed=True)
            res = IcmpData(src_ip, indentifier.port, indentifier, data)
            res.data_slice_cnt = slice_cnt
            return res
        return None

    def response(self, load) -> "IcmpData":
        packet = IcmpData(self.identifier.ip, 0, self.identifier, load)
        return packet


class IcmpCapture:
    def __init__(self, send_to: PipeConnection):
        self.send_to = send_to
        self.listener = threading.Thread(
            target=lambda: sniff(
                prn=self.handle_income, filter=f"icmp and (dst host {Local_ip})"
            )
        )

        self.listener.start()

    def new() -> PipeConnection:
        r, w = Pipe()
        IcmpCapture(w)
        return r

    def handle_income(self, packet):
        data = IcmpData.parse(packet)
        if data is not None:
            try:
                self.send_to.send(data)
            except Exception as e:
                print("IcmpCapture err:", e)


class IcmpDataMerger:
    def __init__(self, recv: PipeConnection, send: PipeConnection):
        self.recv = recv
        self.send = send
        self.buffer: dict[IcmpPacketFuture, tuple[int, list[IcmpData]]] = {}
        threading.Thread(target=self.merge_packets, daemon=True).start()

    def new(recv: PipeConnection) -> PipeConnection:
        r, w = Pipe()
        IcmpDataMerger(recv, w)
        return r

    def merge_packets(
        self,
    ):
        while True:
            try:
                pack: IcmpData = self.recv.recv()
            except Exception as e:
                print("IcmpDataMerger ending:", e)
                break

            identifier = pack.identifier

            if self.buffer.get(identifier) is None:
                self.buffer[identifier] = (0, [])

            buffer = self.buffer[identifier]

            if pack.data_slice_cn < 0:
                pack.data_slice_cnt = buffer[0] = -pack.data_slice_cnt

            buffer[1].append(pack)

            if buffer[0] > 0 and len(buffer[1]) == buffer[0]:
                buffer[1].sort(key=lambda x: x.data_slice_cnt)
                try:
                    self.send.send(IcmpData.shrink(buffer[1]))
                except EOFError:
                    break
                finally:
                    self.buffer.pop(identifier)


class IcmpHost:
    def __init__(self, recv: PipeConnection):
        self.seq_per_ip: dict[str, int] = {}
        self.waiting_for_response: dict[IcmpPacketFuture, PipeConnection] = {}
        self.servers: dict[int, Callable] = {}
        self.recv: PipeConnection = recv

        threading.Thread(target=self.handle_income, daemon=True).start()

    def bind(self, port: int, callback) -> None:
        if port in self.servers:
            raise ValueError("port already in use")
        self.servers[port] = callback

    def request(self, dst: str, port: int, load: bytes) -> PipeConnection:
        r, w = Pipe()
        self.request_to_pipe(dst, port, load, w)
        return r

    def request_to_pipe(
        self, dst: str, port: int, load: bytes, response_to: PipeConnection
    ):
        seq: int = self.seq_per_ip.get(dst, random.randint(0, 1 << 48))
        self.seq_per_ip[dst] = seq + 1
        packet = IcmpData(dst, port, IcmpPacketFuture(Local_ip, port, seq), load)

        self.waiting_for_response[packet.to_future()] = response_to

        for pac in packet.split():
            send(pac.build(), verbose=0)

    def send_response(self, packet: IcmpData):
        for pac in packet.split():
            send(pac.build(), verbose=0)

    def handle_income(self):
        while True:
            try:
                pack: IcmpData = self.recv.recv()
            except Exception as e:
                print("IcmpHost ending:", e)
            future = pack.to_future()
            if pack.port == 0:
                if self.waiting_for_response.get(future) is not None:
                    try:
                        self.waiting_for_response[future].send(pack)
                    except Exception as e:
                        print("IcmpHost err:", e)
                        pass
                    # self.waiting_for_response.pop(future)
                    del self.waiting_for_response[future]
            else:
                try:
                    threading.Thread(
                        target=lambda: self.send_response(
                            pack.response(self.servers[pack.port](pack))
                        )
                    ).start()
                except Exception as e:
                    print("IcmpHost err:", e)


def display_server(request: IcmpData) -> bytes:
    print(request)
    return request.load


if __name__ == "__main__":
    a = IcmpHost(IcmpDataMerger.new(IcmpCapture.new()))
    a.bind(10068, display_server)

    a.request("192.168.1.1", 10068, b"hello world" * 1000)
