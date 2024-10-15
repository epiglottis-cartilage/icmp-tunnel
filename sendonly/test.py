from multiprocessing.connection import PipeConnection
from typing import Optional, Callable
from scapy.all import IP, ICMP, Raw, send, AsyncSniffer, sniff
from multiprocessing import Pipe
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

LOAD_SIZE_LIMIT = 1415


class IcmpPacketFuture:
    """
    由发送者管理
    用于区分不同包
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
        port = int.from_bytes(data[:4], "big")
        sequence = int.from_bytes(data[4:12], "big")
        return IcmpPacketFuture(ip, port, sequence), data[12:]

    def __str__(self):
        return f"{self.ip}:{self.port}:{self.sequence}"

    def __hash__(self):
        return hash((self.ip, self.port, self.sequence))

    def __eq__(self, other):
        return (
            self.ip == other.ip
            and self.port == other.port
            and self.sequence == other.sequence
        )


class IcmpData:
    """
    自定义协议
    使用icmp原有字段区分: type=0, code=114, id=514
    数据部分头部：

    port: u32
    data_slice_cnt: u64
    identifier: unfixed length
    """

    ip: str
    port: int
    data_slice_cnt: int

    identifier: IcmpPacketFuture

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
        """
        合并数据包
        传入sort后的数据包列表（第一个data_slice_cnt为负数）
        """
        if len(packets) == 0:
            raise ValueError("empty packet list")
        packets.sort(key=lambda x: x.data_slice_cnt)

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
            self.port.to_bytes(4, "big")
            + self.data_slice_cnt.to_bytes(8, "big", signed=True)
            + self.identifier.to_bytes()
            + self.load
        )
        packet = (
            IP(dst=self.ip)
            / ICMP(type=0, code=114, id=514, seq=self.identifier.sequence & 0xFFFF)
            / load
        )
        # print(packet.summary())
        return packet

    def parse(packet) -> Optional["IcmpData"]:
        if packet.haslayer(ICMP):
            src_ip = packet[IP].src
            # dst_ip = packet[IP].dst

            code = packet[ICMP].code
            id = packet[ICMP].id
            # seq = packet[ICMP].seq

            if not (int(code) == 114 and int(id) == 514):
                return None

            load = packet[Raw].load

            port = int.from_bytes(load[:4], "big")
            slice_cnt = int.from_bytes(load[4:12], "big", signed=True)

            indentifier, data = IcmpPacketFuture.from_bytes(bytes(load[12:]))
            res = IcmpData(src_ip, port, indentifier, data)

            res.data_slice_cnt = slice_cnt
            return res
        return None

    def response(self, load) -> "IcmpData":
        packet = IcmpData(self.identifier.ip, 0, self.identifier, load)
        return packet

    def __str__(self):
        return f"IcmpData({self.ip}:{self.port}, {self.identifier}, {self.data_slice_cnt}\n {self.load})"


class IcmpCapture:
    """
    抓包
    """

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
    """
    合并同一个 identifier 的数据包
    """

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
            # print("Merger recv", pack)
            identifier = pack.identifier

            if self.buffer.get(identifier) is None:
                self.buffer[identifier] = 0, []

            size, buffer = self.buffer[identifier]

            if pack.data_slice_cnt < 0:
                size = -pack.data_slice_cnt

            buffer.append(pack)

            self.buffer[identifier] = size, buffer

            if size > 0 and len(buffer) == size:
                buffer.sort(key=lambda x: x.data_slice_cnt)
                try:
                    self.send.send(IcmpData.shrink(buffer))
                except EOFError:
                    break
                finally:
                    self.buffer.pop(identifier)


class IcmpHost:
    """
    分离开不同端口
    """

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
                break
            future = pack.to_future()
            if pack.port == 0:
                if self.waiting_for_response.get(future) is not None:
                    try:
                        self.waiting_for_response[future].send(pack.load)
                    except Exception as e:
                        print("IcmpHost err:", e)
                        pass
                    # self.waiting_for_response.pop(future)
                    del self.waiting_for_response[future]
            else:
                if pack.port not in self.servers:
                    print("IcmpHost: port not found", pack.port)
                    continue
                try:
                    threading.Thread(
                        target=lambda: self.send_response(
                            pack.response(self.servers[pack.port](pack))
                        )
                    ).start()
                except Exception as e:
                    print("IcmpHost err:", e)


def debug_server(request: IcmpData) -> bytes:
    """
    server 接受IcmDdata, 返回bytes
    """
    print("\n [Server] recv:", request)
    return (
        b"response to "
        + request.load[:5]
        + b"... "
        + f"(len={len(request.load)})".encode()
    )


if __name__ == "__main__":
    a = IcmpHost(IcmpDataMerger.new(IcmpCapture.new()))
    a.bind(10086, debug_server)
    i = 0
    while True:
        pip = a.request(input("dst:"), 10086, (str(i) * 2000).encode())
        print(pip.recv())
        i += 1
