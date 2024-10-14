from multiprocessing.connection import PipeConnection
from scapy.all import IP, ICMP, Raw, send, AsyncSniffer
from multiprocessing import Process, Pipe
import time
import socket
import threading


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


class IcmpData:
    ip: str

    port: int
    seq: int

    load: bytes

    def __str__(self):
        return f"\n IcmpData{{ {self.ip}:{self.port} => {self.load} }}"

    def build(self):
        load = self.port.to_bytes(2, "big") + self.seq.to_bytes(8, "big") + self.load
        packet = IP(dst=self.ip) / ICMP(type=0, code=114, id=514, seq=1919) / load
        # print(packet.summary())
        return packet

    def resolve(packet):
        if not (
            packet[ICMP].type == 0
            and packet[ICMP].code == 114
            and packet[ICMP].id == 514
        ):
            return None

        res = IcmpData()
        res.ip = str(packet[IP].src)
        res.port = int.from_bytes(packet[Raw].load[:2], "big")
        res.seq = int.from_bytes(packet[Raw].load[2:10], "big")
        res.load = packet[Raw].load[10:]

        return res

    def to_future(self):
        return IcmpRecvFuture(self.ip, self.port, self.seq)


class IcmpRecvFuture:
    ip: str

    port: int
    seq: int

    def __init__(
        self,
        ip: str,
        port: int,
        seq: int,
    ):
        self.ip = ip
        self.port = port
        self.seq = seq

    def with_load(self, load: bytes):
        res = IcmpData()
        res.ip = self.ip
        res.port = self.port
        res.seq = self.seq
        res.load = load

        return res


class Server:
    def __init__(self, port):
        self.port = port
        self.incoming = list()
        self.pips = Pipe()

    def iter(self):
        return iter(self.incoming)


class IcmpHost:
    response_future: dict[IcmpRecvFuture, tuple[PipeConnection, float]] = dict()
    incoming_request: list[tuple[IcmpRecvFuture, bytes, float]] = list()
    count: int = 0

    handler: dict[int, PipeConnection] = dict()

    ttl = 120

    def __init__(self):
        # self.listener = AsyncSniffer(prn=self.handle_income, filter=f"icmp")
        self.listener = AsyncSniffer(
            prn=self.handle_income, filter=f"icmp and (dst host {Local_ip})"
        )
        self.listener.start()

        ttl_thread = threading.Thread(target=self.ttl_guild)
        ttl_thread.start()

    def bind(self, port: int) -> PipeConnection:
        server = Server(port)
        self.handler[server.port] = server.pips[0]
        return server.pips[1]

    def send_request(self, ip, port, data) -> None:
        self.request(ip, port, data)

    def response(self, future: IcmpRecvFuture, load) -> None:
        send(future.with_load(load).build(), verbose=0)

    def request(self, ip, port, load) -> IcmpRecvFuture:
        count = self.count
        self.count += 1
        future = IcmpRecvFuture(ip, port, count)

        self.response_future[future] = (None, time.time())

        send(future.with_load(load).build(), verbose=0)
        return future

    def handle_income(self, packet):
        data = IcmpData.resolve(packet)

        if data is None:
            return

        future = data.to_future()
        if future in self.response_future:
            self.response_future[future] = (data.load, time.time())
        else:
            # self.incoming_request.append((future, data.load, time.time()))
            self.handler[data.port].send(data)

    def check_recv(self, future: IcmpRecvFuture):
        if future in self.response_future:
            return self.response_future[future]
        else:
            return None, 0

    def ttl_guild(self):
        while True:
            time.sleep(10)
            # retain only packets in past 120 sec
            for future, (load, t) in list(self.response_future.items()):
                if time.time() - t > self.ttl:
                    self.response_future.pop(future)


def display(pip: PipeConnection):
    while True:
        data: IcmpData = pip.recv()
        print(data)


if __name__ == "__main__":
    a = IcmpHost()
    display_server = a.bind(514)
    threading.Thread(target=lambda: display(display_server)).start()

    a.send_request(input("dst:"), 514, b"hello")
    while True:
        pass
