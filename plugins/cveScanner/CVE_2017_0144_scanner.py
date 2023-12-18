import socket
import struct
from struct import pack
from colorama import Fore, Style, init

init(autoreset=True)

class EternalBlueScanner:
    def __init__(self, ip_address):
        self.ip_address = ip_address
        self.smb_ports = [139, 445]

    def scan_for_eternalblue(self):
        for port in self.smb_ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                try:
                    s.connect((self.ip_address, port))
                    pkt = b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x17\x02'
                    pkt += b'\x00\xe0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    pkt += b'\x00\x00\x24\x00\x01\x00\x31\x00\x02\x00\x01\x00\x00\x00\x00\x00'
                    pkt += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x00\x00\x00\x60\x00\x04\x00'
                    pkt += b'\x02\x00\x31\x00\x00\x05\x00\x0e\x03\x10\x00\x00\x00\x00\x00\x00\x00'
                    pkt += b'\x00\x00\x00\x00\x00'
                    s.send(pkt)
                    nb, = struct.unpack(">I", s.recv(4))
                    res = s.recv(nb)
                    if res[9:13] == b'\x11\x03\x02\x00':
                        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {self.ip_address} is vulnerable to EternalBlue (CVE-2017-0144) on port {port}")
                    else:
                        pass
                except Exception as e:
                    pass