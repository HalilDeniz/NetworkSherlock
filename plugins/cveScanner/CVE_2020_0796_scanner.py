import socket
import struct
from colorama import Style,Fore,init

init(autoreset=True)

class SMBVulnerabilityChecker:
    def __init__(self, ip_address):
        self.ip_address = ip_address
        self.socket = None

    def connect(self):
        self.socket = socket.socket(socket.AF_INET)
        self.socket.settimeout(3)
        try:
            self.socket.connect((self.ip_address, 445))
            return True
        except Exception as e:
            return False

    def send_packet(self):
        pkt = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
        self.socket.send(pkt)

    def check_vulnerability(self):
        try:
            response = self.socket.recv(4)
            if len(response) != 4:
                return False

            nb, = struct.unpack(">I", response)
            res = self.socket.recv(nb)

            if not res[68:70] == b"\x11\x03" or not res[70:72] == b"\x02\x00":
                return False
            else:
                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Vulnerable CVE-2020-0796       :{Fore.BLUE} https://www.exploit-db.com/exploits/48537{Style.RESET_ALL}")
                return True
        except Exception as e:
            return False

    def close(self):
        if self.socket:
            self.socket.close()

"""
if __name__ == "__main__":
    ip_address = input("Enter IP address: ")
    checker = SMBVulnerabilityChecker(ip_address)

    if checker.connect():
        checker.send_packet()
        checker.check_vulnerability()

    checker.close()
"""