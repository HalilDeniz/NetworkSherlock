import socket
from struct import pack
from colorama import Fore, Style, init

init(autoreset=True)


class BlueKeepScanner:
    def __init__(self, ip_address, port=3389):
        self.ip_address = ip_address
        self.port = port

    def scan_for_bluekeep(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            try:
                s.connect((self.ip_address, self.port))
                pkt = b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00'
                s.send(pkt)
                response = s.recv(1024)

                if response and b"\x03\x00\x00\x13\x0e\xd0" in response:
                    print(
                        f"{Fore.GREEN}[+]{Style.RESET_ALL} Vulnerable CVE-2019-0708       : {Fore.BLUE}https://www.exploit-db.com/exploits/47416{Style.RESET_ALL}")
                else:
                    pass
            except Exception as e:
                pass

"""
# Örnek Kullanım
bluekeep_scanner = BlueKeepScanner("43.143.173.245")
bluekeep_scanner.scan_for_bluekeep()
"""