import socket

class FtpAnonLoginScanner:
    def __init__(self, target, port=21, timeout=5):
        self.target = target
        self.port = port
        self.timeout = timeout

    def check_anon_login(self):
        try:
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                response = self._recv_response(sock)
                if "220" in response:
                    sock.sendall(b"USER anonymous\r\n")
                    response = self._recv_response(sock)
                    if "331" in response:  # Şifre isteniyor mu kontrol et
                        sock.sendall(b"PASS anonymous\r\n")
                        response = self._recv_response(sock)
                        if "230" in response:
                            return True
        except socket.timeout:
            pass
        except socket.error as e:
            pass
        return False

    def _recv_response(self, sock):
        return sock.recv(4096).decode('utf-8', 'ignore').strip()



"""target_ip = "124.221.60.110"
scanner = FtpAnonLoginScanner(target_ip)
if scanner.check_anon_login():
    print(f"[+] Anonymous FTP login possible at {target_ip}.")
else:
    print(f"[+] Anonymous FTP login does not possible at {target_ip}.")
"""