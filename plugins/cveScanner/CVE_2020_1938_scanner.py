import socket

class GhostcatScanner:
    def __init__(self, target, port=8009, timeout=5):
        self.target = target
        self.port = port
        self.timeout = timeout

    def check_vulnerability(self):
        # Apache JServ Protocol (AJP) request packet for Ghostcat vulnerability
        ajp_request = bytearray([
            0x12, 0x34, 0x00, 0x08, 0x48, 0x54, 0x54, 0x50, 0x31, 0x2e, 0x31, 0x00, 0x0A, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00
        ])

        try:
            with socket.create_connection((self.target, self.port), self.timeout) as sock:
                sock.sendall(ajp_request)
                response = sock.recv(1024)
                if response:
                    return True  # Vulnerable
        except Exception as e:
            pass
        return False

"""
target= "10.0.2.81"
scanner = GhostcatScanner(target)
print(scanner.check_vulnerability())
"""