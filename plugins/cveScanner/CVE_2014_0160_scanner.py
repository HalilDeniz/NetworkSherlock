import socket
import struct
import os
import ssl
import ssl
class HeartbleedScanner:
    def __init__(self, target, port=443, timeout=5):
        self.target = target
        self.port = port
        self.timeout = timeout

    def construct_client_hello(self):
        hello_version = b'\x03\x02'  # TLS 1.1
        random = os.urandom(32)
        session_id = b'\x00'
        cipher_suite = b'\x00\x02\x01\x00'  # TLS_RSA_WITH_RC4_128_SHA
        compression_method = b'\x01\x00'  # Null compression

        client_hello = b'\x16' + hello_version + struct.pack('>H', len(random) + len(session_id) + len(cipher_suite) + len(compression_method) + 2) + random + session_id + cipher_suite + compression_method

        return client_hello

    def recvmsg(self, sock):
        hdr = sock.recv(5)
        if len(hdr) != 5:
            return None, None, None

        typ, ver, ln = struct.unpack('>BHH', hdr)
        pay = sock.recv(ln, socket.MSG_WAITALL)

        if len(pay) != ln:
            return None, None, None

        return typ, ver, pay

    def check_vulnerability(self):
        client_hello = self.construct_client_hello()
        try:
            with socket.create_connection((self.target, self.port), self.timeout) as sock:
                # SSLContext nesnesi ile SSL bağlantısı oluşturun
                context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
                context.set_ciphers('RC4-SHA')
                wrapped_sock = context.wrap_socket(sock, server_hostname=self.target)

                wrapped_sock.send(client_hello)
                while True:
                    typ, ver, pay = self.recvmsg(wrapped_sock)
                    if typ is None:
                        return False
                    if typ == 24:
                        return True
                    if typ == 21:
                        return False
        except Exception as e:
            return False

"""
adres = "https://162.144.114.246/"
scanner = HeartbleedScanner(adres)
vulnerable = scanner.check_vulnerability()
print(f"{adres} is vulnerable to Heartbleed: {vulnerable}")
"""