import ssl
import socket
from datetime import datetime

class TLSCertScanner:
    def __init__(self, target, port=443, timeout=5):
        self.target = target
        self.port = port
        self.timeout = timeout

    def get_certificate_details(self):
        context = ssl.create_default_context()
        with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                cert = ssock.getpeercert()
                return self.parse_certificate(cert)

    def parse_certificate(self, cert):
        if not cert:
            return None

        # Sertifikanın 'subject' ve 'issuer' alanlarını ayrıştırma
        subject = dict(x[0] for x in cert['subject'])
        issuer = dict(x[0] for x in cert['issuer'])

        # 'CN' (Common Name) veya alternatif anahtarları kontrol etme
        subject_cn = subject.get('commonName', subject.get('organizationName', 'Unknown'))
        issuer_cn = issuer.get('commonName', issuer.get('organizationName', 'Unknown'))

        details = {
            'subject': subject_cn,
            'issuer': issuer_cn,
            'valid_from': cert['notBefore'],
            'valid_to': cert['notAfter'],
            'version': cert.get('version'),
            'serial_number': cert.get('serialNumber')
        }
        return details
