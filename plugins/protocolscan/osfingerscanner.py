import ssl
import socket
from colorama import Style, init, Fore
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class OSFingerprintScanner:
    def __init__(self, target, timeout=3):
        self.target = target
        self.timeout = timeout

    def guess_os(self):
        common_ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            80,    # HTTP
            110,   # POP3
            139,   # smb
            143,   # IMAP
            443,   # HTTPS
            445,   # smb
            3389,  # RDP
            8080,  # HTTP alternative
            8443   # HTTPS alternative
        ]
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.connect((self.target, port))
                    request = self.prepare_request(port)
                    sock.send(request)
                    response = sock.recv(4096).decode('utf-8', 'ignore').strip()
                    os_guess = self.parse_os_from_response(response)
                    if os_guess != "Unknown":
                        return os_guess
            except Exception as e:
                continue
        return "Unknown"

    def prepare_request(self, port):
        # Differentiate requests based on the port
        if port in [80, 8080]:  # HTTP
            return b"HEAD / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n"
        elif port in [443, 8443]:  # HTTPS
            # Initiate a basic TLS handshake - this is a simplistic approach
            context = ssl.create_default_context()
            with socket.create_connection((self.target, port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    return ssock.version().encode()  # Just get the TLS version as a basic example
        elif port == 22:  # SSH
            return b"\r\n"  # Banner grab for SSH
        elif port == 21:  # FTP
            return b"HELP\r\n"  # FTP HELP command for banner/info grab
        elif port == 25:  # SMTP
            return b"EHLO " + self.target.encode() + b"\r\n"  # EHLO command for SMTP
        elif port == 110:  # POP3
            return b"USER test\r\n"  # POP3 USER command for initial interaction
        elif port == 143:  # IMAP
            return b"a1 LOGIN user pass\r\n"  # IMAP LOGIN command for initial interaction
        elif port == 161:  # SNMP
            return b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x67\x45\x23\x02\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"  # SNMP GET request
        elif port == 3389:  # RDP
            return b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"  # RDP initial connection request
        elif port == 53:  # DNS
            return b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"  # DNS standard query
        else:
            return b"HEAD / HTTP/1.0\r\n\r\n"

    def parse_os_from_response(self, response):
        windows_keywords      = ["Microsoft", "IIS", "Windows", "Win32", "Win64", "ASP.NET", "NT", "Outlook", "Exchange", "SMB"]
        unix_linux_keywords   = ["Apache", "Debian", "Ubuntu", "Fedora", "Red Hat", "CentOS", "Unix", "Linux", "nginx", "OpenSSH","Postfix", "CUPS", "SUSE", "Gentoo", "Slackware"]
        cisco_keywords        = ["Cisco", "IOS", "Catalyst", "ASA", "Nexus", "Meraki", "Aironet", "WebEx"]
        iot_keywords          = ["IoT", "SmartHome", "Netcam", "ESP8266", "ESP32", "Arduino", "Raspberry Pi", "HomeKit", "Z-Wave", "Zigbee"]
        dell_server_keywords  = ["Dell", "PowerEdge", "EqualLogic", "Compellent", "Force10", "EMC"]
        vmware_keywords       = ["VMware", "ESXi", "vSphere", "Workstation", "Fusion", "Horizon"]
        apple_keywords        = ["Mac OS", "MacOS", "Apple", "Darwin", "iMac", "MacBook", "AirPort", "Safari"]
        android_keywords      = ["Android", "Google", "Pixel", "Nexus", "Galaxy", "HTC"]
        aws_keywords          = ["Amazon", "AWS", "EC2", "Elastic Beanstalk", "S3"]
        azure_keywords        = ["Azure", "Microsoft", "Windows Azure", "Azure DevOps", "Azure Active Directory"]
        google_cloud_keywords = ["Google Cloud", "GCP", "Google Compute Engine", "App Engine", "GKE"]
        cloudflare_keywords   = ["Cloudflare", "CF-RAY", "cloudflare-nginx", "CF-Cache-Status"]

        if any(keyword in response for keyword in windows_keywords):
            return "Windows"
        elif any(keyword in response for keyword in unix_linux_keywords):
            return "Unix/Linux"
        elif any(keyword in response for keyword in cisco_keywords):
            return "Cisco Device"
        elif any(keyword in response for keyword in iot_keywords):
            return "IoT Device"
        elif any(keyword in response for keyword in dell_server_keywords):
            return "Dell Server"
        elif any(keyword in response for keyword in vmware_keywords):
            return "VMware Server"
        elif any(keyword in response for keyword in apple_keywords):
            return "Apple Device"
        elif any(keyword in response for keyword in android_keywords):
            return "Android Device"
        elif any(keyword in response for keyword in aws_keywords):
            return "AWS Cloud"
        elif any(keyword in response for keyword in azure_keywords):
            return "Azure Cloud"
        elif any(keyword in response for keyword in google_cloud_keywords):
            return "Google Cloud"
        elif any(keyword in response for keyword in cloudflare_keywords):
            return "Cloudflare Service"
        else:
            return "Unknown"