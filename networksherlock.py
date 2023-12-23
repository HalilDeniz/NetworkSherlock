#!/usr/bin/env python

import sys
import socket
import argparse
import threading
import ipaddress
import subprocess
from queue import Queue
from colorama import Fore, Style, init

from core.modules.arpdiscover import ArpDiscover
from plugins.cveScanner.CVE_2020_0796_scanner import SMBVulnerabilityChecker
from plugins.cveScanner.CVE_2014_6271_scanner import ShellshockScanner
from plugins.cveScanner.CVE_2017_0144_scanner import EternalBlueScanner
from plugins.cveScanner.CVE_2019_0708_scanner import BlueKeepScanner
from plugins.cveScanner.CVE_2017_5638_scanner import ApacheStrutsScanner

from plugins.protocolscan.ftpanonloginscanner import FtpAnonLoginScanner
from plugins.protocolscan.sllscanner import TLSCertScanner
from plugins.protocolscan.osfingerscanner import OSFingerprintScanner

from plugins.onlinescanner.shodanscanner import ShodanScanner

#from plugins.protocolscan.smbscanner import SMBScanner

init(autoreset=True)

class NetworkSherlock:
    def __init__(self, targets, ports, threads=10, protocol='tcp', version_info=False, save_results=None, ping_check=False, config_file='config/networksherlock.cfg', use_shodan=False):
        self.targets = targets
        self.ports = ports
        self.threads = threads
        self.protocol = protocol
        self.version_info = version_info
        self.save_results = save_results
        self.ping_check = ping_check
        self.ip = None
        self.config_file = config_file
        self.use_shodan = use_shodan
        self.ssl_cert_details = {}
        if self.use_shodan:
            self.shodan_scanner = ShodanScanner(self.config_file)
        else:
            self.shodan_scanner = None

    def format_scan_time(self, seconds):
        minutes, seconds = divmod(seconds, 60)
        return f"{int(minutes)} minute {seconds:.2f} seconds"

    def banner_grabbing(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((ip, port))
            if port == 80 or port == 443:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port == 21:
                sock.send(b"USER anonymous\r\n")
            elif port == 22:
                sock.send(b"SSH-2.0-OpenSSH_7.3\r\n")
            elif port == 25:
                sock.send(b"HELO " + ip.encode() + b"\r\n")
            elif port == 23:
                sock.send(b"\xFF\xFD\x18\xFF\xFD\x20\xFF\xFD\x23\xFF\xFD\x27\xFF\xFA\x1F\x00\x50\x00\x18\xFF\xF0")
            elif port == 3306:
                sock.send(b"\x05\x00\x00\x01\x85\xa6\x03\x00\x00\x00\x00\x21\x00\x00\x00\x02\x3f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
            elif port == 139 or port == 445:
                sock.send(b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x17\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2f\x4b\x00\x00\x00\x00\x00\x31\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner.split("\n")[0]
        except Exception as e:
            return ""

    def port_scan(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if self.protocol == 'tcp' else socket.SOCK_DGRAM)
        sock.settimeout(1)
        result = sock.connect_ex((self.ip, port))

        if result == 0:
            try:
                service = socket.getservbyport(port, self.protocol)
            except OSError:
                service = "unknown"

            if port == 21:
                ftp_scanner = FtpAnonLoginScanner(self.ip)
                if ftp_scanner.check_anon_login():
                    self.ftp_anon_accessible.append(port)


            if port == 443 and self.version_info:
                tls_scanner = TLSCertScanner(self.ip)
                try:
                    cert_details = tls_scanner.get_certificate_details()
                    if cert_details:
                        self.ssl_cert_details[self.ip] = cert_details
                except Exception as e:
                    pass

            banner = ""
            shodan_info = ""
            if self.version_info:
                banner = self.banner_grabbing(self.ip, port)

            if self.use_shodan and self.shodan_scanner:
                shodan_result = self.shodan_scanner.perform_scan(socket.gethostbyname(self.ip))
                shodan_info = self.shodan_scanner.format_shodan_info(shodan_result)

            if self.use_shodan:
                port_info = f"{port:<4}/{self.protocol}     open     {service:<14} {banner}\n{Fore.BLUE}From Shodan:{Style.RESET_ALL}\n{shodan_info}"
            else:
                port_info = f"{port:<4}/{self.protocol}     open     {service:<14} {banner}"

            self.open_ports.append(port_info)
        sock.close()
    def ping_check(self):
        command = ["ping", "-c", "1", self.ip]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0

    def thread_process(self):
        while True:
            port = self.port_queue.get()
            if port is None:
                break
            self.port_scan(port)
            self.port_queue.task_done()

    def parse_targets(self, targets):
        parsed_targets = []
        for target in targets.split(','):
            if '/' in target or '-' in target:
                if '-' in target:
                    start_ip, end_ip = target.split('-')
                    start_ip = ipaddress.ip_address(start_ip)
                    end_ip = ipaddress.ip_address(end_ip)
                    while start_ip <= end_ip:
                        parsed_targets.append(str(start_ip))
                        start_ip += 1
                else:  # CIDR Notation
                    for ip in ipaddress.ip_network(target, strict=False):
                        parsed_targets.append(str(ip))
            else:
                parsed_targets.append(target.strip())
        return parsed_targets

    def scan(self):
        if self.targets is None:
            print("Missing target argument. Use --help for more information.")
            return
        targets = self.parse_targets(self.targets)
        for target in targets:
            self.ip = target
            self.open_ports = []
            self.ftp_anon_accessible = []

            if self.ping_check and not self.ping_check():
                continue

            # Port listesi oluştur
            if "-" in self.ports:
                start_port, end_port = map(int, self.ports.split('-'))
                ports = range(start_port, end_port + 1)
            elif "," in self.ports:
                ports = map(int, self.ports.split(','))
            elif self.ports.isdigit():
                ports = [int(self.ports)]
            else:
                print("[red]Invalid port format.[/red]")
                continue

            # Thread'leri başlat
            self.port_queue = Queue()
            for port in ports:
                self.port_queue.put(port)

            threads = []
            for _ in range(self.threads):
                t = threading.Thread(target=self.thread_process)
                t.start()
                threads.append(t)

            for _ in range(self.threads):
                self.port_queue.put(None)

            for t in threads:
                t.join()

            # Açık portları yazdır
            if self.open_ports:
                print(f"********************************************")
                print(f"{Fore.GREEN}Scanning target:{Style.RESET_ALL} {target}")
                print(f"{Fore.GREEN}Scanning IP    :{Style.RESET_ALL} {socket.gethostbyname(self.ip)}")
                print(f"{Fore.GREEN}Ports          :{Style.RESET_ALL} {self.ports}")
                print(f"{Fore.GREEN}Threads        :{Style.RESET_ALL} {self.threads}")
                print(f"{Fore.GREEN}Protocol       :{Style.RESET_ALL} {self.protocol}")
                print(f"---------------------------------------------")
                if self.version_info:
                    print(f"{Fore.RED}Port        Status   Service           VERSION{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Port        Status   Service{Style.RESET_ALL}")

            for port_info in self.open_ports:
                print(port_info)

            if self.version_info and self.ftp_anon_accessible:
                for port in self.ftp_anon_accessible:
                    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Anonymous FTP login possible at: {Fore.BLUE}{self.ip}:{port}{Style.RESET_ALL}")

            if args.os_fingerprint and self.open_ports:
                os_scanner = OSFingerprintScanner(self.ip)
                os_guess = os_scanner.guess_os()
                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} OS Guess for The               : {Fore.BLUE}{os_guess}{Style.RESET_ALL}")

            if args.vuln and '445' in self.ports.split(','):
                vuln_checker = SMBVulnerabilityChecker(self.ip)
                if vuln_checker.connect():
                    vuln_checker.send_packet()
                    vuln_checker.check_vulnerability()
                    vuln_checker.close()


            if self.ip in self.ssl_cert_details:
                cert_details = self.ssl_cert_details[self.ip]
                if "error" not in cert_details:
                    print(f"{Fore.GREEN}[+] {Style.RESET_ALL}SSL/TLS Certificate Details    : {Fore.BLUE}{self.ip}{Style.RESET_ALL}")
                    for key, value in cert_details.items():
                        print(f"\t{Fore.GREEN}{key:<13}:{Style.RESET_ALL} {value}")
                else:
                    pass

            if args.vuln:
                for port in [80, 443]:
                    full_url = f"https://{self.ip}/cgi-bin/test.cgi" if port == 443 else f"http://{self.ip}/cgi-bin/test.cgi"
                    shellshock_scanner = ShellshockScanner(full_url)
                    shellshock_scanner.scan_for_shellshock()

            if args.vuln and ("3389" in self.ports or "-" in self.ports):
                bluekeep_scanner = BlueKeepScanner(self.ip)
                bluekeep_scanner.scan_for_bluekeep()

            if args.vuln:
                smb_ports = [139, 445]
                for port in smb_ports:
                    if str(port) in self.ports or '-' in self.ports:
                        eternal_blue_scanner = EternalBlueScanner(self.ip)
                        eternal_blue_scanner.scan_for_eternalblue()

            if args.vuln and ("80" in self.ports or "443" in self.ports or "-" in self.ports):
                struts_scanner = ApacheStrutsScanner(f"http://{self.ip}")
                struts_scanner.scan_for_apache_struts()
                struts_scanner = ApacheStrutsScanner(f"https://{self.ip}")
                struts_scanner.scan_for_apache_struts()



            if self.save_results:  # Sonuçları dosyaya yaz
                with open(self.save_results, "a") as file:
                    file.write(f"********************************************\n")
                    file.write(f"Scanning target: {target}\n")
                    file.write(f"Scanning IP    : {socket.gethostbyname(self.ip)}\n")
                    file.write(f"Ports          : {self.ports}\n")
                    file.write(f"Threads        : {self.threads}\n")
                    file.write(f"Protocol       : {self.protocol}\n")
                    file.write(f"---------------------------------------------\n")
                    for port_info in self.open_ports:
                        file.write(f"{port_info}\n")
                    #file.write("---------------------------------------------\n")
        print(f"---------------------------------------------")


# Ana program akışı
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='NetworkSherlock: Port Scan Tool')
    parser.add_argument('target', type=str, nargs='?', help='Target IP address(es), range, or CIDR (e.g., 192.168.1.1, 192.168.1.1-192.168.1.5, 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', type=str, default='1-1000', help='Ports to scan (e.g. 1-1024, 21,22,80, or 80)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads to use')
    parser.add_argument('-P', '--protocol', type=str, default='tcp', choices=['tcp', 'udp'], help='Protocol to use for scanning')
    parser.add_argument('-V', '--version-info', action='store_true', help='Used to get version information')
    parser.add_argument('-s', '--save-results', type=str, help='File to save scan results')
    parser.add_argument('-c', '--ping-check', action='store_true', help='Perform ping check before scanning')
    parser.add_argument('-O','--os-fingerprint', action='store_true', help='Enable OS fingerprinting for each target (It may take a long time)')
    parser.add_argument('-v', '--vuln', action='store_true', help='Detect previously discovered vulnerabilities (It may take a long time)')
    parser.add_argument('-ad','--arp-discover', type=str, help='Perform ARP discovery on the specified network (e.g., 10.0.2.0/24)')
    parser.add_argument('-i', '--iface', type=str, help='Network interface to use for ARP discovery')
    parser.add_argument('--use-shodan', action='store_true', help='Enable Shodan integration for additional information')
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    if args.arp_discover and args.iface:
        arp_scanner = ArpDiscover(args.iface)
        devices = arp_scanner.scan(args.arp_discover)
        if devices:
            ip_width           = max(len(device['ip']) for device in devices) + 1
            mac_width          = max(len(device['mac']) for device in devices) + 1
            manufacturer_width = max(len(device['manufacturer']) for device in devices) + 1
            for device in devices:
                print(f"{Fore.CYAN}IP:{Style.RESET_ALL} {device['ip']:<{ip_width}} {Fore.CYAN}MAC:{Style.RESET_ALL} {device['mac']:<{mac_width}} {Fore.CYAN}Manufacturer:{Style.RESET_ALL} {device['manufacturer']:<{manufacturer_width}}")
        else:
            print("No devices found on the network.")
    elif args.arp_discover or args.iface:
        parser.error("ARP discovery requires both --arp-discover and --iface arguments.")
    else:
        scanner = NetworkSherlock(args.target, args.ports, args.threads, args.protocol, args.version_info, args.save_results, args.ping_check, use_shodan=args.use_shodan)
        scanner.scan()
