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
from core.modules.arpdiscover import ArpDiscover

from plugins.main import CVE_Scanner_Main

from plugins.protocolscan.ftpanonloginscanner import FtpAnonLoginScanner
from plugins.protocolscan.sllscanner import TLSCertScanner
from plugins.protocolscan.osfingerscanner import OSFingerprintScanner
from plugins.protocolscan.bannerScanner import BannerScanner
from plugins.onlinescanner.shodanscanner import ShodanScanner
from plugins.webScanner.robotsscanner import RobotsScanner
from plugins.webScanner.wafScanner import WAFDetector

#from plugins.protocolscan.smbscanner import SMBScanner

init(autoreset=True)


def read_ips_from_file(file_path):
    ips = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                ip = line.strip()
                if ip:  # Boş satırları atla
                    ips.append(ip)
    except FileNotFoundError:
        print(f"Error: File not found at '{file_path}'")
    except IOError:
        print(f"Error: Could not read file '{file_path}'")
    return ips



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
                banner_scanner = BannerScanner(self.ip, port)
                banner = banner_scanner.banner_grabbing()

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
        if args.ip_file:
            targets = read_ips_from_file(args.ip_file)
        elif self.targets:
            targets = self.parse_targets(self.targets)
        else:
            print("Missing target argument. Use --help for more information.")
            return

        try:
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
                    print(f"{Fore.RED}Invalid port format.{Style.RESET_ALLs}")
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

                if self.version_info and ('80' in self.ports.split(',') or '443' in self.ports.split(',')):
                    http_url = f"http://{self.ip}/robots.txt"
                    https_url = f"https://{self.ip}"

                    robots_scanner_https = RobotsScanner(https_url)
                    robots_result_https = robots_scanner_https.run_scan()
                    if robots_result_https:
                        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Robots.txt                     : {Fore.BLUE}{robots_result_https}{Style.RESET_ALL}")
                    else:
                        pass

                if args.waf and ('443' in self.ports.split(',')):
                    https_url = f"https://{self.ip}"

                    waf_detector_https = WAFDetector(https_url)
                    waf_result_https = waf_detector_https.detect_waf()
                    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} WAF Detection                  : {Fore.BLUE}{waf_result_https}{Style.RESET_ALL}")


                if self.version_info and self.ftp_anon_accessible:
                    for port in self.ftp_anon_accessible:
                        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Anonymous FTP login possible at: {Fore.BLUE}{self.ip}:{port}{Style.RESET_ALL}")

                if args.vuln:
                    cve_scanner = CVE_Scanner_Main(self.ip)
                    vuln_results = cve_scanner.run_all_scans(self.ports.split(','))
                    for vuln_name, is_vulnerable in vuln_results.items():
                        if is_vulnerable:
                            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {self.ip} is vulnerable to {vuln_name}")


                if args.os_fingerprint and self.open_ports:
                    os_scanner = OSFingerprintScanner(self.ip)
                    os_guess = os_scanner.guess_os()
                    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} OS Guess for The               : {Fore.BLUE}{os_guess}{Style.RESET_ALL}")



                if self.ip in self.ssl_cert_details:
                    cert_details = self.ssl_cert_details[self.ip]
                    if "error" not in cert_details:
                        print(f"{Fore.GREEN}[+] {Style.RESET_ALL}SSL/TLS Certificate Details    : {Fore.BLUE}{self.ip}{Style.RESET_ALL}")
                        for key, value in cert_details.items():
                            print(f"\t{Fore.GREEN}{key:<13}:{Style.RESET_ALL} {value}")
                    else:
                        pass

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
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Interrupted by user. The program is terminating...{Style.RESET_ALL}")
            for t in threads:
                t.join()
            sys.exit(0)

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
    parser.add_argument('--waf','--waf-detect', action='store_true', help='Detect Web Application Firewall (WAF) for each target')
    parser.add_argument('-f', '--ip-file', type=str, help='Read target IP addresses from a file')
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
