import argparse
import socket
import sys
import threading
import time
import subprocess
from queue import Queue
from rich import print


def format_scan_time(seconds):
    minutes, seconds = divmod(seconds, 60)
    return f"{int(minutes)} minute {seconds:.2f} seconds"


def banner_grabbing(ip, port, protocol):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.connect((ip, port))
        sock.send(b"HEAD / HTTP/1.1\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        return banner.split("\n")[0]
    except Exception as e:
        return ""


def port_scan(args, ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if args.protocol == 'tcp' else socket.SOCK_DGRAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    if result == 0:
        try:
            service = socket.getservbyport(port, args.protocol)
        except OSError:
            service = "unknown"
        banner = ""
        if args.version_info:
            banner = banner_grabbing(ip, port, args.protocol)
            print(f"{port:<4}/{args.protocol}     open     {service:<14} {banner}")
        else:
            print(f"{port:<4}/{args.protocol}     open     {service:<14}")
        if args.save_results:
            with open(args.save_results, "a") as file:
                file.write(f"{port}/{args.protocol}\topen\t{service}\t{banner}\n")
    sock.close()


def ping_check(ip):
    command = ["ping", "-c", "1", ip]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0


def thread_process(args, ip):
    while True:
        port = port_queue.get()
        if port is None:
            break
        if args.ping_check and not ping_check(ip):
            print(f"[-] Skipping port scan for {port}/{args.protocol}. Host is unreachable.")
        else:
            port_scan(args, ip, port)
        port_queue.task_done()


def main():
    parser = argparse.ArgumentParser(description='Port Scan Tool',
                                     epilog='''Example Uses:
        python3 scanner.py 192.168.1.4
        python3 scanner.py example.com -p 1-1024 --threads 20
        python3 scanner.py example.com -p 21,22,80,443 --protocol tcp
        python3 scanner.py 192.168.1.1 -p 80 --threads 5 --protocol udp
        python3 scanner.py example.com -p 1-65535 -t 50 -P tcp -V
        python3 scanner.py example.com -p 80,443,8080,8443 --threads 20 --protocol tcp --version-info
        ''', formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('target', type=str, help='Target IP address or domain name')
    parser.add_argument('-p', '--ports', type=str, default='1-1000', help='Ports to scan (e.g. 1-1024 or 21,22,80 or 80)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads to use')
    parser.add_argument('-P', '--protocol', type=str, default='tcp', choices=['tcp', 'udp'], help='Protocol to use for scanning')
    parser.add_argument('-V', '--version-info', action='store_true', help='Used to get version information')
    parser.add_argument('-s', '--save-results', type=str, help='File to save scan results')
    parser.add_argument('-c', '--ping-check', action='store_true', help='Perform ping check before scanning')
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[red]Target: {args.target} not found[/red]")
        sys.exit(1)

    print("********************************************")
    print(f"[cyan]ip address    :[/cyan] {ip}")
    print(f"[cyan]host address  :[/cyan] {args.target}")
    print(f"[cyan]ports address :[/cyan] {args.ports}")
    print(f"[cyan]threads value :[/cyan] {args.threads}")
    if args.version_info:
        print(f"[red]Port        Status   Service        VERSION[/red]")
    else:
        print(f"[red]Port        Status   Service[/red]")

    if args.ping_check and not ping_check(ip):
        print(f"[-] Host {args.target} is unreachable. Aborting scan.")
        sys.exit(1)

    if "-" in args.ports:
        start_port, end_port = map(int, args.ports.split('-'))
        ports = range(start_port, end_port + 1)
    elif "," in args.ports:
        ports = map(int, args.ports.split(','))
    elif args.ports.isdigit():
        ports = [int(args.ports)]
    else:
        print("[red]Invalid port format. Use: 1-1024, 21,22,80, or 80[/red]")
        sys.exit(1)

    start_time = time.time()

    global port_queue
    port_queue = Queue()
    for port in ports:
        port_queue.put(port)

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=thread_process, args=(args, ip))
        t.start()
        threads.append(t)

    for _ in range(args.threads):
        port_queue.put(None)

    for t in threads:
        t.join()

    end_time = time.time()
    scan_time = end_time - start_time
    formatted_time = format_scan_time(scan_time)

    print(f"[cyan]Scan time:[/cyan] {formatted_time}")
    print("********************************************")


if __name__ == '__main__':
    main()
