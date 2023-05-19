# Port Scanner

This is a Python command line tool for scanning open ports on a target machine. The tool allows the user to specify a range of ports, a specific port, or a comma-separated list of ports. It also allows the user to specify the number of threads to use for scanning.
You can also find the use of the tool on my youtube address.
## Installation

1. Clone the repository:
    ```
    git clone https://github.com/HalilDeniz/Port-scanner.git
    ```
2. Install the required packages:
    ```
    pip install -r requirements.txt
    ```

## Usage

```
root@denizhalil:~/Port-scanner# python3 scanner.py --help
usage: scanner.py [-h] [-p PORTS] [-t THREADS] [-P {tcp,udp}] [-V] [-s SAVE_RESULTS] [-c] target

Port Scan Tool

positional arguments:
  target                Target IP address or domain name

options:
  -h, --help            show this help message and exit
  -p PORTS, --ports PORTS
                        Ports to scan (e.g. 1-1024 or 21,22,80 or 80)
  -t THREADS, --threads THREADS
                        Number of threads to use
  -P {tcp,udp}, --protocol {tcp,udp}
                        Protocol to use for scanning
  -V, --version-info    Used to get version information
  -s SAVE_RESULTS, --save-results SAVE_RESULTS
                        File to save scan results
  -c, --ping-check      Perform ping check before scanning

Example Uses:
python3 scanner.py 192.168.1.4
python3 scanner.py example.com -p 1-1024 --threads 20
python3 scanner.py example.com -p 21,22,80,443 --protocol tcp
python3 scanner.py 192.168.1.1 -p 80 --threads 5 --protocol udp
python3 scanner.py example.com -p 1-65535 -t 50 -P tcp -V
python3 scanner.py example.com -p 80,443,8080,8443 --threads 20 --protocol tcp --version-info
```
## OUTPUT EXAMPLE

```

┌──(root💀hackerevreni)-[/home/kali]
└─# python3 scanner.py -p 21-5500 -t 100 192.168.1.5 -V
********************************************
ip address    : 192.168.1.5
host address  : 192.168.1.5
ports address : 21-5500
threads value : 100
Port        Status   Service        VERSION
25  /tcp     open     smtp           220 metasploitable.localdomain ESMTP Postfix (Ubuntu)
22  /tcp     open     telnet         SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
21  /tcp     open     ftp            220 (vsFTPd 2.3.4)
80  /tcp     open     http           HTTP/1.1 400 Bad Request
23  /tcp     open     telnet          #' 
512 /tcp     open     exec           Where are you?
513 /tcp     open     login          
1524/tcp     open     ingreslock     root@metasploitable:/#
2121/tcp     open     iprop          220 ProFTPD 1.3.1 Server (Debian) [::ffff:192.168.1.5]
3306/tcp     open     mysql          >
Scan time: 0 minute 1.16 second
********************************************
```
## New Features

- **Ping Check**: Added the `-c` or `--ping-check` flag to perform a ping check before scanning. If the host is unreachable, the program will skip the port scan for that host.


## Contributing
Contributions are welcome! To contribute to Port-scanner, follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push your changes to your forked repository.
5. Open a pull request in the main repository.


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

- LinkedIn: https://www.linkedin.com/in/halil-ibrahim-deniz/
- TryHackMe: https://tryhackme.com/p/halilovic
- Instagram: https://www.instagram.com/deniz.halil333/
- YouTube: https://www.youtube.com/c/HalilDeniz
- Email: halildeniz313@gmail.com
