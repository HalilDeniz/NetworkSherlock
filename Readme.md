# **NetworkSherlock: Porwerfull Port Scanning With Shodan**
<img src="img/NetworkSherlock1.png"></img>

**NetworkSherlock** is a powerful and flexible port scanning tool designed for network security professionals and penetration testers. 
With its advanced capabilities, NetworkSherlock can efficiently scan IP ranges, CIDR blocks, and multiple targets. 
It stands out with its detailed banner grabbing capabilities across various protocols and integration with Shodan, the world's premier service for scanning and analyzing internet-connected devices. 
This Shodan integration enables NetworkSherlock to provide enhanced scanning capabilities, giving users deeper insights into network vulnerabilities and potential threats. 
By combining local port scanning with Shodan's extensive database, NetworkSherlock offers a comprehensive tool for identifying and analyzing network security issues.


## **Features**

- Scans multiple IPs, IP ranges, and CIDR blocks.
- Supports port scanning over TCP and UDP protocols.
- Detailed banner grabbing feature.
- Ping check for identifying reachable targets.
- Multi-threading support for fast scanning operations.
- Option to save scan results to a file.
- Provides detailed version information.
- Colorful console output for better readability.
- Shodan integration for enhanced scanning capabilities.
- Configuration file support for Shodan API key.

  
## **Installation**
NetworkSherlock requires Python 3.6 or later.

1. Clone the repository:
    ```bash
    git clone https://github.com/HalilDeniz/NetworkSherlock.git
    ```
2. Install the required packages:
    ```bash
    pip install -r requirements.txt
    ```
## Configuration

Update the `networksherlock.cfg` file with your Shodan API key:

```ini
[SHODAN]
api_key = YOUR_SHODAN_API_KEY
```

## **Usage**

```bash
python3 networksherlock.py --help
usage: networksherlock.py [-h] [-p PORTS] [-t THREADS] [-P {tcp,udp}] [-V] [-s SAVE_RESULTS] [-c] target

NetworkSherlock: Port Scan Tool

positional arguments:
  target                Target IP address(es), range, or CIDR (e.g., 192.168.1.1, 192.168.1.1-192.168.1.5,
                        192.168.1.0/24)

options:
  -h, --help            show this help message and exit
  -p PORTS, --ports PORTS
                        Ports to scan (e.g. 1-1024, 21,22,80, or 80)
  -t THREADS, --threads THREADS
                        Number of threads to use
  -P {tcp,udp}, --protocol {tcp,udp}
                        Protocol to use for scanning
  -V, --version-info    Used to get version information
  -s SAVE_RESULTS, --save-results SAVE_RESULTS
                        File to save scan results
  -c, --ping-check      Perform ping check before scanning
  -ad, --arp-discover: Perform ARP discovery on the specified network.
  --use-shodan          Enable Shodan integration for additional information

```
### **Basic Parameters**

- `target`: The target IP address(es), IP range, or CIDR block to scan.
- `-p`, `--ports`: Ports to scan (e.g., 1-1000, 22,80,443).
- `-t`, `--threads`: Number of threads to use.
- `-P`, `--protocol`: Protocol to use for scanning (tcp or udp).
- `-V`, `--version-info`: Obtain version information during banner grabbing.
- `-s`, `--save-results`: Save results to the specified file.
- `-c`, `--ping-check`: Perform a ping check before scanning.
- `--use-shodan`: Enable Shodan integration.

## Example Usage

### Basic Port Scan
Scan a single IP address on default ports:
```bash
python networksherlock.py 192.168.1.1
```

### Custom Port Range
Scan an IP address with a custom range of ports:
```bash
python networksherlock.py 192.168.1.1 -p 1-1024
```

### Multiple IPs and Port Specification
Scan multiple IP addresses on specific ports:
```bash
python networksherlock.py 192.168.1.1,192.168.1.2 -p 22,80,443
```

### CIDR Block Scan
Scan an entire subnet using CIDR notation:
```bash
python networksherlock.py 192.168.1.0/24 -p 80
```

### Using Multi-Threading
Perform a scan using multiple threads for faster execution:
```bash
python networksherlock.py 192.168.1.1-192.168.1.5 -p 1-1024 -t 20
```

### Scanning with Protocol Selection
Scan using a specific protocol (TCP or UDP):
```bash
python networksherlock.py 192.168.1.1 -p 53 -P udp
```

### Scan with Shodan
```bash
python networksherlock.py 192.168.1.1 --use-shodan
```

### Scan Multiple Targets with Shodan
```bash
python networksherlock.py 192.168.1.1,192.168.1.2 -p 22,80,443 -V --use-shodan
```


### Banner Grabbing and Save Results
Perform a detailed scan with banner grabbing and save results to a file:
```bash
python networksherlock.py 192.168.1.1 -p 1-1000 -V -s results.txt
```

### Ping Check Before Scanning
Scan an IP range after performing a ping check:
```bash
python networksherlock.py 10.0.0.1-10.0.0.255 -c
```

## OUTPUT EXAMPLE

```bash
$ python3 networksherlock.py 10.0.2.12 -t 25 -V -p 21-6000 -t 25
********************************************
Scanning target: 10.0.2.12
Scanning IP    : 10.0.2.12
Ports          : 21-6000
Threads        : 25
Protocol       : tcp
---------------------------------------------
Port        Status   Service           VERSION
22  /tcp     open     ssh            SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
21  /tcp     open     telnet         220 (vsFTPd 2.3.4)
80  /tcp     open     http           HTTP/1.1 200 OK
139 /tcp     open     netbios-ssn    %SMBr
25  /tcp     open     smtp           220 metasploitable.localdomain ESMTP Postfix (Ubuntu)
23  /tcp     open     smtp            #' #'
445 /tcp     open     microsoft-ds   %SMBr
514 /tcp     open     shell          
512 /tcp     open     exec           Where are you?
1524/tcp     open     ingreslock     root@metasploitable:/#
2121/tcp     open     iprop          220 ProFTPD 1.3.1 Server (Debian) [::ffff:10.0.2.12]
3306/tcp     open     mysql          >
5900/tcp     open     unknown        RFB 003.003
53  /tcp     open     domain              
---------------------------------------------
```
## OutPut Example
```bash
$ python3 networksherlock.py 10.0.2.0/24 -t 10 -V -p 21-1000
********************************************
Scanning target: 10.0.2.1
Scanning IP    : 10.0.2.1
Ports          : 21-1000
Threads        : 10
Protocol       : tcp
---------------------------------------------
Port        Status   Service           VERSION
53  /tcp     open     domain         
********************************************
Scanning target: 10.0.2.2
Scanning IP    : 10.0.2.2
Ports          : 21-1000
Threads        : 10
Protocol       : tcp
---------------------------------------------
Port        Status   Service           VERSION
445 /tcp     open     microsoft-ds   
135 /tcp     open     epmap          
********************************************
Scanning target: 10.0.2.12
Scanning IP    : 10.0.2.12
Ports          : 21-1000
Threads        : 10
Protocol       : tcp
---------------------------------------------
Port        Status   Service           VERSION
21  /tcp     open     ftp           220 (vsFTPd 2.3.4)
22  /tcp     open     ssh           SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
23  /tcp     open     telnet          #'
80  /tcp     open     http           HTTP/1.1 200 OK
53  /tcp     open     kpasswd        464/udpcp                     
445 /tcp     open     domain         %SMBr
3306/tcp     open     mysql          >
********************************************
Scanning target: 10.0.2.20
Scanning IP    : 10.0.2.20
Ports          : 21-1000
Threads        : 10
Protocol       : tcp
---------------------------------------------
Port        Status   Service           VERSION
22  /tcp     open     ssh            SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9
```

## Contributing
Contributions are welcome! To contribute to NetworkSherlock, follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push your changes to your forked repository.
5. Open a pull request in the main repository.

## Contact
- Linktr :[Halil Deniz](https://linktr.ee/halildeniz)
- LinkedIn  : [Halil İbrahim Deniz](https://www.linkedin.com/in/halil-ibrahim-deniz/)
- TryHackMe : [halilovic](https://tryhackme.com/p/halilovic)
- Instagram : [deniz.halil333](https://www.instagram.com/deniz.halil333/)
- YouTube   : [HalilDeniz](https://www.youtube.com/c/HalilDeniz)
- Email: halildeniz313@gmail.com


## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 💰 You can help me by Donating
  Thank you for considering supporting me! Your support enables me to dedicate more time and effort to creating useful tools like NetworkScherlock and developing new projects. By contributing, you're not only helping me improve existing tools but also inspiring new ideas and innovations. Your support plays a vital role in the growth of this project and future endeavors. Together, let's continue building and learning. Thank you!"<br>
  [![BuyMeACoffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/halildeniz) 
  [![Patreon](https://img.shields.io/badge/Patreon-F96854?style=for-the-badge&logo=patreon&logoColor=white)](https://patreon.com/denizhalil) 
