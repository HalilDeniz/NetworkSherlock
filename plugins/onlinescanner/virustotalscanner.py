import requests
import configparser
from colorama import Fore, Style, init

init(autoreset=True)

class VirusTotalSubdomainScanner:
    def __init__(self, api_key, target):
        self.api_key = api_key
        self.target = target
    def load_virustotal_key(self):
        config = configparser.ConfigParser()
        config.read(self.config_file)
        return config.get('VIRUSTOTAL', 'api_key', fallback=None)

    def scan_subdomains(self):
        url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={self.api_key}&domain={self.target}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            subdomains = data.get('subdomains', [])
            if subdomains:
                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Subdomains found for {self.target}:")
                for subdomain in subdomains:
                    print(f"  - {subdomain}")
            else:
                pass
        else:
            pass


api_key= "f56fcfcf18dedec1a6e8bcf021b42788170edd43be63bb6045e9365f61067288"
target = "hepsiburada.com"
virustotal_scanner = VirusTotalSubdomainScanner(api_key=api_key, target=target)
virustotal_scanner.scan_subdomains()