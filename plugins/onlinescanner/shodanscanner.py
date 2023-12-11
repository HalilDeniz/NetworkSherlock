import shodan
import configparser
from colorama import Fore, Style

class ShodanScanner:
    def __init__(self, config_file):
        self.config_file = config_file
        self.shodan_key = self.load_shodan_key()
        self.shodan_api = shodan.Shodan(self.shodan_key) if self.shodan_key else None

    def load_shodan_key(self):
        config = configparser.ConfigParser()
        config.read(self.config_file)
        return config.get('SHODAN', 'api_key', fallback=None)

    def perform_scan(self, ip):
        try:
            shodan_result = self.shodan_api.host(ip)
            return shodan_result
        except shodan.APIError as e:
            pass
            return None

    def format_shodan_info(self, shodan_result):
        shodan_info = ""
        if not shodan_result:
            return shodan_info

        # Extract and format relevant information from the Shodan result
        os_info = shodan_result.get('os', None)
        if os_info:
            shodan_info += f"   \t{' ' * 5}{Fore.CYAN}- OS          : {Style.RESET_ALL}{os_info}\n"

        asn_info = shodan_result.get('asn', 'Unknown ASN')
        org_info = shodan_result.get('org', 'Unknown Organization')
        shodan_info += f"   \t{' ' * 5}{Fore.CYAN}- ASN         : {Style.RESET_ALL}{asn_info}\n"
        shodan_info += f"   \t{' ' * 5}{Fore.CYAN}- Org         : {Style.RESET_ALL}{org_info}\n"

        domains = shodan_result.get('domains', [])
        if domains:
            domain_info = ', '.join(domains)
            shodan_info += f"   \t{' ' * 5}{Fore.CYAN}- Domains     : {Style.RESET_ALL}{domain_info}\n"

        for service_info in shodan_result.get('data', []):
            product = service_info.get('product')
            version = service_info.get('version')
            if product or version:
                shodan_info += f"   \t{' ' * 5}{Fore.CYAN}- Service     :{Style.RESET_ALL} {product or 'Unknown'} Version: {version or 'Unknown'}\n"

        geoloc_info = shodan_result.get('location', {})
        if geoloc_info:
            city = geoloc_info.get('city', 'Unknown City')
            country = geoloc_info.get('country_name', 'Unknown Country')
            shodan_info += f"   \t{' ' * 5}{Fore.CYAN}- Location   :{Style.RESET_ALL} {city}, {country}\n"

        for item in shodan_result.get('data', []):
            if 'netbios' in item and 'name' in item['netbios']:
                netbios_name = item['netbios']['name']
                shodan_info += f"   \t{' ' * 5}{Fore.CYAN}- NetBIOS Name: {Style.RESET_ALL}{netbios_name}\n"

        hostnames = shodan_result.get('hostnames', [])
        if hostnames:
            hostname_info = ', '.join(hostnames)
            shodan_info += f"   \t{' ' * 5}{Fore.CYAN}- Server Names: {Style.RESET_ALL}{hostname_info}\n"

        return shodan_info
