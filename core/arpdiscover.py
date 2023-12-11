import requests
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp

class ArpDiscover:
    def __init__(self, iface):
        self.iface = iface

    def scan(self, target):
        arp = ARP(pdst=target)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        try:
            result = srp(packet, timeout=3, verbose=0, iface=self.iface)[0]
        except PermissionError:
            print("Error: You do not have sufficient privileges. Try running the program with 'sudo'.")
            exit()
        except OSError as e:
            if "No such device" in str(e):
                print(f"Error: Interface '{self.iface}' does not exist. \nPlease provide a valid interface name.")
                exit()
            else:
                raise

        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc, 'manufacturer': self.get_device_info(received.hwsrc)})

        return devices

    @staticmethod
    def get_device_info(mac_address):
        try:
            url = f"https://api.macvendors.com/{mac_address}"
            response = requests.get(url)
            return response.text.strip() if response.status_code == 200 else "Unknown"
        except requests.exceptions.RequestException:
            return "Unknown"
