import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class CVE20200688Tester:
    def __init__(self, target):
        self.target = target

    def check_vulnerability(self):
        url = f"https://{self.target}/ecp/default.aspx"
        headers = {"User-Agent": "Mozilla/5.0"}

        try:
            response = requests.get(url, headers=headers, verify=False, timeout=5)
            # __VIEWSTATEGENERATOR parametresinin varlığı kontrol edilir
            if "__VIEWSTATEGENERATOR" in response.text:
                return True  # Potansiyel olarak savunmasız
        except requests.RequestException as e:
            pass
        return False  # Erişilemez veya savunmasız değil


"""
if __name__ == "__main__":
    target = input("Hedef Exchange sunucusu (örn: exchange.example.com): ")
    tester = CVE20200688Tester(target)

    if tester.check_vulnerability():
        print(f"{target} CVE-2020-0688 zafiyetine karşı savunmasız!")
    else:
        print(f"{target} CVE-2020-0688 zafiyetine karşı savunmasız değil veya erişilemez.")
"""