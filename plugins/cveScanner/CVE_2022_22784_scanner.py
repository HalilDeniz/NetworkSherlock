import requests

class CVE202222784Scanner:
    def __init__(self, target, timeout=5):
        self.target = target
        self.timeout = timeout

    def check_vulnerability(self):
        # CVE-2022-22784 zafiyetini test etmek için özel bir istek
        url = f"http://{self.target}/cgi-bin/config.exp"  # Zafiyetli URL
        headers = {"User-Agent": "Mozilla/5.0"}

        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
            if response.status_code == 200 and "sysconfig" in response.text:
                return True  # Savunmasız
        except requests.RequestException:
            pass
        return False  # Erişilemez veya savunmasız değil
