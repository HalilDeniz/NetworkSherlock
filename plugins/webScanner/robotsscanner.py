import requests

class RobotsScanner:
    def __init__(self, base_url):
        self.base_url = base_url

    def scan_robots(self):
        robots_url = f"{self.base_url}/robots.txt"
        try:
            response = requests.get(robots_url)
            if response.status_code == 200:
                return "Found"
            else:
                pass
        except requests.RequestException:
            pass
    def run_scan(self):
        return self.scan_robots()
