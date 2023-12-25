from wafw00f import main

class WAFDetector:
    def __init__(self, url):
        self.url = url

    def detect_waf(self):
        waf_detector = main.WAFW00F(self.url)
        waf_info = waf_detector.identwaf()
        if not waf_info:
            waf_info = waf_detector.genericdetect()
        return waf_info


"""
# Örnek kullanım
url = "https://google.com"
detector = WAFDetector(url)
detected_waf = detector.detect_waf()
print(detected_waf)"""