from plugins.cveScanner.CVE_2014_0160_scanner import HeartbleedScanner
from plugins.cveScanner.CVE_2014_6271_scanner import ShellshockScanner
from plugins.cveScanner.CVE_2017_0144_scanner import EternalBlueScanner
from plugins.cveScanner.CVE_2017_5638_scanner import ApacheStrutsScanner
from plugins.cveScanner.CVE_2018_11776_scanner import StrutsScanner
from plugins.cveScanner.CVE_2019_0708_scanner import BlueKeepScanner
from plugins.cveScanner.CVE_2020_0688_scanner import CVE20200688Tester
from plugins.cveScanner.CVE_2020_0796_scanner import SMBVulnerabilityChecker
from plugins.cveScanner.CVE_2020_1938_scanner import GhostcatScanner
from plugins.cveScanner.CVE_2022_1388_scanner import CVE20221388Scanner
from plugins.cveScanner.CVE_2022_22784_scanner import CVE202222784Scanner

class CVE_Scanner_Main:
    def __init__(self, ip):
        self.ip = ip

    def run_all_scans(self, ports):
        results = {}

        http_url = f"http://{self.ip}"
        https_url = f"https://{self.ip}"
        try:
            if '443' in ports:
                heartbleed_scanner = HeartbleedScanner(https_url)
                results['Heartbleed'] = heartbleed_scanner.check_vulnerability()

            for port in ['80', '443']:
                url = https_url if port == '443' else http_url

                if port in ports:
                    shellshock_scanner = ShellshockScanner(f"{url}/cgi-bin/test.cgi")
                    results['Shellshock'] = shellshock_scanner.scan_for_shellshock()

                    struts_scanner = ApacheStrutsScanner(f"{url}/showcase.action")
                    results['ApacheStruts'] = struts_scanner.scan_for_apache_struts()


                    struts2_scanner = StrutsScanner(url)
                    results['CVE2018-11776'] = struts2_scanner.check_vulnerability()

                    if port == '443':
                        cve20200688_scanner = CVE20200688Tester(url)
                        results['CVE-2020-0688'] = cve20200688_scanner.check_vulnerability()

            if '445' in ports:
                smbghost_scanner = SMBVulnerabilityChecker(self.ip)
                results['SMBGhost'] = smbghost_scanner.check_vulnerability()

            if '8009' in ports:
                ghostcat_scanner = GhostcatScanner(self.ip)
                results['Ghostcat'] = ghostcat_scanner.check_vulnerability()

            if '3389' in ports:
                bluekeep_scanner = BlueKeepScanner(self.ip)
                results['BlueKeep'] = bluekeep_scanner.scan_for_bluekeep()

            if '139' in ports or '445' in ports:
                eternalblue_scanner = EternalBlueScanner(self.ip)
                results['EternalBlue'] = eternalblue_scanner.scan_for_eternalblue()

            if '445' in ports:
                cve202222784_scanner = CVE202222784Scanner(self.ip)
                results['CVE-2022-22784'] = cve202222784_scanner.check_vulnerability()

            if '443' in ports:
                cve20221388_scanner = CVE20221388Scanner(self.ip)
                results['CVE-2022-1388'] = cve20221388_scanner.check_vulnerability()
        except:
            pass
        return results