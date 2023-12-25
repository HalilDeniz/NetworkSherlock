from smb.SMBConnection import SMBConnection
from colorama import Fore,Style,init

init(autoreset=True)

class SMBScanner:
    def __init__(self, target, timeout=5):
        self.target = target
        self.timeout = timeout
        self.smb_ports = [139, 445]

                                    # test aşamasında

    def scan_smb(self):
        results = {}
        for port in self.smb_ports:
            try:
                conn = SMBConnection('', '', 'smbclient', self.target, use_ntlm_v2=True)
                connected = conn.connect(self.target, port, timeout=self.timeout)

                if connected:
                    shares = conn.listShares(timeout=self.timeout)
                    share_info = self.get_shares_info(shares)
                    results[port] = {"shares": share_info}
                else:
                    results[port] = {"error": "Unable to connect to the SMB service."}
                conn.close()
            except Exception as e:
                results[port] = {"error": str(e)}
        return results

    def get_shares_info(self, shares):
        share_info = []
        for share in shares:
            share_info.append({
                "name": share.name,
                "type": share.type,
                "comments": share.comments
            })
        return share_info

    def format_scan_results(self, results):
        formatted_result = ""
        for port, data in results.items():
            formatted_result += f"\n{Fore.BLUE}Port {port}:{Style.RESET_ALL}\n"
            if isinstance(data, dict) and 'shares' in data:
                for share in data['shares']:
                    share_name = share['name']
                    comments = share['comments'] or 'No Comments'
                    formatted_result += f"  {Fore.GREEN}- {share_name}:{Style.RESET_ALL} {comments}\n"
            else:
                formatted_result += f"  {data}\n"
        return formatted_result