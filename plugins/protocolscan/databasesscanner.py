import socket

class DatabaseScanner:
    def __init__(self, target, port, timeout=5):
        self.target = target
        self.port = port
        self.timeout = timeout

    def scan_database(self):
        if self.port == 3306:  # MySQL
            return self.scan_mysql()
        elif self.port == 5432:  # PostgreSQL
            return self.scan_postgresql()
        else:
            return "Unknown Database Service"

    def scan_mysql(self):
        try:
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                greeting = sock.recv(1024)
                server_info = self.parse_mysql_greeting(greeting)

                if server_info.get("server_version"):
                    return f"MySQL Server\n - Version: {server_info['server_version']}\n - Protocol Version: {server_info['protocol_version']}\n - Capabilities: {server_info['capabilities']}"
                else:
                    return "MySQL greeting not received or parsed correctly"
        except Exception as e:
            return f"Failed to scan MySQL: {e}"

    def parse_mysql_greeting(self, data):
        try:
            data = data[4:]
            protocol_version = data[0]
            data = data[1:]
            version_end = data.find(b'\x00')
            server_version = data[:version_end].decode('utf-8', 'ignore')
            data = data[version_end + 1:]
            data = data[4 + 8 + 1:]
            capabilities = int.from_bytes(data[:2], byteorder='little')
            data = data[2:]
            return {
                "protocol_version": protocol_version,
                "server_version": server_version,
                "capabilities": capabilities}
        except Exception as e:
            return {"error": f"Error parsing greeting: {e}"}

    def scan_postgresql(self):
        try:
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                # Send a startup message
                startup_message = self.create_startup_message()
                sock.sendall(startup_message)

                response = sock.recv(1024)
                server_info = self.parse_postgresql_response(response)
                return server_info
        except Exception as e:
            return f"Failed to scan PostgreSQL: {e}"

    def create_startup_message(self):
        message = b"\x00\x03\x00\x00user\x00postgres\x00\x00"
        length = len(message) + 4
        return length.to_bytes(4, byteorder='big') + message

    def parse_postgresql_response(self, response):
        # PostgreSQL response parsing
        if response[0] == 0x52:  # 'R' for authentication request
            auth_type = int.from_bytes(response[5:9], byteorder='big')
            auth_message = {
                0: "Trust Authentication",
                2: "Kerberos v5 Authentication",
                3: "Password Authentication",
                5: "MD5 Password Authentication",
                6: "SCM Credential Authentication",
                7: "GSSAPI Authentication",
                9: "SSPI Authentication",
                10: "SASL Authentication"
            }.get(auth_type, "Unknown Authentication")
            return f"PostgreSQL Server\n - Status: Authentication Requested\n - Auth Type: {auth_message}"
        elif response[0] == 0x45:  # 'E' for error
            error_message = self.parse_error_message(response)
            return f"PostgreSQL Server\n - Status: Error Returned\n - Error: {error_message}"
        else:
            return "PostgreSQL Server\n - Status: Unknown Response"
    def parse_error_message(self, response):
        # Extract the error message details from the response
        response = response[5:]  # Skip message type and length
        fields = response.split(b'\x00')
        error_fields = {field[0]: field[1:].decode('utf-8', 'ignore') for field in fields if field}
        return error_fields.get(b'M', "Unknown Error")

while True:
    test = input(">>>> ")
    os_scanner = DatabaseScanner(test,3306)
    os_guess = os_scanner.scan_postgresql()
    print(f"Detected OS/Device Type: {os_guess}")
