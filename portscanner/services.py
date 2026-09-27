"""Ən çox rast gəlinən portlar və servis adları."""

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb",
}


def service_name(port: int) -> str:
    return COMMON_PORTS.get(port, "unknown")
