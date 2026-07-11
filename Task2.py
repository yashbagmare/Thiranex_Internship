import socket

# common ports to check
PORTS_TO_CHECK = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
}

# old versions to look for
OLD_VERSIONS = [
    "OpenSSH_5",
    "OpenSSH_6",
    "Apache/2.2",
    "Apache/2.0",
    "vsFTPd 2.3.4",
]

# risky ports
RISKY_PORTS = {
    21: "FTP sends passwords in plain text",
    23: "Telnet sends everything in plain text - very insecure",
    3389: "Remote Desktop open to the network can be attacked",
}


def is_port_open(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0


def get_banner(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((host, port))
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner
    except Exception:
        return ""


def check_old_version(banner):
    for old in OLD_VERSIONS:
        if old in banner:
            return old
    return None


def scan(host):
    print(f"\nScanning {host} ...\n")
    findings = []

    for port, service in PORTS_TO_CHECK.items():
        if is_port_open(host, port):
            print(f"[OPEN] Port {port} ({service})")
            banner = get_banner(host, port)

            if port in RISKY_PORTS:
                findings.append(f"WARNING: Port {port} ({service}) is open - {RISKY_PORTS[port]}")

            old_version = check_old_version(banner)
            if old_version:
                findings.append(f"WARNING: Port {port} ({service}) is running an old version: {old_version}")

        else:
            print(f"[closed] Port {port} ({service})")

    return findings


def save_report(host, findings):
    with open("report.txt", "w") as f:
        f.write(f"Vulnerability Report for {host}\n")
        f.write("=" * 40 + "\n\n")

        if not findings:
            f.write("No issues found in this scan.\n")
        else:
            for line in findings:
                f.write(line + "\n")

    print("\nReport saved to report.txt")


if __name__ == "__main__":
    target = input("Enter the host to scan (e.g. localhost): ")
    results = scan(target)

    print("\n--- Summary ---")
    if not results:
        print("No issues found.")
    else:
        for line in results:
            print(line)

    save_report(target, results)