import socket
import threading
import argparse
from queue import Queue

# ===== COLORS =====
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

# ===== BANNER =====
def show_banner():
    print(f"""{CYAN}
╔══════════════════════════════╗
║       AeroSecure v6 🔐       ║
║   Advanced Port Scanner     ║
╚══════════════════════════════╝
{RESET}""")

# ===== ARGUMENTS =====
parser = argparse.ArgumentParser(description="AeroSecure CLI Tool")
parser.add_argument("-t", "--target", required=True, help="Target IP or domain")
parser.add_argument("--fast", action="store_true", help="Scan common ports")
parser.add_argument("--full", action="store_true", help="Scan ports 1-1024")
parser.add_argument("-o", "--output", help="Save report to file")
args = parser.parse_args()

# ===== PORT MODES =====
common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]

if args.full:
    ports = range(1, 1025)
else:
    ports = common_ports  # default = fast

# ===== SERVICES =====
services = {
    21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS",
    80: "HTTP", 443: "HTTPS",
    110: "POP3", 139: "NetBIOS",
    143: "IMAP", 445: "SMB", 8080: "HTTP-Alt"
}

# ===== RISK LEVEL =====
def get_risk(port):
    if port in [21, 23]:
        return "HIGH"
    elif port == 80:
        return "MEDIUM"
    elif port == 22:
        return "LOW"
    return "UNKNOWN"

# ===== OS DETECTION =====
def detect_os(banner):
    banner = banner.lower()
    if "ubuntu" in banner or "debian" in banner:
        return "Linux"
    elif "windows" in banner:
        return "Windows"
    elif "nginx" in banner or "apache" in banner:
        return "Linux (Web Server)"
    return "Unknown"

# ===== RESOLVE TARGET =====
try:
    target_ip = socket.gethostbyname(args.target)
except:
    print(f"{RED}Invalid target{RESET}")
    exit()

# ===== INIT =====
show_banner()
print(f"{CYAN}[*] Target: {target_ip}{RESET}")
print(f"{YELLOW}[*] Starting scan...\n{RESET}")

queue = Queue()
results = []
lock = threading.Lock()

# ===== SCAN FUNCTION =====
def scan():
    while not queue.empty():
        port = queue.get()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)

            result = sock.connect_ex((target_ip, port))

            if result == 0:
                service = services.get(port, "Unknown")
                risk = get_risk(port)

                banner = ""
                os_guess = "Unknown"

                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode(errors="ignore").strip()
                    if banner:
                        os_guess = detect_os(banner)
                except:
                    pass

                with lock:
                    results.append({
                        "port": port,
                        "service": service,
                        "risk": risk,
                        "os": os_guess
                    })

            sock.close()

        except:
            pass

        queue.task_done()

# ===== LOAD PORTS =====
for port in ports:
    queue.put(port)

# ===== THREADS =====
for _ in range(100):
    threading.Thread(target=scan, daemon=True).start()

queue.join()

# ===== OUTPUT TABLE =====
print("\n" + "="*55)
print("AeroSecure Scan Results")
print("="*55)
print(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<15}{'RISK':<10}")
print("-"*55)

for r in sorted(results, key=lambda x: x['port']):
    if r['risk'] == "HIGH":
        color = RED
    elif r['risk'] == "MEDIUM":
        color = YELLOW
    else:
        color = GREEN

    print(f"{color}{r['port']:<10}{'OPEN':<10}{r['service']:<15}{r['risk']:<10}{RESET}")

print("="*55)

# ===== SAVE REPORT =====
if args.output:
    with open(args.output, "w") as f:
        f.write("AeroSecure Report\n")
        f.write("=================\n\n")
        for r in results:
            f.write(f"Port: {r['port']}\n")
            f.write(f"Service: {r['service']}\n")
            f.write(f"Risk: {r['risk']}\n")
            f.write(f"OS: {r['os']}\n")
            f.write("----------------------\n")

    print(f"{CYAN}Report saved to {args.output}{RESET}")
