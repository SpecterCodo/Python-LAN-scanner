import scapy.all as scapy
import ipaddress
import socket
from datetime import datetime

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

while True:
    ip_range = input("\nEnter IP range (e.g. 192.168.1.0/24): ")
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        print(f"{network} is a valid IP range")
        break
    except ValueError:
        print("Invalid IP range, try again.")

print("\nScanning...\n")

answered, _ = scapy.arping(str(network), verbose=False)



filename = scan_results.txt

with open(filename, "w") as file:
    header = f"{'IP':<16} {'MAC':<18} {'Hostname'}\n"
    separator = "-" * 50 + "\n"

    print(header.strip())
    print("-" * 50)

    file.write(header)
    file.write(separator)

    for _, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        hostname = get_hostname(ip)

        line = f"{ip:<16} {mac:<18} {hostname}"

        print(line)
        file.write(line + "\n")

print(f"\nResults saved to: {filename}")
