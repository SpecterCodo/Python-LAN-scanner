import scapy.all as scapy
import ipaddress
import socket
import time
from mac_vendor_lookup import MacLookup

socket.setdefaulttimeout(1)

MacLookup().update_vendors()

lookup = MacLookup()

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, TimeoutError):
        return "Unknown"

def get_vendor(mac):
    try:
        return lookup.lookup(mac)
    except:
        return "Unknown"

def get_network():
    while True:
        ip_range = input("\nEnter IP range (e.g. 192.168.1.0/24): ")

        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            print(f"{network} is a valid IP range")
            return network

        except ValueError:
            print("Invalid IP range, try again.")

def scan_network(network):
    try:
        answered, _ = scapy.arping(
            str(network),
            timeout=2,
            retry=1,
            verbose=False
        )

        return answered

    except PermissionError:
        print("\n[ERROR] Run this script as administrator/root.")
        exit()

    except Exception as e:
        print(f"\n[ERROR] {e}")
        exit()

def main():
    network = get_network()

    print("\nScanning...\n")

    start_time = time.time()

    answered = scan_network(network)

    devices = []

    for _, received in answered:
        ip = received.psrc
        mac = received.hwsrc

        devices.append({
            "ip": ip,
            "mac": mac,
            "vendor": get_vendor(mac),
            "hostname": get_hostname(ip)
        })

    devices.sort(key=lambda d: ipaddress.ip_address(d["ip"]))

    filename = "scan_results.txt"

    with open(filename, "w") as file:

        header = f"{'IP':<16} {'MAC':<18} {'Vendor':<25} {'Hostname'}\n"
        separator = "-" * 90 + "\n"

        print(header.strip())
        print("-" * 90)

        file.write(header)
        file.write(separator)

        for device in devices:

            line = (
                f"{device['ip']:<16} "
                f"{device['mac']:<18} "
                f"{device['vendor']:<25} "
                f"{device['hostname']}"
            )

            print(line)
            file.write(line + "\n")

    end_time = time.time()

    print(f"\nDevices found: {len(devices)}")
    print(f"Scan completed in {end_time - start_time:.2f} seconds")
    print(f"Results saved to: {filename}")

if __name__ == "__main__":
    main()
