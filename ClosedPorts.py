import re
import sys

def parse_nmap_output(file_path):
    with open(file_path, 'r') as file:
        content = file.read()

    # Regex pattern to match IP address (both IPv4 and IPv6)
    ip_pattern = re.compile(r'Nmap scan report for ((?:[0-9]{1,3}\.){3}[0-9]{1,3})')
    # Regex pattern to match port information
    port_pattern = re.compile(r'(\d+)/(\w+)\s+(\w+)\s+')

    ip_closed_ports = {}
    current_ip = None

    for line in content.splitlines():
        ip_match = ip_pattern.search(line)
        if ip_match:
            current_ip = ip_match.group(1)
            ip_closed_ports[current_ip] = []

        port_match = port_pattern.search(line)
        if port_match:
            port, protocol, state = port_match.groups()
            if state == 'closed' and current_ip:
                ip_closed_ports[current_ip].append(port)

    return ip_closed_ports

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <nmap_output_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    ip_closed_ports = parse_nmap_output(file_path)

    affected_ips = []

    for ip, closed_ports in ip_closed_ports.items():
        if closed_ports:
            print(f"IP Address: {ip}")
            print("Closed Ports:")
            for port in closed_ports:
                print(f"  - {port}")
            affected_ips.append(ip)

    if affected_ips:
        print("\nAffected IP Addresses:")
        for ip in affected_ips:
            print(ip)

if __name__ == "__main__":
    main()
