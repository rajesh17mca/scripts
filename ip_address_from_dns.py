import socket

def get_ip_from_dns(dns_name):
    try:
        ip_address = socket.gethostbyname(dns_name)
        return ip_address
    except socket.gaierror as e:
        return f"Error: {e}"

def get_dns_from_ip(ip_address):
    try:
        dns_name = socket.gethostbyaddr(ip_address)
        return dns_name[0]
    except socket.herror as e:
        return f"Error: {e}"

if __name__ == "__main__":
    # Example usage
    dns_name = "www.google.com"
    ip_address = get_ip_from_dns(dns_name)
    print(f"IP Address of {dns_name}: {ip_address}")

    reverse_dns = get_dns_from_ip(ip_address)
    print(f"DNS Name of {ip_address}: {reverse_dns}")
