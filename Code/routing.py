# routing.py
# gives helper methods for determining where the server should send the data logically
import socket

# we provide a hostname which is a domain and it returns to us the IP, gethostbyname() performs a DNS query if required
def resolve_host(hostname, default_port=80):
    try:
        ip = socket.gethostbyname(hostname)
        return ip, default_port
    except socket.gaierror:
        # DNS resolution failed
        print("DNS query fail")
        return None, None

# calculates the next logical hop and where server should send data, multiple hops after that to reach destination are handled by routers not our code
# also performs dns query if required 
def get_next_hop(destination_host, destination_port=None):

    port = destination_port if destination_port else 80

    # If hostname is actually an IP, just return it
    try:
        socket.inet_aton(destination_host)
        return destination_host, port
    except socket.error:
        # Not an IP, resolve DNS
        ip, resolved_port = resolve_host(destination_host, port)
        return ip, resolved_port


# simple blocked domains list for demo
BLOCKED_DOMAINS = ["example.com", "badsite.com"]
def is_blocked(destination_host):
    return destination_host.lower() in BLOCKED_DOMAINS
