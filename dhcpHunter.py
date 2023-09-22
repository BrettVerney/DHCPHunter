from scapy.all import *
import socket
import time

def build_dhcp_discover():
    """Builds and returns a DHCP discover packet."""
    return Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(conf.iface)) / \
           IP(src="0.0.0.0", dst="255.255.255.255") / \
           UDP(sport=68, dport=67) / \
           BOOTP(chaddr=get_if_hwaddr(conf.iface), xid=random.randint(1, 1000000000), flags=0xFFFFFF) / \
           DHCP(options=[("message-type", "discover"), "end"])

def send_dhcp_discover(dhcp_discover):
    """Sends the DHCP discover packet and returns the time it was sent."""
    print("Sent 1 DHCP DISCOVER packet...")
    start_time = time.perf_counter()
    sendp(dhcp_discover, iface=conf.route.route("0.0.0.0")[0], verbose=False)
    return start_time

def parse_dhcp_offer(pkt, start_time):
    """If the packet is a DHCP offer, return the server's IP and response latency."""
    if pkt.haslayer(DHCP) and pkt[DHCP].options[0][1] == 2:
        latency = time.perf_counter() - start_time
        return (pkt[IP].src, latency)

def listen_for_offers(start_time):
    """Listens for DHCP offers and returns a set of the responding servers' IPs and latencies."""
    offer_ips = set()
    sniff(prn=lambda pkt: offer_ips.add(parse_dhcp_offer(pkt, start_time)),
          filter="udp and (port 67 or port 68)", iface=conf.route.route("0.0.0.0")[0], timeout=5)
    return offer_ips

def print_offers(offer_ips):
    """Prints the list of DHCP servers that responded with their IPs, hostnames, and latencies."""
    print("The following DHCP servers responded:")
    for offer in offer_ips:
        if offer is not None:  # Ensure we received a response
            ip, latency = offer
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                print(f"{ip} ({hostname}) - latency: {latency:.6f} seconds")
            except socket.herror:
                print(f"{ip} - latency: {latency:.6f} seconds")

if __name__ == "__main__":
    dhcp_discover = build_dhcp_discover()
    start_time = send_dhcp_discover(dhcp_discover)
    offer_ips = listen_for_offers(start_time)
    print_offers(offer_ips)