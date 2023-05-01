from scapy.all import *
import socket
import time

# Build the DHCP discover packet
dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(conf.iface)) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(chaddr=get_if_hwaddr(conf.iface), xid=random.randint(1, 1000000000), flags=0xFFFFFF) / DHCP(options=[("message-type", "discover"), "end"])

# Send the packet using the default route interface and display custom message
print("Sent 1 DHCP DISCOVER packet...")
start_time = time.time() # Record the start time
sendp(dhcp_discover, iface=conf.route.route("0.0.0.0")[0], verbose=False)

# Define a function to parse DHCP offer packets and record the latency
def parse_dhcp_offer(pkt):
    if pkt.haslayer(DHCP) and pkt[DHCP].options[0][1] == 2:
        latency = time.time() - start_time # Calculate the latency
        return (pkt[IP].src, latency)

# Listen for DHCP offer packets on the default route interface
offer_ips = set()
sniff(prn=lambda pkt: offer_ips.add(parse_dhcp_offer(pkt)), filter="udp and (port 67 or port 68)", iface=conf.route.route("0.0.0.0")[0], timeout=5)

# Print the list of DHCP offer IP addresses, hostnames (if available), and latencies
print("The following DHCP servers responded:")
for offer in offer_ips:
    ip, latency = offer
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        print(f"{ip} ({hostname}) - latency: {latency:.6f} seconds")
    except socket.herror:
        print(f"{ip} - latency: {latency:.6f} seconds")
