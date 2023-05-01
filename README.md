# DHCPHunter

This is a Python script that sends a DHCP Discover packet and listens for DHCP Offer packets on the network interface card that has the default route. It uses the Scapy library for packet crafting and sniffing, the Socket library for hostname resolution, and the Time library to determine the latency of the DHCP responsiveness.

**Author:** Brett Verney</br>
**Version:** v0.1 | 1-05-2023

## Use Cases
- This script can be used to detect DHCP servers on a network and their assigned IP addresses.
- It can detect rogue DHCP servers.
- It can be used to test the responsiveness and reliability of DHCP servers on a network.

## How to Use the Script
1. Install the Scapy library by running `pip install scapy`.
2. Run the script using `python dhcpHunter.py`.
3. The script will send a DHCP Discover packet and listen for DHCP Offer packets for 5 seconds.
4. Once the timeout has been reached, the script will display the IP addresses of the DHCP servers that responded and their hostnames (if available).

## Example

The script should output something similar to the image below:

![dhcpHunter Example](https://github.com/BrettVerney/DHCPHunter/blob/main/example_output.PNG)

Note: This script requires root privileges to run, as it involves packet sniffing and sending.

