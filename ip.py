import scapy.all as scapy
import socket

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    print("IP Address\t\tMAC Address")
    print("-" * 40)

    for element in answered_list:
        print(f"{element[1].psrc}\t{element[1].hwsrc}")

def get_local_ip():
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)

if __name__ == "__main__":
    print("Scanning your local network...")
    local_ip = get_local_ip()
    subnet = local_ip.rsplit('.', 1)[0] + ".1/24"  # Adjust subnet range
    scan(subnet)
