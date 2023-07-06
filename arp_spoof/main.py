#!venv/bin/python3

import scapy.all as scapy

def network_scan(subnetmask):
    target_ip = scapy.get_if_addr(scapy.conf.iface)
    index = target_ip.rfind('.')
    target_range = target_ip[0:index] + '.0' + subnetmask
    # IP Address for the destination
    # create ARP packet
    arp = scapy.ARP(pdst=target_range)
    # create the Ether broadcast packet
    # ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # stack them
    packet = ether/arp

    result = scapy.srp(packet, timeout=3, verbose=1)[0]

    # a list of clients, we will fill this in the upcoming loop
    clients = []

    for sent, received in result:
        # for each response, append ip and mac address to `clients` list
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    # print clients
    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))

def get_gw_ip():
    return scapy.conf.route.route("0.0.0.0")[2]

def spoof(target_ip):
    return scapy.getmacbyip(target_ip)

if __name__ == '__main__':
    # network_scan('/16')
    print(spoof('10.1.4.171'))
