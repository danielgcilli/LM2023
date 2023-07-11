#!venv/bin/python3

# MAC header breakdown
# 1. Frame Control (2 byte)
# 2. Duration (2 byte)
# 3. DA (6 byte)
# 4. SA (6 byte)
# 5. BSS ID (6 byte)
# 6. Seq-ctl (2 byte) 
# optional...

# Beacon Frame breakdown
# 1. Timestamp (8 byte)
# 2. Beacon Interval (2 byte)
# 3. Capability info (2 byte)
# 4. SSID (variable size)
# 5. Supported Rates (variable size)
# optional...

# Hardware additions at the ethernet layer are bypassed via packet injection
# libpcap equivalent in c

import scapy.all as scapy
import time

def send_beacon():
    radiotap = scapy.RadioTap()
    access_mac = scapy.getmacbyip(scapy.get_if_addr(scapy.conf.iface))
    ssid = 'TEST'
    dot11 = scapy.Dot11(type = 0, subtype = 8, addr1 = 'ff:ff:ff:ff:ff:ff', addr2 = access_mac, addr3 = access_mac)
    dot11Beacon = scapy.Dot11Beacon(cap='ESS')
    dot112Elt = scapy.Dot11Elt(ID = 'SSID', info = ssid)
    packet = radiotap / dot11 / dot11Beacon / dot112Elt
    while(1):
        try: 
            scapy.sendp(packet, scapy.conf.iface, loop = 0)
            time.sleep(0.1)
        except KeyboardInterrupt:
            print("Exiting...")
            exit()

if __name__ == '__main__':
    send_beacon()

