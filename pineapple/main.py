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

def send_beacon():
    pass

if __name__ == '__main__':
    pass

