#!venv/bin/python3

import scapy.all as scapy
import sys

if __name__ == '__main__':
    print(scapy.getmacbyip(sys.argv[1]))