#!/usr/bin/env python3

import fcntl
import struct
import os
import time
from scapy.all import *

IP_A = "0.0.0.0"
PORT = 9090

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A, PORT))

# Create the TUN interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

# Set up the TUN interface
os.system("ip addr add 192.168.53.1/24 dev {}".format(ifname)) 
os.system("ip link set dev {} up".format(ifname))


while True:
   # Get the data from the socket interface
   data, (ip, port) = sock.recvfrom(2048)
   print("{}:{} --> {}:{}".format(ip, port, IP_A, PORT))
   
   # Treat the received data as an IP packet
   pkt = IP(data)
   print("   Inside: {} --> {}".format(pkt.src, pkt.dst))

   # Write the packet to the TUN interface
   os.write(tun, data)