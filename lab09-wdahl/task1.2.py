from scapy.all import *
a = IP()
a.dst = '10.0.2.5'
b = ICMP()
p = a/b
send(p)
ls(a)