from scapy.all import *
a = IP()
a.dst = "10.0.5.7"
a.ttl = 1
b = ICMP()
send(a/b)