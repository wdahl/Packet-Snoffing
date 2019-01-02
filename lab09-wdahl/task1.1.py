from scapy.all import *

def print_pkt(pkt):
	pkt.show()

pkt = sniff(prn=print_pkt)