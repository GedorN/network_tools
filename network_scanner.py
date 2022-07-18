#!/usr/bin/env python

import scapy.all as scapy
import optparse


def setup():
    parser = optparse.OptionParser()
    parser.add_option("--i", "--ip-range", dest="ip_range", help="IP range of search")
    return parser.parse_args(), parser
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    print(arp_request_broadcast.summary(  ))
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]


    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac":element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def print_result(results_list):
    print("_____________________________________\nIP\t\t\tMAC Address\n-------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])



(options, arguments), parser = setup()
print(options.ip_range)
if not options.ip_range:
    parser.error("[-] ip-range is required. See --help more more info ")
scan_result = scan(options.ip_range)
print_result(scan_result)
