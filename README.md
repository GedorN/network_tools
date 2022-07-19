# Network Tools
A projet with tools to gain control and information over a network. Developed by Gedor Neto

Build in **python 3**. Not tested in previus python versions.

## Network scanner
List devices ip and mac address in network
Usage example:
```bash
python --ip-range 192.168.0.0/24
```
*The final `[...]0/24` conver the adresses in range 1 to 254. You can read more abount this format in [why 0/24](https://social.technet.microsoft.com/Forums/windows/en-US/26de7e91-00e7-428e-a8d4-f76286e39c38/what-is-the-meaning-of-quot1921680024quot?forum=w7itpronetworking)*

## ARP spoofer
A toll to perform [ARP spoof](https://www.crowdstrike.com/cybersecurity-101/spoofing-attacks/arp-spoofing/) setting your device as a man in the middle.
Usage example:
```bash
python --t 192.168.0.10 --g 192.168.0.1
```
In resume, this will tell to router (192.168.0.1) that you are the device with IP 192.168.0.10, and tell to device who have the ip 192.168.0.10 that you are the router.

### Note
In some devices, after perform ARP spoofing, the requests that go through your device are not fowarded, locking the traffic. To solve this, you have no enable the fowarding of requests. Below a couple of examples of how do that in linux

As root:
```bash
sudo bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
```
As sudo:
```bash
net.ipv4.ip_forward = 1
sudo sysctl -p
```

## Packet sniffer
Sniff packages who pass through the device. The output are optimized to show when a password are inserted. Currently, only work in HTTP requests.
Usage example:
```bash
python3 packet_sniffer.py --interface wlp2s0
```

## DNS Spoffer
Redirect a webpage when target DNS is visited. Don't forget to be the man in the middle to spoof packages from another devices.
Usage example:
```bash
python3 net_cut.py -t [target_url] -n [new_ip]
```

