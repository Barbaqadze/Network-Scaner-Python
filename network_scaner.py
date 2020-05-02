import scapy.all as scapy
from argparse import ArgumentParser

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)                           #make packet and store ip address in pdst
    broadcast   = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')         #make packet and store mac address in dst
    arp_request_broadcast = broadcast/arp_request              #concatenate last two packets
    answered , unanswered = scapy.srp(arp_request_broadcast , timeout=1 , verbose=False)    #use send and recieve function and store them into two list - anwered and unanswere
    if len(answered) == 0:
        print("No hosts in that LAN")
        return 0

    print("     IP                   MAC Address\n---------------------------------------")
    for i in answered:
        print(i[1].psrc , "       ", i[1].hwsrc)
    

def get_arguments():
    parser = ArgumentParser()
    parser.add_argument('-t' , '--target', nargs='?' , dest='target' , help='Target IP or IP range' , required=True)
    options = parser.parse_args()
    return options

result = get_arguments()
scan(result.target)


