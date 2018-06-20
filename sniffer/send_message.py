from socket import *
from netaddr import IPNetwork, IPAddress

def send(subnet, msg):
    sock = socket(AF_INET, SOCK_DGRAM)
    for ip in IPNetwork(subnet):
        try:
            print('[SENDING] message to %s' %ip)
            sock.sendto(msg.encode('utf-8'), (str(ip), 9000))
        except Exception as e:
            print(e)
