
#################
## TEST SCRIPT ##
#################

from sniffer.sniff_module import *
from socket import *

def main():
    
    print(gethostname())
    print(gethostbyname(gethostname()))
    
    #sniffing_one_packet_bite(gethostbyname(gethostname()), prn=True)
    #sniffing_one_header_bite(gethostbyname(gethostname()), prn=True)

    #sniffing_all(gethostbyname(gethostname()))
    
    
    sniffing_all('172.30.1.45', ('172.30.1.60'))
    #sniffing_all('10.10.116.158', ('10.10.116.160'))
    #sniffing_all('10.10.116.158', ('10.10.116.160'), file_name='capture_160.raw')
    
    
    #sniffing_all('172.30.1.42', ('172.30.1.15'))
    #sniffing_all('172.30.1.42', ('172.30.1.42'))


if __name__ == '__main__':
    main()
