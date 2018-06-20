
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

    sniffing_all(gethostbyname(gethostname()))
    
    #sniffing_all('172.30.1.42', ('172.30.1.15'))
    #sniffing_all('172.30.1.42', ('172.30.1.42'))


if __name__ == '__main__':
    main()
