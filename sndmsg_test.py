
#################
## TEST SCRIPT ##
#################

from sniffer.send_message import send
from socket import *

def main():
    send(gethostbyname(gethostname())+'/24', 'TEST MESSAGE!')

if __name__ == '__main__':
    main()