import sniff_module
from socket import *


#################
## TEST SCRIPT ##
#################

print(gethostname())
print(gethostbyname(gethostname()))

#sniff_module.sniffing_one_header(gethostbyname(gethostname()))
#sniff_module.sniffing_one_packet(gethostbyname(gethostname()))

#sniff_module.sniffing_all(gethostbyname(gethostname()), ('203.229.168.79', '192.168.0.70'), 'test.txt')


#sniff_module.sniffing_one_packet(gethostbyname(gethostname()),('223.194.30.97'), prn=print)
sniff_module.sniffing_all(gethostbyname(gethostname()), dst_filter=('223.194'))

