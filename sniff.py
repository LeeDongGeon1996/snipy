from sniffer import sniff_module
from socket import *

print(gethostname())
print(gethostbyname(gethostname()))


#sniff_module.sniffing_one_header(gethostbyname(gethostname()))
#sniff_module.sniffing_one_packet(gethostbyname(gethostname()))

sniff_module.sniffing_all(gethostbyname(gethostname()), ('203.229.168.79'))
