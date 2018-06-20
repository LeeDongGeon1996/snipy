from socket import *
import os
import struct
from collections import namedtuple

version_header_length = 0
service_type = 1
entire_packet_length = 2
datagram_id = 3
flag_fragment_offset = 4
time_to_live = 5
protocol = 6
header_checksum = 7
source_ip = 8
destination_ip = 9


def prepare_sniffing(host):
    if os.name is 'nt':
        print('Log[1] : OS is WINDOW')
        sock_protocol = IPPROTO_IP
    else:
        print('Log[1] : OS isn\'t WINDOW')
        sock_protocol = IPPROTO_ICMP

    #SOCK_RAW doesn't listen for a port.
    sniffer = socket(AF_INET, SOCK_RAW, sock_protocol)
    sniffer.bind((host, 0))
    sniffer.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
    print('Log[2] : Socket Binding' + str(sniffer.getsockname()))


    if os.name is 'nt':
       sniffer.ioctl(SIO_RCVALL, RCVALL_ON)

    return sniffer


def finish_sniffing(sniffer):
    if os.name is 'nt':
        sniffer.ioctl(SIO_RCVALL, RCVALL_OFF)


def sniffing_one_packet_bite(host, src_filter=None, dst_filter=None, prn=False):

    sniffer = prepare_sniffing(host)
    packet = _filtering_packet(sniffer, src_filter, dst_filter)

    if(packet):
        if (prn):
            src_ip = packet[1][0]

            print('[Sniff One Packet]')
            print('----------Packet[%s]----------' %src_ip)
            print(packet[0])

    finish_sniffing(sniffer)

    return packet


def sniffing_one_header_bite(host, src_filter=None, dst_filter=None, prn=False):

    #version 2.1
    #sniffer = prepare_sniffing(host)
    #packet = _filtering_packet(sniffer, src_filter, dst_filter)
    
    #version 2.2
    packet = sniffing_one_packet_bite(host, src_filter, dst_filter)
    
    header_bite = None

    if(packet):
        src_ip = packet[1][0]
        header_bite = packet[0][:20]
        
        if (prn):
            print('[Sniff One Packet Header]')
            print('----------Packet[%s]----------' %src_ip)
            print(header_bite)

    #finish_sniffing(sniffer)

    return header_bite


def sniffing_all(host, src_filter=None, dst_filter=None, file_name=None):

    sniffer = prepare_sniffing(host)

    if file_name is not None:
        fd = open(file_name, 'wt+')

    print('[Start Sniffing All]')
    count = 0
    try:
        while True:
            icmp_header = None
            
            packet = _filtering_packet(sniffer, src_filter, dst_filter)
            if packet is None:
                continue

            ipheader = _extract_ipheader(packet)

            count += 1
            print('\n#####%d PACKET######' %count)
            _print_ipheader(ipheader)

            if file_name is not None:
                fd.write('\n\n' + str(ipheader) + '\n')

            if ipheader.protocol is 'ICMP':
                icmp_header = _extract_icmp_header(packet, ipheader.header_length)
                _print_icmp_header(icmp_header)
                print('data : %s' %packet[0][ipheader.header_length+8:])

                if file_name is not None:
                    fd.write(str(icmp_header) + '\n')
                    fd.write(str(packet[0][ipheader.header_length+len(icmp_header):]) + '\n')
            else:
                print('data : %s' %packet[0][ipheader.header_length:])
                if file_name is not None:
                    fd.write(str(packet[0][ipheader.header_length:]) + '\n')
            

    except KeyboardInterrupt:
        finish_sniffing(sniffer)

    if file_name is not None:
        fd.close()


def sniffing_all_bite(host):

    sniffer = prepare_sniffing(host)

    print('[Start Sniffing All Bite]')
    try:
        while input("continue?") == '':
            packet = sniffer.recvfrom(65565)
            print(packet)
            print('[%s] HEADER : %s' % (packet[1][0], packet[0][:20]))
            print('Payload : %s' % packet[0][21:])
    except KeyboardInterrupt:
        finish_sniffing(sniffer)

def _extract_icmp_header(packet, start_offset, prn=False):

    raw_icmp_header = packet[0][start_offset:start_offset+8]

    #1,1,2
    unpacked = struct.unpack('!BBH4s', raw_icmp_header)

    format_element = [
        'type',
        'code',
        'header_checksum',
        'icmp_message'
    ]
    icmp_header_format = namedtuple('icmp_header_format', format_element)

    formatted = icmp_header_format(
        get_icmp_type(unpacked[0]),
        get_icmp_code(unpacked[1]),
        get_icmp_header_checksum(unpacked[2]),
        get_icmp_message(unpacked[3])
    )
    
    if (prn):
        print(formatted)
    
    return formatted


def _extract_ipheader(packet, prn=False):

    raw_ipheader = packet[0][:20]

    #1,1,2,2,2,1,1,2,4,4
    unpacked = struct.unpack('!BBHHHBBH4s4s', raw_ipheader)
    
    format_element = [
        'version',
        'header_length', 
        'service_type', 
        'entire_packet_length',
        'datagram_id',
        'flag',
        'fragment_offset',
        'time_to_live',
        'protocol',
        'header_checksum',
        'source_ip',
        'destination_ip'
    ]
    ipheader_format = namedtuple('ipheader_format', format_element)
    
    formatted = ipheader_format(
        get_version(unpacked[0]),
        get_header_length(unpacked[0]),
        get_service_type(unpacked[1]),
        get_entire_packet_length(unpacked[2]),
        get_datagram_id(unpacked[3]),
        get_flag(unpacked[4]),
        get_fragment_offset(unpacked[4]),
        get_time_to_live(unpacked[5]),
        get_protocol(unpacked[6]),
        get_header_ckecksum(unpacked[7]),
        get_source_ip(unpacked[8]),
        get_destination_ip(unpacked[9])
        )
    
    if (prn):
        print(formatted)
    
    return formatted

def _filtering_packet(sniffer, src_filter=None, dst_filter=None):

    packet = sniffer.recvfrom(65565)

    #source IP filter
    if src_filter is not None:
        if packet[1][0] not in src_filter:
            return None

    #destination IP filter
    if dst_filter is not None:
        if get_destination_ip(packet[0][16:20]) not in dst_filter:
            return None

    return packet


def _print_ipheader(ipheader):

    if type(ipheader).__name__.__ne__('ipheader_format'):
        print('Wrong format. Use _extract_ipheader(packet, prn)')
        return

    print('Datagram SIZE \t: %s' %ipheader.entire_packet_length)
    print('Protocol \t: %s' %ipheader.protocol)
    print('Source IP \t: %s' %ipheader.source_ip)
    print('Destination IP \t: %s' %ipheader.destination_ip)


def _print_icmp_header(icmp_header):

    if type(icmp_header).__name__.__ne__('icmp_header_format'):
        print('Wrong format. Use _extract_icmp_header(packet, start_offset, prn)')
        return

    print('ICMP type \t: %s' %icmp_header.type)
    print('ICMP code \t: %s' %icmp_header.code)
    print('ICMP checksum \t: %s' %icmp_header.header_checksum)
    print('ICMP message \t: %s' %icmp_header.icmp_message)





# (xxxx)(xxxx)에서 앞의 4자리가 버전을 나타냄. 뒤의 4자리를 버리기위해 쉬프트연산.
def get_version(ipheader):return int((ipheader & 0xF0) >> 4)
# (xxxx)(xxxx)에서 뒤의 4자리가 길이를 나타냄. 4바이트단위로 나타냈기 때문에 4를 곱하기위해 쉬프트연산.
def get_header_length(ipheader):return int((ipheader & 0x0F) << 2)

def get_service_type(ipheader):return ipheader

def get_entire_packet_length(ipheader):return int(ipheader)

def get_datagram_id(ipheader):return int(ipheader)

def get_flag(ipheader):return ((ipheader & 0xE0) >> 5)

def get_fragment_offset(ipheader):return (ipheader & 0x1F)

def get_time_to_live(ipheader):return ipheader

def get_protocol(ipheader):
    protocols = {1:'ICMP', 6:'TCP', 17:'UDP', 18:'MUX', 27:'RDP'}
    if ipheader in protocols:
        return protocols[ipheader]
    else:
        return 'OTHERS : ' + str(ipheader)

def get_header_ckecksum(ipheader):return ipheader

def get_source_ip(ipheader):return inet_ntoa(ipheader)

def get_destination_ip(ipheader):return inet_ntoa(ipheader)

def get_icmp_type(icmp_header):
    types = {0:'ICMP Echo Reply', 3:'Destination Unreachable', 8:'ICMP Echo Request'}

    if icmp_header in types:
        return types[icmp_header] + '[' + str(icmp_header) + ']'
    else:
        return 'OTHERS : ' + str(icmp_header)

def get_icmp_code(icmp_header):
    codes = {3:'Port Unreachable'}

    if icmp_header in codes:
        return codes[icmp_header] + '[' + str(icmp_header) + ']'
    else:
        return 'OTHERS : ' + str(icmp_header)

def get_icmp_header_checksum(icmp_header):return int(icmp_header)

def get_icmp_message(icmp_header):return str(icmp_header)