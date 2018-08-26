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

ip_header_size = 20
icmp_header_size = 8
udp_header_size = 8
rtp_header_size = 12
rtp_payload_header_size = 1

def prepare_sniffing(host):
    if os.name is 'nt':
        print('Log[1] : OS is WINDOW')
        sock_protocol = IPPROTO_IP
    elif os.name is 'posix':
        print('Log[1] : OS is POSIX')
        sock_protocol = _select_protocol()
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

    packet = sniffing_one_packet_bite(host, src_filter, dst_filter)
    
    header_bite = None

    if(packet):
        src_ip = packet[1][0]
        header_bite = packet[0][:ip_header_size]
        
        if (prn):
            print('[Sniff One Packet Header]')
            print('----------Packet[%s]----------' %src_ip)
            print(header_bite)

    return header_bite


def sniffing_all(host, src_filter=None, dst_filter=None, file_name=None):

    sniffer = prepare_sniffing(host)

    if file_name is not None:
        fd = open(file_name, 'wb+')

    count = 0
    print('[Start Sniffing All]')
    try:
        while True:
            packet = _filtering_packet(sniffer, src_filter, dst_filter)
            if packet is None:
                continue
            packet = packet[0]

            ip_header = _extract_ipheader(packet)
            ip_payload = packet[ip_header.header_length:]

            count+=1
            print('\n#####%d PACKET######' %count)
            _print_ipheader(ip_header)

            if ip_header.protocol is 'ICMP':
                icmp_header = _extract_icmp_header(ip_payload)
                icmp_payload = ip_payload[icmp_header_size:]
                _print_icmp_header(icmp_header)
                print('ICMP Payload : %s' %icmp_payload)

                if file_name is not None:
                    fd.write(str(icmp_header) + '\n')
                    fd.write(str(icmp_payload) + '\n')
            
            elif ip_header.protocol is 'UDP':
                udp_header = _extract_udp_header(ip_payload)
                udp_payload = ip_payload[udp_header_size:]
                _print_udp_header(udp_header)

                rtp_header = _extract_rtp_header(udp_payload, True)
                if rtp_header:
                    rtp_payload = udp_payload[rtp_header_size:]
                    rtp_payload_header = _extract_rtp_payload_header(rtp_payload, True)
                    sample_data = rtp_payload[rtp_payload_header:]
                    _print_sample_data(sample_data)

                    if file_name is not None:
                        fd.write(rtp_payload)
                else:
                    print('Not RTP packet.')
            
            else:
                print('data : %s' %ip_payload)
                if file_name is not None:
                    fd.write(str(ip_payload) + '\n')
            
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
            print('[%s] HEADER : %s' % (packet[1][0], packet[0][:ip_header_size]))
            print('Payload : %s' % packet[0][ip_header_size:])
    except KeyboardInterrupt:
        finish_sniffing(sniffer)

def _extract_udp_header(packet, prn=False):
    
    raw_udp_header = packet[:udp_header_size]

    #2,2,2,2
    unpacked = struct.unpack('!HHHH', raw_udp_header)

    format_element = [
        'source_port',
        'destination_port',
        'udp_packet_length',
        'udp_header_checksum'
    ]
    udp_header_format = namedtuple('udp_header_format', format_element)

    formatted = udp_header_format(
        unpacked[0],    #16bits
        unpacked[1],    #16bits
        unpacked[2],    #16bits
        unpacked[3]     #16bits
    )

    if (prn):
        print(formatted)
    
    return formatted

def _extract_icmp_header(packet, prn=False):

    raw_icmp_header = packet[:icmp_header_size]

    #1,1,2,4
    unpacked = struct.unpack('!BBH4s', raw_icmp_header)

    format_element = [
        'type',             #8 bits
        'code',             #8 bits
        'header_checksum',  #16bits
        'icmp_message'      #32bits
    ]
    icmp_header_format = namedtuple('icmp_header_format', format_element)

    formatted = icmp_header_format(
        _get_icmp_type(unpacked[0]),
        _get_icmp_code(unpacked[1]),
        _get_icmp_header_checksum(unpacked[2]),
        _get_icmp_message(unpacked[3])
    )
    
    if (prn):
        print(formatted)
    
    return formatted


def _extract_ipheader(packet, prn=False):

    raw_ipheader = packet[:ip_header_size]

    #1,1,2,2,2,1,1,2,4,4
    unpacked = struct.unpack('!BBHHHBBH4s4s', raw_ipheader)
    
    format_element = [
        'version',              #4 bits
        'header_length',        #4 bits
        'service_type',         #8 bits
        'entire_packet_length', #16bits
        'datagram_id',          #16bits
        'flag',                 #3 bits
        'fragment_offset',      #13bits
        'time_to_live',         #8 bits
        'protocol',             #8 bits
        'header_checksum',      #16bits
        'source_ip',            #32bits
        'destination_ip'        #32bits
    ]
    ipheader_format = namedtuple('ipheader_format', format_element)
    
    formatted = ipheader_format(
        _get_version(unpacked[0]),
        _get_header_length(unpacked[0]),
        _get_service_type(unpacked[1]),
        _get_entire_packet_length(unpacked[2]),
        _get_datagram_id(unpacked[3]),
        _get_flag(unpacked[4]),
        _get_fragment_offset(unpacked[4]),
        _get_time_to_live(unpacked[5]),
        _get_protocol(unpacked[6]),
        _get_header_ckecksum(unpacked[7]),
        _get_source_ip(unpacked[8]),
        _get_destination_ip(unpacked[9])
        )
    
    if (prn):
        print(formatted)
    
    return formatted

def _extract_rtp_header(packet, prn=False):

    try:
        raw_rtp_header = packet[:rtp_header_size]

        #1,1,2,4,4
        unpacked = struct.unpack('!BBHLL', raw_rtp_header)

    except:
        return None

    format_element = [
            'version',          #2 bits
            'padding',          #1 bit
            'extension',        #1 bit
            'CSRC_count',       #4 bits
            'marker',           #1 bit
            'payload_type',     #7 bits
            'sequence_num',     #16bits
            'timestamp',        #32bits
            'SSRC',             #32bits
            ]
    rtp_header_format = namedtuple('rtp_header_format', format_element)
    
    formatted = rtp_header_format(
            _get_rtp_version(unpacked[0]),
            _get_rtp_padding(unpacked[0]),
            _get_rtp_extension(unpacked[0]),
            _get_rtp_CSRC_count(unpacked[0]),
            _get_rtp_marker(unpacked[1]),
            _get_rtp_payload_type(unpacked[1]),
            _get_rtp_sequence_num(unpacked[2]),
            _get_rtp_timestamp(unpacked[3]),
            _get_rtp_SSRC(unpacked[4])
            )

    if (prn):
        print(formatted)

    return formatted

def _extract_rtp_payload_header(packet, prn=False):
    
    try:
        raw_rtp_payload_header = packet[rtp_payload_header_size]
        #1
        unpacked = struct.unpack('!B', raw_rtp_payload_header)

    except:
        return None

    format_element = [
            'reserved',     #5 bits
            'mode_index'    #3 bits
            ]

    rtp_payload_header_format = namedtuple('rtp_payload_header_format', format_element)

    formatted = rtp_payload_header_format(
            _get_rtp_payload_reserved(unpacked[0]),
            _get_rtp_payload_mode_index(unpacked[0])
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
        print('Wrong format. Use _extract_icmp_header(packet, prn)')
        return

    print('ICMP type \t: %s' %icmp_header.type)
    print('ICMP code \t: %s' %icmp_header.code)
    print('ICMP checksum \t: %s' %icmp_header.header_checksum)
    print('ICMP message \t: %s' %icmp_header.icmp_message)


def _print_udp_header(udp_header):
    if type(udp_header).__name__.__ne__('udp_header_format'):
        print('Wrong format. Use _extract_udp_header(packet, prn)')
        return

    print('UDP source port \t: %s' %udp_header.source_port)
    print('UDP destination_port \t: %s' %udp_header.destination_port)
    print('UDP packet_length \t: %s' %udp_header.udp_packet_length)
    print('UDP header_checksum \t: %s' %udp_header.udp_header_checksum)

def _print_sample_data(sample_data):
    print('Sample Data : ')
    try:
        for x in sample_data:
            print('%X ' %x, end='')

    except:
        print('Wrong format.')
        return

def _select_protocol():
   
    protocols = {'1':IPPROTO_TCP, '2':IPPROTO_UDP, '3':IPPROTO_ICMP}

    while True:
        print('########Select Protocol########')
        print('\t1. TCP')
        print('\t2. UDP')
        print('\t3. ICMP')
        choose = input('Choose : ')
        if choose in protocols:
            protocol = protocols[choose]
            break;
        else:
            print('Wrong Number!!')
        
    return protocol


# (xxxx)(xxxx)에서 앞의 4자리가 버전을 나타냄. 뒤의 4자리를 버리기위해 쉬프트연산.
def _get_version(ipheader):return int((ipheader & 0xF0) >> 4)
# (xxxx)(xxxx)에서 뒤의 4자리가 길이를 나타냄. 4바이트단위로 나타냈기 때문에 4를 곱하기위해 쉬프트연산.
def _get_header_length(ipheader):return int((ipheader & 0x0F) << 2)

def _get_service_type(ipheader):return ipheader

def _get_entire_packet_length(ipheader):return int(ipheader)

def _get_datagram_id(ipheader):return int(ipheader)

def _get_flag(ipheader):return ((ipheader & 0xE0) >> 5)

def _get_fragment_offset(ipheader):return (ipheader & 0x1F)

def _get_time_to_live(ipheader):return ipheader

def _get_protocol(ipheader):
    protocols = {1:'ICMP', 6:'TCP', 17:'UDP', 18:'MUX', 27:'RDP'}
    if ipheader in protocols:
        return protocols[ipheader]
    else:
        return 'OTHERS : ' + str(ipheader)

def _get_header_ckecksum(ipheader):return ipheader

def _get_source_ip(ipheader):return inet_ntoa(ipheader)

def _get_destination_ip(ipheader):return inet_ntoa(ipheader)

def _get_icmp_type(icmp_header):
    types = {
        0:'ICMP Echo Reply',
        3:'Destination Unreachable',
        4:'Source Quench(NOT STANDARD)',
        5:'Redirect',
        8:'ICMP Echo Request',
        9:'Router Advertisement',
        10:'Router Solicitation',
        11:'Time Exceeded',
        12:'Parameter Problem'
    }

    if icmp_header in types:
        return types[icmp_header] + '[' + str(icmp_header) + ']'
    else:
        return 'OTHERS : ' + str(icmp_header)

def _get_icmp_code(icmp_header):
    codes = {
        0:'Network Unreachable',
        1:'Host Unreachable',
        2:'Protocol Unreachable',
        3:'Port Unreachable'
    }

    if icmp_header in codes:
        return codes[icmp_header] + '[' + str(icmp_header) + ']'
    else:
        return 'OTHERS : ' + str(icmp_header)

def _get_icmp_header_checksum(icmp_header):return int(icmp_header)

def _get_icmp_message(icmp_header):return str(icmp_header)

def _get_udp_source_port(udp_header):return udp_header
    
def _get_udp_destination_port(udp_header):return udp_header
    
def _get_udp_packet_length(udp_header):return udp_header

def _get_udp_checksum(udp_header):return udp_header

def _get_rtp_version(rtp_header):return int((rtp_header & 0b11000000) >> 6)

def _get_rtp_padding(rtp_header):return int((rtp_header & 0b00100000) >> 5)

def _get_rtp_extension(rtp_header):return int((rtp_header & 0b00010000) >> 4)

def _get_rtp_CSRC_count(rtp_header):return int(rtp_header & 0x0F)

def _get_rtp_marker(rtp_header):return int((rtp_header & 0b10000000) >> 7)

def _get_rtp_payload_type(rtp_header):return (rtp_header & 0x7F)

def _get_rtp_sequence_num(rtp_header):return rtp_header

def _get_rtp_timestamp(rtp_header):return (rtp_header)

def _get_rtp_SSRC(rtp_header):return str(rtp_header)

def _get_rtp_payload_reserved(rtp_payload_header):return ((rtp_payload_header & 0xF8) >> 3)

def _get_rtp_payload_mode_index(rtp_payload_header):return int(rtp_payload_header & 0x07)


