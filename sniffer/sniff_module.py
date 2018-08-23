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
        fd = open(file_name, 'wb+')

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

            if ipheader.protocol is 'ICMP':
                icmp_header = _extract_icmp_header(packet, ipheader.header_length)
                _print_icmp_header(icmp_header)
                print('ICMP Payload : %s' %packet[0][ipheader.header_length+icmp_header_size:])

                if file_name is not None:
                    fd.write(str(icmp_header) + '\n')
                    fd.write(str(packet[0][ipheader.header_length+icmp_header_size:]) + '\n')
            
            elif ipheader.protocol is 'UDP':
                udp_header = _extract_udp_header(packet, ipheader.header_length)
                _print_udp_header(udp_header)

                rtp_header = _extract_rtp_header(packet, ipheader.header_length+udp_header_size, True)
                if rtp_header:
                    rtp_payload_header = _extract_rtp_payload_header(packet, ipheader.header_length+udp_header_size+rtp_header_size, True)
                    
                    idx = rtp_payload_header.mode_index
                    if idx > 4:
                        print('big')
                        continue
                    if idx <1:
                        print('small')
                        continue

                    rtp_payload = packet[0][ipheader.header_length+udp_header_size+rtp_header_size+rtp_payload_header_size:]
                    print('RTP Payload : %s' %rtp_payload)

                    if file_name is not None:
                        fd.write(rtp_payload)

                        '''
                        convert = rtp_payload.replace(b'\xff', b'\x00')
                        print('converted : %s' %convert)
                        fd.write(convert)
                        '''
                        
                        ''' 
                        to_write = packet[0][ipheader.header_length+len(udp_header)+len(rtp_header):]
                        write_list=[]
                        for x in to_write:
                            convert = hex(x).replace('0x', '', 1)
                            if len(convert) is 1:
                                convert = '0' + convert
                            write_list.append(convert)
                            print(convert)
                            #write_list.append(hex(x))
                        
                        print(write_list)
                        for sample in write_list:
                            raw_sample = " ".join(sample)
                            #print(raw_sample)
                            #print('samplw : %s' %sample)
                            write_sample = bytearray.fromhex(sample)
                            fd.write(write_sample)
                            print(write_sample)
                        '''


                #Printing UDP payload.
                #print('UDP Payload : %s' %packet[0][ipheader.header_length+len(udp_header):])
            
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

def _extract_udp_header(packet, start_offset, prn=False):
    
    raw_udp_header = packet[0][start_offset:start_offset+8]

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
        unpacked[0],
        unpacked[1],
        unpacked[2],
        unpacked[3]
    )

    if (prn):
        print(formatted)
    
    return formatted

def _extract_icmp_header(packet, start_offset, prn=False):

    raw_icmp_header = packet[0][start_offset:start_offset+8]

    #1,1,2,4
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

def _extract_rtp_header(packet, start_offset, prn=False):

    try:
        raw_rtp_header = packet[0][start_offset:start_offset+12]

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
            get_rtp_version(unpacked[0]),
            get_rtp_padding(unpacked[0]),
            get_rtp_extension(unpacked[0]),
            get_rtp_CSRC_count(unpacked[0]),
            get_rtp_marker(unpacked[1]),
            get_rtp_payload_type(unpacked[1]),
            get_rtp_sequence_num(unpacked[2]),
            get_rtp_timestamp(unpacked[3]),
            get_rtp_SSRC(unpacked[4])
            )

    if (prn):
        print(formatted)

    return formatted

def _extract_rtp_payload_header(packet, start_offset, prn=False):
    
    try:
        raw_rtp_payload_header = packet[0][start_offset:start_offset+1]
        print("payhead : %s" %raw_rtp_payload_header)
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
            get_rtp_payload_reserved(unpacked[0]),
            get_rtp_payload_mode_index(unpacked[0])
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


def _print_udp_header(udp_header):
    if type(udp_header).__name__.__ne__('udp_header_format'):
        print('Wrong format. Use _extract_udp_header(packet, start_offset, prn)')
        return

    print('UDP source port \t: %s' %udp_header.source_port)
    print('UDP destination_port \t: %s' %udp_header.destination_port)
    print('UDP packet_length \t: %s' %udp_header.udp_packet_length)
    print('UDP header_checksum \t: %s' %udp_header.udp_header_checksum)

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

def get_icmp_code(icmp_header):
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

def get_icmp_header_checksum(icmp_header):return int(icmp_header)

def get_icmp_message(icmp_header):return str(icmp_header)

def get_udp_source_port(udp_header):return udp_header
    
def get_udp_destination_port(udp_header):return udp_header
    
def get_udp_packet_length(udp_header):return udp_header

def get_udp_checksum(udp_header):return udp_header

def get_rtp_version(rtp_header):return int((rtp_header & 0b11000000) >> 6)

def get_rtp_padding(rtp_header):return int((rtp_header & 0b00100000) >> 5)

def get_rtp_extension(rtp_header):return int((rtp_header & 0b00010000) >> 4)

def get_rtp_CSRC_count(rtp_header):return int(rtp_header & 0x0F)

def get_rtp_marker(rtp_header):return int((rtp_header & 0b10000000) >> 7)

def get_rtp_payload_type(rtp_header):return (rtp_header & 0x7F)

def get_rtp_sequence_num(rtp_header):return rtp_header

def get_rtp_timestamp(rtp_header):return (rtp_header)

def get_rtp_SSRC(rtp_header):return str(rtp_header)

def get_rtp_payload_reserved(rtp_payload_header):return ((rtp_payload_header & 0xF8) >> 3)

def get_rtp_payload_mode_index(rtp_payload_header):return int(rtp_payload_header & 0x07)


