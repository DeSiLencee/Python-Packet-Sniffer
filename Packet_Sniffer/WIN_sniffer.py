
import socket
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

#Unpack ethernet frame

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return get_mac_Addr(dest_mac), get_mac_Addr(src_mac), socket.htons(proto), data[14:]

def main():
   
    conn = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP) 
    conn.bind(('HOST_IP',0))                                                        #HOST_IP is the Local IPv4 Address
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    while True:
        raw_data, addr = conn.recvfrom(65535)
        
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        
        print('\nEthernet Frame: ')
        print(TAB_1 + 'Destination: {}, Source {}, Protocol {}'.format(dest_mac, src_mac, eth_proto))

        # 8 for IPv4
        if eth_proto == 8:      
            (version, header_length, ttl, proto, src, target, data)= ipv4_packet(data)
            print(TAB_1+ 'IPv4 Packet : ')
            print(TAB_2+ 'Version : {}, Header Length : {}, TTL : {}'.format(version,header_length,ttl))
            print(TAB_2+ 'Protocol : {}, Source : {}, Target : {}'.format(proto,src,target))

            #ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet :')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type,code,checksum))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3,data))
            #TCP
            elif proto == 6:
                src_port, dest_port, sequence, ack_num , flag_urg, flag_syn, flag_fin, flag_psh, flag_rst, flag_ack, data=tcp_segment(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {},'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence,ack_num))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack , flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            #UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port,length))
            
            #Other
            else:
                print(TAB_1 + 'Data:')
                print(format_multi_line(DATA_TAB_2, data))
        
        else:
            print(TAB_1 + 'Data:')
            print(format_multi_line(DATA_TAB_1, data))
                


#Return formatted MAC address ( ie AA:BB:CC:DD:EE:FF)

def get_mac_Addr(bytes_Addr):
    bytes_str = map('{:02x}'.format, bytes_Addr)
    mac_Addr = ':'.join(bytes_str).upper()
    return mac_Addr

#Unpack IPv4 Packets

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
    return version, header_length, ttl , proto, ipv4(src), ipv4(target), data[header_length:]

#Returns properly formatted IPv4 addr

def ipv4(addr):
    return '.'.join(map(str, addr))

#Unpack ICMP Packet

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
    return icmp_type, code, checksum, data[4:]

#Unpack TCP Segment

def tcp_segment(data):
    (src_port, dest_port, sequence, ack_num, offset_reserved_flags) = struct.unpack('!HHLLH', data[:14])
    offset= (offset_reserved_flags >> 12) *4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    return src_port, dest_port, sequence, ack_num , flag_urg, flag_syn, flag_fin, flag_psh, flag_rst, flag_ack, data[offset:]

#Unpack UDP Segment

def udp_segment(data):
    src_port, dest_port, size= struct.unpack('!HH2xH', data[:8])
    return src_port, dest_port,size, data[8:]

# Formats multi-line data

def format_multi_line(prefix, string , size=80):
    size -=len(prefix)
    if isinstance(string, bytes):
        string= ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -=1
    
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()