import os
from binascii import hexlify
from collections import Counter
from scapy.all import rdpcap
from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString


def extract_ethertype(raw_packet):
    if len(raw_packet) >= 14:
        ether_type_bytes = raw_packet[12:14]
        return int.from_bytes(ether_type_bytes, byteorder='big')
    else:
        return None


def extract_8023_type(raw_packet):
    if len(raw_packet) >= 17:
        control = int.from_bytes(raw_packet[16:17], byteorder='big')
        if control == 0X03:  # IEEE 802.3 LLC / LLC + SNAP
            snap_check = int.from_bytes(raw_packet[15:16], byteorder='big')
            if snap_check == 0XAA:
                return "IEEE 802.3 LLC & SNAP"
            else:
                return "IEEE 802.3 LLC"
        else:
            return "IEEE 802.3 RAW"
    else:
        return None


def extract_sap(raw_packet):
    if len(raw_packet) >= 16:
        llc_header = raw_packet[14:17]
        sap = int.from_bytes(llc_header[:1], byteorder='big')
        return sap
    else:
        return None


def extract_ether(raw_packet):
    if len(raw_packet) >= 22:
        snap_header = raw_packet[20:22]
        ethertype = int.from_bytes(snap_header[:2], byteorder='big')
        return ethertype
    else:
        return None


def format_mac(mac_bytes):
    return ':'.join(['{:02X}'.format(byte) for byte in mac_bytes])


def extract_mac(raw_packet):
    if len(raw_packet) >= 12:
        dest = format_mac(raw_packet[0:6])
        src = format_mac(raw_packet[6:12])
        return dest, src
    else:
        return None, None

def extract_arp_ip(raw_packet):
    if len(raw_packet) >=42:
        s = '.'.join(map(str, raw_packet[28:32]))
        d = '.'.join(map(str, raw_packet[38:42]))
        #print(s) src
        #print(d) dst
        return s, d
    else:
        return None, None
def extract_ipv4_ip(raw_packet):
    if len(raw_packet) >= 34:
        s = '.'.join(map(str, raw_packet[26:30]))
        d = '.'.join(map(str, raw_packet[30:34]))
        return s, d
    else:
        return None, None

def extract_ipv6_ip(raw_packet):
    if len(raw_packet) >= 54:
        s = format_mac(raw_packet[22:38])
        d = format_mac(raw_packet[38:54])
        return s,d
    else:
        return None,None

def extract_ipv4_protocol(raw_packet):
    if len(raw_packet) >= 24:
        return int.from_bytes(raw_packet[23:24], byteorder='big')

def extract_UDP_protocols(raw_packet):
    if len(raw_packet) >= 38:
        return int.from_bytes(raw_packet[34:36], byteorder='big'),int.from_bytes(raw_packet[36:38], byteorder='big')
    else:
        return None

def extract_TCP_protocols(raw_packet):
    if len(raw_packet) >= 38:
        return int.from_bytes(raw_packet[34:36], byteorder='big'),int.from_bytes(raw_packet[36:38], byteorder='big')
    else:
        return None


def extract_flag(raw_packet):
    if len(raw_packet) >= 48:
        return int.from_bytes(raw_packet[47:48], byteorder='big')
    else:
        return None

tcp_connections = [None, None]
comm_open = [None, None, None]
comm_close = [None, None, None, None]
def is_comm_start(p1,p2,p3):
    #print("Frame 1 Flags:", int.from_bytes(p1[47:48], byteorder='big'))
    #print("Frame 2 Flags:", int.from_bytes(p2[47:48], byteorder='big'))
    #print("Frame 3 Flags:", int.from_bytes(p3[47:48], byteorder='big'))

    if len(p1) >= 48 and len(p2) >= 48 and len(p3) >= 48:
        if int.from_bytes(p1[47:48], byteorder='big') == 2:
            if int.from_bytes(p2[47:48], byteorder='big') == 18:
                if int.from_bytes(p3[47:48], byteorder='big') == 16:
                    print("Three way handshake YAY!!!")
                    return True
                else: return False
            else: return False
        else: return  False
    else: return False

def is_comm_end(p1,p2,p3,p4):
    #print("Frame 1 Flags:", int.from_bytes(p1[47:48], byteorder='big'))
    #print("Frame 2 Flags:", int.from_bytes(p2[47:48], byteorder='big'))
    #print("Frame 3 Flags:", int.from_bytes(p3[47:48], byteorder='big'))
    #print("Frame 4 Flags:", int.from_bytes(p3[47:48], byteorder='big'))


    if len(p1) >= 48 and len(p2) >= 48 and len(p3) >= 48:
        if int.from_bytes(p1[47:48], byteorder='big') == 17:
            if int.from_bytes(p2[47:48], byteorder='big') == 16:
                if int.from_bytes(p3[47:48], byteorder='big') == 17:
                    if int.from_bytes(p3[47:48], byteorder='big') == 16:
                        print("Four way handshake YAY!!!")
                    return True
                else: return False
            else: return False
        else: return  False
    else: return False



def main():
    file_choice = input("Press ENTER for DEFAULT FILE, or specify file name:")
    pcap_filename = "trace-27.pcap"
    if file_choice:
        try:
            with open(file_choice, 'r'):
                pcap_filename = file_choice
        except FileNotFoundError:
            print(f"File: '{file_choice}' not found, using default file")

    mode = input("Press ENTER for BASIC setup, or -p for PROTOCOL")
    if mode == 'p':
        input_protocol = input("Specify the protocol you want to filter (HTTP, HTTPS, TELNET, SSH, FTP-R, FTP-D)").strip().upper()
        if input_protocol == "HTTP":
            pass
        elif input_protocol == "TELNET":
            pass
        elif input_protocol == "HTTPS":
            pass
        elif input_protocol == "SSH":
            pass
        elif input_protocol == "FTP-R":
            pass
        elif input_protocol == "FTP-D":
            pass
        else:
            pass
    else:
        pass
    packets_data = []
    source_ip_counter = Counter()

    ethertype_data = {}
    with open("Ethertype_data.txt", "r") as ethertype_file:
        for line in ethertype_file:
            parts = line.strip().split(":")
            if len(parts) == 2:
                ethertype, protocol = int(parts[0]), parts[1]
                ethertype_data[ethertype] = protocol

    udp_well_known_data = {}
    with open("Udp_protocol_data.txt", "r") as udp_file:
        for line in udp_file:
            parts = line.strip().split(":")
            if len(parts) == 2:
                udp_prot, udp_well_known_protocol = int(parts[0]), parts[1]
                udp_well_known_data[udp_prot] = udp_well_known_protocol

    tcp_well_known_data = {}
    with open("Tcp_protocol_data.txt", "r") as tcp_file:
        for line in tcp_file:
            parts = line.strip().split(":")
            if len(parts) == 2:
                tcp_prot, tcp_well_known_protocol = int(parts[0]), parts[1]
                tcp_well_known_data[tcp_prot] = tcp_well_known_protocol

    ipv4_protocol_data = {}
    with open("Ipv4_protocol_data.txt", "r") as ipv4_file:
        for line in ipv4_file:
            parts = line.strip().split(":")
            if len(parts) == 2:
                ipv4_prot, protocol = int(parts[0]), parts[1]
                ipv4_protocol_data[ipv4_prot] = protocol

    try:
        packets = rdpcap(pcap_filename)

        for packet_count, packet in enumerate(packets):
            eth_length = 0
            packet_type = "Unknown"
            sap_name = None
            pid_name = None
            e2_protocol = None
            src_ip = None
            dst_ip = None
            well_known_src = None
            well_known_dst = None
            ipv4_protocol = None
            dest, src = extract_mac(bytes(packet))
            ipv4_type = extract_ipv4_protocol(bytes(packet))
            eth_type = extract_ethertype(bytes(packet))
            udp_src, udp_dest = extract_UDP_protocols(bytes(packet))
            tcp_src, tcp_dest = extract_TCP_protocols(bytes(packet))
            flags = None
            comm_src = None
            comm_dst = None
            #print(udp_dest)

            if eth_type is not None:
                if eth_type <= 1500:
                    eth_length = 4
                    packet_type = extract_8023_type(bytes(packet))
                    if packet_type == "IEEE 802.3 LLC" or packet_type == "IEEE 802.3 LLC & SNAP":
                        sap_name = get_sap_name(extract_sap(bytes(packet)))
                    if packet_type == "IEEE 802.3 LLC & SNAP":
                        pid_name = get_pid_name(extract_ether(bytes(packet)))
                else:
                    eth_length = 4
                    packet_type = "ETHERNET II"
                    if eth_type in ethertype_data:
                        e2_protocol = ethertype_data[eth_type]

                        if eth_type == 2054:  # ARP
                            src_ip, dst_ip = extract_arp_ip(bytes(packet))
                            #print(src_ip)

                        if eth_type == 2048: #IPV4
                            src_ip, dst_ip = extract_ipv4_ip(bytes(packet))

                            #uloha 3
                            if src_ip:
                                source_ip_counter[src_ip] += 1

                            if ipv4_type in ipv4_protocol_data:
                                ipv4_protocol = ipv4_protocol_data[ipv4_type]
                                #print(ipv4_protocol)

                            if ipv4_protocol == "TCP":
                                if tcp_src in tcp_well_known_data:
                                    well_known_src = tcp_well_known_data[tcp_src]
                                if tcp_dest in tcp_well_known_data:
                                    well_known_dst = tcp_well_known_data[tcp_dest]
                                flags = extract_flag(bytes(packet))
                                if flags == 2:
                                    #print("Syn")
                                    comm_open[0] = bytes(packet)
                                elif flags == 18:
                                    #print("Syn Ack")
                                    comm_open[1] = bytes(packet)
                                elif flags == 16:
                                    #print("Ack")
                                    comm_open[2] = bytes(packet)
                                if comm_open[0] and comm_open[1] and comm_open[2]:
                                    if is_comm_start(comm_open[0], comm_open[1], comm_open[2]):
                                        comm_src, comm_dst = extract_TCP_protocols(comm_open[0])
                                        tcp_connections[0], tcp_connections[1] = extract_TCP_protocols(comm_open[0])
                                        comm_open[:3] = [None, None, None]  # Empty the comm_open array
                                        print(comm_src, " - ", comm_dst)

                                if flags == 17:
                                    c1,c2 = extract_TCP_protocols(bytes(packet))
                                    print(c1, c2, tcp_connections[0], tcp_connections[1])
                                    if c1 == tcp_connections[0] and c2 == tcp_connections[1]:
                                        comm_close[0] = bytes(packet)
                                    elif c1 == tcp_connections[1] and c2 == tcp_connections[0]:
                                        comm_close[2] = bytes(packet)

                                elif flags == 16:
                                    c1,c2 = extract_TCP_protocols(bytes(packet))
                                    if c1 == tcp_connections[1] and c2 == tcp_connections[0]:
                                        comm_close[1] = bytes(packet)
                                    elif c1 == tcp_connections[0] and c2 == tcp_connections[1]:
                                        comm_close[3] = bytes(packet)

                                if comm_close[0] and comm_close[1] and comm_close[2] and comm_close[3]:
                                    if is_comm_end(comm_close[0], comm_close[1], comm_close[2], comm_close[3]):
                                        comm_close[:4] = [None, None, None, None]
                                        print("Comm between:", tcp_connections[0], " - ", tcp_connections[1], "ended")

                            if ipv4_protocol == "UDP":
                                if udp_src in udp_well_known_data:
                                    well_known_src = udp_well_known_data[udp_src]
                                if udp_dest in udp_well_known_data:
                                    well_known_dst = udp_well_known_data[udp_dest]


                        if eth_type == 34525: #IPV6
                            src_ip, dst_ip = extract_ipv6_ip(bytes(packet))



            else:
                packet_type = "Unknown"

            hex_data = ' '.join(['{:02X}'.format(byte) for byte in bytes(packet)])
            hex_numbers = hex_data.split()
            rows_of_16 = [hex_numbers[i:i + 16] for i in range(0, len(hex_numbers), 16)]

            hexa_frame_content = '\n'.join([' '.join(row) for row in rows_of_16])

            hexa_frame_literal = LiteralScalarString(f"{hexa_frame_content}\n")

            packet_data = {
                "frame_number": packet_count + 1,
                "len_frame_pcap": len(packet),
                "len_frame_medium": max(64, len(packet) + eth_length),
                "frame_type": packet_type,
                "src_mac": src,
                "dst_mac": dest,
                "hexa_frame": hexa_frame_literal,
            }

            if sap_name and pid_name == None:
                packet_data["sap"] = sap_name

            if pid_name:
                packet_data["pid"] = pid_name

            if e2_protocol:
                packet_data["vnoreny protokol (2a)"] = e2_protocol

            if eth_type == 2054 or eth_type == 2048 or eth_type == 34525: #ARP, IPV4, IPV6
                packet_data["src_ip"] = src_ip
                packet_data["dst_ip"] = dst_ip

            if eth_type == 2048:
                if ipv4_protocol:
                    packet_data["IpV4 protocol"] = ipv4_protocol
                    print(ipv4_protocol)

                if ipv4_protocol == "UDP":
                    packet_data["udp_src"] = udp_src
                    packet_data["udp_dest"] = udp_dest
                    if well_known_src:
                        packet_data["udp src well known port"] = well_known_src
                    if well_known_dst:
                        packet_data["udp dst well known port"] = well_known_dst

                if ipv4_protocol == "TCP":
                    packet_data["tcp_src"] = tcp_src
                    packet_data["tcp_dest"] = tcp_dest
                    if well_known_src:
                        packet_data["tcp src well known port"] = well_known_src
                    if well_known_dst:
                        packet_data["tcp dst well known port"] = well_known_dst


            packets_data.append(packet_data)

        most_common_ip, most_common_count = source_ip_counter.most_common(1)[0]
        print("ipv4_senders:")

        for ip, count in source_ip_counter.items():
            print("  - node:", ip)
            print("    number_of_sent_packets:", count)

        print("max_send_packets_by:")
        print("  -", most_common_ip)


    except FileNotFoundError:
        print(f"File not found: {pcap_filename}")
    except Exception as e:
        print(f"Error reading the pcap file: {e}")

    yaml_data = {
        "name": "PKS2023/24",
        "pcap_name": pcap_filename,
        "packets": packets_data,
    }

    yaml = YAML()
    yaml.indent(offset=2, sequence=4)

    with open("output25.yaml", "w") as yaml_file:
        yaml.dump(yaml_data, yaml_file)


def get_sap_name(sap):
    sap_mappings = {
        0x00: "Null SAP",
        0x02: "LLC Sublayer Management / Individual",
        0x03: "LLC Sublayer Management / Group",
        0x06: "IP (DoD Internet Protocol)",
        0x0E: "PROWAY (IEC 955) Network Management, Maintenance and Installation",
        0x42: "STP",
        0x4E: "MMS (Manufacturing Message Service) EIA-RS 511",
        0x5E: "ISI IP",
        0x7E: "X.25 PLP (ISO 8208)",
        0x8E: "PROWAY (IEC 955) Active Station List Maintenance",
        0xAA: "SNAP (Sub-Network Access Protocol / non-IEEE SAPs)",
        0xE0: "IPX",
        0xF0: "NETBIOS",
        0xF4: "LAN Management",
        0xFE: "ISO Network Layer Protocols",
        0xFF: "Global DSAP"
    }
    return sap_mappings.get(sap)


def get_pid_name(pid):
    pid_mappings = {
        0x200: "XEROX PUP",
        0x2000: "CDP",
        0x2004: "DTP",
        0x010B: "PVSTP+",
        0x0201: "PUP Addr Trans",
        0x0800: "Internet IP (IPv4)",
        0x0801: "X.75 Internet",
        0x0805: "X.25 Level 3",
        0x0806: "ARP (Address Resolution Protocol)",
        0x8035: "Reverse ARP",
        0x809B: "Appletalk",
        0X80F3: "AppleTalk AARP (Kinetics)",
        0X8100: "IEEE 802.1Q Vlan-tagged frames",
        0X8137: "NOVELL IPX",
        0X86DD: "IPV6",
        0X880B: "PPP",
        0X8847: "MPLS",
        0X8848: "MPLS with upstream assigned label",
        0X8863: "PPPoE Discovery Stage",
        0X8864: "PPoE Session Stage"
    }
    return pid_mappings.get(pid)


#if __name__ == "__main__":
main()
