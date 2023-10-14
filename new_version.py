from binascii import hexlify
from collections import Counter
from scapy.all import rdpcap
from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString


class Commun:  # class for every tcp protocol
    def __init__(self, source, dest, tcp_source_port, tcp_destination_port):
        self.order = []
        self.comm_packets = []
        self.is_complete = 0
        self.source = source
        self.dest = dest
        self.source_port = tcp_source_port
        self.dest_port = tcp_destination_port

    def add_to_packet(self, byte):
        self.comm_packets.append(byte)

    def add_order(self, cislo_ramca):
        self.order.append(cislo_ramca)

class tftp:  # tftp class
    def __init__(self, source, destination):
        self.order = []
        self.comm_packets = []
        self.is_finished = 0
        self.source_port = source
        self.destination_port = destination

    def add_to_packet(self, byte):
        self.comm_packets.append(byte)

    def add_order(self, cislo_ramca):
        self.order.append(cislo_ramca)


def print_addresses(adres):  # prints adreses in corect format
    print("Zdrojová MAC adresa: ", end="")
    flag = 0
    for x in range(6, 12):
        flag += 1
        print(str(hexlify(adres[x:x + 1]))[2: -1], end="")
        print(" ", end="")
    print()

    print("Cieľová MAC adresa: ", end="")
    flag = 0
    for x in range(6):
        flag += 1
        print(str(hexlify(adres[x:x + 1]))[2: -1], end="")
        print(" ", end="")
    print()

E = {

}

IP = {

}

VSETKY_ADRESY = {

}

TCP = {

}
is_first_tftp = 0
is_comm = 0
frame_number = 0
struct_array = []
http_zoznam = []
https_zoznam = []
ftp_r_zoznam = []
telnet_zoznam = []
ssh_zoznam = []
ftp_d_zoznam = []
arp_zoznam = []
tftp_struct_array = []
def load_e():
    with open("Ethertype_data.txt", "r") as ethertype_file:
        for line in ethertype_file:
            x, y = line.split(":", 1)
            x = int(x)
            y = y[0: -1]
            E[x] = y

    with open('Ipv4_protocol_data.txt', 'r') as ipv4_file:
        for line in ipv4_file:
            x, y = line.split(":", 1)
            x = int(x)
            y = y[0: -1]
            IP[x] = y

    with open('Tcp_protocol_data.txt', 'r') as tcp_file:
        for line in tcp_file:
            x, y = line.split(":", 1)
            x = int(x)
            y = y[0: -1]
            TCP[x] = y



def print_protocol_ether_type(decimal):  # prints ether type protocol
    try:
        x = E[decimal]
        print(x)
    except:
        print("Type unknown")

def protocol_ip_type(decimal):  # returns ip protocol
    try:
        x = IP[decimal]
        return x
    except:
        return 0

def count_addresses(adresa):  # counts number of adreses
    if adresa in VSETKY_ADRESY:
        value = VSETKY_ADRESY[adresa]
        VSETKY_ADRESY[adresa] = value + 1
    else:
        VSETKY_ADRESY[adresa] = 1

def tcp_well_known_port(decimal):  # returns well known port
    try:
        x = TCP[decimal]
        print(x)
        return x
    except:
        return 0

def napln_listy(packet):  # naplni mi vsetky polia pozadovanymi protokolmi
    global frame_number
    global arp_zoznam
    #print("list")
    frame_number += 1
    num_dec = int(str(hexlify(packet[12:14]))[2: -1], 16)
    if num_dec == 2048:
        ip_protocol = protocol_ip_type(int(str(hexlify(packet[23:24]))[2: -1], 16))
        #print(ip_protocol)
        offset = int(str(hexlify(packet[14:15]))[3: -1], 16) * 4 + 14
        if ip_protocol == "TCP":
            tcp_source_port = int(str(hexlify(packet[offset:offset + 2]))[2: -1], 16)
            tcp_destination_port = int(str(hexlify(packet[offset + 2:offset + 4]))[2: -1], 16)
            well_known = ""
            if tcp_source_port < tcp_destination_port:
                try:
                    well_known = TCP[tcp_source_port]
                    #print(well_known)
                except:
                    print(end="")
            else:
                try:
                    well_known = TCP[tcp_destination_port]
                except:
                    print(end="")

            if well_known == "HTTP":
                http_zoznam.append([frame_number, packet])
            if well_known == "HTTPS":
                https_zoznam.append(([frame_number, packet]))
            if well_known == "TELNET":
                telnet_zoznam.append(([frame_number, packet]))
            if well_known == "SSH":
                ssh_zoznam.append(([frame_number, packet]))
            if well_known == "FTP-CONTROL":
                ftp_r_zoznam.append(([frame_number, packet]))
            if well_known == "FTP-DATA":
                ftp_d_zoznam.append(([frame_number, packet]))


    if num_dec == 2054:
        arp_zoznam.append([frame_number, packet])



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


comm_open_srcs = []
comm_open_dsts = []
comm_cloes_srcs = []
comm_close_srcs = []
comm_counter = 0
tcp_connections = [None, None]
comm_open = [None, None, None]
comm_close = [None, None, None, None]
active_communications = []
def is_comm_start(p1,p2,p3):
    global session_counter
    if len(p1) >= 48 and len(p2) >= 48 and len(p3) >= 48:
        if int.from_bytes(p1[47:48], byteorder='big') == 2:
            if int.from_bytes(p2[47:48], byteorder='big') == 18:
                if int.from_bytes(p3[47:48], byteorder='big') == 16:
                    # Three-way handshake detected
                    new_comm_session = {
                        "comm_start": p1,
                        "comm_syn_ack": p2,
                        "comm_ack": p3,
                        "comm_end": None
                    }
                    active_communications.append(new_comm_session)
                    return True
                return False

def is_comm_end(p1,p2,p3,p4):
    if len(p1) >= 48 and len(p2) >= 48 and len(p3) >= 48:
        for session in active_communications:
            if int.from_bytes(p1[47:48], byteorder='big') == 17:
                if int.from_bytes(p2[47:48], byteorder='big') == 16:
                    if int.from_bytes(p3[47:48], byteorder='big') == 17:
                        if int.from_bytes(p3[47:48], byteorder='big') == 16:
                            session["comm_end"] = p4
                            active_communications.remove(session)
                            print("Communication session ended")
                        return True
                    else: return False
                else: return False
            else: return  False
    else: return False


def tcp_filter(protocol):  # vypis ulohy 4a
    global struct_array
    offset = 0
    #print("x")

    for packet in protocol:
        #print("Y")
        offset = int(str(hexlify(packet[1][14:15]))[3: -1], 16) * 4 + 14  # ofset pouzivam na spravne posuvanie sa v bytoch
        #source = get_ipv4(packet[1][26:30])  # source ip
        #dest = get_ipv4(packet[1][30:34])  # dest ip
        source, dest = extract_ipv4_ip(packet[1])       # not sure
        tcp_source_port = int(str(hexlify(packet[1][offset:offset + 2]))[2: -1], 16)  # tcp source port
        tcp_destination_port = int(str(hexlify(packet[1][offset + 2:offset + 4]))[2: -1], 16)  # tcp dest port
        first = Commun(source, dest, tcp_source_port, tcp_destination_port)

        if len(struct_array) == 0:
            first.comm_packets.append(packet[1])
            first.add_order(packet[0])
            struct_array.append(first)


        else:
            done = 0
            for x in struct_array:
                if (x.source == dest and x.source_port == tcp_destination_port and x.dest == source and x.dest_port == tcp_source_port)\
                        or (x.source == source and x.source_port == tcp_source_port and x.dest == dest and x.dest_port == tcp_destination_port):  # trosku zvacsit podmienku
                    x.add_order(packet[0])
                    x.add_to_packet(packet[1])
                    done = 1
                    break
            if done == 0:
                first.comm_packets.append(packet[1])
                first.add_order(packet[0])
                struct_array.append(first)

    counter_kde_som = 0
    for x in struct_array:
        if len(x.comm_packets) < 3:
            struct_array[counter_kde_som] = 0
            counter_kde_som += 1
        else:
            offset1, offset2, offset3, start1, start2, start3, end1, end2, end3, end4 = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            offset1 = int(str(hexlify(x.comm_packets[0][14:15]))[3: -1], 16) * 4 + 14
            offset2 = int(str(hexlify(x.comm_packets[1][14:15]))[3: -1], 16) * 4 + 14
            offset3 = int(str(hexlify(x.comm_packets[2][14:15]))[3: -1], 16) * 4 + 14
            start1 = int(str(hexlify(x.comm_packets[0][offset1 + 13: offset + 14]))[2: -1], 16)
            start2 = int(str(hexlify(x.comm_packets[1][offset2 + 13: offset + 14]))[2: -1], 16)
            start3 = int(str(hexlify(x.comm_packets[2][offset3 + 13: offset + 14]))[2: -1], 16)

            if (start1 == 2 and start2 == 18 and start3 == 16):
                x.comm_packets = x.comm_packets
                counter_kde_som += 1
            else:
                struct_array[counter_kde_som] = 0
                counter_kde_som += 1


    for x in struct_array:
        if x == 0:
            continue
        offset1,offset2,offset3,start1,start2,start3,end1,end2,end3,end4=0,0,0,0,0,0,0,0,0,0
        offset1 = int(str(hexlify(x.comm_packets[0][14:15]))[3: -1], 16) * 4 + 14
        offset2 = int(str(hexlify(x.comm_packets[1][14:15]))[3: -1], 16) * 4 + 14
        offset3 = int(str(hexlify(x.comm_packets[2][14:15]))[3: -1], 16) * 4 + 14

        start1 = int(str(hexlify(x.comm_packets[0][offset1 + 13: offset + 14]))[2: -1], 16)

        start2 = int(str(hexlify(x.comm_packets[1][offset2 + 13: offset + 14]))[2: -1], 16)

        start3 = int(str(hexlify(x.comm_packets[2][offset3 + 13: offset + 14]))[2: -1], 16)

        if len(x.comm_packets) >= 4:
            end1 = int(str(hexlify(x.comm_packets[-1][offset1 + 13: offset + 14]))[2: -1], 16)
            end2 = int(str(hexlify(x.comm_packets[-2][offset2 + 13: offset + 14]))[2: -1], 16)
            end3 = int(str(hexlify(x.comm_packets[-3][offset3 + 13: offset + 14]))[2: -1], 16)
            end4 = int(str(hexlify(x.comm_packets[-4][offset3 + 13: offset + 14]))[2: -1], 16)

        if (start1 == 2 and start2 == 18 and start3 == 16) and ((end1 == 4) or (end1 == 20) or (end1 == 16 and end2 == 17 and end3 == 17) or (end1 == 16 and end2 == 17 and end3 == 16 and end4 == 17)):
            x.is_complete = 1
        else:
            x.is_complete = 0

    vypisana_nespravna = 0
    vypisana_spravna = 0
    counter_spravna = 0
    counter_nespravna = 0
    counter_ramca = 0
    for x in struct_array:
        if x == 0:
            continue
        if x.is_complete == 1 and vypisana_spravna == 0:
            print("Vypis kompletnej komunikacie")
            for y in x.comm_packets:
                counter_spravna += 1
                vypisana_spravna = 1
                if (len(x.comm_packets) > 20 and counter_spravna > 10) and len(x.comm_packets) - counter_spravna >= 10:
                    counter_ramca += 1
                    continue
                print("Ramec ", x.order[counter_ramca], ": ", sep="")
                print("dĺžka rámca poskytnutá pcap API – ", len(y), "B")
                if len(y) < 60:
                    print("dĺžka rámca prenášaného po médiu – 64 B", )
                else:
                    print("dĺžka rámca prenášaného po médiu", len(y) + 4, "B")
                counter_ramca += 1
                num_dec = int(str(hexlify(y[12:14]))[2: -1], 16)
                if num_dec > 1500:
                    print("Ethernet II")
                    print_addresses(y)
                    print_protocol_ether_type(num_dec)
                    if num_dec == 2048:
                        ip_protocol = protocol_ip_type(int(str(hexlify(y[23:24]))[2: -1], 16))
                        count_addresses(y[30:34])
                        offset = int(str(hexlify(y[14:15]))[3: -1], 16) * 4 + 14
                        if ip_protocol == "TCP":
                            source, dest = extract_ipv4_ip(y)
                            print("Zdrojova IP adresa: ", source)
                            #print("Zdrojova IP adresa: ", end="")
                            #source = print_ipv4(y[26:30])
                            print("Cielova IP adresa: ", dest)
                            #print("Cielova IP adresa: ", end="")
                            #dest = print_ipv4(y[30:34])
                            print(ip_protocol)
                            tcp_source_port = int(str(hexlify(y[offset:offset + 2]))[2: -1], 16)
                            tcp_destination_port = int(str(hexlify(y[offset + 2:offset + 4]))[2: -1], 16)
                            if tcp_source_port < tcp_destination_port:
                                tcp_well_known_port(tcp_source_port)
                            else:
                                tcp_well_known_port(tcp_destination_port)
                            print("zdrojovy port:", tcp_source_port)
                            print("cielovy port:", tcp_destination_port)
    counter_ramca = 0
    for x in struct_array:
        if x == 0:
            continue
        if x.is_complete == 0 and vypisana_nespravna == 0:
            print("Vypis nekompletnej komunikacie")
            for y in x.comm_packets:
                counter_nespravna += 1
                vypisana_nespravna = 1
                if (len(x.comm_packets) > 20 and counter_nespravna > 10) and len(x.comm_packets) - counter_nespravna >= 10:
                    counter_ramca += 1
                    continue
                print("Ramec ", x.order[counter_ramca], ": ", sep="")
                print("dĺžka rámca poskytnutá pcap API – ", len(y), "B")
                if len(y) < 60:
                    print("dĺžka rámca prenášaného po médiu – 64 B", )
                else:
                    print("dĺžka rámca prenášaného po médiu", len(y) + 4, "B")
                counter_ramca += 1
                num_dec = int(str(hexlify(y[12:14]))[2: -1], 16)
                if num_dec > 1500:
                    print("Ethernet II")
                    print_addresses(y)
                    print_protocol_ether_type(num_dec)
                    if num_dec == 2048:
                        ip_protocol = protocol_ip_type(int(str(hexlify(y[23:24]))[2: -1], 16))
                        count_addresses(y[30:34])
                        offset = int(str(hexlify(y[14:15]))[3: -1], 16) * 4 + 14
                        if ip_protocol == "TCP":
                            source, dest = extract_ipv4_ip(y)
                            print("Zdrojova IP adresa: ", source)
                            # print("Zdrojova IP adresa: ", end="")
                            # source = print_ipv4(y[26:30])
                            print("Cielova IP adresa: ", dest)
                            # print("Cielova IP adresa: ", end="")
                            # dest = print_ipv4(y[30:34])
                            tcp_source_port = int(str(hexlify(y[offset:offset + 2]))[2: -1], 16)
                            tcp_destination_port = int(str(hexlify(y[offset + 2:offset + 4]))[2: -1], 16)
                            if tcp_source_port < tcp_destination_port:
                                tcp_well_known_port(tcp_source_port)
                            else:
                                tcp_well_known_port(tcp_destination_port)
                            print("zdrojovy port:", tcp_source_port)
                            print("cielovy port:", tcp_destination_port)
    if vypisana_spravna == 0:
        print("v tomto pakete sa nenachadza kompletna komunikacia")
    if vypisana_nespravna ==0:
        print("V tomto pakete sa nenachadza nekompletna komunikacia")


def tftp_filter(packet):   # nacitanie ulohy 4g
    global frame_number
    global is_first_tftp
    frame_number += 1
    global is_comm
    destination_port = 0
    source_port = 0

    num_dec = int(str(hexlify(packet[12:14]))[2: -1], 16)
    if num_dec == 2048:
        ip_protocol = protocol_ip_type(int(str(hexlify(packet[23:24]))[2: -1], 16))
        offset = int(str(hexlify(packet[14:15]))[3: -1], 16) * 4 + 14
        if ip_protocol == "UDP":
            source_port = int(str(hexlify(packet[offset :offset + 2]))[2: -1], 16)
            destination_port = int(str(hexlify(packet[offset + 2:offset + 4]))[2: -1], 16)

            if destination_port == 69:
                is_first_tftp = 1
                if is_comm == 1:
                    is_comm = 0
                if is_comm == 0:
                    is_comm = 1

                filtering = tftp(source_port, destination_port)
                filtering.comm_packets.append(packet)
                filtering.add_order(frame_number)
                tftp_struct_array.append(filtering)
                return
        if ip_protocol == "UDP":
            for x in tftp_struct_array:
                if is_first_tftp == 1:
                    if is_comm and (x.source_port == destination_port or x.source_port == source_port):#kukam iba jeden chcel by som obidva
                        if int(str(hexlify(packet[offset + 8:offset + 10]))[2: -1], 16) == 5:
                            x.comm_packets.append(packet)
                            x.add_order(frame_number)
                            is_comm = 0
                            break
                        else:
                            x.destination_port = source_port
                            x.add_order(frame_number)
                            x.comm_packets.append(packet)
                else:
                    if is_comm and ((x.source_port == source_port and x.destination_port == destination_port) or x.source_port == destination_port and x.destination_port == source_port):#kukam iba jeden chcel by som obidva
                        if int(str(hexlify(packet[offset + 8:offset + 10]))[2: -1], 16) == 5:
                            x.comm_packets.append(packet)
                            x.add_order(frame_number)
                            is_comm = 0
                            break
                        else:
                            x.add_order(frame_number)
                            x.comm_packets.append(packet)


def tftp_output():  # vypis ulohy 4g
    counter = 0
    frame_num_count = 0
    for x in tftp_struct_array:
        frame_num_count = 0
        counter += 1
        print("Toto je komunikacia cislo:", counter)
        correct_counter = 0
        for y in x.comm_packets:
            correct_counter += 1
            if (len(x.comm_packets) > 20 and correct_counter > 10) and len(x.comm_packets) - correct_counter >= 10:
                frame_num_count += 1
                continue
            print("Ramec ", x.order[frame_num_count], ": ", sep="")
            print("dĺžka rámca poskytnutá pcap API – ", len(y), "B")
            if len(y) < 60:
                print("dĺžka rámca prenášaného po médiu – 64 B", )
            else:
                print("dĺžka rámca prenášaného po médiu", len(y) + 4, "B")
            frame_num_count += 1
            num_dec = int(str(hexlify(y[12:14]))[2: -1], 16)
            if num_dec > 1500:
                print("Ethernet II")
                print_addresses(y)
                print_protocol_ether_type(num_dec)
                if num_dec == 2048:
                    ip_protocol = protocol_ip_type(int(str(hexlify(y[23:24]))[2: -1], 16))
                    count_addresses(y[30:34])
                    offset = int(str(hexlify(y[14:15]))[3: -1], 16) * 4 + 14
                    if ip_protocol == "UDP":
                        print("TFTP")
                        source, dest = extract_ipv4_ip(y)
                        print("Zdrojova IP adresa: ", source)
                        # print("Zdrojova IP adresa: ", end="")
                        # source = print_ipv4(y[26:30])
                        print("Cielova IP adresa: ", dest)
                        # print("Cielova IP adresa: ", end="")
                        # dest = print_ipv4(y[30:34])
                        print(ip_protocol)
                        tcp_source_port = int(str(hexlify(y[offset:offset + 2]))[2: -1], 16)
                        tcp_destination_port = int(str(hexlify(y[offset + 2:offset + 4]))[2: -1], 16)
                        print("zdrojovy port:", tcp_source_port)
                        print("cielovy port:", tcp_destination_port)
        print()


def main():
    load_e()
    file_choice = input("Press ENTER for DEFAULT FILE, or specify file name:")
    pcap_filename = "trace_ip_nad_20_B.pcap"
    if file_choice:
        try:
            with open(file_choice, 'r'):
                pcap_filename = file_choice
        except FileNotFoundError:
            print(f"File: '{file_choice}' not found, using default file")


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

    input_protocol = None
    mode = input("Press ENTER for BASIC setup, or -p for PROTOCOL")
    if mode == 'p':
        print("Specify the protocol you want to filter:")
        print("4a) - 4e):\t HTTP, HTTPS, TELNET, SSH, FTP-R, FTP-D ")
        print("4f):\t\t TFTP")
        print("4g) - 4h):\t ICMP")
        print("4i):\t\t ARP")
        input_protocol = input(">").strip().upper()

    try:
        packets = rdpcap(pcap_filename)
        counter = 1
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

            if input_protocol == "HTTP":
                napln_listy(bytes(packet))
                if counter == len(packets):
                    tcp_filter(http_zoznam)
                counter += 1

            elif input_protocol == "FTP-D":
                napln_listy(bytes(packet))
                if counter == len(packets):
                    #print("test")
                    tcp_filter(ftp_d_zoznam)
                counter += 1

            elif input_protocol == "TELNET":
                napln_listy(bytes(packet))
                if counter == len(packets):
                    tcp_filter(telnet_zoznam)
                counter += 1

            elif input_protocol == "HTTPS":
                napln_listy(bytes(packet))
                if counter == len(packets):
                    tcp_filter(https_zoznam)
                counter += 1

            elif input_protocol == "SSH":
                napln_listy(bytes(packet))
                if counter == len(packets):
                    tcp_filter(ssh_zoznam)
                counter += 1

            elif input_protocol == "FTP-R":
                napln_listy(bytes(packet))
                if counter == len(packets):
                    tcp_filter(ftp_r_zoznam)
                counter += 1

            elif input_protocol == "TFTP":
                tftp_filter(bytes(packet))
                if counter == len(packets):
                    tftp_output()
                counter += 1

            elif input_protocol == "ARP":
                pass

            elif input_protocol == "ICMP":
                pass


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
                                    """
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
                                        comm_open_srcs.insert(comm_counter, comm_src)
                                        comm_open_dsts.insert(comm_counter, comm_dst)
                                        tcp_connections[0], tcp_connections[1] = extract_TCP_protocols(comm_open[0])
                                        comm_open[:3] = [None, None, None]  # Empty the comm_open array
                                        print(f"Session between {comm_src} and  {comm_dst} started")

                                if flags == 17:
                                    c1,c2 = extract_TCP_protocols(bytes(packet))
                                    #print(c1, c2, tcp_connections[0], tcp_connections[1])
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
                                        print(f"Comm between {tcp_connections[0]} and {tcp_connections[1]} ended")

                                print(comm_open_srcs)
                                #for x in comm_open_srcs:
                                #    if (tcp_src == comm_open_srcs[x] and tcp_dest == comm_open_dsts[x]) or (tcp_src == comm_open_dsts[x] and tcp_dest == comm_open_srcs[x]):
                                #        print("comm")
"""
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
                    #print(ipv4_protocol)

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
