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
                return "IEEE 802.3 LLC and SNAP"
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


def main():
    pcap_filename = "trace-27.pcap"
    packets_data = []

    try:
        packets = rdpcap(pcap_filename)
        packet_count = 0

        for packet in packets:
            eth_length = 0
            packet_type = "Unknown"
            sap_name = None
            ethertype_name = None
            dest, src = extract_mac(bytes(packet))

            # Extract the EtherType field
            eth_type = extract_ethertype(bytes(packet))

            if eth_type is not None:
                if eth_type <= 1500:
                    eth_length = 4
                    packet_type = extract_8023_type(bytes(packet))
                    if packet_type == "IEEE 802.3 LLC" or packet_type == "IEEE 802.3 LLC and SNAP":
                        sap_name = get_sap_name(extract_sap(bytes(packet)))
                    if packet_type == "IEEE 802.3 LLC and SNAP":
                        ethertype_name = get_ethertype_name(extract_ether(bytes(packet)))
                else:
                    eth_length = 4
                    packet_type = "Ethernet II"
            else:
                # If there is no EtherType, label it as "Unknown"
                packet_type = "Unknown"

            # Convert packet data to hexadecimal format
            hex_data = ' '.join(['{:02X}'.format(byte) for byte in bytes(packet)])
            hex_numbers = hex_data.split()
            rows_of_16 = [hex_numbers[i:i + 16] for i in range(0, len(hex_numbers), 16)]

            #hexa_frame_str = '| \n' + '\n'.join([' '.join(line) for line in rows_of_16])

            # Create a dictionary for the packet data
            packet_data = {
                "frame_number": packet_count + 1,
                "len_frame_pcap": len(packet),
                "len_frame_medium": len(packet) + eth_length,
                "frame_type": packet_type,
                "src_mac": src,
                "dst_mac": dest,
                "hexa_frame": LiteralScalarString('\n'.join([' '.join(row) for row in rows_of_16])),
            }

            if sap_name:
                packet_data["sap"] = sap_name

            if ethertype_name:
                packet_data["pid"] = ethertype_name

            packets_data.append(packet_data)

            packet_count += 1

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
    with open("output.yaml", "w") as yaml_file:
        yaml = YAML()
        yaml.indent(offset=2)
        yaml.dump(yaml_data, yaml_file)


def get_sap_name(sap):
    sap_mappings = {
        0x00: "Null SAP",
        0x02: "LLC Sublayer Management / Individual",
        0x03: "LLC Sublayer Management / Group",
        0x06: "IP (DoD Internet Protocol)",
        0x0E: "PROWAY (IEC 955) Network Management, Maintenance and Installation",
        0x42: "BPDU (Bridge PDU / 802.1 Spanning Tree)",
        0x4E: "MMS (Manufacturing Message Service) EIA-RS 511",
        0x5E: "ISI IP",
        0x7E: "X.25 PLP (ISO 8208)",
        0x8E: "PROWAY (IEC 955) Active Station List Maintenance",
        0xAA: "SNAP (Sub-Network Access Protocol / non-IEEE SAPs)",
        0xE0: "IPX (Novell NetWare)",
        0xF4: "LAN Management",
        0xFE: "ISO Network Layer Protocols",
        0xFF: "Global DSAP"
    }
    return sap_mappings.get(sap)


def get_ethertype_name(ethertype):
    ethertype_mappings = {
        0x200: "XEROX PUP",
        0x2004: "DTP",
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
    return ethertype_mappings.get(ethertype)


if __name__ == "__main__":
    main()
