import binascii

from scapy.all import rdpcap


def extract_ethertype(raw_packet):
    if len(raw_packet) >= 14:
        ether_type_bytes = raw_packet[12:14]
        return int.from_bytes(ether_type_bytes, byteorder='big')
    else:
        return None


def extract_8023_type(raw_packet):
    # 3 bytes in header - Dest MAC, Src MAC, Control
    if len(raw_packet) >= 3:
        control = int.from_bytes(raw_packet[2:3], byteorder='big')

        if control == 0xaaaa03:
            return "IEEE 802.3 LLC and SNAP"
        elif control == 0xaaaa:
            return "IEEE 802.3 LLC"
        else:
            return "IEEE 802.3 RAW"
    else:
        return None


def print_pcap_hex(filename):
    try:
        # Read the pcap file using rdpcap
        packets = rdpcap(filename)
        packet_count = 0

        for packet in packets:
            eth_length = 0

            # Extract the EtherType field
            eth_type = extract_ethertype(bytes(packet))

            if eth_type is not None:
                if eth_type <= 1500:
                    eth_length = 2
                    packet_type = extract_8023_type(bytes(packet))
                else:
                    eth_length = 14
                    packet_type = "Ethernet II"
            else:
                # If there is no EtherType, label it as "Unknown"
                packet_type = "Unknown"

            # Convert packet data to hexadecimal format
            hex_data = ' '.join(['{:02X}'.format(byte) for byte in bytes(packet)])

            # Print the packet information
            print(f"Packet {packet_count + 1}")
            print(f"Packet type: {packet_type}")
            print(f"API Length: {len(packet)} bytes")
            print(f"Over medium Length: {len(packet) + eth_length} bytes")
            print(f"Packet:\n{hex_data}\n")
            packet_count += 1

    except FileNotFoundError:
        print(f"File not found: {filename}")
    except Exception as e:
        print(f"Error reading the pcap file: {e}")


if __name__ == "__main__":
    pcap_filename = "trace-2.pcap"
    print_pcap_hex(pcap_filename)
