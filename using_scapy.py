from scapy.all import rdpcap


def print_pcap_hex(filename):
    try:
        # Read the pcap file using rdpcap
        packets = rdpcap(filename)
        packet_count = 0

        for packet in packets:
            # Convert packet data to hexadecimal format
            hex_data = ' '.join(['{:02X}'.format(byte) for byte in bytes(packet)])

            #Determine packet type
            packet_type = None
            if packet.haslayer("Dot3"):
                packet_type = packet["Dot3"].len
            elif packet.haslayer("SNAP"):
                packet_type = len(packet["SNAP"])

            # Ethernet header Length
            eth_length = 14

            if packet_type == 0x0000:
                #Novell 802.3 RAW -> +3 (Control field)
                eth_length = 17
            elif packet_type == 0x800:
                #IEEE 802.3 LLC / IEEE 802.3 LLC + SNAP
                eth_length = 22 if packet.haslayer("SNAP") else 18

            # Print the hexadecimal data to the console
            print(f"Packet {packet_count + 1} \n(API Length: {len(packet)} bytes)\n(Over medium Length: {len(packet) + eth_length} bytes) \nPacket:\n{hex_data}\n")
            packet_count += 1

    except FileNotFoundError:
        print(f"File not found: {filename}")
    except Exception as e:
        print(f"Error reading the pcap file: {e}")


if __name__ == "__main__":
    pcap_filename = "trace-2.pcap"
    print_pcap_hex(pcap_filename)
