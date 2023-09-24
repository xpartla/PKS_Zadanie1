import binascii

from scapy.all import rdpcap


def print_pcap_hex(filename):
    try:
        # Read the pcap file using rdpcap
        packets = rdpcap(filename)
        packet_count = 0

        for packet in packets:
            eth_length = 0

            if len(packet) < 60:
                eth_length = 4
            # Ethernet II
            else:
                decimal_num = int(str(binascii.hexlify(packet[12:14]))[2: -1], 16)
            if decimal_num > 1500:
                packet_type = "Ethernet II"
                eth_length = 14

            else:
                # Novell 802.3 RAW -> +3 (Control field)
                if str(binascii.hexlify(packet[14:16]))[2: -1] == "ffff":
                    packet_type = "Novell 802.3 RAW"
                    eth_length = 17

                #IEEE 802.3 LLC + SNAP
                elif str(binascii.hexlify(packet[14:15]))[2: -1] == "aa":
                    packet_type = "IEEE 802.3 SNAP"
                    eth_length = 22

                # IEEE 802.3 LLC
                else:
                    decimal_num = int(str(binascii.hexlify(packet[14:15]))[2: -1], 16)
                    packet_type = "IEEE 802.3 LLC"
                    eth_length = 18

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
