from scapy.all import rdpcap


def print_pcap_hex(filename):
    try:
        # Read the pcap file using rdpcap
        packets = rdpcap(filename)
        packet_count = 0

        for packet in packets:
            # Convert packet data to hexadecimal format
            hex_data = ' '.join(['{:02X}'.format(byte) for byte in bytes(packet)])

            # Print the hexadecimal data to the console
            print(f"Packet {packet_count + 1} (Length: {len(packet)} bytes):\n{hex_data}\n")
            packet_count += 1

    except FileNotFoundError:
        print(f"File not found: {filename}")
    except Exception as e:
        print(f"Error reading the pcap file: {e}")


if __name__ == "__main__":
    pcap_filename = "eth-1.pcap"
    print_pcap_hex(pcap_filename)
