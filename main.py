import dpkt

def print_pcap_hex(filename):
    try:
        # Open the pcap file for reading
        with open(filename, 'rb') as pcap_file:
            pcap = dpkt.pcap.Reader(pcap_file)
            packet_count = 0

            for ts, buf in pcap:
                # Convert packet data to hexadecimal format
                hex_data = ' '.join(['{:02X}'.format(byte) for byte in buf])

                # Print the hexadecimal data to the console
                print(f"Packet {packet_count + 1} (Length: {len(buf)} bytes):\n{hex_data}\n")
                packet_count += 1

    except FileNotFoundError:
        print(f"File not found: {filename}")
    except Exception as e:
        print(f"Error reading the pcap file: {e}")

if __name__ == "__main__":
    pcap_filename = "eth-2.pcap"
    print_pcap_hex(pcap_filename)
