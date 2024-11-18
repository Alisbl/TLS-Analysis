import pyshark
def extract_server_packets(pcap_file_path):
    """
    Extracts server handshake details from a PCAP file.
    Returns the extracted server packet data and the set of destination IPs.
    """
    server_data = []
    destination_ips_from_server = set()  # Set to store destination IPs from Server Hello

    # Extracting Server Hello packets
    capture_server = pyshark.FileCapture(pcap_file_path,
                                         display_filter='tls.handshake.type == 2 && tls.handshake.extensions.supported_version == 0x0304')
    for packet in capture_server:
        if 'tls' not in packet:
            continue

        no = packet.number
        time = packet.sniff_time.timestamp()
        src = getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A'
        dst = getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A'
        length = getattr(packet, 'length', 'N/A')
        tls_layer = packet.tls

        random = getattr(tls_layer, 'handshake_random', 'N/A')
        session_id = getattr(tls_layer, 'handshake_session_id', 'N/A')
        cipher_suite_hex = getattr(tls_layer, 'handshake_ciphersuite', 'N/A')
        cipher_suite = f'TLS Cipher Suite {cipher_suite_hex}' if cipher_suite_hex != 'N/A' else 'N/A'
        ja3s = getattr(tls_layer, 'handshake_ja3s', 'N/A')

        # Add the destination IP of the Server Hello to the set
        destination_ips_from_server.add(src)

        # Append the extracted server details to the server_data list
        server_data.append([no, time, src, dst, length, "Server Hello", cipher_suite, random, session_id, ja3s])

    capture_server.close()

    return server_data, destination_ips_from_server
