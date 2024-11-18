import pyshark
import pandas as pd
def extract_client_packets(pcap_file_path):
    """
    Extracts client handshake details from a PCAP file.
    Returns the extracted client packet data with duplicates removed.
    """
    client_data = []

    # Extracting Client Hello packets
    capture_client = pyshark.FileCapture(pcap_file_path,
     display_filter='tls.handshake.type == 1 && tcp && tls.handshake.extensions.supported_version == 0x0304')
    for packet in capture_client:
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
        ja3 = getattr(tls_layer, 'handshake_ja3', 'N/A')
        ja4 = getattr(tls_layer, 'handshake_ja4', 'N/A')
        sni = getattr(tls_layer, 'handshake_extensions_server_name', 'N/A')

        # Append the extracted client details to the client_data list
        client_data.append([no, time, src, dst, length, "Client Hello", cipher_suite, random, session_id, ja3, ja4, sni])

    capture_client.close()

    # Convert to DataFrame to handle duplicates
    client_df = pd.DataFrame(client_data, columns=['No', 'Timestamp', 'Source IP', 'Destination IP', 'Length', 'Info',
                                                  'Cipher Suite', 'Random', 'Session ID', 'JA3', 'JA4', 'SNI'])

    # Drop duplicates based on 'Destination IP' (keeping the first occurrence)
    client_df = client_df.drop_duplicates(subset='Destination IP', keep='first')

    # Return the de-duplicated data as a list
    return client_df.values.tolist()
