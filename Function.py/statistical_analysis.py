import pyshark
import os
    
def statistical_analysis(pcap_file, analyzed_data):
    """
    Perform a comprehensive statistical analysis of the PCAP file and analyzed data.

    Parameters:
        pcap_file (str): Path to the PCAP file.
        analyzed_data (pd.DataFrame): DataFrame containing analyzed packet data.

    Returns:
        dict: A dictionary containing the analysis results.
    """
    try:
        # Calculate the size of the PCAP file
        file_size_bytes = os.path.getsize(pcap_file)
        file_size_mb = file_size_bytes / (1024 * 1024)

        # Open the PCAP file and count total packets
        cap = pyshark.FileCapture(pcap_file)
        total_packets = sum(1 for _ in cap)
        cap.close()

        # Count protocol distribution and TLS 1.3 packets
        protocol_counts = {"FTP": 0, "DNS": 0, "HTTP": 0, "HTTPS": 0, "TLS": 0, "IPv4": 0, "IPv6": 0, "QUIC": 0, "ARP": 0}
        tls_version_count = {"TLS 1.3": 0}
        sni_tls_1_3_count = 0

        cap = pyshark.FileCapture(pcap_file)
        for packet in cap:
            try:
                if hasattr(packet, 'ftp'):
                    protocol_counts['FTP'] += 1
                if hasattr(packet, 'dns'):
                    protocol_counts['DNS'] += 1
                if hasattr(packet, 'http'):
                    protocol_counts['HTTP'] += 1
                if hasattr(packet, 'https'):
                    protocol_counts['HTTPS'] += 1
                if hasattr(packet, 'tls'):
                    protocol_counts['TLS'] += 1
                    if hasattr(packet.tls, 'record_version') and packet.tls.record_version == '0x0303':  # TLS 1.3
                        tls_version_count['TLS 1.3'] += 1
                        if hasattr(packet.tls, 'handshake_extensions_server_name'):  # SNI exists
                            sni_tls_1_3_count += 1
                if hasattr(packet, 'ipv4'):
                    protocol_counts['IPv4'] += 1
                if hasattr(packet, 'ipv6'):
                    protocol_counts['IPv6'] += 1
                if hasattr(packet, 'quic'):
                    protocol_counts['QUIC'] += 1
                if hasattr(packet, 'arp'):
                    protocol_counts['ARP'] += 1
            except Exception:
                continue
        cap.close()

        # Calculate protocol distribution percentages
        protocol_distribution = {
            protocol: (count / total_packets) * 100 if total_packets > 0 else 0
            for protocol, count in protocol_counts.items()
        }

        # Calculate percentage of TLS traffic
        tls_packets = protocol_counts['TLS']
        tls_percentage = (tls_packets / total_packets) * 100 if total_packets > 0 else 0

        # Calculate percentage of TLS 1.3 traffic
        tls_1_3_packets = tls_version_count['TLS 1.3']
        tls_1_3_percentage_total = (tls_1_3_packets / total_packets) * 100 if total_packets > 0 else 0
        tls_1_3_percentage_tls = (tls_1_3_packets / tls_packets) * 100 if tls_packets > 0 else 0

        # Calculate SNI percentage in TLS 1.3
        sni_tls_1_3_percentage = (sni_tls_1_3_count / tls_1_3_packets) * 100 if tls_1_3_packets > 0 else 0

        # Analyze the CSV data
        total_fetched_packets = len(analyzed_data)
        discovered_services = analyzed_data['Predicted Service'].notna().sum()

        # Predicted Services Distribution
        service_counts = analyzed_data['Predicted Service'].value_counts()
        service_distribution = {
            service: (count / discovered_services) * 100 if discovered_services > 0 else 0
            for service, count in service_counts.items()
        }

        # Calculate Discovered Services Percentage
        discovered_services_percentage = (discovered_services / total_fetched_packets) * 100 if total_fetched_packets > 0 else 0

        # Compile analysis results
        analysis_results = {
            "Total PCAP File Size (MB)": file_size_mb,
            "Total Packets in PCAP": total_packets,
            "Protocol Distribution (%)": protocol_distribution,
            "TLS Traffic Percentage (%)": tls_percentage,
            "Total TLS Packets": tls_packets,
            "TLS 1.3 Packets in PCAP": tls_1_3_packets,
            "TLS 1.3 Percentage in Total Packets (%)": tls_1_3_percentage_total,
            "TLS 1.3 Percentage in TLS Packets (%)": tls_1_3_percentage_tls,
            "Predicted Services Distribution (%)": service_distribution,
            "SNI Percentage in TLS 1.3 (%)": sni_tls_1_3_percentage,
            "Discovered Services Percentage (%)": discovered_services_percentage
        }

        return analysis_results

    except Exception as e:
        print(f"An error occurred during statistical analysis: {e}")
        return {}
