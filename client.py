import socket
from datetime import datetime
from scapy.all import rdpcap, DNS, DNSQR, raw

# --- Configuration ---
PCAP_FILE = '5.pcap'
SERVER_IP = '127.0.0.1'
SERVER_PORT = 9999
REPORT_FILE = 'report.txt'

def process_dns_queries():
    """
    Reads a pcap file, filters DNS queries, sends them to the custom server,
    receives the resolved IP, and generates a final report.
    """
    print(f"[*] Reading packets from '{PCAP_FILE}'...")
    try:
        packets = rdpcap(PCAP_FILE)
    except FileNotFoundError:
        print(f"[ERROR] The file '{PCAP_FILE}' was not found. Please place it in the same directory.")
        return

    # Filter for packets that are standard DNS queries (qr=0 means query)
    dns_queries = [pkt for pkt in packets if pkt.haslayer(DNS) and pkt[DNS].qr == 0]

    if not dns_queries:
        print("[*] No DNS queries found in the pcap file.")
        return

    print(f"[*] Found {len(dns_queries)} DNS queries. Processing...")

    report_data = []
    query_id_counter = 0

    for query_packet in dns_queries:
        try:
            # 1. Create the custom 8-byte header (HHMMSSID).
            now = datetime.now()
            hhmmss = now.strftime("%H%M%S")
            # Format ID with a leading zero if it's a single digit (e.g., 00, 01, ..., 09, 10)
            query_id_str = f"{query_id_counter:02d}"
            custom_header = f"{hhmmss}{query_id_str}"

            # 2. Construct the payload: custom header + original DNS packet bytes.
            header_bytes = custom_header.encode('utf-8')
            packet_bytes = raw(query_packet)
            payload = header_bytes + packet_bytes
            
            # 3. Connect to the server and send the payload.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((SERVER_IP, SERVER_PORT))
                s.sendall(payload)
                
                # 4. Receive the server's response (the assigned IP address).
                response = s.recv(1024).decode('utf-8')
                assigned_ip = response

            # 5. Log data for the report.
            queried_domain = query_packet[DNSQR].qname.decode('utf-8').rstrip('.')
            report_data.append((custom_header, queried_domain, assigned_ip))
            print(f"  - Sent Query for '{queried_domain}' with Header '{custom_header}' -> Got IP: {assigned_ip}")
            
            query_id_counter += 1

        except Exception as e:
            print(f"[ERROR] Failed to process a query: {e}")

    # 6. Generate the final report file.
    generate_report(report_data)

def generate_report(data):
    """Writes the final report to a text file and prints it."""
    header = f"{'Custom Header (HHMMSSID)':<30} | {'Domain Name':<40} | {'Assigned IP Address'}\n"
    separator = "-" * 100 + "\n"
    
    report_content = header + separator

    for entry in data:
        report_content += f"{entry[0]:<30} | {entry[1]:<40} | {entry[2]}\n"
    
    try:
        with open(REPORT_FILE, 'w') as f:
            f.write(report_content)
        print(f"\n[*] Report successfully generated: '{REPORT_FILE}'")
    except IOError as e:
        print(f"\n[ERROR] Could not write report to file: {e}")

    print("\n--- Final Report ---")
    print(report_content)


if __name__ == "__main__":
    process_dns_queries()
