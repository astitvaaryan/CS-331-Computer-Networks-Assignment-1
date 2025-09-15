import socket
import threading

# Define the static IP pool as specified in the rules document.
IP_POOL = [
    "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
    "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10",
    "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

def handle_client(conn, addr):
    """
    Handles an individual client connection, applies the DNS resolution rules,
    and sends back the assigned IP address.
    """
    print(f"[NEW CONNECTION] {addr} connected.")
    try:
        # Receive the payload from the client
        data = conn.recv(2048)
        if not data:
            return

        # 1. Extract the 8-byte custom header from the payload.
        custom_header = data[:8].decode('utf-8')
        
        # 2. Parse the header to get the hour (HH) and ID.
        hour = int(custom_header[0:2])
        query_id = int(custom_header[6:8])

        # 3. Apply the time-based routing rules to find the starting index.
        ip_pool_start = 0
        if 4 <= hour <= 11:  # Morning: 04:00-11:59
            ip_pool_start = 0
            time_of_day = "Morning"
        elif 12 <= hour <= 19: # Afternoon: 12:00-19:59
            ip_pool_start = 5
            time_of_day = "Afternoon"
        else: # Night: 20:00-03:59
            ip_pool_start = 10
            time_of_day = "Night"
            
        # 4. Calculate the offset using the ID modulo 5.
        offset = query_id % 5

        # 5. Calculate the final index and select the IP address.
        final_index = ip_pool_start + offset
        assigned_ip = IP_POOL[final_index]
        
        print(f"  [PROCESSING] Header: {custom_header} | Hour: {hour} ({time_of_day}) | ID: {query_id}")
        print(f"  [LOGIC] Pool Start: {ip_pool_start} | Offset (ID % 5): {offset} | Final Index: {final_index}")
        print(f"  [RESULT] Assigned IP: {assigned_ip}")

        # 6. Send the assigned IP back to the client.
        conn.sendall(assigned_ip.encode('utf-8'))

    except (ValueError, IndexError) as e:
        print(f"[ERROR] Invalid data received from {addr}: {e}")
        error_message = "Error: Invalid header or data format"
        conn.sendall(error_message.encode('utf-8'))
    finally:
        conn.close()
        print(f"[CONNECTION CLOSED] {addr}")

def start_server(host='127.0.0.1', port=9999):
    """
    Starts the DNS resolver server, listening for incoming connections.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()
    print(f"[LISTENING] Server is listening on {host}:{port}")

    while True:
        conn, addr = server_socket.accept()
        # Create a new thread to handle each client connection so the server can
        # handle multiple requests concurrently without blocking.
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_server()
