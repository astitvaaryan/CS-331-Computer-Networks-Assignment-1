
# CS-331: Custom DNS Resolver

This project implements a custom DNS resolution system as part of the CS-331 Computer Networks course. It consists of a Python client and server that communicate to resolve DNS queries from a PCAP file based on a set of time-based rules.

---

## Prerequisites

Before you begin, ensure you have the following installed:

* **Python 3**: The scripts are written in Python 3.
* **Scapy**: A powerful Python library for packet manipulation.

You can install Scapy using `pip`:
```bash
pip install scapy
````

-----

## File Structure

Ensure your project directory is set up as follows for the scripts to run correctly:

```
.
├── 5.pcap
├── client.py
└── server.py
```

The `5.pcap` file must be in the same directory as the Python scripts.

-----

## How to Run

You will need to use two separate terminal windows. The **server must be started first** so it is ready to accept connections from the client.

### Step 1: Start the Server

1.  Open your first terminal window.
2.  Navigate to the project directory.
3.  Run the `server.py` script:
    ```bash
    python server.py
    ```
4.  The server will display the following message, indicating it is ready. Leave this terminal window running.
    ```
    [LISTENING] Server is listening on 127.0.0.1:9999
    ```

### Step 2: Run the Client

1.  Open a **new**, second terminal window.
2.  Navigate to the same project directory.
3.  Run the `client.py` script:
    ```bash
    python client.py
    ```

-----

## Expected Output

### Server Terminal

You will see connection logs for each DNS query, showing the processing logic and the IP address it assigned.

```
[NEW CONNECTION] ('127.0.0.1', ...) connected.
  [PROCESSING] Header: 02110100 | Hour: 2 (Night) | ID: 0
  [LOGIC] Pool Start: 10 | Offset (ID % 5): 0 | Final Index: 10
  [RESULT] Assigned IP: 192.168.1.11
[CONNECTION CLOSED] ('127.0.0.1', ...)
```

### Client Terminal

The client will print the status of each query and, upon completion, display a formatted report. It will also save this report to a file named `report.txt`.

```
[*] Reading packets from '5.pcap'...
[*] Found 23 DNS queries. Processing...
  - Sent Query for 'apple.com' with Header '02110100' -> Got IP: 192.168.1.11
  - Sent Query for '_apple-mobdev._tcp.local' with Header '02110101' -> Got IP: 192.168.1.12
  ...

[*] Report successfully generated: 'report.txt'

--- Final Report ---
Custom Header (HHMMSSID)   | Domain Name                    | Assigned IP Address
--------------------------------------------------------------------------------
02110100                       | apple.com                      | 192.168.1.11
...
```

```eof
```
