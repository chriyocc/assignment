# 1.0 Introduction

# 2.0 Implementation

# 3.0 Results

## 3.1 Packet Inspection & Security

### 3.1.1 Setup Web Server

First, I implemented a simple web server on localhost:8080 using Python. This server will waits for a client connection, receives data and prints it.

```python
import socket

while True:
  s = socket.socket()

  hostname = "localhost"
  port = 8080

  try: 
    s.bind((hostname, port))

    s.listen()

    conn, addr = s.accept()
    print(f"Got connection from {addr}")

    while True:
      try:
        data = conn.recv(1024)
        print(data.decode())

        if not data:  # Handle connection closed
          print("Client disconnected")
          break

      except:
        break

  except KeyboardInterrupt:
      print("\nDisconnected")
      break

  finally:
      conn.close()
```

### 3.1.2 Send Data from Client to Server

Next, I connected to the server using Netcat and sent the string "Hello from Client":

```cmd
yoyojun@yoyojuns-MacBook-Air ~ % nc localhost 8080
Hello from Client
```

On the server side, it successfully received the data and prints it out:

```cmd
Got connection from ('127.0.0.1', 53370)
Hello from Client
```

### 3.1.3 Identify the Frames and Packets

Using WireShark, I captured the packets exchange between server and client.

| No.  | Time     | Source    | Destination | Protocol | Length | Info                                                         |
| ---- | -------- | --------- | ----------- | -------- | ------ | ------------------------------------------------------------ |
| 1    | 0.000000 | 127.0.0.1 | 127.0.0.1   | TCP      | 75     | 54830 → 8080 [PSH, ACK] Seq=1 Ack=1 Win=6380 Len=19 TSval=1617315918 TSecr=3123084692 |
| 2    | 0.000098 | 127.0.0.1 | 127.0.0.1   | TCP      | 56     | 8080 → 54830 [ACK] Seq=1 Ack=20 Win=6380 Len=0 TSval=3123626038 TSecr=1617315918 |

**Frame 1**, the client sends the text ("Hello from Client") to the server in plain text (hex + ASCII view):

```
0000   02 00 00 00 45 00 00 47 00 00 40 00 40 06 00 00   ....E..G..@.@...
0010   7f 00 00 01 7f 00 00 01 d6 2e 1f 90 73 14 80 7a   ............s..z
0020   26 99 f4 b8 80 18 18 ec fe 3b 00 00 01 01 08 0a   &........;......
0030   60 66 48 4e ba 26 7d 94 48 65 6c 6c 6f 20 66 72   `fHN.&}.Hello fr
0040   6f 6d 20 43 6c 69 65 6e 74 2e 0a                  om Client..
```

**Frame 2,** the server replied with an ACK, confirming it successfully received the data:

```
0000   02 00 00 00 45 00 00 34 00 00 40 00 40 06 00 00   ....E..4..@.@...
0010   7f 00 00 01 7f 00 00 01 1f 90 d6 2e 26 99 f4 b8   ............&...
0020   73 14 80 8d 80 10 18 ec fe 28 00 00 01 01 08 0a   s........(......
0030   ba 2e c0 36 60 66 48 4e                           ...6`fHN
```

### 3.1.4 Analysis

From 3.1.2, 

- The message is fully visible in plain text.
- The data is not encrypted, meaning any sensitive data like usernames and passwords could be easily sniffed by attackers.

This demonsrates a fundamental security weakness of raw TCP sockets.

### 3.1.5 Improvements

To enhance security while data transmission, use encrypted socket like SSL/TLS are recommend instead of raw TCP. With SSL/TLS, the message gets encrypted and would appear unreadable ciphertext, preventing attackers from seeing sensitive data.



------



## 3.2 Client-Server Communication with Fault Tolerance



### 3.2.1 Setup Echo Server

Using the same code in section 3.1, with the addition of `conn.send(data)` to return received messages to the client:

```python
import socket, random, time

while True:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # allows immediate port reuse
    hostname = "localhost"
    port = 8080

    try:
        s.bind((hostname, port))
        s.listen()
        conn, addr = s.accept()
        print(f"Got connection from {addr}")
        while True:
            try:
                data = conn.recv(1024)
                print(data.decode())

                if not data:  # Handle connection closed
                    print("Client disconnected")
                    break
								
                # Fault injection (3.2.2) goes here
                
            except:
                break

            conn.send(data)

    except KeyboardInterrupt:
        print("\nDisconnected")
        break

    finally:
        s.close()
```



### 3.2.2 Simulate Network Faults

To demonstrate fault tolerance, I artificially introduce delay, packet loss, and corruption before returning data to the client.

**A. Network Delay: **

A fixed delay was inserted before sending the response:

```python
# Fault injection (Line:23)
delay = 1.0
time.sleep(delay)
```



In Wireshark, the message took `~1.0066` seconds longer to appear:

| No.  | Time     | Source    | Destination | Protocol | Length | Info                                                         |
| ---- | -------- | --------- | ----------- | -------- | ------ | ------------------------------------------------------------ |
| 7    | 8.665673 | 127.0.0.1 | 127.0.0.1   | TCP      | 62     | 57593  >  8080 [PSH, ACK] Seq=1 Ack=1 Win=408320 Len=6 TSval=3949452411 TSecr=1283379236 |
| 8    | 8.665769 | 127.0.0.1 | 127.0.0.1   | TCP      | 56     | 8080  >  57593 [ACK] Seq=1 Ack=7 Win=408320 Len=0 TSval=1283387902 TSecr=3949452411 |
| 9    | 9.672276 | 127.0.0.1 | 127.0.0.1   | TCP      | 62     | 8080  >  57593 [PSH, ACK] Seq=1 Ack=7 Win=408320 Len=6 TSval=1283388909 TSecr=3949452411 |
| 10   | 9.672375 | 127.0.0.1 | 127.0.0.1   | TCP      | 56     | 57593  >  8080 [ACK] Seq=7 Ack=7 Win=408320 Len=0 TSval=3949453418 TSecr=1283388909 |

The delay matching the configured 1s delay.



**B. Packet Loss**

Instead of echoing back the original data, the server discards it and returns an fake error message:

```python
#Will simulate Network Fault(3.2.1) here: (Line:23)
msg = "Packet Loss"
print(f"Simulating {msg}")
data = msg.encode() #.send() required bytes-like object
```

| No.  | Time      | Source    | Destination | Protocol | Length | Info                                                         |
| ---- | --------- | --------- | ----------- | -------- | ------ | ------------------------------------------------------------ |
| 7    | 14.355958 | 127.0.0.1 | 127.0.0.1   | TCP      | 62     | 57917  >  8080 [PSH, ACK] Seq=1 Ack=1 Win=408320 Len=6 TSval=526340350 TSecr=392279892 |
| 8    | 14.356057 | 127.0.0.1 | 127.0.0.1   | TCP      | 56     | 8080  >  57917 [ACK] Seq=1 Ack=7 Win=408320 Len=0 TSval=392294249 TSecr=526340350 |
| 9    | 14.356311 | 127.0.0.1 | 127.0.0.1   | TCP      | 67     | 8080  >  57917 [PSH, ACK] Seq=1 Ack=7 Win=408320 Len=11 TSval=392294249 TSecr=526340350 [TCP segment of a reassembled PDU] |
| 10   | 14.356350 | 127.0.0.1 | 127.0.0.1   | TCP      | 56     | 57917  >  8080 [ACK] Seq=7 Ack=12 Win=408320 Len=0 TSval=526340350 TSecr=392294249 |

**Frame 7**, client side sent `Test1` to server: 

```
0030   1f 5f 50 fe 17 61 b7 54 54 65 73 74 31 0a         ._P..a.TTest1.
```

**Frame 9,** server sent back an error `Packet Loss`: 

```
0030   17 61 ef 69 1f 5f 50 fe 50 61 63 6b 65 74 20 4c   .a.i._P.Packet L
0040   6f 73 73                                          oss
```

This simulates how the application layer can signal lost data.



**C. Packet Corruption**

```python
msg = "Corruption"
print(f"Simulating {msg}")
corrupted = bytearray(data)
#Flips 1 to 0 & 0 to 1
corrupted[random.randint(0, len(corrupted) - 2)] ^= 0xFF #avoid trailing "\n"
data = bytes(corrupted)
```

| No.  | Time     | Source    | Destination | Protocol | Length | Info                                                         |
| ---- | -------- | --------- | ----------- | -------- | ------ | ------------------------------------------------------------ |
| 7    | 4.289459 | 127.0.0.1 | 127.0.0.1   | TCP      | 62     | 58384  >  8080 [PSH, ACK] Seq=1 Ack=1 Win=408320 Len=6 TSval=1910981597 TSecr=3075230498 |
| 8    | 4.289566 | 127.0.0.1 | 127.0.0.1   | TCP      | 56     | 8080  >  58384 [ACK] Seq=1 Ack=7 Win=408320 Len=0 TSval=3075234788 TSecr=1910981597 |
| 9    | 4.289834 | 127.0.0.1 | 127.0.0.1   | TCP      | 62     | 8080  >  58384 [PSH, ACK] Seq=1 Ack=7 Win=408320 Len=6 TSval=3075234788 TSecr=1910981597 |
| 10   | 4.289867 | 127.0.0.1 | 127.0.0.1   | TCP      | 56     | 58384  >  8080 [ACK] Seq=7 Ack=7 Win=408320 Len=0 TSval=1910981597 TSecr=3075234788 |

**Frame 7**, client side sent `Test1` to server: 

```
0030   71 e7 43 dd b7 4c 4b 22 54 65 73 74 31 0a         q.C..LK"Test1.
```

**Frame 9**, one letter of the text is corrupted and result in `Te?t1`: 

```
0030   b7 4c 5b e4 71 e7 43 dd 54 65 8c 74 31 0a         .L[.q.C.Te.t1.
```



### 3.2.3 Analysis

- **Delay:** messages arrive late
- **Packet Loss: ** response is replaced or missing
- **Corruption:** response is altered

In these cases, the communication is unreliable without additional protection.



### 3.2.4 Improvements

To make the system reliable:

- **Retransmission:** client will resends if no valid reply within a timeout
- **Error Detection:** add checksums or hashes to detect errors
- **Acknowledgments:** server confirms message receipt with sequence numbers.



------



## 3.3 Developing a Resilient Client Program



### 3.3.1 Overview

This program implements a fault-tolerant multi-client–server system over both TCP and UDP protocols. It simulates real-world issues such as packet loss, delay, and data corruption.

This system consist of two main modules:

- `server.py` → Provides a resilient server that handles both TCP and UDP connections and simulates various network faults for testing
- `client.py` → Implements a client capable of sending validated messages with checksums, handling retransmissions and error detection.

#### `server.py`

```python
import socket, random, time
import threading

def randomFault(data, protocol):
    r = random.random()
    if r < 0.2:
        print(f"[{protocol} SERVER] Simulating packet loss\n")
        return 'error_code'.encode()

    if r < 0.4:
        delay = random.random() * 10
        print(f"[{protocol} SERVER] Simulating delay(s): {delay}\n")
        time.sleep(delay)
        return None

    if r < 0.6:
        data = data.decode()
        print(f"[{protocol} SERVER] Simulating corruption")
        body, recv_checksum = data.split("|")
        corrupted = bytearray(body.encode())
        # Flips 1 to 0 & 0 to 1
        corrupted[random.randint(0, len(corrupted) - 2)] ^= 0xFF
        data = bytes(corrupted) + b"|" + recv_checksum.encode()
        print(f"[{protocol} SERVER] Corrupted data: {data}\n")
        return data

    else:
        print("[SERVER] No fault.")

class ResilientTCPServer(threading.Thread):
    def __init__(self, hostname="localhost", port=8080):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((hostname, port))
        self.sock.listen()
        print(f"[TCP SERVER] Listening on {hostname}:{port}")

    def run(self):
        try:
            while True:
                conn, addr = self.sock.accept()
                print(f"[TCP SERVER] Connection from {addr}\n")
                threading.Thread(target=self.handle_client, args=(conn,), daemon=True).start()
        except KeyboardInterrupt:
            print("\n[TCP SERVER] Disconnected")
        finally:
            self.sock.close()

    def handle_client(self, conn):

        with conn:
            while True:
                try:
                    
                    data = conn.recv(1024)
                    if not data:
                        print("[TCP SERVER] Client disconnected")
                        print("[MAIN] Waiting...")
                        break

                    decoded_data = data.decode()
                    print(f"[TCP SERVER] Message Received: {decoded_data}")

                    fault = randomFault(data, "TCP")
                    if fault is not None:
                        data = fault

                    try:
                        conn.sendall(data)  # echo back
                        print("[TCP SERVER] Sent response.\n")
                        data = conn.recv(1024)

                    except socket.error as e:
                        print(f"[TCP SERVER] Failed to send response: {e}")
                        break
            
                except Exception as e:
                    print(f"[TCP SERVER] Error: {e}")
                    break

class ResilientUDPServer(threading.Thread):
    def __init__(self, hostname="localhost", port=8080):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((hostname, port))
        print(f"[UDP SERVER] Listening on {hostname}:{port}")

    def run(self):
        try:
            while True:
                data, addr = self.sock.recvfrom(1024)
                print(f"[UDP SERVER] Received from {addr}: {data.decode()}")

        except KeyboardInterrupt:
            print("\n[UDP SERVER] Disconnected")
        finally:
            self.sock.close()

if __name__ == "__main__":
    tcp_server = ResilientTCPServer()
    udp_server = ResilientUDPServer()

    tcp_server.start()
    udp_server.start()

    print("[MAIN] TCP and UDP servers are running...\n")

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[MAIN] Shutting down servers...")
```



#### `client.py`

```python
import socket
import sys
import hashlib
import time

class ResilientClient:
    def __init__(self, host="localhost", port=8080, protocol="TCP"):
        self.host = host
        self.port = port
        self.protocol = protocol.upper()
        self.sock = None

    def checksum(self, msg: str) -> str:
        """Simple SHA1-based checksum for message integrity."""
        return hashlib.sha1(msg.encode()).hexdigest()[:8]
    
    def checkmsg(self, msg: str):
        if not msg.strip():
            return False
        
        if any(x in msg.lower() for x in ["drop table", "shutdown", "malware"]):
            print("[CLIENT] Invalid or unsafe message")
            return False
        
        return True

    def connect(self):
        """Establish connection depending on protocol."""
        try:
            if self.protocol == "TCP":
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((self.host, self.port))
                print(f"[CLIENT] Connected to {self.host}:{self.port} via TCP")
            elif self.protocol == "UDP":
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                print(f"[CLIENT] Ready to send to {self.host}:{self.port} via UDP")
            else:
                raise ValueError("Unsupported protocol. Use TCP or UDP.")
        except Exception as e:
            print(f"[CLIENT] Connection error: {e}")
            sys.exit(1)

    def send_message(self, msg: str, retries=3, timeout=3):
        """Send a message with basic fault tolerance."""
        payload = f"{msg}|{self.checksum(msg)}"
        attempts = 0
        print(f"[CLIENT] Message is ready to send: ({payload})")

        while attempts < retries:
            try:
                if self.protocol == "TCP":
                    self.sock.send(payload.encode())
                    self.sock.settimeout(timeout)
                    reply = self.sock.recv(1024).decode(errors="replace") 
                else:  # UDP
                    self.sock.sendto(payload.encode(), (self.host, self.port))
                    break

                print(f"[CLIENT] Message received: {reply}")

                # Validate reply
                if "|" in reply:
                    body, recv_checksum = reply.split("|", 1)
                    curr_checksum = self.checksum(body)
                    print(f"[CLIENT] Current: {curr_checksum} & Original: {recv_checksum}")

                    if curr_checksum == recv_checksum:
                        print(f"[CLIENT] Received valid reply: {body}")
                        return
                    else:
                        print("[CLIENT] Checksum mismatch (possible corruption)")
                        return
                else:
                    print("[CLIENT] Invalid format (possible attack)")

            except socket.timeout:
                print("[CLIENT] Timeout, retrying...")
            except ConnectionResetError:
                print("[CLIENT] Connection reset by server, retrying...")
                self.connect()  # attempt reconnection
            except Exception as e:
                print(f"[CLIENT] Unexpected error: {e}")

            attempts += 1


    def close(self):
        if self.sock:
            self.sock.close()
            time.sleep(1)
            if self.protocol == "TCP":
                print("[CLIENT] Connection closed")


if __name__ == "__main__":
    # Example usage:
    protocol_input = input("[CLIENT] Choose UDP/TCP: ")
    client = ResilientClient(host="localhost", port=8080, protocol=protocol_input)
    client.connect()
    msg_input = input("[CLIENT] Enter something: ")
    if client.checkmsg(msg_input) :
        client.send_message(msg_input)
    client.close()
```



### 3.3.2 Features

#### Client-side

- Support for both TCP and UDP protocols
- Message integrity verification using SHA1 checksums
- Automatic retry mechanism with configurable attempts
- Connection timeout handling
- Automatic reconnection on connection reset
- Input validation and security checks malicious content

#### Server-side

- Support for both TCP and UDP protocols

- Fault simulation for testing resilience:

  - Packet loss simulation (20% probability)

  - Network delay simulation (20% probability, up to 10 seconds)

  - Data corruption simulation (20% probability)
  - No fault (40% probability)

- Echo functionality for message verification



### 3.3.3 Error Simulation

This server includes built-in random fault simulation to test client resilience:

1. **Packet Loss Testing** 

   Server randomly drops a packetsClient automatic retry 3 attempts.
   The client automatically retries up to three times when it detects an invalid or missing response.

   **Example output:**

   `server.py`

   ```cmd
   [TCP SERVER] Message Received: Hey|e4599fa9
   [TCP SERVER] Simulating packet loss
   
   [TCP SERVER] Sent response.
   
   [TCP SERVER] Message Received: Hey|e4599fa9
   [TCP SERVER] Simulating packet loss
   
   [TCP SERVER] Sent response.
   
   [TCP SERVER] Message Received: Hey|e4599fa9
   [TCP SERVER] Simulating packet loss
   
   [TCP SERVER] Sent response.
   ```

   `client.py`

   ```cmd
   [CLIENT] Enter something: Hey
   [CLIENT] Message is ready to send: (Hey|e4599fa9)
   [CLIENT] Attempts: 1
   [CLIENT] Message received: error_code
   [CLIENT] Invalid format (possible attack)
   [CLIENT] Attempts: 2
   [CLIENT] Message received: error_code
   [CLIENT] Invalid format (possible attack)
   [CLIENT] Attempts: 3
   [CLIENT] Message received: error_code
   [CLIENT] Invalid format (possible attack)
   [CLIENT] Connection closed
   ```

   

2. **Delay Testing**

   Random delays up to 10 seconds to simulate network latency.

   If a response does not arrive within the client’s timeout, the client retries the transmission, 3 attempts in total.

   **Example output:**

   `server.py`

   ```cmd
   [TCP SERVER] Message Received: Hey|e4599fa9
   [TCP SERVER] Simulating delay(s): 5.747517592904991
   
   [TCP SERVER] Sent response.
   ```

   `client.py`

   ```cmd
   [CLIENT] Enter something: Hey
   [CLIENT] Message is ready to send: (Hey|e4599fa9)
   [CLIENT] Attempts: 1
   [CLIENT] Timeout, retrying...
   [CLIENT] Attempts: 2
   [CLIENT] Message received: Hey|e4599fa9
   [CLIENT] Current: e4599fa9 & Original: e4599fa9
   [CLIENT] Received valid reply: Hey
   ```

3. **Corruption Testing**

   Randomly flip a bit of client message.

   The client validates the checksum in the reply and rejects messages with mismatched checksums.

   **Example output:**

   `server.py`

   ```cmd
   [TCP SERVER] Message Received: Test3|5e595222
   [TCP SERVER] Simulating corruption
   [TCP SERVER] Corrupted data: b'\xabest3|5e595222'
   
   [TCP SERVER] Sent response.
   ```

   `client.py`

   ```
   [CLIENT] Enter something: Test3
   [CLIENT] Message is ready to send: (Test3|5e595222)
   [CLIENT] Attempts: 1
   [CLIENT] Message received: �est3|5e595222
   [CLIENT] Current: 86e1ea1e & Original: 5e595222
   [CLIENT] Checksum mismatch (possible corruption)
   ```



### 3.3.4 Usage Example 

#### Start server.

```cmd
python server.py
```



#### Start client.

```
python client.py
```



#### Example Terminal session:

`server.py`

```cmd
[TCP SERVER] Listening on localhost:8080
[UDP SERVER] Listening on localhost:8080
[MAIN] TCP and UDP servers are running...

[TCP SERVER] Connection from ('127.0.0.1', 59523)

[TCP SERVER] Message Received: Test3|5e595222
[TCP SERVER] Simulating corruption
[TCP SERVER] Corrupted data: b'\xabest3|5e595222'

[TCP SERVER] Sent response.

[TCP SERVER] Client disconnected
[MAIN] Waiting...

[UDP SERVER] Received from ('127.0.0.1', 54625): Test4|1c77599f
```

`client.py`

```cmd
#TCP
[CLIENT] Choose UDP/TCP: TCP
[CLIENT] Connected to localhost:8080 via TCP
[CLIENT] Enter something: Test3
[CLIENT] Message is ready to send: (Test3|5e595222)
[CLIENT] Attempts: 1
[CLIENT] Message received: �est3|5e595222
[CLIENT] Current: 86e1ea1e & Original: 5e595222
[CLIENT] Checksum mismatch (possible corruption)
[CLIENT] Connection closed

#UDP
[CLIENT] Choose UDP/TCP: UDP
[CLIENT] Ready to send to localhost:8080 via UDP
[CLIENT] Enter something: Test4
[CLIENT] Message is ready to send: (Test4|1c77599f)
[CLIENT] Attempts: 1
```



#### Explanation

1. The server starts and listens on port 8080 for both TCP and UDP connections.
2. The client connects via TCP and sends `Packet1` with its checksum.
3. The server, using its fault-injection module, randomly flips a bit in the message and send back to client.
4. The client verifies the checksum, detects a mismatch, and warns: **(possible corruption)**.
5. Connection closes.
6. Client sends a message (`Test4|1c77599f`) to the UDP server (same port as TCP, localhost:8080).
7. The server receives the message without requiring a persistent connection.
8. Connection closes.



### 3.3.5 Analysis

This resilient client-server system well demonstrates how network faults impact messages delivery and how fault tolerant mechanisms can solve these issues.

(Explain SHA1)



### 3.3.6 Improvements

- Implement SSL/TLS encryption support
- Authentication mechanisms
- Supports multiple clients simultaneously
- Logging framework integration
