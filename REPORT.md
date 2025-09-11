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

The delay mathing the configured 1s delay.



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
