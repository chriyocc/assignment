import socket, sys

s = socket.socket()
hostname = "localhost"
port = 8080

try:
    s.connect((hostname, port))
    print("Connected to echo server. Type messages or [Ctrl+C] to quit:")
    
    while True:
        msg = input("You: ")  
        if not msg:  # Handle empty input
            continue
            
        s.send((msg).encode())
        reply = s.recv(1024)
        
        if not reply:  # Handle connection closed
            print("Connection closed by server")
            break
            
        print("Echo:", reply.decode().strip())  # strip() removes the newline
        
except KeyboardInterrupt:
    print("\nDisconnected")
except Exception as e:
    print(f"Error: {e}")
finally:
    s.close()