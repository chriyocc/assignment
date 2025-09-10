import socket, random, time

def randomFault(data):
    r = random.random()
    # r = 0.1
    if r < 0.2:
        print(f"[SERVER] Simulating packet loss\n")
        return 'error_code'.encode()

    if r < 0.4:
        delay = random.random()*10
        print(f"[SERVER]Simulating delay(s): {delay}\n")
        time.sleep(delay)
        return None

    if r < 0.6:
        print(f"[SERVER] Simulating corruption\n")
        corrupted = bytearray(data)
        #Flips 1 to 0 & 0 to 1
        corrupted[random.randint(0, len(corrupted) - 2)] ^= 0xFF #avoid trailing "\n"
        return bytes(corrupted)
        
    else:
        print("[SERVER] No fault.\n")


class ResilientServer:
    def __init__(self, hostname="localhost", port=8080):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # allows immediate port reuse
        self.sock.bind((hostname, port))
        self.sock.listen()
        print(f"[SERVER] Server listening on {hostname}:{port}")

    def run(self):
        try:
            while True:
                conn, addr = self.sock.accept()
                print(f"[SERVER] Got connection from {addr}\n")
                while True:
                    try:
                        data = conn.recv(1024)
                        decoded_data = data.decode()

                        if decoded_data != '':
                            print(f"[SERVER] Message Received: {decoded_data}")
                            

                        if not data:  # Handle connection closed
                            print("[SERVER] Client Disconnected")
                            print("[SERVER] Waiting...\n")
                            break

                        fault = randomFault(data)
                        if fault != None:
                            data = fault
                            
                        
                    except:
                        break

                    conn.send(data) # echo back
        
        except KeyboardInterrupt:
            print("\n[SERVER] Disconnected")

        finally:
            self.sock.close()

if __name__ == "__main__":
    server = ResilientServer()
    server.run()

        