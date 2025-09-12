import socket, random, time
import threading

def randomFault(data, protocol):
    # r = random.random()
    r = 0.5
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
