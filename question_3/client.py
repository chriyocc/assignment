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
                    reply = self.sock.recv(1024).decode()
                else:  # UDP
                    self.sock.sendto(payload.encode(), (self.host, self.port))
                    self.sock.settimeout(timeout)
                    reply, _ = self.sock.recvfrom(1024)
                    reply = reply.decode()

                # Validate reply
                if "|" in reply:
                    body, recv_checksum = reply.split("|")
                    if self.checksum(body) == recv_checksum:
                        print(f"[CLIENT] Received valid reply: {body}")
                        return
                    else:
                        print("[CLIENT] Checksum mismatch (possible corruption)")
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

        print("[CLIENT] Failed to get valid reply after retries")

    def close(self):
        if self.sock:
            self.sock.close()
            time.sleep(1)
            print("[CLIENT] Connection closed")


if __name__ == "__main__":
    # Example usage:
    client = ResilientClient(host="localhost", port=8080, protocol="TCP")
    client.connect()
    print("[CLIENT] Enter something: ")
    msg_input = input("[CLIENT] ")
    client.send_message(msg_input)
    client.close()

    # print("\nSwitching to UDP...\n")

    # client = ResilientClient(host="localhost", port=8080, protocol="UDP")
    # client.connect()
    # client.send_message("UDP test message")
    # client.close()
