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
