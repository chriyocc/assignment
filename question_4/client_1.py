import socket
import sys
import hashlib
import time
import base64
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key, ParameterFormat
from cryptography.hazmat.primitives.serialization import load_der_parameters, load_der_private_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import json
import getpass

class EncryptionManager:
    """Handle message encryption and decryption with support for Diffie-Hellman key exchange"""
    
    def __init__(self):
        self.fernet = None
        self.enabled = False
        self.dh_private_key = None
        self.dh_parameters = None
        self.shared_key = None
        self.protocol_version = "V2"  # Default to modern protocol
        
    
    def setup_encryption(self, password):
        """Set up encryption using password-based key derivation (legacy mode)"""
        try:
            # Generate a random salt for this session
            self.salt = secrets.token_bytes(16)
            
            # Derive key from password using PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Create Fernet cipher
            self.fernet = Fernet(key)
            self.enabled = True
            print("[ENCRYPTION] Legacy encryption enabled")
            return True
        except Exception as e:
            print(f"[ENCRYPTION] Failed to setup encryption: {e}")
            return False
    
    def setup_dh_encryption(self, dh_params_bytes):
        """Set up encryption using Diffie-Hellman key exchange"""
        try:
            # Load DH parameters
            self.dh_parameters = load_der_parameters(dh_params_bytes)
            
            # Generate private key
            self.dh_private_key = self.dh_parameters.generate_private_key()
            print("[ENCRYPTION] DH key pair generated")
            return True
        except Exception as e:
            print(f"[ENCRYPTION] Failed to setup DH encryption: {e}")
            return False
    
    def get_public_key_bytes(self):
        """Get client's public key as bytes"""
        if not self.dh_private_key:
            print("[ENCRYPTION] No DH private key available")
            return None
            
        try:
            public_key = self.dh_private_key.public_key()
            return public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        except Exception as e:
            print(f"[ENCRYPTION] Failed to get public key bytes: {e}")
            return None
    
    def compute_shared_key(self, server_public_key_bytes):
        """Compute shared key using server's public key"""
        try:
            if not self.dh_private_key:
                print("[ENCRYPTION] No DH private key available")
                return False
                
            # Load server's public key
            server_public_key = load_der_public_key(server_public_key_bytes)
            
            # Compute shared key
            shared_key = self.dh_private_key.exchange(server_public_key)
            
            # Derive encryption key using HKDF
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(shared_key)
            
            # Create Fernet cipher with derived key
            self.fernet = Fernet(base64.urlsafe_b64encode(derived_key))
            self.enabled = True
            print("[ENCRYPTION] Secure DH encryption enabled")
            return True
        except Exception as e:
            print(f"[ENCRYPTION] Failed to compute shared key: {e}")
            return False
    
    def encrypt_message(self, message):
        """Encrypt a message"""
        if not self.enabled:
            return message
        
        try:
            encrypted = self.fernet.encrypt(message.encode())
            # Include salt with encrypted message for decryption
            # For DH mode, we don't need salt as the key is derived from the shared secret
            if hasattr(self, 'salt'):
                salt_b64 = base64.urlsafe_b64encode(self.salt).decode()
            else:
                # For DH mode, use a dummy salt as it's not actually used for decryption
                salt_b64 = base64.urlsafe_b64encode(b'dh_mode_no_salt').decode()
                
            payload = {
                'encrypted': base64.urlsafe_b64encode(encrypted).decode(),
                'salt': salt_b64,
                'encrypted_flag': True
            }
            return json.dumps(payload)
        except Exception as e:
            print(f"[ENCRYPTION] Encryption failed: {e}")
            return message
    
    def decrypt_message(self, encrypted_data):
        """Decrypt a message"""
        if not self.enabled:
            return encrypted_data
        
        try:
            # Try to parse as JSON (encrypted format)
            try:
                payload = json.loads(encrypted_data)
                if not payload.get('encrypted_flag', False):
                    return encrypted_data  # Not encrypted
            except (json.JSONDecodeError, KeyError):
                return encrypted_data  # Not encrypted format
            # Decrypt the message
            encrypted_bytes = base64.urlsafe_b64decode(payload['encrypted'].encode())
            decrypted = self.fernet.decrypt(encrypted_bytes)
            
            return decrypted.decode()
        except Exception as e:
            print(f"[ENCRYPTION] Decryption failed: {e}")
            return encrypted_data

class ResilientClient:
    def __init__(self, host="localhost", port=8080, protocol="TCP"):
        self.host = host
        self.port = port
        self.protocol = protocol.upper()
        self.sock = None
        self.handshake_completed = False
        
        # Initialize encryption manager
        # For V2 protocol (DH), password is not needed for encryption
        self.encryption = EncryptionManager()
        
        # Statistics
        self.stats = {
            'messages_sent': 0,
            'messages_received': 0,
            'timeouts': 0,
            'checksum_mismatches': 0,
            'connection_resets': 0
        }

    def checksum(self, msg: str) -> str:
        """Enhanced SHA256-based checksum for better security."""
        return hashlib.sha256(msg.encode()).hexdigest()[:16]
    
    def checkmsg(self, msg: str):
        """Enhanced message validation"""
        if not msg.strip():
            print("[CLIENT] Empty message not allowed")
            return False
        
        if len(msg) > 1000:
            print("[CLIENT] Message too long (max 1000 characters)")
            return False
        
        suspicious_patterns = [
            "drop table", "delete from", "insert into", "update set",
            "shutdown", "malware", "<script>", "javascript:", 
            "exec(", "eval(", "system(", "__import__"
        ]
        
        if any(pattern in msg.lower() for pattern in suspicious_patterns):
            print("[CLIENT] Message contains potentially unsafe content")
            return False
        
        return True

    def connect(self):
        """Establish connection and perform handshake."""
        try:
            if self.protocol == "TCP":
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(15)
                self.sock.connect((self.host, self.port))
                print(f"[CLIENT] Connected to {self.host}:{self.port} via TCP")
                
                # Perform handshake for TCP connections
                if not self.perform_handshake():
                    print("[CLIENT] Handshake failed")
                    self.close()
                    return False
                    
            elif self.protocol == "UDP":
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.sock.settimeout(10)
                print(f"[CLIENT] Ready to send to {self.host}:{self.port} via UDP")
                
                # Enable encryption for UDP if required
                if not self.encryption.enabled:
                    print("[CLIENT] Encryption is not enabled for UDP")
                self.handshake_completed = True  # UDP doesn't need handshake
            else:
                raise ValueError("Unsupported protocol. Use TCP or UDP.")
            
            return True
            
        except Exception as e:
            print(f"[CLIENT] Connection failed: {e}")
            return False
    
    def perform_handshake(self):
        """Perform handshake with server to establish encryption parameters"""
        try:
            print("[CLIENT] Waiting for handshake request...")
            
            # Wait for server handshake request
            self.sock.settimeout(15.0)
            handshake_request = self.sock.recv(1024).decode()
            
            if not handshake_request.startswith("HANDSHAKE_REQUEST|"):
                print(f"[CLIENT] Unexpected handshake: {handshake_request}")
                return False
            
            # Check protocol version from server
            handshake_parts = handshake_request.split("|")
            server_protocol = handshake_parts[2]
            
            print(f"[CLIENT] Received handshake request from server (protocol: {server_protocol})")
            
            return self.perform_dh_handshake()
            
        except Exception as e:
            print(f"[CLIENT] Handshake failed: {e}")
            return False
    
    def perform_dh_handshake(self):
        """Perform Diffie-Hellman key exchange handshake"""
        try:
            # Send handshake response with V2 protocol
            response = "HANDSHAKE_RESPONSE|ENCRYPTED|V2|"
            print("[CLIENT] Requesting secure DH encrypted communication")
            self.sock.sendall(response.encode())
            
            # Wait for DH parameters from server
            dh_params_response = self.sock.recv(4096).decode()  # Larger buffer for key data
            
            if not dh_params_response.startswith("DH_PARAMS|"):
                print(f"[CLIENT] Unexpected DH response: {dh_params_response}")
                return False
            
            # Extract DH parameters
            dh_params_b64 = dh_params_response.split("|")[1]
            dh_params_bytes = base64.b64decode(dh_params_b64)
            
            # Setup DH encryption
            if not self.encryption.setup_dh_encryption(dh_params_bytes):
                print("[CLIENT] Failed to setup DH encryption")
                return False
            
            # Get client's public key
            client_pubkey = self.encryption.get_public_key_bytes()
            if not client_pubkey:
                print("[CLIENT] Failed to get client public key")
                return False
            
            # Send client's public key to server
            client_pubkey_b64 = base64.b64encode(client_pubkey).decode()
            self.sock.sendall(f"DH_PUBKEY|{client_pubkey_b64}".encode())
            
            # Wait for server's public key
            server_pubkey_response = self.sock.recv(4096).decode()
            
            if not server_pubkey_response.startswith("DH_SERVER_PUBKEY|"):
                print(f"[CLIENT] Unexpected server pubkey response: {server_pubkey_response}")
                return False
            
            # Extract server's public key
            server_pubkey_b64 = server_pubkey_response.split("|")[1]
            server_pubkey = base64.b64decode(server_pubkey_b64)
            
            # Compute shared key
            if not self.encryption.compute_shared_key(server_pubkey):
                print("[CLIENT] Failed to compute shared key")
                self.sock.sendall("DH_ACK|FAILED".encode())
                return False
            
            # Send acknowledgment
            self.sock.sendall("DH_ACK|SUCCESS".encode())
            
            # Wait for final server acknowledgment
            final_ack = self.sock.recv(1024).decode()
            
            if final_ack == "HANDSHAKE_ACK|ENCRYPTION_ENABLED":
                print("[CLIENT] ✓ Server confirmed secure DH encryption enabled")
                self.handshake_completed = True
                return True
            else:
                print(f"[CLIENT] Unexpected final ack: {final_ack}")
                return False
            
        except Exception as e:
            print(f"[CLIENT] DH handshake failed: {e}")
            return False

    def prepare_message(self, msg: str):
        """Prepare message with optional encryption and checksum"""
        # Encrypt if enabled
        if self.encryption.enabled:
            print("[CLIENT] Encrypting message...")
            encrypted_msg = self.encryption.encrypt_message(msg)
            payload = f"{encrypted_msg}|{self.checksum(encrypted_msg)}|ENCRYPTED"
        else:
            payload = f"{msg}|{self.checksum(msg)}|PLAIN"
        
        return payload

    def parse_response(self, response):
        """Parse and validate server response"""
        try:
            parts = response.split("|")
            if len(parts) < 2:
                print("[CLIENT] Invalid response format")
                return None, False
            
            # Handle different message formats
            if len(parts) >= 3 and parts[2] == "ENCRYPTED":
                body, recv_checksum = parts[0], parts[1]
                is_encrypted = True
            else:
                body, recv_checksum = parts[0], parts[1]
                is_encrypted = len(parts) >= 3 and parts[2] == "ENCRYPTED"
            
            # Verify checksum
            curr_checksum = self.checksum(body)
            print(f"[CLIENT] Checksum - Current: {curr_checksum[:8]}..., Received: {recv_checksum[:8]}...")
            
            if curr_checksum != recv_checksum:
                print("[CLIENT] Checksum mismatch (possible corruption)")
                self.stats['checksum_mismatches'] += 1
                return None, False
            
            # Decrypt if necessary
            if is_encrypted and self.encryption.enabled:
                print("[CLIENT] Decrypting response...")
                decrypted_body = self.encryption.decrypt_message(body)
                return decrypted_body, True
            
            return body, True
            
        except Exception as e:
            print(f"[CLIENT] Error parsing response: {e}")
            return None, False

    def send_message(self, msg: str, retries=3, timeout=10):
        """Send a message with enhanced fault tolerance."""
        if not self.checkmsg(msg):
            return False
        
        # Ensure handshake is completed for TCP
        if self.protocol == "TCP" and not self.handshake_completed:
            print("[CLIENT] Handshake not completed, cannot send message")
            return False
        
        payload = self.prepare_message(msg)
        attempts = 0
        
        print(f"[CLIENT] Prepared payload (length: {len(payload)} chars)")

        while attempts < retries:
            attempts += 1
            print(f"[CLIENT] Attempt {attempts}/{retries}")
            
            try:
                # Send message
                if self.protocol == "TCP":
                    self.sock.send(payload.encode())
                    self.sock.settimeout(timeout)
                    reply = self.sock.recv(4096).decode(errors="replace")
                else:  # UDP
                    self.sock.sendto(payload.encode(), (self.host, self.port))
                    print("[CLIENT] UDP message sent. No response expected.")
                    self.stats['messages_sent'] += 1
                    return True  # Exit after sending for UDP

                if not reply:
                    print("[CLIENT] Empty response received")
                    continue

                self.stats['messages_sent'] += 1
                print(f"[CLIENT] Raw response received (length: {len(reply)} chars)")

                # Check for handshake requests (shouldn't happen after initial handshake)
                if reply.startswith("HANDSHAKE_REQUEST"):
                    print("[CLIENT] Unexpected handshake request - connection may have been reset")
                    self.handshake_completed = False
                    if not self.perform_handshake():
                        print("[CLIENT] Re-handshake failed")
                        return False
                    continue

                # Parse and validate response
                parsed_body, is_valid = self.parse_response(reply)
                
                if is_valid and parsed_body is not None:
                    print(f"[CLIENT] ✓ Successfully received: {parsed_body}")
                    self.stats['messages_received'] += 1
                    return True
                else:
                    print("[CLIENT] Invalid response received")
                    continue

            except socket.timeout:
                print(f"[CLIENT] Timeout on attempt {attempts}")
                self.stats['timeouts'] += 1
                if attempts < retries:
                    print(f"[CLIENT] Retrying in 2 seconds...")
                    time.sleep(2)
                    
            except ConnectionResetError:
                print("[CLIENT] Connection reset by server")
                self.stats['connection_resets'] += 1
                if attempts < retries:
                    print("[CLIENT] Attempting to reconnect...")
                    self.close()
                    if not self.connect():
                        break
                        
            except Exception as e:
                print(f"[CLIENT] Unexpected error: {e}")
                if attempts < retries:
                    time.sleep(1)


        print(f"[CLIENT] ✗ Failed to send message after {retries} attempts")
        return False

    def print_stats(self):
        """Print client statistics"""
        print("\n=== CLIENT STATISTICS ===")
        for key, value in self.stats.items():
            print(f"{key.replace('_', ' ').title()}: {value}")
        print("========================")

    def close(self):
        """Close connection and cleanup"""
        if self.sock:
            try:
                if self.protocol == "TCP":
                    self.sock.shutdown(socket.SHUT_RDWR)
            except:
                pass
            
            self.sock.close()
            self.sock = None
            self.handshake_completed = False
            print("[CLIENT] Connection closed")

def get_user_input():
    """Get user configuration"""
    print("\n=== SIMPLE CLIENT CONFIGURATION ===")
    
    # Protocol selection
    while True:
        protocol = input("Choose protocol (TCP/UDP) [TCP]: ").strip().upper()
        if not protocol:
            protocol = "TCP"
        if protocol in ["TCP", "UDP"]:
            break
        print("Please enter TCP or UDP")
    
    # Server details
    host = input("Server host [localhost]: ").strip() or "localhost"
    
    while True:
        try:
            port_input = input("Server port [8080]: ").strip()
            port = int(port_input) if port_input else 8080
            if 1 <= port <= 65535:
                break
            print("Port must be between 1 and 65535")
        except ValueError:
            print("Please enter a valid port number")
    
    
    return protocol, host, port

def main():
    """Simple main function"""
    try:
        # Get configuration
        protocol, host, port= get_user_input()
        
        # Create and connect client
        client = ResilientClient(host, port, protocol)
        
        if not client.connect():
            print("[CLIENT] Failed to connect to server")
            return
        
        print(f"\n=== CONNECTED TO {host}:{port} VIA {protocol} ===")
        if client.encryption.enabled:
            print("🔒 Encryption: ENABLED")
        else:
            print("🔓 Encryption: DISABLED")
        
        # Get message to sedn
        message = input("\n[CLIENT] Enter message: ")
        if message.strip():
            success = client.send_message(message)
            if success:
                print("[CLIENT] ✓ Message sent successfully!")
            else:
                print("[CLIENT] ✗ Failed to send message")
        
        client.print_stats()
    
    except KeyboardInterrupt:
        print("\n[CLIENT] Interrupted by user")
    except Exception as e:
        print(f"[CLIENT] Unexpected error: {e}")
    finally:
        if 'client' in locals():
            client.close()
        print("[CLIENT] Goodbye!")

if __name__ == "__main__":
    main()