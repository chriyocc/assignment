import socket
import random
import time
import threading
import logging
from datetime import datetime
import json
import os
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key, ParameterFormat
from cryptography.hazmat.primitives.serialization import load_der_parameters, load_der_private_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import getpass

class EncryptionManager:
    """Server-side encryption manager to handle encrypted client messages"""
    
    def __init__(self):
        self.encryption_keys = {}  # Store multiple encryption keys by client ID
        self.dh_parameters = None  # DH parameters for key exchange
        self.private_keys = {}     # Store server's private keys for each client
        self.shared_keys = {}      # Store derived shared keys
        self.logger = logging.getLogger('EncryptionManager')
        self.initialize_dh_parameters()
    
    def initialize_dh_parameters(self):
        """Initialize Diffie-Hellman parameters"""
        try:
            # Generate parameters with 2048-bit key size (can be increased for more security)
            self.dh_parameters = dh.generate_parameters(generator=2, key_size=2048)
            self.logger.info("DH parameters initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize DH parameters: {e}")
    
    def get_dh_parameters_bytes(self):
        """Get DH parameters as bytes for sending to client"""
        if not self.dh_parameters:
            return None
        return self.dh_parameters.parameter_bytes(Encoding.DER, ParameterFormat.PKCS3)
    
    def generate_dh_private_key(self, client_id):
        """Generate server's private key for a specific client"""
        try:
            if not self.dh_parameters:
                self.logger.error("DH parameters not initialized")
                return None
                
            private_key = self.dh_parameters.generate_private_key()
            self.private_keys[client_id] = private_key
            return private_key
        except Exception as e:
            self.logger.error(f"Failed to generate private key: {e}")
            return None
    
    def get_public_key_bytes(self, client_id):
        """Get server's public key as bytes for a specific client"""
        if client_id not in self.private_keys:
            if not self.generate_dh_private_key(client_id):
                return None
                
        public_key = self.private_keys[client_id].public_key()
        return public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    
    def compute_shared_key(self, client_id, client_public_key_bytes):
        """Compute shared key using client's public key"""
        try:
            if client_id not in self.private_keys:
                self.logger.error(f"No private key for client {client_id}")
                return False
                
            # Load client's public key
            client_public_key = load_der_public_key(client_public_key_bytes)
            
            # Compute shared key
            shared_key = self.private_keys[client_id].exchange(client_public_key)
            
            # Derive encryption key using HKDF
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(shared_key)
            
            # Store the derived key
            self.encryption_keys[client_id] = base64.urlsafe_b64encode(derived_key)
            self.logger.info(f"Shared key computed for client {client_id}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to compute shared key for {client_id}: {e}")
            return False
    
    def add_client_key(self, client_id, key):
        """Add encryption key for a specific client (legacy method)"""
        try:
            self.encryption_keys[client_id] = key
            self.logger.info(f"Encryption key registered for client {client_id}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to register encryption key for {client_id}: {e}")
            return False
    
    def create_fernet_from_password_and_salt(self, password, salt):
        """Create Fernet cipher from password and salt"""
        try:
            # Check if password is already a base64 encoded key (from DH exchange)
            if isinstance(password, bytes):
                # Already a derived key, just use it
                return Fernet(password)
                
            # Legacy mode - derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            return Fernet(key)
        except Exception as e:
            self.logger.error(f"Failed to create Fernet cipher: {e}")
            return None
    
    def decrypt_message(self, encrypted_data, client_id):
        """Decrypt a message using the client's key"""
        try:
            # Parse the encrypted payload
            payload = json.loads(encrypted_data)
            
            if not payload.get('encrypted_flag', False):
                return encrypted_data  # Not encrypted
            
            # Get client's password or DH-derived key (in production, this would be more secure)
            password = self.encryption_keys.get(client_id)
            if not password:
                self.logger.warning(f"No encryption key found for client {client_id}")
                return "[DECRYPTION_ERROR: No key available]"
            
            # Extract salt and encrypted data
            salt = base64.urlsafe_b64decode(payload['salt'].encode())
            encrypted_bytes = base64.urlsafe_b64decode(payload['encrypted'].encode())
            
            # Check if this is a DH-derived key (already in bytes format)
            if isinstance(password, bytes):
                # DH mode - use the key directly
                fernet = Fernet(password)
            else:
                # Legacy mode - derive key from password and salt
                fernet = self.create_fernet_from_password_and_salt(password, salt)
                
            if not fernet:
                return "[DECRYPTION_ERROR: Failed to create cipher]"
            
            decrypted = fernet.decrypt(encrypted_bytes)
            decrypted_text = decrypted.decode()
            
            self.logger.debug(f"Successfully decrypted message for client {client_id}")
            return decrypted_text
            
        except json.JSONDecodeError:
            # Not a JSON encrypted message, return as-is
            return encrypted_data
        except Exception as e:
            self.logger.error(f"Decryption failed for client {client_id}: {e}")
            return f"[DECRYPTION_ERROR: {str(e)}]"
    
    def encrypt_message(self, message, client_id):
        """Encrypt a message for sending back to client"""
        try:
            password = self.encryption_keys.get(client_id)
            if not password:
                return message  # No encryption key, send plain
            
            # Generate new salt for response
            salt = os.urandom(16)
            
            # Create cipher and encrypt
            fernet = self.create_fernet_from_password_and_salt(password, salt)
            if not fernet:
                return message
            
            encrypted = fernet.encrypt(message.encode())
            
            # Create payload
            payload = {
                'encrypted': base64.urlsafe_b64encode(encrypted).decode(),
                'salt': base64.urlsafe_b64encode(salt).decode(),
                'encrypted_flag': True
            }
            
            return json.dumps(payload)
            
        except Exception as e:
            self.logger.error(f"Encryption failed for client {client_id}: {e}")
            return message

class MessageProcessor:
    """Process and analyze decrypted messages"""
    
    def __init__(self):
        self.logger = logging.getLogger('MessageProcessor')
        self.message_stats = {
            'total_messages': 0,
            'encrypted_messages': 0,
            'plain_messages': 0,
            'decryption_errors': 0
        }
    
    def checksum(self, msg: str) -> str:
        """Calculate SHA256 checksum"""
        return hashlib.sha256(msg.encode()).hexdigest()[:16]
    
    def parse_message(self, data, client_id, encryption_manager):
        """Parse incoming message and handle encryption"""
        try:
            decoded_data = data.decode('utf-8', errors='ignore')
            
            # Parse message format: message|checksum|TYPE
            parts = decoded_data.split("|")
            if len(parts) < 2:
                return None, "Invalid message format", False
            
            message_body = parts[0]
            received_checksum = parts[1]
            message_type = parts[2] if len(parts) >= 3 else "PLAIN"
            
            self.message_stats['total_messages'] += 1
            
            # Handle encrypted messages
            if message_type == "ENCRYPTED":
                self.logger.info(f"Received encrypted message from client {client_id}")
                self.message_stats['encrypted_messages'] += 1
                
                # Decrypt the message
                decrypted_message = encryption_manager.decrypt_message(message_body, client_id)
                
                if decrypted_message.startswith("[DECRYPTION_ERROR"):
                    self.message_stats['decryption_errors'] += 1
                    self.logger.error(f"Decryption failed for client {client_id}")
                    return None, decrypted_message, True
                
                # Verify checksum on encrypted data (before decryption)
                calculated_checksum = self.checksum(message_body)
                
                self.logger.info(f"Decrypted message from {client_id}: {decrypted_message[:50]}...")
                return decrypted_message, message_type, True
                
            else:
                # Plain text message
                self.message_stats['plain_messages'] += 1
                
                # Verify checksum
                calculated_checksum = self.checksum(message_body)
                if calculated_checksum != received_checksum:
                    self.logger.warning(f"Checksum mismatch for client {client_id}")
                    return None, "Checksum verification failed", False
                
                self.logger.info(f"Received plain message from {client_id}: {message_body[:50]}...")
                return message_body, message_type, False
                
        except Exception as e:
            self.logger.error(f"Error parsing message from {client_id}: {e}")
            return None, f"Parse error: {str(e)}", False
    
    def create_response(self, original_message, message_type, is_encrypted, client_id, encryption_manager):
        """Create appropriate response message"""
        try:
            # For demo purposes, echo back with a prefix
            response_message = f"ECHO: {original_message}"
            
            if is_encrypted:
                # Encrypt the response
                encrypted_response = encryption_manager.encrypt_message(response_message, client_id)
                checksum = self.checksum(encrypted_response)
                return f"{encrypted_response}|{checksum}|ENCRYPTED"
            else:
                # Plain response
                checksum = self.checksum(response_message)
                return f"{response_message}|{checksum}|PLAIN"
                
        except Exception as e:
            self.logger.error(f"Error creating response for {client_id}: {e}")
            error_msg = "Server error processing message"
            checksum = self.checksum(error_msg)
            return f"{error_msg}|{checksum}|PLAIN"

# Configure logging (same as before)
def setup_logging():
    """Set up comprehensive logging configuration"""
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )
    
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    
    file_handler = logging.FileHandler(
        f'logs/server_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

class ClientManager:
    """Enhanced client manager with encryption support"""
    
    def __init__(self, encryption_manager):
        self.tcp_clients = {}
        self.udp_clients = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger('ClientManager')
        self.encryption_manager = encryption_manager
    
    def add_tcp_client(self, client_id, conn, addr, encryption_password=None):
        """Add a new TCP client with optional encryption"""
        with self.lock:
            self.tcp_clients[client_id] = {
                'connection': conn,
                'address': addr,
                'connected_at': datetime.now(),
                'messages_sent': 0,
                'messages_received': 0,
                'bytes_sent': 0,
                'bytes_received': 0,
                'encrypted': False  # Will be updated during handshake process
            }
            
    
    def remove_tcp_client(self, client_id):
        """Remove a TCP client and cleanup encryption keys"""
        with self.lock:
            if client_id in self.tcp_clients:
                client_info = self.tcp_clients[client_id]
                duration = datetime.now() - client_info['connected_at']
                encryption_status = "encrypted" if client_info['encrypted'] else "plain"
                self.logger.info(f"TCP client {client_id} ({encryption_status}) disconnected. "
                               f"Duration: {duration}")
                del self.tcp_clients[client_id]
                
                # Remove encryption key
                if client_id in self.encryption_manager.encryption_keys:
                    del self.encryption_manager.encryption_keys[client_id]
    
    def update_tcp_stats(self, client_id, sent=0, received=0, bytes_sent=0, bytes_received=0):
        """Update client statistics"""
        with self.lock:
            if client_id in self.tcp_clients:
                client = self.tcp_clients[client_id]
                client['messages_sent'] += sent
                client['messages_received'] += received
                client['bytes_sent'] += bytes_sent
                client['bytes_received'] += bytes_received

def randomFault(data, protocol, client_id=None):
    """Enhanced fault simulator that preserves message structure"""
    logger = logging.getLogger('FaultSimulator')
    r = random.random()  # Use real randomization
    # r = 0.5
    
    client_info = f" for client {client_id}" if client_id else ""
    
    if r < 0.2:  # Reduced fault probability for better testing
        logger.warning(f"[{protocol}] Simulating packet loss{client_info}")
        return 'error_code'.encode()

    if r < 0.4:
        delay = random.random() * 3  # Reduced delay
        logger.warning(f"[{protocol}] Simulating delay: {delay:.2f}s{client_info}")
        time.sleep(delay)
        return None

    if r < 0.6:
        logger.warning(f"[{protocol}] Simulating data corruption{client_info}")
        
        # Be careful with corruption to maintain some message structure
        corrupted = bytearray(data)
        if len(corrupted) > 10:  # Only corrupt if message is long enough
            # Corrupt a byte that's not likely to be a delimiter
            pos = random.randint(5, len(corrupted) - 5)
            corrupted[pos] ^= 0x01  # Flip just one bit
        
        return bytes(corrupted)

    return None

class EnhancedTCPServer(threading.Thread):
    def __init__(self, hostname="localhost", port=8080, client_manager=None, message_processor=None, server_password=None):
        super().__init__(daemon=True, name="TCPServer")
        self.hostname = hostname
        self.port = port
        self.client_manager = client_manager
        self.message_processor = message_processor
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = False
        self.client_counter = 0
        self.logger = logging.getLogger('TCPServer')
        self.server_password = server_password

    def start_server(self):
        """Start the TCP server"""
        try:
            self.sock.bind((self.hostname, self.port))
            self.sock.listen(10)
            self.running = True
            self.logger.info(f"Enhanced TCP Server listening on {self.hostname}:{self.port}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to start TCP server: {e}")
            return False

    def run(self):
        """Main server loop"""
        if not self.start_server():
            return
        
        try:
            while self.running:
                try:
                    self.sock.settimeout(1.0)
                    conn, addr = self.sock.accept()
                    
                    self.client_counter += 1
                    client_id = f"tcp_client_{self.client_counter}"
                    
                    # Add client to manager (no encryption password by default)
                    if self.client_manager:
                        self.client_manager.add_tcp_client(client_id, conn, addr)
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr, client_id, self.server_password),
                        daemon=True,
                        name=f"TCPClient-{client_id}"
                    )
                    client_thread.start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Error accepting connection: {e}")
                        
        except KeyboardInterrupt:
            self.logger.info("TCP Server shutdown requested")
        finally:
            self.shutdown()

    def handle_client(self, conn, addr, client_id, server_password):
        """Enhanced client handler with encryption support and key exchange"""
        self.logger.info(f"Handling client {client_id} from {addr}")
        
        try:
            with conn:
                # First, perform key exchange handshake
                if not self.perform_key_exchange(conn, client_id, server_password):
                    self.logger.error(f"Key exchange failed for client {client_id}")
                    return
                
                while self.running:
                    try:
                        conn.settimeout(30.0)
                        data = conn.recv(4096)  # Larger buffer for encrypted data
                        
                        if not data:
                            self.logger.info(f"Client {client_id} disconnected.")
                            break

                        # Update receive statistics
                        if self.client_manager:
                            self.client_manager.update_tcp_stats(
                                client_id, received=1, bytes_received=len(data)
                            )

                        # Process the message (decrypt if necessary)
                        decrypted_message, message_info, is_encrypted = self.message_processor.parse_message(
                            data, client_id, self.client_manager.encryption_manager
                        )
                        
                        if decrypted_message is None:
                            # Error occurred during processing
                            error_response = f"ERROR: {message_info}"
                            checksum = self.message_processor.checksum(error_response)
                            response_data = f"{error_response}|{checksum}|PLAIN".encode()
                        else:
                            # Create appropriate response
                            response = self.message_processor.create_response(
                                decrypted_message, message_info, is_encrypted, 
                                client_id, self.client_manager.encryption_manager
                            )
                            response_data = response.encode()

                        # Apply fault simulation
                        fault_result = randomFault(response_data, "TCP", client_id)
                        if fault_result is not None:
                            response_data = fault_result

                        # Send response
                        conn.sendall(response_data)
                        self.logger.debug(f"[{client_id}] Sent response ({len(response_data)} bytes)")
                        
                        # Update send statistics
                        if self.client_manager:
                            self.client_manager.update_tcp_stats(
                                client_id, sent=1, bytes_sent=len(response_data)
                            )

                    except socket.timeout:
                        self.logger.warning(f"Client {client_id} timed out")
                        break
                    except Exception as e:
                        self.logger.error(f"Error with client {client_id}: {e}")
                        break
                        
        finally:
            if self.client_manager:
                self.client_manager.remove_tcp_client(client_id)
            self.logger.info(f"Client {client_id} handler terminated")
    
    def perform_key_exchange(self, conn, client_id, server_password):
        """Perform secure key exchange handshake with client using Diffie-Hellman"""
        try:
            # Send handshake request with protocol version
            handshake_request = "HANDSHAKE_REQUEST|SERVER_READY"
            conn.sendall(handshake_request.encode())
            self.logger.debug(f"Sent handshake request to {client_id}")
            
            # Wait for client response
            conn.settimeout(15.0)  # 15 second timeout for handshake
            response = conn.recv(1024).decode()
            
            if response.startswith("HANDSHAKE_RESPONSE|"):
                parts = response.split("|")
                encryption_mode = parts[1] if len(parts) >= 2 else "PLAIN"  # ENCRYPTED or PLAIN
                protocol_version = parts[2]
                
                if encryption_mode == "ENCRYPTED":
                    # Modern DH key exchange
                    return self.perform_dh_key_exchange(conn, client_id)
                else:
                    # Client wants plain text communication
                    response_msg = "HANDSHAKE_ACK|PLAIN_MODE"
                    self.logger.info(f"Plain text mode for client {client_id}")
                    conn.sendall(response_msg.encode())
                    return True
            
            self.logger.error(f"Invalid handshake response from client {client_id}: {response}")
            return False
            
        except Exception as e:
            self.logger.error(f"Key exchange failed with client {client_id}: {e}")
            return False
    
    def perform_dh_key_exchange(self, conn, client_id):
        """Perform Diffie-Hellman key exchange"""
        try:
            # Get DH parameters
            dh_params = self.client_manager.encryption_manager.get_dh_parameters_bytes()
            if not dh_params:
                self.logger.error("Failed to get DH parameters")
                conn.sendall("HANDSHAKE_ACK|ENCRYPTION_FAILED".encode())
                return False
            
            # Send DH parameters to client
            params_b64 = base64.b64encode(dh_params).decode()
            conn.sendall(f"DH_PARAMS|{params_b64}".encode())
            
            # Wait for client's public key
            client_response = conn.recv(4096).decode()  # Larger buffer for key data
            
            if not client_response.startswith("DH_PUBKEY|"):
                self.logger.error(f"Invalid DH response from client {client_id}")
                conn.sendall("HANDSHAKE_ACK|ENCRYPTION_FAILED".encode())
                return False
            
            # Extract client's public key
            client_pubkey_b64 = client_response.split("|")[1]
            client_pubkey = base64.b64decode(client_pubkey_b64)
            
            # Generate server's key pair and compute shared secret
            server_pubkey = self.client_manager.encryption_manager.get_public_key_bytes(client_id)
            if not server_pubkey:
                self.logger.error("Failed to generate server key pair")
                conn.sendall("HANDSHAKE_ACK|ENCRYPTION_FAILED".encode())
                return False
            
            # Compute shared key
            if not self.client_manager.encryption_manager.compute_shared_key(client_id, client_pubkey):
                self.logger.error("Failed to compute shared key")
                conn.sendall("HANDSHAKE_ACK|ENCRYPTION_FAILED".encode())
                return False
            
            # Send server's public key to client
            server_pubkey_b64 = base64.b64encode(server_pubkey).decode()
            conn.sendall(f"DH_SERVER_PUBKEY|{server_pubkey_b64}".encode())
            
            # Wait for client acknowledgment
            client_ack = conn.recv(1024).decode()
            if client_ack != "DH_ACK|SUCCESS":
                self.logger.error(f"Client failed to compute shared key: {client_ack}")
                conn.sendall("HANDSHAKE_ACK|ENCRYPTION_FAILED".encode())
                return False
            
            # Update client info
            if self.client_manager:
                with self.client_manager.lock:
                    if client_id in self.client_manager.tcp_clients:
                        self.client_manager.tcp_clients[client_id]['encrypted'] = True
            
            # Send final acknowledgment
            conn.sendall("HANDSHAKE_ACK|ENCRYPTION_ENABLED".encode())
            self.logger.info(f"Secure DH encryption enabled for client {client_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"DH key exchange failed with client {client_id}: {e}")
            conn.sendall("HANDSHAKE_ACK|ENCRYPTION_FAILED".encode())
            return False

    def shutdown(self):
        """Shutdown the server"""
        self.running = False
        if self.sock:
            self.sock.close()
        self.logger.info("Enhanced TCP Server shutdown complete")

class EnhancedUDPServer(threading.Thread):
    def __init__(self, hostname="localhost", port=8080, message_processor=None):
        super().__init__(daemon=True, name="UDPServer")
        self.hostname = hostname
        self.port = port
        self.message_processor = message_processor
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.running = False
        self.logger = logging.getLogger('UDPServer')

    def start_server(self):
        """Start the UDP server"""
        try:
            self.sock.bind((self.hostname, self.port))
            self.running = True
            self.logger.info(f"UDP Server listening on {self.hostname}:{self.port}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to start UDP server: {e}")
            return False

    def run(self):
        """Main server loop"""
        if not self.start_server():
            return

        try:
            while self.running:
                try:
                    data, addr = self.sock.recvfrom(4096)  # Buffer size for UDP
                    self.logger.info(f"Received UDP message from {addr}")

                    # Process the message
                    if self.message_processor:
                        response = self.message_processor.create_response(
                            data.decode(), "PLAIN", False, None, None
                        )
                        self.sock.sendto(response.encode(), addr)

                except Exception as e:
                    self.logger.error(f"Error handling UDP message: {e}")

        finally:
            self.shutdown()

    def shutdown(self):
        """Shutdown the server"""
        self.running = False
        if self.sock:
            self.sock.close()
        self.logger.info("UDP Server shutdown complete")

def get_server_config():
    """Get server configuration including encryption support"""
    print("\n=== ENHANCED SERVER CONFIGURATION ===")
    
    # Modern servers use DH key exchange and don't need default passwords
    print("Server Encryption Setup:")
    print("Note: Clients can connect with or without encryption")
    print("DH key exchange will be used for secure connections")
    print("Waiting server to start...")
    
    # No default password in modern setup
    default_password = None
    
    return default_password

def main():
    """Enhanced main function with encryption support"""
    logger = setup_logging()
    logger.info("=== Enhanced Resilient Server Starting ===")

    # Get server configuration - no default password needed for modern DH exchange
    get_server_config()

    # Create components
    encryption_manager = EncryptionManager()
    message_processor = MessageProcessor()
    client_manager = ClientManager(encryption_manager)

    # Use the same port for both TCP and UDP
    port = 8080
    tcp_server = EnhancedTCPServer(port=port, client_manager=client_manager, message_processor=message_processor)
    udp_server = EnhancedUDPServer(port=port, message_processor=message_processor)

    try:
        tcp_server.start()
        udp_server.start()  # Start UDP server

        logger.info("Enhanced server started successfully")
        logger.info(f"TCP and UDP Server: localhost:{port}")
        logger.info("🔒 Encryption: Modern DH key exchange enabled")
        logger.info("Server supports both encrypted and plain text clients")
        logger.info("Press Ctrl+C to shutdown")

        # Keep main thread alive and show periodic stats
        last_stats_time = time.time()
        while True:
            time.sleep(5)

            # Show stats every minute
            if time.time() - last_stats_time >= 60:
                stats = message_processor.message_stats
                logger.info(f"Message Stats - Total: {stats['total_messages']}, "
                          f"Encrypted: {stats['encrypted_messages']}, "
                          f"Plain: {stats['plain_messages']}, "
                          f"Errors: {stats['decryption_errors']}")
                last_stats_time = time.time()

    except KeyboardInterrupt:
        logger.info("\nShutdown requested...")
    finally:
        logger.info("Shutting down server...")
        tcp_server.shutdown()
        udp_server.shutdown()  # Shutdown UDP server
        time.sleep(2)
        logger.info("=== Enhanced Server Shutdown Complete ===")

if __name__ == "__main__":
    main()