import socket
import random
import time
import threading
import logging
from datetime import datetime
import json
import os

# Configure logging
def setup_logging():
    """Set up comprehensive logging configuration"""
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Create formatters
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Set up root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    
    # File handler for all logs
    file_handler = logging.FileHandler(
        f'logs/server_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)
    
    # Console handler for important messages
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

class ClientManager:
    """Manages active client connections and statistics"""
    
    def __init__(self):
        self.tcp_clients = {}
        self.udp_clients = {}
        self.client_stats = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger('ClientManager')
    
    def add_tcp_client(self, client_id, conn, addr):
        """Add a new TCP client"""
        with self.lock:
            self.tcp_clients[client_id] = {
                'connection': conn,
                'address': addr,
                'connected_at': datetime.now(),
                'messages_sent': 0,
                'messages_received': 0,
                'bytes_sent': 0,
                'bytes_received': 0
            }
            self.logger.info(f"TCP client {client_id} connected from {addr}")
    
    def remove_tcp_client(self, client_id):
        """Remove a TCP client"""
        with self.lock:
            if client_id in self.tcp_clients:
                client_info = self.tcp_clients[client_id]
                duration = datetime.now() - client_info['connected_at']
                self.logger.info(f"TCP client {client_id} disconnected. "
                               f"Session duration: {duration}, "
                               f"Messages: {client_info['messages_received']} received, "
                               f"{client_info['messages_sent']} sent")
                del self.tcp_clients[client_id]
    
    def update_tcp_stats(self, client_id, sent=0, received=0, bytes_sent=0, bytes_received=0):
        """Update client statistics"""
        with self.lock:
            if client_id in self.tcp_clients:
                client = self.tcp_clients[client_id]
                client['messages_sent'] += sent
                client['messages_received'] += received
                client['bytes_sent'] += bytes_sent
                client['bytes_received'] += bytes_received
    
    def log_udp_activity(self, addr, message_size):
        """Log UDP client activity"""
        client_key = f"{addr[0]}:{addr[1]}"
        with self.lock:
            if client_key not in self.udp_clients:
                self.udp_clients[client_key] = {
                    'address': addr,
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now(),
                    'message_count': 0,
                    'total_bytes': 0
                }
                self.logger.info(f"New UDP client detected: {addr}")
            
            client = self.udp_clients[client_key]
            client['last_seen'] = datetime.now()
            client['message_count'] += 1
            client['total_bytes'] += message_size
    
    def get_stats(self):
        """Get current server statistics"""
        with self.lock:
            return {
                'tcp_clients_active': len(self.tcp_clients),
                'udp_clients_seen': len(self.udp_clients),
                'tcp_clients': dict(self.tcp_clients),
                'udp_clients': dict(self.udp_clients)
            }

def randomFault(data, protocol, client_id=None):
    """Simulate network faults with logging"""
    logger = logging.getLogger('FaultSimulator')
    # r = random.random()
    r = 0.3  # Fixed for testing - change to random.random() for real simulation
    
    client_info = f" for client {client_id}" if client_id else ""
    
    if r < 0.2:
        logger.warning(f"[{protocol}] Simulating packet loss{client_info}")
        return 'error_code'.encode()

    if r < 0.4:
        delay = random.random() * 10
        logger.warning(f"[{protocol}] Simulating delay: {delay:.2f}s{client_info}")
        time.sleep(5)
        return None

    if r < 0.6:
        data_str = data.decode()
        logger.warning(f"[{protocol}] Simulating data corruption{client_info}")
        
        if "|" in data_str:
            body, recv_checksum = data_str.split("|", 1)
        else:
            body, recv_checksum = data_str, ""
        
        corrupted = bytearray(body.encode())
        if len(corrupted) > 0:
            # Flips random bits
            corrupted[random.randint(0, len(corrupted) - 1)] ^= 0xFF
        
        corrupted_data = bytes(corrupted) + (b"|" + recv_checksum.encode() if recv_checksum else b"")
        logger.debug(f"[{protocol}] Corrupted data: {corrupted_data}{client_info}")
        return corrupted_data

    logger.debug(f"[{protocol}] No fault simulated{client_info}")
    return None

class ResilientTCPServer(threading.Thread):
    def __init__(self, hostname="localhost", port=8080, client_manager=None):
        super().__init__(daemon=True, name="TCPServer")
        self.hostname = hostname
        self.port = port
        self.client_manager = client_manager
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = False
        self.client_counter = 0
        self.logger = logging.getLogger('TCPServer')

    def start_server(self):
        """Start the TCP server"""
        try:
            self.sock.bind((self.hostname, self.port))
            self.sock.listen(10)  # Allow up to 10 pending connections
            self.running = True
            self.logger.info(f"TCP Server listening on {self.hostname}:{self.port}")
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
                    # Set timeout for accept to allow periodic checks
                    self.sock.settimeout(1.0)
                    conn, addr = self.sock.accept()
                    
                    # Generate unique client ID
                    self.client_counter += 1
                    client_id = f"tcp_client_{self.client_counter}"
                    
                    # Add client to manager
                    if self.client_manager:
                        self.client_manager.add_tcp_client(client_id, conn, addr)
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr, client_id),
                        daemon=True,
                        name=f"TCPClient-{client_id}"
                    )
                    client_thread.start()
                    
                except socket.timeout:
                    continue  # Check if we should keep running
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Error accepting connection: {e}")
                        
        except KeyboardInterrupt:
            self.logger.info("TCP Server shutdown requested")
        finally:
            self.shutdown()

    def handle_client(self, conn, addr, client_id):
        """Handle individual client connection"""
        self.logger.info(f"Handling client {client_id} from {addr}")
        
        try:
            with conn:
                while self.running:
                    try:
                        # Receive data with timeout
                        conn.settimeout(30.0)  # 30-second timeout
                        data = conn.recv(1024)
                        
                        if not data:
                            self.logger.info(f"Client {client_id} disconnected gracefully")
                            break

                        decoded_data = data.decode('utf-8', errors='ignore')
                        self.logger.debug(f"[{client_id}] Received: {decoded_data[:100]}...")
                        
                        # Update statistics
                        if self.client_manager:
                            self.client_manager.update_tcp_stats(
                                client_id, received=1, bytes_received=len(data)
                            )

                        # Simulate faults
                        fault_result = randomFault(data, "TCP", client_id)
                        if fault_result is not None:
                            data = fault_result

                        # Echo back the data
                        conn.sendall(data)
                        self.logger.debug(f"[{client_id}] Sent response ({len(data)} bytes)")
                        data = conn.recv(1024)
                        
                        # Update statistics
                        if self.client_manager:
                            self.client_manager.update_tcp_stats(
                                client_id, sent=1, bytes_sent=len(data)
                            )

                    except socket.timeout:
                        self.logger.warning(f"Client {client_id} timed out")
                        break
                    except socket.error as e:
                        self.logger.error(f"Socket error with client {client_id}: {e}")
                        break
                    except Exception as e:
                        self.logger.error(f"Unexpected error with client {client_id}: {e}")
                        break
                        
        finally:
            # Clean up client
            if self.client_manager:
                self.client_manager.remove_tcp_client(client_id)
            self.logger.info(f"Client {client_id} handler terminated")

    def shutdown(self):
        """Shutdown the server"""
        self.running = False
        if self.sock:
            self.sock.close()
        self.logger.info("TCP Server shutdown complete")

class ResilientUDPServer(threading.Thread):
    def __init__(self, hostname="localhost", port=8081, client_manager=None):
        super().__init__(daemon=True, name="UDPServer")
        self.hostname = hostname
        self.port = port
        self.client_manager = client_manager
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
                    # Set timeout for recvfrom
                    self.sock.settimeout(1.0)
                    data, addr = self.sock.recvfrom(1024)
                    
                    decoded_data = data.decode('utf-8', errors='ignore')
                    self.logger.debug(f"UDP message from {addr}: {decoded_data[:100]}...")
                    
                    # Log client activity
                    if self.client_manager:
                        self.client_manager.log_udp_activity(addr, len(data))
                    
                    # Handle message in separate thread for better concurrency
                    threading.Thread(
                        target=self.handle_message,
                        args=(data, addr),
                        daemon=True,
                        name=f"UDPHandler-{addr[0]}:{addr[1]}"
                    ).start()
                    
                except socket.timeout:
                    continue  # Check if we should keep running
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Error receiving UDP data: {e}")
                        
        except KeyboardInterrupt:
            self.logger.info("UDP Server shutdown requested")
        finally:
            self.shutdown()

    def handle_message(self, data, addr):
        """Handle individual UDP message"""
        try:
            # Simulate faults
            fault_result = randomFault(data, "UDP", f"{addr[0]}:{addr[1]}")
            if fault_result is not None:
                data = fault_result
            
            # Echo back (optional for UDP)
            self.sock.sendto(data, addr)
            self.logger.debug(f"UDP response sent to {addr}")
            
        except Exception as e:
            self.logger.error(f"Error handling UDP message from {addr}: {e}")

    def shutdown(self):
        """Shutdown the server"""
        self.running = False
        if self.sock:
            self.sock.close()
        self.logger.info("UDP Server shutdown complete")

class ServerMonitor(threading.Thread):
    """Monitor server statistics and log them periodically"""
    
    def __init__(self, client_manager, interval=60):
        super().__init__(daemon=True, name="ServerMonitor")
        self.client_manager = client_manager
        self.interval = interval
        self.running = False
        self.logger = logging.getLogger('ServerMonitor')

    def run(self):
        self.running = True
        self.logger.info(f"Server monitor started (reporting every {self.interval}s)")
        
        while self.running:
            try:
                time.sleep(self.interval)
                if not self.running:
                    break
                    
                stats = self.client_manager.get_stats()
                self.logger.info(
                    f"Server Stats - TCP Clients: {stats['tcp_clients_active']}, "
                    f"UDP Clients Seen: {stats['udp_clients_seen']}"
                )
                
                # Detailed stats in debug log
                self.logger.debug(f"Detailed stats: {json.dumps(stats, default=str, indent=2)}")
                
            except Exception as e:
                self.logger.error(f"Error in server monitor: {e}")

    def stop(self):
        self.running = False

def main():
    """Main function to start all servers"""
    # Set up logging
    logger = setup_logging()
    logger.info("=== Resilient Server Starting ===")
    
    # Create client manager
    client_manager = ClientManager()
    
    # Create servers
    tcp_server = ResilientTCPServer(port=8080, client_manager=client_manager)
    udp_server = ResilientUDPServer(port=8081, client_manager=client_manager)
    
    # Create monitor
    monitor = ServerMonitor(client_manager, interval=30)
    
    try:
        # Start servers
        tcp_server.start()
        udp_server.start()
        monitor.start()
        
        logger.info("All servers started successfully")
        logger.info("TCP Server: localhost:8080")
        logger.info("UDP Server: localhost:8081")
        logger.info("Press Ctrl+C to shutdown")
        
        # Keep main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("\nShutdown requested...")
    finally:
        # Clean shutdown
        logger.info("Shutting down servers...")
        tcp_server.shutdown()
        udp_server.shutdown()
        monitor.stop()
        
        # Wait a bit for threads to finish
        time.sleep(2)
        logger.info("=== Server Shutdown Complete ===")

if __name__ == "__main__":
    main()