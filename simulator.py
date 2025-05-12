import numpy as np
import time
import random
import pandas as pd
from datetime import datetime, timedelta
from dataset_handler import DatasetHandler

class NetworkSimulator:
    """
    Simulator for generating network packets for testing and demonstration
    Uses a mix of sample packets from the dataset and synthetic packets
    """
    def __init__(self, dataset_dir="./data", use_dataset=True):
        self.dataset_dir = dataset_dir
        self.use_dataset = use_dataset
        self.dataset_handler = DatasetHandler(dataset_dir) if use_dataset else None
        self.sample_packets = []
        self.benign_probability = 0.8  # 80% of packets are benign by default
        self.synthetic_packet_types = [
            self._generate_http_packet,
            self._generate_dns_packet,
            self._generate_ssh_packet,
            self._generate_ftp_packet,
            self._generate_malicious_sql_injection,
            self._generate_malicious_xss,
            self._generate_malicious_port_scan
        ]
        
        # Load sample packets if using dataset
        if self.use_dataset:
            self._load_sample_packets()
    
    def _load_sample_packets(self):
        """
        Load sample packets from the dataset
        """
        # Check if dataset exists, if not, try to download
        if not self.dataset_handler.check_dataset_availability():
            success = self.dataset_handler.download_dataset()
            if not success:
                print("Dataset not available. Using synthetic packets only.")
                return
        
        # Create sample packets if needed
        if not self.dataset_handler.sample_packets:
            self.dataset_handler.create_sample_packets()
        
        # Get the sample packets
        self.sample_packets = self.dataset_handler.sample_packets or []
        
        print(f"Loaded {len(self.sample_packets)} sample packets from dataset")
    
    def set_benign_ratio(self, ratio):
        """
        Set the ratio of benign to malicious packets
        """
        self.benign_probability = max(0.0, min(1.0, ratio))
    
    def get_next_packet(self):
        """
        Get the next network packet for simulation
        """
        # Decide whether to use sample or synthetic packet
        if self.sample_packets and random.random() < 0.7:  # 70% chance to use sample packet
            # Get a random sample packet
            packet = random.choice(self.sample_packets).copy()
            
            # Update timestamp to current time
            packet['timestamp'] = datetime.now().isoformat()
            
            return packet
        else:
            # Generate a synthetic packet
            is_benign = random.random() < self.benign_probability
            
            if is_benign:
                # Generate benign packet
                generator_func = random.choice(self.synthetic_packet_types[:4])  # First 4 are benign
            else:
                # Generate malicious packet
                generator_func = random.choice(self.synthetic_packet_types[4:])  # Last 3 are malicious
            
            return generator_func()
    
    def _generate_base_packet(self, is_malicious=False):
        """
        Generate base packet structure
        """
        # Random IPs
        src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
        dst_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
        
        if random.random() < 0.3:  # 30% chance for external IP
            if random.random() < 0.5:
                src_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            else:
                dst_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        # Base packet
        packet = {
            'timestamp': datetime.now().isoformat(),
            'src': src_ip,
            'dst': dst_ip,
            'sport': random.randint(1024, 65535),
            'dport': random.randint(1, 1023),
            'proto': random.choice(['tcp', 'udp', 'icmp']),
            'len': random.randint(64, 1500),
            'ttl': random.randint(32, 128),
            'flags': 0,
            'is_actually_malicious': is_malicious
        }
        
        return packet
    
    def _generate_http_packet(self):
        """
        Generate an HTTP packet
        """
        packet = self._generate_base_packet(is_malicious=False)
        packet['proto'] = 'tcp'
        packet['dport'] = 80
        
        # HTTP request types
        http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']
        http_method = random.choice(http_methods)
        
        # Common paths
        paths = ['/', '/index.html', '/api/data', '/login', '/images/logo.png', '/css/style.css']
        path = random.choice(paths)
        
        # HTTP version
        http_version = '1.1'
        
        # Build HTTP request
        http_request = f"{http_method} {path} HTTP/{http_version}\r\n"
        http_request += f"Host: example.com\r\n"
        http_request += f"User-Agent: Mozilla/5.0\r\n"
        http_request += f"Accept: */*\r\n"
        http_request += f"Connection: keep-alive\r\n\r\n"
        
        packet['payload'] = http_request
        packet['len'] = len(http_request) + 40  # TCP/IP header
        
        return packet
    
    def _generate_dns_packet(self):
        """
        Generate a DNS packet
        """
        packet = self._generate_base_packet(is_malicious=False)
        packet['proto'] = 'udp'
        packet['dport'] = 53
        
        # Simple DNS query simulation
        domains = ['example.com', 'google.com', 'github.com', 'microsoft.com', 'amazon.com']
        domain = random.choice(domains)
        
        # Very simplified DNS payload
        dns_payload = f"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07{domain}\x00\x00\x01\x00\x01"
        
        packet['payload'] = dns_payload
        packet['len'] = len(dns_payload) + 28  # UDP/IP header
        
        return packet
    
    def _generate_ssh_packet(self):
        """
        Generate an SSH packet
        """
        packet = self._generate_base_packet(is_malicious=False)
        packet['proto'] = 'tcp'
        packet['dport'] = 22
        packet['flags'] = 16  # ACK
        
        # SSH banner/payload
        ssh_payload = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        
        packet['payload'] = ssh_payload
        packet['len'] = len(ssh_payload) + 40  # TCP/IP header
        
        return packet
    
    def _generate_ftp_packet(self):
        """
        Generate an FTP packet
        """
        packet = self._generate_base_packet(is_malicious=False)
        packet['proto'] = 'tcp'
        packet['dport'] = 21
        packet['flags'] = 16  # ACK
        
        # FTP commands/responses
        ftp_commands = [
            "USER anonymous",
            "PASS guest",
            "PWD",
            "CWD /pub",
            "LIST",
            "RETR file.txt",
            "QUIT"
        ]
        
        ftp_responses = [
            "220 FTP server ready",
            "331 Please specify the password",
            "230 Login successful",
            "257 \"/\" is current directory",
            "250 Directory changed",
            "150 Opening data connection",
            "226 Transfer complete",
            "221 Goodbye"
        ]
        
        # 50% chance for command, 50% for response
        if random.random() < 0.5:
            packet['payload'] = random.choice(ftp_commands)
            packet['sport'], packet['dport'] = packet['dport'], packet['sport']  # Swap for client->server
        else:
            packet['payload'] = random.choice(ftp_responses)
        
        packet['len'] = len(packet['payload']) + 40  # TCP/IP header
        
        return packet
    
    def _generate_malicious_sql_injection(self):
        """
        Generate a packet with SQL injection payload
        """
        packet = self._generate_http_packet()  # Start with HTTP packet
        packet['is_actually_malicious'] = True
        
        # SQL injection payloads
        sql_injections = [
            "' OR 1=1 --",
            "'; DROP TABLE users; --",
            "admin' --",
            "1' UNION SELECT username, password FROM users --",
            "1; UPDATE users SET password='hacked' WHERE username='admin' --"
        ]
        
        # Add SQL injection to HTTP request
        sql_payload = random.choice(sql_injections)
        http_request = packet['payload'].replace("GET /", f"GET /login?username={sql_payload}&password=test")
        
        packet['payload'] = http_request
        packet['len'] = len(http_request) + 40
        
        return packet
    
    def _generate_malicious_xss(self):
        """
        Generate a packet with XSS payload
        """
        packet = self._generate_http_packet()  # Start with HTTP packet
        packet['is_actually_malicious'] = True
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src='x' onerror='alert(\"XSS\")'>",
            "<body onload='alert(\"XSS\")'>",
            "<svg/onload=alert('XSS')>",
            "<iframe src='javascript:alert(`XSS`)'>"
        ]
        
        # Add XSS to HTTP request
        xss_payload = random.choice(xss_payloads)
        http_request = packet['payload'].replace("GET /", f"GET /search?q={xss_payload}")
        
        packet['payload'] = http_request
        packet['len'] = len(http_request) + 40
        
        return packet
    
    def _generate_malicious_port_scan(self):
        """
        Generate a packet simulating port scanning behavior
        """
        packet = self._generate_base_packet(is_malicious=True)
        
        # TCP SYN packet (common for port scanning)
        packet['proto'] = 'tcp'
        packet['flags'] = 2  # SYN flag
        
        # Target common vulnerable ports
        vulnerable_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5900]
        packet['dport'] = random.choice(vulnerable_ports)
        
        # Minimal payload
        packet['payload'] = ""
        packet['len'] = 40  # Just TCP/IP header
        
        return packet
    
    def generate_batch(self, count=10, time_spread_seconds=60):
        """
        Generate a batch of packets spread over a time period
        Useful for testing detection over time
        """
        packets = []
        
        # Generate time offsets
        base_time = datetime.now()
        time_offsets = sorted([random.random() * time_spread_seconds for _ in range(count)])
        
        for i in range(count):
            # Get a packet
            packet = self.get_next_packet()
            
            # Adjust timestamp
            packet_time = base_time + timedelta(seconds=time_offsets[i])
            packet['timestamp'] = packet_time.isoformat()
            
            packets.append(packet)
        
        return packets
