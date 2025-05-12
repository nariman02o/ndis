import random
import time
import datetime
import ipaddress
import json
import numpy as np
from scapy.all import IP, TCP, UDP, ICMP, Ether, Raw
import threading
import queue
import os

class RealNetworkSimulator:
    """
    Enhanced simulator for generating realistic network traffic
    Uses Scapy to create realistic packet structures
    """
    def __init__(self, 
                 interface_mode="simulated", 
                 pcap_file=None,
                 capture_interface=None):
        self.interface_mode = interface_mode  # simulated, pcap_replay, live_capture
        self.pcap_file = pcap_file
        self.capture_interface = capture_interface
        
        self.packet_queue = queue.Queue(maxsize=1000)
        self.running = False
        self.simulation_thread = None
        
        # Network topology settings
        self.subnets = {
            'internal': '192.168.1.0/24',
            'dmz': '172.16.1.0/24',
            'external': '203.0.113.0/24'  # TEST-NET-3 for documentation
        }
        
        # Define servers in our simulated network
        self.servers = {
            'web_server': {'ip': '192.168.1.10', 'ports': [80, 443], 'services': ['http', 'https']},
            'database': {'ip': '192.168.1.20', 'ports': [3306, 5432], 'services': ['mysql', 'postgresql']},
            'mail_server': {'ip': '192.168.1.30', 'ports': [25, 110, 143], 'services': ['smtp', 'pop3', 'imap']},
            'file_server': {'ip': '192.168.1.40', 'ports': [21, 22], 'services': ['ftp', 'ssh']},
            'dmz_web': {'ip': '172.16.1.10', 'ports': [80, 443], 'services': ['http', 'https']},
            'vpn_server': {'ip': '172.16.1.20', 'ports': [1194, 443], 'services': ['openvpn', 'ssl']}
        }
        
        # Initialize clients
        self.generate_clients(30)  # Generate 30 internal clients
        
        # Traffic patterns (time-based)
        self.traffic_patterns = {
            'working_hours': {'start': 8, 'end': 18, 'intensity': 0.8},  # 8 AM to 6 PM
            'after_hours': {'start': 18, 'end': 23, 'intensity': 0.3},   # 6 PM to 11 PM
            'night': {'start': 23, 'end': 8, 'intensity': 0.1}           # 11 PM to 8 AM
        }
        
        # Attack patterns for simulation
        self.attack_patterns = {
            'port_scan': {'probability': 0.05, 'duration': 10, 'intensity': 0.7},
            'brute_force': {'probability': 0.03, 'duration': 5, 'intensity': 0.5},
            'ddos': {'probability': 0.01, 'duration': 15, 'intensity': 0.9},
            'data_exfiltration': {'probability': 0.02, 'duration': 8, 'intensity': 0.4},
            'malware_communication': {'probability': 0.04, 'duration': 12, 'intensity': 0.6}
        }
        
        # Current simulation state
        self.current_time = datetime.datetime.now()
        self.current_attacks = {}  # active attacks
        self.benign_ratio = 0.8
        
        # Protocol distribution (approximate real-world percentages)
        self.protocol_distribution = {
            'tcp': 0.75,  # ~75% of traffic
            'udp': 0.20,  # ~20% of traffic
            'icmp': 0.05  # ~5% of traffic
        }
        
        # Service port mappings
        self.common_ports = {
            'http': 80, 'https': 443, 'dns': 53, 'ntp': 123,
            'ssh': 22, 'telnet': 23, 'ftp': 21, 'smtp': 25,
            'pop3': 110, 'imap': 143, 'smb': 445, 'rdp': 3389,
            'mysql': 3306, 'postgresql': 5432, 'mssql': 1433,
            'openvpn': 1194, 'ipsec': 500, 'sip': 5060
        }
        
        # Traffic statistics
        self.stats = {
            'packets_total': 0,
            'packets_tcp': 0,
            'packets_udp': 0,
            'packets_icmp': 0,
            'packets_other': 0,
            'bytes_total': 0,
            'malicious_packets': 0,
            'benign_packets': 0,
            'internal_to_internal': 0,
            'internal_to_external': 0,
            'external_to_internal': 0,
            'external_to_external': 0
        }
        
        # Initialize session tracking
        self.active_sessions = {}
        
    def generate_clients(self, num_clients):
        """Generate a list of client IP addresses in the internal network"""
        self.clients = []
        internal_network = ipaddress.ip_network(self.subnets['internal'])
        hosts = list(internal_network.hosts())
        
        # Filter out servers
        server_ips = [info['ip'] for info in self.servers.values() 
                    if info['ip'].startswith('192.168.')]
        
        available_hosts = [str(ip) for ip in hosts if str(ip) not in server_ips]
        
        # Select random hosts as clients
        if len(available_hosts) >= num_clients:
            self.clients = random.sample(available_hosts, num_clients)
        else:
            self.clients = available_hosts
    
    def get_time_based_intensity(self):
        """Get traffic intensity based on time of day"""
        hour = self.current_time.hour
        
        for pattern_name, pattern in self.traffic_patterns.items():
            if pattern['start'] <= hour < pattern['end'] or \
               (pattern['start'] > pattern['end'] and (hour >= pattern['start'] or hour < pattern['end'])):
                return pattern['intensity']
        
        return 0.5  # default intensity
    
    def is_attack_active(self, attack_type):
        """Check if a specific attack is currently active"""
        return attack_type in self.current_attacks and self.current_attacks[attack_type]['active']
    
    def start_attack(self, attack_type):
        """Start a simulated attack"""
        if attack_type in self.attack_patterns:
            duration = self.attack_patterns[attack_type]['duration']
            intensity = self.attack_patterns[attack_type]['intensity']
            
            self.current_attacks[attack_type] = {
                'active': True,
                'start_time': self.current_time,
                'end_time': self.current_time + datetime.timedelta(seconds=duration),
                'intensity': intensity,
                'source_ip': self._get_random_external_ip()
            }
            
            print(f"Starting {attack_type} attack from {self.current_attacks[attack_type]['source_ip']}")
            
            return True
        return False
    
    def update_attacks(self):
        """Update status of active attacks"""
        for attack_type in list(self.current_attacks.keys()):
            attack = self.current_attacks[attack_type]
            if attack['active'] and self.current_time >= attack['end_time']:
                attack['active'] = False
                print(f"Attack {attack_type} has ended")
    
    def _get_random_internal_ip(self):
        """Get a random internal IP address"""
        if random.random() < 0.7:  # 70% chance to use a client
            return random.choice(self.clients)
        else:  # 30% chance to use a server
            servers = [info['ip'] for name, info in self.servers.items() 
                     if info['ip'].startswith('192.168.')]
            return random.choice(servers) if servers else self.clients[0]
    
    def _get_random_dmz_ip(self):
        """Get a random DMZ IP address"""
        dmz_servers = [info['ip'] for name, info in self.servers.items() 
                     if info['ip'].startswith('172.16.')]
        if dmz_servers:
            return random.choice(dmz_servers)
        
        # If no DMZ servers defined, generate a random one
        dmz_network = ipaddress.ip_network(self.subnets['dmz'])
        hosts = list(dmz_network.hosts())
        return str(random.choice(hosts))
    
    def _get_random_external_ip(self):
        """Get a random external IP address"""
        if random.random() < 0.3:  # 30% chance for well-known IPs
            well_known = [
                '8.8.8.8', '1.1.1.1',  # Google & Cloudflare DNS
                '13.107.42.14', '104.215.148.63',  # Microsoft
                '31.13.70.36', '157.240.2.35',  # Facebook
                '172.217.164.110', '216.58.200.46'  # Google
            ]
            return random.choice(well_known)
            
        # 70% chance for random external IPs
        external_network = ipaddress.ip_network(self.subnets['external'])
        hosts = list(external_network.hosts())
        return str(random.choice(hosts))
    
    def _get_service_port(self, is_source=False):
        """Get a port number for a packet"""
        if is_source:
            # Source ports are typically ephemeral
            return random.randint(1024, 65535)
        else:
            # Destination ports are often well-known service ports
            if random.random() < 0.7:  # 70% chance for common service port
                return random.choice(list(self.common_ports.values()))
            else:  # 30% chance for random port
                return random.randint(1, 65535)
    
    def _get_packet_size(self, packet_type):
        """Generate a realistic packet size based on packet type"""
        if packet_type == 'tcp':
            # TCP packet sizes follow different distributions based on the application
            if random.random() < 0.7:  # Small packets (e.g., ACKs, control packets)
                return random.randint(40, 100)
            else:  # Data packets
                return random.randint(100, 1460)
        elif packet_type == 'udp':
            # UDP packets are often either very small or close to MTU
            if random.random() < 0.5:
                return random.randint(50, 200)  # Small UDP (e.g., DNS)
            else:
                return random.randint(500, 1400)  # Larger UDP (e.g., streaming)
        elif packet_type == 'icmp':
            # ICMP packets are typically small
            return random.randint(64, 128)
        else:
            return random.randint(64, 1460)
    
    def _create_attack_packet(self, attack_type):
        """Create a realistic attack packet"""
        if attack_type == 'port_scan':
            # Port scanning typically involves TCP SYN packets to various ports
            src_ip = self.current_attacks['port_scan']['source_ip']
            dst_ip = self._get_random_internal_ip()
            dst_port = random.randint(1, 10000)  # Scanning wide range of ports
            
            scapy_packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(30000, 65000), 
                                                         dport=dst_port, flags='S')
            
            packet = {
                'timestamp': self.current_time.isoformat(),
                'src': src_ip,
                'dst': dst_ip,
                'sport': scapy_packet[TCP].sport,
                'dport': dst_port,
                'proto': 'tcp',
                'flags': 2,  # SYN flag
                'len': len(scapy_packet),
                'payload': '',
                'is_actually_malicious': True
            }
            
        elif attack_type == 'brute_force':
            # Brute force typically targets SSH, FTP, or web login pages
            src_ip = self.current_attacks['brute_force']['source_ip']
            
            # Choose a server to target
            target_servers = [name for name, info in self.servers.items() 
                           if 'ssh' in info['services'] or 'ftp' in info['services']]
            
            if target_servers:
                target = random.choice(target_servers)
                dst_ip = self.servers[target]['ip']
                service = random.choice([s for s in self.servers[target]['services'] 
                                      if s in ['ssh', 'ftp']])
                dst_port = self.common_ports[service]
            else:
                dst_ip = self._get_random_internal_ip()
                dst_port = random.choice([21, 22])  # FTP or SSH
                service = 'ssh' if dst_port == 22 else 'ftp'
            
            # Create packet with brute force payload
            payload = f"USER admin\r\nPASS {random.choice(['password', 'admin', '123456', 'root', 'qwerty'])}\r\n"
            scapy_packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(30000, 65000), 
                                                         dport=dst_port, flags='PA')/Raw(load=payload)
            
            packet = {
                'timestamp': self.current_time.isoformat(),
                'src': src_ip,
                'dst': dst_ip,
                'sport': scapy_packet[TCP].sport,
                'dport': dst_port,
                'proto': 'tcp',
                'flags': 24,  # PSH+ACK flags
                'len': len(scapy_packet),
                'payload': payload,
                'is_actually_malicious': True
            }
            
        elif attack_type == 'ddos':
            # DDoS simulation - many packets from different sources to one target
            target_servers = [name for name, info in self.servers.items() 
                          if 'http' in info['services'] or 'https' in info['services']]
            
            if target_servers:
                target = random.choice(target_servers)
                dst_ip = self.servers[target]['ip']
                dst_port = random.choice(self.servers[target]['ports'])
            else:
                dst_ip = self._get_random_internal_ip()
                dst_port = 80  # Default to HTTP
            
            # Use a different source IP for each packet in the DDoS
            src_ip = self._get_random_external_ip()
            
            # Create SYN flood or HTTP GET flood
            if random.random() < 0.5:  # SYN flood
                scapy_packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65000), 
                                                            dport=dst_port, flags='S')
                payload = ''
                packet = {
                    'timestamp': self.current_time.isoformat(),
                    'src': src_ip,
                    'dst': dst_ip,
                    'sport': scapy_packet[TCP].sport,
                    'dport': dst_port,
                    'proto': 'tcp',
                    'flags': 2,  # SYN flag
                    'len': len(scapy_packet),
                    'payload': payload,
                    'is_actually_malicious': True
                }
            else:  # HTTP GET flood
                payload = "GET / HTTP/1.1\r\nHost: target.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
                scapy_packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65000), 
                                                            dport=dst_port, flags='PA')/Raw(load=payload)
                packet = {
                    'timestamp': self.current_time.isoformat(),
                    'src': src_ip,
                    'dst': dst_ip,
                    'sport': scapy_packet[TCP].sport,
                    'dport': dst_port,
                    'proto': 'tcp',
                    'flags': 24,  # PSH+ACK flags
                    'len': len(scapy_packet),
                    'payload': payload,
                    'is_actually_malicious': True
                }
                
        elif attack_type == 'data_exfiltration':
            # Data exfiltration usually involves sensitive data being sent out
            src_ip = self._get_random_internal_ip()  # Internal host is compromised
            dst_ip = self.current_attacks['data_exfiltration']['source_ip']  # External C2 server
            
            # Create suspicious outbound connection
            payload_samples = [
                "BEGIN_DATA:user_credentials.csv:BASE64DATA:dXNlcm5hbWUsaGFzaGVkX3Bhc3N3b3JkLGVtYWlsLGFkbWlu==END_DATA",
                "BEGIN_DATA:customer_data.csv:BASE64DATA:bmFtZSxhZGRyZXNzLGNyZWRpdF9jYXJkLGNjdg==END_DATA",
                "BEGIN_DATA:financial_records.xls:BASE64DATA:cXVhcnRlcixwcm9maXQsbG9zcyxleHBlbnNlcw==END_DATA"
            ]
            
            payload = random.choice(payload_samples)
            scapy_packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65000), 
                                                        dport=443, flags='PA')/Raw(load=payload)
            
            packet = {
                'timestamp': self.current_time.isoformat(),
                'src': src_ip,
                'dst': dst_ip,
                'sport': scapy_packet[TCP].sport,
                'dport': 443,
                'proto': 'tcp',
                'flags': 24,  # PSH+ACK flags
                'len': len(scapy_packet),
                'payload': payload,
                'is_actually_malicious': True
            }
            
        elif attack_type == 'malware_communication':
            # Malware beaconing/C2 communication
            src_ip = self._get_random_internal_ip()  # Infected internal host
            dst_ip = self.current_attacks['malware_communication']['source_ip']  # C2 server
            
            # Different C2 communication patterns
            if random.random() < 0.3:  # DNS tunneling
                payload = f"QNAPOWIEJF.{random.randint(1000, 9999)}.malicious-domain.com"
                scapy_packet = IP(src=src_ip, dst=dst_ip)/UDP(sport=random.randint(1024, 65000), 
                                                            dport=53)/Raw(load=payload)
                packet = {
                    'timestamp': self.current_time.isoformat(),
                    'src': src_ip,
                    'dst': dst_ip,
                    'sport': scapy_packet[UDP].sport,
                    'dport': 53,
                    'proto': 'udp',
                    'len': len(scapy_packet),
                    'payload': payload,
                    'is_actually_malicious': True
                }
            else:  # HTTP/HTTPS beaconing
                endpoints = ['/gate.php', '/config.bin', '/updates.js', '/api/v2/check']
                payload = f"GET {random.choice(endpoints)}?id={random.randint(10000, 99999)} HTTP/1.1\r\nHost: c2server.net\r\n\r\n"
                dst_port = 443 if random.random() < 0.7 else 80
                
                scapy_packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65000), 
                                                            dport=dst_port, flags='PA')/Raw(load=payload)
                
                packet = {
                    'timestamp': self.current_time.isoformat(),
                    'src': src_ip,
                    'dst': dst_ip,
                    'sport': scapy_packet[TCP].sport,
                    'dport': dst_port,
                    'proto': 'tcp',
                    'flags': 24,  # PSH+ACK flags
                    'len': len(scapy_packet),
                    'payload': payload,
                    'is_actually_malicious': True
                }
        else:
            # Default to a basic malicious packet
            src_ip = self._get_random_external_ip()
            dst_ip = self._get_random_internal_ip()
            payload = "MALICIOUS_CONTENT"
            
            scapy_packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65000), 
                                                         dport=80, flags='PA')/Raw(load=payload)
            
            packet = {
                'timestamp': self.current_time.isoformat(),
                'src': src_ip,
                'dst': dst_ip,
                'sport': scapy_packet[TCP].sport,
                'dport': 80,
                'proto': 'tcp',
                'flags': 24,  # PSH+ACK flags
                'len': len(scapy_packet),
                'payload': payload,
                'is_actually_malicious': True
            }
        
        # Update statistics
        self.stats['packets_total'] += 1
        self.stats['malicious_packets'] += 1
        self.stats['bytes_total'] += packet['len']
        
        if packet['proto'] == 'tcp':
            self.stats['packets_tcp'] += 1
        elif packet['proto'] == 'udp':
            self.stats['packets_udp'] += 1
        elif packet['proto'] == 'icmp':
            self.stats['packets_icmp'] += 1
        else:
            self.stats['packets_other'] += 1
            
        # Track traffic direction
        src_is_internal = any(src_ip.startswith(prefix) for prefix in ['192.168.', '10.', '172.16.'])
        dst_is_internal = any(dst_ip.startswith(prefix) for prefix in ['192.168.', '10.', '172.16.'])
        
        if src_is_internal and dst_is_internal:
            self.stats['internal_to_internal'] += 1
        elif src_is_internal and not dst_is_internal:
            self.stats['internal_to_external'] += 1
        elif not src_is_internal and dst_is_internal:
            self.stats['external_to_internal'] += 1
        else:
            self.stats['external_to_external'] += 1
            
        return packet
    
    def _create_normal_packet(self):
        """Create a realistic normal network packet"""
        # Determine packet protocol based on distribution
        rand = random.random()
        if rand < self.protocol_distribution['tcp']:
            protocol = 'tcp'
        elif rand < self.protocol_distribution['tcp'] + self.protocol_distribution['udp']:
            protocol = 'udp'
        else:
            protocol = 'icmp'
        
        # Determine source and destination
        direction = random.random()
        
        if direction < 0.4:  # 40% internal to external traffic
            src_ip = self._get_random_internal_ip()
            dst_ip = self._get_random_external_ip()
            self.stats['internal_to_external'] += 1
        elif direction < 0.7:  # 30% external to internal traffic
            src_ip = self._get_random_external_ip()
            dst_ip = self._get_random_internal_ip()
            self.stats['external_to_internal'] += 1
        elif direction < 0.9:  # 20% internal to internal traffic
            src_ip = self._get_random_internal_ip()
            dst_ip = self._get_random_internal_ip()
            while dst_ip == src_ip:  # Avoid same source and destination
                dst_ip = self._get_random_internal_ip()
            self.stats['internal_to_internal'] += 1
        else:  # 10% external to external (transit traffic)
            src_ip = self._get_random_external_ip()
            dst_ip = self._get_random_external_ip()
            while dst_ip == src_ip:  # Avoid same source and destination
                dst_ip = self._get_random_external_ip()
            self.stats['external_to_external'] += 1
        
        # Create the packet based on protocol
        if protocol == 'tcp':
            src_port = self._get_service_port(is_source=True)
            dst_port = self._get_service_port(is_source=False)
            
            # Determine TCP flags based on common patterns
            flag_rand = random.random()
            if flag_rand < 0.1:  # 10% SYN (new connection)
                flags = 2  # SYN
                payload = ""
            elif flag_rand < 0.2:  # 10% SYN-ACK (connection response)
                flags = 18  # SYN-ACK
                payload = ""
            elif flag_rand < 0.7:  # 50% PSH-ACK (data transmission)
                flags = 24  # PSH-ACK
                
                # Generate realistic payload based on destination port
                if dst_port == 80 or dst_port == 8080:  # HTTP
                    http_methods = ['GET', 'POST', 'PUT', 'DELETE']
                    endpoints = ['/', '/index.html', '/api/data', '/login', '/images/logo.png']
                    payload = f"{random.choice(http_methods)} {random.choice(endpoints)} HTTP/1.1\r\nHost: example.com\r\n\r\n"
                elif dst_port == 443:  # HTTPS (encrypted, but we'll simulate)
                    payload = "ENCRYPTED_TLS_DATA"
                elif dst_port == 25:  # SMTP
                    payload = "MAIL FROM: user@example.com\r\nRCPT TO: recipient@example.org\r\n"
                elif dst_port == 53:  # DNS
                    payload = "DNS_QUERY_DATA"
                else:
                    payload = "APPLICATION_DATA"
            else:  # 30% ACK (acknowledgment)
                flags = 16  # ACK
                payload = ""
            
            # Create the packet
            scapy_packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags=flags)
            if payload:
                scapy_packet = scapy_packet/Raw(load=payload)
                
            packet = {
                'timestamp': self.current_time.isoformat(),
                'src': src_ip,
                'dst': dst_ip,
                'sport': src_port,
                'dport': dst_port,
                'proto': 'tcp',
                'flags': flags,
                'len': len(scapy_packet),
                'payload': payload,
                'is_actually_malicious': False
            }
            
            self.stats['packets_tcp'] += 1
            
        elif protocol == 'udp':
            src_port = self._get_service_port(is_source=True)
            
            # Choose common UDP services more frequently
            common_udp_services = {
                'dns': 53,
                'ntp': 123,
                'snmp': 161,
                'dhcp_server': 67,
                'dhcp_client': 68,
                'sip': 5060
            }
            
            if random.random() < 0.7:  # 70% chance for common UDP service
                service = random.choice(list(common_udp_services.keys()))
                dst_port = common_udp_services[service]
            else:
                dst_port = self._get_service_port(is_source=False)
            
            # Generate payload based on service
            if dst_port == 53:  # DNS
                domains = ['example.com', 'google.com', 'microsoft.com', 'amazon.com']
                payload = f"DNS_QUERY_{random.choice(domains)}"
            elif dst_port == 123:  # NTP
                payload = "NTP_DATA"
            elif dst_port == 161:  # SNMP
                payload = "SNMP_GET_REQUEST"
            elif dst_port in [67, 68]:  # DHCP
                payload = "DHCP_REQUEST"
            else:
                payload = f"UDP_DATA_{random.randint(1, 1000)}"
            
            # Create the packet
            scapy_packet = IP(src=src_ip, dst=dst_ip)/UDP(sport=src_port, dport=dst_port)/Raw(load=payload)
            
            packet = {
                'timestamp': self.current_time.isoformat(),
                'src': src_ip,
                'dst': dst_ip,
                'sport': src_port,
                'dport': dst_port,
                'proto': 'udp',
                'len': len(scapy_packet),
                'payload': payload,
                'is_actually_malicious': False
            }
            
            self.stats['packets_udp'] += 1
            
        else:  # ICMP
            # ICMP types: 8 (echo request), 0 (echo reply), 3 (destination unreachable)
            icmp_types = [(8, 0), (0, 0), (3, 1)]  # (type, code) pairs
            icmp_type, icmp_code = random.choice(icmp_types)
            
            if icmp_type == 8:  # Echo request (ping)
                payload = f"PING_DATA_{random.randint(1, 1000)}"
            elif icmp_type == 0:  # Echo reply
                payload = f"PONG_DATA_{random.randint(1, 1000)}"
            else:  # Destination unreachable
                payload = "ICMP_UNREACHABLE"
            
            # Create the packet
            scapy_packet = IP(src=src_ip, dst=dst_ip)/ICMP(type=icmp_type, code=icmp_code)/Raw(load=payload)
            
            packet = {
                'timestamp': self.current_time.isoformat(),
                'src': src_ip,
                'dst': dst_ip,
                'proto': 'icmp',
                'icmp_type': icmp_type,
                'icmp_code': icmp_code,
                'len': len(scapy_packet),
                'payload': payload,
                'is_actually_malicious': False
            }
            
            self.stats['packets_icmp'] += 1
        
        # Update global statistics
        self.stats['packets_total'] += 1
        self.stats['benign_packets'] += 1
        self.stats['bytes_total'] += packet['len']
        
        return packet
    
    def _handle_sessions(self, packet):
        """Track and update sessions for realistic conversation flows"""
        # Only track TCP sessions for now
        if packet['proto'] != 'tcp':
            return packet
        
        # Create a session key
        if 'sport' in packet and 'dport' in packet:
            forward_key = f"{packet['src']}:{packet['sport']}-{packet['dst']}:{packet['dport']}"
            reverse_key = f"{packet['dst']}:{packet['dport']}-{packet['src']}:{packet['sport']}"
            
            # Check if this is part of an existing session
            if forward_key in self.active_sessions:
                session = self.active_sessions[forward_key]
                session['packets'] += 1
                session['last_seen'] = self.current_time
                
                # For established sessions, ensure proper TCP flags for continuity
                if packet['flags'] == 2:  # SYN flag, should only be seen once
                    packet['flags'] = 24  # Change to PSH-ACK for ongoing session
                
            elif reverse_key in self.active_sessions:
                session = self.active_sessions[reverse_key]
                session['packets'] += 1
                session['last_seen'] = self.current_time
                
                # If original direction was SYN, this might be SYN-ACK
                if session['packets'] == 2 and packet['flags'] != 18:
                    packet['flags'] = 18  # Set to SYN-ACK for second packet
                else:
                    packet['flags'] = 24  # Otherwise PSH-ACK for data or 16 for ACK
                    
            else:
                # New session
                if random.random() < 0.9:  # 90% chance to start with SYN
                    packet['flags'] = 2  # SYN flag
                
                self.active_sessions[forward_key] = {
                    'start_time': self.current_time,
                    'last_seen': self.current_time,
                    'packets': 1,
                    'src': packet['src'],
                    'dst': packet['dst'],
                    'sport': packet['sport'],
                    'dport': packet['dport']
                }
                
            # Clean up old sessions (older than 5 minutes)
            self._cleanup_old_sessions(300)  # 300 seconds = 5 minutes
        
        return packet
    
    def _cleanup_old_sessions(self, max_age_seconds):
        """Remove sessions that have been inactive for a while"""
        current_time = self.current_time
        keys_to_remove = []
        
        for key, session in self.active_sessions.items():
            time_diff = (current_time - session['last_seen']).total_seconds()
            if time_diff > max_age_seconds:
                keys_to_remove.append(key)
                
        for key in keys_to_remove:
            del self.active_sessions[key]
    
    def generate_packet(self):
        """Generate a single network packet"""
        # Update current time
        self.current_time = datetime.datetime.now()
        
        # Update attack status
        self.update_attacks()
        
        # Start new attacks based on probability
        for attack_type, attack_info in self.attack_patterns.items():
            if (attack_type not in self.current_attacks or 
                not self.current_attacks[attack_type]['active']):
                if random.random() < attack_info['probability']:
                    self.start_attack(attack_type)
        
        # Determine if this packet should be malicious
        is_attack_packet = False
        active_attacks = [attack for attack, info in self.current_attacks.items() 
                         if info['active']]
        
        if active_attacks and random.random() > self.benign_ratio:
            attack_type = random.choice(active_attacks)
            packet = self._create_attack_packet(attack_type)
            is_attack_packet = True
        else:
            packet = self._create_normal_packet()
        
        # Apply session tracking for realistic conversations
        if not is_attack_packet:  # Don't modify attack packets
            packet = self._handle_sessions(packet)
            
        return packet
    
    def get_next_packet(self):
        """Get the next network packet (main interface method)"""
        if not self.packet_queue.empty():
            return self.packet_queue.get()
        else:
            return self.generate_packet()
    
    def start_simulation(self):
        """Start the packet generation in a background thread"""
        if self.running:
            return
            
        self.running = True
        self.simulation_thread = threading.Thread(target=self._simulation_loop)
        self.simulation_thread.daemon = True
        self.simulation_thread.start()
    
    def stop_simulation(self):
        """Stop the simulation thread"""
        self.running = False
        if self.simulation_thread:
            self.simulation_thread.join(timeout=1.0)
            
    def _simulation_loop(self):
        """Main simulation loop that runs in background thread"""
        while self.running:
            try:
                # Generate packets based on time-of-day intensity
                intensity = self.get_time_based_intensity()
                delay = max(0.1, 1.0 - intensity)  # More intensity = less delay
                
                # Generate a packet
                packet = self.generate_packet()
                
                # Add to queue if not full
                if not self.packet_queue.full():
                    self.packet_queue.put(packet)
                
                # Sleep based on intensity
                time.sleep(delay)
                
            except Exception as e:
                print(f"Error in simulation loop: {str(e)}")
                time.sleep(1.0)  # Sleep on error to prevent CPU spinning
    
    def set_benign_ratio(self, ratio):
        """Set the ratio of benign to malicious packets"""
        self.benign_ratio = max(0.0, min(1.0, ratio))
    
    def get_statistics(self):
        """Get current traffic statistics"""
        return self.stats
    
    def get_active_sessions(self):
        """Get information about active sessions"""
        return self.active_sessions
    
    def get_active_attacks(self):
        """Get information about active attacks"""
        return {k: v for k, v in self.current_attacks.items() if v['active']}
        
    def generate_batch(self, count=10, time_spread_seconds=60):
        """Generate a batch of packets spread over a time period"""
        packets = []
        
        # Calculate time increments
        time_increments = np.linspace(0, time_spread_seconds, count)
        base_time = self.current_time
        
        for i in range(count):
            # Set current time for this packet
            self.current_time = base_time + datetime.timedelta(seconds=time_increments[i])
            
            # Generate a packet
            packet = self.generate_packet()
            packets.append(packet)
        
        # Reset current time
        self.current_time = datetime.datetime.now()
        
        return packets
    
    def export_pcap(self, filename, packet_count=100):
        """Export a batch of generated packets to a PCAP file for analysis"""
        try:
            from scapy.utils import wrpcap
            
            # Generate packets
            packets = []
            for _ in range(packet_count):
                p_dict = self.generate_packet()
                
                # Convert dictionary to scapy packet
                if p_dict['proto'] == 'tcp':
                    layer4 = TCP(
                        sport=p_dict['sport'], 
                        dport=p_dict['dport'],
                        flags=p_dict['flags']
                    )
                elif p_dict['proto'] == 'udp':
                    layer4 = UDP(
                        sport=p_dict['sport'], 
                        dport=p_dict['dport']
                    )
                elif p_dict['proto'] == 'icmp':
                    layer4 = ICMP(
                        type=p_dict.get('icmp_type', 8),
                        code=p_dict.get('icmp_code', 0)
                    )
                else:
                    continue  # Skip unsupported protocols
                    
                # Create the packet
                scapy_packet = IP(src=p_dict['src'], dst=p_dict['dst'])/layer4
                
                # Add payload if present
                if 'payload' in p_dict and p_dict['payload']:
                    scapy_packet = scapy_packet/Raw(load=p_dict['payload'])
                    
                packets.append(scapy_packet)
            
            # Write packets to PCAP file
            wrpcap(filename, packets)
            print(f"Exported {len(packets)} packets to {filename}")
            return True
            
        except Exception as e:
            print(f"Error exporting PCAP: {str(e)}")
            return False
            
    def reset_statistics(self):
        """Reset all traffic statistics"""
        self.stats = {
            'packets_total': 0,
            'packets_tcp': 0,
            'packets_udp': 0,
            'packets_icmp': 0,
            'packets_other': 0,
            'bytes_total': 0,
            'malicious_packets': 0,
            'benign_packets': 0,
            'internal_to_internal': 0,
            'internal_to_external': 0,
            'external_to_internal': 0,
            'external_to_external': 0
        }
        
    def start_pcap_capture(self, interface, filter_str=None):
        """
        Start capturing packets from a network interface
        Note: This requires appropriate permissions
        """
        if not self.capture_interface:
            self.capture_interface = interface
            
        # This functionality would need to be implemented with scapy's sniff function
        # but is not included here as it requires special permissions
        print(f"Packet capture on {interface} is not implemented in this simulator")
        return False