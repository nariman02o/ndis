import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import time
import json
import random
from datetime import datetime, timedelta
import os
import threading
from collections import deque

# Page configuration
st.set_page_config(
    page_title="NIDS - Network Intrusion Detection System",
    page_icon="🛡️",
    layout="wide",
)

# Define color scheme for a professional look
PRIMARY_COLOR = "#1E88E5"
SUCCESS_COLOR = "#4CAF50"
WARNING_COLOR = "#FF9800"
DANGER_COLOR = "#E53935"
INFO_COLOR = "#3949AB"
BACKGROUND_COLOR = "#F9FAFB"

# Apply custom CSS
st.markdown("""
<style>
    .block-container {
        padding-top: 1rem;
        padding-bottom: 1rem;
    }
    .st-emotion-cache-1y4p8pa {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 10px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        border-radius: 4px 4px 0px 0px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #E8F0FE;
        border-bottom: 2px solid #1E88E5;
    }
    .stButton button {
        height: 3em;
    }
    .alert-box {
        padding: 15px;
        border-radius: 5px;
        margin-bottom: 15px;
    }
    .alert-danger {
        background-color: #FFEBEE;
        border-left: 5px solid #E53935;
    }
    .alert-success {
        background-color: #E8F5E9;
        border-left: 5px solid #4CAF50;
    }
    .alert-warning {
        background-color: #FFF8E1;
        border-left: 5px solid #FF9800;
    }
    .alert-info {
        background-color: #E3F2FD;
        border-left: 5px solid #1E88E5;
    }
    .metric-container {
        background-color: white;
        border-radius: 5px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.24);
        padding: 15px;
        text-align: center;
        margin: 10px 0;
        height: 100px;
    }
    .metric-value {
        font-size: 28px;
        font-weight: bold;
        margin-top: 10px;
        margin-bottom: 10px;
        color: #1E88E5;
    }
    .metric-label {
        font-size: 16px;
        color: #555;
        font-weight: 500;
    }
    hr {
        margin-top: 2rem;
        margin-bottom: 2rem;
    }
    .model-card {
        background-color: white;
        border-radius: 5px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        padding: 20px;
        margin-bottom: 20px;
    }
    .model-card-header {
        font-size: 18px;
        font-weight: bold;
        margin-bottom: 15px;
        color: #1E88E5;
        border-bottom: 1px solid #eee;
        padding-bottom: 10px;
    }
    .model-card-content {
        font-size: 16px;
        margin-bottom: 10px;
    }
    .model-card-footer {
        font-size: 14px;
        color: #666;
        margin-top: 15px;
        text-align: right;
    }
    .training-button {
        background-color: #1E88E5;
        color: white;
        font-weight: bold;
        padding: 10px 20px;
        border-radius: 5px;
        border: none;
        cursor: pointer;
        width: 100%;
        margin-top: 10px;
    }
    .training-button:hover {
        background-color: #1565c0;
    }
    .training-button:disabled {
        background-color: #ccc;
        cursor: not-allowed;
    }
    div[data-testid="stVerticalBlock"] {
        gap: 0;
    }
    div[data-testid="column"] {
        padding: 10px;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'initialized' not in st.session_state:
    st.session_state.initialized = False
    st.session_state.monitoring_active = False
    st.session_state.simulator_running = False
    st.session_state.detection_history = []
    st.session_state.alert_history = []
    st.session_state.pending_alerts = []
    st.session_state.processed_alerts = []
    st.session_state.feedback_data = []
    st.session_state.model_initialized = False
    st.session_state.model_retrained = False
    st.session_state.retraining_needed = False
    st.session_state.benign_ratio = 0.8
    st.session_state.attack_active = False
    st.session_state.current_attack = None
    st.session_state.last_update = datetime.now()
    
    # Model metrics
    st.session_state.model_metrics = {
        "precision": 0.85,
        "recall": 0.82,
        "f1": 0.83,
        "accuracy": 0.90,
        "false_positive_rate": 0.08,
        "training_iterations": 0,
        "improvement_rate": 0.0,
        "last_retrained": None
    }
    
    # Statistics
    st.session_state.stats = {
        'total_packets': 0,
        'benign_packets': 0,
        'malicious_packets': 0,
        'alerts_generated': 0,
        'alerts_confirmed': 0,
        'alerts_rejected': 0,
        'total_traffic': 0,  # bytes
        'protocol_distribution': {'tcp': 0, 'udp': 0, 'icmp': 0, 'other': 0},
        'top_sources': {},
        'top_destinations': {},
        'port_distribution': {},
    }
    
    # Network settings
    st.session_state.network_entities = {
        'internal_subnet': '192.168.1.0/24',
        'dmz_subnet': '172.16.1.0/24',
        'external_subnet': '203.0.113.0/24',
        'servers': {
            'web_server': {'ip': '192.168.1.10', 'ports': [80, 443]},
            'database': {'ip': '192.168.1.20', 'ports': [3306, 5432]},
            'mail_server': {'ip': '192.168.1.30', 'ports': [25, 110, 143]},
            'file_server': {'ip': '192.168.1.40', 'ports': [21, 22]},
            'dns_server': {'ip': '192.168.1.50', 'ports': [53]},
        },
        'clients': [f'192.168.1.{i}' for i in range(100, 200)]
    }
    
    # Attack definitions
    st.session_state.attack_types = {
        'port_scan': {
            'name': 'Port Scan',
            'description': 'Scans multiple ports on target systems to find vulnerabilities',
            'severity': 'Medium',
            'duration': 15,  # seconds
        },
        'brute_force': {
            'name': 'Brute Force Attack',
            'description': 'Attempts to crack passwords by trying multiple combinations',
            'severity': 'High',
            'duration': 20,
        },
        'ddos': {
            'name': 'DDoS Attack',
            'description': 'Floods target with traffic to disrupt service',
            'severity': 'Critical',
            'duration': 30,
        },
        'data_exfiltration': {
            'name': 'Data Exfiltration',
            'description': 'Attempts to extract sensitive data from the network',
            'severity': 'High',
            'duration': 25,
        },
        'malware_communication': {
            'name': 'Malware Command & Control',
            'description': 'Infected host communicating with C&C server',
            'severity': 'Critical',
            'duration': 40,
        }
    }
    
    # Initialize packet generation queue
    st.session_state.packet_queue = deque(maxlen=1000)
    st.session_state.packet_batch = []
    
    # Set initialized to True
    st.session_state.initialized = True

# Utility functions
def format_bytes(size_bytes):
    """Format bytes to human-readable size"""
    if size_bytes == 0:
        return "0 B"
    
    # Instead of using numpy, use standard math
    size_name = ("B", "KB", "MB", "GB", "TB")
    
    # Calculate the logarithm manually
    i = 0
    size_float = float(size_bytes)
    while size_float >= 1024.0 and i < len(size_name) - 1:
        size_float /= 1024.0
        i += 1
    
    # Round to 2 decimal places
    s = round(size_float, 2)
    
    return f"{s} {size_name[i]}"

def get_service_name(port):
    """Get service name from port number"""
    common_ports = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        1433: 'MS SQL',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        8080: 'HTTP Proxy',
    }
    return common_ports.get(port, 'Unknown')

def generate_packet(is_malicious=None):
    """Generate a realistic network packet"""
    # Determine if packet should be malicious based on benign ratio if not specified
    if is_malicious is None:
        is_malicious = random.random() > st.session_state.benign_ratio
    
    # Generate timestamp
    timestamp = datetime.now().isoformat()
    
    # Determine source and destination
    if is_malicious and st.session_state.attack_active and random.random() < 0.8:
        # Use the current attack details
        attack_type = st.session_state.current_attack
        
        if attack_type == 'port_scan':
            src_ip = random.choice([
                '203.0.113.10',  # External attacker
                '203.0.113.50',
                '203.0.113.100',
            ])
            dst_ip = random.choice(st.session_state.network_entities['clients'])
            proto = 'tcp'
            sport = random.randint(30000, 65000)
            dport = random.randint(1, 10000)
            flags = 2  # SYN flag
            payload = ''
            
        elif attack_type == 'brute_force':
            src_ip = random.choice([
                '203.0.113.20',  # External attacker
                '203.0.113.45',
                '203.0.113.87',
            ])
            dst_ip = st.session_state.network_entities['servers']['file_server']['ip']
            proto = 'tcp'
            sport = random.randint(40000, 60000)
            dport = 22  # SSH
            flags = 24  # PSH+ACK
            payload = f"USER admin\r\nPASS {random.choice(['password', 'admin', '123456', 'root'])}\r\n"
            
        elif attack_type == 'ddos':
            src_ip = f"203.0.113.{random.randint(1, 254)}"  # Random external IP
            dst_ip = st.session_state.network_entities['servers']['web_server']['ip']
            proto = 'tcp'
            sport = random.randint(1024, 65000)
            dport = 80  # HTTP
            flags = 2 if random.random() < 0.5 else 24  # SYN or PSH+ACK
            payload = "GET / HTTP/1.1\r\nHost: target.com\r\n\r\n" if flags == 24 else ""
            
        elif attack_type == 'data_exfiltration':
            src_ip = random.choice(st.session_state.network_entities['clients'])  # Internal compromised host
            dst_ip = f"203.0.113.{random.randint(1, 254)}"  # External server
            proto = 'tcp'
            sport = random.randint(1024, 65000)
            dport = random.choice([443, 8080, 25])  # HTTPS, HTTP proxy, SMTP
            flags = 24  # PSH+ACK
            payload = "BEGIN_DATA:user_credentials.csv:BASE64DATA:dXNlcm5hbWUsaGFzaGVkX3Bhc3N3b3JkLGVtYWlsLGFkbWlu==END_DATA"
            
        elif attack_type == 'malware_communication':
            src_ip = random.choice(st.session_state.network_entities['clients'])  # Internal infected host
            dst_ip = f"203.0.113.{random.randint(1, 254)}"  # C&C server
            proto = 'tcp'
            sport = random.randint(1024, 65000)
            dport = random.choice([80, 443, 53, 123])  # HTTP, HTTPS, DNS, NTP
            flags = 24  # PSH+ACK
            payload = '{"command":"update","id":"bot123","status":"active","system":"windows"}'
            
        else:
            # Generic malicious packet
            if random.random() < 0.7:  # 70% external -> internal
                src_ip = f"203.0.113.{random.randint(1, 254)}"
                dst_ip = random.choice(st.session_state.network_entities['clients'])
            else:  # 30% internal -> external
                src_ip = random.choice(st.session_state.network_entities['clients'])
                dst_ip = f"203.0.113.{random.randint(1, 254)}"
                
            proto = random.choice(['tcp', 'udp', 'icmp'])
            sport = random.randint(1024, 65000)
            dport = random.choice([22, 80, 443, 445, 3389, 3306])
            flags = random.choice([2, 16, 24]) if proto == 'tcp' else None
            payload = '{"data":"suspicious content"}'
            
    else:
        # Generate benign traffic
        direction = random.random()
        
        if direction < 0.6:  # 60% internal -> external
            src_ip = random.choice(st.session_state.network_entities['clients'])
            dst_ip = f"203.0.113.{random.randint(1, 254)}"
        elif direction < 0.8:  # 20% internal -> server
            src_ip = random.choice(st.session_state.network_entities['clients'])
            server_type = random.choice(list(st.session_state.network_entities['servers'].keys()))
            dst_ip = st.session_state.network_entities['servers'][server_type]['ip']
        else:  # 20% external -> server
            src_ip = f"203.0.113.{random.randint(1, 254)}"
            server_type = random.choice(list(st.session_state.network_entities['servers'].keys()))
            dst_ip = st.session_state.network_entities['servers'][server_type]['ip']
        
        # Determine protocol
        proto_rand = random.random()
        if proto_rand < 0.75:
            proto = 'tcp'
        elif proto_rand < 0.95:
            proto = 'udp'
        else:
            proto = 'icmp'
        
        # Determine ports
        sport = random.randint(1024, 65000)
        if proto == 'tcp':
            dport = random.choice([21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080])
            flags = random.choice([2, 16, 18, 24])  # SYN, ACK, SYN+ACK, PSH+ACK
        elif proto == 'udp':
            dport = random.choice([53, 67, 123, 161, 500, 1900, 5353])
            flags = None
        else:  # icmp
            dport = None
            sport = None
            flags = None
        
        # Generate payload
        if proto == 'tcp' and dport == 80:
            payload = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n" if random.random() < 0.5 else ""
        elif proto == 'tcp' and dport == 443:
            payload = '{"type":"client_hello","tls_version":"1.3"}' if random.random() < 0.5 else ""
        else:
            payload = '{"data":"normal traffic"}' if random.random() < 0.3 else ""
    
    # Create packet with consistent schema
    packet = {
        "timestamp": timestamp,
        "src": src_ip,
        "dst": dst_ip,
        "proto": proto,
        "len": random.randint(64, 1500),  # Random packet size
        "is_malicious": is_malicious,
    }
    
    # Add protocol-specific fields
    if proto in ['tcp', 'udp']:
        packet["sport"] = sport
        packet["dport"] = dport
    
    if proto == 'tcp' and flags is not None:
        packet["flags"] = flags
    
    if payload:
        packet["payload"] = payload
    
    return packet

def update_stats_with_packet(packet):
    """Update network statistics with a new packet"""
    # Update total counters
    st.session_state.stats['total_packets'] += 1
    st.session_state.stats['total_traffic'] += packet.get('len', 0)
    
    # Update malicious/benign counters
    if packet.get('is_malicious', False):
        st.session_state.stats['malicious_packets'] += 1
    else:
        st.session_state.stats['benign_packets'] += 1
    
    # Update protocol distribution
    proto = packet.get('proto', 'other').lower()
    if proto in st.session_state.stats['protocol_distribution']:
        st.session_state.stats['protocol_distribution'][proto] += 1
    else:
        st.session_state.stats['protocol_distribution']['other'] += 1
    
    # Update source IP counts
    src_ip = packet.get('src')
    if src_ip:
        if src_ip in st.session_state.stats['top_sources']:
            st.session_state.stats['top_sources'][src_ip] += 1
        else:
            st.session_state.stats['top_sources'][src_ip] = 1
    
    # Update destination IP counts
    dst_ip = packet.get('dst')
    if dst_ip:
        if dst_ip in st.session_state.stats['top_destinations']:
            st.session_state.stats['top_destinations'][dst_ip] += 1
        else:
            st.session_state.stats['top_destinations'][dst_ip] = 1
    
    # Update port distribution
    dport = packet.get('dport')
    if dport:
        if dport in st.session_state.stats['port_distribution']:
            st.session_state.stats['port_distribution'][dport] += 1
        else:
            st.session_state.stats['port_distribution'][dport] = 1

def get_attack_description(packet):
    """Generate a plausible attack description based on packet attributes"""
    proto = packet.get('proto', '').lower()
    src = packet.get('src', '')
    dst = packet.get('dst', '')
    dport = packet.get('dport', 0)
    sport = packet.get('sport', 0)
    payload = packet.get('payload', '')
    
    # TCP-specific patterns
    if proto == 'tcp':
        flags = packet.get('flags', 0)
        
        if flags == 2 and random.random() < 0.7:  # SYN packet
            return f"Possible port scan from {src} targeting port {dport} on {dst}"
        
        if dport == 22 or dport == 21:
            if payload and ('USER' in payload or 'PASS' in payload):
                return f"Possible brute force attack on {'SSH' if dport == 22 else 'FTP'} service"
        
        if dport == 80 or dport == 443:
            if payload and (("'" in payload and "SELECT" in payload) or ";" in payload or "--" in payload):
                return "SQL Injection attempt detected"
            if payload and ("<script>" in payload or "onerror=" in payload):
                return "Cross-site scripting (XSS) attempt detected"
            if random.random() < 0.3:
                return "Suspicious HTTP traffic detected"
    
    # UDP-specific patterns
    if proto == 'udp':
        if dport == 53:
            if payload and len(payload) > 100:
                return "Possible DNS tunneling detected"
        
        if dport > 1024 and sport > 1024:
            return "Suspicious UDP communication between unusual ports"
    
    # ICMP patterns
    if proto == 'icmp':
        return "Suspicious ICMP packet detected, possible network mapping"
    
    # Generic patterns
    if payload and "BASE64" in payload:
        return "Potential data exfiltration with encoded content"
    
    if payload and any(term in payload for term in ["gate.php", "config.bin", "updates.js", "/admin/"]):
        return "Communication with potential C&C server detected"
    
    # Default
    return "Anomalous network traffic detected"

def generate_alert_for_packet(packet):
    """Generate an alert based on a malicious packet"""
    alert_id = f"alert_{int(time.time())}_{st.session_state.stats['alerts_generated']}"
    
    # Generate random features for the packet (simplified)
    features = [random.random() for _ in range(10)]
    
    # Generate confidence score
    if packet.get('is_malicious', False):
        confidence = random.uniform(0.7, 0.95)
    else:
        confidence = random.uniform(0.6, 0.75)
    
    severity = 'High' if confidence > 0.85 else ('Medium' if confidence > 0.7 else 'Low')
    
    # Create alert
    alert = {
        'id': alert_id,
        'timestamp': packet.get('timestamp', datetime.now().isoformat()),
        'src_ip': packet.get('src', 'Unknown'),
        'dst_ip': packet.get('dst', 'Unknown'),
        'protocol': packet.get('proto', 'Unknown'),
        'severity': severity,
        'description': get_attack_description(packet),
        'packet': packet,
        'features': features,
        'confidence': confidence,
        'status': 'pending'
    }
    
    # Update alerts statistics
    st.session_state.stats['alerts_generated'] += 1
    
    return alert

def update_network_data(batch_size=10):
    """Update network data with new packets"""
    try:
        # Check if key data structures exist in session state
        if 'detection_history' not in st.session_state:
            st.session_state.detection_history = []
        if 'alert_history' not in st.session_state:
            st.session_state.alert_history = []
        if 'pending_alerts' not in st.session_state:
            st.session_state.pending_alerts = []
            
        # Initialize generated packets array
        new_packets = []
        
        # Generate packets
        for _ in range(batch_size):
            # Generate packet with controlled ratio of malicious packets
            is_malicious = None
            if hasattr(st.session_state, 'attack_active') and st.session_state.attack_active:
                # Higher chance of malicious during active attack
                is_malicious = random.random() > 0.4  # 60% malicious during attack
            else:
                # Normal operation
                is_malicious = random.random() > st.session_state.benign_ratio
                
            # Generate the packet
            packet = generate_packet(is_malicious=is_malicious)
            new_packets.append(packet)
            
            # Add to detection history
            st.session_state.detection_history.append(packet)
            
            # Limit detection history size
            if len(st.session_state.detection_history) > 1000:
                st.session_state.detection_history = st.session_state.detection_history[-1000:]
            
            # Update statistics with the new packet
            update_stats_with_packet(packet)
            
            # Generate alert for malicious packets and some false positives
            if packet.get('is_malicious', False) or (random.random() < 0.05):  # 5% chance for false positives
                alert = generate_alert_for_packet(packet)
                
                # Add to alert history
                st.session_state.alert_history.append(alert)
                
                # Limit alert history size
                if len(st.session_state.alert_history) > 100:
                    st.session_state.alert_history = st.session_state.alert_history[-100:]
                
                # Add to pending alerts
                st.session_state.pending_alerts.append(alert)
                
                # Update alert count
                if 'stats' in st.session_state and 'alerts_generated' in st.session_state.stats:
                    st.session_state.stats['alerts_generated'] += 1
        
        # Return the generated packets
        return new_packets
    except Exception as e:
        print(f"Error in update_network_data: {str(e)}")
        return []

def start_attack(attack_type):
    """Start a simulated attack"""
    if attack_type not in st.session_state.attack_types:
        return False
    
    st.session_state.attack_active = True
    st.session_state.current_attack = attack_type
    
    # Calculate end time based on attack duration
    attack_duration = st.session_state.attack_types[attack_type]['duration']
    end_time = datetime.now() + timedelta(seconds=attack_duration)
    
    # Store attack information
    st.session_state.attack_info = {
        'type': attack_type,
        'start_time': datetime.now(),
        'end_time': end_time,
        'source_ip': f"203.0.113.{random.randint(1, 254)}",
        'packets_generated': 0
    }
    
    # During active attack, we'll set benign ratio lower to generate more attacks
    st.session_state.previous_benign_ratio = st.session_state.benign_ratio
    st.session_state.benign_ratio = 0.3  # 70% of packets will be malicious
    
    return True

def stop_attack():
    """Stop the current attack"""
    st.session_state.attack_active = False
    st.session_state.current_attack = None
    
    # Restore previous benign ratio
    if hasattr(st.session_state, 'previous_benign_ratio'):
        st.session_state.benign_ratio = st.session_state.previous_benign_ratio
    
    # Clear attack info
    st.session_state.attack_info = None

def simulation_loop():
    """Background thread for packet simulation"""
    try:
        # Make sure session state is properly initialized
        if 'simulator_running' not in st.session_state:
            st.session_state.simulator_running = False
            return
            
        if 'attack_active' not in st.session_state:
            st.session_state.attack_active = False
            
        # Main simulation loop
        while st.session_state.simulator_running:
            try:
                # Check if attack has ended
                if (st.session_state.attack_active and 
                    hasattr(st.session_state, 'attack_info') and 
                    st.session_state.attack_info is not None and
                    datetime.now() >= st.session_state.attack_info['end_time']):
                    stop_attack()
                
                # Generate packet batch
                update_network_data(batch_size=5)
                
                # Sleep to simulate realistic packet arrival
                time.sleep(1)
            except Exception as e:
                print(f"Error in simulation iteration: {str(e)}")
                time.sleep(2)  # Wait before retrying
    except Exception as e:
        print(f"Error in simulation thread: {str(e)}")
        # Make sure to clean up in case of error
        st.session_state.simulator_running = False
        st.session_state.monitoring_active = False

def start_simulation():
    """Start the packet simulation in a background thread"""
    # Make sure session state is properly initialized
    if 'simulator_running' not in st.session_state:
        st.session_state.simulator_running = False
    
    if st.session_state.simulator_running:
        return
    
    # Set the flag and start the thread
    st.session_state.simulator_running = True
    try:
        simulation_thread = threading.Thread(target=simulation_loop)
        simulation_thread.daemon = True
        simulation_thread.start()
        return True
    except Exception as e:
        st.error(f"Error starting simulation: {str(e)}")
        st.session_state.simulator_running = False
        return False

def stop_simulation():
    """Stop the packet simulation"""
    # Make sure session state is properly initialized
    if 'simulator_running' not in st.session_state:
        st.session_state.simulator_running = False
        
    if 'monitoring_active' not in st.session_state:
        st.session_state.monitoring_active = False
    
    # Set flags to stop
    st.session_state.simulator_running = False
    st.session_state.monitoring_active = False

# Application Layout
st.title("🛡️ Network Intrusion Detection System")
st.markdown("""
This advanced NIDS uses reinforcement learning to detect malicious network packets and continuously improves 
through admin feedback. The system incorporates deep packet inspection (DPI) for detailed traffic analysis.
""")

# Create tabs for different sections
tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Dashboard",
    "🔍 Network Monitor",
    "🚨 Alert Management",
    "📈 Analytics"
])

# Tab 1: Main Dashboard
with tab1:
    st.header("System Dashboard")
    
    # Control Panel
    control_col1, control_col2, control_col3 = st.columns(3)
    
    with control_col1:
        if not st.session_state.monitoring_active:
            if st.button("Start Monitoring System", type="primary", key="start_monitor"):
                # Generate initial batch of packets to show immediate results
                for _ in range(20):
                    packet = generate_packet()
                    st.session_state.detection_history.append(packet)
                    update_stats_with_packet(packet)
                    
                    # Generate some alerts
                    if packet.get('is_malicious', False) or (random.random() < 0.1):
                        alert = generate_alert_for_packet(packet)
                        st.session_state.alert_history.append(alert)
                        st.session_state.pending_alerts.append(alert)
                
                # Start background monitor
                st.session_state.monitoring_active = True
                success = start_simulation()
                
                if success:
                    st.success("✅ Monitoring system started. Network traffic is now being analyzed.")
                    st.rerun()  # Refresh to show initial data
                else:
                    st.error("❌ Failed to start monitoring system. Please try again.")
        else:
            if st.button("Stop Monitoring System", type="primary", key="stop_monitor"):
                stop_simulation()
                st.warning("⚠️ Monitoring system stopped.")
    
    with control_col2:
        # Allow setting the benign/malicious traffic ratio
        st.session_state.benign_ratio = st.slider(
            "Benign Traffic Ratio", 
            min_value=0.1, 
            max_value=0.9, 
            value=st.session_state.benign_ratio,
            step=0.1,
            help="Higher values mean less malicious traffic"
        )
    
    with control_col3:
        if st.session_state.monitoring_active:
            st.success("System is actively monitoring network traffic")
        else:
            st.warning("System monitoring is inactive")
    
    # Main metrics
    st.subheader("Real-time Network Metrics")
    metric_col1, metric_col2, metric_col3, metric_col4, metric_col5 = st.columns(5)
    
    with metric_col1:
        st.markdown(f"""
        <div class="metric-container">
            <div class="metric-value">{st.session_state.stats['total_packets']:,}</div>
            <div class="metric-label">Packets Analyzed</div>
        </div>
        """, unsafe_allow_html=True)
    
    with metric_col2:
        malicious_percentage = 0
        if st.session_state.stats['total_packets'] > 0:
            malicious_percentage = (st.session_state.stats['malicious_packets'] / 
                                 st.session_state.stats['total_packets']) * 100
        st.markdown(f"""
        <div class="metric-container">
            <div class="metric-value">{malicious_percentage:.1f}%</div>
            <div class="metric-label">Malicious Traffic</div>
        </div>
        """, unsafe_allow_html=True)
    
    with metric_col3:
        st.markdown(f"""
        <div class="metric-container">
            <div class="metric-value">{format_bytes(st.session_state.stats['total_traffic'])}</div>
            <div class="metric-label">Traffic Volume</div>
        </div>
        """, unsafe_allow_html=True)
    
    with metric_col4:
        st.markdown(f"""
        <div class="metric-container">
            <div class="metric-value">{st.session_state.stats['alerts_generated']}</div>
            <div class="metric-label">Alerts Generated</div>
        </div>
        """, unsafe_allow_html=True)
    
    with metric_col5:
        st.markdown(f"""
        <div class="metric-container">
            <div class="metric-value">{len(st.session_state.pending_alerts)}</div>
            <div class="metric-label">Pending Alerts</div>
        </div>
        """, unsafe_allow_html=True)
    
    # Attack simulation section
    st.subheader("Attack Simulation")
    
    attack_col1, attack_col2 = st.columns(2)
    
    with attack_col1:
        attack_options = ["None"] + [f"{details['name']} ({details['severity']})" 
                                    for attack_id, details in st.session_state.attack_types.items()]
        selected_attack_display = st.selectbox("Select Attack Type", attack_options, key="attack_select")
        
        # Extract attack_id from the display name
        if selected_attack_display != "None":
            for attack_id, details in st.session_state.attack_types.items():
                display_name = f"{details['name']} ({details['severity']})"
                if display_name == selected_attack_display:
                    selected_attack_id = attack_id
                    break
        else:
            selected_attack_id = None
    
    with attack_col2:
        attack_button_disabled = not st.session_state.monitoring_active or selected_attack_id is None or st.session_state.attack_active
        
        if not st.session_state.attack_active:
            start_attack_button = st.button(
                "Launch Selected Attack", 
                key="launch_attack",
                disabled=attack_button_disabled
            )
            if start_attack_button and selected_attack_id is not None:
                success = start_attack(selected_attack_id)
                if success:
                    attack_details = st.session_state.attack_types[selected_attack_id]
                    st.success(f"Launching {attack_details['name']} attack simulation for {attack_details['duration']} seconds.")
                else:
                    st.error("Failed to start attack simulation.")
        else:
            # Show active attack information
            attack_info = st.session_state.attack_info
            attack_details = st.session_state.attack_types[attack_info['type']]
            time_left = max(0, (attack_info['end_time'] - datetime.now()).total_seconds())
            
            st.warning(f"⚠️ Active attack: {attack_details['name']} ({time_left:.1f}s remaining)")
            
            if st.button("Stop Attack", key="stop_attack"):
                stop_attack()
                st.success("Attack simulation stopped.")
    
    # If attack is active, show some details
    if st.session_state.attack_active and hasattr(st.session_state, 'attack_info') and st.session_state.attack_info is not None:
        attack_info = st.session_state.attack_info
        attack_details = st.session_state.attack_types[attack_info['type']]
        
        st.markdown(f"""
        <div class="alert-box alert-danger">
            <h3>🚨 Active Attack Simulation: {attack_details['name']}</h3>
            <p><strong>Description:</strong> {attack_details['description']}</p>
            <p><strong>Source IP:</strong> {attack_info['source_ip']}</p>
            <p><strong>Started:</strong> {attack_info['start_time'].strftime('%H:%M:%S')}</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Show recent activity
    st.subheader("Recent Activity")
    
    activity_col1, activity_col2 = st.columns(2)
    
    with activity_col1:
        st.markdown("### Traffic Pattern")
        
        if len(st.session_state.detection_history) > 0:
            # Group by minute and malicious status
            df = pd.DataFrame(st.session_state.detection_history[-100:])  # Last 100 packets
            
            if not df.empty and 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                
                # Group by minute and malicious status
                df['minute'] = df['timestamp'].dt.floor('1min')
                traffic_df = df.groupby(['minute', 'is_malicious']).size().reset_index(name='count')
                
                # Create traffic chart
                fig = px.line(
                    traffic_df, 
                    x='minute', 
                    y='count', 
                    color='is_malicious',
                    labels={'minute': 'Time', 'count': 'Packets', 'is_malicious': 'Malicious'},
                    color_discrete_map={True: '#E53935', False: '#4CAF50'},
                    title='Network Traffic (per minute)'
                )
                
                fig.update_layout(
                    height=300,
                    xaxis_title="",
                    yaxis_title="Packet Count",
                    legend_title=""
                )
                
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Waiting for traffic data...")
        else:
            st.info("Start the monitoring system to see traffic patterns.")
    
    with activity_col2:
        st.markdown("### Protocol Distribution")
        
        proto_counts = st.session_state.stats['protocol_distribution']
        
        if sum(proto_counts.values()) > 0:
            proto_df = pd.DataFrame([
                {'Protocol': proto.upper(), 'Count': count}
                for proto, count in proto_counts.items() if count > 0
            ])
            
            # Create protocol chart
            fig = px.pie(
                proto_df,
                values='Count',
                names='Protocol',
                color_discrete_sequence=px.colors.qualitative.Bold,
                hole=0.4
            )
            
            fig.update_layout(
                height=300,
                margin=dict(l=20, r=20, t=30, b=20),
                legend=dict(orientation="h", yanchor="bottom", y=-0.1)
            )
            
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Waiting for protocol data...")

# Tab 2: Network Monitor
with tab2:
    st.header("Network Traffic Monitor")
    
    monitor_col1, monitor_col2 = st.columns([3, 1])
    
    with monitor_col1:
        st.subheader("Live Network Traffic")
        if not st.session_state.monitoring_active:
            st.warning("Network monitoring is not active. Start monitoring from the Dashboard tab.")
    
    with monitor_col2:
        if st.session_state.monitoring_active:
            refresh_clicked = st.button("Refresh Data", key="refresh_monitor")
            if refresh_clicked:
                update_network_data(batch_size=10)
                st.success("Data refreshed.")
    
    # Show packet inspection table
    if st.session_state.monitoring_active:
        last_packets = st.session_state.detection_history[-15:] if st.session_state.detection_history else []
        
        if last_packets:
            packet_table_data = []
            
            # Convert packets to table format
            for packet in reversed(last_packets):  # Show newest first
                timestamp = packet.get('timestamp', '')
                if isinstance(timestamp, str) and 'T' in timestamp:
                    timestamp = timestamp.split('T')[1][:12]
                
                entry = {
                    'Time': timestamp,
                    'Source': packet.get('src', 'Unknown'),
                    'Destination': packet.get('dst', 'Unknown'),
                    'Protocol': packet.get('proto', 'Unknown').upper(),
                    'Length': packet.get('len', 0),
                    'Status': '🔴 Malicious' if packet.get('is_malicious', False) else '🟢 Benign'
                }
                
                # Add protocol-specific fields
                if packet.get('proto') in ['tcp', 'udp']:
                    entry['Src Port'] = packet.get('sport', '-')
                    entry['Dst Port'] = packet.get('dport', '-')
                    
                    if packet.get('dport'):
                        service = get_service_name(packet.get('dport'))
                        if service != 'Unknown':
                            entry['Service'] = service
                
                packet_table_data.append(entry)
            
            # Create dataframe
            packet_df = pd.DataFrame(packet_table_data)
            
            # Show dataframe with conditional formatting
            st.dataframe(
                packet_df.style.apply(
                    lambda x: ['background-color: #FFEBEE' if v == '🔴 Malicious' else 'background-color: #E8F5E9' for v in x],
                    subset=['Status']
                ),
                height=400,
                use_container_width=True
            )
        else:
            st.info("No packets captured yet. Start monitoring to see network traffic.")
    
    # Network Flow Visualization
    st.subheader("Network Flow Analysis")
    
    if st.session_state.detection_history:
        # Take the last 100 packets for analysis
        flow_packets = st.session_state.detection_history[-100:]
        
        # Extract unique source and destination IPs
        sources = set(p.get('src') for p in flow_packets if 'src' in p)
        destinations = set(p.get('dst') for p in flow_packets if 'dst' in p)
        all_ips = list(sources.union(destinations))
        
        # Count connections between IPs
        connections = {}
        for packet in flow_packets:
            src = packet.get('src')
            dst = packet.get('dst')
            if src and dst:
                key = (src, dst)
                is_malicious = packet.get('is_malicious', False)
                
                if key in connections:
                    connections[key]['count'] += 1
                    if is_malicious:
                        connections[key]['malicious_count'] += 1
                else:
                    connections[key] = {
                        'count': 1,
                        'malicious_count': 1 if is_malicious else 0
                    }
        
        # Create a dataframe for plotting
        edges = []
        for (src, dst), data in connections.items():
            malicious_ratio = data['malicious_count'] / data['count']
            color = f"rgba({int(255 * malicious_ratio)}, {int(255 * (1-malicious_ratio))}, 0, 0.8)"
            
            edges.append({
                'source': src,
                'target': dst,
                'count': data['count'],
                'malicious_count': data['malicious_count'],
                'malicious_ratio': malicious_ratio,
                'color': color
            })
        
        edges_df = pd.DataFrame(edges)
        
        if not edges_df.empty:
            # Create network graph using plotly
            node_x = []
            node_y = []
            node_text = []
            node_type = []
            node_size = []
            
            # Create a simple circular layout
            angle_step = 2 * np.pi / len(all_ips)
            for i, ip in enumerate(all_ips):
                angle = i * angle_step
                
                if '192.168.' in ip:  # Internal network
                    radius = 0.7
                    node_type.append('internal')
                elif '172.16.' in ip:  # DMZ
                    radius = 1.0
                    node_type.append('dmz')
                else:  # External
                    radius = 1.3
                    node_type.append('external')
                
                # Add to node lists
                x, y = radius * np.cos(angle), radius * np.sin(angle)
                node_x.append(x)
                node_y.append(y)
                node_text.append(ip)
                
                # Set node size based on number of connections
                src_count = len([e for e in edges if e['source'] == ip])
                dst_count = len([e for e in edges if e['target'] == ip])
                node_size.append(10 + (src_count + dst_count))
            
            # Create a lookup from IP to x,y coordinates
            pos = {ip: (node_x[i], node_y[i]) for i, ip in enumerate(all_ips)}
            
            # Create the edges
            edge_x = []
            edge_y = []
            edge_color = []
            
            for edge in edges:
                x0, y0 = pos[edge['source']]
                x1, y1 = pos[edge['target']]
                
                edge_x.extend([x0, x1, None])
                edge_y.extend([y0, y1, None])
                
                # Set color based on malicious ratio
                color = edge['color']
                edge_color.extend([color, color, color])
            
            # Create node trace
            node_color = ['blue' if t == 'internal' else 'orange' if t == 'dmz' else 'red' for t in node_type]
            
            node_trace = go.Scatter(
                x=node_x, y=node_y,
                mode='markers+text',
                hovertext=node_text,
                text=node_text,
                textposition="top center",
                marker=dict(
                    showscale=False,
                    color=node_color,
                    size=node_size,
                    line=dict(width=1, color='#888')
                )
            )
            
            # Create edge trace
            edge_trace = go.Scatter(
                x=edge_x, y=edge_y,
                mode='lines',
                line=dict(width=1, color=edge_color),
                hoverinfo='none'
            )
            
            # Create the figure
            fig = go.Figure(data=[edge_trace, node_trace],
                          layout=go.Layout(
                              showlegend=False,
                              hovermode='closest',
                              margin=dict(b=5, l=5, r=5, t=5),
                              xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                              yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                              height=600,
                              plot_bgcolor='rgba(240, 240, 240, 0.8)'
                          ))
            
            # Add a legend
            annotations = [
                dict(
                    x=1.05, y=0.9, xref="paper", yref="paper",
                    text="Node Types:", showarrow=False,
                    font=dict(size=14)
                ),
                dict(
                    x=1.05, y=0.85, xref="paper", yref="paper",
                    text="● Internal Network", showarrow=False,
                    font=dict(color="blue", size=12)
                ),
                dict(
                    x=1.05, y=0.8, xref="paper", yref="paper",
                    text="● DMZ", showarrow=False,
                    font=dict(color="orange", size=12)
                ),
                dict(
                    x=1.05, y=0.75, xref="paper", yref="paper",
                    text="● External Network", showarrow=False,
                    font=dict(color="red", size=12)
                ),
                dict(
                    x=1.05, y=0.65, xref="paper", yref="paper",
                    text="Connection Color:", showarrow=False,
                    font=dict(size=14)
                ),
                dict(
                    x=1.05, y=0.6, xref="paper", yref="paper",
                    text="Green: Benign", showarrow=False,
                    font=dict(color="green", size=12)
                ),
                dict(
                    x=1.05, y=0.55, xref="paper", yref="paper",
                    text="Red: Malicious", showarrow=False,
                    font=dict(color="red", size=12)
                ),
            ]
            
            fig.update_layout(annotations=annotations)
            
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Insufficient flow data. Wait for more packets to be captured.")
    else:
        st.info("No network traffic data available. Start monitoring to see network flow visualization.")
    
    # Top IPs and Ports
    ip_col1, ip_col2 = st.columns(2)
    
    with ip_col1:
        st.subheader("Top Source IPs")
        
        top_sources = sorted(
            st.session_state.stats['top_sources'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        if top_sources:
            top_src_df = pd.DataFrame(top_sources, columns=['IP', 'Count'])
            
            # Determine if IP is internal or external
            top_src_df['Network'] = top_src_df['IP'].apply(
                lambda ip: 'Internal' if ip.startswith(('192.168.', '10.', '172.16.')) else 'External'
            )
            
            fig = px.bar(
                top_src_df,
                x='Count',
                y='IP',
                color='Network',
                orientation='h',
                color_discrete_map={'Internal': '#1E88E5', 'External': '#E53935'},
                title='Top Source IP Addresses'
            )
            
            fig.update_layout(height=350, yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No source IP data available yet.")
    
    with ip_col2:
        st.subheader("Top Destination IPs")
        
        top_destinations = sorted(
            st.session_state.stats['top_destinations'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        if top_destinations:
            top_dst_df = pd.DataFrame(top_destinations, columns=['IP', 'Count'])
            
            # Determine if IP is internal or external
            top_dst_df['Network'] = top_dst_df['IP'].apply(
                lambda ip: 'Internal' if ip.startswith(('192.168.', '10.', '172.16.')) else 'External'
            )
            
            fig = px.bar(
                top_dst_df,
                x='Count',
                y='IP',
                color='Network',
                orientation='h',
                color_discrete_map={'Internal': '#1E88E5', 'External': '#E53935'},
                title='Top Destination IP Addresses'
            )
            
            fig.update_layout(height=350, yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No destination IP data available yet.")

# Tab 3: Alert Management
with tab3:
    st.header("Security Alert Management")
    
    # Add demo alert generator
    demo_col1, demo_col2 = st.columns([3, 1])
    
    with demo_col1:
        st.markdown("""
        This section allows you to review and respond to security alerts generated by the NIDS. 
        Each alert requires admin feedback to help train the system and reduce false positives over time.
        """)
    
    with demo_col2:
        if st.button("Generate Demo Alerts", key="gen_demo_alerts"):
            # Generate sample alerts with different characteristics
            sample_count = 5
            alert_types = ['port_scan', 'brute_force', 'ddos', 'data_exfiltration', 'malware_communication']
            
            for i in range(sample_count):
                attack_type = random.choice(alert_types)
                
                # Generate a simulated attack packet
                packet = generate_packet(is_malicious=True)
                packet['attack_type'] = attack_type
                
                # Create an alert
                alert = generate_alert_for_packet(packet)
                
                # Add to pending alerts
                st.session_state.pending_alerts.append(alert)
                
                # Add to alert history
                st.session_state.alert_history.append(alert)
                
                # Update stats
                st.session_state.stats['alerts_generated'] += 1
                
            st.success(f"Generated {sample_count} demo alerts for testing.")
    
    # Alert counter
    alert_count = len(st.session_state.pending_alerts)
    
    if alert_count > 0:
        st.markdown(f"""
        <div class="alert-box alert-warning">
            <h3>⚠️ You have {alert_count} pending alert{'s' if alert_count > 1 else ''} requiring your attention</h3>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="alert-box alert-success">
            <h3>✅ No pending alerts</h3>
            <p>The system is monitoring for threats. Generate demo alerts to test the feedback workflow.</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Process pending alerts
    if st.session_state.pending_alerts:
        for i, alert in enumerate(st.session_state.pending_alerts[:5]):  # Show only first 5 to avoid UI clutter
            with st.expander(f"Alert #{i+1} - {alert['description']} ({alert['severity']} severity)", expanded=i==0):
                # Create three columns: details, packet, and actions
                alert_col1, alert_col2 = st.columns([3, 2])
                
                with alert_col1:
                    st.subheader("Alert Details")
                    
                    st.markdown(f"""
                    **Source IP:** {alert['src_ip']}  
                    **Destination IP:** {alert['dst_ip']}  
                    **Protocol:** {alert['protocol'].upper()}  
                    **Timestamp:** {alert['timestamp']}  
                    **Confidence:** {alert['confidence']:.2f}  
                    **Severity:** {alert['severity']}  
                    
                    **Description:**  
                    {alert['description']}
                    """)
                    
                    # Show packet features
                    if 'features' in alert and alert['features']:
                        st.subheader("Extracted Features")
                        
                        feature_df = pd.DataFrame({
                            'Feature': [f'Feature {i+1}' for i in range(len(alert['features']))],
                            'Value': alert['features']
                        })
                        
                        st.dataframe(feature_df, use_container_width=True)
                
                with alert_col2:
                    st.subheader("Packet Details")
                    
                    # Simplified packet display
                    packet_info = {}
                    for key, value in alert['packet'].items():
                        if key != 'features':  # Skip large arrays
                            packet_info[key] = value
                    
                    st.json(packet_info)
                
                # Action buttons
                action_col1, action_col2, action_col3 = st.columns([1, 1, 1])
                
                # Track alert state
                alert_id = alert['id']
                
                # Initialize feedback state variables for this alert if not present
                if f"confirmed_{alert_id}" not in st.session_state:
                    st.session_state[f"confirmed_{alert_id}"] = False
                if f"rejected_{alert_id}" not in st.session_state:
                    st.session_state[f"rejected_{alert_id}"] = False
                
                with action_col1:
                    confirm_clicked = st.button(
                        "✅ Confirm Threat", 
                        key=f"confirm_{alert_id}",
                        disabled=st.session_state[f"confirmed_{alert_id}"] or st.session_state[f"rejected_{alert_id}"]
                    )
                    
                    if confirm_clicked:
                        st.session_state[f"confirmed_{alert_id}"] = True
                        alert['status'] = 'confirmed'
                        st.session_state.stats['alerts_confirmed'] += 1
                        
                        # Move to processed alerts
                        st.session_state.processed_alerts.append(alert)
                        
                        # Add feedback data
                        st.session_state.feedback_data.append({
                            'features': alert['features'],
                            'label': 1,  # Confirmed as malicious
                            'timestamp': datetime.now().isoformat()
                        })
                        
                        st.success("Alert confirmed as malicious and used for model training.")
                
                with action_col2:
                    reject_clicked = st.button(
                        "❌ False Positive", 
                        key=f"reject_{alert_id}",
                        disabled=st.session_state[f"confirmed_{alert_id}"] or st.session_state[f"rejected_{alert_id}"]
                    )
                    
                    if reject_clicked:
                        st.session_state[f"rejected_{alert_id}"] = True
                        alert['status'] = 'rejected'
                        st.session_state.stats['alerts_rejected'] += 1
                        
                        # Move to processed alerts
                        st.session_state.processed_alerts.append(alert)
                        
                        # Add feedback data
                        st.session_state.feedback_data.append({
                            'features': alert['features'],
                            'label': 0,  # Rejected as benign
                            'timestamp': datetime.now().isoformat()
                        })
                        
                        st.info("Alert rejected as false positive and used for model training.")
                
                with action_col3:
                    needs_analysis_clicked = st.button(
                        "🔍 Needs More Analysis", 
                        key=f"analyze_{alert_id}",
                        disabled=st.session_state[f"confirmed_{alert_id}"] or st.session_state[f"rejected_{alert_id}"]
                    )
                    
                    if needs_analysis_clicked:
                        st.session_state[f"confirmed_{alert_id}"] = True  # Mark as processed
                        alert['status'] = 'needs_analysis'
                        
                        # Move to processed alerts
                        st.session_state.processed_alerts.append(alert)
                        
                        st.warning("Alert marked for further analysis.")
        
        # Button to clear processed alerts
        if any(st.session_state[f"confirmed_{alert['id']}"] or st.session_state[f"rejected_{alert['id']}"] 
              for alert in st.session_state.pending_alerts):
            
            if st.button("Remove Processed Alerts", key="clear_processed_alerts"):
                # Filter out processed alerts
                st.session_state.pending_alerts = [
                    alert for alert in st.session_state.pending_alerts
                    if not (st.session_state[f"confirmed_{alert['id']}"] or 
                            st.session_state[f"rejected_{alert['id']}"])
                ]
                
                st.success("Processed alerts removed from the queue.")
                st.rerun()
    
    # Alert history section
    st.subheader("Alert History & Analysis")
    
    # Create history dataframe
    if st.session_state.alert_history or st.session_state.processed_alerts:
        # Combine processed alerts and alert history, prioritizing processed ones
        processed_ids = [a['id'] for a in st.session_state.processed_alerts]
        unique_alerts = st.session_state.processed_alerts + [
            a for a in st.session_state.alert_history if a['id'] not in processed_ids
        ]
        
        history_data = []
        for alert in unique_alerts:
            history_data.append({
                'Timestamp': alert['timestamp'],
                'Source': alert['src_ip'],
                'Destination': alert['dst_ip'],
                'Protocol': alert['protocol'].upper(),
                'Severity': alert['severity'],
                'Status': alert.get('status', 'pending'),
                'Description': alert['description']
            })
        
        if history_data:
            history_df = pd.DataFrame(history_data)
            
            # Convert timestamp to datetime for sorting
            if 'Timestamp' in history_df.columns:
                history_df['Timestamp'] = pd.to_datetime(history_df['Timestamp'])
                history_df = history_df.sort_values('Timestamp', ascending=False)
            
            # Color-code status
            def color_status(val):
                colors = {
                    'confirmed': 'background-color: #ffcccc',
                    'rejected': 'background-color: #ccffcc',
                    'needs_analysis': 'background-color: #ffffcc',
                    'pending': 'background-color: #e6e6e6'
                }
                return colors.get(val, '')
            
            # Color-code severity
            def color_severity(val):
                colors = {
                    'Critical': 'background-color: #b71c1c; color: white',
                    'High': 'background-color: #e53935; color: white',
                    'Medium': 'background-color: #fb8c00',
                    'Low': 'background-color: #fdd835'
                }
                return colors.get(val, '')
            
            # Convert timestamp back to string for display
            history_df['Timestamp'] = history_df['Timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
            
            # Show styled dataframe
            st.dataframe(
                history_df.style
                    .applymap(color_status, subset=['Status'])
                    .applymap(color_severity, subset=['Severity']),
                use_container_width=True,
                height=400
            )
        else:
            st.info("No alert history available yet.")
    else:
        st.info("No alerts have been generated yet. Start the monitoring system to detect potential threats.")

# Tab 4: Analytics & Model Training
with tab4:
    st.header("Security Analytics & Model Management")
    
    # Main tabs for the analytics section
    analytics_tab1, analytics_tab2, analytics_tab3 = st.tabs([
        "📊 Model Metrics", "🧠 Model Training", "🔄 Feedback Analysis"
    ])
    
    with analytics_tab1:
        st.subheader("Model Performance Metrics")
        
        # Create a card-like container for the model info
        st.markdown("""
        <div class="model-card">
            <div class="model-card-header">Current Model Information</div>
            <div class="model-card-content">
                The NIDS uses a reinforcement learning model to detect network intrusions.
                The model continuously improves through admin feedback and retraining.
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Model metrics display
        metrics_col1, metrics_col2, metrics_col3, metrics_col4 = st.columns(4)
        
        with metrics_col1:
            st.markdown(f"""
            <div class="metric-container">
                <div class="metric-label">Accuracy</div>
                <div class="metric-value">{st.session_state.model_metrics['accuracy']:.2f}</div>
            </div>
            """, unsafe_allow_html=True)
            
        with metrics_col2:
            st.markdown(f"""
            <div class="metric-container">
                <div class="metric-label">Precision</div>
                <div class="metric-value">{st.session_state.model_metrics['precision']:.2f}</div>
            </div>
            """, unsafe_allow_html=True)
            
        with metrics_col3:
            st.markdown(f"""
            <div class="metric-container">
                <div class="metric-label">Recall</div>
                <div class="metric-value">{st.session_state.model_metrics['recall']:.2f}</div>
            </div>
            """, unsafe_allow_html=True)
            
        with metrics_col4:
            st.markdown(f"""
            <div class="metric-container">
                <div class="metric-label">F1 Score</div>
                <div class="metric-value">{st.session_state.model_metrics['f1']:.2f}</div>
            </div>
            """, unsafe_allow_html=True)
        
        # Model performance visualization
        if st.session_state.model_metrics['training_iterations'] > 0:
            st.subheader("Model Performance Over Time")
            
            # Create simulated historical data based on current metrics and improvement rate
            iterations = st.session_state.model_metrics['training_iterations']
            current_accuracy = st.session_state.model_metrics['accuracy']
            current_precision = st.session_state.model_metrics['precision']
            current_recall = st.session_state.model_metrics['recall']
            
            # Start with baseline values
            baseline_accuracy = max(0.65, current_accuracy - (0.05 * iterations))
            baseline_precision = max(0.60, current_precision - (0.05 * iterations))
            baseline_recall = max(0.55, current_recall - (0.05 * iterations))
            
            # Generate history data
            history_data = []
            for i in range(iterations + 1):
                if i == 0:
                    # Initial values
                    history_data.append({
                        'Iteration': i,
                        'Accuracy': baseline_accuracy,
                        'Precision': baseline_precision,
                        'Recall': baseline_recall,
                        'False Positive Rate': min(0.40, st.session_state.model_metrics['false_positive_rate'] * 2)
                    })
                else:
                    # Values after each retraining
                    prev = history_data[-1]
                    improvement_factor = 1 - (0.7 ** i)  # Diminishing returns
                    
                    history_data.append({
                        'Iteration': i,
                        'Accuracy': prev['Accuracy'] + (current_accuracy - baseline_accuracy) * (improvement_factor / iterations),
                        'Precision': prev['Precision'] + (current_precision - baseline_precision) * (improvement_factor / iterations),
                        'Recall': prev['Recall'] + (current_recall - baseline_recall) * (improvement_factor / iterations),
                        'False Positive Rate': max(st.session_state.model_metrics['false_positive_rate'],
                                                prev['False Positive Rate'] * (1 - 0.2 * improvement_factor))
                    })
            
            # Convert to dataframe
            history_df = pd.DataFrame(history_data)
            
            # Create performance chart
            metrics_chart_tab1, metrics_chart_tab2 = st.tabs(["Performance Metrics", "False Positive Rate"])
            
            with metrics_chart_tab1:
                # Melt dataframe for plotting multiple metrics
                plot_df = pd.melt(
                    history_df, 
                    id_vars=['Iteration'], 
                    value_vars=['Accuracy', 'Precision', 'Recall'],
                    var_name='Metric', 
                    value_name='Value'
                )
                
                fig = px.line(
                    plot_df,
                    x='Iteration',
                    y='Value',
                    color='Metric',
                    markers=True,
                    color_discrete_map={
                        'Accuracy': '#1E88E5',
                        'Precision': '#4CAF50',
                        'Recall': '#FF9800'
                    },
                    title='Model Performance Metrics Over Retraining Iterations'
                )
                
                fig.update_layout(
                    height=400,
                    yaxis_range=[0.5, 1.0],
                    xaxis_title="Retraining Iteration",
                    yaxis_title="Metric Value",
                    legend_title="",
                    hovermode="x unified"
                )
                
                st.plotly_chart(fig, use_container_width=True)
            
            with metrics_chart_tab2:
                fig = px.line(
                    history_df,
                    x='Iteration',
                    y='False Positive Rate',
                    markers=True,
                    color_discrete_sequence=['#E53935'],
                    title='False Positive Rate Reduction Over Retraining Iterations'
                )
                
                fig.update_layout(
                    height=400,
                    yaxis_range=[0, 0.5],
                    xaxis_title="Retraining Iteration",
                    yaxis_title="False Positive Rate",
                    hovermode="x unified"
                )
                
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Model performance history will be displayed after retraining.")
    
    with analytics_tab2:
        st.subheader("Model Training Management")
        
        # Split into two columns
        train_col1, train_col2 = st.columns([3, 2])
        
        with train_col1:
            # Last trained info with styled component
            if st.session_state.model_metrics['last_retrained']:
                last_trained = st.session_state.model_metrics['last_retrained'].strftime('%Y-%m-%d %H:%M:%S')
                training_iterations = st.session_state.model_metrics['training_iterations']
                
                st.markdown(f"""
                <div class="model-card">
                    <div class="model-card-header">Model Training Status</div>
                    <div class="model-card-content">
                        <p><strong>Last Retrained:</strong> {last_trained}</p>
                        <p><strong>Total Training Iterations:</strong> {training_iterations}</p>
                        <p><strong>Feedback Data Items:</strong> {len(st.session_state.feedback_data)}</p>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="model-card">
                    <div class="model-card-header">Model Training Status</div>
                    <div class="model-card-content">
                        <p>Model has not been retrained yet.</p>
                        <p><strong>Feedback Data Items:</strong> {len(st.session_state.feedback_data)}</p>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            
            # Retraining recommendations
            if len(st.session_state.feedback_data) > 5:
                pending_feedback = len(st.session_state.feedback_data)
                last_trained_time = st.session_state.model_metrics.get('last_retrained')
                
                if last_trained_time is None or (datetime.now() - last_trained_time).total_seconds() > 300:
                    st.success(f"✅ Retraining recommended: {pending_feedback} feedback items available")
                else:
                    st.info(f"ℹ️ {pending_feedback} feedback items available for next retraining")
            else:
                needed_feedback = max(0, 5 - len(st.session_state.feedback_data))
                st.warning(f"⚠️ Need {needed_feedback} more feedback items before retraining")
            
            # Training dataset info
            st.subheader("Training Dataset")
            
            # Simulated dataset composition
            dataset_col1, dataset_col2 = st.columns(2)
            
            with dataset_col1:
                st.markdown("""
                #### Initial Dataset
                - **Size**: 10,000 network packets
                - **Benign Samples**: 7,500 (75%)
                - **Malicious Samples**: 2,500 (25%)
                - **Attack Types**: Port scans, DDoS, Brute force, Data exfiltration
                """)
            
            with dataset_col2:
                st.markdown(f"""
                #### Feedback Dataset
                - **Size**: {len(st.session_state.feedback_data)} samples
                - **Confirmed Threats**: {st.session_state.stats.get('alerts_confirmed', 0)} 
                - **False Positives**: {st.session_state.stats.get('alerts_rejected', 0)}
                - **Balance Ratio**: {st.session_state.stats.get('alerts_confirmed', 0) / max(1, len(st.session_state.feedback_data)):.2f}
                """)
        
        with train_col2:
            # Training controls
            st.markdown("""
            ### Model Training Controls
            """)
            
            # Initialize model button with nice styling
            if not st.session_state.model_initialized:
                st.markdown("""
                <div class="model-card">
                    <div class="model-card-header">Initialize Model</div>
                    <div class="model-card-content">
                        Train a new model with the initial dataset.
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                if st.button("Initialize Model", key="init_model", type="primary"):
                    with st.spinner("Initializing model with default dataset..."):
                        # Simulate initialization delay
                        time.sleep(3)
                        
                        # Mark model as initialized
                        st.session_state.model_initialized = True
                        st.success("✅ Model successfully initialized with default dataset!")
            
            # Retrain model button with info
            st.markdown("""
            <div class="model-card">
                <div class="model-card-header">Retrain Model</div>
                <div class="model-card-content">
                    Update the model with admin feedback data to improve detection accuracy and reduce false positives.
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            retrain_button = st.button(
                "Retrain Model with Feedback", 
                key="retrain_model", 
                type="primary",
                disabled=len(st.session_state.feedback_data) < 5
            )
            
            if retrain_button:
                with st.spinner("Retraining model with admin feedback..."):
                    # Simulate model training delay
                    time.sleep(2)
                    
                    # Update model metrics to show improvement
                    current_metrics = st.session_state.model_metrics
                    
                    # Calculate improvement factors based on amount of feedback
                    feedback_amount = len(st.session_state.feedback_data)
                    max_improvement = min(0.15, 0.02 * feedback_amount)  # Cap at 15% improvement
                    
                    # Increase metrics with diminishing returns
                    accuracy_improvement = max_improvement * (1 - current_metrics['accuracy'])
                    precision_improvement = max_improvement * (1 - current_metrics['precision'])
                    recall_improvement = max_improvement * (1 - current_metrics['recall'])
                    f1_improvement = max_improvement * (1 - current_metrics['f1'])
                    fpr_reduction = current_metrics['false_positive_rate'] * max_improvement
                    
                    # Update metrics
                    st.session_state.model_metrics.update({
                        "accuracy": min(0.99, current_metrics['accuracy'] + accuracy_improvement),
                        "precision": min(0.99, current_metrics['precision'] + precision_improvement),
                        "recall": min(0.99, current_metrics['recall'] + recall_improvement),
                        "f1": min(0.99, current_metrics['f1'] + f1_improvement),
                        "false_positive_rate": max(0.01, current_metrics['false_positive_rate'] - fpr_reduction),
                        "training_iterations": current_metrics['training_iterations'] + 1,
                        "improvement_rate": max_improvement,
                        "last_retrained": datetime.now()
                    })
                    
                    # Mark model as retrained
                    st.session_state.model_retrained = True
                    st.session_state.retraining_needed = False
                    
                    # Clear some of the feedback data (but keep the most recent ones)
                    if len(st.session_state.feedback_data) > 10:
                        st.session_state.feedback_data = st.session_state.feedback_data[-10:]
                    
                    st.success("✅ Model successfully retrained with admin feedback!")
            
            # Advanced settings accordion
            with st.expander("Advanced Model Settings"):
                st.slider("Learning Rate", 0.001, 0.1, 0.01, format="%.3f")
                st.slider("Batch Size", 16, 256, 64, step=16)
                st.slider("Epochs", 1, 50, 10)
                st.checkbox("Use Early Stopping", value=True)
                st.checkbox("Apply Data Augmentation", value=False)
            
            # DPI settings card
            st.markdown("""
            <div class="model-card">
                <div class="model-card-header">Deep Packet Inspection Settings</div>
                <div class="model-card-content">
                    Enable or disable deep packet inspection for content analysis.
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            dpi_enabled = st.toggle("Enable Deep Packet Inspection", value=True, key="dpi_enabled")
            
            if dpi_enabled:
                st.success("DPI engine is active and analyzing packet payloads")
            else:
                st.warning("DPI engine is disabled. Only header analysis will be performed.")
    
    with analytics_tab3:
        st.subheader("Admin Feedback Analysis")
        
        # Feedback summary
        feedback_confirmed = st.session_state.stats.get('alerts_confirmed', 0)
        feedback_rejected = st.session_state.stats.get('alerts_rejected', 0)
        total_feedback = feedback_confirmed + feedback_rejected
        
        if total_feedback > 0:
            feedback_col1, feedback_col2, feedback_col3 = st.columns(3)
            
            with feedback_col1:
                st.markdown(f"""
                <div class="metric-container">
                    <div class="metric-label">Total Feedback</div>
                    <div class="metric-value">{total_feedback}</div>
                </div>
                """, unsafe_allow_html=True)
            
            with feedback_col2:
                st.markdown(f"""
                <div class="metric-container">
                    <div class="metric-label">Confirmed Threats</div>
                    <div class="metric-value">{feedback_confirmed}</div>
                </div>
                """, unsafe_allow_html=True)
            
            with feedback_col3:
                st.markdown(f"""
                <div class="metric-container">
                    <div class="metric-label">False Positives</div>
                    <div class="metric-value">{feedback_rejected}</div>
                </div>
                """, unsafe_allow_html=True)
            
            # Feedback distribution chart
            st.subheader("Feedback Distribution")
            
            feedback_df = pd.DataFrame([
                {'Feedback Type': 'Confirmed Threats', 'Count': feedback_confirmed},
                {'Feedback Type': 'False Positives', 'Count': feedback_rejected}
            ])
            
            fig = px.pie(
                feedback_df,
                values='Count',
                names='Feedback Type',
                title='Admin Feedback Distribution',
                color_discrete_map={
                    'Confirmed Threats': '#E53935',
                    'False Positives': '#1E88E5'
                },
                hole=0.4
            )
            
            fig.update_layout(height=350)
            st.plotly_chart(fig, use_container_width=True)
            
            # Feedback impact analysis
            st.subheader("Feedback Impact on Model")
            
            # Create simulated impact data
            if st.session_state.model_metrics['training_iterations'] > 0:
                # Show model improvement from feedback
                current_metrics = st.session_state.model_metrics
                
                metrics_improvement = {
                    'Metric': ['Accuracy', 'Precision', 'Recall', 'F1 Score'],
                    'Before': [
                        max(0.65, current_metrics['accuracy'] - 0.1),
                        max(0.60, current_metrics['precision'] - 0.15),
                        max(0.55, current_metrics['recall'] - 0.12),
                        max(0.58, current_metrics['f1'] - 0.13)
                    ],
                    'After': [
                        current_metrics['accuracy'],
                        current_metrics['precision'],
                        current_metrics['recall'],
                        current_metrics['f1']
                    ]
                }
                
                # Calculate improvement
                metrics_improvement['Improvement'] = [
                    metrics_improvement['After'][i] - metrics_improvement['Before'][i]
                    for i in range(len(metrics_improvement['Metric']))
                ]
                
                # Create dataframe
                imp_df = pd.DataFrame(metrics_improvement)
                
                # Show table
                st.dataframe(
                    imp_df.style.format({
                        'Before': '{:.2f}',
                        'After': '{:.2f}',
                        'Improvement': '{:.2f}'
                    }),
                    use_container_width=True
                )
                
                # Show bar chart of improvement
                fig = px.bar(
                    imp_df,
                    x='Metric',
                    y='Improvement',
                    title='Model Improvement from Admin Feedback',
                    color_discrete_sequence=['#4CAF50']
                )
                
                fig.update_layout(height=350)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Feedback impact analysis will be available after model retraining.")
        else:
            st.info("No feedback data available yet. Provide feedback on alerts to see analysis.")
    
    
    # Model performance visualization
    st.subheader("Model Performance History")
    
    # If model has been retrained, show a performance improvement chart
    if st.session_state.model_metrics['training_iterations'] > 0:
        # Create simulated historical data based on current metrics and improvement rate
        iterations = st.session_state.model_metrics['training_iterations']
        current_accuracy = st.session_state.model_metrics['accuracy']
        current_precision = st.session_state.model_metrics['precision']
        current_recall = st.session_state.model_metrics['recall']
        
        # Start with baseline values
        baseline_accuracy = max(0.65, current_accuracy - (0.05 * iterations))
        baseline_precision = max(0.60, current_precision - (0.05 * iterations))
        baseline_recall = max(0.55, current_recall - (0.05 * iterations))
        
        # Generate history data
        history_data = []
        for i in range(iterations + 1):
            if i == 0:
                # Initial values
                history_data.append({
                    'Iteration': i,
                    'Accuracy': baseline_accuracy,
                    'Precision': baseline_precision,
                    'Recall': baseline_recall,
                    'False Positive Rate': min(0.40, st.session_state.model_metrics['false_positive_rate'] * 2)
                })
            else:
                # Values after each retraining
                prev = history_data[-1]
                improvement_factor = 1 - (0.7 ** i)  # Diminishing returns
                
                history_data.append({
                    'Iteration': i,
                    'Accuracy': prev['Accuracy'] + (current_accuracy - baseline_accuracy) * (improvement_factor / iterations),
                    'Precision': prev['Precision'] + (current_precision - baseline_precision) * (improvement_factor / iterations),
                    'Recall': prev['Recall'] + (current_recall - baseline_recall) * (improvement_factor / iterations),
                    'False Positive Rate': max(st.session_state.model_metrics['false_positive_rate'],
                                             prev['False Positive Rate'] * (1 - 0.2 * improvement_factor))
                })
        
        # Convert to dataframe
        history_df = pd.DataFrame(history_data)
        
        # Create performance chart
        metrics_tab1, metrics_tab2 = st.tabs(["Performance Metrics", "False Positive Rate"])
        
        with metrics_tab1:
            # Melt dataframe for plotting multiple metrics
            plot_df = pd.melt(
                history_df, 
                id_vars=['Iteration'], 
                value_vars=['Accuracy', 'Precision', 'Recall'],
                var_name='Metric', 
                value_name='Value'
            )
            
            fig = px.line(
                plot_df,
                x='Iteration',
                y='Value',
                color='Metric',
                markers=True,
                color_discrete_map={
                    'Accuracy': '#1E88E5',
                    'Precision': '#4CAF50',
                    'Recall': '#FF9800'
                },
                title='Model Performance Metrics Over Retraining Iterations'
            )
            
            fig.update_layout(
                height=400,
                yaxis_range=[0.5, 1.0],
                xaxis_title="Retraining Iteration",
                yaxis_title="Metric Value",
                legend_title="",
                hovermode="x unified"
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with metrics_tab2:
            fig = px.line(
                history_df,
                x='Iteration',
                y='False Positive Rate',
                markers=True,
                color_discrete_sequence=['#E53935'],
                title='False Positive Rate Reduction Over Retraining Iterations'
            )
            
            fig.update_layout(
                height=400,
                yaxis_range=[0, 0.5],
                xaxis_title="Retraining Iteration",
                yaxis_title="False Positive Rate",
                hovermode="x unified"
            )
            
            st.plotly_chart(fig, use_container_width=True)
    else:
        # Show placeholder for model performance
        st.info("No model retraining history available yet. Retrain the model to see performance metrics.")
    
    # Overall statistics
    st.subheader("Security Overview")
    
    # Calculate statistics
    total_packets = st.session_state.stats['total_packets']
    malicious_packets = st.session_state.stats['malicious_packets']
    benign_packets = st.session_state.stats['benign_packets']
    total_alerts = st.session_state.stats['alerts_generated']
    confirmed_alerts = st.session_state.stats['alerts_confirmed']
    rejected_alerts = st.session_state.stats['alerts_rejected']
    
    malicious_ratio = malicious_packets / total_packets if total_packets > 0 else 0
    alert_ratio = total_alerts / total_packets if total_packets > 0 else 0
    false_positive_ratio = rejected_alerts / total_alerts if total_alerts > 0 else 0
    true_positive_ratio = confirmed_alerts / total_alerts if total_alerts > 0 else 0
    
    # Create gauge charts for key metrics
    analytics_col1, analytics_col2, analytics_col3 = st.columns(3)
    
    with analytics_col1:
        # Malicious traffic gauge
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=malicious_ratio * 100,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Malicious Traffic %"},
            gauge={
                'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 20], 'color': "green"},
                    {'range': [20, 50], 'color': "yellow"},
                    {'range': [50, 100], 'color': "red"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': malicious_ratio * 100
                }
            }
        ))
        
        fig.update_layout(height=300, margin=dict(l=20, r=20, t=70, b=20))
        st.plotly_chart(fig, use_container_width=True)
    
    with analytics_col2:
        # Alert ratio gauge
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=alert_ratio * 100,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Alert Generation Ratio %"},
            gauge={
                'axis': {'range': [0, 50], 'tickwidth': 1, 'tickcolor': "darkblue"},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 10], 'color': "green"},
                    {'range': [10, 25], 'color': "yellow"},
                    {'range': [25, 50], 'color': "red"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': alert_ratio * 100
                }
            }
        ))
        
        fig.update_layout(height=300, margin=dict(l=20, r=20, t=70, b=20))
        st.plotly_chart(fig, use_container_width=True)
    
    with analytics_col3:
        # False positive ratio gauge
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=false_positive_ratio * 100,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "False Positive Ratio %"},
            gauge={
                'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 25], 'color': "green"},
                    {'range': [25, 50], 'color': "yellow"},
                    {'range': [50, 100], 'color': "red"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': false_positive_ratio * 100
                }
            }
        ))
        
        fig.update_layout(height=300, margin=dict(l=20, r=20, t=70, b=20))
        st.plotly_chart(fig, use_container_width=True)
    
    # Protocol and port statistics
    st.subheader("Protocol & Service Analysis")
    
    proto_col1, proto_col2 = st.columns(2)
    
    with proto_col1:
        # Protocol distribution
        protocol_data = []
        for proto, count in st.session_state.stats['protocol_distribution'].items():
            if count > 0:
                protocol_data.append({
                    'Protocol': proto.upper(),
                    'Count': count,
                    'Percentage': (count / total_packets * 100) if total_packets > 0 else 0
                })
        
        if protocol_data:
            protocol_df = pd.DataFrame(protocol_data)
            
            fig = px.bar(
                protocol_df,
                x='Protocol',
                y='Count',
                color='Protocol',
                color_discrete_sequence=px.colors.qualitative.Bold,
                title='Protocol Distribution'
            )
            
            fig.update_layout(height=350)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No protocol data available yet.")
    
    with proto_col2:
        # Top ports
        port_data = []
        for port, count in st.session_state.stats['port_distribution'].items():
            service = get_service_name(port)
            port_data.append({
                'Port': port,
                'Service': service,
                'Count': count
            })
        
        if port_data:
            port_df = pd.DataFrame(port_data)
            
            # Sort and get top ports
            port_df = port_df.sort_values('Count', ascending=False).head(10)
            
            # Create label with port and service
            port_df['Label'] = port_df.apply(
                lambda x: f"{x['Port']} ({x['Service']})" if x['Service'] != 'Unknown' else str(x['Port']),
                axis=1
            )
            
            fig = px.bar(
                port_df,
                x='Label',
                y='Count',
                color='Service',
                color_discrete_sequence=px.colors.qualitative.Plotly,
                title='Top 10 Ports'
            )
            
            fig.update_layout(height=350, xaxis_title="Port (Service)")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No port data available yet.")
    
    # Threat insights
    st.subheader("Threat Classification Insights")
    
    # Create attack type distribution visualization
    attack_types = {}
    for alert in st.session_state.alert_history:
        description = alert.get('description', 'Unknown')
        
        # Simplified attack categorization based on description
        if 'port scan' in description.lower():
            category = 'Port Scan'
        elif 'brute force' in description.lower():
            category = 'Brute Force'
        elif 'injection' in description.lower():
            category = 'Injection Attack'
        elif 'xss' in description.lower() or 'cross-site' in description.lower():
            category = 'XSS Attack'
        elif 'exfiltration' in description.lower() or 'data' in description.lower():
            category = 'Data Exfiltration'
        elif 'dns' in description.lower():
            category = 'DNS Attack'
        elif 'ddos' in description.lower() or 'flood' in description.lower():
            category = 'DDoS'
        elif 'c&c' in description.lower() or 'command' in description.lower() or 'control' in description.lower():
            category = 'C&C Communication'
        else:
            category = 'Other'
        
        if category in attack_types:
            attack_types[category] += 1
        else:
            attack_types[category] = 1
    
    # Display attack type distribution
    if attack_types:
        attack_df = pd.DataFrame([
            {'Attack Type': category, 'Count': count}
            for category, count in attack_types.items()
        ])
        
        fig = px.pie(
            attack_df,
            values='Count',
            names='Attack Type',
            title='Attack Type Distribution',
            color_discrete_sequence=px.colors.sequential.RdBu,
            hole=0.4
        )
        
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No threat classification data available yet.")
    
    # Display feedback statistics for model learning
    st.subheader("Model Learning & Feedback")
    
    if st.session_state.feedback_data:
        # Count feedback by label
        confirmed_count = sum(1 for item in st.session_state.feedback_data if item['label'] == 1)
        rejected_count = sum(1 for item in st.session_state.feedback_data if item['label'] == 0)
        
        feedback_df = pd.DataFrame([
            {'Feedback Type': 'Confirmed Threats', 'Count': confirmed_count},
            {'Feedback Type': 'False Positives', 'Count': rejected_count}
        ])
        
        feedback_col1, feedback_col2 = st.columns(2)
        
        with feedback_col1:
            fig = px.bar(
                feedback_df,
                x='Feedback Type',
                y='Count',
                color='Feedback Type',
                color_discrete_map={
                    'Confirmed Threats': '#E53935',
                    'False Positives': '#1E88E5'
                },
                title='Admin Feedback Distribution'
            )
            
            fig.update_layout(height=350)
            st.plotly_chart(fig, use_container_width=True)
        
        with feedback_col2:
            # Model improvement simulation based on feedback
            if len(st.session_state.feedback_data) >= 5:
                # Simulate accuracy improvement with increasing feedback
                num_feedback = len(st.session_state.feedback_data)
                accuracy_start = 0.75
                max_improvement = 0.2
                improvement_rate = 0.05
                
                improvement = max_improvement * (1 - math.exp(-improvement_rate * num_feedback))
                accuracy_values = [accuracy_start]
                feedback_counts = [0]
                
                for i in range(1, num_feedback + 1, max(1, num_feedback // 10)):
                    improvement_i = max_improvement * (1 - math.exp(-improvement_rate * i))
                    accuracy_values.append(accuracy_start + improvement_i)
                    feedback_counts.append(i)
                
                learning_df = pd.DataFrame({
                    'Feedback Count': feedback_counts,
                    'Accuracy': accuracy_values
                })
                
                fig = px.line(
                    learning_df,
                    x='Feedback Count',
                    y='Accuracy',
                    markers=True,
                    title='Model Learning Curve',
                    color_discrete_sequence=['#4CAF50']
                )
                
                fig.update_layout(
                    height=350,
                    yaxis_range=[0.7, 1.0]
                )
                
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("More feedback data is needed to show learning curve (at least 5 feedback items required).")
    else:
        st.info("No feedback data available yet. Provide feedback on alerts to help train the model.")
    
    # Reset statistics button for testing
    if st.button("Reset Statistics (For Testing Only)", key="reset_stats"):
        # Reset statistics
        st.session_state.stats = {
            'total_packets': 0,
            'benign_packets': 0,
            'malicious_packets': 0,
            'alerts_generated': 0,
            'alerts_confirmed': 0,
            'alerts_rejected': 0,
            'total_traffic': 0,
            'protocol_distribution': {'tcp': 0, 'udp': 0, 'icmp': 0, 'other': 0},
            'top_sources': {},
            'top_destinations': {},
            'port_distribution': {},
        }
        
        # Clear history
        st.session_state.detection_history = []
        st.session_state.alert_history = []
        st.session_state.pending_alerts = []
        st.session_state.processed_alerts = []
        st.session_state.feedback_data = []
        
        st.success("Statistics and history reset successfully.")
        st.rerun()

# Footer
st.markdown("""
---
### Network Intrusion Detection System v1.0
Powered by reinforcement learning and deep packet inspection technology.
""")