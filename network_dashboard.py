import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import time
from datetime import datetime, timedelta
import json
import math
import random
from database import db
from real_network_simulator import RealNetworkSimulator

def initialize_network_dashboard():
    """
    Initialize network dashboard components in session state
    """
    if 'network_initialized' not in st.session_state:
        st.session_state.network_initialized = True
        st.session_state.packet_history = []
        st.session_state.alert_history = []
        st.session_state.monitoring_active = False
        st.session_state.last_update = datetime.now()
        st.session_state.network_stats = {
            'total_traffic': 0,  # bytes
            'packets_processed': 0,
            'malicious_packets': 0,
            'benign_packets': 0,
            'alert_count': 0,
            'top_sources': {},
            'top_destinations': {},
            'protocol_distribution': {'tcp': 0, 'udp': 0, 'icmp': 0, 'other': 0},
            'port_distribution': {},
            'traffic_timeline': []
        }
        
        # Initialize database
        db.initialize()
        
        # Initialize simulator
        st.session_state.real_simulator = RealNetworkSimulator()

def create_network_dashboard():
    """
    Create comprehensive network monitoring dashboard with real-time data
    """
    # Initialize dashboard if needed
    initialize_network_dashboard()
    
    # Dashboard header
    st.subheader("🌐 Comprehensive Network Monitoring")
    
    # Control section
    control_col1, control_col2, control_col3 = st.columns([1, 1, 1])
    
    with control_col1:
        if not st.session_state.monitoring_active:
            start_button = st.button("Start Network Monitoring", key="start_network", type="primary")
            if start_button:
                st.session_state.monitoring_active = True
                st.session_state.real_simulator.start_simulation()
        else:
            stop_button = st.button("Stop Network Monitoring", key="stop_network", type="secondary")
            if stop_button:
                st.session_state.monitoring_active = False
                st.session_state.real_simulator.stop_simulation()
    
    with control_col2:
        simulation_speed = st.slider("Simulation Speed", min_value=1, max_value=10, value=5)
        # The higher the simulation speed, the lower the benign ratio (more attacks)
        benign_ratio = max(0.1, 1.0 - (simulation_speed / 20))
        st.session_state.real_simulator.set_benign_ratio(benign_ratio)
    
    with control_col3:
        attack_types = ['port_scan', 'brute_force', 'ddos', 'data_exfiltration', 'malware_communication']
        
        # Store attack selection in session state to maintain it between reruns
        if 'selected_attack' not in st.session_state:
            st.session_state.selected_attack = "None"
            
        selected_attack = st.selectbox("Simulate Attack", ["None"] + attack_types, key="attack_selector")
        st.session_state.selected_attack = selected_attack
        
        launch_attack = st.button("Launch Attack", key="launch_attack_button")
        if launch_attack and st.session_state.selected_attack != "None":
            success = st.session_state.real_simulator.start_attack(st.session_state.selected_attack)
            if success:
                st.success(f"Simulated {st.session_state.selected_attack} attack started!")
            else:
                st.error(f"Failed to start attack simulation. Please start network monitoring first.")
    
    # Dashboard layout with multiple metrics and visualizations
    create_dashboard_metrics()
    create_traffic_visualizations()
    create_threat_visualizations()
    create_network_maps()
    create_packet_inspection()
    
    # Automatically update dashboard if monitoring is active
    if st.session_state.monitoring_active:
        # Add an auto-refresh mechanism with a button to manually refresh
        refresh_col1, refresh_col2 = st.columns([3, 1])
        with refresh_col1:
            st.write("Dashboard automatically updates every few seconds while monitoring is active.")
        
        with refresh_col2:
            if st.button("Refresh Now", key="manual_refresh"):
                update_dashboard_data()
                st.session_state.last_update = datetime.now()
        
        # Auto-update on timer
        time_since_update = (datetime.now() - st.session_state.last_update).total_seconds()
        if time_since_update >= 3.0:  # Update every 3 seconds
            update_dashboard_data()
            st.session_state.last_update = datetime.now()

def update_dashboard_data():
    """
    Update dashboard with fresh network data
    """
    simulator = st.session_state.real_simulator
    
    # Get a batch of new packets
    batch_size = 10
    new_packets = []
    for _ in range(batch_size):
        packet = simulator.get_next_packet()
        if packet:
            new_packets.append(packet)
            
            # Add to packet history (limited size)
            st.session_state.packet_history.append(packet)
            if len(st.session_state.packet_history) > 1000:
                st.session_state.packet_history.pop(0)
                
            # Check if malicious packet
            if packet.get('is_actually_malicious', False):
                st.session_state.network_stats['malicious_packets'] += 1
                
                # Create alert for highly suspicious packets (100% for demo purposes)
                alert = {
                    'id': len(st.session_state.alert_history) + 1,
                    'timestamp': packet['timestamp'],
                    'src_ip': packet['src'],
                    'dst_ip': packet['dst'],
                    'protocol': packet['proto'],
                    'severity': 'High' if random.random() < 0.5 else 'Medium',
                    'description': get_attack_description(packet),
                    'packet': packet
                }
                st.session_state.alert_history.append(alert)
                st.session_state.network_stats['alert_count'] += 1
                
                # Store in database
                try:
                    # Add detection to database
                    features = []  # In a real implementation, extract features from packet
                    detection_id = db.add_detection(
                        packet, features, True, random.uniform(0.8, 0.95))
                    
                    # Add alert
                    db.add_alert(detection_id)
                    
                    # Also add to app.py's pending alerts for admin feedback
                    if 'pending_alerts' in st.session_state:
                        alert_id = f"alert_{int(time.time())}_{st.session_state.network_stats['alert_count']}"
                        alert_data = {
                            "id": alert_id,
                            "timestamp": datetime.now().isoformat(),
                            "packet": packet,
                            "features": features,
                            "confidence": random.uniform(0.8, 0.95),
                            "status": "pending"  # pending, confirmed, rejected
                        }
                        st.session_state.pending_alerts.append(alert_data)
                except Exception as e:
                    print(f"Database error: {str(e)}")
            else:
                # Occasionally create false positive alerts (10% chance)
                if random.random() < 0.1:
                    severity = 'Medium' if random.random() < 0.8 else 'Low'
                    alert = {
                        'id': len(st.session_state.alert_history) + 1,
                        'timestamp': packet['timestamp'],
                        'src_ip': packet['src'],
                        'dst_ip': packet['dst'],
                        'protocol': packet['proto'],
                        'severity': severity,
                        'description': f"Unusual traffic pattern from {packet['src']}",
                        'packet': packet
                    }
                    st.session_state.alert_history.append(alert)
                    st.session_state.network_stats['alert_count'] += 1
                    
                    # Add to app.py's pending alerts for admin feedback (false positive case)
                    if 'pending_alerts' in st.session_state:
                        alert_id = f"alert_{int(time.time())}_{st.session_state.network_stats['alert_count']}"
                        alert_data = {
                            "id": alert_id,
                            "timestamp": datetime.now().isoformat(),
                            "packet": packet,
                            "features": [],  # Empty features for demo
                            "confidence": random.uniform(0.6, 0.8),  # Lower confidence for false positives
                            "status": "pending"  # pending, confirmed, rejected
                        }
                        st.session_state.pending_alerts.append(alert_data)
                
                st.session_state.network_stats['benign_packets'] += 1
    
    # Update statistics
    st.session_state.network_stats['packets_processed'] += len(new_packets)
    st.session_state.network_stats['total_traffic'] += sum(p.get('len', 0) for p in new_packets)
    
    # Update protocol distribution
    for packet in new_packets:
        proto = packet.get('proto', 'other')
        if proto in st.session_state.network_stats['protocol_distribution']:
            st.session_state.network_stats['protocol_distribution'][proto] += 1
        else:
            st.session_state.network_stats['protocol_distribution']['other'] += 1
    
    # Update source/destination tracking
    for packet in new_packets:
        src = packet.get('src')
        dst = packet.get('dst')
        
        if src:
            st.session_state.network_stats['top_sources'][src] = st.session_state.network_stats['top_sources'].get(src, 0) + 1
        
        if dst:
            st.session_state.network_stats['top_destinations'][dst] = st.session_state.network_stats['top_destinations'].get(dst, 0) + 1
    
    # Update port distribution
    for packet in new_packets:
        if 'dport' in packet:
            port = packet['dport']
            st.session_state.network_stats['port_distribution'][port] = st.session_state.network_stats['port_distribution'].get(port, 0) + 1
    
    # Update traffic timeline
    now = datetime.now()
    traffic_entry = {
        'timestamp': now.strftime('%H:%M:%S'),
        'packets': len(new_packets),
        'bytes': sum(p.get('len', 0) for p in new_packets),
        'malicious': sum(1 for p in new_packets if p.get('is_actually_malicious', False))
    }
    st.session_state.network_stats['traffic_timeline'].append(traffic_entry)
    
    # Keep timeline limited to last hour (assuming updates every few seconds)
    if len(st.session_state.network_stats['traffic_timeline']) > 3600:
        st.session_state.network_stats['traffic_timeline'] = st.session_state.network_stats['traffic_timeline'][-3600:]

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
            return f"Possible port scan from {src} targeting {dport} on {dst}"
        
        if dport == 22 or dport == 21:
            if 'USER' in payload or 'PASS' in payload:
                return f"Possible brute force attack on {'SSH' if dport == 22 else 'FTP'} service"
        
        if dport == 80 or dport == 443:
            if "')" in payload or ";" in payload or "--" in payload:
                return "SQL Injection attempt detected"
            if "<script>" in payload or "onerror=" in payload:
                return "Cross-site scripting (XSS) attempt detected"
            if random.random() < 0.3:
                return "Suspicious HTTP traffic detected"
    
    # UDP-specific patterns
    if proto == 'udp':
        if dport == 53:
            if len(payload) > 100:
                return "Possible DNS tunneling detected"
        
        if dport > 1024 and sport > 1024:
            return "Suspicious UDP communication between unusual ports"
    
    # ICMP patterns
    if proto == 'icmp':
        return "Suspicious ICMP packet detected, possible network mapping"
    
    # Generic patterns
    if "BASE64" in payload:
        return "Potential data exfiltration with encoded content"
    
    if any(term in payload for term in ["gate.php", "config.bin", "updates.js", "/admin/"]):
        return "Communication with potential C&C server detected"
    
    # Default
    return "Anomalous network traffic detected"

def create_dashboard_metrics():
    """Create the metrics section of the dashboard"""
    st.subheader("📊 Network Traffic Metrics")
    
    # First row of metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    
    col1.metric(
        "Total Traffic", 
        f"{format_bytes(st.session_state.network_stats['total_traffic'])}"
    )
    
    col2.metric(
        "Packets Processed", 
        f"{st.session_state.network_stats['packets_processed']:,}"
    )
    
    benign_percentage = 0
    if st.session_state.network_stats['packets_processed'] > 0:
        benign_percentage = (st.session_state.network_stats['benign_packets'] / 
                           st.session_state.network_stats['packets_processed']) * 100
    
    col3.metric(
        "Benign Traffic", 
        f"{benign_percentage:.1f}%"
    )
    
    malicious_percentage = 0
    if st.session_state.network_stats['packets_processed'] > 0:
        malicious_percentage = (st.session_state.network_stats['malicious_packets'] / 
                              st.session_state.network_stats['packets_processed']) * 100
    
    col4.metric(
        "Malicious Traffic", 
        f"{malicious_percentage:.1f}%"
    )
    
    col5.metric(
        "Active Alerts", 
        f"{st.session_state.network_stats['alert_count']}"
    )
    
    # Second row - protocol distribution
    st.subheader("Protocol Distribution")
    protocol_data = []
    total_packets = sum(st.session_state.network_stats['protocol_distribution'].values())
    
    for proto, count in st.session_state.network_stats['protocol_distribution'].items():
        if count > 0:
            percentage = (count / total_packets) * 100 if total_packets > 0 else 0
            protocol_data.append({'Protocol': proto.upper(), 'Count': count, 'Percentage': percentage})
    
    if protocol_data:
        protocol_df = pd.DataFrame(protocol_data)
        
        # Create donut chart for protocol distribution
        fig = px.pie(
            protocol_df, 
            values='Count', 
            names='Protocol', 
            title='Protocol Distribution',
            hole=0.4,
            color_discrete_sequence=px.colors.qualitative.Bold
        )
        
        fig.update_layout(
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
            margin=dict(l=20, r=20, t=40, b=20),
            height=350
        )
        
        st.plotly_chart(fig, use_container_width=True)

def create_traffic_visualizations():
    """Create traffic visualizations section"""
    st.subheader("🔄 Traffic Flow Analysis")
    
    # Traffic timeline
    timeline_data = st.session_state.network_stats['traffic_timeline']
    
    if timeline_data:
        df = pd.DataFrame(timeline_data)
        
        # Create subplot with two y-axes
        fig = make_subplots(specs=[[{"secondary_y": True}]])
        
        # Add packets line
        fig.add_trace(
            go.Scatter(
                x=df['timestamp'], 
                y=df['packets'],
                name="Packets",
                line=dict(color='blue', width=2)
            ),
            secondary_y=False
        )
        
        # Add bytes line
        fig.add_trace(
            go.Scatter(
                x=df['timestamp'], 
                y=df['bytes'],
                name="Bytes",
                line=dict(color='green', width=2)
            ),
            secondary_y=True
        )
        
        # Add malicious packets
        fig.add_trace(
            go.Scatter(
                x=df['timestamp'], 
                y=df['malicious'],
                name="Malicious",
                line=dict(color='red', width=2)
            ),
            secondary_y=False
        )
        
        # Update layout
        fig.update_layout(
            title_text="Network Traffic Timeline",
            xaxis_title="Time",
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
            margin=dict(l=20, r=20, t=50, b=20),
            height=350
        )
        
        # Set y-axes titles
        fig.update_yaxes(title_text="Packet Count", secondary_y=False)
        fig.update_yaxes(title_text="Bytes", secondary_y=True)
        
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Traffic timeline data will appear here once monitoring begins")
    
    # Top sources and destinations
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Top Source IPs")
        
        # Get top 10 sources
        top_sources = sorted(
            st.session_state.network_stats['top_sources'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        if top_sources:
            source_df = pd.DataFrame(top_sources, columns=['IP', 'Count'])
            
            fig = px.bar(
                source_df, 
                x='Count', 
                y='IP',
                orientation='h',
                color='Count',
                color_continuous_scale='Blues',
                title='Top Source IP Addresses'
            )
            
            fig.update_layout(yaxis={'categoryorder':'total ascending'}, height=400)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Source IP data will appear here once monitoring begins")
    
    with col2:
        st.subheader("Top Destination IPs")
        
        # Get top 10 destinations
        top_destinations = sorted(
            st.session_state.network_stats['top_destinations'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        if top_destinations:
            dest_df = pd.DataFrame(top_destinations, columns=['IP', 'Count'])
            
            fig = px.bar(
                dest_df, 
                x='Count', 
                y='IP',
                orientation='h',
                color='Count',
                color_continuous_scale='Greens',
                title='Top Destination IP Addresses'
            )
            
            fig.update_layout(yaxis={'categoryorder':'total ascending'}, height=400)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Destination IP data will appear here once monitoring begins")
    
    # Service port analysis
    st.subheader("Service Port Analysis")
    
    port_data = st.session_state.network_stats['port_distribution']
    
    if port_data:
        # Get top 15 ports
        top_ports = sorted(port_data.items(), key=lambda x: x[1], reverse=True)[:15]
        port_df = pd.DataFrame(top_ports, columns=['Port', 'Count'])
        
        # Add service names for well-known ports
        port_df['Service'] = port_df['Port'].apply(get_service_name)
        port_df['Port_Service'] = port_df.apply(
            lambda row: f"{row['Port']} ({row['Service']})" if row['Service'] != 'Unknown' else str(row['Port']), 
            axis=1
        )
        
        fig = px.bar(
            port_df, 
            x='Port_Service', 
            y='Count',
            color='Count',
            color_continuous_scale='Viridis',
            title='Top Services by Port'
        )
        
        fig.update_layout(xaxis_title="Port (Service)", height=350)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Port distribution data will appear here once monitoring begins")

def create_threat_visualizations():
    """Create threat visualization section"""
    st.subheader("⚠️ Threat Detection & Analysis")
    
    # Get alert history
    alert_history = st.session_state.alert_history
    
    if alert_history:
        # Create alert severity distribution
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for alert in alert_history:
            severity = alert.get('severity', 'Medium')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Convert to dataframe
        severity_df = pd.DataFrame([
            {'Severity': k, 'Count': v}
            for k, v in severity_counts.items() if v > 0
        ])
        
        # Use custom colors for severity
        severity_colors = {
            'Critical': '#FF0000',
            'High': '#FF6B00',
            'Medium': '#FFC107',
            'Low': '#4CAF50'
        }
        
        color_map = {row['Severity']: severity_colors[row['Severity']] 
                   for _, row in severity_df.iterrows()}
        
        # Create pie chart
        col1, col2 = st.columns([1, 2])
        
        with col1:
            fig = px.pie(
                severity_df,
                values='Count',
                names='Severity',
                title='Alert Severity Distribution',
                color='Severity',
                color_discrete_map=color_map
            )
            
            fig.update_layout(margin=dict(l=20, r=20, t=40, b=20), height=300)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Recent alerts table
            st.subheader("Recent Security Alerts")
            
            # Get 10 most recent alerts
            recent_alerts = alert_history[-10:] if len(alert_history) > 10 else alert_history
            recent_alerts.reverse()  # Show newest first
            
            # Create alert table
            alert_table_data = []
            for alert in recent_alerts:
                alert_table_data.append({
                    'Time': alert['timestamp'].split('T')[1][:8] if 'T' in alert['timestamp'] else alert['timestamp'],
                    'Source IP': alert['src_ip'],
                    'Destination IP': alert['dst_ip'],
                    'Protocol': alert['protocol'].upper(),
                    'Severity': alert['severity'],
                    'Description': alert['description']
                })
            
            alert_df = pd.DataFrame(alert_table_data)
            
            # Color-code severity
            def color_severity(val):
                color_map = {
                    'Critical': 'background-color: #FFCCCC',
                    'High': 'background-color: #FFDACC',
                    'Medium': 'background-color: #FFF9CC',
                    'Low': 'background-color: #DAFFCC'
                }
                return color_map.get(val, '')
            
            st.dataframe(
                alert_df.style.applymap(
                    color_severity, 
                    subset=['Severity']
                ),
                height=300
            )
        
        # Show alert time distribution
        st.subheader("Alert Timeline")
        
        # Extract timestamps and convert to datetime
        alert_times = []
        for alert in alert_history:
            timestamp = alert['timestamp']
            if 'T' in timestamp:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                try:
                    dt = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f')
                except:
                    dt = datetime.now() - timedelta(seconds=random.randint(0, 3600))
            alert_times.append({
                'timestamp': dt,
                'severity': alert['severity']
            })
        
        if alert_times:
            # Create dataframe
            timeline_df = pd.DataFrame(alert_times)
            timeline_df['count'] = 1
            
            # Aggregate by time (10-minute bins)
            timeline_df['time_bin'] = timeline_df['timestamp'].dt.floor('10min')
            agg_df = timeline_df.groupby(['time_bin', 'severity']).sum().reset_index()
            
            # Create line chart
            fig = px.line(
                agg_df,
                x='time_bin',
                y='count',
                color='severity',
                line_shape='linear',
                title='Alert Timeline (10-minute intervals)',
                color_discrete_map=severity_colors
            )
            
            fig.update_layout(
                xaxis_title="Time",
                yaxis_title="Number of Alerts",
                height=300
            )
            
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Alert data will appear here once monitoring begins and threats are detected")

def create_network_maps():
    """Create network maps and topology visualizations"""
    st.subheader("🗺️ Network Topology & Traffic Flows")
    
    # Get recent packets for flow analysis
    recent_packets = st.session_state.packet_history[-100:] if len(st.session_state.packet_history) > 100 else st.session_state.packet_history
    
    if recent_packets:
        # Extract source-destination pairs
        flows = []
        for packet in recent_packets:
            src = packet.get('src')
            dst = packet.get('dst')
            proto = packet.get('proto', 'other')
            is_malicious = packet.get('is_actually_malicious', False)
            
            if src and dst:
                flows.append({
                    'source': src,
                    'target': dst,
                    'protocol': proto,
                    'is_malicious': is_malicious
                })
        
        # Create network diagram
        if flows:
            # Get unique nodes
            nodes = set()
            for flow in flows:
                nodes.add(flow['source'])
                nodes.add(flow['target'])
            
            # Create node list
            node_list = []
            for i, node in enumerate(nodes):
                # Categorize nodes
                node_type = 'internal' if node.startswith(('192.168.', '10.', '172.16.')) else 'external'
                node_list.append({
                    'id': node,
                    'label': node,
                    'type': node_type
                })
            
            # Create edges between nodes
            edge_list = []
            for flow in flows:
                # Check if this edge already exists
                existing_edge = next((e for e in edge_list if e['source'] == flow['source'] and e['target'] == flow['target']), None)
                
                if existing_edge:
                    existing_edge['value'] += 1
                    if flow['is_malicious']:
                        existing_edge['is_malicious'] = True
                else:
                    edge_list.append({
                        'source': flow['source'],
                        'target': flow['target'],
                        'protocol': flow['protocol'],
                        'value': 1,
                        'is_malicious': flow['is_malicious']
                    })
            
            # Create network diagram using Plotly
            edge_x = []
            edge_y = []
            edge_colors = []
            
            # Create a simple circular layout for nodes
            node_positions = {}
            radius = 1
            angle_step = 2 * math.pi / len(node_list)
            
            for i, node in enumerate(node_list):
                angle = i * angle_step
                x = radius * math.cos(angle)
                y = radius * math.sin(angle)
                node_positions[node['id']] = (x, y)
            
            # Create edges
            for edge in edge_list:
                x0, y0 = node_positions[edge['source']]
                x1, y1 = node_positions[edge['target']]
                
                # Add line
                edge_x.extend([x0, x1, None])
                edge_y.extend([y0, y1, None])
                
                # Determine color based on protocol and maliciousness
                if edge['is_malicious']:
                    color = 'rgba(255, 0, 0, 0.6)'  # Red for malicious
                elif edge['protocol'] == 'tcp':
                    color = 'rgba(0, 0, 255, 0.4)'  # Blue for TCP
                elif edge['protocol'] == 'udp':
                    color = 'rgba(0, 255, 0, 0.4)'  # Green for UDP
                elif edge['protocol'] == 'icmp':
                    color = 'rgba(255, 165, 0, 0.4)'  # Orange for ICMP
                else:
                    color = 'rgba(150, 150, 150, 0.4)'  # Grey for others
                
                # Repeat the color for each segment (line + gap)
                edge_colors.extend([color, color, color])
            
            # Create edge trace
            edge_trace = go.Scatter(
                x=edge_x, y=edge_y,
                line=dict(width=1, color=edge_colors),
                hoverinfo='none',
                mode='lines'
            )
            
            # Create node trace
            node_x = []
            node_y = []
            node_text = []
            node_colors = []
            
            for node in node_list:
                x, y = node_positions[node['id']]
                node_x.append(x)
                node_y.append(y)
                node_text.append(node['id'])
                
                # Color internal nodes blue, external nodes red
                if node['type'] == 'internal':
                    node_colors.append('blue')
                else:
                    node_colors.append('red')
            
            node_trace = go.Scatter(
                x=node_x, y=node_y,
                mode='markers+text',
                hoverinfo='text',
                text=node_text,
                textposition="top center",
                marker=dict(
                    showscale=False,
                    color=node_colors,
                    size=15,
                    line_width=2
                )
            )
            
            # Create figure
            fig = go.Figure(data=[edge_trace, node_trace],
                          layout=go.Layout(
                              title='Network Traffic Flow Diagram',
                              titlefont_size=16,
                              showlegend=False,
                              hovermode='closest',
                              margin=dict(b=20, l=5, r=5, t=40),
                              xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                              yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                              height=500,
                              plot_bgcolor='rgba(240, 240, 240, 0.8)'
                          ))
            
            # Add color legend as annotations
            legend_items = [
                ('Internal Host', 'blue', -1.5, -1.3),
                ('External Host', 'red', -1.5, -1.4),
                ('TCP Traffic', 'rgba(0, 0, 255, 0.4)', -0.5, -1.3),
                ('UDP Traffic', 'rgba(0, 255, 0, 0.4)', -0.5, -1.4),
                ('ICMP Traffic', 'rgba(255, 165, 0, 0.4)', 0.5, -1.3),
                ('Malicious Traffic', 'rgba(255, 0, 0, 0.6)', 0.5, -1.4)
            ]
            
            for text, color, x, y in legend_items:
                fig.add_annotation(
                    x=x, y=y,
                    text=text,
                    showarrow=False,
                    font=dict(size=10, color="black"),
                    bgcolor=color,
                    bordercolor="black",
                    borderwidth=1,
                    borderpad=3,
                    opacity=0.8
                )
                
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Network flow data will appear here once sufficient traffic is captured")
    else:
        st.info("Network topology visualization will appear once monitoring begins")

def create_packet_inspection():
    """Create packet inspection section"""
    st.subheader("🔍 Deep Packet Inspection")
    
    # Get recent packets
    recent_packets = st.session_state.packet_history[-20:] if len(st.session_state.packet_history) > 20 else st.session_state.packet_history
    
    if recent_packets:
        # Reverse for newest first
        recent_packets = list(reversed(recent_packets))
        
        # Convert to dataframe for display
        packet_data = []
        for i, packet in enumerate(recent_packets):
            timestamp = packet.get('timestamp', '')
            if 'T' in timestamp:
                timestamp = timestamp.split('T')[1][:12]  # Extract time portion
                
            entry = {
                'Time': timestamp,
                'Source': packet.get('src', 'Unknown'),
                'Destination': packet.get('dst', 'Unknown'),
                'Protocol': packet.get('proto', 'Unknown').upper(),
                'Length': packet.get('len', 0),
                'Flags': hex(packet.get('flags', 0)) if 'flags' in packet else '-',
                'Src Port': packet.get('sport', '-') if 'sport' in packet else '-',
                'Dst Port': packet.get('dport', '-') if 'dport' in packet else '-',
                'Status': '⚠️ Malicious' if packet.get('is_actually_malicious', False) else '✅ Benign',
                '_packet': packet  # Store original packet for details view
            }
            packet_data.append(entry)
        
        packet_df = pd.DataFrame(packet_data)
        
        # Apply color formatting
        def color_status(val):
            if val == '⚠️ Malicious':
                return 'background-color: #FFCCCC'
            elif val == '✅ Benign':
                return 'background-color: #CCFFCC'
            return ''
        
        def color_protocol(val):
            colors = {
                'TCP': 'background-color: #CCE5FF',
                'UDP': 'background-color: #E5FFCC',
                'ICMP': 'background-color: #FFE5CC'
            }
            return colors.get(val, '')
        
        # Show dataframe
        st.dataframe(
            packet_df.drop('_packet', axis=1).style
                .applymap(color_status, subset=['Status'])
                .applymap(color_protocol, subset=['Protocol']),
            height=300
        )
        
        # Packet details inspector
        st.subheader("Packet Details")
        
        # Let user select a packet to inspect
        selected_idx = st.slider("Select Packet to Inspect", 0, len(packet_data) - 1, 0)
        selected_packet = packet_data[selected_idx]['_packet']
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Basic packet info
            st.subheader("Header Information")
            header_info = {
                'Timestamp': selected_packet.get('timestamp', ''),
                'Source IP': selected_packet.get('src', 'Unknown'),
                'Destination IP': selected_packet.get('dst', 'Unknown'),
                'Protocol': selected_packet.get('proto', 'Unknown').upper(),
                'Length': f"{selected_packet.get('len', 0)} bytes"
            }
            
            # Add protocol-specific fields
            if selected_packet.get('proto') == 'tcp':
                header_info.update({
                    'Source Port': selected_packet.get('sport', '-'),
                    'Destination Port': selected_packet.get('dport', '-'),
                    'TCP Flags': format_tcp_flags(selected_packet.get('flags', 0))
                })
            elif selected_packet.get('proto') == 'udp':
                header_info.update({
                    'Source Port': selected_packet.get('sport', '-'),
                    'Destination Port': selected_packet.get('dport', '-')
                })
            elif selected_packet.get('proto') == 'icmp':
                header_info.update({
                    'ICMP Type': selected_packet.get('icmp_type', '-'),
                    'ICMP Code': selected_packet.get('icmp_code', '-')
                })
            
            # Display as key-value pairs
            for key, value in header_info.items():
                st.text(f"{key}: {value}")
        
        with col2:
            # Payload inspection
            st.subheader("Payload Analysis")
            
            payload = selected_packet.get('payload', '')
            
            if payload:
                st.text_area("Raw Payload", payload, height=150)
                
                # Security analysis
                st.subheader("Security Analysis")
                risk_level = "Low"
                security_flags = []
                
                # Check for common attack patterns
                if selected_packet.get('is_actually_malicious', False):
                    risk_level = "High"
                    
                    if '<script>' in payload or 'onerror=' in payload:
                        security_flags.append("⚠️ XSS attack detected")
                    
                    if "'" in payload and ('SELECT' in payload.upper() or 'UNION' in payload.upper()):
                        security_flags.append("⚠️ SQL Injection attempt detected")
                    
                    if '--' in payload or ';' in payload and ('DROP' in payload.upper() or 'UPDATE' in payload.upper()):
                        security_flags.append("⚠️ SQL command injection detected")
                    
                    if '..' in payload and ('/' in payload or '\\' in payload):
                        security_flags.append("⚠️ Directory traversal attempt detected")
                    
                    if 'passwd' in payload.lower() or 'shadow' in payload.lower():
                        security_flags.append("⚠️ Sensitive file access attempt")
                    
                    # Add generic flag if none of the above
                    if not security_flags:
                        security_flags.append("⚠️ Suspicious traffic pattern detected")
                else:
                    security_flags.append("✅ No malicious patterns detected")
                
                # Display risk assessment
                st.markdown(f"**Risk Level: {risk_level}**")
                
                for flag in security_flags:
                    st.markdown(flag)
            else:
                st.info("No payload data available for this packet")
    else:
        st.info("Packet inspection data will appear once monitoring begins")

def get_service_name(port):
    """Get service name from port number"""
    common_ports = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        67: 'DHCP Server',
        68: 'DHCP Client',
        80: 'HTTP',
        110: 'POP3',
        123: 'NTP',
        143: 'IMAP',
        161: 'SNMP',
        443: 'HTTPS',
        445: 'SMB',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MS SQL',
        1521: 'Oracle',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        8080: 'HTTP Proxy',
        8443: 'HTTPS Alt'
    }
    return common_ports.get(port, 'Unknown')

def format_tcp_flags(flags):
    """Format TCP flags for display"""
    if flags is None:
        return "None"
        
    flag_names = []
    if flags & 0x01:
        flag_names.append("FIN")
    if flags & 0x02:
        flag_names.append("SYN")
    if flags & 0x04:
        flag_names.append("RST")
    if flags & 0x08:
        flag_names.append("PSH")
    if flags & 0x10:
        flag_names.append("ACK")
    if flags & 0x20:
        flag_names.append("URG")
    if flags & 0x40:
        flag_names.append("ECE")
    if flags & 0x80:
        flag_names.append("CWR")
    
    if flag_names:
        return f"0x{flags:02x} ({', '.join(flag_names)})"
    return f"0x{flags:02x}"

def format_bytes(size_bytes):
    """Format bytes to human-readable size"""
    if size_bytes == 0:
        return "0 B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"