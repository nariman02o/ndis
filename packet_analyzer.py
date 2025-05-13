import numpy as np
import json
import struct
from datetime import datetime
import ipaddress
import logging
from fpga_interface import fpga_interface

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PacketAnalyzer")

class PacketAnalyzer:
    """
    Class for analyzing network packets and extracting features
    for the reinforcement learning model with optional FPGA acceleration
    """
    def __init__(self, dpi_engine):
        self.dpi_engine = dpi_engine
        self.fpga_interface = fpga_interface
        self.hardware_acceleration = True  # Default to hardware acceleration if available

        # Initialize FPGA hardware acceleration if available
        if self.fpga_interface.is_acceleration_enabled():
            logger.info("FPGA hardware acceleration is available and enabled")
        else:
            logger.info("FPGA hardware acceleration is not available, using software processing")
        # Common ports and their services
        self.common_ports = {
            20: 'ftp_data', 21: 'ftp_control',
            22: 'ssh', 23: 'telnet',
            25: 'smtp', 53: 'dns',
            80: 'http', 443: 'https',
            67: 'dhcp_server', 68: 'dhcp_client',
            110: 'pop3', 143: 'imap',
            161: 'snmp', 162: 'snmp_trap',
            389: 'ldap', 636: 'ldaps',
            137: 'netbios_ns', 138: 'netbios_dgm', 139: 'netbios_ssn',
            445: 'smb',
            3389: 'rdp',
            1433: 'mssql', 1521: 'oracle', 3306: 'mysql', 5432: 'postgresql',
            8080: 'http_alt', 8443: 'https_alt',
            5060: 'sip', 5061: 'sips'
        }

        # Protocol numbers
        self.protocols = {
            1: 'icmp', 6: 'tcp', 17: 'udp', 
            47: 'gre', 50: 'esp', 51: 'ah', 
            58: 'ipv6-icmp', 89: 'ospf', 
            132: 'sctp'
        }

        # Initialize feature extractors
        self.header_feature_extractors = {
            'source_ip_public': self._source_ip_public,
            'dest_ip_public': self._dest_ip_public,
            'source_port_numeric': self._source_port_numeric,
            'dest_port_numeric': self._dest_port_numeric,
            'protocol_tcp': self._protocol_tcp,
            'protocol_udp': self._protocol_udp,
            'protocol_icmp': self._protocol_icmp,
            'packet_size': self._packet_size,
            'tcp_flags': self._tcp_flags,
            'fragment': self._fragment,
            'ttl': self._ttl,
            'common_port': self._common_port
        }

    def extract_features(self, packet):
        """
        Extract features from a packet for model input
        with optional hardware acceleration
        """
        try:
            if not packet:
                return np.zeros(100)  # Return zero features for empty packets

            # Check if hardware acceleration is enabled and available
            if self.hardware_acceleration and self.fpga_interface.is_acceleration_enabled():
                try:
                    # Offload feature extraction to FPGA hardware
                    logger.debug(f"Using FPGA hardware acceleration for packet processing")

                    # Process packet with FPGA hardware
                    fpga_result = self.fpga_interface.process_packet(packet)

                    # Extract features from FPGA hardware result
                    header_features = np.array(list(fpga_result['header_features'].values()))

                    # Extract payload features if DPI is enabled
                    payload = packet.get('payload', None)
                    if payload and self.dpi_engine.is_enabled:
                        if 'payload_features' in fpga_result:
                            # Use FPGA-extracted payload features
                            payload_features = np.array(fpga_result['payload_features']['statistical_features'])
                        else:
                            # Fall back to software DPI if not available in FPGA result
                            payload_features = np.array(self.dpi_engine.extract_features(payload))
                    else:
                        # If no payload or DPI disabled, use zero features
                        payload_features = np.array([0.0] * 15)  # Match the size in DPIEngine.extract_features

                    # Combine features
                    combined_features = np.concatenate([header_features, payload_features])
                    return combined_features

                except Exception as e:
                    logger.warning(f"FPGA acceleration failed: {str(e)}. Falling back to software processing.")
                    # Fall back to software processing

            # Software processing (either by choice or as fallback)
            # Extract header features
            header_features = self._extract_header_features(packet)

            # Extract payload features if DPI is enabled
            payload = packet.get('payload', None)
            if payload and self.dpi_engine.is_enabled:
                payload_features = np.array(self.dpi_engine.extract_features(payload))
            else:
                # If no payload or DPI disabled, use zero features
                payload_features = np.array([0.0] * 15)  # Match the size in DPIEngine.extract_features

            # Combine features
            combined_features = np.concatenate([header_features, payload_features])

            return combined_features
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return np.zeros(100) # Return zero features upon failure

    def _extract_header_features(self, packet):
        """
        Extract features from packet header
        """
        features = []

        # Apply each feature extractor
        for extractor_name, extractor_func in self.header_feature_extractors.items():
            try:
                feature_value = extractor_func(packet)
                features.append(feature_value)
            except Exception as e:
                # If extraction fails, use a default value
                print(f"Error extracting {extractor_name}: {str(e)}")
                features.append(0.0)

        # Special case for flow-based features
        features.append(self._calculate_flow_duration(packet))
        features.append(self._calculate_packet_rate(packet))
        features.append(self._calculate_byte_rate(packet))

        return np.array(features)

    def _source_ip_public(self, packet):
        """Check if source IP is public (1.0) or private (0.0)"""
        src_ip = packet.get('src', '0.0.0.0')
        try:
            ip = ipaddress.ip_address(src_ip)
            return 1.0 if not ip.is_private else 0.0
        except:
            return 0.0

    def _dest_ip_public(self, packet):
        """Check if destination IP is public (1.0) or private (0.0)"""
        dst_ip = packet.get('dst', '0.0.0.0')
        try:
            ip = ipaddress.ip_address(dst_ip)
            return 1.0 if not ip.is_private else 0.0
        except:
            return 0.0

    def _source_port_numeric(self, packet):
        """Normalize source port to 0-1 range"""
        sport = packet.get('sport', 0)
        return min(float(sport) / 65535.0, 1.0)

    def _dest_port_numeric(self, packet):
        """Normalize destination port to 0-1 range"""
        dport = packet.get('dport', 0)
        return min(float(dport) / 65535.0, 1.0)

    def _protocol_tcp(self, packet):
        """Is TCP protocol (1.0) or not (0.0)"""
        return 1.0 if packet.get('proto', '').lower() == 'tcp' else 0.0

    def _protocol_udp(self, packet):
        """Is UDP protocol (1.0) or not (0.0)"""
        return 1.0 if packet.get('proto', '').lower() == 'udp' else 0.0

    def _protocol_icmp(self, packet):
        """Is ICMP protocol (1.0) or not (0.0)"""
        return 1.0 if packet.get('proto', '').lower() == 'icmp' else 0.0

    def _packet_size(self, packet):
        """Normalize packet size (bytes) to 0-1 range, assuming max 65535"""
        size = packet.get('len', 0)
        return min(float(size) / 65535.0, 1.0)

    def _tcp_flags(self, packet):
        """Extract TCP flags as feature"""
        if packet.get('proto', '').lower() != 'tcp':
            return 0.0

        flags = packet.get('flags', 0)

        # Normalize flags (assuming 8-bit field)
        return float(flags) / 255.0 if flags is not None else 0.0

    def _fragment(self, packet):
        """Is packet fragmented (1.0) or not (0.0)"""
        return 1.0 if packet.get('frag', False) else 0.0

    def _ttl(self, packet):
        """Normalize TTL to 0-1 range, assuming max 255"""
        ttl = packet.get('ttl', 0)
        return float(ttl) / 255.0

    def _common_port(self, packet):
        """Is packet using a common/well-known port (1.0) or not (0.0)"""
        sport = packet.get('sport', 0)
        dport = packet.get('dport', 0)
        return 1.0 if sport in self.common_ports or dport in self.common_ports else 0.0

    def _calculate_flow_duration(self, packet):
        """
        Calculate normalized flow duration
        For a single packet, this is 0.0
        For packets with flow information, normalize to 0-1 range assuming max 3600s (1h)
        """
        flow_start = packet.get('flow_start_time', None)
        flow_end = packet.get('flow_end_time', None)

        if flow_start is None or flow_end is None:
            return 0.0

        try:
            # Convert to datetime if they are strings
            if isinstance(flow_start, str):
                flow_start = datetime.fromisoformat(flow_start)
            if isinstance(flow_end, str):
                flow_end = datetime.fromisoformat(flow_end)

            duration = (flow_end - flow_start).total_seconds()
            return min(duration / 3600.0, 1.0)  # Normalize to 0-1 with max 1 hour
        except:
            return 0.0

    def _calculate_packet_rate(self, packet):
        """
        Calculate normalized packet rate (packets per second)
        For a single packet or without flow info, this is 0.0
        Normalize to 0-1 range assuming max 1000 packets per second
        """
        flow_duration = self._calculate_flow_duration(packet) * 3600  # Convert back to seconds
        packet_count = packet.get('flow_packet_count', 1)

        if flow_duration > 0:
            return min(float(packet_count) / flow_duration / 1000.0, 1.0)
        return 0.0

    def _calculate_byte_rate(self, packet):
        """
        Calculate normalized byte rate (bytes per second)
        For a single packet or without flow info, use packet size
        Normalize to 0-1 range assuming max 1,000,000 bytes per second (1 MB/s)
        """
        flow_duration = self._calculate_flow_duration(packet) * 3600  # Convert back to seconds
        byte_count = packet.get('flow_byte_count', packet.get('len', 0))

        if flow_duration > 0:
            return min(float(byte_count) / flow_duration / 1000000.0, 1.0)
        return min(float(byte_count) / 1000000.0, 1.0)

    def enable_hardware_acceleration(self):
        """Enable FPGA hardware acceleration"""
        self.hardware_acceleration = True
        self.fpga_interface.enable_acceleration()
        logger.info("FPGA hardware acceleration enabled")
        return True

    def disable_hardware_acceleration(self):
        """Disable FPGA hardware acceleration"""
        self.hardware_acceleration = False
        self.fpga_interface.disable_acceleration()
        logger.info("FPGA hardware acceleration disabled, using software processing")
        return True

    def get_hardware_acceleration_status(self):
        """Get the status of hardware acceleration"""
        return {
            "enabled": self.hardware_acceleration,
            "available": self.fpga_interface.is_acceleration_enabled(),
            "performance": self.fpga_interface.get_performance_metrics()
        }

    def analyze_packet(self, packet):
        """
        Perform a full analysis of a packet for visualization and reporting
        Returns a dictionary with detailed analysis results
        Uses FPGA acceleration when available
        """
        # Check if FPGA acceleration is enabled
        fpga_result = None
        if self.hardware_acceleration and self.fpga_interface.is_acceleration_enabled():
            try:
                # Process packet with FPGA hardware
                fpga_result = self.fpga_interface.process_packet(packet)
                logger.debug("Using FPGA hardware acceleration for packet analysis")
            except Exception as e:
                logger.warning(f"FPGA acceleration failed during analysis: {str(e)}")
                fpga_result = None

        # Basic packet information (use FPGA results if available)
        if fpga_result and 'header_features' in fpga_result:
            hf = fpga_result['header_features']
            analysis = {
                'timestamp': packet.get('timestamp', datetime.now().isoformat()),
                'src_ip': hf.get('src_ip', packet.get('src', 'unknown')),
                'dst_ip': hf.get('dst_ip', packet.get('dst', 'unknown')),
                'src_port': hf.get('src_port', packet.get('sport', 0)),
                'dst_port': hf.get('dst_port', packet.get('dport', 0)),
                'protocol': hf.get('protocol', packet.get('proto', 'unknown')),
                'length': hf.get('length', packet.get('len', 0)),
                'hardware_accelerated': True,
                'processing_mode': fpga_result.get('processing_mode', 'hardware_simulated')
            }
        else:
            # Use software processing
            analysis = {
                'timestamp': packet.get('timestamp', datetime.now().isoformat()),
                'src_ip': packet.get('src', 'unknown'),
                'dst_ip': packet.get('dst', 'unknown'),
                'src_port': packet.get('sport', 0),
                'dst_port': packet.get('dport', 0),
                'protocol': packet.get('proto', 'unknown'),
                'length': packet.get('len', 0),
                'hardware_accelerated': False,
                'processing_mode': 'software'
            }

        # Add port service names if known
        src_port = analysis['src_port']
        dst_port = analysis['dst_port']

        if src_port in self.common_ports:
            analysis['src_service'] = self.common_ports[src_port]
        else:
            analysis['src_service'] = 'unknown'

        if dst_port in self.common_ports:
            analysis['dst_service'] = self.common_ports[dst_port]
        else:
            analysis['dst_service'] = 'unknown'

        # TCP-specific information
        if analysis['protocol'].lower() == 'tcp':
            flags = packet.get('flags', 0)
            flag_names = []

            if flags & 0x01:
                flag_names.append('FIN')
            if flags & 0x02:
                flag_names.append('SYN')
            if flags & 0x04:
                flag_names.append('RST')
            if flags & 0x08:
                flag_names.append('PSH')
            if flags & 0x10:
                flag_names.append('ACK')
            if flags & 0x20:
                flag_names.append('URG')

            analysis['tcp_flags'] = flag_names
            analysis['tcp_window'] = packet.get('window', 0)

        # ICMP-specific information
        if analysis['protocol'].lower() == 'icmp':
            analysis['icmp_type'] = packet.get('icmp_type', 0)
            analysis['icmp_code'] = packet.get('icmp_code', 0)

        # Payload analysis (use FPGA results if available)
        if fpga_result and 'payload_features' in fpga_result and self.dpi_engine.is_enabled:
            # Use payload analysis from FPGA
            analysis['payload'] = {
                'entropy': fpga_result['payload_features'].get('entropy', 0),
                'printable_ratio': fpga_result['payload_features'].get('printable_ratio', 0),
                'suspicious_patterns': [],  # FPGA doesn't do pattern matching in our implementation
                'content_type': 'unknown'
            }
        elif 'payload' in packet and packet['payload'] and self.dpi_engine.is_enabled:
            # Software payload analysis
            payload_analysis = self.dpi_engine.analyze_payload(packet['payload'])
            analysis['payload'] = payload_analysis
        else:
            analysis['payload'] = None

        # Extract features with hardware acceleration if available
        features = self.extract_features(packet)
        analysis['features'] = features.tolist()

        # Add FPGA performance metrics if hardware accelerated
        if analysis.get('hardware_accelerated', False):
            performance = self.fpga_interface.get_performance_metrics()
            analysis['fpga_metrics'] = {
                'avg_processing_time': performance.get('avg_processing_time', 0),
                'packets_processed': performance.get('packets_processed', 0)
            }

        return analysis