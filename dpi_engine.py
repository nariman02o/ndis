import re
import json
from collections import Counter
import numpy as np

class DPIEngine:
    """
    Deep Packet Inspection Engine for analyzing packet payloads
    """
    def __init__(self):
        self.is_enabled = True
        self.signature_patterns = self._load_default_signatures()
        self.content_type_patterns = {
            'http': re.compile(rb'HTTP/\d\.\d|GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE', re.IGNORECASE),
            'dns': re.compile(rb'\x00\x00\x01\x00\x00\x01|\x00\x01\x00\x00\x01', re.IGNORECASE),
            'ssh': re.compile(rb'SSH-\d\.\d', re.IGNORECASE),
            'ftp': re.compile(rb'220 .* FTP|230 Login successful', re.IGNORECASE),
            'smtp': re.compile(rb'220 .* SMTP|EHLO|HELO|MAIL FROM|RCPT TO', re.IGNORECASE),
            'ssl': re.compile(rb'\x16\x03[\x00\x01\x02\x03]|\x16\xfe[\xff]', re.IGNORECASE),
            'json': re.compile(rb'^\s*\{.*\}\s*$', re.DOTALL),
            'xml': re.compile(rb'^\s*<\?xml|^\s*<[a-zA-Z0-9]+', re.IGNORECASE)
        }
        
    def _load_default_signatures(self):
        """
        Load default attack signatures for payload inspection
        """
        signatures = {
            'sql_injection': re.compile(rb'(?i)(\b(select|update|insert|delete|drop|alter|union)\b.*\b(from|table|where)\b|(\%27)|(\'\s*--)|(\'\s*\Z)|(\'\s*#)|(\'\s*\/\*))', re.IGNORECASE | re.DOTALL),
            'xss': re.compile(rb'(?i)(<script.*?>.*?<\/script>|<.*?javascript:.*?>|<.*?onmouse.*?>|<.*?on\w+\s*=.*?>)', re.IGNORECASE | re.DOTALL),
            'command_injection': re.compile(rb'(?i)(;|\||\`|\$\(|\$\{).*?(\/bin\/|\/etc\/|\/usr\/|\/tmp\/)', re.IGNORECASE | re.DOTALL),
            'path_traversal': re.compile(rb'(?i)(\.\.\/|\.\.\\|\.\.\x5c)', re.IGNORECASE),
            'file_inclusion': re.compile(rb'(?i)(=.*?\.\.\/.*?\.(php|asp|aspx|jsp))', re.IGNORECASE),
            'denial_of_service': re.compile(rb'(?i)(slowloris|r-u-dead-yet|torshammer)', re.IGNORECASE),
            'malware_communication': re.compile(rb'(?i)(botnet|backdoor|trojan|ransomware)', re.IGNORECASE),
            'sensitive_data': re.compile(rb'(?i)(password=|passwd=|pwd=|creditcard=|credit_card=|cc=|ssn=|socialsecurity=|social_security=)', re.IGNORECASE)
        }
        return signatures
    
    def enable(self):
        """Enable DPI engine"""
        self.is_enabled = True
    
    def disable(self):
        """Disable DPI engine"""
        self.is_enabled = False
    
    def add_signature(self, name, pattern):
        """
        Add a new signature pattern for detection
        """
        try:
            compiled_pattern = re.compile(pattern, re.IGNORECASE | re.DOTALL)
            self.signature_patterns[name] = compiled_pattern
            return True
        except Exception as e:
            print(f"Error adding signature: {str(e)}")
            return False
    
    def remove_signature(self, name):
        """
        Remove a signature pattern
        """
        if name in self.signature_patterns:
            del self.signature_patterns[name]
            return True
        return False
    
    def analyze_payload(self, payload):
        """
        Analyze packet payload for suspicious patterns
        Returns a dictionary with detection results
        """
        if not self.is_enabled or not payload:
            return {
                'content_type': 'unknown',
                'detections': [],
                'entropy': 0.0,
                'printable_ratio': 0.0,
                'byte_frequency': {},
                'payload_size': 0
            }
        
        # Convert payload to bytes if it's not already
        if isinstance(payload, str):
            try:
                payload_bytes = payload.encode('utf-8')
            except UnicodeError:
                payload_bytes = payload.encode('latin-1')
        elif isinstance(payload, dict) or isinstance(payload, list):
            try:
                payload_bytes = json.dumps(payload).encode('utf-8')
            except:
                payload_bytes = str(payload).encode('utf-8')
        else:
            payload_bytes = payload if isinstance(payload, bytes) else bytes(payload)
        
        # Calculate basic payload statistics
        payload_size = len(payload_bytes)
        entropy = self._calculate_entropy(payload_bytes)
        printable_ratio = self._calculate_printable_ratio(payload_bytes)
        
        # Calculate byte frequency for potential analysis
        byte_counter = Counter(payload_bytes)
        top_bytes = {hex(k): v/payload_size for k, v in byte_counter.most_common(10)}
        
        # Identify content type
        content_type = self._identify_content_type(payload_bytes)
        
        # Check against signature patterns
        detections = []
        for sig_name, pattern in self.signature_patterns.items():
            if pattern.search(payload_bytes):
                detections.append(sig_name)
        
        # Prepare result
        result = {
            'content_type': content_type,
            'detections': detections,
            'entropy': entropy,
            'printable_ratio': printable_ratio,
            'byte_frequency': top_bytes,
            'payload_size': payload_size
        }
        
        return result
    
    def _calculate_entropy(self, data):
        """
        Calculate Shannon entropy of data
        High entropy (closer to 8.0) may indicate encryption, compression, or obfuscation
        """
        if not data:
            return 0.0
            
        byte_counts = Counter(data)
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / len(data)
            entropy -= probability * np.log2(probability)
        return entropy
    
    def _calculate_printable_ratio(self, data):
        """
        Calculate ratio of printable ASCII characters to total bytes
        Low ratios may indicate binary/encrypted data
        """
        if not data:
            return 0.0
            
        printable_count = sum(1 for b in data if 32 <= b <= 126)
        return printable_count / len(data)
    
    def _identify_content_type(self, data):
        """
        Try to identify the content type of the payload
        """
        for content_type, pattern in self.content_type_patterns.items():
            if pattern.search(data):
                return content_type
        
        # If we can't identify a specific type
        if self._calculate_printable_ratio(data) > 0.8:
            return 'text'
        return 'binary'
    
    def extract_features(self, payload):
        """
        Extract features from payload for model input
        Returns a list of numerical features
        """
        if not self.is_enabled or not payload:
            return [0.0] * 15  # Return zeros if DPI is disabled
        
        analysis = self.analyze_payload(payload)
        
        # Convert content type to one-hot features
        content_type_one_hot = [0] * 8  # For the 8 content types
        content_types = list(self.content_type_patterns.keys())
        
        if analysis['content_type'] in content_types:
            idx = content_types.index(analysis['content_type'])
            content_type_one_hot[idx] = 1
        
        # Create numerical features
        features = [
            analysis['entropy'],
            analysis['printable_ratio'],
            analysis['payload_size'],
            len(analysis['detections']),  # Number of signature matches
        ]
        
        # Add detection flags
        detection_types = [
            'sql_injection', 'xss', 'command_injection', 
            'path_traversal', 'file_inclusion', 'denial_of_service',
            'malware_communication', 'sensitive_data'
        ]
        
        detection_flags = [1 if d in analysis['detections'] else 0 for d in detection_types]
        
        # Combine all features
        all_features = features + detection_flags + content_type_one_hot
        
        return all_features
