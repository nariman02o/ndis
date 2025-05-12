import os
import pandas as pd
import numpy as np
import requests
import zipfile
import io
from data_preprocessing import DataPreprocessor

class DatasetHandler:
    """
    Class for handling the CICIoT2023 dataset
    - Download dataset if not available
    - Prepare dataset for training
    - Provide sample packets for simulation
    """
    def __init__(self, dataset_dir="./data"):
        self.dataset_dir = dataset_dir
        self.dataset_path = os.path.join(dataset_dir, "CICIoT2023.csv")
        self.sample_packets_path = os.path.join(dataset_dir, "sample_packets.csv")
        self.preprocessor = DataPreprocessor()
        self.dataset_url = "https://www.unb.ca/cic/datasets/iotdataset-2023.html"  # Replace with direct URL when available
        self.sample_packets = None
        
        # Create data directory if it doesn't exist
        if not os.path.exists(dataset_dir):
            os.makedirs(dataset_dir)
    
    def check_dataset_availability(self):
        """
        Check if the dataset is available locally
        """
        return os.path.exists(self.dataset_path)
    
    def download_dataset(self):
        """
        Download the CICIoT2023 dataset if not available locally
        Note: This requires the direct download link which may not be publicly available
        """
        if self.check_dataset_availability():
            print(f"Dataset already exists at {self.dataset_path}")
            return True
        
        print(f"Dataset not found. Attempting to download from {self.dataset_url}")
        
        try:
            # This is a placeholder for the actual download logic
            # The CICIoT2023 dataset might require registration or specific access
            # Replace this with the correct download URL when available
            
            print("The CICIoT2023 dataset requires manual download.")
            print("Please visit the following URL to download the dataset:")
            print(self.dataset_url)
            print(f"Then place the dataset in {self.dataset_path}")
            
            return False
        except Exception as e:
            print(f"Error downloading dataset: {str(e)}")
            return False
    
    def prepare_dataset(self):
        """
        Prepare the dataset for training
        - Load and clean the dataset
        - Extract features and labels
        """
        if not self.check_dataset_availability():
            success = self.download_dataset()
            if not success:
                return None
        
        try:
            # Load the dataset
            df = self.preprocessor.load_dataset(self.dataset_path)
            
            # Clean the dataset
            df_clean = self.preprocessor.clean_data(df)
            
            # Identify target column
            target_column = None
            potential_targets = ['label', 'class', 'attack_type', 'is_attack', 'is_malicious']
            
            for col in potential_targets:
                if col in df_clean.columns:
                    target_column = col
                    break
            
            if not target_column:
                raise ValueError("Could not identify target column in dataset")
            
            # Preprocess data
            X, y = self.preprocessor.preprocess_data(df_clean, target_column=target_column, train=True)
            
            return X, y
        except Exception as e:
            print(f"Error preparing dataset: {str(e)}")
            return None
    
    def create_sample_packets(self, sample_size=1000, save=True):
        """
        Create sample packets from the dataset for simulation
        """
        if not self.check_dataset_availability():
            print("Dataset not available. Cannot create sample packets.")
            return None
        
        try:
            # Load the dataset
            df = pd.read_csv(self.dataset_path)
            
            # Take a random sample
            sample_df = df.sample(min(sample_size, len(df)), random_state=42)
            
            # Convert dataset rows to packet format
            packets = []
            
            for _, row in sample_df.iterrows():
                packet = self._convert_row_to_packet(row)
                packets.append(packet)
            
            # Save sample packets
            if save:
                sample_packets_df = pd.DataFrame(packets)
                sample_packets_df.to_csv(self.sample_packets_path, index=False)
                print(f"Sample packets saved to {self.sample_packets_path}")
            
            self.sample_packets = packets
            return packets
        except Exception as e:
            print(f"Error creating sample packets: {str(e)}")
            return None
    
    def _convert_row_to_packet(self, row):
        """
        Convert a dataset row to a packet format compatible with the packet analyzer
        """
        # This conversion depends on the specific structure of the CICIoT2023 dataset
        # The following is a generalized approach that may need adjustment
        
        packet = {}
        
        # Basic packet info
        if 'src_ip' in row:
            packet['src'] = row['src_ip']
        elif 'src' in row:
            packet['src'] = row['src']
        else:
            packet['src'] = '192.168.1.1'  # Default
        
        if 'dst_ip' in row:
            packet['dst'] = row['dst_ip']
        elif 'dst' in row:
            packet['dst'] = row['dst']
        else:
            packet['dst'] = '192.168.1.2'  # Default
        
        # Ports
        if 'src_port' in row:
            packet['sport'] = int(row['src_port'])
        else:
            packet['sport'] = 1024  # Default
        
        if 'dst_port' in row:
            packet['dport'] = int(row['dst_port'])
        else:
            packet['dport'] = 80  # Default
        
        # Protocol
        if 'protocol' in row:
            packet['proto'] = row['protocol']
        else:
            packet['proto'] = 'tcp'  # Default
        
        # Packet length
        if 'pkt_len' in row:
            packet['len'] = int(row['pkt_len'])
        elif 'packet_length' in row:
            packet['len'] = int(row['packet_length'])
        else:
            packet['len'] = 128  # Default
        
        # TCP flags
        if 'tcp_flags' in row:
            packet['flags'] = int(row['tcp_flags'])
        else:
            packet['flags'] = 16 if packet['proto'] == 'tcp' else 0  # Default (ACK)
        
        # TTL
        if 'ttl' in row:
            packet['ttl'] = int(row['ttl'])
        else:
            packet['ttl'] = 64  # Default
        
        # Timestamp
        if 'timestamp' in row:
            packet['timestamp'] = row['timestamp']
        else:
            packet['timestamp'] = pd.Timestamp.now().isoformat()
        
        # Payload (simplified for simulation)
        if 'payload' in row:
            packet['payload'] = row['payload']
        else:
            # Generate synthetic payload based on protocol
            if packet['proto'] == 'http' or packet['dport'] == 80:
                packet['payload'] = 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
            elif packet['proto'] == 'dns' or packet['dport'] == 53:
                packet['payload'] = '\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            else:
                packet['payload'] = 'test_payload'
        
        # Malicious flag (for simulation)
        if 'label' in row:
            label = row['label']
            if isinstance(label, str):
                packet['is_actually_malicious'] = label.lower() != 'benign'
            else:
                packet['is_actually_malicious'] = bool(label)
        elif 'is_attack' in row:
            packet['is_actually_malicious'] = bool(row['is_attack'])
        else:
            packet['is_actually_malicious'] = False
        
        return packet
    
    def get_sample_packets(self, count=10):
        """
        Get a sample of packets for simulation
        """
        if self.sample_packets is None:
            self.create_sample_packets()
        
        if not self.sample_packets:
            return []
        
        # Return random packets from the sample
        indices = np.random.choice(len(self.sample_packets), min(count, len(self.sample_packets)), replace=False)
        return [self.sample_packets[i] for i in indices]
