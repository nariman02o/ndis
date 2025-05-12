"""
FPGA Interface for PYNQ-Z1 board integration with the NIDS system

This module provides an interface for running the NIDS application directly on the 
PYNQ-Z1 FPGA board, enabling hardware acceleration of packet processing and 
machine learning inference.

PYNQ-Z1 Details:
- Xilinx Zynq-7000 SoC (XC7Z020-1CLG400C)
- Dual-core ARM Cortex-A9 processor (PS)
- Artix-7 FPGA programmable logic (PL)
- 13,300 logic slices, 630KB BRAM, 220 DSP slices
- 512MB DDR3 memory
- 100MHz clock
"""

import numpy as np
import json
import time
import random  # for simulation when running on non-PYNQ systems
import logging
import os
import sys

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FPGA-Interface")

# Check if running on a PYNQ-Z1 board
def is_running_on_pynq():
    """Detect if code is running on a PYNQ-Z1 board"""
    try:
        # Check for PYNQ-specific paths and files
        if os.path.exists('/usr/local/share/pynq-venv'):
            return True
        if os.path.exists('/home/xilinx') and os.path.exists('/sys/bus/platform/drivers/xdma'):
            return True
        return False
    except:
        return False

# Determine if we're running on actual PYNQ hardware
ON_PYNQ_HARDWARE = is_running_on_pynq()

# Try to import PYNQ-specific libraries if running on PYNQ hardware
if ON_PYNQ_HARDWARE:
    try:
        from pynq import Overlay
        from pynq import allocate
        import pynq.lib.dma
        PYNQ_IMPORTS_SUCCESSFUL = True
    except ImportError:
        logger.warning("Running on PYNQ hardware but couldn't import PYNQ libraries")
        PYNQ_IMPORTS_SUCCESSFUL = False
else:
    PYNQ_IMPORTS_SUCCESSFUL = False

class FPGAInterface:
    """
    Interface for communicating with PYNQ-Z1 FPGA
    
    This class handles the communication between the NIDS software and the FPGA hardware,
    including feature extraction acceleration and model inference offloading.
    
    When running directly on the PYNQ-Z1 board, this interface provides direct access to
    the hardware accelerators implemented in the programmable logic.
    """
    
    def __init__(self, simulation_mode=None, bitstream_path="./pynq_overlay/nids_overlay.bit"):
        """
        Initialize the FPGA interface
        
        Args:
            simulation_mode (bool): If None, auto-detect based on hardware.
                                  If True, force simulation mode.
                                  If False, force hardware mode.
            bitstream_path (str): Path to the FPGA bitstream file
        """
        # Auto-detect if simulation_mode is not specified
        if simulation_mode is None:
            self.simulation_mode = not (ON_PYNQ_HARDWARE and PYNQ_IMPORTS_SUCCESSFUL)
        else:
            self.simulation_mode = simulation_mode
            
        self.initialized = False
        self.acceleration_enabled = False
        self.bitstream_path = bitstream_path
        self.overlay = None
        self.dma = None
        self.offload_features = ["header_processing", "payload_analysis", "ml_inference"]
        
        # Performance metrics
        self.performance = {
            "packets_processed": 0,
            "hardware_accelerated": 0,
            "software_processed": 0,
            "avg_processing_time": 0.0,
            "total_processing_time": 0.0
        }
        
        # Try to initialize the FPGA connection
        if not self.simulation_mode:
            try:
                self._initialize_fpga_connection()
            except Exception as e:
                logger.warning(f"Failed to initialize FPGA hardware: {str(e)}")
                logger.info("Falling back to simulation mode")
                self.simulation_mode = True
        
        # Initialize simulation mode if hardware connection failed or wasn't attempted
        if self.simulation_mode:
            logger.info("Running in FPGA simulation mode")
            self._initialize_simulation()
        
        self.initialized = True
        logger.info("FPGA Interface initialized successfully")
    
    def _initialize_fpga_connection(self):
        """
        Initialize connection to the PYNQ-Z1 FPGA hardware
        
        This method loads the bitstream and configures the programmable logic
        on the PYNQ-Z1 board.
        """
        try:
            # Check if we're running on PYNQ hardware
            if not ON_PYNQ_HARDWARE:
                raise RuntimeError("Not running on PYNQ hardware")
                
            # Check if PYNQ libraries were imported successfully
            if not PYNQ_IMPORTS_SUCCESSFUL:
                raise ImportError("PYNQ libraries not available")
            
            # Load the bitstream to configure the FPGA
            logger.info(f"Loading FPGA bitstream from {self.bitstream_path}")
            self.overlay = Overlay(self.bitstream_path)
            
            # Access hardware accelerators and DMA engines defined in the overlay
            self.dma = self.overlay.axi_dma_0
            
            # Allocate memory buffers for DMA transfers
            self.input_buffer = allocate(shape=(100,), dtype=np.float32)
            self.output_buffer = allocate(shape=(2,), dtype=np.float32)
            
            logger.info("FPGA hardware connection initialized")
            self.acceleration_enabled = True
            
        except ImportError:
            logger.error("PYNQ library not found. Cannot connect to FPGA hardware.")
            raise
        except Exception as e:
            logger.error(f"Error initializing FPGA hardware: {str(e)}")
            raise
    
    def _initialize_simulation(self):
        """
        Initialize simulation mode for testing without FPGA hardware
        """
        logger.info("Initializing FPGA simulation mode")
        self.acceleration_enabled = True
    
    def enable_acceleration(self):
        """Enable FPGA acceleration"""
        self.acceleration_enabled = True
        logger.info("FPGA acceleration enabled")
        return True
    
    def disable_acceleration(self):
        """Disable FPGA acceleration"""
        self.acceleration_enabled = False
        logger.info("FPGA acceleration disabled")
        return True
    
    def is_acceleration_enabled(self):
        """Check if acceleration is enabled"""
        return self.acceleration_enabled
    
    def get_performance_metrics(self):
        """Get performance metrics of FPGA acceleration"""
        return self.performance
    
    def reset_performance_metrics(self):
        """Reset performance metrics"""
        self.performance = {
            "packets_processed": 0,
            "hardware_accelerated": 0, 
            "software_processed": 0,
            "avg_processing_time": 0.0,
            "total_processing_time": 0.0
        }
        return True
    
    def process_packet(self, packet_data):
        """
        Process a network packet using FPGA hardware acceleration
        
        Args:
            packet_data (dict): Raw packet data including headers and payload
            
        Returns:
            dict: Processed features extracted from the packet
        """
        start_time = time.time()
        
        # Tracking metrics
        self.performance["packets_processed"] += 1
        
        if not self.acceleration_enabled:
            # Process entirely in software
            features = self._software_packet_processing(packet_data)
            self.performance["software_processed"] += 1
        else:
            if self.simulation_mode:
                # Simulate hardware acceleration
                features = self._simulated_hardware_processing(packet_data)
                self.performance["hardware_accelerated"] += 1
            else:
                # Actual hardware acceleration
                features = self._hardware_packet_processing(packet_data)
                self.performance["hardware_accelerated"] += 1
        
        # Update timing metrics
        processing_time = time.time() - start_time
        total_time = self.performance["total_processing_time"] + processing_time
        self.performance["total_processing_time"] = total_time
        self.performance["avg_processing_time"] = total_time / self.performance["packets_processed"]
        
        return features
    
    def _software_packet_processing(self, packet_data):
        """Process packet entirely in software"""
        # For simplicity, we'll just extract basic features here
        # In a real implementation, this would be more complex
        features = {
            "header_features": self._extract_header_features(packet_data),
            "payload_features": self._extract_payload_features(packet_data),
            "processing_mode": "software"
        }
        
        # Simulate software processing time
        time.sleep(0.001)  # 1ms per packet in software
        
        return features
    
    def _simulated_hardware_processing(self, packet_data):
        """Simulate FPGA hardware acceleration"""
        # For simulation, we'll extract the same features as software
        # but with a performance boost
        features = {
            "header_features": self._extract_header_features(packet_data),
            "payload_features": self._extract_payload_features(packet_data),
            "processing_mode": "hardware_simulated"
        }
        
        # Simulate faster hardware processing time
        time.sleep(0.0001)  # 0.1ms per packet with simulated hardware acceleration
        
        return features
    
    def _hardware_packet_processing(self, packet_data):
        """Process packet using actual FPGA hardware acceleration"""
        try:
            # Check if we have PYNQ hardware initialized
            if not hasattr(self, 'overlay') or self.overlay is None:
                logger.warning("FPGA hardware not initialized. Falling back to simulation.")
                return self._simulated_hardware_processing(packet_data)
                
            # Extract basic features to fill the input buffer
            header_features = self._extract_header_features(packet_data)
            
            # Prepare features in the format expected by the hardware
            # Convert packet features to numpy array for hardware processing
            feature_array = np.zeros(100, dtype=np.float32)
            
            # Fill in basic features (this should match the hardware implementation)
            feature_array[0] = header_features.get("length", 0) / 1500.0  # Normalize length
            feature_array[1] = header_features.get("src_port", 0) / 65535.0  # Normalize src port
            feature_array[2] = header_features.get("dst_port", 0) / 65535.0  # Normalize dst port
            
            # Protocol one-hot encoding
            protocol = header_features.get("protocol", "").lower()
            if protocol == "tcp":
                feature_array[3] = 1.0
            elif protocol == "udp":
                feature_array[4] = 1.0
            elif protocol == "icmp":
                feature_array[5] = 1.0
                
            # Copy feature array to the input buffer
            for i, val in enumerate(feature_array):
                self.input_buffer[i] = val
            
            # Send data to FPGA using DMA
            self.dma.sendchannel.transfer(self.input_buffer)
            self.dma.recvchannel.transfer(self.output_buffer)
            
            # Wait for processing to complete
            self.dma.sendchannel.wait()
            self.dma.recvchannel.wait()
            
            # Extract results from output buffer
            # Format the result as expected by the application
            features = {
                "header_features": header_features,
                "payload_features": self._extract_payload_features(packet_data),
                "hardware_features": {
                    "raw_output": [float(self.output_buffer[i]) for i in range(len(self.output_buffer))],
                },
                "processing_mode": "hardware_actual"
            }
            
            return features
            
        except Exception as e:
            logger.error(f"Hardware packet processing failed: {str(e)}")
            logger.info("Falling back to simulated hardware processing")
            return self._simulated_hardware_processing(packet_data)
    
    def _extract_header_features(self, packet_data):
        """Extract features from packet headers"""
        return {
            "src_ip": packet_data.get("src", "0.0.0.0"),
            "dst_ip": packet_data.get("dst", "0.0.0.0"),
            "src_port": packet_data.get("sport", 0),
            "dst_port": packet_data.get("dport", 0),
            "protocol": packet_data.get("proto", "unknown"),
            "length": packet_data.get("len", 0),
            "flags": packet_data.get("flags", 0)
        }
    
    def _extract_payload_features(self, packet_data):
        """Extract features from packet payload"""
        payload = packet_data.get("payload", "")
        
        if self.simulation_mode or not hasattr(self, 'overlay'):
            # Simulated payload analysis
            features = {
                "payload_len": len(payload),
                "entropy": random.random() * 8.0,  # Simulated entropy (0-8)
                "printable_ratio": random.random(),  # Simulated printable ratio (0-1)
                "null_byte_ratio": random.random() * 0.1,  # Simulated null byte ratio
                "statistical_features": [random.random() for _ in range(8)]  # 8 statistical features
            }
        else:
            # Try to use hardware payload analysis
            try:
                # For real implementation, hardware would calculate these metrics
                # Here we'll still use simulated values but show how it would work
                features = {
                    "payload_len": len(payload),
                    "entropy": sum(self.output_buffer[10:18]) / 8.0,  # Using values from FPGA
                    "printable_ratio": float(self.output_buffer[20]),
                    "null_byte_ratio": float(self.output_buffer[21]),
                    "statistical_features": [float(self.output_buffer[i+30]) for i in range(8)]
                }
            except Exception as e:
                logger.warning(f"Hardware payload analysis failed: {str(e)}")
                # Fall back to simulated values
                features = {
                    "payload_len": len(payload),
                    "entropy": random.random() * 8.0,
                    "printable_ratio": random.random(),
                    "null_byte_ratio": random.random() * 0.1,
                    "statistical_features": [random.random() for _ in range(8)]
                }
        
        return features
    
    def ml_inference(self, features):
        """
        Perform machine learning inference using FPGA acceleration
        
        Args:
            features (dict): Features extracted from a packet
            
        Returns:
            tuple: (is_malicious, confidence) - detection result and confidence
        """
        start_time = time.time()
        
        if not self.acceleration_enabled:
            # Software inference
            result = self._software_inference(features)
        else:
            if self.simulation_mode:
                # Simulated hardware inference
                result = self._simulated_hardware_inference(features)
            else:
                # Actual hardware inference
                result = self._hardware_inference(features)
        
        # Update timing metrics in future
        
        return result
    
    def _software_inference(self, features):
        """Perform ML inference in software"""
        # Simple simulation of inference result
        # In a real implementation, this would use an actual ML model
        
        # Convert features to a flat list
        header = features.get("header_features", {})
        payload = features.get("payload_features", {})
        
        # Simulate inference time
        time.sleep(0.002)  # 2ms for software inference
        
        # Simplified decision logic for simulation
        malicious_indicators = 0
        
        # Check for suspicious port numbers
        if header.get("dst_port") in [4444, 31337, 8080, 22, 23]:
            malicious_indicators += 1
            
        # Check for suspicious protocols
        if header.get("protocol") not in ["tcp", "udp", "icmp"]:
            malicious_indicators += 1
            
        # Check payload features
        if payload.get("entropy", 0) > 7.0:
            malicious_indicators += 1
            
        if payload.get("printable_ratio", 1.0) < 0.3:
            malicious_indicators += 1
            
        # Final decision
        is_malicious = malicious_indicators >= 2
        confidence = 0.5 + (malicious_indicators * 0.1)  # 0.5 - 0.9 confidence
        
        return (is_malicious, confidence)
    
    def _simulated_hardware_inference(self, features):
        """Simulate ML inference with FPGA acceleration"""
        # Similar to software inference but faster
        time.sleep(0.0005)  # 0.5ms for simulated hardware inference
        
        # Generate similar result to software for consistency
        return self._software_inference(features)
    
    def _hardware_inference(self, features):
        """Perform ML inference using actual FPGA hardware"""
        try:
            # Check if we have PYNQ hardware initialized
            if not hasattr(self, 'overlay') or self.overlay is None:
                logger.warning("FPGA hardware not initialized. Falling back to simulation.")
                return self._simulated_hardware_inference(features)
            
            # If we already processed this packet with hardware, use those results
            if "hardware_features" in features and "raw_output" in features["hardware_features"]:
                raw_output = features["hardware_features"]["raw_output"]
                if len(raw_output) >= 2:
                    # First value is classification, second is confidence
                    is_malicious = raw_output[0] > 0.5
                    confidence = raw_output[0] if is_malicious else 1.0 - raw_output[0]
                    return (is_malicious, confidence)
            
            # Otherwise, prepare features and send to FPGA
            # Extract features into flat array
            feature_array = np.zeros(100, dtype=np.float32)
            
            # Fill basic header features
            header = features.get("header_features", {})
            feature_array[0] = header.get("length", 0) / 1500.0
            feature_array[1] = header.get("src_port", 0) / 65535.0
            feature_array[2] = header.get("dst_port", 0) / 65535.0
            
            # Protocol one-hot encoding
            protocol = header.get("protocol", "").lower()
            if protocol == "tcp":
                feature_array[3] = 1.0
            elif protocol == "udp":
                feature_array[4] = 1.0
            elif protocol == "icmp":
                feature_array[5] = 1.0
            
            # Copy feature array to the input buffer
            for i, val in enumerate(feature_array):
                self.input_buffer[i] = val
            
            # Send data to FPGA and wait for results
            self.dma.sendchannel.transfer(self.input_buffer)
            self.dma.recvchannel.transfer(self.output_buffer)
            
            self.dma.sendchannel.wait()
            self.dma.recvchannel.wait()
            
            # Extract results
            is_malicious = bool(self.output_buffer[0] > 0.5)
            confidence = float(self.output_buffer[0] if is_malicious else 1.0 - self.output_buffer[0])
            
            return (is_malicious, confidence)
            
        except Exception as e:
            logger.error(f"Hardware inference failed: {str(e)}")
            logger.info("Falling back to simulated hardware inference")
            return self._simulated_hardware_inference(features)

# Create a global instance for use throughout the application
# Auto-detect if we're running on PYNQ hardware
fpga_interface = FPGAInterface(simulation_mode=None)