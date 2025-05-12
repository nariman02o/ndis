#!/usr/bin/env python3
"""
Main entry point for running the NIDS application directly on a PYNQ-Z1 board.

This script is designed to be executed on the PYNQ-Z1 board itself, not on a host computer.
It configures the FPGA with the NIDS overlay and runs the network intrusion detection
system with hardware acceleration.

Usage:
  python3 pynq_main.py [options]

Options:
  --simulate           Run in simulation mode even on PYNQ hardware
  --interface=IFACE    Network interface to capture packets from (default: eth0)
  --overlay=PATH       Path to overlay bitstream (default: ./pynq_overlay/nids_overlay.bit)
  --help               Show this help message
"""

import os
import sys
import time
import argparse
import logging
import json
import numpy as np
import threading
import queue
import signal

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('NIDS-PYNQ')

# Parse command line arguments
def parse_args():
    parser = argparse.ArgumentParser(description='NIDS application for PYNQ-Z1')
    parser.add_argument('--simulate', action='store_true', help='Run in simulation mode')
    parser.add_argument('--interface', default='eth0', help='Network interface to capture packets from')
    parser.add_argument('--overlay', default='./pynq_overlay/nids_overlay.bit', help='Path to overlay bitstream')
    return parser.parse_args()

# Check if running on PYNQ hardware
def is_running_on_pynq():
    try:
        # Check for PYNQ-specific paths and files
        if os.path.exists('/usr/local/share/pynq-venv'):
            return True
        if os.path.exists('/home/xilinx') and os.path.exists('/sys/bus/platform/drivers/xdma'):
            return True
        return False
    except:
        return False

# Import PYNQ libraries if running on PYNQ hardware
ON_PYNQ_HARDWARE = is_running_on_pynq()
PYNQ_IMPORTS_OK = False

if ON_PYNQ_HARDWARE:
    try:
        from pynq import Overlay
        from pynq import allocate
        import pynq.lib.dma
        PYNQ_IMPORTS_OK = True
        logger.info("PYNQ libraries imported successfully")
    except ImportError as e:
        logger.error(f"Failed to import PYNQ libraries: {e}")

# Import scapy for packet capture (may need to be installed on PYNQ)
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
    logger.info("Scapy imported successfully")
except ImportError:
    SCAPY_AVAILABLE = False
    logger.error("Failed to import Scapy. Packet capture will not be available.")

# Import our NIDS modules
from fpga_interface import FPGAInterface

class PYNQNetworkCapture:
    """Network packet capture for PYNQ-Z1"""
    
    def __init__(self, interface='eth0', packet_queue=None):
        self.interface = interface
        self.packet_queue = packet_queue or queue.Queue(maxsize=1000)
        self.running = False
        self.capture_thread = None
        
    def start_capture(self):
        """Start packet capture in a background thread"""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available. Cannot start packet capture.")
            return False
            
        self.running = True
        self.capture_thread = threading.Thread(target=self._capture_loop)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        logger.info(f"Started packet capture on interface {self.interface}")
        return True
        
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=3)
        logger.info("Stopped packet capture")
        
    def _capture_loop(self):
        """Capture packets in a loop"""
        try:
            sniff(iface=self.interface, prn=self._process_packet, store=0, stop_filter=lambda _: not self.running)
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
            self.running = False
            
    def _process_packet(self, packet):
        """Process a captured packet and put it in the queue"""
        try:
            # Only process IP packets
            if IP in packet:
                packet_data = {
                    'src': packet[IP].src,
                    'dst': packet[IP].dst,
                    'len': len(packet),
                    'time': time.time(),
                }
                
                # Extract protocol-specific information
                if TCP in packet:
                    packet_data['proto'] = 'tcp'
                    packet_data['sport'] = packet[TCP].sport
                    packet_data['dport'] = packet[TCP].dport
                    packet_data['flags'] = packet[TCP].flags
                elif UDP in packet:
                    packet_data['proto'] = 'udp'
                    packet_data['sport'] = packet[UDP].sport
                    packet_data['dport'] = packet[UDP].dport
                    packet_data['flags'] = 0
                elif ICMP in packet:
                    packet_data['proto'] = 'icmp'
                    packet_data['sport'] = 0
                    packet_data['dport'] = 0
                    packet_data['flags'] = 0
                else:
                    packet_data['proto'] = 'other'
                    packet_data['sport'] = 0
                    packet_data['dport'] = 0
                    packet_data['flags'] = 0
                
                # Extract payload
                if packet.haslayer('Raw'):
                    raw_payload = bytes(packet.getlayer('Raw'))
                    packet_data['payload'] = raw_payload[:100]  # Limit payload size
                else:
                    packet_data['payload'] = b''
                    
                # Add to queue, but don't block if queue is full
                try:
                    self.packet_queue.put(packet_data, block=False)
                except queue.Full:
                    pass  # Drop packet if queue is full
                    
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

class PYNQNetworkMonitor:
    """Network intrusion detection monitor for PYNQ-Z1"""
    
    def __init__(self, simulation_mode=None, bitstream_path=None):
        self.simulation_mode = simulation_mode
        self.bitstream_path = bitstream_path
        self.packet_queue = queue.Queue(maxsize=1000)
        self.result_queue = queue.Queue(maxsize=1000)
        self.fpga_interface = None
        self.packet_capture = None
        self.processing_thread = None
        self.running = False
        self.stats = {
            'packets_processed': 0,
            'malicious_detected': 0,
            'benign_detected': 0,
            'start_time': 0,
        }
        
    def initialize(self):
        """Initialize the monitor"""
        # Create FPGA interface with specified mode
        self.fpga_interface = FPGAInterface(
            simulation_mode=self.simulation_mode,
            bitstream_path=self.bitstream_path
        )
        
        # Create packet capture
        self.packet_capture = PYNQNetworkCapture(
            interface='eth0',
            packet_queue=self.packet_queue
        )
        
        return True
        
    def start(self):
        """Start monitoring"""
        self.running = True
        self.stats['start_time'] = time.time()
        
        # Start packet capture
        self.packet_capture.start_capture()
        
        # Start packet processing
        self.processing_thread = threading.Thread(target=self._processing_loop)
        self.processing_thread.daemon = True
        self.processing_thread.start()
        
        logger.info("Started network monitoring")
        return True
        
    def stop(self):
        """Stop monitoring"""
        self.running = False
        
        # Stop packet capture
        if self.packet_capture:
            self.packet_capture.stop_capture()
            
        # Wait for processing thread to finish
        if self.processing_thread and self.processing_thread.is_alive():
            self.processing_thread.join(timeout=3)
            
        logger.info("Stopped network monitoring")
        
    def _processing_loop(self):
        """Process packets in a loop"""
        while self.running:
            try:
                # Get packet from queue with timeout
                try:
                    packet = self.packet_queue.get(timeout=0.1)
                except queue.Empty:
                    continue
                    
                # Process packet using FPGA
                features = self.fpga_interface.process_packet(packet)
                
                # Perform inference
                is_malicious, confidence = self.fpga_interface.ml_inference(features)
                
                # Update statistics
                self.stats['packets_processed'] += 1
                if is_malicious:
                    self.stats['malicious_detected'] += 1
                else:
                    self.stats['benign_detected'] += 1
                    
                # Create result
                result = {
                    'packet': packet,
                    'features': features,
                    'is_malicious': is_malicious,
                    'confidence': confidence,
                    'time': time.time()
                }
                
                # Add to result queue
                try:
                    self.result_queue.put(result, block=False)
                except queue.Full:
                    # Remove oldest result if queue is full
                    try:
                        self.result_queue.get_nowait()
                        self.result_queue.put(result, block=False)
                    except:
                        pass
                        
                # Log detection if malicious
                if is_malicious:
                    src = packet.get('src', 'unknown')
                    dst = packet.get('dst', 'unknown')
                    proto = packet.get('proto', 'unknown')
                    sport = packet.get('sport', 0)
                    dport = packet.get('dport', 0)
                    logger.warning(f"ALERT: Malicious traffic detected: {src}:{sport} -> {dst}:{dport} ({proto}) [Confidence: {confidence:.2f}]")
                    
            except Exception as e:
                logger.error(f"Error in packet processing: {e}")
                
    def get_statistics(self):
        """Get monitoring statistics"""
        stats = self.stats.copy()
        
        # Calculate derived statistics
        runtime = time.time() - stats['start_time']
        stats['runtime_seconds'] = runtime
        stats['packets_per_second'] = stats['packets_processed'] / runtime if runtime > 0 else 0
        
        # Add FPGA performance metrics
        stats['fpga_metrics'] = self.fpga_interface.get_performance_metrics()
        
        return stats
        
    def get_latest_detections(self, count=10):
        """Get the latest detection results"""
        results = []
        for _ in range(min(count, self.result_queue.qsize())):
            try:
                results.append(self.result_queue.get_nowait())
                self.result_queue.task_done()
            except queue.Empty:
                break
        return results

def print_statistics(monitor):
    """Print monitoring statistics"""
    stats = monitor.get_statistics()
    print("\n--- NIDS Statistics ---")
    print(f"Runtime: {stats['runtime_seconds']:.1f} seconds")
    print(f"Packets Processed: {stats['packets_processed']}")
    print(f"Packets Per Second: {stats['packets_per_second']:.2f}")
    print(f"Malicious Packets: {stats['malicious_detected']}")
    print(f"Benign Packets: {stats['benign_detected']}")
    
    # FPGA metrics
    fpga_metrics = stats['fpga_metrics']
    print("\n--- FPGA Performance ---")
    print(f"Hardware Accelerated: {fpga_metrics['hardware_accelerated']}")
    print(f"Software Processed: {fpga_metrics['software_processed']}")
    print(f"Average Processing Time: {fpga_metrics['avg_processing_time']*1000:.2f} ms/packet")

def signal_handler(sig, frame):
    """Handle Ctrl+C"""
    print("\nStopping NIDS application...")
    if 'monitor' in globals():
        monitor.stop()
    sys.exit(0)

def main():
    """Main function"""
    global monitor
    
    # Parse command line arguments
    args = parse_args()
    
    # Check if running on PYNQ hardware
    if not ON_PYNQ_HARDWARE:
        logger.warning("Not running on PYNQ hardware. Forcing simulation mode.")
        args.simulate = True
    
    # Check if PYNQ libraries are available
    if not PYNQ_IMPORTS_OK and not args.simulate:
        logger.warning("PYNQ libraries not available. Forcing simulation mode.")
        args.simulate = True
    
    # Initialize monitor
    monitor = PYNQNetworkMonitor(
        simulation_mode=args.simulate,
        bitstream_path=args.overlay
    )
    
    if not monitor.initialize():
        logger.error("Failed to initialize monitor. Exiting.")
        return 1
    
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start monitoring
    if not monitor.start():
        logger.error("Failed to start monitoring. Exiting.")
        return 1
    
    # Main loop
    try:
        print("NIDS application running on PYNQ-Z1. Press Ctrl+C to stop.")
        while True:
            # Print statistics periodically
            print_statistics(monitor)
            
            # Check for malicious traffic
            detections = monitor.get_latest_detections()
            if detections:
                print("\n--- Latest Detections ---")
                for i, detection in enumerate(detections):
                    if detection['is_malicious']:
                        packet = detection['packet']
                        src = packet.get('src', 'unknown')
                        dst = packet.get('dst', 'unknown')
                        proto = packet.get('proto', 'unknown')
                        sport = packet.get('sport', 0)
                        dport = packet.get('dport', 0)
                        conf = detection['confidence']
                        print(f"{i+1}. ALERT: {src}:{sport} -> {dst}:{dport} ({proto}) [Confidence: {conf:.2f}]")
            
            # Sleep for a bit
            time.sleep(5)
            
    except KeyboardInterrupt:
        print("\nStopping NIDS application...")
        monitor.stop()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())