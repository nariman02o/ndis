
"""FPGA interface simulation for development without hardware"""
import time
import random
from typing import Dict, Any

class FPGAInterface:
    def __init__(self):
        self._enabled = True
        self._metrics = {
            "packets_processed": 0,
            "hardware_accelerated": 0,
            "software_processed": 0,
            "avg_processing_time": 0.001
        }
        
    def is_acceleration_enabled(self) -> bool:
        return self._enabled
        
    def enable_acceleration(self) -> None:
        self._enabled = True
        
    def disable_acceleration(self) -> None:
        self._enabled = False
        
    def process_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate FPGA processing of a packet"""
        start_time = time.time()
        
        # Simulate processing delay
        time.sleep(0.001)
        
        self._metrics["packets_processed"] += 1
        if self._enabled:
            self._metrics["hardware_accelerated"] += 1
        else:
            self._metrics["software_processed"] += 1
            
        # Calculate running average processing time
        elapsed = time.time() - start_time
        self._metrics["avg_processing_time"] = (
            self._metrics["avg_processing_time"] * 0.95 + elapsed * 0.05
        )
        
        # Return simulated results
        return {
            "header_features": {
                "src_ip": packet.get("src", ""),
                "dst_ip": packet.get("dst", ""),
                "src_port": packet.get("sport", 0),
                "dst_port": packet.get("dport", 0),
                "protocol": packet.get("proto", ""),
                "length": packet.get("len", 0)
            },
            "payload_features": {
                "entropy": random.random(),
                "printable_ratio": random.random(),
                "statistical_features": [random.random() for _ in range(10)]
            },
            "processing_mode": "hardware_simulated" if self._enabled else "software"
        }
        
    def get_performance_metrics(self) -> Dict[str, Any]:
        return self._metrics.copy()
        
    def reset_performance_metrics(self) -> None:
        self._metrics = {
            "packets_processed": 0,
            "hardware_accelerated": 0, 
            "software_processed": 0,
            "avg_processing_time": 0.001
        }

# Create singleton instance
fpga_interface = FPGAInterface()
