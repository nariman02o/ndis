#!/usr/bin/env python3
"""
Check if the application is running on a PYNQ-Z1 board
and print hardware information for debugging purposes.
"""

import os
import sys
import platform
import subprocess
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("PYNQ-Check")

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

def get_system_info():
    """Get system information"""
    info = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
    }
    
    # Try to get CPU info
    try:
        with open('/proc/cpuinfo', 'r') as f:
            cpu_info = f.read()
        
        # Extract model name
        for line in cpu_info.split('\n'):
            if 'model name' in line:
                info['cpu_model'] = line.split(':')[1].strip()
                break
    except:
        info['cpu_model'] = "Unknown"
    
    # Check for FPGA devices
    try:
        fpga_devices = []
        if os.path.exists('/sys/class/fpga'):
            fpga_devices = os.listdir('/sys/class/fpga')
        info['fpga_devices'] = fpga_devices
    except:
        info['fpga_devices'] = []
    
    # Check for Zynq devices
    try:
        zynq_devices = []
        if os.path.exists('/sys/bus/platform/drivers/zynq-ocm'):
            zynq_devices = ["zynq-ocm found"]
        info['zynq_devices'] = zynq_devices
    except:
        info['zynq_devices'] = []
    
    return info

def check_pynq_imports():
    """Try to import PYNQ libraries and return result"""
    try:
        import pynq
        return {"success": True, "version": pynq.__version__, "path": pynq.__file__}
    except ImportError as e:
        return {"success": False, "error": str(e)}

def main():
    logger.info("Checking if running on PYNQ hardware...")
    
    on_pynq = is_running_on_pynq()
    if on_pynq:
        logger.info("✅ Running on PYNQ hardware")
    else:
        logger.info("❌ Not running on PYNQ hardware")
    
    logger.info("\nSystem information:")
    system_info = get_system_info()
    for key, value in system_info.items():
        logger.info(f"  {key}: {value}")
    
    logger.info("\nChecking PYNQ libraries:")
    pynq_import_result = check_pynq_imports()
    if pynq_import_result["success"]:
        logger.info(f"✅ PYNQ library imported successfully")
        logger.info(f"  Version: {pynq_import_result['version']}")
        logger.info(f"  Path: {pynq_import_result['path']}")
    else:
        logger.info(f"❌ Failed to import PYNQ library")
        logger.info(f"  Error: {pynq_import_result['error']}")
    
    logger.info("\nSummary:")
    if on_pynq and pynq_import_result["success"]:
        logger.info("✅ The application can use PYNQ hardware acceleration")
    else:
        logger.info("❌ The application will run in simulation mode")

if __name__ == "__main__":
    main()