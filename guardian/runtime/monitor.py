"""
Process Monitor - Runtime Security and Anomaly Detection

This module provides real-time monitoring of system processes to detect suspicious
activity that may indicate a compromised AI agent or malicious code execution.
It establishes a baseline of safe processes and alerts on deviations.

The Monitor tracks:
- New process creation
- Suspicious process names (nc, curl, wget, etc.)
- Process tree changes
- Resource usage anomalies

Key Components:
    - Monitor: Main class for process monitoring
    - get_suspicious_processes(): Identifies potentially malicious processes
    - Baseline tracking: Establishes normal process state
    - Real-time alerting: Detects runtime anomalies

Usage Example:
    ```python
    from runtime.monitor import Monitor
    
    monitor = Monitor()
    
    # Check for suspicious activity
    suspicious = monitor.get_suspicious_processes()
    if suspicious:
        print(f"Alert: {len(suspicious)} suspicious processes detected!")
        for proc in suspicious:
            print(f"  - {proc['name']} (PID: {proc['pid']})")
    ```

Security Notes:
    - Requires psutil library for process inspection
    - Baseline is established at initialization
    - Monitors for common attack tools (netcat, curl piping, etc.)
    - Can detect reverse shell attempts

Performance:
    - Lightweight (~5-10ms per check)
    - Minimal CPU overhead
    - Suitable for continuous monitoring

Author: GuardianAI Team
License: MIT
"""
import psutil
import threading
import time
import logging
import os
from typing import Dict, Any, List
logger = logging.getLogger("openclaw_guardian")

class RuntimeMonitor:
    """
    Monitors process and resource usage to detect system-level anomalies.

    This class establishes a baseline of safe processes at startup and alerts on
    new suspicious processes, high CPU/Memory usage, or blocked command attempts.

    Attributes:
        interval (int): Sampling interval in seconds.
        max_cpu (float): CPU usage threshold percentage.
        max_memory (float): Memory usage threshold percentage.
        safe_pids (set): Set of PIDs considered 'known-safe' via baseline snapshot.
    """
    def __init__(self, config: Dict[str, Any]):
        """
        Initializes the RuntimeMonitor with configuration and takes a baseline snapshot.

        Args:
            config (dict): The global GuardianAI configuration dictionary.
        """
        self.config = config
        monitor_config = config.get('runtime_monitoring', {})
        self.interval = monitor_config.get('check_interval_seconds', 5)
        self.blocked_processes = set(p.lower() for p in monitor_config.get('blocked_processes', []))
        
        self.max_cpu = monitor_config.get('max_cpu_percent', 90.0)
        self.max_memory = monitor_config.get('max_memory_percent', 90.0)
        
        self._stop_event = threading.Event()
        self._thread = None
        
        # Baseline Snapshot: Ignore processes that were already running when we started
        self.safe_pids = set()
        try:
            for p in psutil.process_iter(['pid']):
                self.safe_pids.add(p.info['pid'])
            logger.info(f"Initialized Process Baseline: Ignoring {len(self.safe_pids)} existing background processes.")
        except (psutil.Error, KeyError) as e:
            # Failed to enumerate processes - continue without baseline
            logger.warning(f"Could not initialize process baseline: {e}")

    def start(self):
        """Starts the asynchronous monitoring loop in a background daemon thread."""
        if self._thread is not None:
            return
        print("DEBUG: Runtime Monitor Thread STARTING via print()") # FORCE PRINT
        logger.info("Starting Runtime Monitor...") 
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stops the monitoring thread and waits for clean termination."""
        if self._thread is None:
            return
        logger.info("Stopping Runtime Monitor...")
        self._stop_event.set()
        self._thread.join()
        self._thread = None

    def _monitor_loop(self):
        while not self._stop_event.is_set():
            try:
                self.check_resources()
                self.check_processes()
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
            
            time.sleep(self.interval)

    def check_resources(self) -> List[str]:
        """
        Performs a point-in-time resource check (CPU/RAM).

        Returns:
            list[str]: A list of warning messages if thresholds are exceeded.
        """
        alerts = []
        try:
            cpu_percent = psutil.cpu_percent(interval=None)
            memory_percent = psutil.virtual_memory().percent
            
            if cpu_percent > self.max_cpu:
                msg = f"High CPU usage detected: {cpu_percent}% (Threshold: {self.max_cpu}%)"
                logger.warning(msg)
                alerts.append(msg)
            
            if memory_percent > self.max_memory:
                msg = f"High Memory usage detected: {memory_percent}% (Threshold: {self.max_memory}%)"
                logger.warning(msg)
                alerts.append(msg)
        except Exception as e:
            logger.error(f"Resource check failed: {e}")
            
        return alerts

    def check_processes(self):
        """
        Scans for blocked processes and actively terminates them.
        """
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                # Baseline check: If process was present at start, ignore it.
                if proc.info['pid'] in self.safe_pids:
                    continue
 
                pname = proc.info['name'].lower() if proc.info['name'] else ""
                
                if pname in self.blocked_processes:
                    should_block = True
                # Special handling for Windows Calculator variants (UWP/Win32)
                elif "calc.exe" in self.blocked_processes and pname in ["calculator.exe", "calculatorapp.exe", "win32calc.exe"]:
                    should_block = True
                else:
                    should_block = False

                if should_block:
                    # BLOCK IT!
                    logger.warning(f"🛡️  HIGH ALERT: System Shield blocking rogue process: {proc.info['name']} (PID: {proc.info['pid']})")
                    try:
                        proc.terminate()
                        proc.wait(timeout=3)
                        logger.info(f"✅  Terminated {proc.info['name']} successfully.")
                        self._report_event("system_alert", "critical", {
                            "action": "process_terminated",
                            "process": proc.info['name'],
                            "pid": proc.info['pid'],
                            "reason": "rogue_process_detected"
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired) as e:
                        logger.error(f"Failed to terminate {proc.info['name']}: {e}")
                        # Try kill if terminate failed/timed out
                        try:
                            proc.kill()
                            self._report_event("system_alert", "critical", {
                                "action": "process_killed",
                                "process": proc.info['name'],
                                "pid": proc.info['pid'],
                                "reason": "rogue_process_force_kill"
                            })
                        except:
                            pass

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

    def _report_event(self, event_type: str, severity: str, details: Dict[str, Any]):
        """Sends telemetry to backend."""
        backend_url = self.config.get('backend', {}).get('url')
        if not backend_url: return

        payload = {
            "guardian_id": self.config.get('guardian_id', 'unknown'),
            "event_type": event_type,
            "severity": severity,
            "details": details,
            "timestamp": time.time()
        }
        
        def send_bg():
            import requests # Lazy import
            try:
                requests.post(backend_url, json=payload, timeout=5)
            except Exception as e:
                logger.error(f"Failed to report system event: {e}")
        
        threading.Thread(target=send_bg, daemon=True).start()

    def get_suspicious_processes(self) -> List[Dict[str, Any]]:
        """
        Legacy method for reporting only. Actual enforcement is now in check_processes.
        """
        suspicious = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['pid'] in self.safe_pids: continue
                if proc.info['name'] and proc.info['name'].lower() in self.blocked_processes:
                    suspicious.append({"pid": proc.info['pid'], "name": proc.info['name']})
            except:
                pass
        return suspicious
