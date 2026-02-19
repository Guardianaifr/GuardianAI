import subprocess
import logging
import signal
import os
import time
from typing import List, Dict, Any, Optional

logger = logging.getLogger("GuardianAI")

class SSHTunnelManager:
    """
    Manages secure SSH tunnels for remote AI services.
    Handles startup, monitoring, and graceful shutdown of port-forwarding processes.
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config.get('ssh_tunnels', {})
        self.tunnels = self.config.get('tunnels', [])
        self.processes: Dict[str, subprocess.Popen] = {}
        self.enabled = self.config.get('enabled', False)

    def start_all(self):
        """Starts all configured SSH tunnels."""
        if not self.enabled:
            return

        for tunnel in self.tunnels:
            name = tunnel.get('name', 'unnamed')
            remote_host = tunnel.get('remote_host')
            remote_user = tunnel.get('remote_user')
            remote_port = tunnel.get('remote_port')
            local_port = tunnel.get('local_port')

            if not all([remote_host, remote_user, remote_port, local_port]):
                logger.error(f"SSH Tunnel '{name}' is missing required configuration.")
                continue

            self._start_tunnel(name, remote_user, remote_host, remote_port, local_port)

    def _start_tunnel(self, name: str, user: str, host: str, remote_port: int, local_port: int):
        """Spawns an SSH process for a specific tunnel."""
        # Command syntax: ssh -L [LocalPort]:localhost:[RemotePort] [User]@[ServerIP] -N
        # -N: Do not execute a remote command (useful for just forwarding ports)
        cmd = [
            "ssh",
            "-L", f"{local_port}:localhost:{remote_port}",
            f"{user}@{host}",
            "-N",
            "-o", "ExitOnForwardFailure=yes"
        ]

        try:
            logger.info(f"🚀 Opening SSH Tunnel '{name}': localhost:{local_port} -> {host}:{remote_port}")
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
            )
            self.processes[name] = process
            
            # Brief wait to see if it fails immediately
            time.sleep(1)
            if process.poll() is not None:
                _, stderr = process.communicate()
                logger.error(f"SSH Tunnel '{name}' failed to start: {stderr.strip()}")
        except Exception as e:
            logger.error(f"Failed to spawn SSH process for '{name}': {e}")

    def stop_all(self):
        """Gracefully terminates all active SSH tunnel processes."""
        for name, process in self.processes.items():
            if process.poll() is None:
                logger.info(f"🛑 Closing SSH Tunnel '{name}'...")
                if os.name == 'nt':
                    process.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    process.terminate()
                
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logger.warning(f"SSH Tunnel '{name}' did not exit gracefully, killing...")
                    process.kill()
        
        self.processes.clear()

    def check_health(self) -> Dict[str, bool]:
        """Checks the status of all managed tunnels."""
        status = {}
        for name, process in self.processes.items():
            status[name] = process.poll() is None
        return status
