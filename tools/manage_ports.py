import psutil
import sys

def kill_processes_on_ports(ports):
    killed = 0
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr.port in ports and conn.pid:
            try:
                proc = psutil.Process(conn.pid)
                print(f"Killing process {proc.name()} (PID: {conn.pid}) on port {conn.laddr.port}")
                proc.kill()
                killed += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    return killed

if __name__ == "__main__":
    if len(sys.argv) > 1:
        ports_to_kill = [int(p) for p in sys.argv[1:]]
    else:
        ports_to_kill = [8001, 8081]
    
    killed_count = kill_processes_on_ports(ports_to_kill)
    print(f"Killed {killed_count} processes.")
