import pytest
from unittest.mock import MagicMock, patch
import sys

# --- MOCKING STRATEGY ---
mock_psutil = MagicMock()
sys.modules['psutil'] = mock_psutil

from guardian.runtime.monitor import RuntimeMonitor

@pytest.fixture
def setup_mocks():
    mock_psutil.reset_mock()
    return mock_psutil

@pytest.fixture
def monitor_config():
    return {
        'runtime_monitoring': {
            'check_interval_seconds': 0.1,
            'blocked_processes': ['nc', 'ncat', 'cmd.exe', 'nc.exe'],
            'max_cpu_percent': 80.0,
            'max_memory_percent': 80.0
        }
    }

@pytest.fixture
def monitor(monitor_config, setup_mocks):
    return RuntimeMonitor(monitor_config)

def test_initialization(monitor):
    assert monitor.interval == 0.1
    assert 'nc' in monitor.blocked_processes
    assert monitor.max_cpu == 80.0

def test_get_suspicious_processes_clean(monitor):
    """Test that safe processes are not flagged."""
    # Setup mock processes
    p1 = MagicMock()
    p1.info = {'pid': 100, 'name': 'python.exe', 'cmdline': ['python', 'main.py']}
    p2 = MagicMock()
    p2.info = {'pid': 101, 'name': 'chrome.exe', 'cmdline': ['chrome']}
    
    # We must set process_iter directly on the global mock used by the module
    mock_psutil.process_iter.return_value = [p1, p2]
    
    suspicious = monitor.get_suspicious_processes()
    assert len(suspicious) == 0

def test_get_suspicious_processes_detected(monitor):
    """Test detection of blocked process names."""
    # Setup mock processes
    p1 = MagicMock()
    p1.info = {'pid': 666, 'name': 'nc.exe', 'cmdline': ['nc', '-l', '-p', '4444']}
    
    mock_psutil.process_iter.return_value = [p1]
    
    suspicious = monitor.get_suspicious_processes()
    assert len(suspicious) == 1
    assert suspicious[0]['name'] == 'nc.exe'
    assert suspicious[0]['pid'] == 666

def test_check_resources_normal(monitor):
    """Test normal resource usage."""
    mock_psutil.cpu_percent.return_value = 50.0
    mock_psutil.virtual_memory.return_value.percent = 40.0
    
    alerts = monitor.check_resources()
    assert len(alerts) == 0

def test_check_resources_high_cpu(monitor):
    """Test high CPU usage alert."""
    mock_psutil.cpu_percent.return_value = 95.0 # Above 80.0 threshold
    mock_psutil.virtual_memory.return_value.percent = 40.0
    
    alerts = monitor.check_resources()
    assert len(alerts) == 1
    assert "High CPU" in alerts[0]

def test_check_resources_high_memory(monitor):
    """Test high memory usage alert."""
    mock_psutil.cpu_percent.return_value = 20.0 
    mock_psutil.virtual_memory.return_value.percent = 90.0 # Above 80.0 threshold
    
    alerts = monitor.check_resources()
    assert len(alerts) == 1
    assert "High Memory" in alerts[0]

def test_monitoring_thread_start_stop(monitor):
    """Test starting and stopping the monitoring thread."""
    with patch('threading.Thread') as MockThread:
        mock_thread_instance = MagicMock()
        MockThread.return_value = mock_thread_instance
        
        monitor.start()
        MockThread.assert_called_once()
        mock_thread_instance.start.assert_called_once()
        
        monitor.stop()
        assert monitor._stop_event.is_set()
