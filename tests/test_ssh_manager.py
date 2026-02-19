import unittest
from unittest.mock import MagicMock, patch
import subprocess
import os
import signal
from guardian.utils.ssh_manager import SSHTunnelManager

class TestSSHTunnelManager(unittest.TestCase):
    def setUp(self):
        self.config = {
            'ssh_tunnels': {
                'enabled': True,
                'tunnels': [
                    {
                        'name': 'TestTunnel',
                        'remote_host': 'remote.test',
                        'remote_user': 'testuser',
                        'remote_port': 8080,
                        'local_port': 9090
                    }
                ]
            }
        }
        self.manager = SSHTunnelManager(self.config)

    @patch('subprocess.Popen')
    def test_start_tunnel(self, mock_popen):
        # Mock process setup
        mock_process = MagicMock()
        mock_process.poll.return_value = None # Running
        mock_popen.return_value = mock_process
        
        self.manager.start_all()
        
        # Verify SSH command
        expected_cmd = [
            "ssh",
            "-L", "9090:localhost:8080",
            "testuser@remote.test",
            "-N",
            "-o", "ExitOnForwardFailure=yes"
        ]
        mock_popen.assert_called_with(
            expected_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
        )
        self.assertIn('TestTunnel', self.manager.processes)

    @patch('subprocess.Popen')
    def test_stop_tunnel(self, mock_popen):
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        self.manager.processes['TestTunnel'] = mock_process
        
        self.manager.stop_all()
        
        if os.name == 'nt':
            mock_process.send_signal.assert_called_with(signal.CTRL_BREAK_EVENT)
        else:
            mock_process.terminate.assert_called()
        
        self.assertEqual(len(self.manager.processes), 0)

    def test_disabled_manager(self):
        self.config['ssh_tunnels']['enabled'] = False
        manager = SSHTunnelManager(self.config)
        with patch('subprocess.Popen') as mock_popen:
            manager.start_all()
            mock_popen.assert_not_called()

if __name__ == '__main__':
    unittest.main()
