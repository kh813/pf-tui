import unittest
from unittest.mock import patch, mock_open, MagicMock
import os
import sys
import json
import importlib.util

# Programmatically import pf-tui.py since it contains a hyphen
def load_module_from_path(path, module_name):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'pf-tui.py'))
pf_tui = load_module_from_path(script_path, 'pf_tui')

FirewallManager = pf_tui.FirewallManager
FirewallRule = pf_tui.FirewallRule
Action = pf_tui.Action
Direction = pf_tui.Direction
PortForwardingRule = pf_tui.PortForwardingRule

class TestFirewallManager(unittest.TestCase):

    def setUp(self):
        """Set up a new FirewallManager instance before each test."""
        # Patch the config directory to avoid creating files in the user's home
        with patch('os.path.expanduser', return_value='/tmp/pf-tui-test-config'):
            self.manager = FirewallManager()
            # Clear any rules that might be loaded by default
            self.manager.rules = []
            self.manager.rdr_rules = []

    def test_add_filter_rule(self):
        """Test adding a single filter rule."""
        self.assertEqual(len(self.manager.rules), 0)
        rule = FirewallRule(
            action=Action.BLOCK,
            direction=Direction.IN,
            description="Test block rule"
        )
        self.manager.rules.append(rule)
        self.assertEqual(len(self.manager.rules), 1)
        self.assertEqual(self.manager.rules[0].description, "Test block rule")

    def test_generate_anchor_config_single_rule(self):
        """Test the generation of pf.conf content for a single rule."""
        rule = FirewallRule(
            action=Action.PASS,
            direction=Direction.OUT,
            protocol="tcp",
            destination="8.8.8.8",
            port="53",
            quick=True,
            keep_state=True,
            description="Allow DNS"
        )
        self.manager.rules.append(rule)
        
        expected_output = (
            "# --- Filter Rules ---\n"
            "# Allow DNS\n"
            "pass out quick proto tcp from any to 8.8.8.8 port 53 keep state\n"
        )
        
        # We need to handle the case where there are rdr_rules, which adds a header
        # Since we have no rdr_rules, we expect the filter rules header.
        # A better implementation of generate_anchor_config might not add the header if there are no rdr_rules.
        # Let's adjust the expected output based on the current implementation.
        
        # The current implementation adds a header if there are filter rules.
        # Let's re-verify the implementation logic.
        # The logic is: `if self.rdr_rules and self.rules: ...`
        # So if there are no rdr_rules, the filter header is not added. Let's adjust.
        
        expected_output_no_rdr = (
            "# Allow DNS\n"
            "pass out quick proto tcp from any to 8.8.8.8 port 53 keep state\n"
        )

        config = self.manager.generate_anchor_config()
        self.assertEqual(config.strip(), expected_output_no_rdr.strip())

    def test_generate_anchor_config_rdr_rule(self):
        """Test the generation of pf.conf content for a port forwarding rule."""
        rdr_rule = PortForwardingRule(
            interface="en0",
            protocol="tcp",
            external_ip="any",
            external_port="8080",
            internal_ip="192.168.1.100",
            internal_port="80",
            description="Web server redirect"
        )
        self.manager.rdr_rules.append(rdr_rule)
        
        expected_output = (
            "# Web server redirect\n"
            "rdr pass on en0 proto tcp from any to any port 8080 -> 192.168.1.100 port 80"
        )
        
        config = self.manager.generate_anchor_config()
        self.assertEqual(config.strip(), expected_output.strip())

    @patch('builtins.open', new_callable=mock_open, read_data=json.dumps({
        "filter_rules": [{
            "action": "block", "direction": "in", "interface": "any", "protocol": "any",
            "source": "any", "destination": "any", "port": "any", "description": "Loaded from JSON",
            "quick": False, "keep_state": False
        }],
        "rdr_rules": []
    }))
    def test_load_rules_from_file(self, mock_file):
        """Test loading rules from a JSON file using a mock."""
        # Patch os.path.exists to simulate that the file exists
        with patch('os.path.exists', return_value=True):
            self.manager.load_rules()
        
        self.assertEqual(len(self.manager.rules), 1)
        self.assertEqual(self.manager.rules[0].description, "Loaded from JSON")
        self.assertEqual(self.manager.rules[0].action, Action.BLOCK)

    @patch('os.path.exists', return_value=True)
    @patch('pf_tui.FirewallManager.request_sudo_password')
    @patch('pf_tui.FirewallManager.check_sudo_access')
    @patch('subprocess.run')
    def test_apply_rules_success_simulation(self, mock_subprocess_run, mock_check_sudo_access, mock_request_sudo_password, mock_os_path_exists):
        """Simulate a successful run of apply_rules by mocking subprocess."""
        mock_check_sudo_access.return_value = (False, "password required")
        mock_request_sudo_password.return_value = (True, "succeeded")
        # Add a rule to be applied
        self.manager.rules.append(FirewallRule(action=Action.PASS, direction=Direction.OUT, description="Test"))
        self.manager.rdr_rules.append(PortForwardingRule(
            interface="en0",
            protocol="tcp",
            external_ip="any",
            external_port="8080",
            internal_ip="192.168.1.100",
            internal_port="80",
            description="Web server redirect"
        ))

        # We also need to mock open for the temporary file writing
        m = mock_open(read_data="some rule")
        with patch('builtins.open', m):
            success, message = self.manager.apply_rules(dry_run=True)

        self.assertTrue(success)
        self.assertEqual(message, "Dry run successful")

if __name__ == '__main__':
    unittest.main()
