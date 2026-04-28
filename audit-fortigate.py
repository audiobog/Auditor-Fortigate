#!/usr/bin/env python3
"""
FortiGate CIS L1 + UK CAF + IEC 62443 SL4 Compliance Validator
"""

import paramiko
import json
import re
from datetime import datetime
import argparse
import getpass


# Helper functions
def extract_value(output_str, key):
    """
    Extract the value for a given key from the output of a FortiOS command.
    
    Args:
        output_str (str): The output string from a FortiOS command.
        key (str): The key to search for in the output.
    
    Returns:
        The value associated with the given key, or None if the key is not found.
    """
    for line in output_str.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0] == key:
            return parts[1]
    return None

def check_ssh_restrictions(output_str):
    """
    Check if the SSH access restrictions are properly configured.
    
    Args:
        output_str (str): The output of the "get system admin" command.
    
    Returns:
        True if the SSH access restrictions are properly configured, False otherwise.
    """
    # Check if SSH access is restricted to specific IP addresses or subnets
    if "ssh-valid-time" not in output_str or "ssh-filter" not in output_str:
        return False
    
    # Check if the SSH valid time is restricted to 15 minutes or less
    ssh_valid_time = extract_value(output_str, "ssh-valid-time")
    if ssh_valid_time is None or int(ssh_valid_time) > 15:
        return False
    
    # Check if the SSH filter is configured to restrict access to specific IPs or subnets
    ssh_filter = extract_value(output_str, "ssh-filter")
    if ssh_filter is None or ssh_filter == "all":
        return False
    
    return True

def check_default_admin_disabled(output_str):
    """
    Check if the default admin account is disabled.
    
    Args:
        output_str (str): The output of the "get system admin" command.
    
    Returns:
        True if the default admin account is disabled, False otherwise.
    """
    # Check if the default admin account is present in the output
    if "admin admin" in output_str:
        # Check if the default admin account is disabled
        if "status: disable" in output_str:
            return True
        else:
            return False
    else:
        # Default admin account is not present, which is also acceptable
        return True

def run_checks(validator, checks):
    """
    Execute the validation checks and store the results.
    
    Args:
        validator (FortiGateValidator): The FortiGateValidator instance.
        checks (dict): A dictionary of validation checks, where the keys are the check names
                      and the values are dictionaries with "command", "test", and "requirement" keys.
    
    Returns:
        bool: True if all checks pass, False otherwise.
    """
    all_passed = True
    for check_name, check_config in checks.items():
        output = validator.execute_command(check_config["command"])
        passed = check_config["test"](output)
        validator.results[check_name] = {
            "requirement": check_config["requirement"],
            "passed": passed
        }
        if not passed:
            all_passed = False
    return all_passed



# Core validation functions   
    
def validate_logging_monitoring(validator):
    """CIS 3.x - Logging and Monitoring"""
    
def validate_network_services(validator):
    """CIS 4.x - Network Services"""
    
def validate_firewall_policies(validator):
    """CIS 5.x - Firewall Policy Controls"""


def validate_password_policy(validator):
    checks = {
        "password_policy_enabled": {
            "command": "get system password-policy",
            "test": lambda x: "status: enable" in x,
            "requirement": "CIS 1.1.1 - Password policy must be enabled"
        },
        "minimum_length": {
            "command": "get system password-policy", 
            "test": lambda x: extract_value(x, "minimum-length") >= 14,
            "requirement": "CIS 1.1.2 - Minimum password length 14+"
        },
        "complexity_requirements": {
            "command": "get system password-policy",
            "test": lambda x: all([
                "min-lower-case-letter: 1" in x,
                "min-upper-case-letter: 1" in x, 
                "min-non-alphanumeric: 1" in x,
                "min-number: 1" in x
            ]),
            "requirement": "CIS 1.1.3 - Password complexity"
        },
        "admin_lockout": {
            "command": "get system global",
            "test": lambda x: extract_value(x, "admin-lockout-threshold") <= 5,
            "requirement": "CIS 1.2.1 - Account lockout threshold"
        }
    }
    return run_checks(validator, checks)


def validate_admin_access(validator):
    checks = {
        "admin_timeout": {
            "command": "get system global",
            "test": lambda x: extract_value(x, "admintimeout") <= 15,
            "requirement": "CIS 2.1.1 - Admin session timeout"
        },
        "strong_crypto": {
            "command": "get system global",
            "test": lambda x: "strong-crypto: enable" in x,
            "requirement": "CIS 2.2.1 - Strong cryptography"
        },
        "ssh_restrictions": {
            "command": "get system admin",
            "test": lambda x: check_ssh_restrictions(x),
            "requirement": "CIS 2.3.1 - SSH access restrictions"
        },
        "default_admin": {
            "command": "get system admin",
            "test": lambda x: check_default_admin_disabled(x),
            "requirement": "CIS 2.4.1 - Default admin account disabled"
        }
    }  
    return run_checks(validator, checks)

class FortiGateValidator:
    def __init__(self, host, username, password, port=22):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.ssh = None
        self.results = {}

    def connect(self):
        """Establish SSH connection"""
        
    def execute_command(self, command):
        """Execute FortiOS command and return output"""
        
    def disconnect(self):
        """Close SSH connection"""

def main():
    parser = argparse.ArgumentParser(description="FortiGate CIS L1 + UK CAF + IEC 62443 SL4 Compliance Validator")
    parser.add_argument("--host", required=True, help="FortiGate hostname or IP address")
    parser.add_argument("--user", required=True, help="FortiGate admin username")
    parser.add_argument("--prompt-for-password", action="store_true", help="Prompt for password instead of using a command-line argument")
    args = parser.parse_args()

    if args.prompt_for_password:
        password = getpass.getpass("Enter FortiGate password: ")
    else:
        parser.add_argument("--password", required=True, help="FortiGate admin password")
        args = parser.parse_args()
        password = args.password

    validator = FortiGateValidator(
        host=args.host,
        username=args.user,
        password=password
    )

    # Run validation checks
    validate_password_policy(validator)
    #validate_admin_access(validator)
    #validate_logging_monitoring(validator)
    #validate_network_services(validator)
    #validate_firewall_policies(validator)

    # Display results
    for check, result in validator.results.items():
        print(f"{result['requirement']}: {'PASS' if result['passed'] else 'FAIL'}")

if __name__ == "__main__":
    main()


