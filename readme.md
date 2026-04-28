## FortiGate CIS L1, UK CAF, and IEC 62443 SL4 Compliance Validator

This Python script allows you to validate the configuration of your FortiGate firewall against the CIS Benchmarks for FortiOS (Level 1), as well as additional requirements from the UK Cyber Assessment Framework (UK CAF) and IEC 62443 Security Level 4 (SL4).

### Prerequisites

- Python 3.6 or later
- `paramiko` library (for SSH connectivity)

### Installation

1. Clone the repository:

```
git clone https://github.com/your-username/fortigate-compliance-validator.git
```

2. Install the required dependencies:

```
pip install paramiko
```

### Usage

1. Update the `FortiGateValidator` class in the `fortigate_validator.py` file with your FortiGate's connection details:

```python
validator = FortiGateValidator(
    host="your-fortigate-ip-or-hostname",
    username="your-fortigate-username",
    password="your-fortigate-password",
    port=22  # Change if necessary
)
```

2. Run the validation script:

```
python fortigate_validator.py
```

The script will connect to your FortiGate, run the various compliance checks, and display the results.

### Validation Checks

The script performs the following validation checks:

1. **Password Policy & Authentication (CIS 1.x)**
   - Password policy enabled
   - Minimum password length
   - Password complexity requirements
   - Admin account lockout

2. **Administrative Access (CIS 2.x)**
   - Admin session timeout
   - Strong cryptography
   - SSH access restrictions
   - Default admin account disabled

3. **Logging and Monitoring (CIS 3.x)**
   - System event logging
   - Firewall event logging
   - Log retention

4. **Network Services (CIS 4.x)**
   - Unnecessary network services disabled
   - SNMP access restrictions

5. **Firewall Policy Controls (CIS 5.x)**
   - Default deny firewall policy
   - Explicit firewall rules

The script also includes additional checks to meet the requirements of the UK Cyber Assessment Framework (UK CAF) and IEC 62443 Security Level 4 (SL4).

### Reporting

The validation results are displayed in the console output, with each check indicating whether it passed or failed, along with the relevant requirement.

### Customization

You can further customize the validation checks by modifying the `validate_*` functions in the `fortigate_validator.py` file. You can add, remove, or modify the checks to fit your specific compliance needs.

### Contributions

Contributions to this project are welcome. If you find any issues or have suggestions for improvements, please feel free to open an issue or submit a pull request.