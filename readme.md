## FortiGate CIS L1, UK CAF, and IEC 62443 SL4 Compliance Validator

This Python script allows you to validate the configuration of your FortiGate firewall against the CIS Benchmarks for FortiOS (Level 1), as well as additional requirements from the UK Cyber Assessment Framework (UK CAF) and IEC 62443 Security Level 4 (SL4).


## Compliance coverage (each check has id, severity, standards mapping, expected, actual, and remediation CLI):
•  CIS 1.x – password policy enabled, length ≥ 14 (SL4-hardened from CIS L1's 8), complexity, expiry ≤ 90 d, reuse prevention, lockout threshold/duration.
•  CIS 2.x – idle timeout ≤ 10 min, strong-crypto, pre/post login banners, trusted-hosts on every admin, default admin removed/disabled, SSHv1 disabled, plus IEC FR1.5 MFA-on-every-admin.
•  CIS 3.x – remote syslog enabled, reliable + encrypted transport, full event-filter coverage, local disk/memory buffer.
•  CIS 4.x – NTP sync, dual DNS, SNMPv3-only, no telnet/http on any interface, USB mgmt disabled.
•  CIS 5.x – no any/any rules, traffic logging on every policy, IPS sensor coverage, AV profile applied, ≥1 IPS sensor defined.
•  IEC 62443 SL4 extras – FIPS-CC mode, HA cluster active, admin GUI HTTPS-only, SSH-CBC/MD5/SHA1 disabled, admin TLS ≥ 1.2.

## Reporting
•  Console summary with PASS/FAIL/ERROR/MANUAL counts and overall score.
•  --report-json, --report-md, and a self-contained styled --report-html (severity-coloured rows, collapsible remediation).
•  --fail-on {any,high,never} controls the process exit code so the tool plugs into CI/pipelines.

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



Run example:
bash

### Usage

1. Run the validation script:


```
python audit-fortigate.py --host 192.168.1.99 --user admin --prompt-for-password --report-html report.html --report-json report.json --report-md report.md

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