# Fortigate CIS Level 1 Auditor

A lightweight script to audit FortiGate firewall configurations against the CIS Level 1 Benchmark. Ideal for security teams, auditors, and administrators who want a quick compliance check of FortiGate devices.

## Features

- Checks common hardening recommendations from the CIS FortiGate Benchmark
- Supports automated scanning of configuration files or direct device output
- Produces a concise report showing compliant and non-compliant settings
- Easy to integrate into security review workflows or scheduled audits

## Usage

1. Save your FortiGate configuration file locally.
2. Run the script against the configuration file.
3. Review the generated audit report and address any non-compliant findings.

Example:

```bash
python fortigate_cis_l1_auditor.py --config fortigate.conf
```

## Audit Scope

The script focuses on CIS Level 1 recommendations, including:

- Administrative access restrictions
- Password and authentication settings
- Logging and monitoring configuration
- Network protocol hardening
- System and firmware integrity settings

## Output

The audit report summarizes:

- Passed checks
- Failed checks
- Informational recommendations

## Requirements

- Python 3.8+
- Standard Python libraries or dependencies listed in requirements.txt if included

## Notes

This tool is intended to help assess FortiGate configuration posture against CIS Level 1 guidance, but it should be used as part of a broader security review process.

## License

Include your preferred license information here, if applicable.
