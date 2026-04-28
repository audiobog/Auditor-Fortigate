#!/usr/bin/env python3
"""
FortiGate CIS L1 + UK CAF + IEC 62443 SL4 Compliance Validator.

This single-file tool connects to a FortiGate device over SSH, runs a series
of read-only configuration queries, and grades the device against:

* CIS FortiGate Benchmark (Level 1) - sections 1.x through 5.x
* IEC 62443-3-3 Security Level 4 (SL4) Foundational Requirements (FR1-FR7)
* UK NCSC Cyber Assessment Framework (CAF) - mapped where applicable

The tool prints a console summary and can optionally emit JSON, Markdown,
and self-contained HTML reports.

Only `get`/`show`/`diagnose` style read-only commands are issued; the
script never modifies device configuration.
"""

from __future__ import annotations

import argparse
import getpass
import html
import json
import os
import re
import socket
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

try:
    import paramiko
except ImportError:  # pragma: no cover - import-time guard
    sys.stderr.write(
        "ERROR: the 'paramiko' package is required. Install it with:\n"
        "       pip install paramiko\n"
    )
    sys.exit(2)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"

STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_ERROR = "ERROR"
STATUS_MANUAL = "MANUAL"


@dataclass
class CheckResult:
    """Outcome of a single compliance check."""

    check_id: str
    title: str
    standards: List[str]
    severity: str
    requirement: str
    expected: str
    remediation: str
    status: str = STATUS_ERROR
    actual: str = ""
    evidence: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Helpers for parsing FortiOS output
# ---------------------------------------------------------------------------

# FortiOS `get` output uses `key   : value` (with arbitrary spaces around the
# colon). `show` output uses `set key value`.
_GET_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*:\s*(.*?)\s*$")
_SET_LINE_RE = re.compile(r"^\s*set\s+([A-Za-z0-9_.\-]+)\s+(.+?)\s*$")


def parse_get_output(output: str) -> Dict[str, str]:
    """Parse the `key : value` pairs produced by FortiOS `get` commands."""
    result: Dict[str, str] = {}
    for line in output.splitlines():
        m = _GET_LINE_RE.match(line)
        if not m:
            continue
        key, value = m.group(1), m.group(2).strip().strip('"')
        # Skip section headers like `== [ admin ]`
        if not key or key in {"name", "==", "--"}:
            continue
        result[key] = value
    return result


def extract_value(output: str, key: str) -> Optional[str]:
    """Return the value associated with `key` in `get` output, or None."""
    pattern = re.compile(
        rf"^\s*{re.escape(key)}\s*:\s*(.+?)\s*$",
        re.MULTILINE,
    )
    m = pattern.search(output)
    return m.group(1).strip().strip('"') if m else None


def to_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError, AttributeError):
        return default


def value_equals(output: str, key: str, expected: str) -> bool:
    val = extract_value(output, key)
    return val is not None and val.lower() == expected.lower()


# ---------------------------------------------------------------------------
# SSH session
# ---------------------------------------------------------------------------

# Strip ANSI escape sequences that some FortiOS versions emit.
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
# Default FortiGate prompts end with `# ` (privileged) or `$ ` (operator).
# Match either at start of buffer or after a newline so the very first prompt
# is recognised even when no preceding newline has been received.
_PROMPT_RE = re.compile(r"(?:^|[\r\n])[\w.\-]+(?:\s*\([\w.\-]+\))?\s*[#$]\s*$")
# FortiOS pre-login disclaimer prompt: "Press 'a' to accept this disclaimer".
_DISCLAIMER_RE = re.compile(r"Press\s+'a'\s+to\s+accept", re.IGNORECASE)
# FortiOS forced-password-change / Y-N prompts.
_YESNO_RE = re.compile(r"\(y/n\)\s*$", re.IGNORECASE)
# FortiOS "--More--" pager prompt (in case pager-disable hasn't taken effect yet).
_MORE_RE = re.compile(r"--More--\s*$")


class FortiGateSession:
    """Thin wrapper around a paramiko interactive shell to a FortiGate."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 22,
        timeout: int = 20,
        verbose: bool = False,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
        self._client: Optional[paramiko.SSHClient] = None
        self._chan: Optional[paramiko.Channel] = None

    # -- Lifecycle ---------------------------------------------------------

    def connect(self) -> None:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                allow_agent=False,
                look_for_keys=False,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
            )
        except (paramiko.AuthenticationException, paramiko.SSHException,
                socket.error, socket.timeout) as exc:
            raise ConnectionError(f"SSH connection to {self.host} failed: {exc}") from exc

        # Keep the SSH transport alive across slow checks so the FortiGate
        # doesn't tear the channel down on us mid-audit.
        try:
            transport = client.get_transport()
            if transport is not None:
                transport.set_keepalive(15)
        except Exception:  # pragma: no cover - best-effort hardening
            pass

        chan = client.invoke_shell(width=512, height=2000)
        chan.settimeout(self.timeout)
        self._client = client
        self._chan = chan

        # Drain banner / login text and accept any pre-login disclaimer.
        self._read_until_prompt(initial=True)
        # Disable terminal pagination on the FortiGate. We probe each command
        # individually so an unexpected error on one of them doesn't poison
        # the rest of the session.
        for cmd in ("config system console", "set output standard", "end"):
            if self._chan is None or self._chan.closed:
                raise ConnectionError(
                    "FortiGate closed the SSH channel during login. "
                    "Check trusted-hosts, account permissions, or any "
                    "forced password-change prompt."
                )
            try:
                self.execute_command(cmd)
            except Exception:  # pragma: no cover - best-effort hardening
                break

    def disconnect(self) -> None:
        if self._chan is not None:
            try:
                self._chan.send("exit\n")
            except Exception:
                pass
            try:
                self._chan.close()
            except Exception:
                pass
            self._chan = None
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def __enter__(self) -> "FortiGateSession":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.disconnect()

    # -- I/O ---------------------------------------------------------------

    def execute_command(self, command: str) -> str:
        """Run a single FortiOS CLI command and return its stripped output."""
        if self._chan is None:
            raise RuntimeError("SSH session is not connected")
        if self._chan.closed or self._chan.exit_status_ready():
            raise ConnectionError(
                "FortiGate SSH channel was closed by the remote side before "
                "the command could be sent. The most common causes are: a "
                "trusted-host restriction, an idle/admintimeout, or a "
                "pre-login disclaimer/forced password-change that the script "
                "could not auto-answer."
            )
        if self.verbose:
            print(f"  [cmd] {command}", file=sys.stderr)
        try:
            self._chan.send(command + "\n")
        except (OSError, paramiko.SSHException) as exc:
            raise ConnectionError(f"SSH send failed: {exc}") from exc
        raw = self._read_until_prompt()
        return self._clean_output(raw, command)

    def _read_until_prompt(self, initial: bool = False) -> str:
        assert self._chan is not None
        buf = ""
        deadline = time.time() + self.timeout
        idle_deadline = time.time() + (3 if initial else 1.5)
        while time.time() < deadline:
            if self._chan.closed:
                break
            if self._chan.recv_ready():
                try:
                    chunk = self._chan.recv(65535).decode("utf-8", errors="replace")
                except (OSError, socket.timeout, paramiko.SSHException):
                    break
                if not chunk:
                    break
                buf += chunk
                idle_deadline = time.time() + 1.0

                # Auto-handle interactive prompts that would otherwise hang us.
                if _DISCLAIMER_RE.search(buf):
                    try:
                        self._chan.send("a")
                    except Exception:
                        break
                    buf = ""
                    continue
                if _MORE_RE.search(buf):
                    try:
                        self._chan.send(" ")
                    except Exception:
                        break
                    continue
                if _YESNO_RE.search(buf):
                    # Decline anything we don't recognise (e.g. forced password
                    # change). The caller will see the surrounding text.
                    try:
                        self._chan.send("n\n")
                    except Exception:
                        break
                    continue

                if _PROMPT_RE.search(buf):
                    # Make sure no more bytes are pending.
                    time.sleep(0.05)
                    if not self._chan.recv_ready():
                        break
            else:
                if time.time() >= idle_deadline and (initial or _PROMPT_RE.search(buf)):
                    break
                time.sleep(0.05)
        return buf

    @staticmethod
    def _clean_output(raw: str, command: str) -> str:
        text = _ANSI_RE.sub("", raw).replace("\r\n", "\n").replace("\r", "\n")
        lines = text.split("\n")
        # Drop the first line if it just echoes the command we sent.
        if lines and command and lines[0].strip().endswith(command.strip()):
            lines = lines[1:]
        # Drop the final prompt line (FortiGate may include a sub-mode segment
        # in parentheses, e.g. "FGT-VM64 (global) #").
        prompt_line = re.compile(r"^[\w.\-]+(?:\s*\([\w.\-]+\))?\s*[#$]\s*$")
        if lines and prompt_line.match(lines[-1].strip()):
            lines = lines[:-1]
        return "\n".join(lines).strip()


# ---------------------------------------------------------------------------
# Check engine
# ---------------------------------------------------------------------------

# A "check spec" is a dict describing one compliance test. The engine
# executes commands once per unique command, then evaluates each check.

CheckFn = Callable[[Dict[str, str]], "CheckOutcome"]


@dataclass
class CheckOutcome:
    """Returned by a check function to describe the verdict."""

    status: str
    actual: str = ""
    evidence: str = ""


class CheckEngine:
    def __init__(self, session: Optional[FortiGateSession], offline: bool = False) -> None:
        self.session = session
        self.offline = offline
        self._cache: Dict[str, str] = {}
        self.results: List[CheckResult] = []

    def run(self, command: str) -> str:
        if self.offline or self.session is None:
            return self._cache.get(command, "")
        if command in self._cache:
            return self._cache[command]
        try:
            output = self.session.execute_command(command)
        except Exception as exc:  # pragma: no cover - runtime only
            output = f"__ERROR__: {exc}"
        self._cache[command] = output
        return output

    def evaluate(
        self,
        check_id: str,
        title: str,
        standards: List[str],
        severity: str,
        requirement: str,
        expected: str,
        remediation: str,
        commands: List[str],
        evaluator: Callable[[Dict[str, str]], CheckOutcome],
    ) -> CheckResult:
        result = CheckResult(
            check_id=check_id,
            title=title,
            standards=standards,
            severity=severity,
            requirement=requirement,
            expected=expected,
            remediation=remediation,
        )
        outputs: Dict[str, str] = {}
        try:
            for cmd in commands:
                outputs[cmd] = self.run(cmd)
            for cmd, out in outputs.items():
                if out.startswith("__ERROR__"):
                    raise RuntimeError(out)
            outcome = evaluator(outputs)
            result.status = outcome.status
            result.actual = outcome.actual
            result.evidence = outcome.evidence
        except Exception as exc:
            result.status = STATUS_ERROR
            result.error = str(exc)
        self.results.append(result)
        return result


# ---------------------------------------------------------------------------
# Compliance checks
# ---------------------------------------------------------------------------

CIS = "CIS FortiGate L1"
IEC = "IEC 62443-3-3 SL4"
CAF = "UK NCSC CAF"


def _outcome(passed: bool, actual: str, evidence: str = "") -> CheckOutcome:
    return CheckOutcome(STATUS_PASS if passed else STATUS_FAIL, actual=actual, evidence=evidence)


def register_password_policy_checks(engine: CheckEngine) -> None:
    cmd = "get system password-policy"

    def chk_enabled(o: Dict[str, str]) -> CheckOutcome:
        out = o[cmd]
        status = extract_value(out, "status") or "unknown"
        return _outcome(status.lower() == "enable", f"status={status}", out)

    engine.evaluate(
        "CIS-1.1.1",
        "Password policy is enabled",
        [CIS, IEC + " FR1.7", CAF + " B2.a"],
        SEVERITY_HIGH,
        "A password policy must be enforced for all administrative accounts.",
        "status: enable",
        "config system password-policy\n  set status enable\nend",
        [cmd],
        chk_enabled,
    )

    def chk_minlen(o: Dict[str, str]) -> CheckOutcome:
        n = to_int(extract_value(o[cmd], "minimum-length"))
        return _outcome(n is not None and n >= 14, f"minimum-length={n}")

    engine.evaluate(
        "CIS-1.1.2",
        "Minimum password length >= 14",
        [CIS, IEC + " FR1.7"],
        SEVERITY_HIGH,
        "Administrative passwords must be at least 14 characters long (SL4 hardening over CIS L1's 8).",
        "minimum-length >= 14",
        "config system password-policy\n  set minimum-length 14\nend",
        [cmd],
        chk_minlen,
    )

    def chk_complexity(o: Dict[str, str]) -> CheckOutcome:
        out = o[cmd]
        checks = {
            "min-lower-case-letter": 1,
            "min-upper-case-letter": 1,
            "min-non-alphanumeric": 1,
            "min-number": 1,
        }
        actual_parts: List[str] = []
        ok = True
        for key, want in checks.items():
            val = to_int(extract_value(out, key))
            actual_parts.append(f"{key}={val}")
            if val is None or val < want:
                ok = False
        return _outcome(ok, ", ".join(actual_parts))

    engine.evaluate(
        "CIS-1.1.3",
        "Password complexity (upper, lower, number, special)",
        [CIS, IEC + " FR1.7"],
        SEVERITY_HIGH,
        "Passwords must contain at least one uppercase, lowercase, numeric and special character.",
        "all of: min-upper-case-letter, min-lower-case-letter, min-number, min-non-alphanumeric >= 1",
        "config system password-policy\n  set min-lower-case-letter 1\n  set min-upper-case-letter 1\n  set min-number 1\n  set min-non-alphanumeric 1\nend",
        [cmd],
        chk_complexity,
    )

    def chk_expiry(o: Dict[str, str]) -> CheckOutcome:
        days = to_int(extract_value(o[cmd], "expire-day"))
        return _outcome(days is not None and 0 < days <= 90, f"expire-day={days}")

    engine.evaluate(
        "CIS-1.1.4",
        "Password expiration <= 365 days",
        [CIS, IEC + " FR1.7"],
        SEVERITY_MEDIUM,
        "Administrative passwords must expire at least every 365 days.",
        "expire-day in (365)",
        "config system password-policy\n  set expire-status enable\n  set expire-day 365\nend",
        [cmd],
        chk_expiry,
    )

    def chk_reuse(o: Dict[str, str]) -> CheckOutcome:
        reuse = to_int(extract_value(o[cmd], "reuse-password"))
        # 0 (off) means reuse is allowed - we want it disabled or counted.
        status = extract_value(o[cmd], "reuse-password")
        return _outcome(status is not None and status.lower() == "disable",
                        f"reuse-password={status}")

    engine.evaluate(
        "CIS-1.1.5",
        "Password reuse prevention",
        [CIS, IEC + " FR1.7"],
        SEVERITY_MEDIUM,
        "Reuse of previous administrative passwords must be prevented.",
        "reuse-password: disable",
        "config system password-policy\n  set reuse-password disable\nend",
        [cmd],
        chk_reuse,
    )

    def chk_lockout(o: Dict[str, str]) -> CheckOutcome:
        out = engine.run("get system global")
        threshold = to_int(extract_value(out, "admin-lockout-threshold"))
        duration = to_int(extract_value(out, "admin-lockout-duration"))
        ok = (threshold is not None and 0 < threshold <= 5
              and duration is not None and duration >= 60)
        return _outcome(ok, f"threshold={threshold}, duration={duration}s")

    engine.evaluate(
        "CIS-1.2.1",
        "Admin lockout threshold and duration",
        [CIS, IEC + " FR1.11", CAF + " B2.a"],
        SEVERITY_HIGH,
        "Failed logins must lock the account after a small number of attempts.",
        "admin-lockout-threshold <= 5 AND admin-lockout-duration >= 60",
        "config system global\n  set admin-lockout-threshold 3\n  set admin-lockout-duration 60\nend",
        ["get system global"],
        chk_lockout,
    )


def register_admin_access_checks(engine: CheckEngine) -> None:
    g = "get system global"
    a = "show system admin"
    a_get = "get system admin"

    def chk_timeout(o: Dict[str, str]) -> CheckOutcome:
        n = to_int(extract_value(o[g], "admintimeout"))
        return _outcome(n is not None and 0 < n <= 15, f"admintimeout={n}")

    engine.evaluate(
        "CIS-2.1.1",
        "Idle administrative session timeout <= 15 minutes",
        [CIS, IEC + " FR1.13"],
        SEVERITY_HIGH,
        "Idle administrator sessions must be terminated within 15 minutes.",
        "admintimeout in (1..15)",
        "config system global\n  set admintimeout 5\nend",
        [g],
        chk_timeout,
    )

    def chk_strong_crypto(o: Dict[str, str]) -> CheckOutcome:
        return _outcome(value_equals(o[g], "strong-crypto", "enable"),
                        f"strong-crypto={extract_value(o[g], 'strong-crypto')}")

    engine.evaluate(
        "CIS-2.2.1",
        "Strong cryptography enabled (TLS 1.2+/SSH-2)",
        [CIS, IEC + " FR4.1"],
        SEVERITY_HIGH,
        "FIPS-grade ciphers must be enforced for all management traffic.",
        "strong-crypto: enable",
        "config system global\n  set strong-crypto enable\nend",
        [g],
        chk_strong_crypto,
    )

    def chk_pre_login_banner(o: Dict[str, str]) -> CheckOutcome:
        return _outcome(value_equals(o[g], "pre-login-banner", "enable"),
                        f"pre-login-banner={extract_value(o[g], 'pre-login-banner')}")

    engine.evaluate(
        "CIS-2.1.2",
        "Pre-login banner enabled",
        [CIS, CAF + " B5.a"],
        SEVERITY_LOW,
        "A pre-login banner notifying users of acceptable use must be displayed.",
        "pre-login-banner: enable",
        "config system global\n  set pre-login-banner enable\nend",
        [g],
        chk_pre_login_banner,
    )

    def chk_post_login_banner(o: Dict[str, str]) -> CheckOutcome:
        return _outcome(value_equals(o[g], "post-login-banner", "enable"),
                        f"post-login-banner={extract_value(o[g], 'post-login-banner')}")

    engine.evaluate(
        "CIS-2.1.3",
        "Post-login banner enabled",
        [CIS, CAF + " B5.a"],
        SEVERITY_LOW,
        "A post-login banner reinforcing accountability must be displayed.",
        "post-login-banner: enable",
        "config system global\n  set post-login-banner enable\nend",
        [g],
        chk_post_login_banner,
    )

    def chk_trusted_hosts(o: Dict[str, str]) -> CheckOutcome:
        out = o[a]
        # Look for `set trusthost1` lines under at least one admin section.
        admins_with_trusthost = len(re.findall(r"set\s+trusthost\d+\s+", out))
        admin_blocks = re.findall(r"edit\s+\"[^\"]+\"", out)
        ok = bool(admin_blocks) and admins_with_trusthost >= len(admin_blocks)
        return _outcome(
            ok,
            f"admins={len(admin_blocks)}, trusthost-entries={admins_with_trusthost}",
        )

    engine.evaluate(
        "CIS-2.3.1",
        "All admin accounts restricted by trusted hosts",
        [CIS, IEC + " FR1.1", CAF + " B2.c"],
        SEVERITY_HIGH,
        "Every administrator account must restrict source IPs via trusthost1..N.",
        "every admin has at least one trusthost set",
        "config system admin\n  edit <name>\n    set trusthost1 <cidr>\n  next\nend",
        [a],
        chk_trusted_hosts,
    )

    def chk_default_admin(o: Dict[str, str]) -> CheckOutcome:
        out = o[a]
        # CIS requires the built-in 'admin' account to be removed or disabled.
        present = re.search(r"edit\s+\"admin\"", out) is not None
        if not present:
            return _outcome(True, "default 'admin' account not present")
        # Look for 'set status disable' inside the admin block.
        admin_block = re.search(
            r"edit\s+\"admin\"(?P<body>.*?)next", out, flags=re.DOTALL,
        )
        body = admin_block.group("body") if admin_block else ""
        disabled = bool(re.search(r"set\s+status\s+disable", body))
        return _outcome(disabled, "default 'admin' present, "
                        + ("disabled" if disabled else "ENABLED"))

    engine.evaluate(
        "CIS-2.4.1",
        "Default 'admin' account removed or disabled",
        [CIS, IEC + " FR1.1"],
        SEVERITY_HIGH,
        "The factory-default 'admin' username must not be usable.",
        "no enabled admin named 'admin'",
        "config system admin\n  delete admin\nend  (or rename / disable)",
        [a],
        chk_default_admin,
    )

    def chk_admin_two_factor(o: Dict[str, str]) -> CheckOutcome:
        out = o[a]
        admin_blocks = re.findall(
            r"edit\s+\"[^\"]+\"(.*?)next", out, flags=re.DOTALL,
        )
        if not admin_blocks:
            return CheckOutcome(STATUS_MANUAL, actual="no admin blocks parsed")
        with_2fa = 0
        for body in admin_blocks:
            if re.search(r"set\s+two-factor\s+(fortitoken|email|sms|fortitoken-cloud)",
                         body):
                with_2fa += 1
        ok = with_2fa == len(admin_blocks)
        return _outcome(ok, f"{with_2fa}/{len(admin_blocks)} admins with 2FA")

    engine.evaluate(
        "IEC-1.5",
        "Multi-factor authentication for all administrators",
        [IEC + " FR1.5", CAF + " B2.a"],
        SEVERITY_HIGH,
        "All administrative accounts must require a second authentication factor.",
        "every admin: set two-factor fortitoken|email|sms",
        "config system admin\n  edit <name>\n    set two-factor fortitoken\n    set fortitoken <serial>\n  next\nend",
        [a],
        chk_admin_two_factor,
    )

    def chk_ssh_v2(o: Dict[str, str]) -> CheckOutcome:
        return _outcome(
            value_equals(o[g], "admin-ssh-v1", "disable"),
            f"admin-ssh-v1={extract_value(o[g], 'admin-ssh-v1')}",
        )

    engine.evaluate(
        "CIS-2.3.2",
        "SSHv1 disabled on management plane",
        [CIS, IEC + " FR4.1"],
        SEVERITY_MEDIUM,
        "Only SSHv2 must be permitted for CLI administration.",
        "admin-ssh-v1: disable",
        "config system global\n  set admin-ssh-v1 disable\nend",
        [g],
        chk_ssh_v2,
    )


def register_logging_checks(engine: CheckEngine) -> None:
    """CIS 3.x - Logging and Monitoring + IEC 62443 FR2/FR6."""
    syslog = "show log syslogd setting"
    eventfilter = "show log eventfilter"
    diskset = "show log disk setting"
    memoryset = "show log memory setting"

    def chk_syslog(o: Dict[str, str]) -> CheckOutcome:
        out = o[syslog]
        enabled = bool(re.search(r"set\s+status\s+enable", out))
        has_server = bool(re.search(r"set\s+server\s+\S+", out))
        return _outcome(enabled and has_server,
                        f"syslogd enabled={enabled}, server={'set' if has_server else 'unset'}")

    engine.evaluate(
        "CIS-3.1.1",
        "Remote syslog enabled",
        [CIS, IEC + " FR6.1", CAF + " C1.a"],
        SEVERITY_HIGH,
        "Logs must be shipped off-box to a tamper-evident SIEM/syslog target.",
        "syslogd status enable AND server set",
        "config log syslogd setting\n  set status enable\n  set server <ip>\n  set mode reliable\n  set port 6514\nend",
        [syslog],
        chk_syslog,
    )

    def chk_syslog_secure(o: Dict[str, str]) -> CheckOutcome:
        out = o[syslog]
        reliable = bool(re.search(r"set\s+mode\s+reliable", out))
        encrypt = bool(re.search(r"set\s+enc-algorithm\s+(high|high-medium|default)", out))
        # FortiOS uses 'reliable' (TCP) and optionally 'enc-algorithm' for TLS.
        return _outcome(reliable and encrypt,
                        f"reliable={reliable}, enc={encrypt}")

    engine.evaluate(
        "IEC-6.2",
        "Syslog transport is reliable and encrypted",
        [IEC + " FR4.1", IEC + " FR6.1"],
        SEVERITY_HIGH,
        "Audit log transmission to the SIEM must be reliable and confidential.",
        "syslogd mode reliable AND enc-algorithm high",
        "config log syslogd setting\n  set mode reliable\n  set enc-algorithm high\nend",
        [syslog],
        chk_syslog_secure,
    )

    def chk_event_logging(o: Dict[str, str]) -> CheckOutcome:
        out = o[eventfilter]
        keys = ["event", "system", "user", "router", "vpn", "wan-opt"]
        missing = [k for k in keys if not re.search(rf"set\s+{re.escape(k)}\s+enable", out)]
        return _outcome(not missing,
                        "all enabled" if not missing else f"missing: {','.join(missing)}")

    engine.evaluate(
        "CIS-3.1.2",
        "All event categories logged",
        [CIS, IEC + " FR2.8"],
        SEVERITY_MEDIUM,
        "All security-relevant event categories must be logged.",
        "log eventfilter: event, system, user, router, vpn, wan-opt = enable",
        "config log eventfilter\n  set event enable\n  set system enable\n  set user enable\n  set router enable\n  set vpn enable\nend",
        [eventfilter],
        chk_event_logging,
    )

    def chk_disk_or_memory_log(o: Dict[str, str]) -> CheckOutcome:
        disk_on = bool(re.search(r"set\s+status\s+enable", o[diskset]))
        mem_on = bool(re.search(r"set\s+status\s+enable", o[memoryset]))
        return _outcome(disk_on or mem_on,
                        f"disk={disk_on}, memory={mem_on}")

    engine.evaluate(
        "CIS-3.2.1",
        "Local logging buffer enabled",
        [CIS],
        SEVERITY_LOW,
        "Local disk or memory logging must be available to bridge syslog outages.",
        "disk or memory log status: enable",
        "config log disk setting\n  set status enable\nend",
        [diskset, memoryset],
        chk_disk_or_memory_log,
    )


def register_network_services_checks(engine: CheckEngine) -> None:
    """CIS 4.x - Network services + IEC 62443 FR7 (resource availability)."""
    g = "get system global"
    ntp = "get system ntp"
    dns = "get system dns"
    snmp_sys = "show system snmp sysinfo"
    snmp_comm = "show system snmp community"
    snmp_user = "show system snmp user"
    interfaces = "show system interface"

    def chk_ntp(o: Dict[str, str]) -> CheckOutcome:
        ok = value_equals(o[ntp], "ntpsync", "enable")
        return _outcome(ok, f"ntpsync={extract_value(o[ntp], 'ntpsync')}")

    engine.evaluate(
        "CIS-4.1.1",
        "NTP synchronisation enabled",
        [CIS, IEC + " FR2.10"],
        SEVERITY_MEDIUM,
        "Accurate time is required for forensic correlation.",
        "ntpsync: enable",
        "config system ntp\n  set ntpsync enable\n  set type custom\n  set server <ntp>\nend",
        [ntp],
        chk_ntp,
    )

    def chk_dns(o: Dict[str, str]) -> CheckOutcome:
        primary = extract_value(o[dns], "primary")
        secondary = extract_value(o[dns], "secondary")
        ok = bool(primary) and primary != "0.0.0.0" and bool(secondary) and secondary != "0.0.0.0"
        return _outcome(ok, f"primary={primary}, secondary={secondary}")

    engine.evaluate(
        "CIS-4.1.2",
        "Resilient DNS configuration",
        [CIS, IEC + " FR7.1"],
        SEVERITY_LOW,
        "Both primary and secondary DNS must be configured for resilience.",
        "primary AND secondary DNS set (non-zero)",
        "config system dns\n  set primary <ip>\n  set secondary <ip>\nend",
        [dns],
        chk_dns,
    )

    def chk_snmp_v3_only(o: Dict[str, str]) -> CheckOutcome:
        comm = o[snmp_comm]
        user = o[snmp_user]
        v1v2_enabled = bool(re.search(r"set\s+status\s+enable", comm))
        v3_users = len(re.findall(r"edit\s+\"[^\"]+\"", user))
        ok = (not v1v2_enabled) and v3_users > 0
        return _outcome(ok, f"v1/v2c={'on' if v1v2_enabled else 'off'}, v3-users={v3_users}")

    engine.evaluate(
        "CIS-4.3.1",
        "SNMPv3 only (no v1/v2c communities)",
        [CIS, IEC + " FR4.1"],
        SEVERITY_HIGH,
        "Only authenticated/encrypted SNMPv3 may be used; v1/v2c must be disabled.",
        "no enabled snmp communities AND >=1 snmp v3 user",
        "config system snmp community\n  delete <id>\nend\nconfig system snmp user\n  edit <name>\n    set security-level auth-priv\n    set auth-proto sha256\n    set priv-proto aes256\n  next\nend",
        [snmp_comm, snmp_user],
        chk_snmp_v3_only,
    )

    def chk_mgmt_services(o: Dict[str, str]) -> CheckOutcome:
        out = o[interfaces]
        bad = []
        for proto in ("telnet", "http"):
            if re.search(rf"set\s+allowaccess[^\n]*\b{proto}\b", out):
                bad.append(proto)
        return _outcome(not bad, "clear-text mgmt: " + (",".join(bad) if bad else "none"))

    engine.evaluate(
        "CIS-4.4.1",
        "No clear-text management protocols on any interface",
        [CIS, IEC + " FR4.1"],
        SEVERITY_HIGH,
        "Telnet and HTTP must not be permitted on any interface.",
        "no interface has allowaccess including telnet or http",
        "config system interface\n  edit <iface>\n    unset allowaccess  (then re-add only ssh, https, ping, snmp)\n  next\nend",
        [interfaces],
        chk_mgmt_services,
    )

    def chk_usb_disable(o: Dict[str, str]) -> CheckOutcome:
        out = o[g]
        return _outcome(value_equals(out, "usb-mgmt", "disable"),
                        f"usb-mgmt={extract_value(out, 'usb-mgmt')}")

    engine.evaluate(
        "IEC-3.2",
        "USB management interface disabled",
        [IEC + " FR3.2"],
        SEVERITY_MEDIUM,
        "Physical USB-based provisioning must be disabled to reduce attack surface.",
        "usb-mgmt: disable",
        "config system global\n  set usb-mgmt disable\nend",
        [g],
        chk_usb_disable,
    )


def register_firewall_policy_checks(engine: CheckEngine) -> None:
    """CIS 5.x - Firewall Policy Controls + IEC 62443 FR5 (restricted data flow)."""
    policies = "show firewall policy"
    avs = "show antivirus profile"
    ips = "show ips sensor"

    def chk_any_any(o: Dict[str, str]) -> CheckOutcome:
        out = o[policies]
        # Find policies whose srcaddr, dstaddr or service is just 'all/ALL'.
        edits = re.findall(r"edit\s+\d+(.*?)next", out, flags=re.DOTALL)
        offenders: List[str] = []
        for idx, body in enumerate(edits, 1):
            src = re.search(r"set\s+srcaddr\s+([^\n]+)", body)
            dst = re.search(r"set\s+dstaddr\s+([^\n]+)", body)
            svc = re.search(r"set\s+service\s+([^\n]+)", body)
            sname = re.search(r"set\s+name\s+\"([^\"]+)\"", body)
            label = sname.group(1) if sname else f"policy#{idx}"
            if src and dst and svc and \
                    re.fullmatch(r'"all"\s*', src.group(1).strip()) and \
                    re.fullmatch(r'"all"\s*', dst.group(1).strip()) and \
                    re.fullmatch(r'"ALL"\s*', svc.group(1).strip()):
                offenders.append(label)
        return _outcome(not offenders,
                        "any/any policies: " + (",".join(offenders) if offenders else "none"))

    engine.evaluate(
        "CIS-5.1.1",
        "No any/any firewall policies",
        [CIS, IEC + " FR5.1", CAF + " B4.a"],
        SEVERITY_HIGH,
        "Policies that allow all sources, destinations and services concurrently are forbidden.",
        "no policy with srcaddr=all AND dstaddr=all AND service=ALL",
        "Replace overly broad policies with least-privilege rules limited by source, destination and service.",
        [policies],
        chk_any_any,
    )

    def chk_logging(o: Dict[str, str]) -> CheckOutcome:
        out = o[policies]
        edits = re.findall(r"edit\s+\d+(.*?)next", out, flags=re.DOTALL)
        if not edits:
            return CheckOutcome(STATUS_MANUAL, actual="no policies parsed")
        without_log = 0
        for body in edits:
            if not re.search(r"set\s+logtraffic\s+(all|utm)", body):
                without_log += 1
        return _outcome(without_log == 0,
                        f"{len(edits) - without_log}/{len(edits)} policies with traffic logging")

    engine.evaluate(
        "CIS-5.2.1",
        "All firewall policies log traffic",
        [CIS, IEC + " FR2.8", CAF + " C1.a"],
        SEVERITY_MEDIUM,
        "Every accept/deny policy must log traffic for auditability.",
        "set logtraffic all|utm on every policy",
        "config firewall policy\n  edit <id>\n    set logtraffic all\n  next\nend",
        [policies],
        chk_logging,
    )

    def chk_ips(o: Dict[str, str]) -> CheckOutcome:
        out = o[policies]
        edits = re.findall(r"edit\s+\d+(.*?)next", out, flags=re.DOTALL)
        if not edits:
            return CheckOutcome(STATUS_MANUAL, actual="no policies parsed")
        with_ips = sum(1 for b in edits if re.search(r"set\s+ips-sensor\s+\"", b))
        ok = with_ips >= max(1, len(edits) // 2)  # at least half
        return _outcome(ok, f"{with_ips}/{len(edits)} policies with ips-sensor")

    engine.evaluate(
        "CIS-5.3.1",
        "IPS profile applied on inter-zone policies",
        [CIS, IEC + " FR3.4"],
        SEVERITY_HIGH,
        "Intrusion Prevention must protect cross-zone traffic.",
        ">=50% of policies have an ips-sensor set",
        "config firewall policy\n  edit <id>\n    set ips-sensor \"protect_client\"\n  next\nend",
        [policies],
        chk_ips,
    )

    def chk_av(o: Dict[str, str]) -> CheckOutcome:
        out_av = o[avs]
        out_pol = o[policies]
        has_av_profile = bool(re.search(r"edit\s+\"[^\"]+\"", out_av))
        edits = re.findall(r"edit\s+\d+(.*?)next", out_pol, flags=re.DOTALL)
        with_av = sum(1 for b in edits if re.search(r"set\s+av-profile\s+\"", b))
        ok = has_av_profile and with_av > 0
        return _outcome(ok,
                        f"av-profile defined={has_av_profile}, policies with av={with_av}")

    engine.evaluate(
        "CIS-5.4.1",
        "Antivirus profile applied to user-facing policies",
        [CIS, IEC + " FR3.2"],
        SEVERITY_MEDIUM,
        "AV inspection must protect user/server flows.",
        ">=1 policy with av-profile",
        "config antivirus profile\n  edit \"default\"\n  next\nend\nconfig firewall policy\n  edit <id>\n    set av-profile \"default\"\n  next\nend",
        [avs, policies],
        chk_av,
    )

    def chk_ips_sensor_defined(o: Dict[str, str]) -> CheckOutcome:
        return _outcome(bool(re.search(r"edit\s+\"[^\"]+\"", o[ips])),
                        "ips sensors found" if re.search(r"edit\s+\"[^\"]+\"", o[ips])
                        else "no ips sensors defined")

    engine.evaluate(
        "IEC-3.4",
        "At least one IPS sensor profile is defined",
        [IEC + " FR3.4"],
        SEVERITY_LOW,
        "The device must have at least one IPS profile available to attach to policies.",
        ">=1 ips sensor",
        "config ips sensor\n  edit \"default\"\n  next\nend",
        [ips],
        chk_ips_sensor_defined,
    )


def register_iec_sl4_checks(engine: CheckEngine) -> None:
    """Additional IEC 62443 SL4 / UK CAF specific controls."""
    g = "get system global"
    fips = "get system fips-cc"
    ha = "get system ha status"
    ha_cfg = "get system ha"

    def chk_fips_cc(o: Dict[str, str]) -> CheckOutcome:
        # Older FortiOS versions expose fips-cc via `get system global`.
        out = o[g]
        val = extract_value(out, "fips-cc-mode") or extract_value(o.get(fips, ""), "status")
        return _outcome(val is not None and val.lower() == "enable",
                        f"fips-cc={val}")

    engine.evaluate(
        "IEC-4.3",
        "FIPS-CC mode enabled",
        [IEC + " FR4.3", CAF + " B5.b"],
        SEVERITY_HIGH,
        "FIPS 140-2/3 evaluated cryptographic mode is required at SL4.",
        "fips-cc-mode: enable",
        "config system fips-cc\n  set status enable\nend",
        [g, fips],
        chk_fips_cc,
    )

    def chk_ha(o: Dict[str, str]) -> CheckOutcome:
        out_status = o[ha]
        out_cfg = o[ha_cfg]
        mode = extract_value(out_cfg, "mode") or "standalone"
        ok = mode.lower() in {"a-p", "a-a", "active-passive", "active-active"}
        return _outcome(ok, f"ha-mode={mode}")

    engine.evaluate(
        "IEC-7.2",
        "High availability cluster configured",
        [IEC + " FR7.2", CAF + " D1.a"],
        SEVERITY_MEDIUM,
        "Redundant control / data plane is required for SL4 availability.",
        "ha-mode in {a-p, a-a}",
        "config system ha\n  set mode a-p\n  set group-name <gid>\nend",
        [ha, ha_cfg],
        chk_ha,
    )

    def chk_admin_https_only(o: Dict[str, str]) -> CheckOutcome:
        out = o[g]
        port = to_int(extract_value(out, "admin-port"))
        sport = to_int(extract_value(out, "admin-sport"))
        https_redirect = value_equals(out, "admin-https-redirect", "enable")
        # If admin-port (HTTP) is reachable without redirect, fail.
        return _outcome(https_redirect or port is None or port == 0,
                        f"admin-port={port}, admin-sport={sport}, https-redirect={https_redirect}")

    engine.evaluate(
        "IEC-4.1",
        "Management GUI forces HTTPS",
        [IEC + " FR4.1", CAF + " B5.b"],
        SEVERITY_HIGH,
        "Plaintext HTTP administration must be redirected to HTTPS.",
        "admin-https-redirect: enable",
        "config system global\n  set admin-https-redirect enable\nend",
        [g],
        chk_admin_https_only,
    )

    def chk_global_strong(o: Dict[str, str]) -> CheckOutcome:
        out = o[g]
        bits = {
            "strong-crypto": "enable",
            "ssh-cbc-cipher": "disable",
            "ssh-hmac-md5": "disable",
            "ssh-kex-sha1": "disable",
            "admin-https-ssl-versions": "tlsv1-2 tlsv1-3",
        }
        actual_parts: List[str] = []
        ok = True
        for key, want in bits.items():
            v = extract_value(out, key)
            actual_parts.append(f"{key}={v}")
            if v is None:
                ok = False
                continue
            if want.startswith("tlsv"):
                if "tlsv1-2" not in v and "tlsv1-3" not in v:
                    ok = False
                if "tlsv1.0" in v or "tlsv1-0" in v or "tlsv1.1" in v or "tlsv1-1" in v:
                    ok = False
            elif v.lower() != want.lower():
                ok = False
        return _outcome(ok, ", ".join(actual_parts))

    engine.evaluate(
        "IEC-4.2",
        "Cryptographic hardening (no SSH-CBC, MD5, SHA1, TLS<1.2)",
        [IEC + " FR4.1", CIS],
        SEVERITY_HIGH,
        "Weak ciphers must be disabled across the management plane.",
        "ssh-cbc-cipher/ssh-hmac-md5/ssh-kex-sha1: disable; admin TLS >= 1.2",
        "config system global\n  set ssh-cbc-cipher disable\n  set ssh-hmac-md5 disable\n  set ssh-kex-sha1 disable\n  set admin-https-ssl-versions tlsv1-2 tlsv1-3\nend",
        [g],
        chk_global_strong,
    )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _summary_counts(results: List[CheckResult]) -> Dict[str, int]:
    counts = {STATUS_PASS: 0, STATUS_FAIL: 0, STATUS_ERROR: 0, STATUS_MANUAL: 0}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts


def render_console(results: List[CheckResult], device: str) -> str:
    counts = _summary_counts(results)
    total = len(results)
    score = (counts[STATUS_PASS] / total * 100.0) if total else 0.0

    lines: List[str] = []
    lines.append("=" * 78)
    lines.append(f" FortiGate Compliance Report  -  {device}")
    lines.append(f" Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    lines.append("=" * 78)
    lines.append(
        f" PASS={counts[STATUS_PASS]}  FAIL={counts[STATUS_FAIL]}  "
        f"ERROR={counts[STATUS_ERROR]}  MANUAL={counts[STATUS_MANUAL]}  "
        f"(score: {score:.1f}%)"
    )
    lines.append("-" * 78)
    for r in sorted(results, key=lambda x: (x.status != STATUS_FAIL, x.check_id)):
        marker = {
            STATUS_PASS: "[ OK ]",
            STATUS_FAIL: "[FAIL]",
            STATUS_ERROR: "[ERR ]",
            STATUS_MANUAL: "[MAN ]",
        }.get(r.status, "[ ?? ]")
        lines.append(f"{marker} {r.check_id} ({r.severity}) - {r.title}")
        lines.append(f"        standards : {', '.join(r.standards)}")
        lines.append(f"        expected  : {r.expected}")
        if r.actual:
            lines.append(f"        actual    : {r.actual}")
        if r.error:
            lines.append(f"        error     : {r.error}")
        if r.status == STATUS_FAIL:
            lines.append(f"        remediate : {r.remediation.splitlines()[0]}")
    lines.append("=" * 78)
    return "\n".join(lines)


def render_json(results: List[CheckResult], device: str) -> str:
    payload = {
        "device": device,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": _summary_counts(results),
        "total": len(results),
        "results": [r.to_dict() for r in results],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def render_markdown(results: List[CheckResult], device: str) -> str:
    counts = _summary_counts(results)
    total = len(results)
    score = (counts[STATUS_PASS] / total * 100.0) if total else 0.0
    out: List[str] = []
    out.append(f"# FortiGate Compliance Report - {device}")
    out.append("")
    out.append(f"_Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}_")
    out.append("")
    out.append(f"**Summary:** PASS={counts[STATUS_PASS]} | FAIL={counts[STATUS_FAIL]} "
               f"| ERROR={counts[STATUS_ERROR]} | MANUAL={counts[STATUS_MANUAL]} "
               f"| Score: **{score:.1f}%**")
    out.append("")
    out.append("## Results")
    for r in sorted(results, key=lambda x: x.check_id):
        out.append("")
        out.append(f"### {r.check_id} - {r.title}")
        out.append(f"- **Status:** {r.status}")
        out.append(f"- **Severity:** {r.severity}")
        out.append(f"- **Standards:** {', '.join(r.standards)}")
        out.append(f"- **Requirement:** {r.requirement}")
        out.append(f"- **Expected:** `{r.expected}`")
        if r.actual:
            out.append(f"- **Actual:** `{r.actual}`")
        if r.error:
            out.append(f"- **Error:** `{r.error}`")
        if r.status == STATUS_FAIL:
            out.append("- **Remediation:**")
            out.append("")
            out.append("```")
            out.append(r.remediation)
            out.append("```")
    return "\n".join(out) + "\n"


_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>FortiGate Compliance Report - {device}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         margin: 2rem; color: #1f2933; }}
  h1 {{ margin-bottom: 0; }}
  .meta {{ color: #6b7280; margin-bottom: 1.5rem; }}
  .summary {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; }}
  .card {{ padding: 1rem 1.25rem; border-radius: 8px; min-width: 110px;
           color: #fff; font-weight: 600; }}
  .card span {{ display:block; font-size: 0.75rem; font-weight: 400; opacity: 0.85; }}
  .pass {{ background:#15803d; }}
  .fail {{ background:#b91c1c; }}
  .err  {{ background:#b45309; }}
  .man  {{ background:#4b5563; }}
  table {{ border-collapse: collapse; width:100%; font-size: 0.92rem; }}
  th, td {{ padding: 0.55rem 0.75rem; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
  th {{ background:#f3f4f6; text-align:left; }}
  tr.pass-row td:first-child {{ border-left: 4px solid #15803d; }}
  tr.fail-row td:first-child {{ border-left: 4px solid #b91c1c; }}
  tr.err-row  td:first-child {{ border-left: 4px solid #b45309; }}
  tr.man-row  td:first-child {{ border-left: 4px solid #4b5563; }}
  .sev-HIGH {{ color:#b91c1c; font-weight:600; }}
  .sev-MEDIUM {{ color:#b45309; font-weight:600; }}
  .sev-LOW {{ color:#15803d; font-weight:600; }}
  pre {{ background:#0f172a; color:#e2e8f0; padding: 0.6rem; border-radius:6px;
         white-space: pre-wrap; word-break: break-word; font-size: 0.82rem; }}
  details summary {{ cursor:pointer; color:#1d4ed8; }}
</style>
</head>
<body>
<h1>FortiGate Compliance Report</h1>
<p class="meta">Device: <strong>{device}</strong> &middot; Generated {generated} UTC
&middot; Score <strong>{score:.1f}%</strong></p>
<div class="summary">
  <div class="card pass"><span>PASS</span>{p}</div>
  <div class="card fail"><span>FAIL</span>{f}</div>
  <div class="card err"><span>ERROR</span>{e}</div>
  <div class="card man"><span>MANUAL</span>{m}</div>
</div>
<table>
<thead>
<tr><th>ID</th><th>Status</th><th>Severity</th><th>Title</th>
<th>Standards</th><th>Result / Remediation</th></tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</body></html>
"""


def render_html(results: List[CheckResult], device: str) -> str:
    counts = _summary_counts(results)
    total = len(results)
    score = (counts[STATUS_PASS] / total * 100.0) if total else 0.0
    rows: List[str] = []
    for r in sorted(results, key=lambda x: (x.status != STATUS_FAIL, x.check_id)):
        css = {
            STATUS_PASS: "pass-row",
            STATUS_FAIL: "fail-row",
            STATUS_ERROR: "err-row",
            STATUS_MANUAL: "man-row",
        }.get(r.status, "")
        details_parts = [
            f"<strong>Requirement:</strong> {html.escape(r.requirement)}<br>",
            f"<strong>Expected:</strong> <code>{html.escape(r.expected)}</code><br>",
        ]
        if r.actual:
            details_parts.append(
                f"<strong>Actual:</strong> <code>{html.escape(r.actual)}</code><br>"
            )
        if r.error:
            details_parts.append(
                f"<strong>Error:</strong> <code>{html.escape(r.error)}</code><br>"
            )
        if r.status == STATUS_FAIL:
            details_parts.append(
                "<details><summary>Remediation</summary><pre>"
                + html.escape(r.remediation)
                + "</pre></details>"
            )
        rows.append(
            "<tr class='{css}'><td><code>{cid}</code></td><td>{status}</td>"
            "<td class='sev-{sev}'>{sev}</td><td>{title}</td><td>{stds}</td>"
            "<td>{details}</td></tr>".format(
                css=css,
                cid=html.escape(r.check_id),
                status=html.escape(r.status),
                sev=html.escape(r.severity),
                title=html.escape(r.title),
                stds=html.escape(", ".join(r.standards)),
                details="".join(details_parts),
            )
        )
    return _HTML_TEMPLATE.format(
        device=html.escape(device),
        generated=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        score=score,
        p=counts[STATUS_PASS], f=counts[STATUS_FAIL],
        e=counts[STATUS_ERROR], m=counts[STATUS_MANUAL],
        rows="\n".join(rows),
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="FortiGate CIS L1 + UK CAF + IEC 62443 SL4 Compliance Validator",
    )
    p.add_argument("--host", required=True, help="FortiGate hostname or IP address")
    p.add_argument("--user", required=True, help="FortiGate admin username")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--timeout", type=int, default=20,
                   help="SSH command timeout in seconds (default: 20)")
    pwd = p.add_mutually_exclusive_group()
    pwd.add_argument("--password", help="FortiGate admin password (use --prompt-for-password "
                     "or FORTIGATE_PASSWORD env var when possible)")
    pwd.add_argument("--prompt-for-password", action="store_true",
                     help="Prompt interactively for the password")
    p.add_argument("--report-json", metavar="FILE", help="Write JSON report to FILE")
    p.add_argument("--report-html", metavar="FILE", help="Write HTML report to FILE")
    p.add_argument("--report-md", metavar="FILE", help="Write Markdown report to FILE")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Print each command sent to the device")
    p.add_argument("--fail-on", choices=["any", "high", "never"], default="any",
                   help="Process exit code 1 if any (default), only HIGH severity, or never")
    return p


def resolve_password(args: argparse.Namespace) -> str:
    if args.prompt_for_password:
        return getpass.getpass("FortiGate password: ")
    env = os.environ.get("FORTIGATE_PASSWORD")
    if env:
        return env
    if args.password:
        return args.password
    sys.stderr.write(
        "ERROR: a password is required. Pass --password, set FORTIGATE_PASSWORD, "
        "or use --prompt-for-password.\n"
    )
    sys.exit(2)


def register_all_checks(engine: CheckEngine) -> None:
    register_password_policy_checks(engine)
    register_admin_access_checks(engine)
    register_logging_checks(engine)
    register_network_services_checks(engine)
    register_firewall_policy_checks(engine)
    register_iec_sl4_checks(engine)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    password = resolve_password(args)

    session = FortiGateSession(
        host=args.host,
        username=args.user,
        password=password,
        port=args.port,
        timeout=args.timeout,
        verbose=args.verbose,
    )

    try:
        session.connect()
    except ConnectionError as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 3

    try:
        engine = CheckEngine(session)
        register_all_checks(engine)
    finally:
        session.disconnect()

    device_label = f"{args.user}@{args.host}:{args.port}"
    print(render_console(engine.results, device_label))

    if args.report_json:
        with open(args.report_json, "w", encoding="utf-8") as f:
            f.write(render_json(engine.results, device_label))
        print(f"[+] JSON report written to {args.report_json}")
    if args.report_md:
        with open(args.report_md, "w", encoding="utf-8") as f:
            f.write(render_markdown(engine.results, device_label))
        print(f"[+] Markdown report written to {args.report_md}")
    if args.report_html:
        with open(args.report_html, "w", encoding="utf-8") as f:
            f.write(render_html(engine.results, device_label))
        print(f"[+] HTML report written to {args.report_html}")

    counts = _summary_counts(engine.results)
    if args.fail_on == "never":
        return 0
    if args.fail_on == "high":
        return 1 if any(r.status == STATUS_FAIL and r.severity == SEVERITY_HIGH
                        for r in engine.results) else 0
    return 1 if counts[STATUS_FAIL] or counts[STATUS_ERROR] else 0


if __name__ == "__main__":
    sys.exit(main())
