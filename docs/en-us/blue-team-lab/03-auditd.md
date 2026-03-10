# Implementation Auditd

## 1. Objective

To establish a kernel-level auditing layer using Auditd on a Linux server, integrated with Wazuh for centralized monitoring and alert generation. The primary goal of this phase was not to monitor a single command, but to:

- Activate the Linux kernel auditing subsystem.
- Define a structured rule creation model.
- Integrate audit events into the SIEM.
- Validate the full detection pipeline from event generation to dashboard alert.

For validation purposes, a monitoring rule targeting the base64 binary was implemented as a Proof of Concept (PoC).
Future audit policies and additional monitored binaries will be implemented and documented in dedicated modules.

## 2. Installation and Activation of Auditd

Auditd was installed using the package manager:

```bash
sudo apt update && sudo apt install auditd -y
```

Auditd operates as the user-space interface to the Linux kernel auditing subsystem, allowing detailed monitoring of:

- Binary execution
- File modifications
- Permission changes
- System calls
- Security-relevant system activity

Enabling Auditd establishes a behavioral monitoring foundation at the operating system level.

## 3. Initial Audit Rule Structure (Proof of Concept)

To validate the monitoring workflow, a rule was created to track execution of the binary:

```bash
/usr/bin/base64
```

Command used:

``` bash
sudo auditctl -w /usr/bin/base64 -p x -k monitor_base64
```

Parameters explained:

* -w → defines the path to monitor
* -p x → monitors execution permission
* -k monitor_base64 → assigns a key for event identification and filtering

The base64 utility was selected due to its common use in:

- Data obfuscation
- Encoding payloads
- Post-exploitation techniques
- Potential data exfiltration workflows

Its use in this phase was strictly for validation purposes.

## 4. Rule Persistence

To ensure persistence across system reboots, the rule was added to:

``` bash
/etc/audit/rules.d/audit.rules
```

This step ensures that the auditing configuration becomes part of the system's baseline security configuration.

## 5. Integration

To centralize security events, Auditd logs were integrated into rsyslog. See the process here.
Auditd-generated events were collected by the Wazuh Agent and forwarded to the Wazuh Manager.

Initially, the events arrived with:

- Rule ID: 80700
- Level: 0
- This indicated that events were stored but did not generate visible alerts.

## 6. Custom Rule Creation on the Wazuh Manager

To elevate the event’s severity and make it operationally relevant, a custom rule override was created in:

```bash
/var/ossec/etc/rules/local_rules.xml
```

Applied logic:

- If rule.id equals 80700
- And audit.key equals monitor_base64
- Elevate the severity level to 10

After implementation, execution of the monitored binary triggered a visible alert in the Wazuh Dashboard.

## 7. Operational Validation
### 7.1. Manual Trigger

Execution of the monitored binary:

```bash
echo "test" | base64
```

### 7.2. Log Testing with Wazuh

Using:

```bash
/var/ossec/bin/wazuh-logtest
```

The test confirmed:

- Proper decoding of audit.exe
- Correct identification of audit.key
- Matching against the custom rule

### 7.3. Dashboard Verification

The alert appeared in the Wazuh Dashboard including:

- Executable path
- Executing user
- Timestamp
- Rule ID
- Elevated severity level

This confirmed end-to-end functionality of the detection pipeline.

## 8. Future Expansion

The base64 monitoring rule served as a structural validation of the auditing architecture.
The established framework now allows expansion to include:
Monitoring additional high-risk binaries (e.g., curl, wget, nc, bash)
Tracking modifications to critical files
Auditing privilege escalation attempts
Mapping detection logic to frameworks such as MITRE ATT&CK
These expansions will be documented in dedicated modules to maintain clarity and architectural organization.

## 9. Architectural Justification

Enabling Auditd introduces kernel-level behavioral monitoring, complementing existing security layers within the laboratory:

- Network monitoring (Suricata)
- Host-based monitoring (Wazuh Agent)
- Centralized correlation and alerting (Wazuh Manager)

This implementation strengthens the defense-in-depth model and transitions the laboratory from tool installation to structured detection engineering.
