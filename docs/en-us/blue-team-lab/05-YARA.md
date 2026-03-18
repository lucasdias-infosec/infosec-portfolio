# Implementation Report: File-Based Threat Detection with YARA and Wazuh Integration

## 1. Objective

Implement a file-based threat detection mechanism using YARA, with automated execution and integration into Wazuh for centralized alerting.

The objectives of this implementation were:

- Introduce signature-based file detection
- Automate periodic system scans
- Integrate detection results into the existing logging pipeline
- Validate the creation and effectiveness of custom detection rules

The implemented rule serves as a Proof of Concept (PoC), establishing a foundation for future expansion.

## 2. YARA Installation

The installation was performed using the system’s package manager:

```bash
sudo apt update
sudo apt install yara libyara-dev -y
```

This approach ensures compatibility with the operating system and simplifies maintenance and updates.

## 3. YARA Rule Creation (PoC)

A rule was created to detect patterns commonly associated with simple webshells.

File:

```bash
/etc/yara/rules/teste_webshell.yar
```

Content:

```bash
rule Identifica_Webshell_Simples {
    meta:
        description = "Detect common PHP webshell strings"
        author = "Lab"
    strings:
        $a = "eval(base64_decode"
        $b = "shell_exec"
    condition:
        $a or $b
}
```

### 3.1. Rationale

The selected patterns are frequently linked to:

- Remote code execution
- Payload obfuscation
- Simple PHP-based webshells

This rule is intentionally simple and serves as an initial validation step. More advanced and context-aware rules will be implemented in future iterations.

## 4. Scan Automation
### 4.1. Execution Script

File:

```bash
/usr/local/bin/yara-scan.sh
```

Content:

```bash
#!/bin/bash

RULES_DIR="/etc/yara/rules"
SCAN_DIR="/tmp"
COMPILED_RULES="/tmp/top_rules.yarc"

rm -f $COMPILED_RULES

yarac $RULES_DIR/*.yar $COMPILED_RULES

yara -C $COMPILED_RULES -r $SCAN_DIR | while read -r line; do
    echo "$(date) YARA_ENGINE: DETECTION: $line" >> /var/log/yara_detections.log
done
```

#### 4.1.1. Script Responsibilities

- Compile rules (yarac) for improved performance
- Execute recursive scans (-r)
- Log detections in a structured format
- Standardize output for SIEM integration

### 4.2. Systemd Service

File:

```bash
/etc/systemd/system/yara-scan.service
```

Content:

```bash
[Unit]
Description=YARA Automation Scan Service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/yara-scan.sh
```

### 4.3 Scheduled Execution (Timer)

File:

```bash
/etc/systemd/system/yara-scan.timer
```

Content:

```bash
[Unit]
Description=Run YARA scan periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
Rationale
```
#### 4.3.1. Rationale

Using a systemd timer provides:

- Native scheduling within the operating system
- Controlled and predictable execution cycles
- Reduced dependency on external scheduling tools (e.g., cron)

## 5. Wazuh Integration
### 5.1. Log Collection

Log file monitored:

```bash
/var/log/yara_detections.log
```

Wazuh configuration:

```bash
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/yara_detections.log</location>
</localfile>
```

### 5.2. Custom Decoder

```bash
<decoder name="yara_engine">
  <prematch>YARA_ENGINE: DETECTION:</prematch>
</decoder>

<decoder name="yara_engine_fields">
  <parent>yara_engine</parent>
  <regex offset="after_parent">^ (\S+) (\S+)</regex>
  <order>yara_rule, yara_file</order>
</decoder>
```

### 5.3 Detection Rule

```bash
<group name="yara_automation,">

  <rule id="100010" level="8">
    <decoded_as>yara_engine</decoded_as>
    <description>
      YARA: Malware detected! Rule: $(yara_rule) in the file $(yara_file)
    </description>
  </rule>

</group>
```

## 6. Validation

Validation can be performed by creating a test file containing patterns defined in the YARA rule.

Example:

```bash
echo "eval(base64_decode('test'));" > /tmp/teste.php
```

Expected results:

- YARA detects the pattern
- Detection is logged in the local file
- Wazuh decodes the event
- Alert is displayed in the Wazuh Dashboard

[Versão pt-BR](../../pt-br/blue-team-lab-pt-br/05-YARA.md)
