# Suricata Implementation as IDS/IPS in the Laboratory Environment

## 1. Context

Suricata is a high-performance network intrusion detection engine (IDS) with additional capabilities to operate as IPS and NSM (Network Security Monitoring).

Its implementation in the laboratory aimed to:

- Monitor network traffic at the host level.
- Detect attack patterns using signature-based rules.
- Integrate network-level events into the Wazuh SIEM.
- Expand visibility beyond operating system logs.

2. Suricata Installation

Suricata was installed on a Debian/Ubuntu-based system using the official repositories:

```bash
sudo apt update
sudo apt install suricata -y
```

This method ensures:

- Compatibility with the operating system
- Automatic dependency handling
- Future updates via the APT package manager

After installation, the service was automatically registered within systemd.

## 3. Detection Engine Configuration
### 3.1 Network Interface Identification

Network interfaces were identified using:

```bash
ip a
```

The monitored interfaces were:

- enp0s3
- enp0s8

These were selected based on the laboratory’s network architecture (NAT interface and internal network interface).

### 3.2 Suricata Main Configuration

The primary configuration file:

```bash
/etc/suricata/suricata.yaml
```

Was adjusted to:

- Specify the correct network interfaces
- Ensure proper traffic capture

### 3.3 Signature Update

Detection rules were updated using:

```bash
sudo suricata-update
```

This step is essential to:

- Maintain protection against newly discovered threats
- Incorporate updated community rulesets
- Increase detection coverage

3.4 Service Restart and Validation

After applying configuration changes and updating signatures:

```bash
sudo systemctl restart suricata
```

Service status was verified with:

```bash
sudo systemctl status suricata
```
## 4. Integration

To centralize security events, Suricata logs were integrated into rsyslog. See the process here.

## 5. Operational Validation (Proof of Concept)

A practical test was performed to validate both Suricata detection and Wazuh integration.

### 5.1 Alert Generation

The following command was executed:

```bash
curl http://testmynids.com
```

This domain intentionally triggers IDS signatures.

### 5.2 Local Verification in Suricata

Real-time log monitoring:

```bash
sudo tail -f /var/log/suricata/fast.log
```

Expected outcome: 

- Alert entry with rule ID
- Severity classification
- Network flow details (source and destination IPs)

### 5.3 Verification in Wazuh

Within the Wazuh Dashboard:

- Security Events → filter by “Suricata”

Expected results:

- Alerts typically within rule ID range 80000+
- Severity classification
- Source and destination IP addresses involved in the event

## 6. Architectural Justification

The implementation of Suricata introduces a dedicated network monitoring layer to complement the existing host-based monitoring provided by Wazuh.

This architecture enables:

- Visibility into malicious network traffic
- Signature-based attack detection
- Correlation between system-level and network-level events
- A more realistic simulation of corporate security environments

The laboratory now operates under a defense-in-depth model, combining:

- Host monitoring (Wazuh Agent/Manager)
- Network monitoring (Suricata IDS)
- Centralized log analysis (Wazuh Dashboard)

This multi-layered approach strengthens the overall security posture of the infrastructure and improves detection capability across different attack vectors.
