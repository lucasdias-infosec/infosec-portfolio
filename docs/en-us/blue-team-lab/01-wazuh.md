# Wazuh Manager Deployment: Single-Node Architecture

## 1. Context

With the base infrastructure previously consolidated and secure remote access established, the implementation of the monitoring and detection layer of the lab was initiated.
The chosen tool was Wazuh, a widely used open-source platform for log centralization, rule-based detection, file integrity monitoring (FIM), and vulnerability analysis.
The adoption of Wazuh marks the transition of the lab from a merely structured environment to one capable of observing, correlating, and interpreting security events.

### 1.1. Architectural Justification

The choice of Wazuh was motivated by its modular architecture and its ability to integrate, within a single stack, functionalities typically associated with a lightweight SIEM and a host-based intrusion detection system (HIDS).
A single-node (all-in-one) installation mode was selected, in which these systems operate on the same virtual machine:

- Wazuh Indexer
- Wazuh Server (Manager)
- Wazuh Dashboard

This decision was based on three main criteria:

- Resource limitations of the environment (8 GB of RAM available on the physical host).
- Initial objective of functional validation of the stack.
- Simplification of the environment to understand the internal event flow before segmentation into a distributed architecture.

It is acknowledged that, in a production environment, separating components into distinct nodes would be recommended to reduce compromise impact and improve scalability.

## 2. Installation Method

Deployment was performed using the official automation script in all-in-one mode:

```bash
sudo bash wazuh-install.sh -a
```
The -a parameter executes the integrated installation of the following components:

- Wazuh Indexer – responsible for indexing and storing events.
- Wazuh Server (Manager) – responsible for rule application, correlation, and alert generation.
- Wazuh Dashboard – web interface for visualization and analysis.

This approach ensures version consistency and reduces manual configuration errors.

## 3. Local Monitoring (Internal Agent)

As an initial step, the decision was made to monitor the same virtual machine where the Manager is installed.

This decision is methodological in nature:

- It allows validation of the complete pipeline: collection → analysis → indexing → visualization.
- It eliminates external network variables.
- It ensures a controlled environment for initial testing.

The system uses the default internal agent (ID 000), corresponding to the Manager itself.

## 4. Operational Validation (Proof of Concept)

To confirm detection functionality, controlled tests were performed.

### 4.1. Simulation of SSH Authentication Attempts

Multiple login attempts were executed using a non-existent user:

```bash
ssh nonexistent_user@<vm_ip>
```
Observed result:

- Generation of alerts related to authentication failures.
- Progressive severity escalation after repeated attempts.
- Automatic application of rules associated with brute-force behavior.

This test confirmed:

- Correct collection of authentication logs.
- Processing by the rule engine.
- Indexing and visualization in the dashboard.

## 6. System Startup Events

After rebooting the virtual machine, the following were recorded:

- Informational system events.
- Low and medium severity alerts associated with services.

This confirms that:

- Log monitoring is active.
- The analysis engine is functional.
- Communication between Manager, Indexer, and Dashboard is operational.

## 7. Interface Access

Dashboard access is performed via HTTPS:

```bash
https://<vm_ip>
```

Administrative credentials were defined during installation and are not exposed in this documentation.

## 8. Current Environment Status

After deployment:

- The stack is active and operational.
- The internal agent is functional.
- Alert generation and indexing have been validated.
- The environment is ready for expansion with external agents.

To preserve the functional state, a virtual machine snapshot was created on the hypervisor, enabling rapid rollback during future testing and integration phases.
