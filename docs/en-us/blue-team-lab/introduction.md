# 🛡️ Blue Team Security Lab
Hands-on Information Security laboratory focused on detection, monitoring, and incident analysis, using open-source tools in a virtualized environment.

---

## 🎯 Objective
Build a controlled environment for studying:

- Security monitoring,
- Log analysis,
- Intrusion detection,
- Vulnerability testing,
- Linux system hardening.

The lab simulates a basic corporate scenario with defensive tools (Blue Team) and vulnerable applications for testing purposes.

---

## 🏗 General Architecture
- **Base System:** Ubuntu Server.
- **Firmware:** UEFI.
- **Disk Encryption:** LUKS.
- **Volume Management:** LVM.
- **Virtualization:** (VirtualBox / VMware).
- **Network:** Host-Only (isolated environment).

The detailed base infrastructure setup is documented in:

📂 [00-base-infra](00-base-infra.md)

---

## 🧱 Repository Structure

lab-blue-team/

 - 00-base-infra/
 - 01-wazuh/
 - 02-suricata/
 - 03-dvwa/
 - 04-juice-shop/

README.md

Each directory contains:

- Installation documentation,
- Applied configurations,
- Security adjustments,
- Commands used,
- Technical notes.

---

## 🔧 Implemented Tools (under construction)

---

[Versão pt-BR](../../pt-br/blue-team-lab-pt-br/introducao.md)
