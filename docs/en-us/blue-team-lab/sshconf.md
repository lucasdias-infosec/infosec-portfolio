# SSH Access Configuration with Public Key Authentication

## 1. Context

During the Ubuntu Server installation, the OpenSSH service was enabled automatically. However, the environment was configured to rely exclusively on password-based authentication, with no public keys previously associated with the administrative user.
Since the laboratory aims to simulate security practices aligned with real-world corporate environments, an asymmetric cryptography-based authentication model was implemented. This approach significantly reduces the attack surface related to brute-force attempts and weak credential exposure.

## 2. SSH Service Verification and Persistence

The status of the SSH service was initially verified using:

```bash
sudo systemctl status ssh
```

To ensure the service was active and configured to start automatically at boot, the following commands were executed:

```bash
sudo systemctl enable ssh
sudo systemctl start ssh
```

Observed Results:

- Service status: active (running)
- Service enabled for automatic startup

Persistence confirmed after system reboot
This step ensured continuous availability of remote access, a fundamental requirement for secure administrative operations.

## 3. Network Interface Identification

The virtual machine's IP address was identified using:

```bash
ip a
```

Actual IP addresses were intentionally omitted from this documentation to follow security best practices regarding public exposure of infrastructure details.

This step enabled remote communication between the host system and the virtual machine via SSH.

## 4. Public Key Authentication Implementation

The ED25519 algorithm was selected due to:

- Modern cryptographic security standards
- Efficient computational performance
- Strong adoption across current Linux environments

Public key authentication replaces exclusive password-based access, mitigating risks associated with automated attacks.

### 4.1. Key Pair Generation

On the administrative host machine, the following command was executed:

```bash
ssh-keygen -t ed25519 -C "lab-ssh-access"
```

This process generated:

- Private key: ~/.ssh/id_ed25519
- Public key: ~/.ssh/id_ed25519.pub

The private key remained exclusively stored on the host machine and was never transferred to the server.

### 4.2 Public Key Deployment

The public key was transferred to the server using:

``` bash
ssh-copy-id <user>@<vm_ip>
```
Alternatively, the procedure can be performed manually:

```bash
cat ~/.ssh/id_ed25519.pub | ssh <user>@<vm_ip> "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys"
chmod 600 ~/.ssh/authorized_keys
```

This operation appended the public key to:

```bash
~/.ssh/authorized_keys
```

## 5. Host Verification and Trust Establishment

On the first connection after configuration, the following command was executed:

```bash
ssh <user>@<vm_ip>
```

The server fingerprint was validated and automatically stored in:

```bash
~/.ssh/known_hosts
```

This mechanism protects against Man-in-the-Middle (MITM) attacks by ensuring that future connections are established only with the previously trusted server.

## 6. Current Remote Access State

After implementation:

- The SSH service is active and persistent.
- Authentication is performed using the private key.
- Password entry is no longer required for the configured user.

Remote access is performed via:

```bash
ssh <user>@<vm_ip>
```

## 7. Architectural Justification

The adoption of public key authentication establishes a secure foundation for remote administration of the laboratory environment, aligning it with corporate security practices by:

- Reducing exposure to brute-force attacks.
- Eliminating reliance on memorized credentials.
- Enabling stronger identity control mechanisms.
- Preparing the infrastructure for future hardening measures (e.g., disabling password authentication entirely).

This configuration strengthens the remote access layer of the infrastructure and reinforces the security posture of the laboratory from its foundational stage.
