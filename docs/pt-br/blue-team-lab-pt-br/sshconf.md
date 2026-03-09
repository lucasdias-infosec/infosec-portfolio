# Configuração de Acesso SSH com Autenticação por Chave Pública

## 1. Contextualização

Durante a instalação do Ubuntu Server, o serviço OpenSSH foi habilitado automaticamente. Entretanto, o ambiente encontrava-se configurado apenas para autenticação baseada em senha, sem chaves públicas previamente associadas ao usuário administrativo.

Considerando que o laboratório tem como objetivo reproduzir práticas compatíveis com ambientes corporativos reais, foi adotado o modelo de autenticação baseado em criptografia assimétrica. Essa abordagem reduz significativamente a superfície de ataque associada a tentativas de força bruta e credenciais fracas.

## 2. Verificação e Garantia de Persistência do Serviço SSH

Inicialmente, foi verificado o estado do serviço SSH:

```bash
sudo systemctl status ssh
```

Para assegurar que o serviço estivesse ativo e configurado para inicialização automática no boot, foram executados:

```bash
sudo systemctl enable ssh
sudo systemctl start ssh
```

Resultado Observado:

- Serviço em estado ativo (running).
- Serviço habilitado para inicialização automática.
- Persistência confirmada após reinicialização da máquina virtual.

Essa etapa garantiu a disponibilidade contínua do acesso remoto, requisito fundamental para administração segura do ambiente.

## 3. Identificação da Interface de Rede

A identificação do endereço IP da máquina virtual foi realizada por meio do comando:

```bash
ip a
```

Essa etapa foi necessária para viabilizar a comunicação remota entre o host e a máquina virtual via SSH.

Os endereços reais foram omitidos da documentação por boas práticas de segurança relacionadas à exposição pública de infraestrutura.

## 4. Implementação de Autenticação por Chave Pública

Foi adotado o algoritmo ED25519, escolhido por:

- Segurança criptográfica moderna
- Melhor desempenho computacional em comparação com RSA tradicional
- Forte recomendação em ambientes Linux atuais

A autenticação por chave pública substitui o modelo baseado exclusivamente em senha, reduzindo riscos associados a ataques automatizados.

### 4.1. Geração do Par de Chaves

No host administrativo, foi executado:

```bash
ssh-keygen -t ed25519 -C "lab-ssh-access"
```

Foram gerados:

- Chave privada: ~/.ssh/id_ed25519
- Chave pública: ~/.ssh/id_ed25519.pub

A chave privada permaneceu exclusivamente armazenada no host, não sendo transferida para a VM em nenhum momento.

### 4.2. Exportação da Chave Pública

A transferência da chave pública foi realizada por meio de:

```bash
ssh-copy-id <usuario>@<ip_da_vm>
```

Alternativamente, o procedimento pode ser realizado manualmente:

```bash
cat ~/.ssh/id_ed25519.pub | ssh <usuario>@<ip_da_vm> "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys"
chmod 600 ~/.ssh/authorized_keys
```

Esse processo adicionou a chave ao arquivo:

```bash
~/.ssh/authorized_keys
```

As permissões foram configuradas para garantir conformidade com os requisitos de segurança do OpenSSH.

## 5. Estabelecimento de Confiança (Host Verification)

No primeiro acesso após a configuração, foi executado:

```bash
ssh <usuario>@<ip_da_vm>
```

A fingerprint do servidor foi validada e registrada automaticamente no arquivo:

```bash
~/.ssh/known_hosts
```

Esse mecanismo protege contra ataques de interceptação (Man-in-the-Middle), assegurando que futuras conexões ocorram apenas com o servidor previamente confiável.

## 6. Estado Atual do Acesso Remoto

Após a implementação:

- O serviço SSH encontra-se ativo e persistente.
- A autenticação ocorre por meio de chave privada.
- O uso de senha para o usuário configurado tornou-se desnecessário.

O acesso remoto é realizado via:

```bash
ssh <usuario>@<ip_da_vm>
```

## 7. Justificativa Arquitetural

A adoção da autenticação por chave pública estabelece uma base segura para administração remota do laboratório, alinhando o ambiente às seguintes práticas:

- Redução da exposição a ataques de força bruta.
- Eliminação da dependência exclusiva de credenciais memorizadas.
- Maior controle sobre identidades autorizadas.
- Preparação do ambiente para futuras políticas de hardening (ex: desabilitar autenticação por senha).

Essa configuração fortalece a camada de acesso remoto da infraestrutura e consolida a postura de segurança do laboratório desde sua fase inicial.
