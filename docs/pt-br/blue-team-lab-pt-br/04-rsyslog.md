# Relatório de Implementação: Centralização de Logs com Rsyslog, Auditd, Suricata e Wazuh

## 1. Objetivo

Implementar uma arquitetura centralizada de coleta e correlação de eventos de segurança, utilizando o Rsyslog como camada intermediária entre os geradores de log (Auditd e Suricata) e o mecanismo de análise (Wazuh).

O objetivo desta etapa foi:

- Unificar logs de sistema e rede.
- Evitar duplicidade de leitura por múltiplos agentes.
- Separar responsabilidades entre coleta, transporte e análise.
- Preparar o ambiente para futura escalabilidade.

## 2. Visão Geral da Arquitetura

A solução consolidou três camadas de segurança em um único servidor, com funções bem definidas:

- Auditd: monitora eventos no nível do kernel.
- Suricata: realiza inspeção de tráfego de rede (IDS).
- Rsyslog: atua como coletor e encaminhador (forwarder) de logs.
- Wazuh Manager: recebe, decodifica, correlaciona e gera alertas no Dashboard.

Fluxo de dados estabelecido:

Auditd / Suricata → Rsyslog → Wazuh Manager → Dashboard

## 3. Instalação e Garantia do Serviço Rsyslog

Foi garantida a instalação do serviço com:

```bash
sudo apt update
sudo apt install rsyslog -y
```

Validação:

```bash
sudo systemctl status rsyslog
```

O serviço permaneceu ativo e habilitado para inicialização automática.

## 4. Configuração da Ponte de Logs no Rsyslog
### 4.1. Criação do Arquivo de Configuração

Arquivo criado:

```bash
/etc/rsyslog.d/99-monitoring.conf
```

### 4.2. Leitura de Arquivos (imfile)

Arquivos monitorados:

```bash
/var/log/audit/audit.log
/var/log/suricata/eve.json
```

### 4.3. Encaminhamento (omfwd)

Encaminhamento configurado para:

```bash
<IP_DO_MANAGER>:515
```

Diretiva utilizada:

```bash
*.* @<IP_DO_MANAGER>:515
```

Justificativa da Porta:

- Porta 515/UDP destinada ao Wazuh.
- Porta 514/UDP/TCP reservada para recebimento futuro de logs externos.

Essa separação resolveu o conflito de binding anteriormente identificado.

## 5. Configuração do Wazuh como Analisador

No arquivo:

```bash
/var/ossec/etc/ossec.conf
```

Bloco configurado:

```bash
<remote>
  <connection>syslog</connection>
  <port>515</port>
  <protocol>udp</protocol>
  <allowed-ips><REDE_INTERNA_DO_LAB></allowed-ips>
</remote>
```

### 6. Ajuste Arquitetural

Os blocos <localfile> que realizavam leitura direta dos arquivos foram removidos, evitando:

- Duplicidade de logs
- Processamento redundante
- Conflitos internos

A leitura passou a ser responsabilidade exclusiva do Rsyslog.

## 7. Testes de Validação
### 7.1. Teste de Sistema (Auditd)

```bash
echo "teste" | base64 -d
```

Resultado esperado:

- Log gerado pelo Auditd
- Capturado pelo Rsyslog
- Encaminhado ao Manager
- Exibido no Dashboard

### 7.2. Teste de Rede (Suricata)

```bash
curl http://testmyids.com
```

Resultado esperado:

- Detecção de assinatura pelo Suricata
- Registro em eve.json
- Encaminhamento via Rsyslog
- Exibição de alerta contendo IP de origem e destino

## 8. Benefícios Arquiteturais
### 8.1. Separação de Responsabilidades

- Geração de logs → Ferramentas específicas
- Transporte → Rsyslog
- Análise e correlação → Wazuh

### 8.2. Escalabilidade

Novos servidores podem ser integrados apenas instalando Rsyslog e configurando o encaminhamento para:

```bash
<IP_DO_SERVIDOR_CENTRAL>:514
```

Sem necessidade de alterar a arquitetura central.

## 9. Justificativa Arquitetural

A adoção do Rsyslog como camada intermediária promove:

- Modularidade
- Controle granular do fluxo de logs
- Preparação para expansão
- Organização do pipeline de eventos

A infraestrutura então evolui para um modelo estruturado de centralização e correlação de logs, alinhado a práticas de ambientes corporativos.
