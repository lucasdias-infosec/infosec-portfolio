# Detecção de Artefatos Maliciosos com YARA e Integração ao Wazuh

## 1. Objetivo

Implementar um mecanismo de detecção de arquivos maliciosos utilizando YARA, com execução automatizada e integração ao Wazuh para geração de alertas centralizados.

O objetivo desta etapa foi:

- Introduzir detecção baseada em assinaturas de arquivos.
- Automatizar varreduras periódicas no sistema.
- Integrar resultados ao pipeline de logs existente.
- Validar a criação de regras customizadas.

A regra implementada teve caráter de prova de conceito (PoC), servindo como base para futuras expansões.

## 2. Instalação do YARA

A instalação foi realizada via repositório oficial:

```bash
sudo apt update
sudo apt install yara libyara-dev -y
```

Essa abordagem garante compatibilidade com o sistema e facilidade de atualização.

## 3. Criação de Regras YARA (PoC)

Foi criada uma regra para identificação de padrões comuns em webshells simples.

Arquivo:

```bash
/etc/yara/rules/teste_webshell.yar
```

Conteúdo:

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

### 3.1. Justificativa

Os padrões utilizados são frequentemente associados a:

- Execução remota de código
- Obfuscação de payloads
- Webshells simples em PHP

A regra tem caráter introdutório e será expandida com maior sofisticação em etapas futuras.

## 4. Automação do Processo de Varredura
### 4.1. Script de Execução

Arquivo:

```bash
/usr/local/bin/yara-scan.sh
```

Conteúdo:

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

#### 4.1.1. Funções do Script

- Compilar regras (yarac) para melhor desempenho
- Executar varredura recursiva (-r)
- Registrar detecções em log estruturado
- Padronizar saída para integração com SIEM

### 4.2. Serviço Systemd

Arquivo:

```bash
/etc/systemd/system/yara-scan.service
```

Conteúdo:

```bash
[Unit]
Description=YARA Automation Scan Service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/yara-scan.sh
```

### 4.3. Agendamento com Timer

Arquivo:

```bash
/etc/systemd/system/yara-scan.timer
```

Conteúdo:

```bash
[Unit]
Description=Run YARA scan periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

#### 4.3.1. Justificativa

O uso de systemd timer permite:

- Execução periódica automatizada
- Integração nativa com o sistema
- Maior controle do ciclo de execução

## 5. Integração com o Wazuh
### 5.1. Coleta de Logs

Arquivo de log monitorado:

```bash
/var/log/yara_detections.log
```

Configuração no Wazuh:

```bash
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/yara_detections.log</location>
</localfile>
```

### 5.2. Decoder Customizado

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

### 5.3. Regra de Detecção

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

## 6. Validação da Implementação

A validação pode ser realizada por meio da criação de um arquivo de teste contendo os padrões definidos na regra.

Exemplo:

```bash
echo "eval(base64_decode('test'));" > /tmp/teste.php
```

Resultados esperados:

- YARA detecta o padrão
- Registro no arquivo de log
- Wazuh decodifica o evento
- Alerta visível no Dashboard
