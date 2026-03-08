# Relatório de Implementação Auditd

## 1. Objetivo

Implementar uma camada de auditoria no nível do kernel Linux utilizando o Auditd, com integração ao Wazuh, permitindo o monitoramento estruturado da execução de binários sensíveis.

O foco desta etapa não foi o monitoramento isolado de um único comando, mas sim:

- Ativar o subsistema de auditoria do kernel.
- Estabelecer um modelo de criação de regras.
- Integrar eventos ao SIEM.
- Validar o fluxo completo de detecção.

Para fins de validação técnica, foi utilizada uma regra de monitoramento do utilitário base64 como prova de conceito (PoC).

Novas regras e políticas de auditoria serão implementadas futuramente e documentadas de forma específica.

## 2. Instalação e Ativação do Auditd

O serviço foi instalado por meio do gerenciador de pacotes:

```bash
sudo apt update && sudo apt install auditd -y
```

O Auditd opera como interface de controle do subsistema de auditoria do kernel Linux, permitindo registrar eventos relacionados a:

- Execução de binários
- Alterações de arquivos
- Modificações de permissões
- Chamadas de sistema
- Eventos relacionados a segurança

Sua ativação estabelece a base para monitoramento comportamental no nível do sistema operacional.

## 3. Estruturação da Primeira Regra de Auditoria (PoC)

Para validar o funcionamento do mecanismo, foi criada uma regra de monitoramento da execução do binário:

```bash
/usr/bin/base64
```

Comando utilizado:

```bash
sudo auditctl -w /usr/bin/base64 -p x -k monitor_base64
```

Parâmetros aplicados:

* -w: define o caminho monitorado
* -p x: monitora execução do binário
* -k monitor_base64: adiciona uma chave de identificação ao evento

A escolha do base64 ocorreu por se tratar de um utilitário frequentemente utilizado em:

- Obfuscação de dados
- Exfiltração
- Técnicas pós-exploração

Essa regra teve caráter exclusivamente validatório.

## 4. Persistência das Regras

Para garantir continuidade após reinicializações, a regra foi adicionada ao arquivo:

```bash
/etc/audit/rules.d/audit.rules
```

Essa etapa consolida a auditoria como parte estrutural da configuração do sistema.

## 5. Integração

Para centralizar os eventos de segurança, os registros do Suricata foram integrados ao rsyslog. Veja o processo aqui. Os eventos gerados pelo Auditd passaram a ser coletados pelo Wazuh Agent e encaminhados ao Manager.

Inicialmente, os logs chegaram com:

- Rule ID: 80700
- Level: 0

Ou seja, eram armazenados, mas não geravam alertas.

## 6. Criação de Regra Customizada no Manager

Para transformar o evento em alerta relevante, foi criada uma regra de sobreposição no arquivo:

```bash
/var/ossec/etc/rules/local_rules.xml
```

Lógica aplicada:

Se o evento possuir Rule ID 80700

E audit.key = monitor_base64

Elevar o nível para 10

Após essa modificação, o evento passou a ser classificado como alerta crítico no Dashboard.

## 7. Validação Operacional
### 7.1. Execução do Binário Monitorado

```bash
echo "teste" | base64
```

### 7.2. Teste com wazuh-logtest

Validação da decodificação correta dos campos:

- audit.exe
- audit.key
- associação com a regra customizada

### 7.3. Verificação no Dashboard

O alerta foi visualizado contendo:

- Caminho do executável
- Usuário responsável
- Timestamp
- Rule ID
- Nível elevado de severidade

## 8. Direcionamento Futuro

A implementação do monitoramento do base64 serviu como etapa inicial de validação da arquitetura.

A estrutura estabelecida permite a expansão futura para:

- Monitoramento de múltiplos binários sensíveis (ex: curl, wget, nc, bash)
- Monitoramento de alterações em arquivos críticos
- Auditoria de privilégios elevados
- Mapeamento de regras para frameworks como MITRE ATT&CK

Essas expansões serão documentadas em módulos específicos, mantendo a organização e rastreabilidade do laboratório.

## 9. Justificativa Arquitetural

A ativação do Auditd adiciona ao laboratório uma camada de detecção baseada em comportamento no nível do kernel, complementando:

- Monitoramento de rede (Suricata)
- Monitoramento de host via logs tradicionais
- Correlação centralizada no Wazuh

Essa abordagem reforça o modelo de Defense in Depth e prepara o ambiente para evoluir de um laboratório funcional para uma arquitetura estruturada de engenharia de detecção.
