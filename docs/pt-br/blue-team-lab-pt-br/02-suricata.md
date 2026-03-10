# Implementação do Suricata como IDS/IPS no Laboratório

## 1. Contextualização

O Suricata é um mecanismo de monitoramento e detecção de intrusão de rede (IDS), com capacidade adicional de operar como IPS e ferramenta de Network Security Monitoring (NSM).

Sua implementação no laboratório teve como objetivo:

- Monitorar o tráfego de rede da máquina virtual.
- Detectar padrões de ataque baseados em assinaturas.
- Integrar eventos de rede ao SIEM (Wazuh).
- Expandir a visibilidade além de logs locais do sistema operacional.

## 2. Instalação do Suricata

A instalação foi realizada em sistema baseado em Debian/Ubuntu por meio dos repositórios oficiais:

```bash
sudo apt update
sudo apt install suricata -y
```

Essa abordagem garante:

- Atualizações automatizadas via APT.
- Compatibilidade com o sistema.
- Instalação de dependências necessárias.

Após a instalação, o serviço foi automaticamente registrado no systemd.

## 3. Configuração do Motor de Detecção
### 3.1. Identificação das Interfaces de Rede

A identificação das interfaces foi realizada com:

```bash
ip a
```

As interfaces monitoradas foram:

- enp0s3
- enp0s8

A escolha se deu com base na arquitetura de rede do laboratório (interface NAT e interface interna).

### 3.2. Configuração do suricata.yaml

O arquivo principal de configuração:

```bash
/etc/suricata/suricata.yaml
```

Foi ajustado para:

- Definir as interfaces corretas.
- Garantir captura adequada de tráfego.

### 3.3. Atualização das Assinaturas

As regras de detecção foram atualizadas utilizando:

```bash
sudo suricata-update
```

Essa etapa é fundamental para:

- Manter o mecanismo atualizado contra ameaças conhecidas.
- Incorporar novas assinaturas da comunidade.
- Aumentar a cobertura de detecção.

### 3.4. Reinicialização do Serviço

Após alterações e atualização das regras:

```bash
sudo systemctl restart suricata
```

O status foi validado com:

```bash
sudo systemctl status suricata
```

## 4. Integração

Para centralizar os eventos de segurança, os registros do Suricata foram integrados ao rsyslog. Veja o processo [aqui](rsyslog.md).

## 5. Validação Operacional (PoC)

Para validar o funcionamento do Suricata e sua integração com o Wazuh, foi realizado um teste prático.

### 5.1. Geração de Alerta

Foi executado:

```basg
curl http://testmynids.com
```

Esse domínio contém padrões intencionais para disparar regras IDS.

### 5.2. Verificação Local no Suricata

Monitoramento do log rápido:

```bash
sudo tail -f /var/log/suricata/fast.log
```

Resultado esperado:

- Registro de alerta com ID de regra.
- Classificação de severidade.
- Detalhes do fluxo de rede.

### 5.3. Verificação no Wazuh

No Dashboard do Wazuh:

- Security Events → filtro por “Suricata”

Eventos esperados:

- Alertas com Rule ID geralmente na faixa 80000+.
- Classificação de severidade.
- IP de origem e destino envolvidos.

## 6. Justificativa Arquitetural

A implementação do Suricata adiciona ao laboratório uma camada de monitoramento de rede complementar ao monitoramento de host já realizado pelo Wazuh.

Essa arquitetura permite:

- Visibilidade de tráfego malicioso.
- Detecção baseada em assinatura.
- Correlação entre eventos de sistema e eventos de rede.
- Simulação mais realista de um ambiente corporativo com múltiplas camadas de defesa.

O laboratório passa, portanto, a operar sob um modelo de defesa em profundidade (Defense in Depth), combinando:

- Monitoramento de host (Wazuh Agent/Manager)
- Monitoramento de rede (Suricata IDS)
- Análise centralizada de eventos (Wazuh Dashboard)

Essa abordagem multicamadas fortalece a postura geral de segurança da infraestrutura e melhora a capacidade de detecção em diferentes vetores de ataque.
