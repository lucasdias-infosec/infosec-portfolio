# 🛡️ Blue Team Security Lab
Laboratório prático de Segurança da Informação voltado para detecção, monitoramento e análise de incidentes, utilizando ferramentas open-source em ambiente virtualizado.

---

## 🎯 Objetivo
Construir um ambiente controlado para estudo de:
- Monitoramento de segurança
- Análise de logs
- Detecção de intrusão
- Testes de vulnerabilidades
- Hardening de sistemas Linux
O laboratório simula um cenário corporativo básico com ferramentas de defesa (Blue Team) e aplicações vulneráveis para testes.

---

## 🏗 Arquitetura Geral
- **Sistema Base:** Ubuntu Server
- **Firmware:** UEFI
- **Criptografia de Disco:** LUKS
- **Gerenciamento de Volume:** LVM
- **Virtualização:** (VirtualBox / VMware)
- **Rede:** Host-Only (ambiente isolado)

A construção detalhada da base está documentada em:

📂 [00-base-infra](00-base-infra.md)

---

## 🧱 Estrutura do Repositório

lab-blue-team/

 - 00-base-infra/
 - 01-wazuh/
 - 02-suricata/
 - 03-dvwa/
 - 04-juice-shop/

README.md

Cada diretório contém:
- Documentação de instalação
- Configurações aplicadas
- Ajustes de segurança
- Comandos utilizados
- Observações técnicas

---

## 🔧 Ferramentas Implementadas (em construção)

## Guia para Contribuições

📂 [Guia-de-Contribuições](Guia-de-Contribuições.md)

## 👤 Autor

Lucas  
Estudante de Ciência da Computação  
Foco em Segurança da Informação
