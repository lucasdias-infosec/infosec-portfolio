# Implantação do Wazuh Manager – Arquitetura Single-Node

## 1. Contexto

Com a infraestrutura base previamente consolidada e o acesso remoto seguro estabelecido, iniciou-se a implementação da camada de monitoramento e detecção do laboratório.
A ferramenta escolhida foi o Wazuh, plataforma open-source amplamente utilizada para centralização de logs, detecção baseada em regras, monitoramento de integridade de arquivos (FIM) e análise de vulnerabilidades.
A adoção do Wazuh marca a transição do laboratório de um ambiente apenas estruturado para um ambiente capaz de observar, correlacionar e interpretar eventos de segurança.

## 2. Justificativa Arquitetural

A escolha do Wazuh foi motivada por sua arquitetura modular e pela capacidade de integrar, em uma única stack, funcionalidades típicas de um SIEM leve e de um sistema de detecção baseado em host (HIDS).

Optou-se pela instalação em modo single-node (all-in-one), no qual operam na mesma máquina virtual:

- Wazuh Indexer
- Wazuh Server (Manager)
- Wazuh Dashboard

Essa decisão foi fundamentada em três critérios principais:

- Limitação de recursos do ambiente (8 GB de RAM disponíveis no host físico).
- Objetivo inicial de validação funcional da stack.
- Simplificação do ambiente para compreensão do fluxo interno de eventos antes da segmentação em arquitetura distribuída.

Reconhece-se que, em ambiente produtivo, a separação dos componentes em nós distintos seria recomendável para reduzir impacto de comprometimento e melhorar escalabilidade.

## 3. Método de Instalação

A implantação foi realizada por meio do script oficial de automação no modo all-in-one:

```bash
sudo bash wazuh-install.sh -a
```

O parâmetro -a executa a instalação integrada dos seguintes componentes:

- Wazuh Indexer – responsável pela indexação e armazenamento dos eventos.
- Wazuh Server (Manager) – responsável pela aplicação de regras, correlação e geração de alertas.
- Wazuh Dashboard – interface web para visualização e análise.

Essa abordagem garante consistência entre versões e reduz erros de configuração manual.

## 4. Monitoramento Local (Agente Interno)

Como etapa inicial, optou-se por monitorar a própria máquina virtual onde o Manager está instalado.

Essa decisão possui caráter metodológico:

- Permite validar o pipeline completo de coleta → análise → indexação → visualização.
- Elimina variáveis externas de rede.
- Garante ambiente controlado para testes iniciais.

O sistema utiliza o agente interno padrão (ID 000), correspondente ao próprio Manager.

## 5. Validação Operacional (Proof of Concept)

Para confirmar o funcionamento da detecção, foram realizados testes controlados.

### 5.1. Simulação de Tentativas de Autenticação SSH

Foram executadas múltiplas tentativas de login com usuário inexistente:

```bash
ssh usuario_inexistente@<ip_da_vm>
```

Resultado observado:

- Geração de alertas relacionados a falhas de autenticação.
- Elevação progressiva de severidade após repetição das tentativas.
- Aplicação automática de regras associadas a comportamento de brute-force.

Esse teste confirmou:

- Coleta correta dos logs de autenticação.
- Processamento pelo mecanismo de regras.
- Indexação e visualização no dashboard.

## 6. Eventos de Inicialização do Sistema

Após reinicialização da máquina virtual, foram registrados:

- Eventos informativos de sistema.
- Alertas de severidade baixa e média associados a serviços.

Isso confirma que:

- O monitoramento de logs está ativo.
- O mecanismo de análise está funcional.
- A comunicação entre Manager, Indexer e Dashboard está operacional.

## 7. Acesso à Interface

O acesso ao Dashboard é realizado via HTTPS:

```bash
https://<ip_da_vm>
```

Credenciais administrativas foram definidas durante a instalação e não são expostas nesta documentação.

## 8. Estado Atual do Ambiente

Após a implantação:

- A stack encontra-se ativa e operacional.
- O agente interno está funcional.
- A geração e indexação de alertas foi validada.
- O ambiente está apto para expansão com agentes externos.

Para preservação do estado funcional, foi criado um snapshot da máquina virtual no hypervisor, permitindo reversão rápida durante futuras fases de teste e integração.
