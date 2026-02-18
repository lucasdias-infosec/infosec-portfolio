# Introdução

Esta etapa do laboratório consiste na construção da infraestrutura fundamental que servirá como base para todas as ferramentas de segurança implementadas posteriormente.
Antes da instalação de qualquer solução de monitoramento ou detecção, foi priorizada a criação de um ambiente sólido, seguro e controlado. A abordagem adotada considera princípios de arquitetura defensiva, isolamento de ambiente e boas práticas de hardening desde a camada mais baixa do sistema.
A infraestrutura foi projetada com foco em:

- Organização modular,
- Segurança desde a instalação do sistema,
- Controle sobre armazenamento e volumes,
- Isolamento de rede para testes controlados,
- Preparação para expansão futura do laboratório.

Foram aplicados conceitos como criptografia de disco com LUKS, gerenciamento de volumes com LVM, configuração em modo UEFI e segmentação de rede em ambiente virtualizado.
Esta base estabelece os fundamentos necessários para a implementação das ferramentas de Blue Team, garantindo que o laboratório não seja apenas funcional, mas estruturado com consciência de arquitetura e segurança.

---

## 1. Objetivo do Laboratório

O objetivo deste laboratório é a construção de um ambiente controlado, leve e funcional destinado ao treinamento prático em Segurança da Informação, com foco em atividades de Blue Team.
O ambiente visa possibilitar o monitoramento de eventos, a análise de logs, a detecção de ameaças e a aplicação de técnicas de defesa, considerando um cenário de recursos de hardware limitados.

## 2. Objetivos de Aprendizado e Demonstração

- Este laboratório foi projetado para permitir a aquisição e demonstração das seguintes competências:
- Configuração e operação de ferramentas de monitoramento e detecção, como IDS e SIEM,
- Análise de atividades suspeitas e investigação de incidentes de segurança,
- Identificação de evidências geradas por ataques comuns em ambientes corporativos,
- Aplicação de medidas de hardening e boas práticas de defesa,
- Demonstração do processo de correlação de eventos e tratamento de alertas por um analista de segurança.

### 2.1 Escopo e Limitações

Este laboratório tem como escopo o estudo prático de mecanismos de monitoramento, detecção, análise e resposta a incidentes em um ambiente controlado e reduzido, com foco em atividades de Blue Team.
Não é objetivo deste laboratório:

- Simular ambientes de produção em larga escala,
- Reproduzir operações de SOC distribuído,
- Realizar testes de alta disponibilidade ou desempenho,
- Representar fielmente infraestruturas corporativas complexas.

As limitações de escopo são intencionais e visam manter o ambiente simples, previsível e alinhado aos objetivos educacionais e de estudo técnico.

## 3. Cenário Simulado

O laboratório representa um ambiente corporativo simplificado, composto pelos seguintes elementos:
- Um servidor Linux monitorado por ferramentas de segurança.
- Uma estação do analista, a partir da qual são conduzidos testes controlados, como varredura de portas, ataques de força bruta e exploração de aplicações vulneráveis.

O objetivo do cenário é reproduzir eventos realistas para fins de estudo de detecção, análise e resposta a incidentes, permitindo a correlação de logs e a observação do comportamento de ataques em um ambiente isolado.

### 3.1 Modelo de Ameaça

Os eventos maliciosos simulados no laboratório representam ataques amplamente conhecidos e documentados, com baixo a médio nível de sofisticação, típicos de ambientes corporativos de pequeno porte.
As atividades ofensivas são utilizadas exclusivamente como fonte controlada de eventos, com o objetivo de gerar logs, alertas e evidências para análise defensiva, correlação e resposta a incidentes. Não há foco em exploração avançada, desenvolvimento de exploits ou simulação de ameaças persistentes sofisticadas.

## 4. Hardware Utilizado

O laboratório foi construído sobre o seguinte hardware:

- CPU: AMD Ryzen 7 (série 5000)
- Memória RAM: 8 GB
- Armazenamento: SSD de 256 GB

Essas especificações impõem limitações de recursos, o que influencia diretamente as decisões de arquitetura e exige a adoção de uma solução de virtualização leve e eficiente.

## 5. Software de Virtualização

Para a virtualização do ambiente foram utilizados:

- Oracle VirtualBox
- VirtualBox Extension Pack

## 6. Justificativa para a Escolha do Oracle VirtualBox

A escolha do Oracle VirtualBox como plataforma de virtualização baseou-se nos seguintes critérios:

- Licenciamento e Custo: O VirtualBox é distribuído sob licença open source, permitindo seu uso gratuito em contextos pessoais, acadêmicos e laboratoriais. Essa característica reduz custos e amplia a flexibilidade do ambiente,
- Leveza e Baixa Exigência de Hardware: O VirtualBox apresenta baixo consumo de recursos em comparação com outras soluções de virtualização, possibilitando a execução de múltiplas máquinas virtuais mesmo em hardware com limitações de memória e armazenamento,
- Suporte à Documentação Visual: A ferramenta permite a captura de screenshots diretamente pela interface gráfica, o que facilita:
    - A documentação dos procedimentos,
    - A elaboração de relatórios técnicos,
    - A registro visual de evidências durante os estudos.
- Facilidade de Uso e Comunidade: A interface intuitiva e a ampla disponibilidade de documentação tornam o VirtualBox acessível, ao mesmo tempo em que sua comunidade ativa contribui para a rápida resolução de problemas e dúvidas técnicas,
- Compatibilidade Ampla: O VirtualBox oferece suporte a diversos sistemas operacionais, tanto como host quanto como guest, incluindo Windows, Linux e BSD. Essa compatibilidade é essencial para a simulação de ambientes corporativos heterogêneos.

## 7. Justificativa para o Uso do VirtualBox Extension Pack

O VirtualBox Extension Pack adiciona funcionalidades avançadas que ampliam significativamente o realismo e a utilidade do laboratório.

### 7.1 Suporte a USB 2.0 e USB 3.0

Permite que dispositivos físicos conectados ao host sejam acessados pelas máquinas virtuais, viabilizando:

- Testes com dispositivos externos,
- Análise de mídias removíveis,
- Simulação de ataques via USB,
- Uso de adaptadores Wi-Fi, dongles e leitores externos.

Sem o Extension Pack, esses recursos permanecem limitados.

### 7.2 Suporte a Boot via Rede (PXE)

O suporte a placas Intel PXE possibilita o boot via rede, permitindo a simulação de:

- Implantação de sistemas operacionais via rede,
- Cenários envolvendo DHCP e PXE,
- Ambientes corporativos reais de provisioning.

### 7.3 Suporte a VRDP (VirtualBox Remote Desktop Protocol)

O VRDP permite o acesso remoto às máquinas virtuais sem a necessidade de interação direta com a interface gráfica local, sendo útil para:

- Simulações de acesso remoto,
- Gerenciamento de VMs em modo headless,
- Operação simultânea de múltiplas VMs com menor impacto no host.

### 7.4 Melhor Integração com o Host

O Extension Pack inclui melhorias adicionais de desempenho e compatibilidade, contribuindo para maior estabilidade e fluidez do ambiente virtualizado.

### 7.5 Importância para Documentação e Estudos

As funcionalidades adicionais fornecidas pelo Extension Pack tornam o laboratório mais completo e realista, permitindo:

- Registro de etapas por meio de acesso remoto,
- Testes que dependem de suporte USB,
- Simulação de cenários corporativos que exigem boot via rede.

Dessa forma, a utilização do VirtualBox Extension Pack é justificada pelo ganho funcional significativo para fins de estudo, testes controlados e documentação em Segurança da Informação.

## 8. Criação da Máquina Virtual

Foi criada uma máquina virtual dedicada ao servidor de segurança utilizando o Oracle VirtualBox. A configuração prioriza leveza, controle do ambiente e fidelidade a cenários reais de servidores corporativos utilizados em contextos de Segurança da Informação.

## 9. Sistema Operacional

- Distribuição: Ubuntu Server
- Versão: 24.04.03 LTS
- Arquitetura: amd64 (64 bits)

A escolha do Ubuntu Server 24.04 LTS baseia-se nos seguintes fatores:

- Versão LTS, garantindo estabilidade e suporte prolongado,
- Ausência de interface gráfica por padrão, reduzindo consumo de memória,
- Ampla documentação e compatibilidade com ferramentas de Blue Team,
- Uso recorrente em ambientes corporativos, aumentando o realismo do laboratório.

## 10. Configuração de Hardware da Máquina Virtual

### 10.1 Memória RAM

- RAM alocada: 3 GB

### 10.2 Processador

- vCPUs: 2

## 11. Firmware e Inicialização

### 11.1 Modo de Boot

A máquina virtual foi configurada para inicializar em modo UEFI (Unified Extensible Firmware Interface), em substituição ao BIOS legado.
Justificativa da escolha:

- UEFI é o padrão predominante em servidores e estações corporativas modernas,
- Oferece arquitetura de inicialização mais robusta e estruturada,
- Permite suporte a recursos avançados de segurança e gerenciamento,
- Aproxima o laboratório de cenários reais de infraestrutura contemporânea.

## 12. Configuração de Rede

### 12.1 Adaptador Host-Only (Operação do Laboratório)

O laboratório opera, em sua fase normal de uso, com um adaptador de rede configurado em modo Host-Only.
Esse modo cria uma rede privada entre o host e a máquina virtual, sem acesso direto à internet ou exposição à rede externa, permitindo comunicação controlada e previsível.
A utilização do Host-Only atende aos seguintes objetivos:

- Garantir isolamento de segurança durante a execução de ataques simulados,
- Evitar vazamento de tráfego malicioso para redes reais,
- Simular um cenário corporativo interno, no qual um analista acessa servidores não expostos externamente,
- Fornecer tráfego limpo e controlado para análise por ferramentas como IDS e SIEM.

### 12.2 Modo Promíscuo

- Configuração: Permitir VMs

Essa configuração é necessária para permitir a observação de pacotes de rede por ferramentas de análise de tráfego, como o Suricata, viabilizando estudos de detecção e monitoramento.

### 12.3 Adaptador NAT (Provisionamento)

Durante a fase de provisionamento inicial, um adaptador de rede em modo NAT pode ser habilitado temporariamente.
Finalidade exclusiva:

- Atualização do sistema operacional,
- Instalação de pacotes e dependências.

Após a conclusão do provisionamento e a criação de um snapshot base estável, o adaptador NAT é removido, mantendo o laboratório operando de forma isolada em Host-Only.

## 13. Instalação do Sistema Operacional

### 13.1 Tipo de Instalação

- Ubuntu Server – instalação minimizada

A opção de instalação minimizada foi adotada com o objetivo de:

- Reduzir a superfície de ataque inicial do sistema,
- Diminuir consumo de recursos (RAM e armazenamento),
- Evitar serviços e pacotes desnecessários,
- Manter maior controle sobre os componentes instalados.

Essa abordagem permite que cada ferramenta e dependência seja instalada de forma consciente e documentada posteriormente, alinhando o ambiente com boas práticas de hardening e princípio do menor privilégio.
Mesmo na modalidade minimizada, o sistema mantém funcionalidades essenciais para administração remota e configuração manual dos serviços necessários ao laboratório.

## 14. Configuração de Armazenamento

### 14.1 Esquema de Disco

- LUKS + LVM
- Layout padrão do instalador

## 15. Configuração de Acesso Remoto

### 15.1 SSH

- OpenSSH Server instalado durante a instalação

Permite administração remota do servidor e reflete práticas comuns de gestão em ambientes corporativos.

### 15.2 Chaves SSH

A importação de chaves SSH não foi realizada nesta etapa, permitindo a definição posterior de políticas de hardening adequadas.

## 16. Serviços Adicionais

Nenhum snap adicional foi instalado durante a instalação inicial.
Justificativa:

- Manter o sistema limpo e sob controle,
- Evitar consumo desnecessário de recursos,
- Garantir que cada ferramenta seja instalada e documentada de forma consciente.

## 17. Finalização da Instalação

Após a instalação:

- A sistema foi reiniciado,
- O disco criptografado foi desbloqueado manualmente,
- As informações de hostname, versão do sistema e acesso SSH foram exibidas corretamente.

Isso confirma que:
- O processo de boot foi concluído com sucesso,
- LUKS e LVM estão operacionais,
- O servidor está pronto para a configuração das ferramentas de segurança.

## 18. Configuração de Volumes Lógicos sobre Camada Criptografada (LUKS + LVM)

Com o sistema já instalado sobre uma camada criptografada (LUKS) e utilizando LVM para gerenciamento lógico de volumes, foi realizada a criação de volumes dedicados para:

- Logs do sistema e ferramentas de segurança,
- Dados de aplicações vulneráveis e serviços auxiliares.

Essa segmentação visa:

- Melhor organização estrutural,
- Isolamento entre sistema, logs e dados de aplicação,
- Maior controle de armazenamento,
- Simulação de boas práticas adotadas em ambientes corporativos.

### 18.1 Preparação da Estrutura LVM

#### 18.1.2 Verificação do Volume Group

Foi identificado espaço livre disponível no Volume Group ubuntu-vg, residente sobre o container criptografado LUKS.
Essa verificação garantiu que novos volumes poderiam ser criados sem necessidade de redimensionamento do volume raiz.
#### 18.1.3 Criação dos Logical Volumes
Foram criados dois novos Logical Volumes:

- lv_logs

Tamanho: 10 GB.
Finalidade: Armazenamento de logs do sistema, Suricata, Wazuh, Rsyslog e demais ferramentas de monitoramento.

- lv_srv

Tamanho: Espaço restante disponível no Volume Group,
Finalidade: Armazenamento de aplicações vulneráveis (ex: DVWA, Juice Shop) e dados associados.

A criação desses volumes mantém a separação entre:

- Sistema operacional (/),
- Logs críticos (/var/log),
- Dados de aplicação (/srv).

### 18.2 Formatação e Preparação dos Volumes

#### 18.2.1 Sistema de Ficheiros

Os volumes foram formatados com:

- Sistema de ficheiros: ext4.

Justificativa:

- Estável,
- Leve,
- Amplamente suportado,
- Adequado para ambientes de laboratório.

#### 18.2.2 Migração de Dados Existentes

Para garantir integridade e preservação de permissões:

- Foi instalada a ferramenta rsync,
- Realizada sincronização do conteúdo existente de /var/log para o novo volume dedicado.

O uso de rsync permitiu:

- Preservação de permissões,
- Preservação de atributos,
- Preservação de timestamps,
- Redução de risco de inconsistência.

### 18.3 Persistência e Montagem Permanente

#### 18.3.1 Atualização do Ficheiro /etc/fstab

Para garantir montagem automática no arranque do sistema, o ficheiro /etc/fstab foi editado com a inclusão das seguintes entradas:

- /dev/mapper/ubuntu--vg-lv_logs → montado em /var/log,
- /dev/mapper/ubuntu--vg-lv_srv → montado em /srv.

Essa configuração assegura que:

- Os volumes sejam montados automaticamente durante o boot,
- O sistema mantenha consistência estrutural após reinicializações.

#### 18.3.2 Atualização das Definições do Sistema

Após modificação do fstab, foi executado:

- systemctl daemon-reload.

### 18.4 Validação

Após reinicialização do sistema, foi verificado que:

- /var/log encontra-se montado no volume dedicado lv_logs,
- /srv encontra-se montado no volume lv_srv,
- O sistema inicializa sem erros,
- O container LUKS é desbloqueado corretamente no boot,
- O LVM reconhece todos os Logical Volumes criados.

---

# Conclusão

A construção da base da infraestrutura estabeleceu os pilares técnicos do laboratório, garantindo um ambiente controlado, isolado e seguro para a implementação das ferramentas de monitoramento e detecção.
A utilização de UEFI, criptografia com LUKS e gerenciamento de volumes com LVM proporcionou maior controle sobre o armazenamento e aumentou o nível de proteção dos dados. A segmentação de rede e o isolamento do ambiente virtual garantem que os testes possam ser realizados sem impacto externo.
Essa etapa foi essencial para aplicar conceitos fundamentais de segurança, como:

- Defesa em profundidade,
- Princípio do menor privilégio,
- Isolamento de ambiente,
- Planejamento de arquitetura.

Com a base consolidada, o laboratório está preparado para a instalação e configuração das ferramentas de segurança, permitindo a simulação de cenários reais de monitoramento e análise de incidentes.
A infraestrutura criada não é apenas funcional, mas estruturada com foco em boas práticas de segurança desde a camada mais fundamental do sistema.
