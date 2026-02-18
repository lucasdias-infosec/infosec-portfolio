# Guia de Estilo

Este guia detalha padrões de escrita, formatação, convenções de nomenclatura e boas práticas para manter a documentação consistente, clara e segura.

---

## 1. Estrutura e Organização do Documento

**Hierarquia de Títulos:**

# → Título do Documento  

## → Seções Principais  

### → Sub-seções  

#### → Tópicos Detalhados  

**Parágrafos:** Prefira 3–5 linhas; quebre o texto para melhorar a legibilidade.  

**Listas:** Utilize `-` ou `*` de forma consistente; listas numeradas apenas para etapas sequenciais.  

**Referências:** Cite fontes externas de forma concisa ao final do documento.  

---

## 2. Código e Comandos

- Sempre utilize blocos de código (```) com a linguagem especificada (bash, yaml, python).  
- Nunca inclua dados reais de rede, senhas ou chaves privadas.  
- Prefira exemplos genéricos:

```bash
ssh user@host.example
```
- Utilize comentários dentro do código para explicar partes complexas.

---

## 3. Imagens e Mídias

- Armazene em `docs/assets/` com nomes claros (ex.: `topology-red-blue.png`).  
- Evite capturas de tela de sistemas reais ou informações sensíveis.  
- Padronize tamanho e proporção sempre que possível (ex.: largura máxima de 800px).  
- Utilize legendas curtas e descritivas para contextualizar as imagens.  

---

## 4. Terminologia e Linguagem

- Utilize termos técnicos precisos e consistentes.  
- Utilize inglês para conceitos globais (ex.: SIEM, IDS), explicando em português quando necessário.  
- Evite jargões ou abreviações sem explicação.  
- Mantenha linguagem clara, objetiva e neutra.  

---

## 5. Padronização em Markdown

- **Código:** Blocos com linguagem especificada.  
- **Links internos:** Utilize caminhos relativos.  
- **Ênfase:** Negrito para alertas ou termos importantes; itálico para exemplos ou observações.  
- **Tabelas:** Organize dados de forma consistente, com cabeçalhos claros.  

---

## 6. Revisão e Pull Requests

- Verifique ortografia, gramática e estilo antes de enviar o PR.  
- Inclua descrição clara das alterações e do propósito.  
- Garanta que a branch siga o padrão de nomenclatura: `firstname-lastname/feature` ou `feature/name`.  
- O PR deve ser revisado por pelo menos um colaborador antes do merge.  

---

## 7. Boas Práticas de Segurança

- Todo o conteúdo deve seguir princípios éticos e boas práticas de segurança da informação.  
- Nunca envie dados reais de clientes, redes ou sistemas.  
- Exemplos de ataques devem ser sempre simulados em ambiente seguro.
