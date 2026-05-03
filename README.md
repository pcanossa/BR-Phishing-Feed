# Br-Phishing-Feed: Feed de Detecções de Domínios Phishing no Brasil


O **Br-Phishing-Feed** é uma infraestrutura de coleta rápida e resiliente projetada para operações de Cyber Threat Intelligence (CTI). Ele fornece um nó local do CertStream (escrito em Rust) que consome o feed global de Transparência de Certificados (CT Logs) em tempo real.

Este repositório disponibiliza **exclusivamente a infraestrutura do Feed (Backend)**. O objetivo é fornecer uma "mangueira de dados" limpa, sem latência e sem limites de taxa (rate limiting), servindo como base para pipelines de segurança, detecção de phishing e proteção de marcas.

## 🏗️ Arquitetura Criada (O Funil de CTI)

Para lidar com a avalanche de dados globais (centenas de certificados por segundo) sem esgotar recursos, recomendamos o consumo deste Feed através de uma arquitetura de múltiplas camadas, culminando em uma triagem baseada em Inteligência Artificial.

1. **Camada 1 - A Fonte (Este Repositório):** Servidor local conectando-se aos CT Logs globais e expondo um WebSocket.
2. **Camada 2 - Filtro Heurístico Rápido:** Um consumidor (ex: script Python ou n8n) que aplica filtros Regex e Whitelists para cortar 99% do ruído mundial e isolar marcas de interesse.
3. **Camada 3 - Triagem com IA e Auditoria:** Domínios que passam pelo filtro rápido são enviados a um LLM (ex: Ollama local com GPT oss) para análise de contexto, *typosquatting* e intenção maliciosa.

## 🧠 Triagem Inteligente e Auditoria de Falsos Positivos

O grande desafio da detecção baseada em palavras-chave é o alto índice de **Falsos Positivos**. Para resolver isso, a integração de um LLM no final do pipeline não apenas valida a ameaça, mas **audita a decisão**.

Ao invés de um simples alerta de "Bloqueado", a IA deve ser instruída a gerar um relatório em JSON documentando o raciocínio forense que a levou a classificar o domínio como um **Real Positivo**. 

**------------------IMPORTANTE: O FLUXO DE TRIAGEM CRIADA, NÃO EXCLUI A POSSIBILIDADE 0% DE OCORRÊNCIA DE FALSOS POSITIVOS------------------**
**Exemplo de Saída Esperada do Pipeline de IA:**
```json
{
  "dominio": "entrega-correios.com",
  "data_registro": "05/03/26 11:22:32",
  "categoria_ameaca": "phishing",
  "auditoria_decisao": {
    "motivo_classificacao": "verdadeiro_positivo",
    "caracteristicas_suspeitas": [
      "Contém a marca governamental 'correios' isolada",
      "Contém o termo de urgência/logística 'entrega' como prefixo",
      "Ausência do TLD oficial '.com.br'"
    ],
    "analise_comportamental": "O domínio imita a estrutura de rastreamento do órgão oficial, utilizando engenharia social comum em fraudes logísticas no Brasil."
  }
}
```
---
## Criadora do Projeto
* **Github:** pcanossa
* **Linkedin:** linkedin.com/in/patricia-canossa-gagliardi

---
## Objetivo do Projeto

Esse proejto foi criado, principalmente, para, fornecer de forma fácil e aberta, inteligência de detecção de domínios com alto potencial de malignidade para vítimas do Brasil, assim, permitindo a fácil detecção e atividade em CTI por profissionais atunates no mercado de trabalho e pesquisadores indepentes, fortalecendo a comunidade de Cibersegutana do Brasil e auxiliando no aumento segurança cibernética nacional e proteção das vítimas. 
Sinta-se a vontade para apoiar o projeto com sugestões, críticas e colaboração direta de melhorias. Toda ajuda é bem vinda!!

