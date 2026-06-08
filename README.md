# 🌐 Network Analysis Labs — SOC Lab

Laboratório prático de análise de tráfego de rede com foco em identificação de anomalias e triagem SOC.  
Todos os exercícios foram realizados com arquivos **pcap reais**, utilizando **Wireshark** e **tshark** em ambiente WSL (Ubuntu).

---

## 📂 Estrutura do repositório

```
network-analysis-labs/
├── 01-traffic-analysis/
│   ├── README.md
│   ├── traffic-investigation.md
│   └── incident-report-network.md
├── 02-dns-analysis/
│   ├── README.md
│   └── dns-investigation.md
├── reference/
│   └── network-cheatsheet.md
└── README.md
```

---

## 🧪 Lab 01 — Análise de Tráfego Anômalo (Exercício Cego)

### Contexto

Arquivo pcap fornecido sem contexto prévio — simulando um alerta real de SOC onde o analista recebe apenas o tráfego capturado e precisa determinar o que aconteceu.  
Objetivo: identificar anomalias, classificar o tipo de tráfego suspeito e elaborar relatório de incidente.

### Objetivo

Analisar o tráfego sem informações prévias, identificar padrões anômalos e determinar se houve comprometimento, exfiltração de dados ou comunicação com infraestrutura maliciosa.

---

### 🔍 Fluxo de investigação

#### Etapa 1 — Visão geral do arquivo pcap

```bash
# Via tshark no terminal
tshark -r arquivo.pcap -q -z io,phs

# Quantidade total de pacotes
tshark -r arquivo.pcap | wc -l
```

**O que analisar:**
- Hierarquia de protocolos — quais protocolos dominam o tráfego?
- Volume total de pacotes — tráfego excessivo pode indicar scan ou exfiltração
- Janela de tempo — qual o período capturado?

---

#### Etapa 2 — Identificar os hosts envolvidos

```bash
# IPs de origem e destino mais frequentes
tshark -r arquivo.pcap -q -z conv,ip

# Via Wireshark: Statistics → Conversations → IPv4
```

**O que analisar:**
- IPs internos vs externos — há comunicação com IPs fora da rede esperada?
- Volume por host — algum host concentra tráfego desproporcional?
- IPs desconhecidos ou de geolocalização suspeita

---

#### Etapa 3 — Analisar conversas TCP

```bash
# Listar todas as conversas TCP
tshark -r arquivo.pcap -q -z conv,tcp

# Via Wireshark: Statistics → Conversations → TCP
```

**O que analisar:**
- Portas de destino incomuns (fora de 80, 443, 53, 22)
- Conexões para portas altas (>1024) em IPs externos
- Volume de dados transferido por conversa — exfiltração gera conversas com alto volume de saída
- Flags TCP anômalos (SYN sem SYN-ACK = scan de porta)

---

#### Etapa 4 — Investigar queries DNS

```bash
# Extrair todas as queries DNS
tshark -r arquivo.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name

# Filtrar respostas DNS com falha (NXDOMAIN)
tshark -r arquivo.pcap -Y "dns.flags.rcode == 3" -T fields -e dns.qry.name
```

**Red flags DNS:**
- Alto volume de queries NXDOMAIN — pode indicar DGA (Domain Generation Algorithm)
- Domínios com nomes aleatórios (`xk3j9as.com`, `p9f2lmq.net`)
- Queries para subdomínios excessivamente longos — possível DNS tunneling
- Resolução de domínios recém-registrados

---

#### Etapa 5 — Inspecionar conteúdo HTTP

```bash
# Extrair requisições HTTP
tshark -r arquivo.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

# Ver User-Agents
tshark -r arquivo.pcap -Y "http.request" -T fields -e http.user_agent
```

**O que analisar:**
- User-agents incomuns ou genéricos (ferramentas de ataque usam UAs padrão)
- URIs com parâmetros codificados em base64
- Downloads de executáveis (`.exe`, `.ps1`, `.bat`)
- Comunicação HTTP sem criptografia com IPs externos (C2 básico)

---

#### Etapa 6 — Filtros de investigação no Wireshark

```wireshark
# Tráfego de um IP específico
ip.addr == 192.168.1.100

# Apenas tráfego DNS
dns

# Apenas tráfego HTTP
http

# Pacotes com payload (excluir ACKs vazios)
tcp.len > 0

# Conexões para portas não padrão
tcp.dstport != 80 && tcp.dstport != 443 && tcp.dstport != 53

# SYN sem resposta (port scan)
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

---

#### Etapa 7 — Exportar objetos suspeitos

No Wireshark:
1. **File → Export Objects → HTTP**
2. Identifica arquivos transferidos (executáveis, scripts, documentos)
3. Gera hash SHA256 dos arquivos exportados
4. Consulta no VirusTotal

```bash
sha256sum arquivo-exportado
```

---

### 📋 Relatório de Incidente — Tráfego Anômalo

**Data:** 02/06/2026  
**Analista:** Natan Almeida  
**Severidade:** Severidade  
**Status:** Investigado

| Campo | Detalhe |
|---|---|
| Tipo de incidente | Tráfego de rede anômalo identificado em pcap |
| Hosts envolvidos | Não aplicável - exercicío de referência |
| Protocolos | DNS / HTTP / TCP |
| Anomalia principal | DNS anômalo / tráfego HTTP sem criptografia |
| Período do tráfego | Não aplicável - exercicío de refência |
| Arquivos exportados | Não |
| Hash SHA256 | Não aplicável |
| Resultado VirusTotal | Não aplicável |
| Ação recomendada | Bloquear IP / Isolar host / Escalar para N2 |
| Escalonamento | Não |

---

## 🧪 Lab 02 — Análise de Queries DNS Suspeitas

### Contexto

Identificação de padrões DNS anômalos que podem indicar comunicação com infraestrutura de C2 (Command and Control) ou tentativa de DNS tunneling.

### Fluxo de investigação

```bash
# Volume de queries por domínio
tshark -r arquivo.pcap -Y "dns.flags.response == 0" \
  -T fields -e dns.qry.name | sort | uniq -c | sort -rn

# Identificar domínios com alto volume de NXDOMAIN
tshark -r arquivo.pcap -Y "dns.flags.rcode == 3" \
  -T fields -e dns.qry.name | sort | uniq -c | sort -rn

# Subdomínios longos (possível tunneling)
tshark -r arquivo.pcap -Y "dns.flags.response == 0" \
  -T fields -e dns.qry.name | awk 'length > 50'
```

**Critérios de suspeita:**
- Mais de 100 queries NXDOMAIN em curto período
- Subdomínios com mais de 50 caracteres
- Padrão de nomes aleatórios (entropia alta)
- Queries para o mesmo domínio raiz com subdomínios variados

---

## 📎 Referências utilizadas

- [Wireshark Display Filters](https://wiki.wireshark.org/DisplayFilters)
- [tshark man page](https://www.wireshark.org/docs/man-pages/tshark.html)
- [VirusTotal](https://www.virustotal.com)
- [Any.run Sandbox](https://any.run)
- Trilha SOC Analyst Júnior (estudo estruturado com foco em Blue Team)

---

## 🛠️ Ambiente

| Item | Detalhe |
|---|---|
| OS | Ubuntu (WSL) |
| Ferramentas | Wireshark, tshark |
| Arquivos analisados | pcap (capturas reais de exercício) |
| Contexto | Exercício cego — análise sem informações prévias |

---

*Laboratório em evolução — novos exercícios e pcaps adicionados conforme avanço na trilha.*
