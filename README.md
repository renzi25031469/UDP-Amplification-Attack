<p align="center">

![alt text](https://github.com/renzi25031469/UDP-Amplification-Attack/blob/main/udp_amp_blueteam_banner.svg?raw=true)

<p align="center">

<p align="center">
  <img src="https://img.shields.io/badge/python-3.6%2B-blue?style=for-the-badge&logo=python"/>
  <img src="https://img.shields.io/badge/platform-linux-lightgrey?style=for-the-badge&logo=linux"/>
  <img src="https://img.shields.io/badge/requires-root-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/purpose-blue%20team-0080ff?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/dependencies-zero-brightgreen?style=for-the-badge"/>
</p>

<p align="center">
  UDP scanner for DDoS amplification attack surface mapping.<br/>
  Scanner UDP para mapeamento de superfície de ataque de amplificação DDoS.<br/><br/>
  <b>by Renzi</b>
</p>

---

<p align="center">
  <a href="#-english">🇺🇸 English</a> &nbsp;|&nbsp; <a href="#-português">🇧🇷 Português</a>
</p>

---

## 🇺🇸 English

### Table of Contents

- [Overview](#overview)
- [Why this scanner?](#why-this-scanner)
- [Monitored Services](#monitored-services)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Options](#options)
- [Targets Format](#targets-format)
- [Output Files](#output-files)
- [Practical Examples](#practical-examples)
- [How It Works](#how-it-works)
- [Legal Notice](#legal-notice)

---

### Overview

`udp_amp_monitor.py` is a **blue team** tool for identifying misconfigured UDP services that can be exploited in DDoS amplification attacks. These attacks abuse protocols that respond with packets far larger than the original request, allowing an attacker to amplify their traffic by directing reflections at the victim.

The tool scans IP blocks for vulnerable services such as SNMP, NTP, Memcached, open DNS resolvers, and others, generating detailed reports in TXT, CSV, and JSON formats.

---

### Why this scanner?

Most UDP scanning tools (masscan, naabu) rely on **libpcap / AF_PACKET (Layer 2 raw sockets)**, which is **blocked by the kernel** in:

- VMs and hypervisors (VMware, KVM, Hyper-V)
- Cloud VPS (AWS, GCP, Azure, DigitalOcean)
- Containers (Docker, LXC)
- Environments with capability restrictions

This scanner uses `SOCK_RAW IPPROTO_UDP` **(Layer 3)** — no libpcap, no ARP, no dependency on a specific interface. It works in **any Linux environment with Python 3.6+ and root**.

| Feature | masscan / naabu | udp_amp_monitor |
|---|---|---|
| Works on VPS / cloud | ❌ (libpcap blocked) | ✅ |
| Works in containers | ❌ | ✅ |
| External dependencies | libpcap, Go/gcc | **None** |
| Service-specific probes | ❌ | ✅ |
| Report with amplification factor | ❌ | ✅ |
| CSV + JSON + TXT output | ❌ | ✅ |

---

### Monitored Services

| Port | Service | Amplification Factor |
|---|---|---|
| UDP/19 | Chargen | ~358x |
| UDP/53 | DNS (open resolver) | ~28–54x |
| UDP/69 | TFTP | ~60x |
| UDP/111 | Portmap / RPCbind | ~7–28x |
| UDP/123 | NTP | ~556x ⚠️ |
| UDP/137 | NetBIOS NS | ~3.8x |
| UDP/161 | SNMP v1/v2 | ~650x ⚠️ |
| UDP/389 | CLDAP | ~56–70x ⚠️ |
| UDP/500 | IKE / IPSec | variable |
| UDP/520 | RIP | ~13x |
| UDP/623 | IPMI / RMCP | ~9x |
| UDP/1194 | OpenVPN | variable |
| UDP/1434 | MSSQL | ~250x |
| UDP/1900 | SSDP / UPnP | ~30x |
| UDP/3283 | Apple ARD | ~35x |
| UDP/3702 | WS-Discovery | ~500x ⚠️ |
| UDP/4500 | IKEv2 NAT-T | variable |
| UDP/5353 | mDNS | ~2–10x |
| UDP/5683 | CoAP | ~34x |
| UDP/6881 | BitTorrent DHT | ~4x |
| UDP/11211 | **Memcached** | **~50,000x** 🔴 |
| UDP/17185 | VXWORKS WDBRPC | >100x |
| UDP/27015 | Steam | variable |
| UDP/27960 | QuakeWorld | ~63x |

> 🔴 **Critical** — Memcached and SNMP have the highest factors and are actively exploited in real-world attacks.

---

### Requirements

- Python **3.6+** (no external dependencies)
- Linux (tested on Ubuntu 20.04, 22.04, 24.04, Debian 11/12)
- **root** privileges (required for raw sockets)

---

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/udp-amp-monitor.git
cd udp-amp-monitor

# No installation needed — pure Python
# Make executable (optional)
chmod +x udp_amp_monitor.py
```

---

### Usage

```bash
# Basic usage — scans all 24 amplification services
sudo python3 udp_amp_monitor.py targets.txt

# Scan specific ports only
sudo python3 udp_amp_monitor.py targets.txt --ports 53,123,161,11211

# Faster scan with more threads
sudo python3 udp_amp_monitor.py targets.txt --workers 300 --timeout 2.0

# Save results to a custom directory
sudo python3 udp_amp_monitor.py targets.txt --output-dir /opt/scan-results

# Email alert when vulnerable hosts are found
sudo python3 udp_amp_monitor.py targets.txt \
    --alert-email sec@company.com \
    --threshold 10

# Quiet mode (only prints found hosts)
sudo python3 udp_amp_monitor.py targets.txt --quiet
```

---

### Options

| Option | Default | Description |
|---|---|---|
| `targets` | — | File with IPs/CIDRs (required) |
| `--ports` | all | Comma-separated UDP ports |
| `--workers` | `150` | Parallel threads |
| `--timeout` | `1.5` | Per-host timeout in seconds |
| `--retries` | `2` | Retries for unresponsive hosts |
| `--output-dir` | `./udp_amp_results` | Report output directory |
| `--threshold` | `5` | Alert threshold — minimum vulnerable hosts |
| `--alert-email` | — | Email for alerts (requires `mailutils`) |
| `--no-progress` | — | Disable progress logging |
| `--quiet` | — | Show only discovered hosts |

---

### Targets Format

The targets file accepts IPs, CIDRs, and comments:

```
# Internal network
192.168.0.0/24

# External range
100.10.0.0/16

# Single host
203.0.113.45

# /32 also works
198.51.100.1/32
```

---

### Output Files

All files are saved under `--output-dir` (default: `./udp_amp_results/`):

```
udp_amp_results/
├── monitor.log                    # Full execution log
├── report_20240101_120000.txt     # Human-readable report
├── report_20240101_120000.csv     # For spreadsheets / SIEM ingestion
└── report_20240101_120000.json    # For integration with other tools
```

#### Sample TXT report

```
==============================================================
  UDP ATTACK SURFACE REPORT — 2024-01-01 12:00:00
==============================================================
  Total hosts with open ports : 47
  Total findings (ip:port)    : 112

--------------------------------------------------------------
  BREAKDOWN BY SERVICE
--------------------------------------------------------------
  UDP/123     NTP                    factor ~556x      31 hosts
  UDP/161     SNMP v1/v2             factor ~650x      12 hosts
  UDP/1900    SSDP/UPnP              factor ~30x        9 hosts
  UDP/11211   Memcached              factor ~50000x     5 hosts

--------------------------------------------------------------
  TOP 20 MOST EXPOSED HOSTS
--------------------------------------------------------------
  203.0.113.10        4 port(s)
  203.0.113.25        3 port(s)

--------------------------------------------------------------
  ⚠  CRITICAL PRIORITY (severe amplification)
--------------------------------------------------------------
  203.0.113.10        UDP/11211   Memcached  (factor ~50000x)
  203.0.113.44        UDP/161     SNMP v1/v2 (factor ~650x)
```

#### Sample JSON output

```json
{
  "timestamp": "2024-01-01T12:00:00+00:00",
  "scan_elapsed": 142.3,
  "summary": {
    "total_hosts": 47,
    "total_findings": 112
  },
  "services": [
    {
      "port": 161,
      "service": "SNMP v1/v2",
      "factor": "~650x",
      "count": 12,
      "hosts": ["203.0.113.10", "203.0.113.44"]
    }
  ]
}
```

---

### Practical Examples

#### Corporate network scan

```bash
cat > targets.txt << EOF
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
EOF

sudo python3 udp_amp_monitor.py targets.txt \
    --workers 200 \
    --timeout 2.0 \
    --output-dir ./corporate-scan \
    --threshold 1
```

#### Continuous monitoring via cron

```bash
# /etc/cron.d/udp-amp-monitor
0 3 * * * root python3 /opt/udp_amp_monitor.py /etc/scan/targets.txt \
    --quiet \
    --output-dir /var/log/udp-amp \
    --alert-email soc@company.com \
    --threshold 1
```

#### Focused scan on critical services

```bash
# Memcached, SNMP and NTP only (most actively exploited)
sudo python3 udp_amp_monitor.py targets.txt --ports 11211,161,123
```

#### Pipeline integration

```bash
# Extract vulnerable IPs from CSV for remediation
sudo python3 udp_amp_monitor.py targets.txt --quiet
tail -n +2 udp_amp_results/report_*.csv | cut -d',' -f1 | sort -u > vulnerable_ips.txt
```

---

### How It Works

#### Technical architecture

The scanner operates in three stages per host:

```
1. SEND (SOCK_RAW + IP_HDRINCL)
   ┌──────────────────────────────────────────┐
   │  Builds raw IP + UDP + probe packet       │
   │  Computes IP and UDP checksums manually   │
   │  Sends via SOCK_RAW IPPROTO_UDP           │
   └──────────────────────────────────────────┘
            ↓ (per port)

2. RECEIVE (SOCK_RAW recv loop)
   ┌──────────────────────────────────────────┐
   │  Waits for UDP replies within timeout     │
   │  Filters packets by source IP             │
   │  Parses IP header → UDP header            │
   │  Source port of reply = open target port  │
   └──────────────────────────────────────────┘

3. PARALLELISM (ThreadPoolExecutor)
   ┌──────────────────────────────────────────┐
   │  Up to 150 simultaneous hosts             │
   │  Automatic retries for silent hosts       │
   └──────────────────────────────────────────┘
```

#### Why SOCK_RAW IPPROTO_UDP instead of libpcap?

| Layer | Socket | Requires |
|---|---|---|
| Layer 2 (Ethernet) | `AF_PACKET` | libpcap, physical NIC access |
| **Layer 3 (IP)** | **`SOCK_RAW IPPROTO_UDP`** | **root only** |
| Layer 4 (UDP) | `SOCK_DGRAM` | Nothing |

`masscan` and `naabu` use `AF_PACKET` (Layer 2), blocked in virtualized environments because there is no direct NIC access. `SOCK_RAW IPPROTO_UDP` operates at Layer 3 — the kernel handles routing and the packet is transmitted normally.

#### Service-specific probes

Each port uses a minimal probe that triggers a response from the service:

- **SNMP/161** — `GetRequest` for OID `sysDescr` with community `public`
- **NTP/123** — mode 3 client request (monlist disabled, but port responds)
- **Memcached/11211** — `stats\r\n` command
- **DNS/53** — `TXT version.bind CH` query (responds even without resolving)
- **SSDP/1900** — `M-SEARCH` HTTP/1.1 for `ssdp:all`
- all others — standard protocol probes

---

### Legal Notice

> **This tool is intended exclusively for defensive purposes (blue team), security audits, and testing on networks you own or have explicit written authorization to test.**
>
> Unauthorized use to scan third-party networks may be illegal in many jurisdictions. The author accepts no responsibility for misuse of this tool.
>
> Always obtain written authorization before performing security tests on any network.

---

---

## 🇧🇷 Português

### Índice

- [Visão Geral](#visão-geral)
- [Por que este scanner?](#por-que-este-scanner)
- [Serviços Monitorados](#serviços-monitorados)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Uso](#uso)
- [Opções](#opções)
- [Formato dos Targets](#formato-dos-targets)
- [Saídas Geradas](#saídas-geradas)
- [Exemplos Práticos](#exemplos-práticos)
- [Como Funciona](#como-funciona)
- [Aviso Legal](#aviso-legal)

---

### Visão Geral

`udp_amp_monitor.py` é uma ferramenta de **blue team** para identificar serviços UDP mal configurados que podem ser explorados em ataques de amplificação DDoS. Esses ataques abusam de protocolos que respondem com pacotes muito maiores do que a requisição original, permitindo que um atacante amplifique seu tráfego apontando reflexões para a vítima.

A ferramenta escaneia blocos de IP em busca de serviços vulneráveis como SNMP, NTP, Memcached, DNS aberto, entre outros, e gera relatórios detalhados em TXT, CSV e JSON.

---

### Por que este scanner?

A maioria das ferramentas de scan UDP (masscan, naabu) usa **libpcap / AF_PACKET (Layer 2 raw sockets)**, que é **bloqueado pelo kernel** em:

- VMs e hypervisors (VMware, KVM, Hyper-V)
- VPS em nuvem (AWS, GCP, Azure, DigitalOcean)
- Containers (Docker, LXC)
- Ambientes com restrição de capabilities

Este scanner usa `SOCK_RAW IPPROTO_UDP` **(Layer 3)** — sem libpcap, sem ARP, sem dependência de interface específica. Funciona em **qualquer ambiente Linux com Python 3.6+ e root**.

| Feature | masscan / naabu | udp_amp_monitor |
|---|---|---|
| Funciona em VPS/cloud | ❌ (libpcap bloqueado) | ✅ |
| Funciona em containers | ❌ | ✅ |
| Dependências externas | libpcap, Go/gcc | **Nenhuma** |
| Probes específicos por serviço | ❌ | ✅ |
| Relatório com fator de amplificação | ❌ | ✅ |
| Saída CSV + JSON + TXT | ❌ | ✅ |

---

### Serviços Monitorados

| Porta | Serviço | Fator de Amplificação |
|---|---|---|
| UDP/19 | Chargen | ~358x |
| UDP/53 | DNS (open resolver) | ~28–54x |
| UDP/69 | TFTP | ~60x |
| UDP/111 | Portmap / RPCbind | ~7–28x |
| UDP/123 | NTP | ~556x ⚠️ |
| UDP/137 | NetBIOS NS | ~3.8x |
| UDP/161 | SNMP v1/v2 | ~650x ⚠️ |
| UDP/389 | CLDAP | ~56–70x ⚠️ |
| UDP/500 | IKE / IPSec | variável |
| UDP/520 | RIP | ~13x |
| UDP/623 | IPMI / RMCP | ~9x |
| UDP/1194 | OpenVPN | variável |
| UDP/1434 | MSSQL | ~250x |
| UDP/1900 | SSDP / UPnP | ~30x |
| UDP/3283 | Apple ARD | ~35x |
| UDP/3702 | WS-Discovery | ~500x ⚠️ |
| UDP/4500 | IKEv2 NAT-T | variável |
| UDP/5353 | mDNS | ~2–10x |
| UDP/5683 | CoAP | ~34x |
| UDP/6881 | BitTorrent DHT | ~4x |
| UDP/11211 | **Memcached** | **~50.000x** 🔴 |
| UDP/17185 | VXWORKS WDBRPC | >100x |
| UDP/27015 | Steam | variável |
| UDP/27960 | QuakeWorld | ~63x |

> 🔴 **Crítico** — Memcached e SNMP possuem os maiores fatores e são ativamente explorados em ataques reais.

---

### Requisitos

- Python **3.6+** (sem dependências externas)
- Linux (testado em Ubuntu 20.04, 22.04, 24.04, Debian 11/12)
- Privilégios **root** (necessário para raw sockets)

---

### Instalação

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/udp-amp-monitor.git
cd udp-amp-monitor

# Nenhuma instalação necessária — Python puro
# Torna executável (opcional)
chmod +x udp_amp_monitor.py
```

---

### Uso

```bash
# Uso básico — escaneia todos os 24 serviços de amplificação
sudo python3 udp_amp_monitor.py targets.txt

# Escaneia portas específicas
sudo python3 udp_amp_monitor.py targets.txt --ports 53,123,161,11211

# Scan mais rápido com mais threads
sudo python3 udp_amp_monitor.py targets.txt --workers 300 --timeout 2.0

# Salva resultados em diretório customizado
sudo python3 udp_amp_monitor.py targets.txt --output-dir /opt/scan-results

# Alerta por e-mail quando encontrar hosts vulneráveis
sudo python3 udp_amp_monitor.py targets.txt \
    --alert-email sec@empresa.com \
    --threshold 10

# Modo silencioso (só exibe hosts encontrados)
sudo python3 udp_amp_monitor.py targets.txt --quiet
```

---

### Opções

| Opção | Padrão | Descrição |
|---|---|---|
| `targets` | — | Arquivo com IPs/CIDRs (obrigatório) |
| `--ports` | todos | Portas UDP separadas por vírgula |
| `--workers` | `150` | Threads paralelas |
| `--timeout` | `1.5` | Timeout por host (segundos) |
| `--retries` | `2` | Retentativas por host sem resposta |
| `--output-dir` | `./udp_amp_results` | Diretório de saída dos relatórios |
| `--threshold` | `5` | Limiar para alerta — mínimo de hosts vulneráveis |
| `--alert-email` | — | E-mail para alerta (requer `mailutils`) |
| `--no-progress` | — | Desativa log de progresso |
| `--quiet` | — | Exibe somente hosts encontrados |

---

### Formato dos Targets

O arquivo de targets aceita IPs, CIDRs e comentários:

```
# Rede interna
192.168.0.0/24

# Faixa externa
100.10.0.0/16

# Host único
203.0.113.45

# /32 também funciona
198.51.100.1/32
```

---

### Saídas Geradas

Todos os arquivos são salvos em `--output-dir` (padrão: `./udp_amp_results/`):

```
udp_amp_results/
├── monitor.log                    # Log completo da execução
├── report_20240101_120000.txt     # Relatório legível
├── report_20240101_120000.csv     # Para planilhas / SIEM
└── report_20240101_120000.json    # Para integração com outras ferramentas
```

#### Exemplo de relatório TXT

```
==============================================================
  RELATÓRIO DE SUPERFÍCIE DE ATAQUE UDP — 2024-01-01 12:00:00
==============================================================
  Total de hosts com portas abertas : 47
  Total de achados (ip:porta)       : 112

--------------------------------------------------------------
  DETALHAMENTO POR SERVIÇO
--------------------------------------------------------------
  UDP/123     NTP                    fator ~556x       31 hosts
  UDP/161     SNMP v1/v2             fator ~650x       12 hosts
  UDP/1900    SSDP/UPnP              fator ~30x         9 hosts
  UDP/11211   Memcached              fator ~50000x      5 hosts

--------------------------------------------------------------
  HOSTS MAIS EXPOSTOS (Top 20)
--------------------------------------------------------------
  203.0.113.10        4 porta(s)
  203.0.113.25        3 porta(s)

--------------------------------------------------------------
  ⚠  PRIORIDADE CRÍTICA (amplificação severa)
--------------------------------------------------------------
  203.0.113.10        UDP/11211   Memcached  (fator ~50000x)
  203.0.113.44        UDP/161     SNMP v1/v2 (fator ~650x)
```

#### Exemplo de saída JSON

```json
{
  "timestamp": "2024-01-01T12:00:00+00:00",
  "scan_elapsed": 142.3,
  "summary": {
    "total_hosts": 47,
    "total_findings": 112
  },
  "services": [
    {
      "port": 161,
      "service": "SNMP v1/v2",
      "factor": "~650x",
      "count": 12,
      "hosts": ["203.0.113.10", "203.0.113.44"]
    }
  ]
}
```

---

### Exemplos Práticos

#### Scan de rede corporativa

```bash
cat > targets.txt << EOF
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
EOF

sudo python3 udp_amp_monitor.py targets.txt \
    --workers 200 \
    --timeout 2.0 \
    --output-dir ./corporate-scan \
    --threshold 1
```

#### Monitoramento contínuo via cron

```bash
# /etc/cron.d/udp-amp-monitor
0 3 * * * root python3 /opt/udp_amp_monitor.py /etc/scan/targets.txt \
    --quiet \
    --output-dir /var/log/udp-amp \
    --alert-email soc@empresa.com \
    --threshold 1
```

#### Scan focado em serviços críticos

```bash
# Apenas Memcached, SNMP e NTP (os mais explorados)
sudo python3 udp_amp_monitor.py targets.txt --ports 11211,161,123
```

#### Integração com pipeline de dados

```bash
# Extrai só os IPs vulneráveis do CSV para remediar
sudo python3 udp_amp_monitor.py targets.txt --quiet
tail -n +2 udp_amp_results/report_*.csv | cut -d',' -f1 | sort -u > vulnerable_ips.txt
```

---

### Como Funciona

#### Arquitetura técnica

O scanner opera em três etapas para cada host:

```
1. ENVIO (SOCK_RAW + IP_HDRINCL)
   ┌─────────────────────────────────────────┐
   │  Monta pacote IP + UDP + probe           │
   │  Calcula checksums IP e UDP manualmente  │
   │  Envia via SOCK_RAW IPPROTO_UDP          │
   └─────────────────────────────────────────┘
            ↓ (para cada porta)

2. RECEPÇÃO (SOCK_RAW recv em loop)
   ┌─────────────────────────────────────────┐
   │  Aguarda respostas UDP dentro do timeout │
   │  Filtra pacotes pelo IP de origem        │
   │  Parseia cabeçalho IP → UDP              │
   │  Identifica porta de origem = porta alvo │
   └─────────────────────────────────────────┘

3. PARALELISMO (ThreadPoolExecutor)
   ┌─────────────────────────────────────────┐
   │  Até 150 hosts simultâneos (configurável)│
   │  Retentativas automáticas para silenciosos│
   └─────────────────────────────────────────┘
```

#### Por que SOCK_RAW IPPROTO_UDP e não libpcap?

| Camada | Socket | Requer |
|---|---|---|
| Layer 2 (Ethernet) | `AF_PACKET` | libpcap, acesso físico à interface |
| **Layer 3 (IP)** | **`SOCK_RAW IPPROTO_UDP`** | **Apenas root** |
| Layer 4 (UDP) | `SOCK_DGRAM` | Nenhum |

`masscan` e `naabu` usam `AF_PACKET` (Layer 2), que é bloqueado em ambientes virtualizados porque não há acesso direto à placa de rede. `SOCK_RAW IPPROTO_UDP` opera no Layer 3 — o kernel cuida do roteamento e o pacote é enviado normalmente.

#### Probes específicos por serviço

Cada porta usa um probe mínimo que provoca resposta do serviço:

- **SNMP/161** — `GetRequest` para OID `sysDescr` com community `public`
- **NTP/123** — client request modo 3 (monlist desabilitado, mas a porta responde)
- **Memcached/11211** — comando `stats\r\n`
- **DNS/53** — query `TXT version.bind CH` (responde mesmo sem resolver)
- **SSDP/1900** — `M-SEARCH` HTTP/1.1 para `ssdp:all`
- demais serviços — probes padrão do protocolo

---

### Aviso Legal

> **Esta ferramenta é destinada exclusivamente a fins defensivos (blue team), auditoria de segurança e testes em redes sob sua responsabilidade ou com autorização explícita por escrito.**
>
> O uso não autorizado para escanear redes de terceiros pode ser ilegal em diversas jurisdições. O autor não se responsabiliza pelo uso indevido desta ferramenta.
>
> Sempre obtenha autorização por escrito antes de realizar testes de segurança em qualquer rede.

---

<p align="center">
  Built for blue teamers who need a tool that <b>actually works</b>.<br/>
  Feito para blue teamers que precisam de uma ferramenta que <b>realmente funciona</b>.<br/><br/>
  <b>by Renzi</b>
</p>
