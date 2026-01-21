

# Prometheus Monitoring Stack - Production Deployment Guide


Complete production-ready monitoring stack with **Prometheus**, **Grafana**, **Node Exporter**, **Blackbox Exporter**, and **Alertmanager** on Ubuntu 24.04 LTS.

---

## 📋 Table of Contents

- [Architecture Overview](#-architecture-overview)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
  - [1. Prometheus](#1-prometheus-installation)
  - [2. Node Exporter](#2-node-exporter-installation)
  - [3. Blackbox Exporter](#3-blackbox-exporter-installation)
  - [4. Alertmanager](#4-alertmanager-installation)
  - [5. Grafana](#5-grafana-installation)
- [Configuration](#-configuration)
- [Alert Rules](#-alert-rules)
- [Data Persistence](#-data-persistence--backup)
- [Verification](#-verification)
- [Troubleshooting](#-troubleshooting)
- [Security](#-security-hardening)

---

## 🏗️ Architecture Overview

```



```

### Component Ports

| Component | Port | Purpose | Data Location |
|-----------|------|---------|---------------|
| **Prometheus** | 9090 | Metrics storage & scraping | `/var/lib/prometheus` |
| **Grafana** | 3000 | Visualization | `/var/lib/grafana` |
| **Node Exporter** | 9100 | System metrics | N/A (stateless) |
| **Blackbox Exporter** | 9115 | Endpoint monitoring | N/A (stateless) |
| **Alertmanager** | 9093 | Alert routing | `/var/lib/alertmanager` |

---

## 📦 Prerequisites

### System Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| **OS** | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |
| **CPU** | 2 cores | 4+ cores |
| **RAM** | 4 GB | 8+ GB |
| **Disk** | 50 GB | 100+ GB (SSD) |

### Pre-installation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y wget curl nano tar gpg apt-transport-https
```

---

## 🚀 Installation

### 1. Prometheus Installation

#### 1.1. Create User and Directories

```bash
# Create prometheus user
sudo useradd --no-create-home --shell /bin/false prometheus

# Create directories
sudo mkdir -p /etc/prometheus/{rules,file_sd}
sudo mkdir -p /var/lib/prometheus
```

#### 1.2. Download and Install

```bash
cd /tmp
PROM_VERSION="2.44.0"

# Download
wget https://github.com/prometheus/prometheus/releases/download/v${PROM_VERSION}/prometheus-${PROM_VERSION}.linux-amd64.tar.gz

# Extract
tar -xvzf prometheus-${PROM_VERSION}.linux-amd64.tar.gz
cd prometheus-${PROM_VERSION}.linux-amd64

# Install binaries
sudo mv prometheus promtool /usr/local/bin/
sudo chown prometheus:prometheus /usr/local/bin/prometheus
sudo chown prometheus:prometheus /usr/local/bin/promtool

# Copy console templates
sudo cp -r consoles console_libraries /etc/prometheus/

# Set ownership
sudo chown -R prometheus:prometheus /etc/prometheus
sudo chown -R prometheus:prometheus /var/lib/prometheus
```

#### 1.3. Create Systemd Service

```bash
sudo tee /etc/systemd/system/prometheus.service > /dev/null <<'EOF'
[Unit]
Description=Prometheus Monitoring System
Documentation=https://prometheus.io/docs/introduction/overview/
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=prometheus
Group=prometheus
ExecReload=/bin/kill -HUP $MAINPID
ExecStart=/usr/local/bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/var/lib/prometheus \
  --storage.tsdb.retention.time=30d \
  --storage.tsdb.retention.size=10GB \
  --web.console.templates=/etc/prometheus/consoles \
  --web.console.libraries=/etc/prometheus/console_libraries \
  --web.listen-address=0.0.0.0:9090 \
  --web.enable-lifecycle

SyslogIdentifier=prometheus
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
```

#### 1.4. Enable and Start

```bash
sudo systemctl daemon-reload
sudo systemctl enable prometheus
sudo systemctl start prometheus
sudo systemctl status prometheus
```

---

### 2. Node Exporter Installation

#### 2.1. Download and Install

```bash
cd /tmp
NODE_VERSION="1.7.0"

# Download
wget https://github.com/prometheus/node_exporter/releases/download/v${NODE_VERSION}/node_exporter-${NODE_VERSION}.linux-amd64.tar.gz

# Extract
tar -xzf node_exporter-${NODE_VERSION}.linux-amd64.tar.gz

# Install
sudo mv node_exporter-${NODE_VERSION}.linux-amd64/node_exporter /usr/local/bin/

# Create user
sudo useradd --no-create-home --shell /bin/false nodeexporter
sudo chown nodeexporter:nodeexporter /usr/local/bin/node_exporter
```

#### 2.2. Create Systemd Service

```bash
sudo tee /etc/systemd/system/node_exporter.service > /dev/null <<'EOF'
[Unit]
Description=Prometheus Node Exporter
Documentation=https://github.com/prometheus/node_exporter
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=nodeexporter
Group=nodeexporter
ExecStart=/usr/local/bin/node_exporter \
  --web.listen-address=0.0.0.0:9100

SyslogIdentifier=node_exporter
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

#### 2.3. Enable and Start

```bash
sudo systemctl daemon-reload
sudo systemctl enable node_exporter
sudo systemctl start node_exporter
sudo systemctl status node_exporter
```

> ⚠️ **Security Warning**: Do NOT expose port 9100 to the public internet.

---

### 3. Blackbox Exporter Installation

#### 3.1. Download and Install

```bash
cd /tmp
BLACKBOX_VERSION="0.25.0"

# Download
wget https://github.com/prometheus/blackbox_exporter/releases/download/v${BLACKBOX_VERSION}/blackbox_exporter-${BLACKBOX_VERSION}.linux-amd64.tar.gz

# Extract
tar -xzf blackbox_exporter-${BLACKBOX_VERSION}.linux-amd64.tar.gz

# Install
sudo mv blackbox_exporter-${BLACKBOX_VERSION}.linux-amd64/blackbox_exporter /usr/local/bin/
sudo chown prometheus:prometheus /usr/local/bin/blackbox_exporter

# Create config directory
sudo mkdir -p /etc/blackbox_exporter
```

#### 3.2. Create Configuration

```bash
sudo tee /etc/blackbox_exporter/blackbox.yml > /dev/null <<'EOF'
modules:
  http_2xx:
    prober: http
    timeout: 5s
    http:
      valid_http_versions: ["HTTP/1.1", "HTTP/2.0"]
      valid_status_codes: []
      method: GET
      preferred_ip_protocol: "ip4"
      follow_redirects: true

  http_post_2xx:
    prober: http
    timeout: 5s
    http:
      method: POST
      preferred_ip_protocol: "ip4"

  tcp_connect:
    prober: tcp
    timeout: 5s

  icmp:
    prober: icmp
    timeout: 5s
    icmp:
      preferred_ip_protocol: "ip4"
EOF

sudo chown -R prometheus:prometheus /etc/blackbox_exporter
```

#### 3.3. Create Systemd Service

```bash
sudo tee /etc/systemd/system/blackbox_exporter.service > /dev/null <<'EOF'
[Unit]
Description=Blackbox Exporter
Documentation=https://github.com/prometheus/blackbox_exporter
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=prometheus
Group=prometheus
ExecStart=/usr/local/bin/blackbox_exporter \
  --config.file=/etc/blackbox_exporter/blackbox.yml \
  --web.listen-address=0.0.0.0:9115

SyslogIdentifier=blackbox_exporter
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

#### 3.4. Enable and Start

```bash
sudo systemctl daemon-reload
sudo systemctl enable blackbox_exporter
sudo systemctl start blackbox_exporter
sudo systemctl status blackbox_exporter
```

---

### 4. Alertmanager Installation

#### 4.1. Download and Install

```bash
cd /tmp
AM_VERSION="0.27.0"

# Download
wget https://github.com/prometheus/alertmanager/releases/download/v${AM_VERSION}/alertmanager-${AM_VERSION}.linux-amd64.tar.gz

# Extract
tar -xzf alertmanager-${AM_VERSION}.linux-amd64.tar.gz
cd alertmanager-${AM_VERSION}.linux-amd64

# Install
sudo mv alertmanager amtool /usr/local/bin/
sudo chown prometheus:prometheus /usr/local/bin/alertmanager
sudo chown prometheus:prometheus /usr/local/bin/amtool

# Create directories
sudo mkdir -p /etc/alertmanager
sudo mkdir -p /var/lib/alertmanager
sudo chown -R prometheus:prometheus /etc/alertmanager
sudo chown -R prometheus:prometheus /var/lib/alertmanager
```

#### 4.2. Create Systemd Service

```bash
sudo tee /etc/systemd/system/alertmanager.service > /dev/null <<'EOF'
[Unit]
Description=Prometheus Alertmanager
Documentation=https://prometheus.io/docs/alerting/alertmanager/
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=prometheus
Group=prometheus
ExecStart=/usr/local/bin/alertmanager \
  --config.file=/etc/alertmanager/alertmanager.yml \
  --storage.path=/var/lib/alertmanager \
  --web.listen-address=0.0.0.0:9093

SyslogIdentifier=alertmanager
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

#### 4.3. Enable Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable alertmanager
# Will start after configuration
```

---

### 5. Grafana Installation

#### 5.1. Add Repository

```bash
# Add GPG key
sudo mkdir -p /etc/apt/keyrings/
wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | sudo tee /etc/apt/keyrings/grafana.gpg > /dev/null

# Add repository
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
```

#### 5.2. Install Grafana

```bash
sudo apt-get update
sudo apt-get install -y grafana
```

#### 5.3. Enable and Start

```bash
sudo systemctl daemon-reload
sudo systemctl enable grafana-server
sudo systemctl start grafana-server
sudo systemctl status grafana-server
```

**Access Grafana:**
- URL: `http://<SERVER_IP>:3000`
- Default: `admin` / `admin`

---

## ⚙️ Configuration

### Prometheus Configuration

```bash
sudo tee /etc/prometheus/prometheus.yml > /dev/null <<'EOF'
# Global configuration
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'production'
    replica: '1'

# Alertmanager configuration
alerting:
  alertmanagers:
    - static_configs:
        - targets:
            - localhost:9093

# Load rules
rule_files:
  - "rules/*.yml"

# Scrape configurations
scrape_configs:
  # Prometheus itself
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
        labels:
          env: 'production'

  # Node Exporter
  - job_name: 'node_exporter'
    static_configs:
      - targets: ['localhost:9100']
        labels:
          env: 'production'
          instance: 'monitoring-server'

  # Blackbox Exporter - HTTP probes
  - job_name: 'blackbox_http'
    metrics_path: /probe
    params:
      module: [http_2xx]
    static_configs:
      - targets:
          - https://www.google.com
          - https://status.webex.com
          - https://prometheus.io
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: localhost:9115

  # Blackbox Exporter - TCP probes
  - job_name: 'blackbox_tcp'
    metrics_path: /probe
    params:
      module: [tcp_connect]
    static_configs:
      - targets:
          - 8.8.8.8:53
          - 1.1.1.1:53
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: localhost:9115

  # Blackbox Exporter - ICMP probes
  - job_name: 'blackbox_icmp'
    metrics_path: /probe
    params:
      module: [icmp]
    static_configs:
      - targets:
          - 8.8.8.8
          - 1.1.1.1
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: localhost:9115
EOF

sudo chown prometheus:prometheus /etc/prometheus/prometheus.yml
```

**Validate Configuration:**

```bash
promtool check config /etc/prometheus/prometheus.yml
```

**Restart Prometheus:**

```bash
sudo systemctl restart prometheus
```

---

## 🚨 Alert Rules

### System Alerts

```bash
sudo tee /etc/prometheus/rules/system_alerts.yml > /dev/null <<'EOF'
groups:
  - name: system_alerts
    interval: 30s
    rules:
      - alert: HighCPUUsage
        expr: 100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage on {{ $labels.instance }}"
          description: "CPU usage is {{ $value }}%"

      - alert: CriticalCPUUsage
        expr: 100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 95
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Critical CPU usage on {{ $labels.instance }}"
          description: "CPU usage is {{ $value }}%"

      - alert: HighMemoryUsage
        expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100 > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage on {{ $labels.instance }}"
          description: "Memory usage is {{ $value }}%"

      - alert: DiskSpaceLow
        expr: (node_filesystem_avail_bytes{mountpoint="/",fstype!="rootfs"} / node_filesystem_size_bytes{mountpoint="/",fstype!="rootfs"}) * 100 < 20
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Low disk space on {{ $labels.instance }}"
          description: "Disk space is {{ $value }}%"

      - alert: DiskSpaceCritical
        expr: (node_filesystem_avail_bytes{mountpoint="/",fstype!="rootfs"} / node_filesystem_size_bytes{mountpoint="/",fstype!="rootfs"}) * 100 < 10
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Critical disk space on {{ $labels.instance }}"
          description: "Disk space is {{ $value }}%"
EOF
```

### Service Alerts

```bash
sudo tee /etc/prometheus/rules/service_alerts.yml > /dev/null <<'EOF'
groups:
  - name: service_alerts
    interval: 30s
    rules:
      - alert: ServiceDown
        expr: up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Service {{ $labels.job }} down on {{ $labels.instance }}"
          description: "{{ $labels.job }} has been down for 1 minute"

      - alert: PrometheusDown
        expr: up{job="prometheus"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Prometheus is down"
          description: "Prometheus has been down for 1 minute"

      - alert: NodeExporterDown
        expr: up{job="node_exporter"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Node Exporter down on {{ $labels.instance }}"
          description: "Node Exporter has been down for 1 minute"
EOF
```

### Blackbox Alerts

```bash
sudo tee /etc/prometheus/rules/blackbox_alerts.yml > /dev/null <<'EOF'
groups:
  - name: blackbox_alerts
    interval: 30s
    rules:
      - alert: WebsiteDown
        expr: probe_success{job="blackbox_http"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Website {{ $labels.instance }} is down"
          description: "{{ $labels.instance }} unreachable for 2 minutes"

      - alert: SSLCertificateExpiringSoon
        expr: probe_ssl_earliest_cert_expiry - time() < 86400 * 30
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "SSL certificate expiring soon for {{ $labels.instance }}"
          description: "Certificate expires in {{ $value | humanizeDuration }}"

      - alert: SlowHTTPResponse
        expr: probe_http_duration_seconds > 3
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Slow HTTP response from {{ $labels.instance }}"
          description: "Response time is {{ $value }}s"

      - alert: HTTPStatusCodeError
        expr: probe_http_status_code != 200
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "HTTP error on {{ $labels.instance }}"
          description: "Status code is {{ $value }}"
EOF
```

### Prometheus Self-Monitoring

```bash
sudo tee /etc/prometheus/rules/prometheus_alerts.yml > /dev/null <<'EOF'
groups:
  - name: prometheus_alerts
    interval: 30s
    rules:
      - alert: PrometheusConfigReloadFailure
        expr: prometheus_config_last_reload_successful == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Prometheus config reload failed"
          description: "Configuration reload has failed"

      - alert: PrometheusTSDBCompactionFailed
        expr: rate(prometheus_tsdb_compactions_failed_total[5m]) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Prometheus TSDB compaction failed"
          description: "TSDB compaction is failing"

      - alert: PrometheusRuleEvaluationSlow
        expr: prometheus_rule_group_last_duration_seconds > prometheus_rule_group_interval_seconds
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Prometheus rule evaluation slow"
          description: "Rule group {{ $labels.rule_group }} taking {{ $value }}s"
EOF
```

**Set Ownership and Validate:**

```bash
sudo chown -R prometheus:prometheus /etc/prometheus/rules
promtool check rules /etc/prometheus/rules/*.yml
sudo systemctl restart prometheus
```

---

### Alertmanager Configuration

```bash
sudo tee /etc/alertmanager/alertmanager.yml > /dev/null <<'EOF'
global:
  resolve_timeout: 5m
  smtp_smarthost: 'smtp.gmail.com:587'
  smtp_from: 'alertmanager@example.com'
  smtp_auth_username: 'your-email@gmail.com'
  smtp_auth_password: 'your-app-password'
  smtp_require_tls: true

route:
  receiver: 'default'
  group_by: ['alertname', 'cluster']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  
  routes:
    - match:
        severity: critical
      receiver: 'critical-alerts'
      group_wait: 10s
      repeat_interval: 1h

    - match:
        severity: warning
      receiver: 'warning-alerts'

inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'instance']

receivers:
  - name: 'default'
    email_configs:
      - to: 'team@example.com'
        send_resolved: true

  - name: 'critical-alerts'
    email_configs:
      - to: 'oncall@example.com'
        send_resolved: true
        headers:
          Subject: '[CRITICAL] {{ .GroupLabels.alertname }}'

  - name: 'warning-alerts'
    email_configs:
      - to: 'team@example.com'
        send_resolved: true
        headers:
          Subject: '[WARNING] {{ .GroupLabels.alertname }}'
EOF

sudo chown prometheus:prometheus /etc/alertmanager/alertmanager.yml
```

**Start Alertmanager:**

```bash
sudo systemctl start alertmanager
sudo systemctl status alertmanager
```

---

## 💾 Data Persistence & Backup

### Data Locations

| Component | Data Path | Retention |
|-----------|-----------|-----------|
| Prometheus | `/var/lib/prometheus` | 30 days |
| Grafana | `/var/lib/grafana` | Permanent |
| Alertmanager | `/var/lib/alertmanager` | Temporary |

### Backup Script

```bash
sudo tee /usr/local/bin/prometheus-backup.sh > /dev/null <<'EOF'
#!/bin/bash
BACKUP_DIR="/backup/prometheus"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p ${BACKUP_DIR}

# Prometheus snapshot
SNAPSHOT=$(curl -s -XPOST http://localhost:9090/api/v1/admin/tsdb/snapshot | jq -r '.data.name')

if [ ! -z "$SNAPSHOT" ]; then
    tar -czf ${BACKUP_DIR}/prometheus_${DATE}.tar.gz -C /var/lib/prometheus/snapshots ${SNAPSHOT}
    rm -rf /var/lib/prometheus/snapshots/${SNAPSHOT}
    find ${BACKUP_DIR} -name "prometheus_*.tar.gz" -mtime +7 -delete
    echo "Backup completed: prometheus_${DATE}.tar.gz"
fi

# Backup configs
tar -czf ${BACKUP_DIR}/prometheus_config_${DATE}.tar.gz -C /etc prometheus
EOF

sudo chmod +x /usr/local/bin/prometheus-backup.sh
```

### Daily Backup Cron

```bash
echo "0 2 * * * root /usr/local/bin/prometheus-backup.sh >> /var/log/prometheus-backup.log 2>&1" | sudo tee -a /etc/crontab
```

---

## ✅ Verification

### 1. Check All Services

```bash
# Check service status
sudo systemctl status prometheus --no-pager
sudo systemctl status node_exporter --no-pager
sudo systemctl status blackbox_exporter --no-pager
sudo systemctl status alertmanager --no-pager
sudo systemctl status grafana-server --no-pager
```

### 2. Verify Ports

```bash
sudo ss -lntp | grep -E ':9090|:9100|:9115|:9093|:3000'
```

**Expected Output:**
```
LISTEN 0  4096  *:9090  *:*  users:(("prometheus",pid=...))
LISTEN 0  4096  *:9100  *:*  users:(("node_exporter",pid=...))
LISTEN 0  4096  *:9115  *:*  users:(("blackbox_export",pid=...))
LISTEN 0  4096  *:9093  *:*  users:(("alertmanager",pid=...))
LISTEN 0  4096  *:3000  *:*  users:(("grafana-server",pid=...))
```

### 3. HTTP Health Checks

```bash
# Prometheus
curl -sS http://localhost:9090/-/healthy

# Node Exporter
curl -sS http://localhost:9100/metrics | head -n 5

# Blackbox Exporter
curl -sS http://localhost:9115/metrics | head -n 5

# Alertmanager
curl -sS http://localhost:9093/-/healthy

# Grafana
curl -sS -I http://localhost:3000 | head -n 1
```

### 4. Verify Prometheus Targets

```bash
# Check all targets
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, instance: .labels.instance, health: .health}'
```

**Expected: All targets with `"health": "up"`**

### 5. Test Blackbox Probes

```bash
# Test HTTP probe
curl -s 'http://localhost:9115/probe?target=https://google.com&module=http_2xx' | grep probe_success

# Test TCP probe
curl -s 'http://localhost:9115/probe?target=8.8.8.8:53&module=tcp_connect' | grep probe_success
```

### 6. Validate Configurations

```bash
# Prometheus config
promtool check config /etc/prometheus/prometheus.yml

# Alert rules
promtool check rules /etc/prometheus/rules/*.yml

# Alertmanager config
amtool check-config /etc/alertmanager/alertmanager.yml
```

### 7. Web UI Verification

| Service | URL | Check |
|---------|-----|-------|
| Prometheus | `http://<IP>:9090` | Status → Targets (all UP) |
| Grafana | `http://<IP>:3000` | Login with admin/admin |
| Alertmanager | `http://<IP>:9093` | No firing alerts initially |

### 8. Query Test

```bash
# CPU usage query
curl -s 'http://localhost:9090/api/v1/query?query=100-(avg(rate(node_cpu_seconds_total{mode="idle"}[5m]))*100)' | jq

# Memory usage query
curl -s 'http://localhost:9090/api/v1/query?query=(1-(node_memory_MemAvailable_bytes/node_memory_MemTotal_bytes))*100' | jq

# Probe success
curl -s 'http://localhost:9090/api/v1/query?query=probe_success' | jq
```

---

## 🔧 Troubleshooting

### Service Issues

#### Prometheus Not Starting

```bash
# Check logs
sudo journalctl -u prometheus -n 50 --no-pager

# Common issues:
# 1. Config syntax error
promtool check config /etc/prometheus/prometheus.yml

# 2. Permission issues
sudo chown -R prometheus:prometheus /etc/prometheus
sudo chown -R prometheus:prometheus /var/lib/prometheus

# 3. Port already in use
sudo ss -lntp | grep :9090
```

#### Node Exporter Issues

```bash
# Check status
sudo systemctl status node_exporter --no-pager
sudo journalctl -u node_exporter -n 50

# Test metrics endpoint
curl http://localhost:9100/metrics

# Restart service
sudo systemctl restart node_exporter
```

#### Blackbox Exporter Issues

```bash
# Check status
sudo systemctl status blackbox_exporter --no-pager
sudo journalctl -u blackbox_exporter -n 50

# Validate config
cat /etc/blackbox_exporter/blackbox.yml

# Test probe
curl -v 'http://localhost:9115/probe?target=https://google.com&module=http_2xx'

# Restart service
sudo systemctl restart blackbox_exporter
```

#### Alertmanager Issues

```bash
# Check status
sudo systemctl status alertmanager --no-pager
sudo journalctl -u alertmanager -n 50

# Validate config
amtool check-config /etc/alertmanager/alertmanager.yml

# Test alertmanager API
curl http://localhost:9093/api/v1/status

# Restart service
sudo systemctl restart alertmanager
```

#### Grafana Issues

```bash
# Check status
sudo systemctl status grafana-server --no-pager
sudo journalctl -u grafana-server -n 50

# Check port
sudo ss -lntp | grep :3000

# Restart service
sudo systemctl restart grafana-server
```

### Targets Down in Prometheus

```bash
# Check target status
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | select(.health=="down")'

# Verify services are running
sudo systemctl status node_exporter blackbox_exporter

# Check firewall rules
sudo ufw status

# Test connectivity
curl -v http://localhost:9100/metrics
curl -v http://localhost:9115/metrics
```

### Alert Rules Not Firing

```bash
# Validate rules
promtool check rules /etc/prometheus/rules/*.yml

# Check rule evaluation
curl http://localhost:9090/api/v1/rules

# Force alert evaluation
curl -X POST http://localhost:9090/-/reload

# Check Alertmanager connection
curl http://localhost:9090/api/v1/alertmanagers
```

### High Memory Usage

```bash
# Check Prometheus memory
ps aux | grep prometheus

# Reduce retention
sudo nano /etc/systemd/system/prometheus.service
# Change: --storage.tsdb.retention.time=15d
sudo systemctl daemon-reload
sudo systemctl restart prometheus

# Clear old data
sudo rm -rf /var/lib/prometheus/data/old/
```

### Data Not Persisting After Restart

```bash
# Check data directory ownership
ls -la /var/lib/prometheus
sudo chown -R prometheus:prometheus /var/lib/prometheus

# Check systemd service user
grep User /etc/systemd/system/prometheus.service

# Verify retention settings
curl http://localhost:9090/api/v1/status/runtimeinfo | jq
```

---

## 🔒 Security Hardening

### 1. Firewall Configuration

```bash
# Allow only necessary ports
sudo ufw allow 22/tcp        # SSH
sudo ufw allow 9090/tcp      # Prometheus (restrict to internal network)
sudo ufw allow 3000/tcp      # Grafana (restrict to internal network)
sudo ufw deny 9100/tcp       # Node Exporter (internal only)
sudo ufw deny 9115/tcp       # Blackbox Exporter (internal only)
sudo ufw deny 9093/tcp       # Alertmanager (internal only)
sudo ufw enable
```

### 2. Enable Basic Auth for Prometheus

```bash
# Install apache2-utils
sudo apt-get install -y apache2-utils

# Create password file
htpasswd -c /etc/prometheus/.htpasswd admin

# Update prometheus.yml (add to web section)
# --web.config.file=/etc/prometheus/web.yml
```

### 3. TLS/HTTPS Setup

```bash
# Generate self-signed certificate
sudo openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -keyout /etc/prometheus/prometheus.key \
  -out /etc/prometheus/prometheus.crt

# Update systemd service to use TLS
# Add: --web.config.file=/etc/prometheus/web-config.yml
```

### 4. Restrict Network Access

```bash
# Edit systemd services to listen on localhost only
# Change: --web.listen-address=127.0.0.1:9090

# Use reverse proxy (Nginx/Apache) for external access
```

### 5. Regular Updates

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Check for new releases
# Prometheus: https://github.com/prometheus/prometheus/releases
# Grafana: sudo apt-get update && sudo apt-get upgrade grafana
```

---

## 📚 Additional Resources

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [Node Exporter](https://github.com/prometheus/node_exporter)
- [Blackbox Exporter](https://github.com/prometheus/blackbox_exporter)
- [Alertmanager](https://prometheus.io/docs/alerting/latest/alertmanager/)

---

## 📄 License

MIT License - See LICENSE file for details

---

## 🤝 Contributing

Contributions welcome! Please submit pull requests or open issues.

---

**Last Updated:** January 2026
