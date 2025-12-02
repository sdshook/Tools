<!-- EVMS (c) Shane D. Shook, 2025 All Rights Reserved -->
# EVMS Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the EVMS (Exposure and Vulnerability Management System) platform across different environments, from development to production.

## Prerequisites

### System Requirements

#### Minimum Requirements
- **CPU**: 8 cores (16 threads recommended)
- **RAM**: 16GB (32GB recommended for production)
- **Storage**: 100GB SSD (500GB+ for production)
- **Network**: 1Gbps connection
- **OS**: Ubuntu 20.04+ / CentOS 8+ / RHEL 8+

#### Recommended Production Requirements
- **CPU**: 16+ cores with AVX2 support
- **RAM**: 64GB+ 
- **Storage**: 1TB+ NVMe SSD with RAID 10
- **GPU**: NVIDIA GPU with 8GB+ VRAM (for GraphRL training)
- **Network**: 10Gbps connection with redundancy

### Software Dependencies

#### Core Dependencies
```bash
# Docker and Docker Compose
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Node.js 18+
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Python 3.9+ (for GraphRL)
sudo apt-get install -y python3.9 python3.9-pip python3.9-venv

# Git
sudo apt-get install -y git
```

#### Optional Dependencies
```bash
# Kubernetes (for production deployment)
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
echo "deb https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee -a /etc/apt/sources.list.d/kubernetes.list
sudo apt-get update
sudo apt-get install -y kubectl

# Helm (for Kubernetes deployments)
curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
sudo apt-get update
sudo apt-get install helm
```

## Deployment Options

### 1. Development Environment

#### Quick Start with Docker Compose
```bash
# Clone the repository
git clone <repository-url>
cd EVMS

# Copy environment configuration
cp .env.example .env

# Edit configuration (update passwords, URLs, etc.)
nano .env

# Start all services
docker-compose up -d

# Verify deployment
docker-compose ps
```

#### Manual Development Setup
```bash
# Install Node.js dependencies
npm install

# Set up Python environment for GraphRL
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Initialize databases
npm run db:init

# Start services individually
npm run start:orchestrator &
npm run start:agents &
npm run start:graphrl &
npm run start:dashboard &
```

### 2. Production Environment

#### Docker Swarm Deployment
```bash
# Initialize Docker Swarm
docker swarm init

# Create overlay network
docker network create --driver overlay evms-network

# Deploy stack
docker stack deploy -c docker-compose.prod.yml evms

# Scale services
docker service scale evms_agents=5
docker service scale evms_orchestrator=3
```

#### Kubernetes Deployment
```bash
# Create namespace
kubectl create namespace evms

# Apply configurations
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmaps/
kubectl apply -f k8s/secrets/
kubectl apply -f k8s/persistent-volumes/
kubectl apply -f k8s/services/
kubectl apply -f k8s/deployments/
kubectl apply -f k8s/ingress/

# Verify deployment
kubectl get pods -n evms
kubectl get services -n evms
```

#### Helm Chart Deployment
```bash
# Add EVMS Helm repository
helm repo add evms https://charts.evms.io
helm repo update

# Install EVMS
helm install evms evms/evms-platform \
  --namespace evms \
  --create-namespace \
  --values values.prod.yaml

# Upgrade deployment
helm upgrade evms evms/evms-platform \
  --namespace evms \
  --values values.prod.yaml
```

## Configuration

### Environment Variables

#### Core Configuration
```bash
# Application
NODE_ENV=production
PORT=3000
LOG_LEVEL=info

# Database URLs
NATS_URL=nats://nats-cluster:4222
GRAPH_DB_URL=bolt://neo4j-cluster:7687
REDIS_URL=redis://redis-cluster:6379

# Security
JWT_SECRET=<generate-strong-secret>
BCRYPT_ROUNDS=12
```

#### Production Security Configuration
```bash
# TLS/SSL Configuration
TLS_ENABLED=true
TLS_CERT_PATH=/etc/ssl/certs/evms.crt
TLS_KEY_PATH=/etc/ssl/private/evms.key
TLS_CA_PATH=/etc/ssl/certs/ca.crt

# Authentication
AUTH_PROVIDER=ldap
LDAP_URL=ldaps://ldap.company.com:636
LDAP_BIND_DN=cn=evms,ou=service,dc=company,dc=com
LDAP_BIND_PASSWORD=<ldap-password>
LDAP_SEARCH_BASE=ou=users,dc=company,dc=com

# Network Security
CORS_ORIGIN=https://evms.company.com
ALLOWED_IPS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
RATE_LIMIT_ENABLED=true
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=100
```

### Database Configuration

#### Neo4j Production Setup
```yaml
# neo4j.conf
dbms.default_listen_address=0.0.0.0
dbms.connector.bolt.listen_address=:7687
dbms.connector.http.listen_address=:7474

# Memory settings
dbms.memory.heap.initial_size=4G
dbms.memory.heap.max_size=8G
dbms.memory.pagecache.size=4G

# Security
dbms.security.auth_enabled=true
dbms.security.procedures.unrestricted=apoc.*,gds.*

# Clustering (for HA)
causal_clustering.minimum_core_cluster_size_at_formation=3
causal_clustering.initial_discovery_members=neo4j-1:5000,neo4j-2:5000,neo4j-3:5000
```

#### NATS JetStream Configuration
```yaml
# nats-server.conf
jetstream: {
  store_dir: "/data/jetstream"
  max_memory_store: 4GB
  max_file_store: 100GB
}

cluster: {
  name: evms-cluster
  listen: 0.0.0.0:6222
  routes: [
    nats://nats-1:6222
    nats://nats-2:6222
    nats://nats-3:6222
  ]
}

accounts: {
  EVMS: {
    jetstream: enabled
    users: [
      {user: evms_orchestrator, password: <password>}
      {user: evms_agents, password: <password>}
      {user: evms_graphrl, password: <password>}
    ]
  }
}
```

## High Availability Setup

### Load Balancing

#### Nginx Configuration
```nginx
upstream evms_orchestrator {
    least_conn;
    server orchestrator-1:3000 max_fails=3 fail_timeout=30s;
    server orchestrator-2:3000 max_fails=3 fail_timeout=30s;
    server orchestrator-3:3000 max_fails=3 fail_timeout=30s;
}

upstream evms_dashboard {
    least_conn;
    server dashboard-1:3001 max_fails=3 fail_timeout=30s;
    server dashboard-2:3001 max_fails=3 fail_timeout=30s;
}

server {
    listen 443 ssl http2;
    server_name evms.company.com;
    
    ssl_certificate /etc/ssl/certs/evms.crt;
    ssl_certificate_key /etc/ssl/private/evms.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    
    location /api/ {
        proxy_pass http://evms_orchestrator;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location / {
        proxy_pass http://evms_dashboard;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /ws/ {
        proxy_pass http://evms_orchestrator;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

### Database Clustering

#### Neo4j Causal Cluster
```yaml
# docker-compose.cluster.yml
version: '3.8'
services:
  neo4j-core-1:
    image: neo4j:5.12-enterprise
    environment:
      - NEO4J_AUTH=neo4j/password
      - NEO4J_causal__clustering_minimum__core__cluster__size__at__formation=3
      - NEO4J_causal__clustering_initial__discovery__members=neo4j-core-1:5000,neo4j-core-2:5000,neo4j-core-3:5000
      - NEO4J_dbms_mode=CORE
    ports:
      - "7474:7474"
      - "7687:7687"
    volumes:
      - neo4j-core-1-data:/data
    networks:
      - evms-cluster

  neo4j-core-2:
    image: neo4j:5.12-enterprise
    environment:
      - NEO4J_AUTH=neo4j/password
      - NEO4J_causal__clustering_minimum__core__cluster__size__at__formation=3
      - NEO4J_causal__clustering_initial__discovery__members=neo4j-core-1:5000,neo4j-core-2:5000,neo4j-core-3:5000
      - NEO4J_dbms_mode=CORE
    volumes:
      - neo4j-core-2-data:/data
    networks:
      - evms-cluster

  neo4j-core-3:
    image: neo4j:5.12-enterprise
    environment:
      - NEO4J_AUTH=neo4j/password
      - NEO4J_causal__clustering_minimum__core__cluster__size__at__formation=3
      - NEO4J_causal__clustering_initial__discovery__members=neo4j-core-1:5000,neo4j-core-2:5000,neo4j-core-3:5000
      - NEO4J_dbms_mode=CORE
    volumes:
      - neo4j-core-3-data:/data
    networks:
      - evms-cluster
```

#### Redis Cluster
```yaml
redis-cluster:
  image: redis:7.2-alpine
  command: redis-cli --cluster create redis-1:6379 redis-2:6379 redis-3:6379 redis-4:6379 redis-5:6379 redis-6:6379 --cluster-replicas 1 --cluster-yes
  depends_on:
    - redis-1
    - redis-2
    - redis-3
    - redis-4
    - redis-5
    - redis-6
```

## Monitoring and Observability

### Prometheus Configuration
```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "evms_rules.yml"

scrape_configs:
  - job_name: 'evms-orchestrator'
    static_configs:
      - targets: ['orchestrator:3000']
    metrics_path: '/metrics'
    scrape_interval: 10s

  - job_name: 'evms-agents'
    static_configs:
      - targets: ['agents:3000']
    metrics_path: '/metrics'
    scrape_interval: 10s

  - job_name: 'evms-graphrl'
    static_configs:
      - targets: ['graphrl:8000']
    metrics_path: '/metrics'
    scrape_interval: 30s

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

### Grafana Dashboards
```json
{
  "dashboard": {
    "title": "EVMS Platform Overview",
    "panels": [
      {
        "title": "Active Scans",
        "type": "stat",
        "targets": [
          {
            "expr": "evms_active_scans_total",
            "legendFormat": "Active Scans"
          }
        ]
      },
      {
        "title": "Vulnerabilities Detected",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(evms_vulnerabilities_detected_total[5m])",
            "legendFormat": "Detection Rate"
          }
        ]
      },
      {
        "title": "GraphRL Performance",
        "type": "graph",
        "targets": [
          {
            "expr": "evms_graphrl_reward_average",
            "legendFormat": "Average Reward"
          }
        ]
      }
    ]
  }
}
```

## Security Hardening

### Container Security
```dockerfile
# Use non-root user
FROM node:18-alpine
RUN addgroup -g 1001 -S evms && adduser -S evms -u 1001
USER evms

# Security scanning
RUN apk add --no-cache dumb-init
ENTRYPOINT ["dumb-init", "--"]

# Read-only filesystem
VOLUME ["/tmp", "/var/log"]
```

### Network Security
```yaml
# Network policies for Kubernetes
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: evms-network-policy
  namespace: evms
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: evms
    ports:
    - protocol: TCP
      port: 3000
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: evms
    ports:
    - protocol: TCP
      port: 4222
    - protocol: TCP
      port: 7687
    - protocol: TCP
      port: 6379
```

### Secrets Management
```bash
# Using Kubernetes secrets
kubectl create secret generic evms-secrets \
  --from-literal=jwt-secret=<jwt-secret> \
  --from-literal=db-password=<db-password> \
  --from-literal=redis-password=<redis-password> \
  --namespace evms

# Using HashiCorp Vault
vault kv put secret/evms \
  jwt_secret=<jwt-secret> \
  db_password=<db-password> \
  redis_password=<redis-password>
```

## Backup and Recovery

### Database Backup
```bash
#!/bin/bash
# backup-script.sh

# Neo4j backup
docker exec evms-neo4j neo4j-admin backup \
  --backup-dir=/backups \
  --name=graph-$(date +%Y%m%d-%H%M%S) \
  --database=evms

# Redis backup
docker exec evms-redis redis-cli BGSAVE
docker cp evms-redis:/data/dump.rdb ./backups/redis-$(date +%Y%m%d-%H%M%S).rdb

# Upload to S3
aws s3 sync ./backups s3://evms-backups/$(date +%Y/%m/%d)/
```

### Disaster Recovery
```bash
#!/bin/bash
# restore-script.sh

# Restore Neo4j
docker exec evms-neo4j neo4j-admin restore \
  --from=/backups/graph-20231201-120000 \
  --database=evms \
  --force

# Restore Redis
docker cp ./backups/redis-20231201-120000.rdb evms-redis:/data/dump.rdb
docker restart evms-redis
```

## Performance Tuning

### JVM Tuning (Neo4j)
```bash
# Neo4j JVM settings
-Xms8g
-Xmx8g
-XX:+UseG1GC
-XX:+UnlockExperimentalVMOptions
-XX:+UseTransparentHugePages
-XX:G1HeapRegionSize=16m
```

### Node.js Tuning
```bash
# Node.js performance settings
export NODE_OPTIONS="--max-old-space-size=4096 --optimize-for-size"
export UV_THREADPOOL_SIZE=128
```

### System Tuning
```bash
# Linux kernel parameters
echo 'vm.max_map_count=262144' >> /etc/sysctl.conf
echo 'fs.file-max=65536' >> /etc/sysctl.conf
echo 'net.core.somaxconn=65535' >> /etc/sysctl.conf
sysctl -p
```

## Troubleshooting

### Common Issues

#### Service Discovery Problems
```bash
# Check NATS connectivity
nats-cli server check --server=nats://localhost:4222

# Verify service registration
nats-cli stream ls
nats-cli consumer ls <stream-name>
```

#### Database Connection Issues
```bash
# Test Neo4j connection
cypher-shell -a bolt://localhost:7687 -u neo4j -p password "RETURN 1"

# Check Redis connectivity
redis-cli -h localhost -p 6379 ping
```

#### Performance Issues
```bash
# Monitor resource usage
docker stats
kubectl top pods -n evms

# Check application logs
docker logs evms-orchestrator
kubectl logs -f deployment/evms-orchestrator -n evms
```

### Log Analysis
```bash
# Centralized logging with ELK
curl -X GET "elasticsearch:9200/_cat/indices?v"
curl -X GET "elasticsearch:9200/evms-logs-*/_search?q=level:ERROR"
```

## Maintenance

### Regular Maintenance Tasks
```bash
#!/bin/bash
# maintenance.sh

# Update vulnerability databases
curl -o cve-data.xml https://cve.mitre.org/data/downloads/allitems.xml
docker exec evms-orchestrator npm run update:cve-database

# Clean up old logs
find /var/log/evms -name "*.log" -mtime +30 -delete

# Optimize databases
docker exec evms-neo4j cypher-shell "CALL db.indexes()"
docker exec evms-redis redis-cli MEMORY PURGE

# Update Docker images
docker-compose pull
docker-compose up -d
```

### Health Checks
```bash
#!/bin/bash
# health-check.sh

# Check service health
curl -f http://localhost:3000/health || exit 1
curl -f http://localhost:3001/health || exit 1

# Check database connectivity
timeout 5 bash -c "</dev/tcp/localhost/7687" || exit 1
timeout 5 bash -c "</dev/tcp/localhost/6379" || exit 1
timeout 5 bash -c "</dev/tcp/localhost/4222" || exit 1

echo "All services healthy"
```

This deployment guide provides comprehensive instructions for setting up EVMS in various environments with proper security, monitoring, and maintenance procedures.