<!-- EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved -->
# EVMS Project Structure

## Directory Layout

```
EVMS/
├── README.md                    # Main project documentation
├── ARCHITECTURE.md              # Detailed architecture documentation
├── GRAPHRL_DESIGN.md           # GraphRL implementation details
├── DEPLOYMENT.md               # Deployment and operations guide
├── PROJECT_STRUCTURE.md        # This file
├── package.json                # Node.js dependencies and scripts
├── docker-compose.yml          # Development environment setup
├── .env.example               # Environment configuration template
├── .gitignore                 # Git ignore patterns
├── .eslintrc.js              # ESLint configuration
├── .prettierrc               # Prettier configuration
├── jest.config.js            # Jest testing configuration
├── webpack.config.js         # Webpack build configuration
├── Dockerfile                # Main application container
├── Dockerfile.orchestrator   # Orchestrator service container
├── Dockerfile.agents         # Agents service container
├── Dockerfile.graphrl        # GraphRL service container
├── Dockerfile.dashboard      # Dashboard service container
├── requirements.txt          # Python dependencies for GraphRL
├── pyproject.toml           # Python project configuration
├── LICENSE                  # Project license
├── CHANGELOG.md            # Version history and changes
├── CONTRIBUTING.md         # Contribution guidelines
├── SECURITY.md            # Security policy and reporting
├── CODE_OF_CONDUCT.md     # Community guidelines
│
├── src/                   # Source code
│   ├── index.js          # Main application entry point
│   ├── config/           # Configuration management
│   │   ├── index.js      # Configuration loader
│   │   ├── database.js   # Database configurations
│   │   ├── nats.js       # NATS messaging configuration
│   │   ├── security.js   # Security settings
│   │   └── logging.js    # Logging configuration
│   │
│   ├── services/         # Core services
│   │   ├── orchestrator/ # Central coordination service
│   │   │   ├── index.js
│   │   │   ├── taskManager.js
│   │   │   ├── agentManager.js
│   │   │   ├── scheduler.js
│   │   │   └── api/
│   │   │       ├── routes/
│   │   │       ├── controllers/
│   │   │       └── middleware/
│   │   │
│   │   ├── agents/       # Scanning agents
│   │   │   ├── index.js
│   │   │   ├── base/
│   │   │   │   ├── BaseAgent.js
│   │   │   │   ├── AgentPool.js
│   │   │   │   └── AgentRegistry.js
│   │   │   ├── vulnerability/
│   │   │   │   ├── VulnScanner.js
│   │   │   │   ├── CVECorrelator.js
│   │   │   │   └── ExploitChecker.js
│   │   │   ├── discovery/
│   │   │   │   ├── NetworkDiscovery.js
│   │   │   │   ├── ServiceEnumeration.js
│   │   │   │   └── AssetInventory.js
│   │   │   ├── configuration/
│   │   │   │   ├── ConfigAuditor.js
│   │   │   │   ├── ComplianceChecker.js
│   │   │   │   └── PolicyValidator.js
│   │   │   └── intelligence/
│   │   │       ├── ThreatIntel.js
│   │   │       ├── IOCMatcher.js
│   │   │       └── ThreatHunter.js
│   │   │
│   │   ├── graphrl/      # Graph Reinforcement Learning
│   │   │   ├── agent.py
│   │   │   ├── environment.py
│   │   │   ├── models/
│   │   │   │   ├── graph_dqn.py
│   │   │   │   ├── graph_encoder.py
│   │   │   │   └── reward_calculator.py
│   │   │   ├── training/
│   │   │   │   ├── trainer.py
│   │   │   │   ├── replay_buffer.py
│   │   │   │   └── curriculum.py
│   │   │   └── utils/
│   │   │       ├── graph_utils.py
│   │   │       ├── metrics.py
│   │   │       └── visualization.py
│   │   │
│   │   ├── hotl/         # Human-On-The-Loop interface
│   │   │   ├── index.js
│   │   │   ├── reviewManager.js
│   │   │   ├── feedbackCollector.js
│   │   │   ├── approvalWorkflow.js
│   │   │   └── notifications/
│   │   │       ├── emailNotifier.js
│   │   │       ├── slackNotifier.js
│   │   │       └── webhookNotifier.js
│   │   │
│   │   └── dashboard/    # Web dashboard and UI
│   │       ├── server.js
│   │       ├── api/
│   │       ├── websocket/
│   │       ├── static/
│   │       └── templates/
│   │
│   ├── data/             # Data access layer
│   │   ├── repositories/ # Data repositories
│   │   │   ├── AssetRepository.js
│   │   │   ├── VulnerabilityRepository.js
│   │   │   ├── ScanRepository.js
│   │   │   └── RiskRepository.js
│   │   ├── models/       # Data models
│   │   │   ├── Asset.js
│   │   │   ├── Vulnerability.js
│   │   │   ├── Scan.js
│   │   │   ├── Risk.js
│   │   │   └── User.js
│   │   ├── graph/        # Graph database operations
│   │   │   ├── GraphDB.js
│   │   │   ├── queries/
│   │   │   └── migrations/
│   │   ├── cache/        # Caching layer
│   │   │   ├── RedisCache.js
│   │   │   └── CacheManager.js
│   │   └── messaging/    # Message handling
│   │       ├── NATSClient.js
│   │       ├── MessageBus.js
│   │       └── EventHandlers.js
│   │
│   ├── ml/               # Machine Learning components
│   │   ├── features/     # Feature engineering
│   │   │   ├── FeatureExtractor.js
│   │   │   ├── GraphFeatures.py
│   │   │   └── TemporalFeatures.py
│   │   ├── models/       # ML models
│   │   │   ├── RiskScorer.py
│   │   │   ├── AnomalyDetector.py
│   │   │   └── PriorityRanker.py
│   │   ├── training/     # Training pipelines
│   │   │   ├── DataPipeline.py
│   │   │   ├── ModelTrainer.py
│   │   │   └── Evaluator.py
│   │   └── inference/    # Model serving
│   │       ├── ModelServer.py
│   │       ├── PredictionAPI.py
│   │       └── BatchPredictor.py
│   │
│   ├── utils/            # Utility functions
│   │   ├── logger.js     # Logging utilities
│   │   ├── crypto.js     # Cryptographic functions
│   │   ├── validation.js # Input validation
│   │   ├── errors.js     # Error handling
│   │   ├── metrics.js    # Metrics collection
│   │   └── helpers.js    # General helpers
│   │
│   └── integrations/     # External integrations
│       ├── cve/          # CVE database integration
│       │   ├── CVEClient.js
│       │   ├── NVDClient.js
│       │   └── MITREClient.js
│       ├── threat-intel/ # Threat intelligence feeds
│       │   ├── ThreatIntelClient.js
│       │   ├── OTXClient.js
│       │   └── VirusTotalClient.js
│       ├── scanners/     # External scanner integrations
│       │   ├── NmapWrapper.js
│       │   ├── OpenVASWrapper.js
│       │   └── NessusWrapper.js
│       ├── compliance/   # Compliance frameworks
│       │   ├── CISBenchmarks.js
│       │   ├── NISTFramework.js
│       │   └── ISO27001.js
│       └── notifications/# Notification services
│           ├── EmailService.js
│           ├── SlackService.js
│           └── PagerDutyService.js
│
├── docs/                 # Documentation
│   ├── api/             # API documentation
│   │   ├── openapi.yaml
│   │   ├── postman/
│   │   └── examples/
│   ├── guides/          # User guides
│   │   ├── getting-started.md
│   │   ├── user-manual.md
│   │   ├── admin-guide.md
│   │   └── troubleshooting.md
│   ├── development/     # Development documentation
│   │   ├── setup.md
│   │   ├── coding-standards.md
│   │   ├── testing.md
│   │   └── debugging.md
│   ├── architecture/    # Architecture documentation
│   │   ├── system-design.md
│   │   ├── data-flow.md
│   │   ├── security.md
│   │   └── scalability.md
│   └── images/          # Documentation images
│       ├── architecture-diagram.png
│       ├── data-flow.png
│       └── ui-screenshots/
│
├── config/              # Configuration files
│   ├── default.json     # Default configuration
│   ├── development.json # Development environment
│   ├── production.json  # Production environment
│   ├── test.json       # Test environment
│   ├── database/       # Database configurations
│   │   ├── neo4j.conf
│   │   ├── redis.conf
│   │   └── migrations/
│   ├── nats/           # NATS configurations
│   │   ├── nats-server.conf
│   │   └── jetstream.conf
│   └── security/       # Security configurations
│       ├── tls/
│       ├── auth/
│       └── policies/
│
├── scripts/             # Utility scripts
│   ├── setup.sh        # Environment setup
│   ├── build.sh        # Build script
│   ├── deploy.sh       # Deployment script
│   ├── backup.sh       # Backup script
│   ├── restore.sh      # Restore script
│   ├── init-database.js # Database initialization
│   ├── migrate.js      # Database migration
│   ├── seed.js         # Test data seeding
│   ├── update-cve.js   # CVE database update
│   └── health-check.sh # Health check script
│
├── tests/               # Test files
│   ├── unit/           # Unit tests
│   │   ├── services/
│   │   ├── data/
│   │   ├── utils/
│   │   └── integrations/
│   ├── integration/    # Integration tests
│   │   ├── api/
│   │   ├── database/
│   │   └── messaging/
│   ├── e2e/           # End-to-end tests
│   │   ├── scenarios/
│   │   ├── fixtures/
│   │   └── helpers/
│   ├── performance/   # Performance tests
│   │   ├── load/
│   │   ├── stress/
│   │   └── benchmarks/
│   ├── security/      # Security tests
│   │   ├── penetration/
│   │   ├── vulnerability/
│   │   └── compliance/
│   └── fixtures/      # Test data
│       ├── assets.json
│       ├── vulnerabilities.json
│       └── scans.json
│
├── k8s/                # Kubernetes manifests
│   ├── namespace.yaml
│   ├── configmaps/
│   │   ├── app-config.yaml
│   │   ├── database-config.yaml
│   │   └── nats-config.yaml
│   ├── secrets/
│   │   ├── app-secrets.yaml
│   │   ├── database-secrets.yaml
│   │   └── tls-secrets.yaml
│   ├── persistent-volumes/
│   │   ├── neo4j-pv.yaml
│   │   ├── redis-pv.yaml
│   │   └── nats-pv.yaml
│   ├── services/
│   │   ├── orchestrator-service.yaml
│   │   ├── dashboard-service.yaml
│   │   └── database-services.yaml
│   ├── deployments/
│   │   ├── orchestrator-deployment.yaml
│   │   ├── agents-deployment.yaml
│   │   ├── graphrl-deployment.yaml
│   │   ├── dashboard-deployment.yaml
│   │   └── database-deployments.yaml
│   ├── ingress/
│   │   ├── evms-ingress.yaml
│   │   └── tls-ingress.yaml
│   ├── rbac/
│   │   ├── service-accounts.yaml
│   │   ├── roles.yaml
│   │   └── role-bindings.yaml
│   ├── network-policies/
│   │   ├── default-deny.yaml
│   │   ├── app-network-policy.yaml
│   │   └── database-network-policy.yaml
│   └── helm/           # Helm charts
│       ├── Chart.yaml
│       ├── values.yaml
│       ├── values-prod.yaml
│       └── templates/
│
├── monitoring/         # Monitoring and observability
│   ├── prometheus/
│   │   ├── prometheus.yml
│   │   ├── rules/
│   │   └── alerts/
│   ├── grafana/
│   │   ├── dashboards/
│   │   ├── provisioning/
│   │   └── plugins/
│   ├── jaeger/
│   │   ├── jaeger-config.yaml
│   │   └── sampling-strategies.json
│   ├── elasticsearch/
│   │   ├── elasticsearch.yml
│   │   ├── index-templates/
│   │   └── pipelines/
│   └── kibana/
│       ├── kibana.yml
│       ├── dashboards/
│       └── visualizations/
│
├── data/               # Data files (not in version control)
│   ├── models/         # Trained ML models
│   ├── logs/          # Application logs
│   ├── backups/       # Database backups
│   ├── uploads/       # Uploaded files
│   └── cache/         # Cached data
│
├── tools/             # Development tools
│   ├── generators/    # Code generators
│   ├── linters/       # Custom linters
│   ├── formatters/    # Code formatters
│   └── analyzers/     # Code analyzers
│
└── examples/          # Example configurations and usage
    ├── configurations/
    ├── integrations/
    ├── workflows/
    └── tutorials/
```

## Key Components Description

### Core Services

#### Orchestrator Service (`src/services/orchestrator/`)
- Central coordination hub for all EVMS operations
- Task scheduling and distribution
- Agent lifecycle management
- API gateway for external interactions
- Real-time dashboard data aggregation

#### Agents Service (`src/services/agents/`)
- Distributed scanning agents
- Vulnerability assessment engines
- Asset discovery and enumeration
- Configuration auditing
- Threat intelligence correlation

#### GraphRL Service (`src/services/graphrl/`)
- Graph-based reinforcement learning engine
- Risk scoring and prioritization
- Autonomous decision making
- Continuous learning from feedback
- Action recommendation system

#### HOTL Service (`src/services/hotl/`)
- Human-on-the-loop interface
- Review and approval workflows
- Feedback collection and processing
- Notification and alerting system
- Override and escalation handling

#### Dashboard Service (`src/services/dashboard/`)
- Web-based user interface
- Real-time data visualization
- Interactive chat interface
- Report generation and export
- User management and authentication

### Data Layer

#### Repositories (`src/data/repositories/`)
- Data access abstraction layer
- CRUD operations for all entities
- Query optimization and caching
- Transaction management
- Data validation and sanitization

#### Graph Database (`src/data/graph/`)
- Neo4j integration and management
- Graph query optimization
- Relationship modeling
- Schema migration and versioning
- Performance monitoring

#### Messaging (`src/data/messaging/`)
- NATS JetStream integration
- Event-driven architecture
- Message routing and filtering
- Fault tolerance and retry logic
- Stream processing and aggregation

### Machine Learning

#### GraphRL (`src/ml/`)
- Deep reinforcement learning models
- Graph neural network architectures
- Feature engineering pipelines
- Model training and evaluation
- Inference and prediction services

### Configuration Management

#### Environment Configs (`config/`)
- Environment-specific settings
- Database connection strings
- Security configurations
- Feature flags and toggles
- Performance tuning parameters

### Deployment and Operations

#### Kubernetes (`k8s/`)
- Container orchestration manifests
- Service discovery and networking
- Persistent storage management
- Security policies and RBAC
- Auto-scaling and resource management

#### Monitoring (`monitoring/`)
- Metrics collection and alerting
- Log aggregation and analysis
- Distributed tracing
- Performance monitoring
- Health checks and diagnostics

### Development and Testing

#### Tests (`tests/`)
- Comprehensive test suites
- Unit, integration, and E2E tests
- Performance and security testing
- Test data and fixtures
- Continuous integration support

#### Scripts (`scripts/`)
- Automation and utility scripts
- Database management tools
- Deployment and maintenance scripts
- Data migration utilities
- Health check and monitoring tools

## File Naming Conventions

### JavaScript/Node.js Files
- **PascalCase** for classes: `AssetRepository.js`, `VulnerabilityScanner.js`
- **camelCase** for functions and variables: `taskManager.js`, `agentPool.js`
- **kebab-case** for configuration files: `database-config.js`, `security-settings.js`

### Python Files
- **snake_case** for all Python files: `graph_dqn.py`, `reward_calculator.py`
- **PascalCase** for class names within files
- **UPPER_CASE** for constants and environment variables

### Configuration Files
- **kebab-case** for YAML/JSON configs: `app-config.yaml`, `database-secrets.yaml`
- **snake_case** for Python configs: `model_config.py`, `training_params.py`
- **camelCase** for JavaScript configs: `defaultConfig.js`, `productionConfig.js`

### Documentation
- **kebab-case** for markdown files: `getting-started.md`, `api-reference.md`
- **UPPERCASE** for important docs: `README.md`, `LICENSE`, `CHANGELOG.md`

## Development Workflow

### Branch Strategy
```
main                    # Production-ready code
├── develop            # Integration branch
├── feature/           # Feature development
│   ├── graphrl-improvements
│   ├── hotl-interface
│   └── dashboard-redesign
├── hotfix/           # Critical fixes
│   └── security-patch
└── release/          # Release preparation
    └── v1.2.0
```

### Code Organization Principles

1. **Separation of Concerns**: Each module has a single responsibility
2. **Dependency Injection**: Services are loosely coupled through interfaces
3. **Configuration Management**: All settings externalized and environment-specific
4. **Error Handling**: Comprehensive error handling and logging throughout
5. **Security First**: Security considerations integrated at every layer
6. **Testability**: Code designed for easy unit and integration testing
7. **Scalability**: Architecture supports horizontal and vertical scaling
8. **Observability**: Comprehensive monitoring, logging, and tracing built-in

This structure provides a solid foundation for building, maintaining, and scaling the EVMS platform while ensuring code quality, security, and operational excellence.