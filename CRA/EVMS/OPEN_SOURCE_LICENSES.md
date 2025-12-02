<!-- EVMS (c) Shane D. Shook, 2025 All Rights Reserved -->
# Open Source Licenses and Attributions

EVMS leverages several outstanding open-source projects. We are grateful to the maintainers and contributors of these projects and ensure full compliance with their respective licenses.

## Core Security Tools

### Masscan
- **Repository**: https://github.com/robertdavidgraham/masscan
- **License**: AGPL v3
- **Author**: Robert David Graham
- **Description**: Ultra-fast network discovery and port scanner
- **Usage in EVMS**: Active network discovery and asset enumeration
- **License Compliance**: EVMS complies with AGPL v3 requirements by making source code available

### Nuclei
- **Repository**: https://github.com/projectdiscovery/nuclei
- **License**: MIT
- **Author**: ProjectDiscovery Team
- **Description**: Fast and customizable vulnerability scanner
- **Usage in EVMS**: Template-based vulnerability assessment
- **License Compliance**: MIT license allows commercial use with attribution

### Zeek (formerly Bro)
- **Repository**: https://github.com/zeek/zeek
- **License**: BSD 3-Clause
- **Author**: The Zeek Project
- **Description**: Network security monitoring platform
- **Usage in EVMS**: Passive network monitoring and protocol analysis
- **License Compliance**: BSD license allows commercial use with attribution

## Infrastructure Components

### NATS Server
- **Repository**: https://github.com/nats-io/nats-server
- **License**: Apache 2.0
- **Author**: NATS.io Team
- **Description**: High-performance messaging system
- **Usage in EVMS**: Event bus and message streaming
- **License Compliance**: Apache 2.0 allows commercial use with attribution

### Neo4j Community Edition
- **Repository**: https://github.com/neo4j/neo4j
- **License**: GPL v3
- **Author**: Neo4j, Inc.
- **Description**: Graph database platform
- **Usage in EVMS**: Asset relationship modeling and graph analytics
- **License Compliance**: GPL v3 compliance through open-source distribution

### Redis
- **Repository**: https://github.com/redis/redis
- **License**: BSD 3-Clause (versions ≤ 7.0)
- **Author**: Redis Ltd.
- **Description**: In-memory data structure store
- **Usage in EVMS**: Caching and session storage
- **License Compliance**: BSD license allows commercial use with attribution

## Machine Learning and AI

### PyTorch
- **Repository**: https://github.com/pytorch/pytorch
- **License**: BSD 3-Clause
- **Author**: Meta Platforms, Inc.
- **Description**: Machine learning framework
- **Usage in EVMS**: GraphRL implementation and neural networks
- **License Compliance**: BSD license allows commercial use with attribution

### PyTorch Geometric
- **Repository**: https://github.com/pyg-team/pytorch_geometric
- **License**: MIT
- **Author**: PyG Team
- **Description**: Graph neural network library
- **Usage in EVMS**: Graph-based machine learning models
- **License Compliance**: MIT license allows commercial use with attribution

### Transformers (Hugging Face)
- **Repository**: https://github.com/huggingface/transformers
- **License**: Apache 2.0
- **Author**: Hugging Face Team
- **Description**: Natural language processing models
- **Usage in EVMS**: LLM integration for chat interface
- **License Compliance**: Apache 2.0 allows commercial use with attribution

## Development and Runtime

### Node.js
- **Repository**: https://github.com/nodejs/node
- **License**: MIT
- **Author**: Node.js Foundation
- **Description**: JavaScript runtime environment
- **Usage in EVMS**: Application runtime and service orchestration
- **License Compliance**: MIT license allows commercial use with attribution

### Express.js
- **Repository**: https://github.com/expressjs/express
- **License**: MIT
- **Author**: TJ Holowaychuk and Express.js Team
- **Description**: Web application framework
- **Usage in EVMS**: REST API and web service framework
- **License Compliance**: MIT license allows commercial use with attribution

### Python
- **Repository**: https://github.com/python/cpython
- **License**: Python Software Foundation License
- **Author**: Python Software Foundation
- **Description**: Programming language
- **Usage in EVMS**: Machine learning and data processing components
- **License Compliance**: PSF license allows commercial use

## Monitoring and Observability

### Prometheus
- **Repository**: https://github.com/prometheus/prometheus
- **License**: Apache 2.0
- **Author**: Prometheus Authors
- **Description**: Monitoring and alerting toolkit
- **Usage in EVMS**: Metrics collection and monitoring
- **License Compliance**: Apache 2.0 allows commercial use with attribution

### Grafana
- **Repository**: https://github.com/grafana/grafana
- **License**: AGPL v3
- **Author**: Grafana Labs
- **Description**: Analytics and monitoring platform
- **Usage in EVMS**: Data visualization and dashboards
- **License Compliance**: AGPL v3 compliance through open-source distribution

### Jaeger
- **Repository**: https://github.com/jaegertracing/jaeger
- **License**: Apache 2.0
- **Author**: Jaeger Authors
- **Description**: Distributed tracing system
- **Usage in EVMS**: Request tracing and performance monitoring
- **License Compliance**: Apache 2.0 allows commercial use with attribution

## Vector Databases and RAG

### Qdrant
- **Repository**: https://github.com/qdrant/qdrant
- **License**: Apache 2.0
- **Author**: Qdrant Team
- **Description**: Vector similarity search engine
- **Usage in EVMS**: Vector storage for RAG implementation
- **License Compliance**: Apache 2.0 allows commercial use with attribution

### LangChain
- **Repository**: https://github.com/langchain-ai/langchain
- **License**: MIT
- **Author**: LangChain Team
- **Description**: Framework for developing LLM applications
- **Usage in EVMS**: RAG pipeline and LLM orchestration
- **License Compliance**: MIT license allows commercial use with attribution

## Container and Orchestration

### Docker
- **Repository**: https://github.com/moby/moby
- **License**: Apache 2.0
- **Author**: Docker, Inc.
- **Description**: Container platform
- **Usage in EVMS**: Application containerization and deployment
- **License Compliance**: Apache 2.0 allows commercial use with attribution

### Kubernetes
- **Repository**: https://github.com/kubernetes/kubernetes
- **License**: Apache 2.0
- **Author**: The Kubernetes Authors
- **Description**: Container orchestration platform
- **Usage in EVMS**: Production deployment and scaling
- **License Compliance**: Apache 2.0 allows commercial use with attribution

## Testing and Development Tools

### Jest
- **Repository**: https://github.com/facebook/jest
- **License**: MIT
- **Author**: Meta Platforms, Inc.
- **Description**: JavaScript testing framework
- **Usage in EVMS**: Unit and integration testing
- **License Compliance**: MIT license allows commercial use with attribution

### ESLint
- **Repository**: https://github.com/eslint/eslint
- **License**: MIT
- **Author**: ESLint Team
- **Description**: JavaScript linting utility
- **Usage in EVMS**: Code quality and style enforcement
- **License Compliance**: MIT license allows commercial use with attribution

### Pytest
- **Repository**: https://github.com/pytest-dev/pytest
- **License**: MIT
- **Author**: Pytest Development Team
- **Description**: Python testing framework
- **Usage in EVMS**: Python component testing
- **License Compliance**: MIT license allows commercial use with attribution

## License Compliance Statement

EVMS is committed to full compliance with all open-source licenses. We:

1. **Maintain Attribution**: All required copyright notices and attributions are preserved
2. **Respect Copyleft**: GPL and AGPL components are handled according to their license terms
3. **Provide Source Access**: Source code is made available as required by copyleft licenses
4. **Document Dependencies**: All dependencies and their licenses are clearly documented
5. **Regular Audits**: We regularly audit our dependencies for license compliance

## Contributing Back

EVMS actively contributes back to the open-source community through:

- **Bug Reports**: Reporting issues found during integration and testing
- **Feature Contributions**: Contributing enhancements and new features
- **Documentation**: Improving documentation and examples
- **Security Research**: Sharing security findings and improvements
- **Templates and Scripts**: Contributing Nuclei templates and Zeek scripts

## License Compatibility Matrix

| Component | License | Commercial Use | Modification | Distribution | Patent Grant |
|-----------|---------|----------------|--------------|--------------|--------------|
| Masscan | AGPL v3 | ✓* | ✓ | ✓* | ✗ |
| Nuclei | MIT | ✓ | ✓ | ✓ | ✗ |
| Zeek | BSD 3-Clause | ✓ | ✓ | ✓ | ✗ |
| NATS | Apache 2.0 | ✓ | ✓ | ✓ | ✓ |
| Neo4j CE | GPL v3 | ✓* | ✓ | ✓* | ✗ |
| Redis | BSD 3-Clause | ✓ | ✓ | ✓ | ✗ |
| PyTorch | BSD 3-Clause | ✓ | ✓ | ✓ | ✗ |
| Node.js | MIT | ✓ | ✓ | ✓ | ✗ |

*Requires source code availability for derivative works

## Contact

For questions about license compliance or to report license-related issues:

- **Email**: legal@evms-project.org
- **GitHub Issues**: Use the "license" label
- **Documentation**: See individual component documentation for specific license terms

## Acknowledgments

We extend our gratitude to all open-source maintainers and contributors whose work makes EVMS possible. The cybersecurity community's collaborative spirit drives innovation and helps protect organizations worldwide.

---

*This document is maintained to ensure accurate license compliance. Last updated: December 2024*