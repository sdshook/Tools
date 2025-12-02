<!-- EVMS (c) Shane D. Shook, 2025 All Rights Reserved -->
# Changelog

All notable changes to the EVMS (Exposure and Vulnerability Management System) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project structure and documentation
- Core architecture design documents
- GraphRL implementation framework
- NATS.io and JetStream integration
- Docker containerization setup
- Kubernetes deployment manifests
- Monitoring and observability stack
- Comprehensive testing framework

### Changed
- N/A

### Deprecated
- N/A

### Removed
- N/A

### Fixed
- N/A

### Security
- Implemented secure-by-default configuration
- Added comprehensive input validation
- Configured security-focused ESLint rules
- Implemented proper authentication and authorization framework

## [1.0.0] - 2025-12-02

### Added
- Initial release of EVMS platform
- Autonomous vulnerability scanning with GraphRL
- Human-On-The-Loop (HOTL) interface
- Real-time dashboard and chat interface
- Integration with major vulnerability databases (CVE, NVD, MITRE)
- Support for multiple scanning engines (Masscan, Nuclei, Nmap)
- Graph-based risk assessment and prioritization
- NATS.io messaging and JetStream persistence
- Neo4j graph database integration
- Comprehensive API documentation
- Docker and Kubernetes deployment support
- Monitoring with Prometheus and Grafana
- Distributed tracing with Jaeger
- Log aggregation with ELK stack

### Security
- End-to-end encryption for all communications
- Role-based access control (RBAC)
- Secure credential management
- Network segmentation and policies
- Regular security scanning and updates
- Compliance with security frameworks (NIST, CIS, ISO 27001)