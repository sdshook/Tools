# EVMS Security Tools

This directory contains the security scanning tools integrated with EVMS.

## Included Tools

### masscan
- **Location**: `./masscan/bin/masscan`
- **Purpose**: High-speed port scanner for network discovery
- **Usage**: Network sweeping and port enumeration

### nuclei
- **Location**: `./nuclei/nuclei`
- **Purpose**: Vulnerability scanner with template-based detection
- **Usage**: Web application vulnerability scanning

### subfinder
- **Location**: `./subfinder/subfinder`
- **Purpose**: Subdomain discovery tool
- **Usage**: Asset discovery and reconnaissance

### httpx
- **Location**: `./httpx/httpx`
- **Purpose**: HTTP toolkit for probing and analysis
- **Usage**: Web service detection and technology fingerprinting

## Tool Integration

These tools are integrated into the EVMS agent framework and are automatically detected and used when available. The system provides fallback mechanisms when tools are not present.

## Configuration

Tool paths are configured in the agent scanner classes:
- `src/services/agents/vulnerability/VulnScanner.js`
- `src/services/agents/discovery/NetworkDiscovery.js`

## Security Considerations

- All tools run in sandboxed environments
- Output is parsed and sanitized before processing
- Timeouts and resource limits are enforced
- Tool execution is logged and monitored