# EVMS Security Tools

This directory is where the security scanning tools integrated with EVMS should be installed.

## Required Tools Setup

EVMS expects the following tools to be installed in this directory structure:

### masscan
- **Expected Location**: `./masscan/bin/masscan`
- **Purpose**: High-speed port scanner for network discovery
- **Download**: https://github.com/robertdavidgraham/masscan
- **Installation**: 
  ```bash
  # Create directory
  mkdir -p masscan/bin
  # Download or compile masscan binary and place at masscan/bin/masscan
  ```

### nuclei
- **Expected Location**: `./nuclei/nuclei`
- **Purpose**: Vulnerability scanner with template-based detection
- **Download**: https://github.com/projectdiscovery/nuclei
- **Installation**:
  ```bash
  # Create directory
  mkdir -p nuclei
  # Download nuclei binary and place at nuclei/nuclei
  ```

### subfinder
- **Expected Location**: `./subfinder/subfinder`
- **Purpose**: Subdomain discovery tool
- **Download**: https://github.com/projectdiscovery/subfinder
- **Installation**:
  ```bash
  # Create directory
  mkdir -p subfinder
  # Download subfinder binary and place at subfinder/subfinder
  ```

### httpx
- **Expected Location**: `./httpx/httpx`
- **Purpose**: HTTP toolkit for probing and analysis
- **Download**: https://github.com/projectdiscovery/httpx
- **Installation**:
  ```bash
  # Create directory
  mkdir -p httpx
  # Download httpx binary and place at httpx/httpx
  ```

## Current Status

⚠️ **Tools Not Yet Installed**: The tool binaries are not included in this repository and must be downloaded separately.

## Quick Setup

Create the directory structure:
```bash
npm run tools:setup
```

Run the validation script to check tool availability:
```bash
npm run tools:validate
```

## Tool Integration

These tools are integrated into the EVMS agent framework and are automatically detected and used when available. The system provides fallback mechanisms when tools are not present.

### Fallback Behavior

When tools are not available, EVMS will:
- Use built-in network scanning capabilities
- Provide basic vulnerability detection
- Log warnings about missing tools
- Continue operation with reduced functionality

### Installation Notes

- All tools are **optional** - EVMS will function without them
- Tools provide enhanced performance and detection capabilities
- Download binaries from official GitHub releases
- Ensure binaries are executable (`chmod +x`)
- Use the exact paths specified above

## Configuration

Tool paths are configured in the agent scanner classes:
- `src/services/agents/vulnerability/VulnScanner.js`
- `src/services/agents/discovery/NetworkDiscovery.js`

## Security Considerations

- All tools run in sandboxed environments
- Output is parsed and sanitized before processing
- Timeouts and resource limits are enforced
- Tool execution is logged and monitored