#!/usr/bin/env python3
"""
EVMS Setup Script
Installs dependencies and downloads required security tools
"""

import os
import sys
import subprocess
import urllib.request
import tarfile
import zipfile
import shutil
from pathlib import Path
import platform
import json

def run_command(cmd, check=True):
    """Run shell command"""
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"Error: {result.stderr}")
        sys.exit(1)
    return result

def download_file(url, dest):
    """Download file from URL"""
    print(f"Downloading {url} to {dest}")
    urllib.request.urlretrieve(url, dest)

def extract_archive(archive_path, dest_dir):
    """Extract tar.gz or zip archive"""
    if archive_path.endswith('.tar.gz') or archive_path.endswith('.tgz'):
        with tarfile.open(archive_path, 'r:gz') as tar:
            tar.extractall(dest_dir)
    elif archive_path.endswith('.zip'):
        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            zip_ref.extractall(dest_dir)

def setup_python_environment():
    """Setup Python environment and install dependencies"""
    print("Setting up Python environment...")
    
    # Install Python dependencies
    run_command(f"{sys.executable} -m pip install --upgrade pip")
    run_command(f"{sys.executable} -m pip install -r requirements.txt")

def setup_tools():
    """Download and setup security tools"""
    print("Setting up security tools...")
    
    tools_dir = Path("tools")
    tools_dir.mkdir(exist_ok=True)
    
    system = platform.system().lower()
    arch = platform.machine().lower()
    
    # Map architecture names
    if arch in ['x86_64', 'amd64']:
        arch = 'amd64'
    elif arch in ['aarch64', 'arm64']:
        arch = 'arm64'
    
    tools_config = {
        'masscan': {
            'linux': {
                'url': 'https://github.com/robertdavidgraham/masscan/archive/refs/tags/1.3.2.tar.gz',
                'extract_dir': 'masscan-1.3.2',
                'build_cmd': 'make && mkdir -p bin && cp bin/masscan bin/',
                'binary_path': 'bin/masscan'
            },
            'windows': {
                'note': 'Masscan not available for Windows. Using nmap as alternative.',
                'alternative': 'nmap',
                'install_cmd': 'winget install Insecure.Nmap'
            }
        },
        'nuclei': {
            'linux': {
                'amd64': 'https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip',
                'arm64': 'https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_arm64.zip'
            },
            'darwin': {
                'amd64': 'https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_macOS_amd64.zip',
                'arm64': 'https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_macOS_arm64.zip'
            },
            'windows': {
                'amd64': 'https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_windows_amd64.zip',
                'arm64': 'https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_windows_arm64.zip'
            }
        },
        'httpx': {
            'linux': {
                'amd64': 'https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_linux_amd64.zip',
                'arm64': 'https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_linux_arm64.zip'
            },
            'darwin': {
                'amd64': 'https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_macOS_amd64.zip',
                'arm64': 'https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_macOS_arm64.zip'
            },
            'windows': {
                'amd64': 'https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_windows_amd64.zip',
                'arm64': 'https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_windows_arm64.zip'
            }
        },
        'subfinder': {
            'linux': {
                'amd64': 'https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip',
                'arm64': 'https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_arm64.zip'
            },
            'darwin': {
                'amd64': 'https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_macOS_amd64.zip',
                'arm64': 'https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_macOS_arm64.zip'
            },
            'windows': {
                'amd64': 'https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_windows_amd64.zip',
                'arm64': 'https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_windows_arm64.zip'
            }
        }
    }
    
    for tool_name, tool_config in tools_config.items():
        tool_dir = tools_dir / tool_name
        tool_dir.mkdir(exist_ok=True)
        
        print(f"Setting up {tool_name}...")
        
        if tool_name == 'masscan':
            # Special handling for masscan (needs compilation on Linux, alternative on Windows)
            if system == 'linux':
                config = tool_config['linux']
                archive_path = tool_dir / 'masscan.tar.gz'
                download_file(config['url'], archive_path)
                extract_archive(archive_path, tool_dir)
                
                # Build masscan
                build_dir = tool_dir / config['extract_dir']
                if build_dir.exists():
                    original_dir = os.getcwd()
                    os.chdir(build_dir)
                    run_command(config['build_cmd'])
                    os.chdir(original_dir)
                    
                    # Copy binary
                    src_binary = build_dir / 'bin' / 'masscan'
                    dest_binary = tool_dir / 'bin' / 'masscan'
                    dest_binary.parent.mkdir(exist_ok=True)
                    shutil.copy2(src_binary, dest_binary)
                    dest_binary.chmod(0o755)
            elif system == 'windows':
                config = tool_config['windows']
                print(f"Note: {config['note']}")
                print(f"Installing {config['alternative']} as alternative...")
                try:
                    run_command(config['install_cmd'], check=False)
                    print(f"{config['alternative']} installation attempted via winget")
                except Exception as e:
                    print(f"Could not install {config['alternative']} automatically: {e}")
                    print(f"Please install {config['alternative']} manually from https://nmap.org/download.html")
            else:
                print(f"Masscan setup not supported on {system}")
        else:
            # Binary downloads
            if system in tool_config and arch in tool_config[system]:
                url = tool_config[system][arch]
                archive_path = tool_dir / f"{tool_name}.zip"
                download_file(url, archive_path)
                extract_archive(archive_path, tool_dir)
                
                # Make binary executable (Windows .exe files don't need chmod)
                if system == 'windows':
                    binary_path = tool_dir / f"{tool_name}.exe"
                else:
                    binary_path = tool_dir / tool_name
                
                if binary_path.exists() and system != 'windows':
                    binary_path.chmod(0o755)
            else:
                print(f"No {tool_name} binary available for {system} {arch}")
    
    # Download nuclei templates
    nuclei_dir = tools_dir / 'nuclei'
    templates_dir = nuclei_dir / 'templates'
    if not templates_dir.exists():
        print("Downloading nuclei templates...")
        run_command(f"git clone https://github.com/projectdiscovery/nuclei-templates.git {templates_dir}")

def setup_services():
    """Setup external services (Neo4j)"""
    print("Setting up external services...")
    
    # Check if Docker is available
    docker_available = run_command("docker --version", check=False).returncode == 0
    
    if docker_available:
        print("Docker detected. Setting up Neo4j with Docker...")
        
        print("Starting services with Docker Compose...")
        run_command("docker-compose up -d")
        
        print("Services started. Neo4j available at http://localhost:7474")
    else:
        system = platform.system().lower()
        print("Docker not available. Please install Neo4j manually:")
        if system == 'windows':
            print("Neo4j Desktop: https://neo4j.com/download/")
            print("Or install Docker Desktop: https://www.docker.com/products/docker-desktop")
        else:
            print("Neo4j: https://neo4j.com/download/")

def create_directories():
    """Create required directories"""
    directories = ['data', 'reports', 'templates', 'logs']
    for dir_name in directories:
        Path(dir_name).mkdir(exist_ok=True)

def setup_environment_file():
    """Create .env file template"""
    env_content = """# EVMS Environment Configuration
# Copy this to .env and update with your values

# Neo4j Configuration
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=password

# OpenAI Configuration (required for LLM features)
OPENAI_API_KEY=your_openai_api_key_here

# Web Interface
WEB_PORT=5000

# Scanning Configuration
MASSCAN_RATE=1000
SCAN_TIMEOUT=600
"""
    
    with open('.env.example', 'w') as f:
        f.write(env_content)
    
    print("Created .env.example - copy to .env and update with your configuration")

def main():
    """Main setup function"""
    print("EVMS Setup - Enterprise Vulnerability Management Scanner")
    print("=" * 60)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher required")
        sys.exit(1)
    
    try:
        # Setup steps
        create_directories()
        setup_python_environment()
        setup_tools()
        setup_services()
        setup_environment_file()
        
        print("\n" + "=" * 60)
        print("EVMS Setup Complete!")
        print("=" * 60)
        print("\nNext steps:")
        print("1. Copy .env.example to .env and update configuration")
        print("2. Ensure Neo4j is running")
        print("3. Run: python evms.py --help")
        print("4. Start web interface: python evms.py --web-only")
        print("5. Run a scan: python evms.py --target 192.168.1.1")
        
    except Exception as e:
        print(f"Setup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()