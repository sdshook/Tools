# Chatdisco — Installation Guide

## Python Package

```bash
pip install -e .
# or
pip install chatdisco
```

Requires Python 3.9+.

---

## Required Third-Party Tools

All three are **hard dependencies**. Chatdisco will refuse to run without them.

---

### bulk_extractor

Used for: byte-stream carving (JSON, URLs, base64, x509, cookies,
network packets, TLS key labels) from memory, disk, PCAP, and prefetch files.

**Linux (Ubuntu/Debian)**
```bash
sudo apt install bulk-extractor
```

**Linux (from source)**
```bash
git clone https://github.com/simsong/bulk_extractor.git
cd bulk_extractor
./configure && make -j$(nproc) && sudo make install
```

**macOS**
```bash
brew install bulk_extractor
```

**Windows**

Download the signed binary from:
https://github.com/simsong/bulk_extractor/releases

Add to PATH.

**Verify:**
```
bulk_extractor --version
```

---

### tshark + editcap (Wireshark CLI)

Used for: HTTP/2 dissection, SSE stream reconstruction, TCP stream
reassembly, TLS decryption with keylog injection. `editcap` ships
with Wireshark and is required for TLS secret injection into pcapng.

**Linux (Ubuntu/Debian)**
```bash
sudo apt install tshark wireshark-common
# Add your user to wireshark group for live capture:
sudo usermod -aG wireshark $USER
```

**macOS**
```bash
brew install wireshark
# tshark is included
```

**Windows**

Download the Wireshark installer from https://www.wireshark.org/download.html

During installation, select "TShark" under command-line tools.
Add `C:\Program Files\Wireshark` to PATH.

**Verify:**
```
tshark --version
editcap --version
```

---

### Volatility 3

Used for: OS structure analysis from memory images (process trees,
network connections, environment variables, command lines, registry).

```bash
pip install volatility3
```

Or from source for latest plugins:
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip install -e .
```

**Symbol tables** (required for Windows memory analysis):

Volatility needs Windows symbol tables to parse kernel structures.
Download from https://downloads.volatilityfoundation.org/volatility3/symbols/

```bash
# Place in Volatility's symbols directory:
~/.local/share/volatility3/symbols/   # Linux/macOS
%APPDATA%\volatility3\symbols\        # Windows
```

Or set environment variable:
```bash
export VOLATILITY3_SYMBOL_PATH=/path/to/symbols
```

**Verify:**
```
vol --help
python3 -c "import volatility3; print(volatility3.__version__)"
```

---

## Optional Tools (enhance capability)

### Memory Acquisition

**Windows — WinPmem** (required for `chatdisco collect` on Windows)
```
https://github.com/Velocidex/WinPmem/releases
```
Download `winpmem_mini_x64.exe`, place on USB or evidence drive.
Must be run as Administrator.

**Linux — AVML** (preferred, no kernel module needed)
```bash
# Download from https://github.com/microsoft/avml/releases
curl -L https://github.com/microsoft/avml/releases/latest/download/avml \
  -o avml && chmod +x avml
sudo ./avml memory.lime
```

**Linux — LiME** (kernel module)
```bash
sudo apt install linux-headers-$(uname -r)
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src && make
sudo insmod lime.ko "path=/mnt/evidence/memory.lime format=lime"
```

**macOS — osxpmem**
```
https://github.com/google/rekall/releases
```

### Live TLS Key Capture

**friTap** (Frida-based, live TLS key extraction from running processes)
```bash
pip install fritap
```

Requires Frida to be installed on the target system.

---

## Platform-Specific Notes

### Windows

- Live collection (`chatdisco collect`) requires Administrator.
- WinPmem must be on PATH or in the same directory as chatdisco.
- Registry hive export requires elevated privileges.
- Windows Defender may flag memory acquisition tools — add exclusions
  or use an isolated forensic workstation.

### Linux

- Live collection requires root.
- `/proc/PID/mem` access requires root or ptrace capability.
- AVML is recommended over LiME for ease of deployment.

### macOS

- osxpmem requires SIP disabled for full memory access.
- System Integrity Protection restricts memory acquisition.

---

## Post-Installation Check

Run the dependency checker:
```bash
chatdisco --help
python3 -c "
from chatdisco.core.dependency_check import check_dependencies, print_dependency_table
report = check_dependencies(require_collection=True)
print_dependency_table(report)
"
```

All required tools should show ✓ Present before running an analysis.

---

## Quick Start

**Analyse a memory dump:**
```bash
chatdisco analyze \
  -i memory.raw \
  -o ./case-001-results \
  -e "J. Smith" \
  -c "CASE-2025-001"
```

**Analyse a PCAP with TLS keys:**
```bash
chatdisco analyze \
  -i capture.pcapng \
  --keylog tls-keys.log \
  -o ./case-001-results \
  -e "J. Smith" \
  -c "CASE-2025-001"
```

**Live collection:**
```bash
# Run as Administrator/root on the target system
chatdisco collect \
  -o /media/usb/CASE-2025-001 \
  -e "J. Smith" \
  -c "CASE-2025-001" \
  --mode triage
```

**Analyse collection output:**
```bash
chatdisco analyze \
  -i /media/usb/CASE-2025-001 \
  -o ./results \
  -e "J. Smith" \
  -c "CASE-2025-001"
```
