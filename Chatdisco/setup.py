from setuptools import setup, find_packages

setup(
    name="chatdisco",
    version="0.1.0",
    description="AI Chat Forensics Tool - Memory, PCAP, and Disk Artifact Extraction",
    author="Chatdisco Project",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "volatility3>=2.11.0",
        "dpkt>=1.9.8",
        "yara-python>=4.3.0",
        "python-dateutil>=2.8.2",
        "rich>=13.0.0",
        "click>=8.1.0",
        "jinja2>=3.1.0",
        "pytz>=2023.3",
    ],
    entry_points={
        "console_scripts": [
            "chatdisco=chatdisco.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
    ],
)
