# PyDefender 🛡️

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Advanced hash-based malware detection system written in Python.

## Features
- Multi-algorithm hash detection (MD5, SHA-1, SHA-256, SHA-512)
- Automatic malware database updates
- Cross-platform support (Windows/Linux/macOS)
- Detailed scan reporting

## Installation
```bash
pip install git+https://github.com/yourusername/PyDefender.git
```

## Usage
```bash
pydefender scan --quick  # Quick system scan
pydefender scan --full   # Complete system scan
```

## Development
```bash
git clone https://github.com/yourusername/PyDefender.git
cd PyDefender
pip install -e .
```
