# Rexa - Advanced Malware Analysis Platform

<div align="center">

![Rexa Logo](https://img.shields.io/badge/Rexa-v2.0-blue?style=for-the-badge)
[![Python](https://img.shields.io/badge/Python-3.8+-green?style=for-the-badge&logo=python)](https://www.python.org/)
[![PyQt6](https://img.shields.io/badge/PyQt6-UI-orange?style=for-the-badge)](https://www.riverbankcomputing.com/software/pyqt/)
[![License](https://img.shields.io/badge/License-MIT-red?style=for-the-badge)](LICENSE)

**All-in-One Reverse Engineering & Malware Analysis Command Center**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Documentation](#documentation)

</div>

---

## 🎯 Overview

Rexa is a comprehensive desktop application for malware analysis and reverse engineering, combining static analysis, dynamic analysis, threat intelligence, and collaborative features into a single powerful platform.

## ✨ Features

### 🔬 **Dynamic Analysis**
- **Sandbox Integration**: Cuckoo & CAPE sandbox support
- **Behavioral Analysis**: Process trees, network indicators, dropped files
- **Real-time Monitoring**: Track malware behavior during execution

### 🔍 **Disassembly & Reverse Engineering**
- **Multi-Architecture Support**: x86, x64, ARM, MIPS via Capstone
- **Ghidra Integration**: Decompilation to C pseudocode
- **Interactive Disassembly**: Syntax highlighting, function navigation, cross-references

### 📊 **Graph Visualization**
- **Call Graphs**: Visualize function relationships
- **Control Flow Graphs (CFG)**: Analyze program logic
- **Interactive Graphs**: Zoom, pan, export to PNG/SVG/DOT

### 🌐 **Threat Intelligence**
- **VirusTotal Integration**: 70+ AV engine results
- **AlienVault OTX**: Threat pulse analysis
- **IOC Enrichment**: Automatic reputation scoring

### 🤝 **Collaboration**
- **Multi-User Support**: Role-based access control (Admin/Analyst/Viewer)
- **Shared Projects**: Team collaboration on malware samples
- **Annotations**: Comments, tags, highlights on code
- **Activity Feed**: Track team analysis progress

### 🛠️ **Core Features**
- **Static Analysis**: PE parsing, string extraction, entropy analysis
- **YARA Rules**: Custom malware detection
- **AI-Powered Analysis**: LLM integration for code explanation
- **Report Generation**: JSON & HTML export
- **Hex Editor**: Binary file inspection

---

## 📦 Installation

### Prerequisites

- **Python 3.8+**
- **pip** package manager
- **(Optional)** Ghidra for decompilation
- **(Optional)** Cuckoo/CAPE sandbox instance

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/rexa.git
cd rexa

# Install dependencies
pip install -r requirements.txt

# Run Rexa
python main.py
```

### Dependencies

Core dependencies are automatically installed:
- PyQt6 (UI framework)
- SQLAlchemy (Database ORM)
- Capstone (Disassembly engine)
- NetworkX (Graph visualization)
- bcrypt (Password hashing)
- cryptography (API key encryption)
- vt-py (VirusTotal API)
- OTXv2 (AlienVault OTX)

---

## 🚀 Usage

### First Launch

1. **Login/Register**: Create an account or use Guest Mode
2. **Create Project**: Organize your malware samples
3. **Upload Sample**: Drag & drop or browse for files
4. **Analyze**: Automatic static analysis on upload

### Advanced Features

#### Disassembly View
```
Sample → 🔍 Disassembly Button
```
- View functions, assembly code, and cross-references
- Syntax highlighting for mnemonics and registers
- Search by instruction, API, or address

#### Sandbox Analysis
```
Sample → 📦 Sandbox Button
```
- Submit to Cuckoo or CAPE sandbox
- View behavioral signatures, network activity, dropped files
- Track process trees and API calls

#### Threat Intelligence
```
Sample → 🌐 Threat Intel Button
```
- Query VirusTotal and AlienVault OTX
- View detection ratios and threat pulses
- Aggregate reputation scoring

#### Graph Visualization
```
Sample → 📊 Graphs Button
```
- Generate call graphs and CFGs
- Interactive navigation with zoom/pan
- Export to multiple formats

### Configuration

Access settings via **File → Settings** (⚙️):

1. **Sandbox**: Configure Cuckoo/CAPE URLs
2. **Threat Intel**: Add VirusTotal/OTX API keys
3. **Disassembly**: Set Ghidra installation path
4. **UI**: Customize theme and preferences

---

## 📁 Project Structure

```
rexa/
├── core/
│   ├── analysis/          # Static analysis modules
│   ├── auth/              # User authentication
│   ├── disassembly/       # Capstone & Ghidra integration
│   ├── sandbox/           # Cuckoo & CAPE providers
│   ├── visualization/     # Graph generators
│   ├── ai/                # LLM integration
│   ├── config.py          # Configuration management
│   └── database.py        # SQLAlchemy models
├── integrations/
│   ├── virustotal.py      # VirusTotal API client
│   └── otx.py             # AlienVault OTX client
├── ui/
│   ├── dashboard.py       # Main dashboard
│   ├── analysis_view.py   # Sample analysis view
│   ├── disassembly_view.py
│   ├── sandbox_view.py
│   ├── graph_view.py
│   ├── threat_intel_view.py
│   └── widgets/           # Reusable UI components
├── config/
│   └── settings.yaml      # User configuration
├── rules/                 # YARA rules
├── main.py                # Application entry point
└── requirements.txt       # Python dependencies
```

---

## 🔐 Security

- **Password Hashing**: bcrypt with cost factor 12
- **API Key Encryption**: Fernet symmetric encryption
- **Database**: SQLite with parameterized queries
- **Sandboxing**: Isolated malware execution

⚠️ **Warning**: Always analyze malware in isolated environments. Rexa does not provide built-in sandboxing.

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Capstone** - Disassembly framework
- **Ghidra** - NSA's reverse engineering tool
- **Cuckoo/CAPE** - Automated malware analysis
- **VirusTotal** - Malware intelligence service
- **AlienVault OTX** - Open threat exchange

---

## 📧 Contact

**Project Maintainer**: Gourav Dange
- GitHub: [@yourusername](https://github.com/Rathox110)
- Email: gauravdange26@gmail.com

---

<div align="center">

**⭐ Star this repo if you find it useful!**

Made with ❤️ for the cybersecurity community

</div>
