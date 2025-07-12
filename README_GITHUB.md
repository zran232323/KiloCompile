# KiloTrace - KiloCompile Compression Tool

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.6%2B-brightgreen)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)](https://github.com/yourusername/kilotrace)

KiloTrace is a modern GUI compression tool that uses the custom KiloCompile format with built-in security features and malware scanning capabilities.

## 🚀 Features

- **🎨 Modern GUI Interface**: Easy-to-use Tkinter-based interface
- **🔒 Security First**: Built-in malware scanning with ClamAV integration
- **📦 Dual Format Support**: 
  - `.kc` - Standard compressed files
  - `.kca` - Application archives (Node.js, Java, JavaScript, C++ code)
- **🔑 Format Key Protection**: Unique cryptographic keys embedded in each file
- **🛡️ Integrity Verification**: SHA-256 hash checking for file integrity
- **🗂️ Smart File Filtering**: Automatically excludes compressed and temporary files
- **⚡ Auto-Dependency Installation**: Automatically installs required packages

## 📋 Supported File Types

### .kca (Application Archives)
- **Node.js**: `.js`, `.json`, `package.json`, etc.
- **Java**: `.java`, `.class`, `.jar`, etc.
- **JavaScript**: `.js`, `.ts`, `.jsx`, `.tsx`, etc.
- **C++**: `.cpp`, `.h`, `.hpp`, `.c`, etc.

### .kc (Standard Compression)
- Documents, images, and general files
- Automatically excludes already compressed files

## 🔧 Installation

### Automatic Installation (Recommended)
```bash
# One-line installer
curl -sSL https://raw.githubusercontent.com/yourusername/kilotrace/main/quick_install.sh | bash
```

### Manual Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/kilotrace.git
cd kilotrace

# Run the automatic installer
python3 install.py
```

### Prerequisites
- Python 3.6 or higher
- Git (for cloning)
- Internet connection (for downloading dependencies)

**Note**: The installer automatically installs all required dependencies including:
- Tkinter (GUI framework)
- ClamAV (antivirus scanning)
- PyInstaller (for building executables)
- System packages based on your distribution

### Quick Start (Without Building)
```bash
git clone https://github.com/yourusername/kilotrace.git
cd kilotrace
python3 src/kilotrace.py
```

## 🖥️ Usage

### GUI Mode
```bash
./kilotrace
```

### Command Line
```bash
python3 src/kilotrace.py
```

## 📁 File Structure

```
KiloTrace/
├── src/
│   └── kilotrace.py      # Main application
├── docs/                 # Documentation
├── build/                # Build artifacts
├── build.sh              # Build script
├── kilotrace             # Executable launcher
├── LICENSE               # License file
└── README.md             # This file
```

## 🔐 Security Features

1. **Format Key**: 32-character cryptographically secure random string
2. **Malware Scanning**: Integrated ClamAV scanning before compression
3. **Magic Number Validation**: Prevents processing of invalid files
4. **Integrity Verification**: SHA-256 hash verification
5. **Temporary File Cleanup**: Automatic cleanup of temporary files

## 📊 File Format Specification

### Header Structure
```
[4 bytes] Magic Number (KC01 for .kc, KCA1 for .kca)
[4 bytes] Header Size (little-endian)
[N bytes] JSON Header (includes Format Key and metadata)
[M bytes] Compressed Data (zlib compression)
```

### JSON Header Format
```json
{
  "version": "1.0",
  "created": "2024-01-01T12:00:00.000000",
  "format_key": "Abc123!@#...",
  "type": "standard|application",
  "metadata": {
    "original_name": "filename.ext",
    "original_size": 1024,
    "original_hash": "sha256_hash",
    "is_directory": false
  }
}
```

## 🛠️ Dependencies

KiloTrace automatically installs required dependencies on first run:

- **ClamAV**: For malware scanning
- **Python packages**: All included in standard library

Supported package managers:
- `pacman` (Arch/Manjaro)
- `apt` (Ubuntu/Debian)
- `yum` (RedHat/CentOS)
- `dnf` (Fedora)

## 🏗️ Building

To create standalone executables:

```bash
./build.sh
```

This creates:
- Linux executable in `build/`
- Cross-platform Python package

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🐛 Bug Reports

If you find a bug, please create an issue with:
- Operating system and version
- Python version
- Steps to reproduce
- Expected vs actual behavior

## 🔮 Roadmap

- [ ] Web interface
- [ ] More compression algorithms
- [ ] Batch processing
- [ ] Cloud storage integration
- [ ] Plugin system

## 👥 Authors

- **Your Name** - *Initial work* - [YourUsername](https://github.com/yourusername)

## 🙏 Acknowledgments

- ClamAV team for antivirus scanning
- Python community for excellent libraries
- All contributors and testers

---

**⭐ Star this repository if you find it useful!**
