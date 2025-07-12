# KiloTrace - KiloCompile Compression Tool

KiloTrace is a modern GUI compression tool that uses the KiloCompile format with built-in security features and malware scanning.

## Features

- **GUI Interface**: Easy-to-use Tkinter-based interface
- **Dual Format Support**: 
  - `.kc` - Standard compressed files
  - `.kca` - Application archives (Node.js, Java, JavaScript, C++ code)
- **Security Features**:
  - Unique Format Key embedded in each file
  - Malware scanning before compression
  - Integrity verification
- **Compression**: Uses zlib compression with configurable levels

## Directory Structure

```
KiloTrace/
├── src/
│   └── kilotrace.py    # Main application source
├── docs/               # Documentation
├── build/              # Build artifacts
├── kilotrace           # Executable launcher
└── README.md           # This file
```

## Installation

1. Make sure you have Python 3.6+ installed
2. Install Tkinter if not already available:
   ```bash
   sudo pacman -S tk  # On Arch/Manjaro
   sudo apt install python3-tk  # On Ubuntu/Debian
   ```
3. For malware scanning, install ClamAV:
   ```bash
   sudo pacman -S clamav  # On Arch/Manjaro
   sudo apt install clamav  # On Ubuntu/Debian
   ```

## Usage

### GUI Mode
```bash
cd KiloTrace
./kilotrace
```

### Direct Python Execution
```bash
python3 src/kilotrace.py
```

## File Format Specification

### .kc Format (Standard)
- Used for general file compression
- Suitable for documents, images, and other files

### .kca Format (Application)
- Designed for code archives
- Supports Node.js, Java, JavaScript, and C++ projects
- Includes metadata about file structure

## File Structure

```
[4 bytes] Magic Number (KC01 for .kc, KCA1 for .kca)
[4 bytes] Header Size (little-endian)
[N bytes] JSON Header
[M bytes] Compressed Data
```

## Security Features

1. **Format Key**: 32-character cryptographically secure random string
2. **Malware Scanning**: ClamAV integration for pre-compression scanning
3. **Magic Number Validation**: Prevents processing of invalid files
4. **Integrity Verification**: Ensures file integrity during operations

## Supported Code Types for .kca

- **Node.js**: `.js`, `.json`, `package.json`, etc.
- **Java**: `.java`, `.class`, `.jar`, etc.
- **JavaScript**: `.js`, `.ts`, `.jsx`, `.tsx`, etc.
- **C++**: `.cpp`, `.h`, `.hpp`, `.c`, etc.

## Requirements

- Python 3.6 or higher
- Tkinter (usually included with Python)
- ClamAV (optional, for malware scanning)

## License

KiloCompile Format v1.0 - Custom compression format with security features
