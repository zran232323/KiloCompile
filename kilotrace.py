#!/usr/bin/env python3
"""
KiloTrace GUI for KiloCompile Compression
A modern GUI for compressing and decompressing files using the KiloCompile format.

File formats:
- .kc: Standard compressed file
- .kca: Compressed application/archive

Features:
- GUI for user interaction
- Support compressing Node.js, Java, JavaScript, and C++ code in .kca
- Built-in Format Key for security
- Malware scanning before compression
"""

import os
import sys
import zlib
import json
import hashlib
import secrets
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess
import shutil

class KiloCompile:
    """KiloCompile compression format handler"""
    
    KC_MAGIC = b'KC01'  # Magic bytes for .kc files
    KCA_MAGIC = b'KCA1'  # Magic bytes for .kca files

    def __init__(self):
        self.format_key = self.generate_format_key()
        self.check_dependencies()

    def generate_format_key(self, length=32):
        """Generate a secure Format Key"""
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^6*"
        return ''.join(secrets.choice(chars) for _ in range(length))

    def compress_file(self, input_path, output_path, is_application=False, compression_level=6):
        """Compress a file or directory"""
        input_path = Path(input_path)

        # Malware scanning
        if not self.scan_for_malware(input_path):
            raise Exception("Malware detected! Aborting compression.")

        if input_path.is_file():
            # Single file compression
            with open(input_path, 'rb') as f:
                data = f.read()
            
            metadata = {
                'original_name': input_path.name,
                'original_size': len(data),
                'original_hash': hashlib.sha256(data).hexdigest(),
                'is_directory': False
            }
            
            compressed_data = zlib.compress(data, compression_level)
        else:
            # Directory compression
            all_files = []
            total_size = 0
            
            for file in input_path.rglob('*'):
                if file.is_file() and not self.is_compressed_file(file) and not self.is_temp_file(file):
                    all_files.append(file)
                    total_size += file.stat().st_size
            
            metadata = {
                'original_name': input_path.name,
                'original_size': total_size,
                'files': [str(f.relative_to(input_path)) for f in all_files],
                'is_directory': True
            }
            
            # Create a tar-like structure for directories
            import io
            buffer = io.BytesIO()
            
            for file in all_files:
                with open(file, 'rb') as f:
                    file_data = f.read()
                    # Store file path length, path, data length, and data
                    rel_path = str(file.relative_to(input_path))
                    path_bytes = rel_path.encode('utf-8')
                    buffer.write(len(path_bytes).to_bytes(4, 'little'))
                    buffer.write(path_bytes)
                    buffer.write(len(file_data).to_bytes(4, 'little'))
                    buffer.write(file_data)
            
            compressed_data = zlib.compress(buffer.getvalue(), compression_level)

        header = self.create_header(is_application, metadata)
        header_size = len(header).to_bytes(4, 'little')
        magic = self.KCA_MAGIC if is_application else self.KC_MAGIC

        with open(output_path, 'wb') as out_file:
            out_file.write(magic)
            out_file.write(header_size)
            out_file.write(header)
            out_file.write(compressed_data)

    def create_header(self, is_application=False, metadata=None):
        """Create KC file header"""
        header = {
            'version': '1.0',
            'created': datetime.now().isoformat(),
            'format_key': self.format_key,
            'type': 'application' if is_application else 'standard',
            'metadata': metadata or {}
        }
        return json.dumps(header, separators=(',', ':')).encode('utf-8')

    def is_compressed_file(self, file_path):
        """Check if a file is already compressed"""
        compressed_extensions = {
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.lzma',
            '.kc', '.kca', '.jar', '.war', '.ear', '.apk', '.deb', '.rpm'
        }
        return file_path.suffix.lower() in compressed_extensions
    
    def is_temp_file(self, file_path):
        """Check if a file is a temporary file that should be excluded"""
        temp_files = {
            'kc', 'KC_FORMAT.md', 'kilocompile.py', '.DS_Store', 'Thumbs.db',
            '.gitignore', '.gitkeep', 'desktop.ini'
        }
        return file_path.name in temp_files or file_path.name.startswith('.')

    def decompress_file(self, input_path, output_path=None):
        """Decompress a KC/KCA file"""
        input_path = Path(input_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        with open(input_path, 'rb') as f:
            # Read magic bytes
            magic = f.read(4)
            if magic not in [self.KC_MAGIC, self.KCA_MAGIC]:
                raise ValueError("Invalid KC file format")
            
            is_application = magic == self.KCA_MAGIC
            
            # Read header size
            header_size = int.from_bytes(f.read(4), 'little')
            
            # Read header
            header_data = f.read(header_size)
            header = json.loads(header_data.decode('utf-8'))
            
            # Read compressed data
            compressed_data = f.read()
        
        # Decompress data
        decompressed_data = zlib.decompress(compressed_data)
        
        # Determine output path
        if output_path is None:
            output_path = input_path.parent / header['metadata']['original_name']
        else:
            output_path = Path(output_path)
        
        metadata = header['metadata']
        
        if metadata.get('is_directory', True):  # Default to directory for backwards compatibility
            # Directory decompression
            output_path.mkdir(exist_ok=True)
            
            import io
            buffer = io.BytesIO(decompressed_data)
            
            while buffer.tell() < len(decompressed_data):
                # Read path length
                path_len_bytes = buffer.read(4)
                if len(path_len_bytes) < 4:
                    break
                path_len = int.from_bytes(path_len_bytes, 'little')
                
                # Read path
                path_bytes = buffer.read(path_len)
                rel_path = path_bytes.decode('utf-8')
                
                # Read data length
                data_len = int.from_bytes(buffer.read(4), 'little')
                
                # Read file data
                file_data = buffer.read(data_len)
                
                # Create file
                file_path = output_path / rel_path
                file_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(file_path, 'wb') as f:
                    f.write(file_data)
        else:
            # Single file decompression
            with open(output_path, 'wb') as f:
                f.write(decompressed_data)
        
        # Clean up any leftover temporary files
        self.cleanup_temp_files(output_path)
        
        return str(output_path)
    
    def cleanup_temp_files(self, output_path):
        """Remove temporary files that may have been created during compression/decompression"""
        output_path = Path(output_path)
        temp_files = ['kc', 'KC_FORMAT.md', 'kilocompile.py']
        
        for temp_file in temp_files:
            temp_path = output_path / temp_file if output_path.is_dir() else output_path.parent / temp_file
            if temp_path.exists():
                try:
                    if temp_path.is_file():
                        temp_path.unlink()
                    elif temp_path.is_dir():
                        shutil.rmtree(temp_path)
                except Exception as e:
                    print(f"Warning: Could not remove temporary file {temp_path}: {e}")

    def check_dependencies(self):
        """Check and install required dependencies"""
        try:
            # Check if ClamAV is installed
            subprocess.run(['which', 'clamscan'], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            self.install_clamav()
    
    def install_clamav(self):
        """Install ClamAV antivirus scanner"""
        try:
            # Detect the package manager and install ClamAV
            if shutil.which('pacman'):  # Arch/Manjaro
                subprocess.run(['sudo', 'pacman', '-S', 'clamav', '--noconfirm'], check=True)
            elif shutil.which('apt'):  # Ubuntu/Debian
                subprocess.run(['sudo', 'apt', 'update'], check=True)
                subprocess.run(['sudo', 'apt', 'install', '-y', 'clamav'], check=True)
            elif shutil.which('yum'):  # RedHat/CentOS
                subprocess.run(['sudo', 'yum', 'install', '-y', 'clamav'], check=True)
            elif shutil.which('dnf'):  # Fedora
                subprocess.run(['sudo', 'dnf', 'install', '-y', 'clamav'], check=True)
            else:
                print("Warning: Could not detect package manager. Please install ClamAV manually.")
                return
            
            # Update virus database
            subprocess.run(['sudo', 'freshclam'], capture_output=True)
            print("ClamAV installed and updated successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Warning: Could not install ClamAV: {e}")
        except Exception as e:
            print(f"Warning: Error during ClamAV installation: {e}")
    
    def scan_for_malware(self, path):
        """Scan the file or directory for malware"""
        try:
            result = subprocess.run(['clamscan', str(path)], capture_output=True, text=True)
            return 'Infected files: 0' in result.stdout
        except FileNotFoundError:
            print("Warning: ClamAV not found, skipping malware scan.")
            return True  # Skip the scan since it's unavailable

class KiloTraceGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title('KiloTrace Compression Tool')
        self.window.geometry('500x350')

        self.kc = KiloCompile()
        
        # Title
        title_label = tk.Label(self.window, text='KiloTrace Compression Tool', font=('Arial', 14, 'bold'))
        title_label.pack(pady=10)
        
        # Compression section
        compress_frame = tk.Frame(self.window)
        compress_frame.pack(pady=10, padx=20, fill='x')
        
        tk.Label(compress_frame, text='Select file or directory to compress:', font=('Arial', 10)).pack()
        
        self.compress_path_entry = tk.Entry(compress_frame, width=50)
        self.compress_path_entry.pack(pady=5)
        
        compress_buttons_frame = tk.Frame(compress_frame)
        compress_buttons_frame.pack(pady=5)
        
        tk.Button(compress_buttons_frame, text='Browse', command=self.browse_compress).pack(side='left', padx=5)
        tk.Button(compress_buttons_frame, text='Compress as .kc', command=self.compress_kc).pack(side='left', padx=5)
        tk.Button(compress_buttons_frame, text='Compress as .kca (Application)', command=self.compress_kca).pack(side='left', padx=5)
        
        # Separator
        separator = tk.Frame(self.window, height=2, bg='gray')
        separator.pack(fill='x', pady=20)
        
        # Decompression section
        decompress_frame = tk.Frame(self.window)
        decompress_frame.pack(pady=10, padx=20, fill='x')
        
        tk.Label(decompress_frame, text='Select .kc or .kca file to decompress:', font=('Arial', 10)).pack()
        
        self.decompress_path_entry = tk.Entry(decompress_frame, width=50)
        self.decompress_path_entry.pack(pady=5)
        
        decompress_buttons_frame = tk.Frame(decompress_frame)
        decompress_buttons_frame.pack(pady=5)
        
        tk.Button(decompress_buttons_frame, text='Browse KC/KCA', command=self.browse_decompress).pack(side='left', padx=5)
        tk.Button(decompress_buttons_frame, text='Decompress', command=self.decompress).pack(side='left', padx=5)
        
        # Status label
        self.status_label = tk.Label(self.window, text='Ready', fg='green', font=('Arial', 9))
        self.status_label.pack(pady=10)

        self.window.mainloop()

    def browse_compress(self):
        # Allow all files except compressed ones
        path = filedialog.askdirectory(title="Select directory to compress") or \
               filedialog.askopenfilename(
                   title="Select file to compress",
                   filetypes=[
                       ("All non-compressed files", "*.*"),
                       ("Text files", "*.txt"),
                       ("Source code", "*.py;*.js;*.cpp;*.java;*.c;*.h"),
                       ("Documents", "*.pdf;*.doc;*.docx"),
                       ("Images", "*.png;*.jpg;*.jpeg;*.gif;*.bmp"),
                       ("All files", "*.*")
                   ]
               )
        if path:
            # Check if it's a compressed file
            if Path(path).is_file() and self.kc.is_compressed_file(Path(path)):
                messagebox.showwarning('Warning', 'Selected file appears to be already compressed. Proceeding anyway.')
            
            self.compress_path_entry.delete(0, tk.END)
            self.compress_path_entry.insert(0, path)

    def browse_decompress(self):
        path = filedialog.askopenfilename(
            title="Select KC/KCA file to decompress",
            filetypes=[
                ("KiloCompile files", "*.kc;*.kca"),
                ("KC Standard", "*.kc"),
                ("KCA Application", "*.kca"),
                ("All files", "*.*")
            ]
        )
        if path:
            self.decompress_path_entry.delete(0, tk.END)
            self.decompress_path_entry.insert(0, path)

    def compress_kc(self):
        self.compress(False)

    def compress_kca(self):
        self.compress(True)

    def compress(self, is_application):
        path = Path(self.compress_path_entry.get())
        if not path.exists():
            messagebox.showerror('Error', 'Invalid path selected')
            return

        # Create output path
        extension = '.kca' if is_application else '.kc'
        if path.is_file():
            output_path = path.with_suffix(extension)
        else:
            output_path = path.parent / f"{path.name}{extension}"
        
        try:
            self.status_label.config(text='Compressing...', fg='orange')
            self.window.update()
            
            self.kc.compress_file(path, output_path, is_application)
            
            self.status_label.config(text='Compression completed successfully!', fg='green')
            messagebox.showinfo('Success', f'Compressed to {output_path}')
        except Exception as e:
            self.status_label.config(text='Compression failed!', fg='red')
            messagebox.showerror('Error', str(e))
    
    def decompress(self):
        path = Path(self.decompress_path_entry.get())
        if not path.exists():
            messagebox.showerror('Error', 'Invalid KC/KCA file selected')
            return
        
        try:
            self.status_label.config(text='Decompressing...', fg='orange')
            self.window.update()
            
            output_path = self.kc.decompress_file(path)
            
            self.status_label.config(text='Decompression completed successfully!', fg='green')
            messagebox.showinfo('Success', f'Decompressed to {output_path}')
        except Exception as e:
            self.status_label.config(text='Decompression failed!', fg='red')
            messagebox.showerror('Error', str(e))

def main():
    """Main entry point for the application"""
    KiloTraceGUI()

if __name__ == '__main__':
    main()

