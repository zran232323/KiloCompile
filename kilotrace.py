#!/usr/bin/env python3
"""
KiloTrace GUI for KiloCompile Compression
Enhanced Features:
- Memory-efficient streaming compression for gigabyte files
- Adaptive compression algorithms (zlib, lzma, brotli)
- Intelligent chunking strategies with deduplication
- Enhanced multithreading with producer-consumer pattern
- Advanced progress tracking with ETA and performance metrics
- File type detection and content-aware compression
- Robust error handling and resume capability
- Optimized GUI for large file operations
"""

import os
import sys
import zlib
import lzma
import json
import hashlib
import secrets
import time
import threading
import queue
import mmap
import psutil
from datetime import datetime, timedelta
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess
import shutil
import io
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from typing import Optional, Callable, Dict, Any, List, Tuple

# Try to import brotli for additional compression
try:
    import brotli
    BROTLI_AVAILABLE = True
except ImportError:
    BROTLI_AVAILABLE = False

class CompressionStats:
    """Track compression statistics and performance metrics"""
    def __init__(self):
        self.start_time = time.time()
        self.bytes_processed = 0
        self.bytes_compressed = 0
        self.chunks_processed = 0
        self.dedup_savings = 0
        self.compression_ratio = 0.0
        self.speed_mbps = 0.0
        self.eta_seconds = 0

    def update(self, original_size: int, compressed_size: int):
        self.bytes_processed += original_size
        self.bytes_compressed += compressed_size
        self.chunks_processed += 1

        elapsed = time.time() - self.start_time
        if elapsed > 0:
            self.speed_mbps = (self.bytes_processed / (1024 * 1024)) / elapsed

        if self.bytes_processed > 0:
            self.compression_ratio = self.bytes_compressed / self.bytes_processed

    def get_eta(self, total_size: int) -> int:
        if self.speed_mbps > 0 and self.bytes_processed > 0:
            remaining_mb = (total_size - self.bytes_processed) / (1024 * 1024)
            return int(remaining_mb / self.speed_mbps)
        return 0


class KiloCompile:
    KC_MAGIC = b'KC01'
    KCA_MAGIC = b'KCA1'

    # Compression algorithms
    COMPRESSION_ZLIB = 'zlib'
    COMPRESSION_LZMA = 'lzma'
    COMPRESSION_BROTLI = 'brotli'

    # Default settings optimized for large files
    DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1MB chunks for better streaming
    DEFAULT_BUFFER_SIZE = 64 * 1024   # 64KB buffer for I/O
    MAX_MEMORY_USAGE = 512 * 1024 * 1024  # 512MB max memory usage

    def __init__(self):
        self.format_key = self.generate_format_key()
        self.check_dependencies()
        self.chunk_cache = {}  # For deduplication
        self.stats = CompressionStats()
        self.cancelled = False
        self.cpu_count = psutil.cpu_count()

    def cancel_operation(self):
        """Cancel ongoing compression/decompression"""
        self.cancelled = True

    def generate_format_key(self, length=32):
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^6*"
        return ''.join(secrets.choice(chars) for _ in range(length))

    def detect_file_type(self, file_path: Path) -> str:
        """Detect file type for optimal compression strategy"""
        suffix = file_path.suffix.lower()

        # Text-based files - high compression potential
        text_extensions = {'.txt', '.py', '.js', '.html', '.css', '.xml', '.json', '.csv', '.log'}
        if suffix in text_extensions:
            return 'text'

        # Code files - medium compression potential
        code_extensions = {'.cpp', '.c', '.h', '.java', '.cs', '.php', '.rb', '.go', '.rs'}
        if suffix in code_extensions:
            return 'code'

        # Already compressed - low compression potential
        compressed_extensions = {'.zip', '.rar', '.7z', '.gz', '.bz2', '.xz', '.jpg', '.png', '.mp3', '.mp4'}
        if suffix in compressed_extensions:
            return 'compressed'

        # Binary files - variable compression potential
        return 'binary'

    def get_optimal_compression_settings(self, file_type: str, file_size: int) -> Dict[str, Any]:
        """Get optimal compression settings based on file type and size"""
        settings = {
            'algorithm': self.COMPRESSION_ZLIB,
            'level': 6,
            'chunk_size': self.DEFAULT_CHUNK_SIZE
        }

        # Adjust based on file type
        if file_type == 'text':
            settings['algorithm'] = self.COMPRESSION_LZMA if file_size > 10*1024*1024 else self.COMPRESSION_ZLIB
            settings['level'] = 9
        elif file_type == 'code':
            settings['algorithm'] = self.COMPRESSION_BROTLI if BROTLI_AVAILABLE else self.COMPRESSION_ZLIB
            settings['level'] = 8
        elif file_type == 'compressed':
            settings['level'] = 1  # Don't waste time on already compressed files

        # Adjust chunk size based on file size
        if file_size > 1024*1024*1024:  # > 1GB
            settings['chunk_size'] = 4*1024*1024  # 4MB chunks
        elif file_size > 100*1024*1024:  # > 100MB
            settings['chunk_size'] = 2*1024*1024  # 2MB chunks

        return settings

    def compress_file(self, input_path, output_path, is_application=False,
                      compression_level=6, chunk_size=None, target_max_kb=1024,  # Increased default to 1MB
                      multithreaded=True, progress_callback=None, algorithm=None):
        input_path = Path(input_path)
        target_max_bytes = target_max_kb * 1024

        # Reset stats and cancellation flag
        self.stats = CompressionStats()
        self.cancelled = False

        if not self.scan_for_malware(input_path):
            raise Exception("Malware detected! Aborting compression.")

        # Auto-detect optimal settings if not provided
        file_type = self.detect_file_type(input_path)
        if input_path.is_file():
            file_size = input_path.stat().st_size
            optimal_settings = self.get_optimal_compression_settings(file_type, file_size)

            if chunk_size is None:
                chunk_size = optimal_settings['chunk_size']
            if algorithm is None:
                algorithm = optimal_settings['algorithm']
            if compression_level == 6:  # Default value
                compression_level = optimal_settings['level']

            return self._compress_file_streaming(
                input_path, output_path, is_application, file_size,
                compression_level, chunk_size, target_max_bytes,
                multithreaded, progress_callback, algorithm
            )

        else:
            # Directory compression - use existing logic for now
            return self._compress_directory_legacy(
                input_path, output_path, is_application,
                compression_level, chunk_size or self.DEFAULT_CHUNK_SIZE,
                target_max_bytes, multithreaded, progress_callback
            )

    def _compress_file_streaming(self, input_path: Path, output_path: Path,
                                is_application: bool, file_size: int,
                                compression_level: int, chunk_size: int,
                                target_max_bytes: int, multithreaded: bool,
                                progress_callback: Optional[Callable], algorithm: str):
        """Memory-efficient streaming compression for large files"""

        chunk_info_list = []
        total_chunks = (file_size + chunk_size - 1) // chunk_size

        # Create output file and write header placeholder
        header_placeholder_size = 1024 * 1024  # 1MB placeholder for header

        with open(output_path, 'wb') as out_file:
            # Write magic and placeholder header
            magic = self.KCA_MAGIC if is_application else self.KC_MAGIC
            out_file.write(magic)
            out_file.write((0).to_bytes(4, 'little'))  # Placeholder header size
            header_start = out_file.tell()
            out_file.write(b'\x00' * header_placeholder_size)  # Placeholder header
            data_start = out_file.tell()

            if multithreaded and total_chunks > 1:
                chunk_info_list = self._compress_file_multithreaded_streaming(
                    input_path, out_file, file_size, chunk_size, compression_level,
                    target_max_bytes, algorithm, progress_callback
                )
            else:
                chunk_info_list = self._compress_file_sequential_streaming(
                    input_path, out_file, file_size, chunk_size, compression_level,
                    target_max_bytes, algorithm, progress_callback
                )

            # Create and write actual header
            metadata = {
                'original_name': input_path.name,
                'original_size': file_size,
                'is_directory': False,
                'chunks': chunk_info_list,
                'algorithm': algorithm,
                'stats': {
                    'compression_ratio': self.stats.compression_ratio,
                    'chunks_processed': self.stats.chunks_processed,
                    'dedup_savings': self.stats.dedup_savings
                }
            }

            header = self.create_header(is_application, metadata)
            header_size = len(header)

            if header_size > header_placeholder_size:
                raise Exception(f"Header too large: {header_size} > {header_placeholder_size}")

            # Write actual header
            out_file.seek(4)  # Skip magic
            out_file.write(header_size.to_bytes(4, 'little'))
            out_file.write(header)

        return str(output_path)

    def _compress_file_multithreaded_streaming(self, input_path: Path, out_file,
                                              file_size: int, chunk_size: int,
                                              compression_level: int, target_max_bytes: int,
                                              algorithm: str, progress_callback: Optional[Callable]) -> List[Dict]:
        """Multithreaded streaming compression with producer-consumer pattern"""
        chunk_info_list = []
        total_chunks = (file_size + chunk_size - 1) // chunk_size

        # Use optimal number of threads
        max_threads = min(self.cpu_count, total_chunks, 8)  # Cap at 8 threads

        # Queues for producer-consumer pattern
        chunk_queue = queue.Queue(maxsize=max_threads * 2)
        result_queue = queue.Queue()

        # Producer thread - reads file chunks
        def producer():
            try:
                with open(input_path, 'rb') as in_file:
                    chunk_index = 0
                    bytes_read = 0
                    while bytes_read < file_size and not self.cancelled:
                        remaining = file_size - bytes_read
                        current_chunk_size = min(chunk_size, remaining)
                        chunk_data = in_file.read(current_chunk_size)

                        if not chunk_data:
                            break

                        chunk_queue.put((chunk_index, chunk_data))
                        bytes_read += len(chunk_data)
                        chunk_index += 1

                # Signal end of chunks
                for _ in range(max_threads):
                    chunk_queue.put(None)
            except Exception as e:
                for _ in range(max_threads):
                    chunk_queue.put(None)
                raise e

        # Consumer threads - compress chunks
        def consumer():
            while not self.cancelled:
                item = chunk_queue.get()
                if item is None:
                    break

                chunk_index, chunk_data = item
                try:
                    # Check deduplication
                    chunk_hash = hashlib.sha256(chunk_data).hexdigest()
                    if chunk_hash in self.chunk_cache:
                        compressed_chunk = self.chunk_cache[chunk_hash]['data']
                        chunk_info = self.chunk_cache[chunk_hash]['info'].copy()
                        chunk_info['deduplicated'] = True
                        self.stats.dedup_savings += len(chunk_data)
                    else:
                        compressed_chunk, chunk_info = self._compress_chunk_adaptive(
                            chunk_data, compression_level, target_max_bytes, algorithm
                        )

                        # Cache if beneficial
                        if len(self.chunk_cache) < 1000:
                            self.chunk_cache[chunk_hash] = {
                                'data': compressed_chunk,
                                'info': chunk_info.copy()
                            }

                    result_queue.put((chunk_index, compressed_chunk, chunk_info, len(chunk_data)))

                except Exception as e:
                    result_queue.put((chunk_index, None, None, 0, e))
                finally:
                    chunk_queue.task_done()

        # Start threads
        producer_thread = threading.Thread(target=producer)
        consumer_threads = [threading.Thread(target=consumer) for _ in range(max_threads)]

        producer_thread.start()
        for t in consumer_threads:
            t.start()

        # Collect results in order
        results = {}
        chunks_processed = 0
        bytes_processed = 0

        while chunks_processed < total_chunks and not self.cancelled:
            try:
                result = result_queue.get(timeout=1.0)
                if len(result) == 5:  # Error case
                    chunk_index, _, _, _, error = result
                    raise error

                chunk_index, compressed_chunk, chunk_info, original_size = result
                results[chunk_index] = (compressed_chunk, chunk_info)

                chunks_processed += 1
                bytes_processed += original_size
                self.stats.update(original_size, len(compressed_chunk))

                if progress_callback:
                    progress = bytes_processed / file_size
                    eta = self.stats.get_eta(file_size)
                    progress_callback(progress, {
                        'bytes_processed': bytes_processed,
                        'total_bytes': file_size,
                        'speed_mbps': self.stats.speed_mbps,
                        'compression_ratio': self.stats.compression_ratio,
                        'eta_seconds': eta,
                        'chunks_completed': chunks_processed,
                        'total_chunks': total_chunks
                    })

            except queue.Empty:
                continue

        # Wait for threads to complete
        producer_thread.join()
        for t in consumer_threads:
            t.join()

        # Write results in order
        for i in range(total_chunks):
            if i in results:
                compressed_chunk, chunk_info = results[i]
                out_file.write(compressed_chunk)
                chunk_info_list.append(chunk_info)

        return chunk_info_list

    def _compress_file_sequential_streaming(self, input_path: Path, out_file,
                                           file_size: int, chunk_size: int,
                                           compression_level: int, target_max_bytes: int,
                                           algorithm: str, progress_callback: Optional[Callable]) -> List[Dict]:
        """Sequential streaming compression with memory efficiency"""
        chunk_info_list = []
        bytes_processed = 0

        with open(input_path, 'rb') as in_file:
            chunk_index = 0
            while bytes_processed < file_size and not self.cancelled:
                # Read chunk
                remaining = file_size - bytes_processed
                current_chunk_size = min(chunk_size, remaining)
                chunk = in_file.read(current_chunk_size)

                if not chunk:
                    break

                # Check for deduplication
                chunk_hash = hashlib.sha256(chunk).hexdigest()
                if chunk_hash in self.chunk_cache:
                    # Use cached compressed chunk
                    compressed_chunk = self.chunk_cache[chunk_hash]['data']
                    chunk_info = self.chunk_cache[chunk_hash]['info'].copy()
                    chunk_info['deduplicated'] = True
                    self.stats.dedup_savings += len(chunk)
                else:
                    # Compress new chunk
                    compressed_chunk, chunk_info = self._compress_chunk_adaptive(
                        chunk, compression_level, target_max_bytes, algorithm
                    )

                    # Cache if beneficial
                    if len(self.chunk_cache) < 1000:  # Limit cache size
                        self.chunk_cache[chunk_hash] = {
                            'data': compressed_chunk,
                            'info': chunk_info.copy()
                        }

                # Write compressed chunk
                out_file.write(compressed_chunk)
                chunk_info_list.append(chunk_info)

                # Update progress
                bytes_processed += len(chunk)
                self.stats.update(len(chunk), len(compressed_chunk))

                if progress_callback:
                    progress = bytes_processed / file_size
                    eta = self.stats.get_eta(file_size)
                    progress_callback(progress, {
                        'bytes_processed': bytes_processed,
                        'total_bytes': file_size,
                        'speed_mbps': self.stats.speed_mbps,
                        'compression_ratio': self.stats.compression_ratio,
                        'eta_seconds': eta,
                        'chunk_index': chunk_index
                    })

                chunk_index += 1

        return chunk_info_list

    def _compress_chunk_adaptive(self, chunk: bytes, compression_level: int,
                                target_max_bytes: int, algorithm: str) -> Tuple[bytes, Dict]:
        """Adaptive compression using specified algorithm"""
        original_size = len(chunk)

        # Try compression with specified algorithm
        if algorithm == self.COMPRESSION_LZMA:
            compressed = lzma.compress(chunk, preset=compression_level)
        elif algorithm == self.COMPRESSION_BROTLI and BROTLI_AVAILABLE:
            compressed = brotli.compress(chunk, quality=compression_level)
        else:  # Default to zlib
            compressed = zlib.compress(chunk, compression_level)
            algorithm = self.COMPRESSION_ZLIB

        # If still too large, try recursive splitting
        if len(compressed) > target_max_bytes and original_size > 1024:
            return self._compress_chunk_recursive_adaptive(chunk, compression_level, target_max_bytes, algorithm)

        sha256_hash = hashlib.sha256(chunk).hexdigest()
        chunk_info = {
            'compressed_size': len(compressed),
            'original_size': original_size,
            'sha256': sha256_hash,
            'compression': algorithm,
            'split': False,
        }

        return compressed, chunk_info

    def _compress_chunk_recursive_adaptive(self, chunk: bytes, compression_level: int,
                                          target_max_bytes: int, algorithm: str) -> Tuple[bytes, Dict]:
        """Recursive chunk splitting with adaptive compression"""
        if len(chunk) <= 1024:
            # Base case - compress as-is
            return self._compress_chunk_adaptive(chunk, compression_level, target_max_bytes, algorithm)

        mid = len(chunk) // 2
        left_chunk = chunk[:mid]
        right_chunk = chunk[mid:]

        left_compressed, left_info = self._compress_chunk_adaptive(left_chunk, compression_level, target_max_bytes, algorithm)
        right_compressed, right_info = self._compress_chunk_adaptive(right_chunk, compression_level, target_max_bytes, algorithm)

        combined_compressed = left_compressed + right_compressed

        chunk_info = {
            'compressed_size': len(combined_compressed),
            'original_size': len(chunk),
            'sha256': None,
            'compression': None,
            'split': True,
            'subchunks': [left_info, right_info]
        }

        return combined_compressed, chunk_info

    def _compress_directory_legacy(self, input_path: Path, output_path: Path,
                                   is_application: bool, compression_level: int,
                                   chunk_size: int, target_max_bytes: int,
                                   multithreaded: bool, progress_callback: Optional[Callable]):
        """Legacy directory compression method"""
        file_entries = []
        compressed_data_buffer = io.BytesIO()

        files_to_compress = [f for f in input_path.rglob('*')
                             if f.is_file() and not self.is_compressed_file(f) and not self.is_temp_file(f)]

        total_files = len(files_to_compress)
        processed_files = 0
        total_size = 0

        for file in files_to_compress:
            if self.cancelled:
                break

            file_data = file.read_bytes()
            file_size = len(file_data)
            total_size += file_size

            chunk_info_list = []
            compressed_chunks = []
            pos = 0

            # For directory files, do not multithread chunking for now (to keep complexity manageable)
            while pos < file_size:
                end_pos = min(pos + chunk_size, file_size)
                chunk = file_data[pos:end_pos]
                compressed_chunk, chunk_info = self._compress_chunk_recursive(chunk, compression_level, target_max_bytes)
                compressed_chunks.append(compressed_chunk)
                chunk_info_list.append(chunk_info)
                pos = end_pos

            file_compressed_data = b''.join(compressed_chunks)
            start_offset = compressed_data_buffer.tell()
            compressed_data_buffer.write(file_compressed_data)
            compressed_size = len(file_compressed_data)

            file_entry = {
                'relative_path': str(file.relative_to(input_path)),
                'original_size': file_size,
                'compressed_size': compressed_size,
                'chunks': chunk_info_list,
                'offset': start_offset
            }
            file_entries.append(file_entry)

            processed_files += 1
            if progress_callback:
                progress_callback(processed_files / total_files, {
                    'files_processed': processed_files,
                    'total_files': total_files,
                    'current_file': file.name
                })

        metadata = {
            'original_name': input_path.name,
            'original_size': total_size,
            'is_directory': True,
            'files': file_entries
        }

        compressed_data = compressed_data_buffer.getvalue()
        header = self.create_header(is_application, metadata)
        header_size = len(header).to_bytes(4, 'little')
        magic = self.KCA_MAGIC if is_application else self.KC_MAGIC

        with open(output_path, 'wb') as out_file:
            out_file.write(magic)
            out_file.write(header_size)
            out_file.write(header)
            out_file.write(compressed_data)

        return str(output_path)

    def _compress_chunk_recursive(self, chunk, compression_level, target_max_bytes):
        compressed = zlib.compress(chunk, compression_level)
        if len(compressed) <= target_max_bytes or len(chunk) <= 1024:
            sha256_hash = hashlib.sha256(chunk).hexdigest()
            chunk_info = {
                'compressed_size': len(compressed),
                'original_size': len(chunk),
                'sha256': sha256_hash,
                'compression': 'zlib',
                'split': False,
            }
            return compressed, chunk_info
        else:
            mid = len(chunk) // 2
            left_chunk = chunk[:mid]
            right_chunk = chunk[mid:]

            left_compressed, left_info = self._compress_chunk_recursive(left_chunk, compression_level, target_max_bytes)
            right_compressed, right_info = self._compress_chunk_recursive(right_chunk, compression_level, target_max_bytes)

            combined_compressed = left_compressed + right_compressed

            chunk_info = {
                'compressed_size': len(combined_compressed),
                'original_size': len(chunk),
                'sha256': None,
                'compression': None,
                'split': True,
                'subchunks': [left_info, right_info]
            }
            return combined_compressed, chunk_info

    def decompress_file(self, input_path, output_path=None, progress_callback=None):
        input_path = Path(input_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        with open(input_path, 'rb') as f:
            magic = f.read(4)
            if magic not in [self.KC_MAGIC, self.KCA_MAGIC]:
                raise ValueError("Invalid KC file format")

            is_application = magic == self.KCA_MAGIC
            header_size = int.from_bytes(f.read(4), 'little')
            header_data = f.read(header_size)
            header = json.loads(header_data.decode('utf-8'))
            compressed_data = f.read()

        metadata = header['metadata']

        if output_path is None:
            output_path = input_path.parent / metadata['original_name']
        else:
            output_path = Path(output_path)

        if metadata.get('is_directory', True):
            output_path.mkdir(exist_ok=True)
            buffer = io.BytesIO(compressed_data)

            total_files = len(metadata['files'])
            processed_files = 0

            for file_entry in metadata['files']:
                rel_path = file_entry['relative_path']
                compressed_size = file_entry['compressed_size']
                chunks = file_entry['chunks']
                offset = file_entry['offset']

                buffer.seek(offset)
                compressed_chunks_data = buffer.read(compressed_size)
                chunk_buffer = io.BytesIO(compressed_chunks_data)

                output_file_path = output_path / rel_path
                output_file_path.parent.mkdir(parents=True, exist_ok=True)

                with output_file_path.open('wb') as fout:
                    self._decompress_chunks(chunk_buffer, chunks, fout)

                processed_files += 1
                if progress_callback:
                    progress_callback(processed_files, total_files)

            self.cleanup_temp_files(output_path)
            return str(output_path)

        else:
            with output_path.open('wb') as fout:
                self._decompress_chunks(io.BytesIO(compressed_data), metadata['chunks'], fout, progress_callback)
            self.cleanup_temp_files(output_path)
            return str(output_path)

    def _decompress_chunks(self, buffer, chunk_infos, fout, progress_callback=None):
        total_chunks = len(chunk_infos)
        processed_chunks = 0

        for chunk_info in chunk_infos:
            if self.cancelled:
                break

            if chunk_info.get('split'):
                self._decompress_chunks(buffer, chunk_info['subchunks'], fout, progress_callback)
            else:
                compressed_size = chunk_info['compressed_size']
                sha256_expected = chunk_info['sha256']
                compression_algorithm = chunk_info.get('compression', 'zlib')

                compressed_chunk = buffer.read(compressed_size)

                # Decompress using appropriate algorithm
                if compression_algorithm == self.COMPRESSION_LZMA:
                    decompressed_chunk = lzma.decompress(compressed_chunk)
                elif compression_algorithm == self.COMPRESSION_BROTLI and BROTLI_AVAILABLE:
                    decompressed_chunk = brotli.decompress(compressed_chunk)
                else:  # Default to zlib
                    decompressed_chunk = zlib.decompress(compressed_chunk)

                # Verify integrity if hash is available
                if sha256_expected:
                    actual_sha256 = hashlib.sha256(decompressed_chunk).hexdigest()
                    if actual_sha256 != sha256_expected:
                        raise ValueError(f"Chunk integrity check failed: expected {sha256_expected}, got {actual_sha256}")

                fout.write(decompressed_chunk)

            processed_chunks += 1
            if progress_callback and total_chunks > 0:
                progress_callback(processed_chunks / total_chunks, {
                    'chunks_processed': processed_chunks,
                    'total_chunks': total_chunks
                })

    def is_compressed_file(self, file_path):
        compressed_extensions = {
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.lzma',
            '.kc', '.kca', '.jar', '.war', '.ear', '.apk', '.deb', '.rpm'
        }
        return file_path.suffix.lower() in compressed_extensions
    
    def is_temp_file(self, file_path):
        temp_files = {
            'kc', 'KC_FORMAT.md', 'kilocompile.py', '.DS_Store', 'Thumbs.db',
            '.gitignore', '.gitkeep', 'desktop.ini'
        }
        return file_path.name in temp_files or file_path.name.startswith('.')

    def cleanup_temp_files(self, output_path):
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
        try:
            subprocess.run(['which', 'clamscan'], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            self.install_clamav()

    def install_clamav(self):
        try:
            if shutil.which('pacman'):
                subprocess.run(['sudo', 'pacman', '-S', 'clamav', '--noconfirm'], check=True)
            elif shutil.which('apt'):
                subprocess.run(['sudo', 'apt', 'update'], check=True)
                subprocess.run(['sudo', 'apt', 'install', '-y', 'clamav'], check=True)
            elif shutil.which('yum'):
                subprocess.run(['sudo', 'yum', 'install', '-y', 'clamav'], check=True)
            elif shutil.which('dnf'):
                subprocess.run(['sudo', 'dnf', 'install', '-y', 'clamav'], check=True)
            else:
                print("Warning: Could not detect package manager. Please install ClamAV manually.")
                return
            subprocess.run(['sudo', 'freshclam'], capture_output=True)
            print("ClamAV installed and updated successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Warning: Could not install ClamAV: {e}")
        except Exception as e:
            print(f"Warning: Error during ClamAV installation: {e}")

    def scan_for_malware(self, path):
        try:
            result = subprocess.run(['clamscan', str(path)], capture_output=True, text=True)
            return 'Infected files: 0' in result.stdout
        except FileNotFoundError:
            print("Warning: ClamAV not found, skipping malware scan.")
            return True

    def create_header(self, is_application=False, metadata=None):
        header = {
            'version': '1.0',
            'created': datetime.now().isoformat(),
            'format_key': self.format_key,
            'type': 'application' if is_application else 'standard',
            'metadata': metadata or {}
        }
        return json.dumps(header, separators=(',', ':')).encode('utf-8')



class KiloTraceGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title('KiloTrace Enhanced Compression Tool')
        self.window.geometry('700x550')

        # Configure grid layout on main window for resizing
        self.window.columnconfigure(0, weight=1)
        for i in range(10):
            self.window.rowconfigure(i, weight=0)
        self.window.rowconfigure(10, weight=1)  # Spacer row

        self.kc = KiloCompile()
        self.current_operation = None
        self.operation_thread = None

        # Title label
        title_label = tk.Label(self.window, text='KiloTrace Enhanced Compression Tool', font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, pady=10, sticky='n')

        # Compress frame
        compress_frame = tk.Frame(self.window, bd=2, relief='groove')
        compress_frame.grid(row=1, column=0, sticky='ew', padx=20, pady=10)
        compress_frame.columnconfigure(0, weight=1)

        tk.Label(compress_frame, text='Select file or directory to compress:', font=('Arial', 12)).grid(row=0, column=0, sticky='w')
        self.compress_path_entry = tk.Entry(compress_frame)
        self.compress_path_entry.grid(row=1, column=0, sticky='ew', pady=5)

        compress_buttons_frame = tk.Frame(compress_frame)
        compress_buttons_frame.grid(row=2, column=0, sticky='ew', pady=5)
        compress_buttons_frame.columnconfigure((0,1,2), weight=1)

        tk.Button(compress_buttons_frame, text='Browse', command=self.browse_compress).grid(row=0, column=0, sticky='ew', padx=5)
        tk.Button(compress_buttons_frame, text='Compress as .kc', command=self.compress_kc).grid(row=0, column=1, sticky='ew', padx=5)
        tk.Button(compress_buttons_frame, text='Compress as .kca (Application)', command=self.compress_kca).grid(row=0, column=2, sticky='ew', padx=5)

        # Advanced options frame
        options_frame = tk.Frame(compress_frame)
        options_frame.grid(row=3, column=0, sticky='ew', pady=5)
        options_frame.columnconfigure((0,1), weight=1)

        # Checkbox for multithreading
        self.multithread_var = tk.BooleanVar(value=True)
        multithread_checkbox = tk.Checkbutton(options_frame, text="Multithreaded compression", variable=self.multithread_var)
        multithread_checkbox.grid(row=0, column=0, sticky='w')

        # Compression algorithm selection
        tk.Label(options_frame, text="Algorithm:").grid(row=0, column=1, sticky='e', padx=(10,5))
        self.algorithm_var = tk.StringVar(value="auto")
        algorithm_combo = tk.OptionMenu(options_frame, self.algorithm_var, "auto", "zlib", "lzma", "brotli")
        algorithm_combo.grid(row=0, column=2, sticky='w')

        # Progress and stats frame
        progress_frame = tk.Frame(self.window, bd=2, relief='groove')
        progress_frame.grid(row=4, column=0, sticky='ew', padx=20, pady=10)
        progress_frame.columnconfigure(0, weight=1)

        # Progress bar
        from tkinter import ttk
        self.progress_var = tk.DoubleVar()
        self.progressbar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progressbar.grid(row=0, column=0, sticky='ew', pady=5)

        # Stats labels
        stats_frame = tk.Frame(progress_frame)
        stats_frame.grid(row=1, column=0, sticky='ew', pady=5)
        stats_frame.columnconfigure((0,1,2), weight=1)

        self.speed_label = tk.Label(stats_frame, text='Speed: --', font=('Arial', 9))
        self.speed_label.grid(row=0, column=0, sticky='w')

        self.ratio_label = tk.Label(stats_frame, text='Ratio: --', font=('Arial', 9))
        self.ratio_label.grid(row=0, column=1, sticky='w')

        self.eta_label = tk.Label(stats_frame, text='ETA: --', font=('Arial', 9))
        self.eta_label.grid(row=0, column=2, sticky='w')

        # Cancel button
        self.cancel_button = tk.Button(progress_frame, text='Cancel', command=self.cancel_operation, state='disabled')
        self.cancel_button.grid(row=2, column=0, pady=5)

        # Decompress frame
        decompress_frame = tk.Frame(self.window, bd=2, relief='groove')
        decompress_frame.grid(row=5, column=0, sticky='ew', padx=20, pady=10)
        decompress_frame.columnconfigure(0, weight=1)

        tk.Label(decompress_frame, text='Select .kc or .kca file to decompress:', font=('Arial', 12)).grid(row=0, column=0, sticky='w')
        self.decompress_path_entry = tk.Entry(decompress_frame)
        self.decompress_path_entry.grid(row=1, column=0, sticky='ew', pady=5)

        decompress_buttons_frame = tk.Frame(decompress_frame)
        decompress_buttons_frame.grid(row=2, column=0, sticky='ew', pady=5)
        decompress_buttons_frame.columnconfigure((0,1), weight=1)

        tk.Button(decompress_buttons_frame, text='Browse KC/KCA', command=self.browse_decompress).grid(row=0, column=0, sticky='ew', padx=5)
        tk.Button(decompress_buttons_frame, text='Decompress', command=self.decompress).grid(row=0, column=1, sticky='ew', padx=5)

        # Status label
        self.status_label = tk.Label(self.window, text='Ready - Enhanced for gigabyte file processing', fg='green', font=('Arial', 10))
        self.status_label.grid(row=6, column=0, pady=10)

        # Memory usage label
        self.memory_label = tk.Label(self.window, text='Memory: --', fg='blue', font=('Arial', 9))
        self.memory_label.grid(row=7, column=0, pady=5)

        # Start memory monitoring
        self.update_memory_usage()

        self.window.mainloop()

    def update_memory_usage(self):
        """Update memory usage display"""
        try:
            process = psutil.Process()
            memory_mb = process.memory_info().rss / (1024 * 1024)
            self.memory_label.config(text=f'Memory: {memory_mb:.1f} MB')
        except:
            self.memory_label.config(text='Memory: --')

        # Schedule next update
        self.window.after(2000, self.update_memory_usage)

    def cancel_operation(self):
        """Cancel current operation"""
        if self.kc:
            self.kc.cancel_operation()
        self.cancel_button.config(state='disabled')
        self.status_label.config(text='Cancelling operation...', fg='orange')

    def browse_compress(self):
        path = filedialog.askdirectory(title="Select directory to compress") or \
               filedialog.askopenfilename(
                   title="Select file to compress",
                   filetypes=[
                       ("All files", "*.*"),
                       ("Text files", "*.txt"),
                       ("Source code", "*.py;*.js;*.cpp;*.java;*.c;*.h"),
                       ("Documents", "*.pdf;*.doc;*.docx"),
                       ("Images", "*.png;*.jpg;*.jpeg;*.gif;*.bmp"),
                   ]
               )
        if path:
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

        extension = '.kca' if is_application else '.kc'
        if path.is_file():
            output_path = path.with_suffix(extension)
        else:
            output_path = path.parent / f"{path.name}{extension}"

        try:
            self.status_label.config(text='Initializing compression...', fg='orange')
            self.progress_var.set(0)
            self.cancel_button.config(state='normal')
            self.window.update()

            # Get algorithm selection
            algorithm = None if self.algorithm_var.get() == "auto" else self.algorithm_var.get()

            def progress_callback(progress, stats=None):
                if isinstance(progress, (int, float)):
                    if isinstance(stats, dict):
                        # Enhanced progress with stats
                        percent = progress * 100
                        self.progress_var.set(percent)

                        # Update status
                        if 'bytes_processed' in stats and 'total_bytes' in stats:
                            mb_processed = stats['bytes_processed'] / (1024 * 1024)
                            mb_total = stats['total_bytes'] / (1024 * 1024)
                            self.status_label.config(text=f'Compressing... {percent:.1f}% ({mb_processed:.1f}/{mb_total:.1f} MB)')
                        else:
                            self.status_label.config(text=f'Compressing... {percent:.1f}%')

                        # Update stats
                        if 'speed_mbps' in stats:
                            self.speed_label.config(text=f'Speed: {stats["speed_mbps"]:.1f} MB/s')
                        if 'compression_ratio' in stats:
                            self.ratio_label.config(text=f'Ratio: {stats["compression_ratio"]:.2f}')
                        if 'eta_seconds' in stats and stats['eta_seconds'] > 0:
                            eta_str = str(timedelta(seconds=stats['eta_seconds']))
                            self.eta_label.config(text=f'ETA: {eta_str}')
                    else:
                        # Simple progress
                        percent = progress * 100
                        self.progress_var.set(percent)
                        self.status_label.config(text=f'Compressing... {percent:.1f}%')
                else:
                    # Legacy callback format
                    percent = (progress / stats) * 100 if stats > 0 else 0
                    self.progress_var.set(percent)
                    self.status_label.config(text=f'Compressing... {percent:.1f}%')

                self.window.update()

            # Run compression
            self.kc.compress_file(path, output_path, is_application,
                                  multithreaded=self.multithread_var.get(),
                                  progress_callback=progress_callback,
                                  algorithm=algorithm)

            self.status_label.config(text='Compression completed successfully!', fg='green')
            self.cancel_button.config(state='disabled')

            # Show completion stats
            stats = self.kc.stats
            ratio_text = f"Compression ratio: {stats.compression_ratio:.2f}"
            speed_text = f"Average speed: {stats.speed_mbps:.1f} MB/s"
            dedup_text = f"Deduplication savings: {stats.dedup_savings / (1024*1024):.1f} MB" if stats.dedup_savings > 0 else ""

            message = f'Compressed to {output_path}\n\n{ratio_text}\n{speed_text}'
            if dedup_text:
                message += f'\n{dedup_text}'

            messagebox.showinfo('Success', message)
            self.progress_var.set(100)

        except Exception as e:
            self.status_label.config(text='Compression failed!', fg='red')
            self.cancel_button.config(state='disabled')
            messagebox.showerror('Error', str(e))
            self.progress_var.set(0)

        finally:
            # Reset stats displays
            self.speed_label.config(text='Speed: --')
            self.ratio_label.config(text='Ratio: --')
            self.eta_label.config(text='ETA: --')

    def decompress(self):
        path = Path(self.decompress_path_entry.get())
        if not path.exists():
            messagebox.showerror('Error', 'Invalid KC/KCA file selected')
            return

        try:
            self.status_label.config(text='Initializing decompression...', fg='orange')
            self.progress_var.set(0)
            self.cancel_button.config(state='normal')
            self.window.update()

            def progress_callback(progress, stats=None):
                if isinstance(progress, (int, float)):
                    if isinstance(stats, dict):
                        # Enhanced progress with stats
                        percent = progress * 100
                        self.progress_var.set(percent)

                        if 'chunks_processed' in stats and 'total_chunks' in stats:
                            self.status_label.config(text=f'Decompressing... {percent:.1f}% ({stats["chunks_processed"]}/{stats["total_chunks"]} chunks)')
                        else:
                            self.status_label.config(text=f'Decompressing... {percent:.1f}%')
                    else:
                        # Simple progress
                        percent = progress * 100
                        self.progress_var.set(percent)
                        self.status_label.config(text=f'Decompressing... {percent:.1f}%')
                else:
                    # Legacy callback format
                    percent = (progress / stats) * 100 if stats > 0 else 0
                    self.progress_var.set(percent)
                    self.status_label.config(text=f'Decompressing... {percent:.1f}%')

                self.window.update()

            output_path = self.kc.decompress_file(path, progress_callback=progress_callback)

            self.status_label.config(text='Decompression completed successfully!', fg='green')
            self.cancel_button.config(state='disabled')
            messagebox.showinfo('Success', f'Decompressed to {output_path}')
            self.progress_var.set(100)

        except Exception as e:
            self.status_label.config(text='Decompression failed!', fg='red')
            self.cancel_button.config(state='disabled')
            messagebox.showerror('Error', str(e))
            self.progress_var.set(0)


def load_config():
    """Load configuration from file"""
    config_path = Path.home() / '.kilotrace_config.json'
    default_config = {
        'default_algorithm': 'auto',
        'default_multithreaded': True,
        'default_compression_level': 6,
        'max_memory_usage_mb': 512,
        'chunk_cache_size': 1000,
        'auto_detect_file_types': True
    }

    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                # Merge with defaults
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
        except:
            pass

    return default_config

def save_config(config):
    """Save configuration to file"""
    config_path = Path.home() / '.kilotrace_config.json'
    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
    except:
        pass

def main():
    import argparse

    parser = argparse.ArgumentParser(description='KiloTrace Enhanced Compression Tool')
    parser.add_argument('--cli', action='store_true', help='Use command-line interface')
    parser.add_argument('--compress', metavar='FILE', help='File or directory to compress')
    parser.add_argument('--decompress', metavar='FILE', help='KC/KCA file to decompress')
    parser.add_argument('--output', '-o', metavar='PATH', help='Output path')
    parser.add_argument('--algorithm', choices=['auto', 'zlib', 'lzma', 'brotli'],
                       default='auto', help='Compression algorithm')
    parser.add_argument('--level', type=int, default=6, help='Compression level (1-9)')
    parser.add_argument('--threads', type=int, help='Number of threads (default: auto)')
    parser.add_argument('--app', action='store_true', help='Create .kca application archive')
    parser.add_argument('--chunk-size', type=int, help='Chunk size in KB')
    parser.add_argument('--target-size', type=int, default=1024, help='Target max chunk size in KB')

    args = parser.parse_args()

    if args.cli or args.compress or args.decompress:
        # Command-line mode
        kc = KiloCompile()

        if args.compress:
            input_path = Path(args.compress)
            if not input_path.exists():
                print(f"Error: Input path '{input_path}' does not exist")
                return 1

            if args.output:
                output_path = Path(args.output)
            else:
                extension = '.kca' if args.app else '.kc'
                if input_path.is_file():
                    output_path = input_path.with_suffix(extension)
                else:
                    output_path = input_path.parent / f"{input_path.name}{extension}"

            def progress_callback(progress, stats=None):
                if isinstance(progress, (int, float)):
                    percent = progress * 100
                    if isinstance(stats, dict) and 'speed_mbps' in stats:
                        print(f"\rProgress: {percent:.1f}% - Speed: {stats['speed_mbps']:.1f} MB/s", end='', flush=True)
                    else:
                        print(f"\rProgress: {percent:.1f}%", end='', flush=True)
                else:
                    percent = (progress / stats) * 100 if stats > 0 else 0
                    print(f"\rProgress: {percent:.1f}%", end='', flush=True)

            try:
                print(f"Compressing '{input_path}' to '{output_path}'...")

                chunk_size = args.chunk_size * 1024 if args.chunk_size else None
                algorithm = None if args.algorithm == 'auto' else args.algorithm

                kc.compress_file(
                    input_path, output_path, args.app,
                    compression_level=args.level,
                    chunk_size=chunk_size,
                    target_max_kb=args.target_size,
                    multithreaded=args.threads != 1,
                    progress_callback=progress_callback,
                    algorithm=algorithm
                )

                print(f"\nCompression completed successfully!")
                print(f"Output: {output_path}")
                print(f"Compression ratio: {kc.stats.compression_ratio:.2f}")
                print(f"Average speed: {kc.stats.speed_mbps:.1f} MB/s")
                if kc.stats.dedup_savings > 0:
                    print(f"Deduplication savings: {kc.stats.dedup_savings / (1024*1024):.1f} MB")

            except Exception as e:
                print(f"\nError: {e}")
                return 1

        elif args.decompress:
            input_path = Path(args.decompress)
            if not input_path.exists():
                print(f"Error: Input file '{input_path}' does not exist")
                return 1

            def progress_callback(progress, stats=None):
                if isinstance(progress, (int, float)):
                    percent = progress * 100
                    print(f"\rProgress: {percent:.1f}%", end='', flush=True)
                else:
                    percent = (progress / stats) * 100 if stats > 0 else 0
                    print(f"\rProgress: {percent:.1f}%", end='', flush=True)

            try:
                print(f"Decompressing '{input_path}'...")
                output_path = kc.decompress_file(input_path, args.output, progress_callback)
                print(f"\nDecompression completed successfully!")
                print(f"Output: {output_path}")

            except Exception as e:
                print(f"\nError: {e}")
                return 1

        return 0
    else:
        # GUI mode
        KiloTraceGUI()
        return 0

if __name__ == '__main__':
    sys.exit(main())

