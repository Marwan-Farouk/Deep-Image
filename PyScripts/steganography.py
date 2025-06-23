import numpy as np
from PIL import Image
import logging
import zlib
import os
import struct
from typing import Optional, Tuple
import argparse
import time
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
from pathlib import Path

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

class LSBSteganography:
    """Simplified LSB Steganography without randomization."""
    
    def __init__(self, bits_per_pixel=1):
        self.bits_per_pixel = bits_per_pixel
        self.message_header = b'LSBSTEGO'  # 8-byte header
    
    def _validate_image(self, image_path: str) -> Image.Image:
        """Validate and load image file."""
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image file not found: {image_path}")
        
        try:
            img = Image.open(image_path)
            if img.mode not in ['L', 'RGB']:
                logging.info(f"Converting image from {img.mode} to RGB")
                img = img.convert('RGB')
            return img
        except Exception as e:
            raise IOError(f"Failed to load image {image_path}: {e}")
    
    def _prepare_message(self, message: str) -> bytes:
        """Prepare message with compression and length prefix."""
        try:
            msg_bytes = message.encode('utf-8')
            compressed = zlib.compress(msg_bytes, level=9)
            length = len(compressed)
            # Header + length + compressed message
            prepared = self.message_header + struct.pack('<I', length) + compressed
            return prepared
        except Exception as e:
            raise RuntimeError(f"Message preparation failed: {e}")
    
    def _extract_message(self, msg_bytes: bytes) -> str:
        """Extract message from bytes."""
        try:
            if not msg_bytes.startswith(self.message_header):
                raise ValueError("Invalid message header")
            
            header_len = len(self.message_header)
            length = struct.unpack('<I', msg_bytes[header_len:header_len+4])[0]
            compressed = msg_bytes[header_len+4:header_len+4+length]
            msg_bytes = zlib.decompress(compressed)
            return msg_bytes.decode('utf-8')
        except Exception as e:
            raise RuntimeError(f"Message extraction failed: {e}")
    
    def _bytes_to_bits(self, data: bytes) -> str:
        """Convert bytes to binary string."""
        return ''.join(format(byte, '08b') for byte in data)
    
    def _bits_to_bytes(self, bits: str) -> bytes:
        """Convert binary string to bytes."""
        # Pad to multiple of 8 if necessary
        while len(bits) % 8 != 0:
            bits += '0'
        return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
    
    def _embed_bit(self, pixel_value: int, bit: str) -> int:
        """Embed a single bit into the LSB of a pixel value."""
        # Ensure pixel_value is positive integer
        pixel_value = int(pixel_value) & 0xFF  # Keep only 8 bits
        pixel_value = pixel_value & ~1  # Clear LSB (bitwise AND with 11111110)
        pixel_value |= int(bit)  # Set LSB to bit
        return pixel_value & 0xFF  # Ensure result stays in 0-255 range
    
    def _extract_bit(self, pixel_value: int) -> str:
        """Extract the LSB from a pixel value."""
        return str(int(pixel_value) & 1)
    
    def get_capacity_info(self, image_path: str) -> dict:
        """Get capacity information for an image."""
        try:
            img = self._validate_image(image_path)
            img_array = np.array(img)
            
            height, width = img_array.shape[:2]
            channels = 1 if img_array.ndim == 2 else 3
            total_pixels = height * width * channels
            
            # Account for header (8 bytes) + length (4 bytes) = 12 bytes = 96 bits
            overhead_bits = 96
            max_message_bits = total_pixels - overhead_bits
            max_message_chars = max_message_bits // 8
            
            return {
                'image_size': (width, height),
                'total_pixels': total_pixels,
                'overhead_bits': overhead_bits,
                'max_message_bits': max(0, max_message_bits),
                'max_message_chars_approx': max(0, max_message_chars),
                'bits_per_pixel': self.bits_per_pixel
            }
        except Exception as e:
            return {'error': str(e)}
    
    def encode(self, image_path: str, message: str, output_path: str) -> bool:
        """Encode message in image using LSB."""
        try:
            img = self._validate_image(image_path)
            img_array = np.array(img)
            
            # Prepare message
            msg_bytes = self._prepare_message(message)
            msg_bits = self._bytes_to_bits(msg_bytes)
                        
            # Check capacity
            height, width = img_array.shape[:2]
            channels = 1 if img_array.ndim == 2 else 3
            total_capacity = height * width * channels
            
            if len(msg_bits) > total_capacity:
                raise ValueError(f"Message too large ({len(msg_bits)} bits) for image capacity ({total_capacity} bits)")
            
            # Create copy for modification
            stego_array = img_array.copy().astype(np.int32)  # Use int32 to prevent overflow
            
            # Embed bits sequentially
            bit_index = 0
            for row in range(height):
                for col in range(width):
                    if channels == 1:  # Grayscale
                        if bit_index < len(msg_bits):
                            stego_array[row, col] = self._embed_bit(
                                stego_array[row, col], msg_bits[bit_index])
                            bit_index += 1
                    else:  # RGB
                        for channel in range(channels):
                            if bit_index < len(msg_bits):
                                stego_array[row, col, channel] = self._embed_bit(
                                    stego_array[row, col, channel], msg_bits[bit_index])
                                bit_index += 1
                
                if bit_index >= len(msg_bits):
                    break
            
            # Convert back to uint8 and save as PNG
            stego_array = np.clip(stego_array, 0, 255).astype(np.uint8)
            Image.fromarray(stego_array).save(output_path, format='PNG')
            logging.info(f"Message embedded successfully in {output_path}")
            return True
            
        except Exception as e:
            logging.error(f"Encoding error: {e}")
            return False
    
    def decode(self, stego_path: str) -> Optional[str]:
        """Decode message from stego image using LSB."""
        try:
            img = self._validate_image(stego_path)
            img_array = np.array(img)
            
            height, width = img_array.shape[:2]
            channels = 1 if img_array.ndim == 2 else 3
            
            # Extract bits in the exact same order as embedding
            extracted_bits = ""
            
            for row in range(height):
                for col in range(width):
                    if channels == 1:  # Grayscale
                        bit = self._extract_bit(img_array[row, col])
                        extracted_bits += bit
                    else:  # RGB
                        for channel in range(channels):
                            bit = self._extract_bit(img_array[row, col, channel])
                            extracted_bits += bit
                    
                    # Once we have at least 96 bits, try to find the header
                    if len(extracted_bits) >= 96:
                        # Try to parse the first 96 bits as header
                        header_bytes = self._bits_to_bytes(extracted_bits[:96])
                        
                        if header_bytes.startswith(self.message_header):
                            # Found valid header, extract message length
                            try:
                                length = struct.unpack('<I', header_bytes[len(self.message_header):len(self.message_header)+4])[0]
                                total_needed_bits = 96 + (length * 8)
                                # Wait until we have enough bits
                                if len(extracted_bits) >= total_needed_bits:
                                    msg_bits = extracted_bits[:total_needed_bits]
                                    msg_bytes = self._bits_to_bytes(msg_bits)
                                    message = self._extract_message(msg_bytes)
                                    return message
                                    
                            except struct.error:
                                continue  # Invalid header, keep looking
            
            # If we didn't return yet, check if we found a valid header but need more bits
            if len(extracted_bits) >= 96:
                header_bytes = self._bits_to_bytes(extracted_bits[:96])
                if header_bytes.startswith(self.message_header):
                    try:
                        length = struct.unpack('<I', header_bytes[len(self.message_header):len(self.message_header)+4])[0]
                        total_needed_bits = 96 + (length * 8)
                        
                        if len(extracted_bits) >= total_needed_bits:
                            msg_bits = extracted_bits[:total_needed_bits]
                            msg_bytes = self._bits_to_bytes(msg_bits)
                            message = self._extract_message(msg_bytes)
                            return message
                        else:
                            raise ValueError(f"Image too small: need {total_needed_bits} bits, got {len(extracted_bits)}")
                    except struct.error:
                        pass
            
            raise ValueError("No valid message header found")
            
        except Exception as e:
            logging.error(f"Decoding error: {e}")
            return None

class SteganographyAnalyzer:
    """Analysis tools for steganography performance."""
    
    @staticmethod
    def calculate_psnr(original_path: str, stego_path: str) -> float:
        """Calculate Peak Signal-to-Noise Ratio between original and stego images."""
        try:
            orig_img = np.array(Image.open(original_path)).astype(np.float32)
            stego_img = np.array(Image.open(stego_path)).astype(np.float32)
            
            if orig_img.shape != stego_img.shape:
                raise ValueError("Images must have the same dimensions")
            
            mse = np.mean((orig_img - stego_img) ** 2)
            if mse == 0:
                return float('inf')
            
            max_pixel = 255.0
            psnr = 20 * np.log10(max_pixel / np.sqrt(mse))
            return psnr
            
        except Exception as e:
            logging.error(f"PSNR calculation error: {e}")
            return 0.0
    
    @staticmethod
    def benchmark_embedding(stego: LSBSteganography, image_path: str, message: str, output_path: str) -> dict:
        """Benchmark embedding process and analyze results."""
        start_time = time.time()
        
        capacity_info = stego.get_capacity_info(image_path)
        
        success = stego.encode(image_path, message, output_path)
        embed_time = time.time() - start_time
        
        if not success:
            return {'error': 'Embedding failed', 'capacity_info': capacity_info}
        
        start_decode = time.time()
        decoded_message = stego.decode(output_path)
        decode_time = time.time() - start_decode
        
        psnr = SteganographyAnalyzer.calculate_psnr(image_path, output_path)
        
        orig_size = os.path.getsize(image_path)
        stego_size = os.path.getsize(output_path)
        
        return {
            'success': success,
            'message_recovered': decoded_message == message,
            'embed_time': embed_time,
            'decode_time': decode_time,
            'psnr': psnr,
            'original_size': orig_size,
            'stego_size': stego_size,
            'capacity_info': capacity_info,
            'message_length': len(message)
        }

class SteganographyGUI:
    """GUI for LSB Steganography Tool."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("LSB Steganography Tool")
        self.root.geometry("800x700")
        self.root.minsize(600, 500)
        
        # Initialize steganography engine
        self.stego = LSBSteganography()
        
        # Variables
        self.input_image_path = tk.StringVar()
        self.output_image_path = tk.StringVar()
        self.stego_image_path = tk.StringVar()
        
        self.setup_gui()
        
    def setup_gui(self):
        """Setup the GUI layout."""
        # Create notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Encode tab
        encode_frame = ttk.Frame(notebook)
        notebook.add(encode_frame, text="Encode Message")
        self.setup_encode_tab(encode_frame)
        
        # Decode tab
        decode_frame = ttk.Frame(notebook)
        notebook.add(decode_frame, text="Decode Message")
        self.setup_decode_tab(decode_frame)
        
        # Analyze tab
        analyze_frame = ttk.Frame(notebook)
        notebook.add(analyze_frame, text="Analyze Image")
        self.setup_analyze_tab(analyze_frame)
        
        # Benchmark tab
        benchmark_frame = ttk.Frame(notebook)
        notebook.add(benchmark_frame, text="Benchmark")
        self.setup_benchmark_tab(benchmark_frame)
        
    def setup_encode_tab(self, parent):
        """Setup the encode message tab."""
        # Input image selection
        img_frame = ttk.LabelFrame(parent, text="Input Image", padding=10)
        img_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Entry(img_frame, textvariable=self.input_image_path, width=60).pack(side='left', fill='x', expand=True)
        ttk.Button(img_frame, text="Browse", command=self.browse_input_image).pack(side='right', padx=(5,0))
        
        # Message input
        msg_frame = ttk.LabelFrame(parent, text="Message to Hide", padding=10)
        msg_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.message_text = scrolledtext.ScrolledText(msg_frame, height=8, wrap=tk.WORD)
        self.message_text.pack(fill='both', expand=True)
        
        # Message file option
        file_frame = ttk.Frame(msg_frame)
        file_frame.pack(fill='x', pady=(5,0))
        
        ttk.Button(file_frame, text="Load from File", command=self.load_message_file).pack(side='left')
        ttk.Button(file_frame, text="Clear", command=lambda: self.message_text.delete(1.0, tk.END)).pack(side='left', padx=(5,0))
        
        # Output settings
        out_frame = ttk.LabelFrame(parent, text="Output Settings", padding=10)
        out_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Entry(out_frame, textvariable=self.output_image_path, width=60).pack(side='left', fill='x', expand=True)
        ttk.Button(out_frame, text="Save As", command=self.browse_output_image).pack(side='right', padx=(5,0))
        
        # Control buttons
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(btn_frame, text="Check Capacity", command=self.check_capacity).pack(side='left')
        ttk.Button(btn_frame, text="Encode Message", command=self.encode_message).pack(side='right')
        
    def setup_decode_tab(self, parent):
        """Setup the decode message tab."""
        # Input image selection
        img_frame = ttk.LabelFrame(parent, text="Stego Image", padding=10)
        img_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Entry(img_frame, textvariable=self.stego_image_path, width=60).pack(side='left', fill='x', expand=True)
        ttk.Button(img_frame, text="Browse", command=self.browse_stego_image).pack(side='right', padx=(5,0))
        
        # Decoded message display
        msg_frame = ttk.LabelFrame(parent, text="Decoded Message", padding=10)
        msg_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.decoded_text = scrolledtext.ScrolledText(msg_frame, height=12, wrap=tk.WORD, state='disabled')
        self.decoded_text.pack(fill='both', expand=True)
        
        # Control buttons
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(btn_frame, text="Decode Message", command=self.decode_message).pack(side='left')
        ttk.Button(btn_frame, text="Save to File", command=self.save_decoded_message).pack(side='left', padx=(10,0))
        ttk.Button(btn_frame, text="Clear", command=self.clear_decoded_message).pack(side='right')
        
    def setup_analyze_tab(self, parent):
        """Setup the analyze image tab."""
        # Input image selection
        img_frame = ttk.LabelFrame(parent, text="Image to Analyze", padding=10)
        img_frame.pack(fill='x', padx=10, pady=5)
        
        self.analyze_image_path = tk.StringVar()
        ttk.Entry(img_frame, textvariable=self.analyze_image_path, width=60).pack(side='left', fill='x', expand=True)
        ttk.Button(img_frame, text="Browse", command=self.browse_analyze_image).pack(side='right', padx=(5,0))
        
        # Analysis results
        results_frame = ttk.LabelFrame(parent, text="Analysis Results", padding=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.analysis_text = scrolledtext.ScrolledText(results_frame, height=15, wrap=tk.WORD, state='disabled')
        self.analysis_text.pack(fill='both', expand=True)
        
        # Control button
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(btn_frame, text="Analyze Image", command=self.analyze_image).pack(side='left')
        
    def setup_benchmark_tab(self, parent):
        """Setup the benchmark tab."""
        # Input settings
        settings_frame = ttk.LabelFrame(parent, text="Benchmark Settings", padding=10)
        settings_frame.pack(fill='x', padx=10, pady=5)
        
        # Image selection
        img_row = ttk.Frame(settings_frame)
        img_row.pack(fill='x', pady=2)
        ttk.Label(img_row, text="Image:", width=15).pack(side='left')
        self.benchmark_image_path = tk.StringVar()
        ttk.Entry(img_row, textvariable=self.benchmark_image_path, width=45).pack(side='left', fill='x', expand=True)
        ttk.Button(img_row, text="Browse", command=self.browse_benchmark_image).pack(side='right', padx=(5,0))
        
        # Output selection
        out_row = ttk.Frame(settings_frame)
        out_row.pack(fill='x', pady=2)
        ttk.Label(out_row, text="Output:", width=15).pack(side='left')
        self.benchmark_output_path = tk.StringVar(value="benchmark_output.png")
        ttk.Entry(out_row, textvariable=self.benchmark_output_path, width=45).pack(side='left', fill='x', expand=True)
        ttk.Button(out_row, text="Save As", command=self.browse_benchmark_output).pack(side='right', padx=(5,0))
        
        # Test message
        msg_frame = ttk.LabelFrame(parent, text="Test Message", padding=10)
        msg_frame.pack(fill='x', padx=10, pady=5)
        
        self.benchmark_message = tk.Text(msg_frame, height=4, wrap=tk.WORD)
        self.benchmark_message.pack(fill='x')
        self.benchmark_message.insert(1.0, "This is a test message for benchmarking the steganography system performance.")
        
        # Results
        results_frame = ttk.LabelFrame(parent, text="Benchmark Results", padding=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.benchmark_text = scrolledtext.ScrolledText(results_frame, height=10, wrap=tk.WORD, state='disabled')
        self.benchmark_text.pack(fill='both', expand=True)
        
        # Control button
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(btn_frame, text="Run Benchmark", command=self.run_benchmark).pack(side='left')
        
    def browse_input_image(self):
        """Browse for input image."""
        filename = filedialog.askopenfilename(
            title="Select Input Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.tiff"), ("All files", "*.*")]
        )
        if filename:
            self.input_image_path.set(filename)
            # Auto-generate output filename
            if not self.output_image_path.get():
                base = Path(filename).stem
                self.output_image_path.set(f"{base}_stego.png")
    
    def browse_output_image(self):
        """Browse for output image location."""
        filename = filedialog.asksaveasfilename(
            title="Save Stego Image As",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
        )
        if filename:
            self.output_image_path.set(filename)
    
    def browse_stego_image(self):
        """Browse for stego image to decode."""
        filename = filedialog.askopenfilename(
            title="Select Stego Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.tiff"), ("All files", "*.*")]
        )
        if filename:
            self.stego_image_path.set(filename)
    
    def browse_analyze_image(self):
        """Browse for image to analyze."""
        filename = filedialog.askopenfilename(
            title="Select Image to Analyze",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.tiff"), ("All files", "*.*")]
        )
        if filename:
            self.analyze_image_path.set(filename)
    
    def browse_benchmark_image(self):
        """Browse for benchmark image."""
        filename = filedialog.askopenfilename(
            title="Select Benchmark Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.tiff"), ("All files", "*.*")]
        )
        if filename:
            self.benchmark_image_path.set(filename)
    
    def browse_benchmark_output(self):
        """Browse for benchmark output location."""
        filename = filedialog.asksaveasfilename(
            title="Save Benchmark Output As",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
        )
        if filename:
            self.benchmark_output_path.set(filename)
    
    def load_message_file(self):
        """Load message from file."""
        filename = filedialog.askopenfilename(
            title="Load Message from File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.message_text.delete(1.0, tk.END)
                self.message_text.insert(1.0, content)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {e}")
    
    def check_capacity(self):
        """Check image capacity for message."""
        if not self.input_image_path.get():
            messagebox.showwarning("Warning", "Please select an input image first.")
            return
        
        try:
            capacity = self.stego.get_capacity_info(self.input_image_path.get())
            message = self.message_text.get(1.0, tk.END).strip()
            
            if 'error' in capacity:
                messagebox.showerror("Error", f"Capacity analysis failed: {capacity['error']}")
                return
            
            msg = f"Image Capacity Analysis:\n\n"
            msg += f"Image Size: {capacity['image_size'][0]} x {capacity['image_size'][1]}\n"
            msg += f"Total Pixels: {capacity['total_pixels']:,}\n"
            msg += f"Maximum Message Length: ~{capacity['max_message_chars_approx']:,} characters\n\n"
            
            if message:
                msg += f"Current Message Length: {len(message):,} characters\n"
                if len(message) <= capacity['max_message_chars_approx']:
                    msg += "✓ Message fits in image"
                else:
                    msg += "✗ Message too large for image"
            
            messagebox.showinfo("Capacity Analysis", msg)
            
        except Exception as e:
            messagebox.showerror("Error", f"Capacity check failed: {e}")
    
    def encode_message(self):
        """Encode message in image."""
        if not self.input_image_path.get():
            messagebox.showwarning("Warning", "Please select an input image.")
            return
        
        if not self.output_image_path.get():
            messagebox.showwarning("Warning", "Please specify output image path.")
            return
        
        message = self.message_text.get(1.0, tk.END).strip()
        if not message:
            messagebox.showwarning("Warning", "Please enter a message to encode.")
            return
        
        def encode_thread():
            try:
                success = self.stego.encode(
                    self.input_image_path.get(),
                    message,
                    self.output_image_path.get()
                )
                
                if success:
                    self.root.after(0, lambda: messagebox.showinfo("Success", 
                        f"Message encoded successfully!\nOutput saved to: {self.output_image_path.get()}"))
                else:
                    self.root.after(0, lambda: messagebox.showerror("Error", "Encoding failed."))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Encoding failed: {e}"))
        
        threading.Thread(target=encode_thread, daemon=True).start()
    
    def decode_message(self):
        """Decode message from stego image."""
        if not self.stego_image_path.get():
            messagebox.showwarning("Warning", "Please select a stego image.")
            return
        
        def decode_thread():
            try:
                decoded = self.stego.decode(self.stego_image_path.get())
                
                def update_ui():
                    self.decoded_text.config(state='normal')
                    self.decoded_text.delete(1.0, tk.END)
                    
                    if decoded:
                        self.decoded_text.insert(1.0, decoded)
                        messagebox.showinfo("Success", "Message decoded successfully!")
                    else:
                        self.decoded_text.insert(1.0, "No message found or decoding failed.")
                        messagebox.showwarning("Warning", "No message found or decoding failed.")
                    
                    self.decoded_text.config(state='disabled')
                
                self.root.after(0, update_ui)
                
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Decoding failed: {e}"))
        
        threading.Thread(target=decode_thread, daemon=True).start()
    
    def save_decoded_message(self):
        """Save decoded message to file."""
        message = self.decoded_text.get(1.0, tk.END).strip()
        if not message or message == "No message found or decoding failed.":
            messagebox.showwarning("Warning", "No decoded message to save.")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Save Decoded Message",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(message)
                messagebox.showinfo("Success", f"Message saved to: {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save message: {e}")
    
    def clear_decoded_message(self):
        """Clear decoded message display."""
        self.decoded_text.config(state='normal')
        self.decoded_text.delete(1.0, tk.END)
        self.decoded_text.config(state='disabled')
    
    def analyze_image(self):
        """Analyze image capacity and properties."""
        if not self.analyze_image_path.get():
            messagebox.showwarning("Warning", "Please select an image to analyze.")
            return
        
        try:
            capacity = self.stego.get_capacity_info(self.analyze_image_path.get())
            
            self.analysis_text.config(state='normal')
            self.analysis_text.delete(1.0, tk.END)
            
            if 'error' in capacity:
                self.analysis_text.insert(tk.END, f"Analysis failed: {capacity['error']}")
            else:
                analysis_result = "Image Analysis Results:\n"
                analysis_result += "=" * 50 + "\n\n"
                analysis_result += f"Image Dimensions: {capacity['image_size'][0]} x {capacity['image_size'][1]} pixels\n"
                analysis_result += f"Total Pixels: {capacity['total_pixels']:,}\n"
                analysis_result += f"Bits per Pixel: {capacity['bits_per_pixel']}\n\n"
                analysis_result += "Steganography Capacity:\n"
                analysis_result += f"• Header Overhead: {capacity['overhead_bits']} bits\n"
                analysis_result += f"• Available for Message: {capacity['max_message_bits']:,} bits\n"
                analysis_result += f"• Approximate Character Capacity: {capacity['max_message_chars_approx']:,} characters\n\n"
                
                # Calculate file size if available
                try:
                    file_size = os.path.getsize(self.analyze_image_path.get())
                    analysis_result += f"File Size: {file_size:,} bytes ({file_size/1024:.1f} KB)\n"
                except:
                    pass
                
                # Estimate compression efficiency
                if capacity['max_message_chars_approx'] > 0:
                    efficiency = (capacity['max_message_chars_approx'] * 8) / capacity['total_pixels'] * 100
                    analysis_result += f"Storage Efficiency: {efficiency:.2f}% of pixel capacity used\n"
                
                self.analysis_text.insert(tk.END, analysis_result)
            
            self.analysis_text.config(state='disabled')
            
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {e}")
    
    def run_benchmark(self):
        """Run benchmark test."""
        if not self.benchmark_image_path.get():
            messagebox.showwarning("Warning", "Please select a benchmark image.")
            return
        
        message = self.benchmark_message.get(1.0, tk.END).strip()
        if not message:
            messagebox.showwarning("Warning", "Please enter a test message.")
            return
        
        def benchmark_thread():
            try:
                results = SteganographyAnalyzer.benchmark_embedding(
                    self.stego,
                    self.benchmark_image_path.get(),
                    message,
                    self.benchmark_output_path.get()
                )
                
                def update_ui():
                    self.benchmark_text.config(state='normal')
                    self.benchmark_text.delete(1.0, tk.END)
                    
                    if 'error' in results:
                        self.benchmark_text.insert(tk.END, f"Benchmark failed: {results['error']}\n\n")
                        if 'capacity_info' in results:
                            self.benchmark_text.insert(tk.END, "Capacity Info:\n")
                            self.benchmark_text.insert(tk.END, json.dumps(results['capacity_info'], indent=2))
                    else:
                        benchmark_result = "Benchmark Results:\n"
                        benchmark_result += "=" * 50 + "\n\n"
                        benchmark_result += f"✓ Encoding Success: {'Yes' if results['success'] else 'No'}\n"
                        benchmark_result += f"✓ Message Recovery: {'Yes' if results['message_recovered'] else 'No'}\n\n"
                        
                        benchmark_result += "Performance Metrics:\n"
                        benchmark_result += f"• Embedding Time: {results['embed_time']:.3f} seconds\n"
                        benchmark_result += f"• Decoding Time: {results['decode_time']:.3f} seconds\n"
                        benchmark_result += f"• Total Time: {results['embed_time'] + results['decode_time']:.3f} seconds\n\n"
                        
                        benchmark_result += "Quality Metrics:\n"
                        if results['psnr'] == float('inf'):
                            benchmark_result += "• PSNR: ∞ dB (perfect quality)\n"
                        else:
                            benchmark_result += f"• PSNR: {results['psnr']:.2f} dB\n"
                        
                        benchmark_result += "\nFile Size Comparison:\n"
                        benchmark_result += f"• Original: {results['original_size']:,} bytes\n"
                        benchmark_result += f"• Stego: {results['stego_size']:,} bytes\n"
                        size_diff = results['stego_size'] - results['original_size']
                        benchmark_result += f"• Difference: {size_diff:,} bytes ({size_diff/results['original_size']*100:+.2f}%)\n\n"
                        
                        benchmark_result += "Message Statistics:\n"
                        benchmark_result += f"• Message Length: {results['message_length']:,} characters\n"
                        
                        if 'capacity_info' in results:
                            cap = results['capacity_info']
                            usage = (results['message_length'] / cap['max_message_chars_approx']) * 100 if cap['max_message_chars_approx'] > 0 else 0
                            benchmark_result += f"• Capacity Usage: {usage:.1f}%\n"
                            benchmark_result += f"• Remaining Capacity: {cap['max_message_chars_approx'] - results['message_length']:,} characters\n"
                    
                        self.benchmark_text.insert(tk.END, benchmark_result)
                    
                    self.benchmark_text.config(state='disabled')
                    messagebox.showinfo("Complete", "Benchmark completed!")
                
                self.root.after(0, update_ui)
                
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Benchmark failed: {e}"))
        
        threading.Thread(target=benchmark_thread, daemon=True).start()

# Convenience functions (keeping original CLI functions)
def lsb_encode(image_path: str, message: str, output_path: str) -> bool:
    """Simple function to encode a message in an image."""
    stego = LSBSteganography()
    return stego.encode(image_path, message, output_path)

def lsb_decode(stego_path: str) -> Optional[str]:
    """Simple function to decode a message from an image."""
    stego = LSBSteganography()
    return stego.decode(stego_path)

def analyze_image_capacity(image_path: str) -> dict:
    """Analyze image capacity for LSB steganography."""
    stego = LSBSteganography()
    return stego.get_capacity_info(image_path)

# Command Line Interface
def main():
    parser = argparse.ArgumentParser(description='LSB Steganography Tool with GUI and CLI')
    parser.add_argument('action', nargs='?', choices=['encode', 'decode', 'analyze', 'benchmark', 'gui'], 
                       help='Action to perform (use "gui" to launch GUI)', default='gui')
    parser.add_argument('-i', '--input', help='Input image path')
    parser.add_argument('-o', '--output', help='Output image path (for encode)')
    parser.add_argument('-m', '--message', help='Message to encode')
    parser.add_argument('--file', help='File containing message to encode')
    
    args = parser.parse_args()
    
    if args.action == 'gui' or (args.action is None):
        # Launch GUI
        root = tk.Tk()
        app = SteganographyGUI(root)
        root.mainloop()
        return
    
    # CLI operations
    if args.action == 'encode':
        if not args.input:
            parser.error('Input image path required for encoding')
        if not args.output:
            parser.error('Output path required for encoding')
        
        message = args.message
        if args.file:
            with open(args.file, 'r', encoding='utf-8') as f:
                message = f.read()
        
        if not message:
            parser.error('Message or message file required for encoding')
        
        success = lsb_encode(args.input, message, args.output)
        print(f"Encoding {'successful' if success else 'failed'}")
    
    elif args.action == 'decode':
        if not args.input:
            parser.error('Input stego image path required for decoding')
        
        decoded = lsb_decode(args.input)
        if decoded:
            print(f"Decoded message: {decoded}")
        else:
            print("Decoding failed")
    
    elif args.action == 'analyze':
        if not args.input:
            parser.error('Input image path required for analysis')
        
        capacity = analyze_image_capacity(args.input)
        print("Image Capacity Analysis:")
        print(json.dumps(capacity, indent=2))
    
    elif args.action == 'benchmark':
        if not args.input:
            parser.error('Input image path required for benchmark')
        
        if not args.message and not args.file:
            args.message = "This is a test message for benchmarking the steganography system."
        
        message = args.message
        if args.file:
            with open(args.file, 'r', encoding='utf-8') as f:
                message = f.read()
        
        output_path = args.output or 'benchmark_output.png'
        stego = LSBSteganography()
        results = SteganographyAnalyzer.benchmark_embedding(stego, args.input, message, output_path)
        print("Benchmark Results:")
        print(json.dumps(results, indent=2, default=str))

if __name__ == "__main__":
    try:
        import sys
        if len(sys.argv) > 1:
            main()
        else:
            try:
                import tkinter
                # Launch GUI by default
                main()
            except ImportError:
                # Fallback to CLI demo if tkinter not available
                print("GUI not available (tkinter not installed). Running CLI demo...")
                stego = LSBSteganography()
                test_message = "This is a secret message! 🔐"
                
                if os.path.exists("test_image.png"):
                    print("Running demo with test_image.png...")
                    
                    # Analyze capacity
                    capacity = stego.get_capacity_info("test_image.png")
                    print("Capacity Analysis:")
                    print(json.dumps(capacity, indent=2))
                    
                    # Encode message
                    success = stego.encode("test_image.png", test_message, "stego_output.png")
                    if success:
                        print("✓ Message encoded successfully")
                        
                        # Decode message
                        decoded = stego.decode("stego_output.png")
                        if decoded == test_message:
                            print("✓ Message decoded successfully")
                            print(f"Original: {test_message}")
                            print(f"Decoded:  {decoded}")
                        else:
                            print("✗ Message decoding failed")
                    else:
                        print("✗ Message encoding failed")
                else:
                    print("Demo requires a test image file named 'test_image.png'")
                    print("Usage examples:")
                    print("  python script.py gui                    # Launch GUI")
                    print("  python script.py encode -i image.png -m 'secret message' -o stego.png")
                    print("  python script.py decode -i stego.png")
                    print("  python script.py analyze -i image.png")
                    print("  python script.py benchmark -i image.png")
                
    except Exception as e:
        logging.error(f"Error: {e}")