# Steganography Toolkit: Python Encoder & Chrome Extension Decoder

## Overview

This project provides a complete workflow for hiding and extracting secret messages in images using LSB (Least Significant Bit) steganography. It consists of:

-   **Python Tool:** Encodes (hides) and decodes (extracts) messages in PNG images using LSB and zlib compression.
-   **Chrome Extension:** Allows users to extract hidden text from images by simply dragging and dropping them into any text input on a webpage.

---

## Python Steganography Tool

### Features

-   Hide (encode) any text message inside a PNG image using LSB steganography.
-   Extract (decode) hidden messages from images.
-   Uses zlib compression for efficient storage.
-   CLI and GUI support.
-   Capacity analysis and benchmarking tools.

### Usage

-   **Encoding:**
    ```bash
    python ToolKit.py encode -i input.png -o output.png -m "Secret message here"
    ```
-   **Decoding:**
    ```bash
    python ToolKit.py decode -i output.png
    ```
-   **GUI:**
    ```bash
    python ToolKit.py gui
    ```

---

## Chrome Extension: Image Text Extractor

### Features

-   Instantly extracts hidden text from images encoded with the Python tool.
-   Works by dragging and dropping an image into any text input or textarea on a webpage.
-   No manual decoding or uploads required.
-   Only works with images encoded using the provided Python tool (LSB, zlib, PNG recommended).

### How to Use

1. Encode a message into an image using the Python tool.
2. On any webpage, drag and drop the encoded image into a text input or textarea.
3. The hidden text will be automatically extracted and inserted at the cursor position.

---

## Demo Video


https://github.com/user-attachments/assets/d70bbe76-9395-466c-b901-5a186a0f92dd


---


