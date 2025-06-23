// Function to decompress zlib data (top-level)

// zlibDecompress helper for zlib (pako) decompression
function zlibDecompress(data) {
    try {
        return pako.inflate(data, { to: "string" });
    } catch (e) {
        console.error("Decompression failed:", e);
        return null;
    }
}   

// LSB Steganography decoder implementation
async function extractTextFromImage(imageFile) {
    const MESSAGE_HEADER = new Uint8Array([
        0x4c, 0x53, 0x42, 0x53, 0x54, 0x45, 0x47, 0x4f,
    ]); // "LSBSTEGO" in bytes

    try {
        // Load and validate image
        const img = await loadImage(imageFile);
        const canvas = document.createElement("canvas");
        const ctx = canvas.getContext("2d");

        canvas.width = img.width;
        canvas.height = img.height;
        ctx.drawImage(img, 0, 0);

        const imageData = ctx.getImageData(0, 0, img.width, img.height);
        const pixels = imageData.data; // RGBA format

        const height = img.height;
        const width = img.width;

        console.log(`Processing ${width}x${height} image`);

        // First, extract exactly 96 bits (header + length) to check for valid message
        const headerBits = new Array(96);
        let bitIndex = 0;

        // Extract header bits following exact encoding pattern
        extractBits: for (let row = 0; row < height && bitIndex < 96; row++) {
            for (let col = 0; col < width && bitIndex < 96; col++) {
                const pixelIndex = (row * width + col) * 4;

                // Extract from RGB channels (skip alpha) - same order as encoding
                for (let channel = 0; channel < 3 && bitIndex < 96; channel++) {
                    headerBits[bitIndex] = pixels[pixelIndex + channel] & 1;
                    bitIndex++;
                }
            }
        }

        if (bitIndex < 96) {
            throw new Error("Image too small to contain header");
        }

        // Convert header bits to bytes - always MSB-first
        const headerBytes = new Uint8Array(12); // 96 bits = 12 bytes
        for (let i = 0; i < 12; i++) {
            let byte = 0;
            for (let j = 0; j < 8; j++) {
                if (headerBits[i * 8 + j]) {
                    byte |= 1 << (7 - j); // MSB first
                }
            }
            headerBytes[i] = byte;
        }

        // Debug: Print first few bytes
        console.log(
            "First 12 extracted bytes:",
            Array.from(headerBytes)
                .map((b) => `0x${b.toString(16).padStart(2, "0")}`)
                .join(" ")
        );
        console.log(
            "Expected header bytes:",
            Array.from(MESSAGE_HEADER)
                .map((b) => `0x${b.toString(16).padStart(2, "0")}`)
                .join(" ")
        );
        console.log(
            "First 8 bytes as string:",
            new TextDecoder().decode(headerBytes.slice(0, 8))
        );

        // Check header
        let validHeader = false;
        let messageLength = 0;
        let finalHeaderBytes = null;

        if (arrayStartsWith(headerBytes, MESSAGE_HEADER)) {
            console.log("Found valid header (MSB-first bit order)");
            validHeader = true;
            finalHeaderBytes = headerBytes;
        }

        if (!validHeader) {
            throw new Error("No valid message header found");
        }

        // Extract message length from header
        const lengthBytes = finalHeaderBytes.slice(
            MESSAGE_HEADER.length,
            MESSAGE_HEADER.length + 4
        );
        messageLength = bytesToUint32LE(lengthBytes);

        console.log(
            `Found valid header. Message length: ${messageLength} bytes`
        );

        if (messageLength <= 0 || messageLength > 1000000) {
            throw new Error(`Invalid message length: ${messageLength}`);
        }

        // Calculate total bits needed
        const totalBitsNeeded = 96 + messageLength * 8;

        // Extract all message bits
        const allBits = new Array(totalBitsNeeded);
        bitIndex = 0;

        // Extract bits following exact encoding pattern
        extractAllBits: for (
            let row = 0;
            row < height && bitIndex < totalBitsNeeded;
            row++
        ) {
            for (
                let col = 0;
                col < width && bitIndex < totalBitsNeeded;
                col++
            ) {
                const pixelIndex = (row * width + col) * 4;

                // Extract from RGB channels (skip alpha)
                for (
                    let channel = 0;
                    channel < 3 && bitIndex < totalBitsNeeded;
                    channel++
                ) {
                    allBits[bitIndex] = pixels[pixelIndex + channel] & 1;
                    bitIndex++;
                }
            }

            // Yield control periodically to prevent freezing
            if (row % 100 === 0) {
                await new Promise((resolve) => setTimeout(resolve, 0));
            }
        }

        if (bitIndex < totalBitsNeeded) {
            throw new Error(
                `Image too small: need ${totalBitsNeeded} bits, got ${bitIndex}`
            );
        }

        // Convert all bits to bytes using MSB-first
        const totalBytes = Math.ceil(totalBitsNeeded / 8);
        const msgBytes = new Uint8Array(totalBytes);

        for (let i = 0; i < totalBytes; i++) {
            let byte = 0;
            for (let j = 0; j < 8 && i * 8 + j < totalBitsNeeded; j++) {
                if (allBits[i * 8 + j]) {
                    byte |= 1 << (7 - j); // MSB first
                }
            }
            msgBytes[i] = byte;
        }

        // Extract the actual message (skip header and length)
        const message = extractMessage(msgBytes);
        console.log("Successfully extracted message");
        return message;
    } catch (error) {
        console.error("Decoding error:", error);
        return null;
    }
}

// Helper function to load image from file
function loadImage(file) {
    return new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = () => resolve(img);
        img.onerror = reject;
        img.src = URL.createObjectURL(file);
    });
}

// Fast bit extraction without function call
function extractBit(pixelValue) {
    return pixelValue & 1;
}

// Optimized bits to bytes conversion for specific ranges
function fastBitsToBytes(bitString, start, length) {
    const numBytes = Math.ceil(length / 8);
    const bytes = new Uint8Array(numBytes);

    for (let i = 0; i < length; i += 8) {
        let byte = 0;
        const bitsInByte = Math.min(8, length - i);

        for (let j = 0; j < bitsInByte; j++) {
            const bitIndex = start + i + j;
            if (
                bitIndex < bitString.length &&
                (bitString[bitIndex] === "1" || bitString[bitIndex] === 1)
            ) {
                byte |= 1 << j;
            }
        }

        bytes[Math.floor(i / 8)] = byte;
    }

    return bytes;
}

// Convert 4 bytes to uint32 (big-endian)
function bytesToUint32(bytes) {
    return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}

// Convert 4 bytes to uint32 (little-endian)
function bytesToUint32LE(bytes) {
    return bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
}

// Check if array starts with another array
function arrayStartsWith(array, prefix) {
    if (array.length < prefix.length) return false;

    for (let i = 0; i < prefix.length; i++) {
        if (array[i] !== prefix[i]) return false;
    }

    return true;
}

// Extract message from byte array (after header and length)
function extractMessage(msgBytes) {
    const MESSAGE_HEADER = new Uint8Array([
        0x4c, 0x53, 0x42, 0x53, 0x54, 0x45, 0x47, 0x4f,
    ]); // "LSBSTEGO" in bytes
    const headerAndLengthSize = MESSAGE_HEADER.length + 4; // header + 4 bytes for length

    // Extract the compressed message part (skip header and length)
    const compressedBytes = msgBytes.slice(headerAndLengthSize);

    // Decompress the message using zlib
    const decompressedText = zlibDecompress(compressedBytes);
    if (!decompressedText) {
        throw new Error("Failed to decompress message");
    }

    return decompressedText;
}

// Handle drag and drop events for all text inputs
document.addEventListener(
    "dragover",
    (e) => {
        // Only allow if the target is a text input
        if (e.target.matches('input[type="text"], textarea')) {
            e.preventDefault();
            e.dataTransfer.dropEffect = "copy";
        }
    },
    false
);

document.addEventListener(
    "drop",
    async (e) => {
        // Only handle drops on text inputs
        if (
            !e.target.matches(
                'input[type="text"], textarea, input[type="password"]'
            )
        ) {
            return;
        }

        e.preventDefault();

        const files = Array.from(e.dataTransfer.files);
        const imageFile = files.find((file) => file.type.startsWith("image/"));

        if (!imageFile) {
            console.log("No image file found in drop");
            return;
        }

        try {
            // Extract text from the image using LSB steganography
            const extractedText = await extractTextFromImage(imageFile);

            if (extractedText) {
                // Insert the extracted text at the cursor position or append to the end
                const input = e.target;
                const start = input.selectionStart || 0;
                const end = input.selectionEnd || 0;
                const textBefore = input.value.substring(0, start);
                const textAfter = input.value.substring(end);

                input.value = textBefore + extractedText + textAfter;

                // Trigger input event to ensure the change is registered
                input.dispatchEvent(new Event("input", { bubbles: true }));

                console.log("Successfully extracted hidden text from image");
            } else {
                console.log("No hidden text found in the image");
            }
        } catch (error) {
            console.error("Error processing image:", error);
        }
    },
    false
);
