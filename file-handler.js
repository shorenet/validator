/**
 * File Handler Module
 * Handles file upload, drag-and-drop, and JSONL parsing
 */

export class FileHandler {
    constructor() {
        this.supportedFormats = ['.jsonl', '.json'];
    }

    /**
     * Handle file drop event
     * @param {DragEvent} event - Drop event
     * @returns {Promise<Array<Object>>} Array of parsed transactions
     */
    async handleDrop(event) {
        event.preventDefault();
        event.stopPropagation();

        const files = Array.from(event.dataTransfer.files);
        if (files.length === 0) {
            throw new Error('No files dropped');
        }

        // Process first file only
        const file = files[0];
        return await this.handleFile(file);
    }

    /**
     * Handle file select event
     * @param {Event} event - File input change event
     * @returns {Promise<Array<Object>>} Array of parsed transactions
     */
    async handleFileSelect(event) {
        const files = Array.from(event.target.files);
        if (files.length === 0) {
            throw new Error('No file selected');
        }

        const file = files[0];
        return await this.handleFile(file);
    }

    /**
     * Handle a single file
     * @param {File} file - File to process
     * @returns {Promise<Array<Object>>} Array of parsed transactions
     */
    async handleFile(file) {
        // Validate file type
        const extension = '.' + file.name.split('.').pop().toLowerCase();
        if (!this.supportedFormats.includes(extension)) {
            throw new Error(`Unsupported file format: ${extension}. Supported: ${this.supportedFormats.join(', ')}`);
        }

        // Parse based on extension
        if (extension === '.jsonl') {
            return await this.parseJsonl(file);
        } else if (extension === '.json') {
            return await this.parseJson(file);
        }

        throw new Error('Unknown file format');
    }

    /**
     * Parse JSONL file (newline-delimited JSON)
     * @param {File} file - JSONL file
     * @returns {Promise<Array<Object>>} Array of parsed transactions
     */
    async parseJsonl(file) {
        const text = await this.readFileAsText(file);
        const lines = text.trim().split('\n');
        const transactions = [];

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue; // Skip empty lines

            try {
                const record = JSON.parse(line);

                // Handle wrapped format: { type: "transaction", data: {...} }
                if (record.type && record.data) {
                    transactions.push(record);
                } else {
                    // Unwrapped transaction
                    transactions.push({ type: 'transaction', data: record });
                }
            } catch (error) {
                console.warn(`Failed to parse line ${i + 1}:`, error.message);
                // Continue parsing other lines
            }
        }

        if (transactions.length === 0) {
            throw new Error('No valid transactions found in file');
        }

        return transactions;
    }

    /**
     * Parse JSON file (array of transactions)
     * @param {File} file - JSON file
     * @returns {Promise<Array<Object>>} Array of parsed transactions
     */
    async parseJson(file) {
        const text = await this.readFileAsText(file);
        const data = JSON.parse(text);

        if (!Array.isArray(data)) {
            throw new Error('JSON file must contain an array of transactions');
        }

        // Ensure wrapped format
        return data.map(item => {
            if (item.type && item.data) {
                return item;
            }
            return { type: 'transaction', data: item };
        });
    }

    /**
     * Read file as text
     * @param {File} file - File to read
     * @returns {Promise<string>} File contents as text
     */
    readFileAsText(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();

            reader.onload = (event) => {
                resolve(event.target.result);
            };

            reader.onerror = (error) => {
                reject(new Error(`Failed to read file: ${error}`));
            };

            reader.readAsText(file);
        });
    }

    /**
     * Format file size for display
     * @param {number} bytes - File size in bytes
     * @returns {string} Formatted size string
     */
    formatFileSize(bytes) {
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
        if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
        return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
    }
}
