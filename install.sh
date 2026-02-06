#!/bin/bash

# YAHA Installation Script
# Installation script for YAHA Web Security Scanner

echo "=================================="
echo "YAHA Installation Script"
echo "=================================="
echo ""

# Check Python version
echo "[*] Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "[✗] Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "[✓] Python $PYTHON_VERSION found"
echo ""

# Create virtual environment
echo "[*] Creating virtual environment..."
if [ -d "venv" ]; then
    echo "[!] Virtual environment already exists"
else
    python3 -m venv venv
    echo "[✓] Virtual environment created"
fi
echo ""

# Activate virtual environment
echo "[*] Activating virtual environment..."
source venv/bin/activate
echo "[✓] Virtual environment activated"
echo ""

# Install dependencies
echo "[*] Installing dependencies..."
pip install -q -r requirements.txt
echo "[✓] Dependencies installed"
echo ""

# Make main script executable
echo "[*] Setting permissions..."
chmod +x yaha.py
echo "[✓] Permissions set"
echo ""

# Create reports directory
echo "[*] Creating reports directory..."
mkdir -p reports
echo "[✓] Reports directory created"
echo ""

echo "=================================="
echo "✓ Installation Complete!"
echo "=================================="
echo ""
echo "To use YAHA:"
echo ""
echo "  1. Activate virtual environment:"
echo "     source venv/bin/activate"
echo ""
echo "  2. Run YAHA:"
echo "     python3 yaha.py https://example.com"
echo ""
echo "  3. View help:"
echo "     python3 yaha.py --help"
echo ""
echo "For more information, see README.md"
echo ""
