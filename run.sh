#!/bin/bash
set -e

echo "=============================================="
echo "WiFi Security Analyzer"
echo "=============================================="

python3 -m pip install -r requirements.txt
mkdir -p reports logs static templates
python3 main.py
