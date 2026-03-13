#!/usr/bin/env bash
set -euo pipefail

# Create virtual environment and install dependencies
echo "Setting up Python environment with uv..."
uv venv
uv pip install -e ".[analysis]"

# Download MegaVul dataset (C/C++ and Java)
echo "Downloading MegaVul dataset..."
wget -O megavul.zip "XXXX"
unzip -o megavul.zip -d megavul
rm megavul.zip

echo ""
echo "Setup complete. To run the benchmark:"
echo "  source .venv/bin/activate"
echo "  python main.py"
echo ""
echo "To analyze results:"
echo "  python analyze_results.py"
