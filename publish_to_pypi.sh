#!/bin/bash

# Script to publish to PyPI
# Copyright (C) 2024  Ethan Troy
# Licensed under GNU GPL v3.0 or later

echo "🚀 Publishing AWS Bedrock Security Checker to PyPI"
echo "=================================================="

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf dist/ build/ *.egg-info/

# Create distributions
echo "📦 Building distributions..."
python3 -m pip install --upgrade build twine
python3 -m build

# Check the distributions
echo "🔍 Checking distributions..."
python3 -m twine check dist/*

# Upload to Test PyPI first (optional)
echo ""
echo "📤 Do you want to upload to Test PyPI first? (recommended) [y/N]"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    echo "Uploading to Test PyPI..."
    python3 -m twine upload --repository testpypi dist/*
    echo ""
    echo "✅ Test upload complete!"
    echo "Test with: pip install --index-url https://test.pypi.org/simple/ bedrock-security-checker"
    echo ""
    echo "Press Enter to continue to production PyPI, or Ctrl+C to stop here"
    read -r
fi

# Upload to production PyPI
echo "📤 Uploading to PyPI..."
python3 -m twine upload dist/*

echo ""
echo "✅ Upload complete!"
echo "Install with: pip install bedrock-security-checker"