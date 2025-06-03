#!/bin/bash
# Release automation script for bedrock-security-checker
# Copyright (C) 2024  Ethan Troy
# Licensed under GNU GPL v3.0 or later

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 AWS Bedrock Security Checker - Release Script${NC}"
echo "================================================"

# Check if we're in the right directory
if [ ! -f "bedrock_security_checker.py" ]; then
    echo -e "${RED}Error: bedrock_security_checker.py not found. Run this script from the project root.${NC}"
    exit 1
fi

# Get current version
CURRENT_VERSION=$(python -c "import re; content=open('setup.py').read(); print(re.search(r'version=\"([^\"]+)\"', content).group(1))")
echo -e "Current version: ${YELLOW}$CURRENT_VERSION${NC}"

# Ask for new version
echo -n "Enter new version (or press Enter to auto-increment): "
read NEW_VERSION

if [ -z "$NEW_VERSION" ]; then
    # Auto-increment patch version
    IFS='.' read -ra VERSION_PARTS <<< "$CURRENT_VERSION"
    MAJOR="${VERSION_PARTS[0]}"
    MINOR="${VERSION_PARTS[1]}"
    PATCH="${VERSION_PARTS[2]}"
    NEW_PATCH=$((PATCH + 1))
    NEW_VERSION="$MAJOR.$MINOR.$NEW_PATCH"
fi

echo -e "New version will be: ${GREEN}$NEW_VERSION${NC}"
echo -n "Continue? [y/N] "
read -r response
if [[ ! "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    echo "Aborted."
    exit 1
fi

# Update version in setup.py
sed -i.bak "s/version=\"$CURRENT_VERSION\"/version=\"$NEW_VERSION\"/" setup.py && rm setup.py.bak

# Update version in pyproject.toml
sed -i.bak "s/version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" pyproject.toml && rm pyproject.toml.bak

echo -e "${GREEN}✓ Updated version to $NEW_VERSION${NC}"

# Get changelog
echo ""
echo "Enter changelog for this release (press Ctrl+D when done):"
CHANGELOG=$(cat)

# Commit changes
git add setup.py pyproject.toml
git commit -m "Release version $NEW_VERSION

$CHANGELOG

🧪👽 Generated with automated release script"

# Create tag
git tag -a "v$NEW_VERSION" -m "Version $NEW_VERSION

$CHANGELOG"

echo -e "${GREEN}✓ Created git commit and tag${NC}"

# Build the package
echo -e "${YELLOW}Building package...${NC}"
rm -rf dist/ build/ *.egg-info/
python -m build

# Check the package
echo -e "${YELLOW}Checking package...${NC}"
python -m twine check dist/*

# Ask if we should push to Git
echo ""
echo -n "Push to Git? [y/N] "
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    git push origin main
    git push origin "v$NEW_VERSION"
    echo -e "${GREEN}✓ Pushed to Git${NC}"
fi

# Ask if we should publish to PyPI
echo ""
echo -n "Publish to PyPI? [y/N] "
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    echo -e "${YELLOW}Publishing to PyPI...${NC}"
    python -m twine upload dist/*
    echo -e "${GREEN}✓ Published to PyPI${NC}"
fi

echo ""
echo -e "${GREEN}🎉 Release $NEW_VERSION complete!${NC}"
echo ""
echo "Next steps:"
echo "  - If using GitHub Actions, the package will auto-publish when pushed"
echo "  - Create a GitHub release at: https://github.com/ethantroy/aws-bedrock-security-config-check/releases"
echo "  - Update the package with: pip install --upgrade bedrock-security-checker"