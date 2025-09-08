#!/bin/bash

# Zabbix to NetBox Sync - Quick Start Script

echo "========================================="
echo "Zabbix to NetBox Synchronization Tool"
echo "========================================="

# Check Python version
python_version=$(python3 --version 2>&1 | grep -Po '(?<=Python )\d+\.\d+')
echo "✓ Python version: $python_version"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment exists"
fi

# Activate virtual environment
source venv/bin/activate

# Install/upgrade pip
pip install --upgrade pip > /dev/null 2>&1

# Install requirements
echo "Installing requirements..."
pip install -r requirements.txt > /dev/null 2>&1
echo "✓ Requirements installed"

# Check if .env exists
if [ ! -f ".env" ]; then
    echo ""
    echo "⚠️  No .env file found!"
    echo "Creating .env from template..."
    cp .env.example .env
    echo "✓ Created .env file"
    echo ""
    echo "Please edit .env file with your credentials:"
    echo "  1. Set ZABBIX_USER and ZABBIX_PASSWORD"
    echo "  2. Set NETBOX_TOKEN"
    echo ""
    read -p "Press Enter after updating .env file..."
fi

# Check Redis
echo ""
echo "Checking Redis connection..."
if redis-cli ping > /dev/null 2>&1; then
    echo "✓ Redis is running"
else
    echo "⚠️  Redis is not running"
    echo "  The tool will use in-memory cache (less efficient)"
    echo "  To install Redis: sudo apt-get install redis-server"
fi

# Test connections
echo ""
echo "Testing connections..."
python main.py test

# Show available commands
echo ""
echo "========================================="
echo "Available Commands:"
echo "========================================="
echo ""
echo "1. Test connections:"
echo "   python main.py test"
echo ""
echo "2. List available groups:"
echo "   python main.py list-groups"
echo ""
echo "3. List devices in a group:"
echo "   python main.py list-devices 'VMware hypervisor discovery: DC-Karaganda'"
echo ""
echo "4. Dry run sync (no changes):"
echo "   python main.py sync --dry-run -g 'VMware hypervisor discovery: DC-Karaganda'"
echo ""
echo "5. Full sync:"
echo "   python main.py sync -g 'VMware hypervisor discovery: DC-Karaganda'"
echo ""
echo "6. Incremental update:"
echo "   python main.py update"
echo ""
echo "7. View help:"
echo "   python main.py --help"
echo ""
echo "========================================="