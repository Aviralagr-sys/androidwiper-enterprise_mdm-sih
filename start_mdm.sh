#!/bin/bash

# Enterprise MDM System Startup Script
# This script opens the README file and Python MDM application

echo "================================================"
echo "Starting Enterprise MDM System..."
echo "================================================"
echo ""

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Define file paths based on your directory structure
README_FILE="$SCRIPT_DIR/README.md"
PYTHON_SCRIPT="$SCRIPT_DIR/src/enterprise_mdm.py"

echo "Project Directory: $SCRIPT_DIR"
echo ""

# Check if README file exists and open it
if [ -f "$README_FILE" ]; then
    echo "✅ Opening README file with factory reset instructions..."
    echo "   File: $README_FILE"
    # Open README with default text editor
    xdg-open "$README_FILE" &
    sleep 2  # Delay to ensure README opens first and gets focus
else
    echo "❌ Warning: README.md not found at $README_FILE"
    echo "   Please ensure README.md exists with factory reset instructions"
fi

echo ""

# Check if Python script exists and open it
if [ -f "$PYTHON_SCRIPT" ]; then
    echo "✅ Opening Python MDM script for review..."
    echo "   File: $PYTHON_SCRIPT"
    # Open Python file with default application (usually a text editor or IDE)
    xdg-open "$PYTHON_SCRIPT" &
    sleep 2
else
    echo "❌ Error: enterprise_mdm.py not found at $PYTHON_SCRIPT"
    echo "   Please ensure your Python MDM script exists in the src directory"
    exit 1
fi

echo ""
echo "================================================"
echo "IMPORTANT: Factory Reset Process"
echo "================================================"
echo "⚠️  PLEASE READ THE README FILE CAREFULLY!"
echo ""
echo "After device wiping, you MUST:"
echo "1. Review the README.md file (now open)"
echo "2. Follow the factory reset procedures"
echo "3. Complete MDM reconfiguration steps"
echo "4. Verify all systems are properly restored"
echo ""

# Ask if user wants to run the Python script
echo "================================================"
echo "Python Script Execution"
echo "================================================"
echo "The enterprise_mdm.py script is now open for review."
echo ""
echo "Do you want to run the Python MDM script now? (y/N)"
echo "⏰ Waiting 15 seconds for your response..."

read -t 15 -r response

if [[ $response =~ ^[Yy]$ ]]; then
    echo ""
    echo "🚀 Running Python MDM application..."
    echo "   Executing: python3 $PYTHON_SCRIPT"
    echo ""
    cd "$SCRIPT_DIR"
    python3 "$PYTHON_SCRIPT"
else
    echo ""
    echo "📝 Python script opened in editor only."
    echo "   Run manually when ready with: python3 src/enterprise_mdm.py"
fi

echo ""
echo "================================================"
echo "Additional Resources"
echo "================================================"

# Open the project directory in file manager for easy access
echo "📁 Opening project directory in file manager..."
xdg-open "$SCRIPT_DIR" &

# Open the src directory as well
echo "📁 Opening src directory for quick access to scripts..."
xdg-open "$SCRIPT_DIR/src" &

echo ""
echo "================================================"
echo "Enterprise MDM System Startup Complete!"
echo "================================================"
echo ""
echo "✅ README.md opened (contains factory reset instructions)"
echo "✅ enterprise_mdm.py opened for review"
echo "✅ Project directories opened in file manager"
echo ""
echo "🔄 REMINDER: Complete factory reset process as documented"
echo "📋 All configuration files are in their respective directories"
echo ""
echo "Press Enter to close this terminal or Ctrl+C to exit immediately"
read
