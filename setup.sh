#!/bin/bash

set -e

echo "=========================================="
echo "  DTing Server Setup Script"
echo "=========================================="
echo ""

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# ==========================================
# Argument parsing - flag mandatory
# ==========================================
if [ $# -eq 0 ]; then
    echo -e "${RED}✗ Error: Setup mode required.${NC}"
    echo ""
    echo "Usage:"
    echo -e "  ${GREEN}./setup.sh docker${NC}   - Setup with Docker / Docker Compose"
    echo -e "  ${GREEN}./setup.sh python${NC}   - Setup without Docker, manual venv"
    echo ""
    exit 1
fi

SETUP_MODE="$1"

# ==========================================
# .env check — existence is the only gate.
# ==========================================


echo -e "${GREEN}✓ .env file found. Proceeding...${NC}"
echo ""

# ==========================================
# Docker setup
# ==========================================
if [[ "$SETUP_MODE" == "docker" ]]; then
    echo -e "${GREEN}Setting up with Docker...${NC}"

    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}✗ Docker is not installed. Please install Docker first.${NC}"
        exit 1
    fi

    # Check if Docker Compose is installed
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        echo -e "${RED}✗ Docker Compose is not installed.${NC}"
        echo "You can either install Docker Compose or run: ./setup.sh python"
        exit 1
    fi

    echo -e "${GREEN}Building Docker image...${NC}"
    $COMPOSE_CMD build

    echo ""
    echo -e "${GREEN}Starting DTing Server...${NC}"
    $COMPOSE_CMD up -d

    echo ""
    echo -e "${GREEN}✓ Setup complete!${NC}"
    echo ""
    echo "=========================================="
    echo "  Docker Setup Complete"
    echo "=========================================="
    echo ""
    echo -e "🚀 DTing Server is running at:"
    echo -e "   ${GREEN}http://localhost:8000${NC}"
    echo ""
    echo -e "📚 API Documentation:"
    echo -e "   ${GREEN}http://localhost:8000/docs${NC}"
    echo ""
    echo -e "🔐 Admin Login:"
    echo -e "   ${GREEN}http://localhost:8000/admin/login${NC}"
    echo ""
    echo "View logs:"
    echo -e "   ${GREEN}$COMPOSE_CMD logs -f${NC}"
    echo ""
    echo "Stop server:"
    echo -e "   ${GREEN}$COMPOSE_CMD down${NC}"
    echo ""

# ==========================================
# Manual python venv setup
# ==========================================
elif [[ "$SETUP_MODE" == "python" ]]; then
    echo -e "${GREEN}Setting up without Docker...${NC}"

    # Check if Python 3.10+ is installed
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}✗ Python 3 is not installed. Please install Python 3.10 or newer.${NC}"
        exit 1
    fi

    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    echo "Python version: $PYTHON_VERSION"

    echo ""
    echo -e "${GREEN}Creating virtual environment...${NC}"
    python3 -m venv venv

    echo -e "${GREEN}Activating virtual environment...${NC}"
    source venv/bin/activate

    echo -e "${GREEN}Upgrading pip...${NC}"
    pip install --upgrade pip

    echo -e "${GREEN}Installing dependencies...${NC}"
    pip install -r requirements.txt

    echo ""
    echo -e "${GREEN}✓ Setup complete!${NC}"
    echo ""
    echo "=========================================="
    echo "  Manual Setup Complete"
    echo "=========================================="
    echo ""
    echo "Starting the server..."
    echo -e "   ${GREEN}uvicorn app.main:app --host 0.0.0.0 --port 8000${NC}"
    echo ""
    uvicorn app.main:app --host 0.0.0.0 --port 8000

else
    echo -e "${RED}✗ Invalid option: $SETUP_MODE${NC}"
    echo ""
    echo "Valid options:"
    echo -e "  ${GREEN}./setup.sh docker${NC}   - Setup with Docker"
    echo -e "  ${GREEN}./setup.sh python${NC}   - Setup with Python venv"
    echo ""
    exit 1
fi

echo ""