#!/bin/bash
# NightWalk3r | Behnjamin Barlow | TTU CCDC

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  SSH Enumeration Script${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script must be run as root or with sudo${NC}" 
   exit 1
fi

echo -e "${GREEN}[+] Starting enumeration...${NC}"
echo ""

#############################################
# SSH Authorized Keys Enumeration
#############################################

echo -e "${YELLOW}[*] Checking SSH authorized_keys files...${NC}"
echo ""

# Check root's authorized_keys
echo -e "${BLUE}--- Checking /root/.ssh/authorized_keys ---${NC}"
if [ -f "/root/.ssh/authorized_keys" ]; then
    echo -e "${GREEN}[+] File exists: /root/.ssh/authorized_keys${NC}"
    echo -e "${YELLOW}Contents:${NC}"
    cat /root/.ssh/authorized_keys
    echo ""
else
    echo -e "${RED}[-] File not found: /root/.ssh/authorized_keys${NC}"
    echo ""
fi

# Iterate through all user home directories
echo -e "${BLUE}--- Checking user home directories ---${NC}"

# Get all users with home directories
for user_home in /home/*; do
    if [ -d "$user_home" ]; then
        username=$(basename "$user_home")
        auth_keys_file="$user_home/.ssh/authorized_keys"
        
        echo -e "${BLUE}Checking user: ${username}${NC}"
        
        if [ -f "$auth_keys_file" ]; then
            echo -e "${GREEN}[+] File exists: $auth_keys_file${NC}"
            echo -e "${YELLOW}Contents:${NC}"
            cat "$auth_keys_file"
            echo ""
        else
            echo -e "${RED}[-] File not found: $auth_keys_file${NC}"
            echo ""
        fi
    fi
done

# Also check for any authorized_keys files in unusual locations
echo -e "${BLUE}--- Searching for authorized_keys in unusual locations ---${NC}"
find / -name "authorized_keys" -type f 2>/dev/null | while read -r file; do
    # Skip the ones we already checked
    if [[ ! "$file" =~ ^/root/.ssh/authorized_keys$ ]] && [[ ! "$file" =~ ^/home/[^/]+/.ssh/authorized_keys$ ]]; then
        echo -e "${YELLOW}[!] Found authorized_keys in unusual location: $file${NC}"
        echo -e "${YELLOW}Contents:${NC}"
        cat "$file"
        echo ""
    fi
done

echo -e "${GREEN}[+] SSH authorized_keys enumeration complete${NC}"
echo ""

#############################################
# SSH Configuration Enumeration
#############################################

echo -e "${YELLOW}[*] Checking SSH configuration files...${NC}"
echo ""

# Check main sshd_config
if [ -f /etc/ssh/sshd_config ]; then
    echo -e "${BLUE}--- /etc/ssh/sshd_config ---${NC}"
    echo -e "${GREEN}[+] File exists: /etc/ssh/sshd_config${NC}"
    echo -e "${YELLOW}Active configuration (non-comment lines):${NC}"
    echo "=========================================="
    # Ignore comments and empty lines
    grep "^\s*[^#]" /etc/ssh/sshd_config
    echo "=========================================="
    echo ""
else
    echo -e "${RED}[-] File not found: /etc/ssh/sshd_config${NC}"
    echo ""
fi

# Check sshd_config.d directory
if [ -d /etc/ssh/sshd_config.d ]; then
    echo -e "${BLUE}--- /etc/ssh/sshd_config.d/ directory ---${NC}"
    echo -e "${GREEN}[+] Directory exists: /etc/ssh/sshd_config.d${NC}"
    echo ""
    
    for file in /etc/ssh/sshd_config.d/*; do
        if [ -f "$file" ]; then
            echo -e "${YELLOW}Configuration file: $file${NC}"
            echo "=========================================="
            # Ignore comments and empty lines
            grep "^\s*[^#]" "$file"
            echo "=========================================="
            echo ""
        fi
    done
else
    echo -e "${RED}[-] Directory not found: /etc/ssh/sshd_config.d${NC}"
    echo ""
fi

echo -e "${GREEN}[+] SSH configuration enumeration complete${NC}"
echo ""

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Enumeration Complete${NC}"
echo -e "${BLUE}========================================${NC}"
