#!/bin/bash

set -euo pipefail

HARDN_STATUS() {
    local status="$1"
    local message="$2"
    case "$status" in
        "info")    echo -e "\033[1;34m[INFO]\033[0m $message" ;;
        "pass")    echo -e "\033[1;32m[PASS]\033[0m $message" ;;
        "warning") echo -e "\033[1;33m[WARNING]\033[0m $message" ;;
        "error")   echo -e "\033[1;31m[ERROR]\033[0m $message" ;;
        *)         echo "$message" ;;
    esac
}


update_system() {
    HARDN_STATUS "info" "Updating system package lists..."
    apt update

}

check_git() {
    HARDN_STATUS "info" "Checking if git is installed..."
    if command -v git >/dev/null 2>&1; then
        HARDN_STATUS "pass" "Git is installed."
    else
        HARDN_STATUS "warning" "Git not found. Installing git..."
        apt install git -y
        HARDN_STATUS "pass" "Git is now installed."
    fi
}

retrieve_repo() {
    if [ -d "HARDN-XDR" ]; then
        HARDN_STATUS "warning" "HARDN-XDR directory already exists. Pulling latest changes..."
        cd HARDN-XDR
        git pull
        cd ..
else
        git clone -b deb-package https://github.com/OpenSource-For-Freedom/HARDN-XDR.git
    fi
}

build_and_install_deb() {
    cd HARDN-XDR
    HARDN_STATUS "info" "Building the .deb package..."
    apt install devscripts debhelper 
    apt install build-essential 
    apt install fakeroot 
    apt install lintian 
    apt install dh-make 
    apt install debhelper 
    apt install libssl-dev 
    apt install libcurl4-gnutls-dev 
    dpkg-buildpackage -us -uc -b

    cd ..
    DEB_FILE=$(ls -t hardn*.deb | head -n 1)
    if [[ -z "$DEB_FILE" ]]; then
        HARDN_STATUS "error" ".deb file not found! Build may have failed."
        exit 1
    fi

    HARDN_STATUS "info" "Installing the .deb package: $DEB_FILE"
    dpkg -i "$DEB_FILE" || apt-get -f install -y
}

run_packages_sh() {
    # Detect OS
    OS_FAMILY=""
    if [ -f /etc/debian_version ]; then
        OS_FAMILY="debian"
    elif [ -f /etc/redhat-release ]; then
        OS_FAMILY="redhat"
    elif [ -f /etc/centos-release ]; then
        OS_FAMILY="redhat"
    elif grep -qi 'ubuntu' /etc/os-release 2>/dev/null; then
        OS_FAMILY="debian"
    elif grep -qi 'fedora' /etc/os-release 2>/dev/null; then
        OS_FAMILY="redhat"
    else
        OS_FAMILY="unknown"
    fi

    if [ "$OS_FAMILY" = "debian" ]; then
        HARDN_STATUS "info" "Detected Debian/Ubuntu-based system."
        if [ -f HARDN-XDR/src/setup/packages.sh ]; then
            chmod +x HARDN-XDR/src/setup/packages.sh
            HARDN-XDR/src/setup/packages.sh debian
        else
            HARDN_STATUS "warning" "packages.sh not found for Debian/Ubuntu system."
        fi
    elif [ "$OS_FAMILY" = "redhat" ]; then
        HARDN_STATUS "info" "Detected RedHat/Fedora/CentOS-based system."
        if [ -f HARDN-XDR/src/setup/packages.sh ]; then
            chmod +x HARDN-XDR/src/setup/packages.sh
            HARDN-XDR/src/setup/packages.sh redhat
        else
            HARDN_STATUS "warning" "packages.sh not found for RedHat/Fedora/CentOS system."
        fi
    else
        HARDN_STATUS "warning" "Unknown OS type. Skipping packages.sh."
    fi
}

launch_menu() {
    if command -v hardn >/dev/null 2>&1; then
        echo
        HARDN_STATUS "info" "Starting HARDN-XDR setup..."
        HARDN_STATUS "info" "-----------------------------------------------------"
        HARDN_STATUS "info" "Launching the HARDN-XDR main menu."
        HARDN_STATUS "info" "You can use:"
        HARDN_STATUS "info" " - 'start'  to begin system hardening"
        HARDN_STATUS "info" " - 'audit'  to run a compliance/security audit"
        HARDN_STATUS "info" " - 'help'   to see all available commands"
        HARDN_STATUS "info" "-----------------------------------------------------"
        sleep 2
        hardn
    else
        HARDN_STATUS "error" "Could not find the installed 'hardn' command in PATH."
        HARDN_STATUS "info" "You can start it later by running: sudo hardn"
    fi
}

main() {
    update_system
    check_git
    retrieve_repo
    build_and_install_deb
    run_packages_sh
    launch_menu
}

main
