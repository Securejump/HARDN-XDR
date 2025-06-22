#!/bin/bash

PACKAGES=(
    "auditd"
    "audispd-plugins"
    "suricata"
    "fail2ban"
    "rkhunter"
    "chkrootkit"
    "unhide"
    "debsums"
    "lynis"
    "clamav"
    "clamav-daemon"
    "clamav-freshclam"
    "yara"
    "aide"
    "aide-common"
    "rsyslog"
    "logrotate"
    "needrestart"
    "apt-listchanges"
    "apt-listbugs"
    "unattended-upgrades"
    "apt-transport-https"
    "ca-certificates"
    "software-properties-common"
    "lsb-release"
    "gnupg"
    "openssh-server"
    "openssh-client"
    "ufw"
    "systemd-timesyncd"
    "apparmor"
    "apparmor-profiles"
    "apparmor-utils"
    "firejail"
    "libpam-pwquality"
    "libpam-google-authenticator"
    "libpam-tmpdir"
    "curl"
    "wget"
    "lsof"
    "psmisc"
    "procps"
    "git"
)

if [ "$(id -u)" -ne 0 ]; then
   echo "This script must be run as root. Please use sudo." >&2
   exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    ID_LIKE=${ID_LIKE:-""}
else
    echo "Cannot detect OS from /etc/os-release." >&2
    exit 1
fi

echo "Detected Operating System: $OS"

# Install packages per OS
if [[ "$OS" == "debian" || "$OS" == "ubuntu" ]]; then
    echo "Using APT package manager."
    echo "Updating package lists..."
    apt-get update -y

    echo "Installing packages..."
    if apt-get install -y "${PACKAGES[@]}"; then
        echo "Package installation completed successfully."
    else
        echo "An error occurred during APT package installation. Please check the output above." >&2
        exit 1
    fi

elif [[ "$OS" == "rhel" || "$OS" == "centos" || "$OS" == "fedora" || "$ID_LIKE" == *"rhel"* || "$ID_LIKE" == *"fedora"* ]]; then
    echo "Warning: The package list may contain Debian-specific packages."
    echo "Installation may fail for packages not found in your distribution's repositories."

    INSTALL_COMMAND=""
    if command -v dnf &> /dev/null; then
        echo "Using DNF package manager."
        INSTALL_COMMAND="dnf"
    elif command -v yum &> /dev/null; then
        echo "Using YUM package manager."
        INSTALL_COMMAND="yum"
    else
        echo "No DNF or YUM package manager found on this system." >&2
        exit 1
    fi

    if "$INSTALL_COMMAND" install -y "${PACKAGES[@]}"; then
        echo "Package installation completed successfully."
    else
        echo "An error occurred during package installation. Please check the output above." >&2
        exit 1
    fi
else
    echo "Unsupported operating system: $OS" >&2
    exit 1
fi

exit 0
