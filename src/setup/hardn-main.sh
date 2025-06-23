#!/bin/bash

# HARDN-XDR - The Linux Security Hardening Sentinel
# Version 2.0.0
# Developed and built by Christopher Bingham and Tim Burns
# About this script:
# STIG Compliance: Security Technical Implementation Guide.

HARDN_VERSION="2.1.0"
export APT_LISTBUGS_FRONTEND=none
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROGS_CSV_PATH="${SCRIPT_DIR}/../../progs.csv"
CURRENT_DEBIAN_VERSION_ID=""
CURRENT_DEBIAN_CODENAME=""

HARDN_STATUS() {
    local status="$1"
    local message="$2"
    case "$status" in
        "pass")
            echo -e "\033[1;32m[PASS]\033[0m $message"
            ;;
        "warning")
            echo -e "\033[1;33m[WARNING]\033[0m $message"
            ;;
        "error")
            echo -e "\033[1;31m[ERROR]\033[0m $message"
            ;;
        "info")
            echo -e "\033[1;34m[INFO]\033[0m $message"
            ;;
        *)
            echo -e "\033[1;37m[UNKNOWN]\033[0m $message"
            ;;
    esac
}   
detect_os_details() {
    if [[ -r /etc/os-release ]]; then
        source /etc/os-release
        CURRENT_DEBIAN_CODENAME="${VERSION_CODENAME}"
        CURRENT_DEBIAN_VERSION_ID="${VERSION_ID}"
    fi
}

detect_os_details

show_system_info() {
    echo "HARDN-XDR v${HARDN_VERSION} - System Information"
    echo "================================================"
    echo "Script Version: ${HARDN_VERSION}"
    echo "Target OS: Debian-based systems (Debian 12+, Ubuntu 24.04+)"
    if [[ -n "${CURRENT_DEBIAN_VERSION_ID}" && -n "${CURRENT_DEBIAN_CODENAME}" ]]; then
        echo "Detected OS: ${ID:-Unknown} ${CURRENT_DEBIAN_VERSION_ID} (${CURRENT_DEBIAN_CODENAME})"
    fi
    echo "Features: STIG Compliance, Malware Detection, System Hardening"
    echo "Security Tools: UFW, Fail2Ban, AppArmor, AIDE, rkhunter, and more"
    echo ""
}

welcomemsg() {
    echo ""
    echo ""
    echo "HARDN-XDR v${HARDN_VERSION} - Linux Security Hardening Sentinel"
    echo "================================================================"
    whiptail --title "HARDN-XDR v${HARDN_VERSION}" --msgbox "Welcome to HARDN-XDR v${HARDN_VERSION} - A Debian Security tool for System Hardening\n\nThis will apply STIG compliance, security tools, and comprehensive system hardening." 12 70
    echo ""
    echo "This installer will update your system first..."
    if whiptail --title "HARDN-XDR v${HARDN_VERSION}" --yesno "Do you want to continue with the installation?" 10 60; then
        true  
    else
        echo "Installation cancelled by user."
        exit 1
    fi
}

preinstallmsg() {
    echo ""
    whiptail --title "HARDN-XDR" --msgbox "Welcome to HARDN-XDR. A Linux Security Hardening program." 10 60
    echo "The system will be configured to ensure STIG and Security compliance."
   
}

update_system_packages() {
    HARDN_STATUS "pass" "Updating system packages..."
    if DEBIAN_FRONTEND=noninteractive timeout 10s apt-get -o Acquire::ForceIPv4=true update -y; then
        HARDN_STATUS "pass" "System package list updated successfully."
    else
        HARDN_STATUS "warning" "apt-get update failed or timed out after 60 seconds. Check your network or apt sources, but continuing script."
    fi
}

# install_package_dependencies
install_package_dependencies() {
    HARDN_STATUS "pass" "Installing package dependencies from ${PROGS_CSV_PATH}..."

    if ! command -v git >/dev/null 2>&1; then
        HARDN_STATUS "info" "Git is not installed. Attempting to install git..."
        if DEBIAN_FRONTEND=noninteractive apt-get install -y git >/dev/null 2>&1; then
            HARDN_STATUS "pass" "Successfully installed git."
        else
            HARDN_STATUS "error" "Failed to install git. Some packages might fail to install if they require git."
            # Do not exit, allow script to continue if git is not strictly needed by all packages
        fi
    else
        HARDN_STATUS "info" "Git is already installed."
    fi

    # Check if the CSV file exists
    if [[ ! -f "${PROGS_CSV_PATH}" ]]; then
        HARDN_STATUS "error" "Package list file not found: ${PROGS_CSV_PATH}"
        return 1
    fi

    # Read the CSV file, skipping the header
    while IFS=, read -r name version debian_min_version debian_codenames_str rest || [[ -n "$name" ]]; do
        # Skip comments and empty lines
        [[ -z "$name" || "$name" =~ ^[[:space:]]*# ]] && continue

        name=$(echo "$name" | xargs)
        version=$(echo "$version" | xargs)
        debian_min_version=$(echo "$debian_min_version" | xargs)
        debian_codenames_str=$(echo "$debian_codenames_str" | xargs | tr -d '"') # Remove quotes from codenames string

        if [[ -z "$name" ]]; then
            HARDN_STATUS "warning" "Skipping line with empty package name."
            continue
        fi

        HARDN_STATUS "info" "Processing package: $name (Version: $version, Min Debian: $debian_min_version, Codenames: '$debian_codenames_str')"

        # Check OS compatibility
        os_compatible=false
        if [[ ",${debian_codenames_str}," == *",${CURRENT_DEBIAN_CODENAME},"* ]]; then
            if [[ "${debian_min_version}" == "12" ]]; then
                os_compatible=true
            else
                HARDN_STATUS "warning" "Skipping $name: Requires Debian version >= $debian_min_version, but current is $CURRENT_DEBIAN_VERSION_ID."
            fi
        else
            HARDN_STATUS "warning" "Skipping $name: Not compatible with Debian codename $CURRENT_DEBIAN_CODENAME (requires one of: $debian_codenames_str)."
        fi

        if ! $os_compatible; then
            continue
        fi

        # Installation logic based on version
        case "$version" in
            "latest")
                if ! dpkg -s "$name" >/dev/null 2>&1; then
                    HARDN_STATUS "info" "Attempting to install package: $name (latest from apt)..."
                    if DEBIAN_FRONTEND=noninteractive apt install -y "$name"; then
                        HARDN_STATUS "pass" "Successfully installed $name."
                    else
                        HARDN_STATUS "warning" "apt install failed for $name, trying apt-get..."
                        if DEBIAN_FRONTEND=noninteractive apt-get install -y "$name"; then
                             HARDN_STATUS "pass" "Successfully installed $name with apt-get."
                        else
                            HARDN_STATUS "error" "Failed to install $name with both apt and apt-get. Please check manually."
                        fi
                    fi
                else
                    HARDN_STATUS "info" "Package $name is already installed."
                fi
                ;;
            "source")
                HARDN_STATUS "warning" "INFO: 'source' installation type for $name. This type requires manual implementation in the script."
                HARDN_STATUS "warning" "Example steps for a source install (e.g., for a package named 'mytool'):"
                HARDN_STATUS "warning" "  1. Ensure build dependencies are installed (e.g., build-essential, cmake, etc.)."
                HARDN_STATUS "warning" "  2. wget https://example.com/mytool-src.tar.gz -O /tmp/mytool-src.tar.gz"
                HARDN_STATUS "warning" "  3. tar -xzf /tmp/mytool-src.tar.gz -C /tmp"
                HARDN_STATUS "warning" "  4. cd /tmp/mytool-* || exit 1"
                HARDN_STATUS "warning" "  5. ./configure && make && sudo make install"
                HARDN_STATUS "warning" "Skipping $name as its specific source installation steps are not defined."
                ;;
            "custom")
                HARDN_STATUS "warning" "INFO: 'custom' installation type for $name. This type requires manual implementation in the script."
                HARDN_STATUS "warning" "Example steps for a custom install (e.g., for a package named 'mycustomapp'):"
                HARDN_STATUS "warning" "  1. Add custom repository: curl -sSL https://example.com/repo/gpg | sudo apt-key add -"
                HARDN_STATUS "warning" "  2. echo 'deb https://example.com/repo ${CURRENT_DEBIAN_CODENAME} main' | sudo tee /etc/apt/sources.list.d/mycustomapp.list"
                HARDN_STATUS "warning" "  3. sudo apt update"
                HARDN_STATUS "warning" "  4. sudo apt install -y mycustomapp"
                HARDN_STATUS "warning" "Skipping $name as its specific custom installation steps are not defined."
                ;;
            *)
                HARDN_STATUS "error" "Unknown version '$version' for package $name. Skipping..."
                ;;
        esac
    done < <(tail -n +2 "${PROGS_CSV_PATH}")
    HARDN_STATUS "pass" "Package dependency installation attempt completed."
}

print_ascii_banner() {

    local terminal_width
    terminal_width=$(tput cols)
    local banner
    banner=$(cat << "EOF"

   ▄█    █▄            ▄████████         ▄████████      ████████▄       ███▄▄▄▄   
  ███    ███          ███    ███        ███    ███      ███   ▀███      ███▀▀▀██▄ 
  ███    ███          ███    ███        ███    ███      ███    ███      ███   ███ 
 ▄███▄▄▄▄███▄▄        ███    ███       ▄███▄▄▄▄██▀      ███    ███      ███   ███ 
▀▀███▀▀▀▀███▀       ▀███████████      ▀▀███▀▀▀▀▀        ███    ███      ███   ███ 
  ███    ███          ███    ███      ▀███████████      ███    ███      ███   ███ 
  ███    ███          ███    ███        ███    ███      ███   ▄███      ███   ███ 
  ███    █▀           ███    █▀         ███    ███      ████████▀        ▀█   █▀  
                                        ███    ███ 
                           
                            Extended Detection and Response
                            by Security International Group
                                  
EOF
)
    local banner_width
    banner_width=$(echo "$banner" | awk '{print length($0)}' | sort -n | tail -1)
    local padding=$(( (terminal_width - banner_width) / 2 ))
    local i
    printf "\033[1;31m"
    while IFS= read -r line; do
        for ((i=0; i<padding; i++)); do
            printf " "
        done
        printf "%s\n" "$line"
    done <<< "$banner"
    sleep 2
    printf "\033[0m"

}

setup_security(){
    # OS detection is done by detect_os_details() 
    # global variables CURRENT_DEBIAN_VERSION_ID and CURRENT_DEBIAN_CODENAME are available.
    HARDN_STATUS "pass" "Using detected system: Debian ${CURRENT_DEBIAN_VERSION_ID} (${CURRENT_DEBIAN_CODENAME}) for security setup."
    HARDN_STATUS "info" "Setting up security tools and configurations..."
    source ./modules/ufw.sh 
	source ./modules/deleted_files.sh 
	source ./modules/ntp.sh
	source ./modules/usb.sh
	source ./modules/network_protocols.sh
	source ./modules/file_perms.sh
	source ./modules/shared_mem.sh
	source ./modules/coredumps.sh
	source ./modules/auto_updates.sh
	source ./modules/secure_net.sh
	source ./modules/rkhutner.sh
	source ./modules/stig_pwquality.sh
	source ./modules/chkrootkit.sh
	source ./modules/auditd.sh
	source ./modules/suricata.sh
	source ./modules/debsums.sh
	source ./modules/aide.sh
	source ./modules/yara.sh
	source ./modules/banner.sh
	source ./modules/cmopilers.sh
	source ./modules/grub.sh
	source ./modules/binfmt.sh
	source ./modules/purge_old_pkgs.sh
	source ./modules/dns_config.sh
	source ./modules/firewire.sh
}

enable_process_accounting_and_sysstat() {
        HARDN_STATUS "error" "Enabling process accounting (acct) and system statistics (sysstat)..."
        local changed_acct changed_sysstat
        changed_acct=false
        changed_sysstat=false

        # Enable Process Accounting (acct/psacct)
        HARDN_STATUS "info" "Checking and installing acct (process accounting)..."
        if ! dpkg -s acct >/dev/null 2>&1 && ! dpkg -s psacct >/dev/null 2>&1; then
            whiptail --infobox "Installing acct (process accounting)..." 7 60
            if apt-get install -y acct; then
                HARDN_STATUS "pass" "acct installed successfully."
                changed_acct=true
            else
                HARDN_STATUS "error" "Failed to install acct. Please check manually."
            fi
        else
            HARDN_STATUS "info" "acct/psacct is already installed."
        fi

        if dpkg -s acct >/dev/null 2>&1 || dpkg -s psacct >/dev/null 2>&1; then
            if ! systemctl is-active --quiet acct && ! systemctl is-active --quiet psacct; then
                HARDN_STATUS "info" "Attempting to enable and start acct/psacct service..."
                systemctl enable --now acct 2>/dev/null || systemctl enable --now psacct 2>/dev/null
                HARDN_STATUS "pass" "acct/psacct service enabled and started."
                changed_acct=true
            else
                HARDN_STATUS "pass" "acct/psacct service is already active."
            fi
        fi

        # Enable Sysstat
        HARDN_STATUS "info" "Checking and installing sysstat..."
        if ! dpkg -s sysstat >/dev/null 2>&1; then
            whiptail --infobox "Installing sysstat..." 7 60
            if apt-get install -y sysstat; then
                HARDN_STATUS "pass" "sysstat installed successfully."
                changed_sysstat=true
            else
                HARDN_STATUS "error" "Failed to install sysstat. Please check manually."
            fi
        else
            HARDN_STATUS "info" "sysstat is already installed."
        fi

        if dpkg -s sysstat >/dev/null 2>&1; then
            local sysstat_conf
            sysstat_conf="/etc/default/sysstat"
            if [[ -f "$sysstat_conf" ]]; then
                if ! grep -qE '^\s*ENABLED="true"' "$sysstat_conf"; then
                    HARDN_STATUS "info" "Enabling sysstat data collection in $sysstat_conf..."
                    sed -i 's/^\s*ENABLED="false"/ENABLED="true"/' "$sysstat_conf"
                    if ! grep -qE '^\s*ENABLED=' "$sysstat_conf"; then
                        echo 'ENABLED="true"' >> "$sysstat_conf"
                    fi
                    changed_sysstat=true
                    HARDN_STATUS "pass" "sysstat data collection enabled."
                else
                    HARDN_STATUS "pass" "sysstat data collection is already enabled in $sysstat_conf."
                fi
            else
                HARDN_STATUS "warning" "sysstat configuration file $sysstat_conf not found. Manual check might be needed."
            fi

            if ! systemctl is-active --quiet sysstat; then
                HARDN_STATUS "info" "Attempting to enable and start sysstat service..."
                if systemctl enable --now sysstat; then
                    HARDN_STATUS "pass" "sysstat service enabled and started."
                    changed_sysstat=true
                else
                    HARDN_STATUS "error" "Failed to enable/start sysstat service."
                fi
            else
                HARDN_STATUS "pass" "sysstat service is already active."
            fi
        fi

        if [[ "$changed_acct" = true || "$changed_sysstat" = true ]]; then
            HARDN_STATUS "pass" "Process accounting (acct) and sysstat configured successfully."
        else
            HARDN_STATUS "pass" "Process accounting (acct) and sysstat already configured or no changes needed."
        fi
    }
    
apply_kernel_security() {
    HARDN_STATUS "info" "Applying kernel security settings..."

    declare -A kernel_params=(
        # === Console and Memory Protections ===
        ["dev.tty.ldisc_autoload"]="0"
        ["fs.protected_fifos"]="2"
        ["fs.protected_hardlinks"]="1"
        ["fs.protected_regular"]="2"
        ["fs.protected_symlinks"]="1"
        ["fs.suid_dumpable"]="0"

        # === Kernel Info Leak Prevention ===
        ["kernel.core_uses_pid"]="1"
        ["kernel.ctrl-alt-del"]="0"
        ["kernel.dmesg_restrict"]="1"
        ["kernel.kptr_restrict"]="2"

        # === Performance & BPF ===
        ["kernel.perf_event_paranoid"]="2"
        ["kernel.randomize_va_space"]="2"
        ["kernel.unprivileged_bpf_disabled"]="1"

        # === BPF JIT Hardening ===
        ["net.core.bpf_jit_harden"]="2"

        # === IPv4 Hardening ===
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.default.accept_redirects"]="0"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv4.conf.default.accept_source_route"]="0"
        ["net.ipv4.conf.all.bootp_relay"]="0"
        ["net.ipv4.conf.all.forwarding"]="0"
        ["net.ipv4.conf.all.log_martians"]="1"
        ["net.ipv4.conf.default.log_martians"]="1"
        ["net.ipv4.conf.all.mc_forwarding"]="0"
        ["net.ipv4.conf.all.proxy_arp"]="0"
        ["net.ipv4.conf.all.rp_filter"]="1"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["net.ipv4.conf.default.send_redirects"]="0"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
        ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
        ["net.ipv4.tcp_syncookies"]="1"
        ["net.ipv4.tcp_timestamps"]="1"

        # === IPv6 Hardening ===
        ["net.ipv6.conf.all.accept_redirects"]="0"
        ["net.ipv6.conf.default.accept_redirects"]="0"
        ["net.ipv6.conf.all.accept_source_route"]="0"
        ["net.ipv6.conf.default.accept_source_route"]="0"
    )

    for param in "${!kernel_params[@]}"; do
        expected_value="${kernel_params[$param]}"
        current_value=$(sysctl -n "$param" 2>/dev/null)

        if [[ -z "$current_value" ]]; then
            HARDN_STATUS "warning" "Kernel parameter '$param' not found. Skipping."
            continue
        fi

        if [[ "$current_value" != "$expected_value" ]]; then
            HARDN_STATUS "info" "Setting '$param' to '$expected_value' (was '$current_value')..."
            sed -i "/^$param\s*=/d" /etc/sysctl.conf
            echo "$param = $expected_value" >> /etc/sysctl.conf
            sysctl -w "$param=$expected_value" >/dev/null 2>&1
            HARDN_STATUS "pass" "'$param' set to '$expected_value'."
        else
            HARDN_STATUS "info" "'$param' is already set to '$expected_value'."
        fi
    done

    sysctl --system >/dev/null 2>&1
    HARDN_STATUS "pass" "Kernel hardening applied successfully."
}

# Central logging
setup_central_logging() {
    HARDN_STATUS "error" "Setting up central logging for security tools..."

    # Check and install rsyslog and logrotate if necessary
    local logging_packages="rsyslog logrotate"
    HARDN_STATUS "info" "Checking and installing logging packages ($logging_packages)..."
    # shellcheck disable=SC2086
    if ! dpkg -s $logging_packages >/dev/null 2>&1; then
        # shellcheck disable=SC2086
        if apt-get update >/dev/null 2>&1 && apt-get install -y $logging_packages >/dev/null 2>&1; then
            HARDN_STATUS "pass" "Logging packages installed successfully."
        else
            HARDN_STATUS "error" "Error: Failed to install logging packages. Skipping central logging configuration."
            return 1 # Exit this section if packages fail to install
        fi
    else
        HARDN_STATUS "pass" "Logging packages are already installed."
    fi


    # Create necessary directories
    # ADD ALL DIR's fo monitoring
    HARDN_STATUS "info" "Creating log directories and files..."
    mkdir -p /usr/local/var/log/suricata
    # Note: /var/log/suricata is often created by the suricata package itself
    touch /usr/local/var/log/suricata/hardn-xdr.log
    chmod 640 /usr/local/var/log/suricata/hardn-xdr.log
    chown root:adm /usr/local/var/log/suricata/hardn-xdr.log
    HARDN_STATUS "pass" "Log directory /usr/local/var/log/suricata created and permissions set."


    # Create rsyslog configuration for centralized logging
    HARDN_STATUS "info" "Creating rsyslog configuration file /etc/rsyslog.d/30-hardn-xdr.conf..."
    cat > /etc/rsyslog.d/30-hardn-xdr.conf << 'EOF'
# HARDN-XDR Central Logging Configuration
# This file is automatically generated by HARDN-XDR.
# Any manual changes may be overwritten.

# Create a template for security logs
$template HARDNFormat,"%TIMESTAMP% %HOSTNAME% %syslogtag%%msg%\n"

# Define the central log file path
local5.* /usr/local/var/log/suricata/hardn-xdr.log;HARDNFormat

# Specific rules to route logs to local5 facility if they don't use it by default
# Suricata (often uses local5, but explicit rule ensures it)
if $programname == 'suricata' then local5.*
# AIDE
if $programname == 'aide' then local5.*
# Fail2Ban
if $programname == 'fail2ban' then local5.*
# AppArmor
if $programname == 'apparmor' then local5.*
# Auditd/SELinux (auditd logs via auditd, setroubleshoot logs via setroubleshoot)
if $programname == 'audit' or $programname == 'setroubleshoot' then local5.*
# RKHunter (often logs with tag rkhunter)
if $programname == 'rkhunter' or $syslogtag contains 'rkhunter' then local5.*
# Debsums (piped to logger, tag might be debsums or CRON)
if $programname == 'debsums' or $syslogtag contains 'debsums' then local5.*
# Lynis (cronjob logs via logger, tag might be lynis or CRON)
if $programname == 'lynis' or $syslogtag contains 'lynis' then local5.*

# Stop processing these messages after they are sent to the central log
& stop
EOF
    chmod 644 /etc/rsyslog.d/30-hardn-xdr.conf
    HARDN_STATUS "pass" "Rsyslog configuration created/updated."


    # Create logrotate configuration for the central log
    HARDN_STATUS "info" "Creating logrotate configuration file /etc/logrotate.d/hardn-xdr..."
    cat > /etc/logrotate.d/hardn-xdr << 'EOF'
/usr/local/var/log/suricata/hardn-xdr.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
    postrotate
        # Ensure rsyslog reloads its configuration or reopens log files
        # Use the standard rsyslog-rotate script if available, otherwise restart
        if [ -x /usr/lib/rsyslog/rsyslog-rotate ]; then
            /usr/lib/rsyslog/rsyslog-rotate
        else
            systemctl reload rsyslog >/dev/null 2>&1 || true
        fi
    endscript
    # Add a prerotate script to ensure the file exists and has correct permissions before rotation
    prerotate
        if [ ! -f /usr/local/var/log/suricata/hardn-xdr.log ]; then
            mkdir -p /usr/local/var/log/suricata
            touch /usr/local/var/log/suricata/hardn-xdr.log
        fi
        chmod 640 /usr/local/var/log/suricata/hardn-xdr.log
        chown root:adm /usr/local/var/log/suricata/hardn-xdr.log
    endscript
}
EOF
    chmod 644 /etc/logrotate.d/hardn-xdr
    HARDN_STATUS "pass" "Logrotate configuration created/updated."



    # Restart rsyslog to apply changes
    HARDN_STATUS "info" "Restarting rsyslog service to apply configuration changes..."
    if systemctl restart rsyslog; then
        HARDN_STATUS "pass" "Rsyslog service restarted successfully."
    else
        HARDN_STATUS "error" "Failed to restart rsyslog service. Manual check required."
    fi

    # Create a symlink in /var/log for easier access
    HARDN_STATUS "info" "Creating symlink /var/log/hardn-xdr.log..."
    ln -sf /usr/local/var/log/suricata/hardn-xdr.log /var/log/hardn-xdr.log
    HARDN_STATUS "pass" "Symlink created at /var/log/hardn-xdr.log."


    HARDN_STATUS "pass" "Central logging setup complete. All security logs will be collected in /usr/local/var/log/suricata/hardn-xdr.log"
}

disable_service_if_active() {
    local service_name
    service_name="$1"
    if systemctl is-active --quiet "$service_name"; then
        HARDN_STATUS "error" "Disabling active service: $service_name..."
        systemctl disable --now "$service_name" || HARDN_STATUS "warning" "Failed to disable service: $service_name (may not be installed or already disabled)."
    elif systemctl list-unit-files --type=service | grep -qw "^$service_name.service"; then
        HARDN_STATUS "error" "Service $service_name is not active, ensuring it is disabled..."
        systemctl disable "$service_name" || HARDN_STATUS "warning" "Failed to disable service: $service_name (may not be installed or already disabled)."
    else
        HARDN_STATUS "info" "Service $service_name not found or not installed. Skipping."
    fi
}

remove_unnecessary_services() {
    HARDN_STATUS "pass" "Disabling unnecessary services..."
    
    disable_service_if_active avahi-daemon
    disable_service_if_active cups
    disable_service_if_active rpcbind
    disable_service_if_active nfs-server
    disable_service_if_active smbd
    disable_service_if_active snmpd
    disable_service_if_active apache2
    disable_service_if_active mysql
    disable_service_if_active bind9


    packages_to_remove="telnet vsftpd proftpd tftpd postfix exim4"
    for pkg in $packages_to_remove; do
        if dpkg -s "$pkg" >/dev/null 2>&1; then
            HARDN_STATUS "error" "Removing package: $pkg..."
            apt remove -y "$pkg"
        else
            HARDN_STATUS "info" "Package $pkg not installed. Skipping removal."
        fi
    done

    HARDN_STATUS "pass" "Unnecessary services checked and disabled/removed where applicable."
}

audit_system() {
    HARDN_STATUS "info" "Applying safe Lynis score improvements..."

    # Set secure permissions on /tmp and /var/tmp
    chmod 1777 /tmp
    if [[ -d /var/tmp ]]; then
        chmod 1777 /var/tmp
    fi

    # Secure log file permissions (safe default)
    find /var/log -type f -exec chmod 640 {} \; 2>/dev/null || true
    find /var/log -type d -exec chmod 750 {} \; 2>/dev/null || true

    # SSH hardening with safe login defaults
    local ssh_config="/etc/ssh/sshd_config"
    if [[ -f "$ssh_config" ]]; then
        HARDN_STATUS "info" "Enhancing SSH configuration for better Lynis scores..."
        cp "$ssh_config" "${ssh_config}.bak.hardn" 2>/dev/null || true

        declare -A ssh_settings=(
            ["ClientAliveInterval"]="300"
            ["ClientAliveCountMax"]="0"
            ["MaxStartups"]="10:30:60"
            ["LoginGraceTime"]="60"
            ["MaxSessions"]="4"
            ["PermitRootLogin"]="prohibit-password"
            ["PasswordAuthentication"]="yes"
            ["X11Forwarding"]="no"
            ["UsePAM"]="yes"
            ["Protocol"]="2"
        )

        for key in "${!ssh_settings[@]}"; do
            val="${ssh_settings[$key]}"
            if grep -qE "^#*\s*${key}\b" "$ssh_config"; then
                sed -i "s/^#*\s*${key}.*/${key} ${val}/" "$ssh_config"
            else
                echo "${key} ${val}" >> "$ssh_config"
            fi
        done

        systemctl reload ssh 2>/dev/null || true
    fi

    # Kernel parameter improvements
    HARDN_STATUS "info" "Applying additional kernel parameters for Lynis score improvement..."
    local sysctl_lynis="/etc/sysctl.d/99-lynis-hardening.conf"
    cat > "$sysctl_lynis" << 'EOF'
# Additional kernel parameters for Lynis score improvement
# Generated by HARDN-XDR

# Network security enhancements
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2
net.ipv4.tcp_syncookies = 1

# Additional memory protection
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Process restrictions
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
EOF

    sysctl -p "$sysctl_lynis" >/dev/null 2>&1 || true

    # PAM configuration improvements
    HARDN_STATUS "info" "Enhancing PAM configuration for Lynis scores..."
    local pam_login="/etc/pam.d/login"
    if [[ -f "$pam_login" ]] && ! grep -q "pam_limits.so" "$pam_login"; then
        echo "session required pam_limits.so" >> "$pam_login"
    fi

    # Limits hardening
    if ! grep -q '\* hard core 0' /etc/security/limits.conf 2>/dev/null; then
        echo '* hard core 0' >> /etc/security/limits.conf
    fi

    # File permission hardening
    chmod 644 /etc/crontab 2>/dev/null || true
    chmod -R 644 /etc/cron.d/* 2>/dev/null || true
    chmod -R 755 /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly 2>/dev/null || true

    chmod 644 /etc/passwd 2>/dev/null || true
    chmod 640 /etc/shadow 2>/dev/null || true
    chmod 644 /etc/group 2>/dev/null || true
    chmod 640 /etc/gshadow 2>/dev/null || true

    # Remove world-writable permissions from .conf files only
    HARDN_STATUS "info" "Removing world-writable permissions from system config files..."
    find /etc -type f -name "*.conf" -perm -002 -exec chmod o-w {} \; 2>/dev/null || true

    # Set umask
    if ! grep -q "umask 027" /etc/profile; then
        echo "umask 027" >> /etc/profile
    fi

    # Set login banners (safe overwrite)
    echo 'Unauthorized access is prohibited.' > /etc/issue
    echo 'Unauthorized access is prohibited.' > /etc/issue.net

    # Mail queue permissions
    if command -v postfix >/dev/null 2>&1; then
        chmod 700 /var/spool/postfix/maildrop 2>/dev/null || true
    fi

    HARDN_STATUS "pass" "Lynis score improvements applied successfully."
}
    
pen_test() {
    HARDN_STATUS "info" "Running comprehensive security audit with Lynis and nmap..."
    
    # Ensure Lynis is installed (it should be from progs.csv)
    if ! command -v lynis >/dev/null 2>&1; then
        HARDN_STATUS "info" "Installing Lynis..."
        apt-get install lynis -y >/dev/null 2>&1
    fi
    
    # Create Lynis log directory
    mkdir -p /var/log/lynis
    chmod 750 /var/log/lynis
    
    # Apply Lynis score improvements first
    improve_lynis_score
    
    # Run comprehensive Lynis audit
    HARDN_STATUS "info" "Running comprehensive Lynis system audit..."
    lynis audit system --verbose --log-file /var/log/lynis/hardn-audit.log --report-file /var/log/lynis/hardn-report.dat 2>/dev/null
    
    # Run Lynis with pentest profile for additional checks
    HARDN_STATUS "info" "Running Lynis penetration testing profile..."
    lynis audit system --pentest --verbose --log-file /var/log/lynis/hardn-pentest.log 2>/dev/null
    
    # Generate Lynis report
    if [[ -f /var/log/lynis/hardn-report.dat ]]; then
        HARDN_STATUS "pass" "Lynis audit completed. Report saved to /var/log/lynis/hardn-report.dat"
        
        # Extract and display hardening index if available
        local hardening_index
        hardening_index=$(grep "hardening_index=" /var/log/lynis/hardn-report.dat 2>/dev/null | cut -d'=' -f2)
        if [[ -n "$hardening_index" ]]; then
            HARDN_STATUS "info" "Lynis Hardening Index: ${hardening_index}%"
        fi
    else
        HARDN_STATUS "warning" "Lynis report file not found. Check /var/log/lynis/ for details."
    fi
    
    # Run nmap scan for network security assessment
    HARDN_STATUS "info" "Starting network security assessment with nmap..."
    
    # Install nmap if not present
    if ! command -v nmap >/dev/null 2>&1; then
        apt install nmap -y >/dev/null 2>&1
    fi
    
    # Create nmap log directory
    mkdir -p /var/log/nmap
    chmod 750 /var/log/nmap
    
    # Run comprehensive nmap scan
    nmap -sS -sV -O -p- localhost > /var/log/nmap/hardn-localhost-scan.log 2>&1 &
    local nmap_pid=$!
    
    # Run network interface scan
    local interface_ip
    interface_ip=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' | head -1)
    if [[ -n "$interface_ip" ]]; then
        nmap -sn "${interface_ip%.*}.0/24" > /var/log/nmap/hardn-network-discovery.log 2>&1 &
    fi
    
    # Wait for localhost scan to complete
    wait $nmap_pid
    if wait $nmap_pid; then
        HARDN_STATUS "pass" "Network security scan completed. Results saved to /var/log/nmap/"
    else
        HARDN_STATUS "error" "Network scan encountered issues. Check /var/log/nmap/ for details."
    fi
    
    # Summary of security audit
    HARDN_STATUS "info" "Security audit summary:"
    HARDN_STATUS "info" "- Lynis reports: /var/log/lynis/"
    HARDN_STATUS "info" "- Network scans: /var/log/nmap/"
    HARDN_STATUS "info" "- Review these files for security recommendations"
}

cleanup() {
    HARDN_STATUS "info" "Performing final system cleanup..."
    apt-get autoremove -y >/dev/null 2>&1
    apt-get clean >/dev/null 2>&1
    apt-get autoclean >/dev/null 2>&1
    HARDN_STATUS "pass" "System cleanup completed. Unused packages and cache cleared."
    whiptail --infobox "HARDN-XDR v${HARDN_VERSION} setup complete! Please reboot your system." 8 75
    sleep 3

}

main() {
    print_ascii_banner
    show_system_info
    welcomemsg
    update_system_packages
    install_package_dependencies "../../progs.csv"
    setup_security
    apply_kernel_security
    enable_nameservers
    enable_process_accounting_and_sysstat
    purge_old_packages
    disable_firewire_drivers
    restrict_compilers
    disable_binfmt_misc
    remove_unnecessary_services
    setup_grub_password
    setup_central_logging
    audit_system
    pen_test
    cleanup
    print_ascii_banner

    HARDN_STATUS "pass" "HARDN-XDR v${HARDN_VERSION} installation completed successfully!"
    HARDN_STATUS "info" "Your system has been hardened with STIG compliance and security tools."
    HARDN_STATUS "warning" "Please reboot your system to complete the configuration."
}

# Command line argument handling
if [[ $# -gt 0 ]]; then
    case "$1" in
        --version|-v)
            echo "HARDN-XDR v${HARDN_VERSION}"
            echo "Linux Security Hardening Sentinel"
            echo "Extended Detection and Response"
            echo ""
            echo "Target Systems: Debian 12+, Ubuntu 24.04+"
            echo "Features: STIG Compliance, Malware Detection, System Hardening"
            echo "Developed by: Christopher Bingham and Tim Burns"
            echo ""
            echo "This is the final public release of HARDN-XDR."
            exit 0
            ;;
        --help|-h)
            echo "HARDN-XDR v${HARDN_VERSION} - Linux Security Hardening Sentinel"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --version, -v    Show version information"
            echo "  --help, -h       Show this help message"
            echo ""
            echo "This script applies comprehensive security hardening to Debian-based systems"
            echo "including STIG compliance, malware detection, and security monitoring."
            echo ""
            echo "WARNING: This script makes significant system changes. Run only on systems"
            echo "         intended for security hardening."
            exit 0
            ;;
        *)
            echo "Error: Unknown option '$1'"
            echo "Use '$0 --help' for usage information."
            exit 1
            ;;
    esac
fi

main
