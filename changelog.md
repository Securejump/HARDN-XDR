# Changelog

## Version 1.2.0 - Debian Packaging & Workflow Automation (2025-06-22)

### Added
- **Debian Packaging**: Implemented a complete Debian packaging workflow using `dpkg-buildpackage` for robust and standardized installations.
- **GitHub Actions CI/CD**: Created `.github/workflows/build_release.yml` to automatically build the `.deb` package on pushes to `main` and `deb-package`, and create a GitHub Release with the package for pushes to `main`.
- **One-Command Installer**: Added a user-friendly one-command installer script (`scripts/hardn.sh`) for end-users to easily fetch and install the latest release from GitHub.
- **Lynis Compliance Enhancements**: Added kernel hardening, password policies, login banners, AIDE initialization, scheduled security scans, and process accounting to `hardn-main.sh` to significantly improve Lynis compliance score.
- **Main Executable**: Created a main executable at `/usr/local/bin/hardn` which acts as the primary entry point for the application.

### Improved
- **Installation Process**: Overhauled the installation process, providing two clear paths: a source install for developers (`install.sh`) and a package-based install for end-users (`.deb`).
- **Script Quality**: Performed a full `shellcheck` audit on all shell scripts (`hardn-main.sh`, `packages.sh`, `install.sh`) and fixed all actionable warnings, improving script reliability and maintainability.
- **Documentation**: Significantly updated `README.md` to explain the new installation methods, the role of each script, and the automated build/release process.
- **Permissions Handling**: Ensured all scripts are correctly set as executable during both source and Debian package installations via `install.sh` and `debian/postinst`.

### Fixed
- **Packaging Manifest**: Corrected `debian/install` to only include necessary files (`hardn`, `hardn-main.sh`, `packages.sh`) in the final `.deb` package.
- **README.md Rendering**: Fixed Mermaid diagram syntax in `README.md` to ensure it renders correctly.

---


#### Added
- **Version Tracking**: Added explicit version identifier (v2.0.0) throughout the script and user interface
- **Enhanced User Experience**: Improved welcome messages, banners, and completion notifications with version information
- **Production Ready**: Finalized as the definitive public release of HARDN-XDR

#### Improved
- **User Interface**: Enhanced all user-facing messages with clearer version information and better formatting
- **Feedback Systems**: Improved completion messages and system cleanup notifications
- **Code Quality**: Maintained high code quality standards from previous ShellCheck improvements

#### Fixed
- **Version Consistency**: Unified version numbering across all components
- **User Communication**: Better feedback during installation and completion phases

### Final Mission Goals
- Comprehensive STIG compliance for Debian-based systems
- Advanced malware detection and response capabilities
- Complete system hardening with security tools integration
- Central logging and monitoring systems
- Extended Detection and Response (XDR) functionality

---

## Version 1.1.8-9

### Added
- **New Feature**: Introduced a new feature for enhanced system monitoring.

### Improved
- **Performance**: Optimized system performance for faster execution of tasks.

### Fixed
- **Bug Fixes**: Resolved minor bugs reported in version `1.1.6`.

---
## Version 1.1.6

### Added
- **Internet Connectivity Check**: Added a function to verify internet connectivity before proceeding with the setup.
- **Linux Malware Detect (maldet)**: Automated installation and configuration of maldet.
- **Audit Rules**: Configured audit rules for critical system files like `/etc/passwd` and `/etc/shadow`.

### Improved
- **File Permissions**: Fixed permissions for critical files such as `/etc/shadow` and `/etc/passwd`.
- **Service Management**: Enhanced error handling and ensured `Fail2Ban`, `AppArmor`, and `auditd` are enabled and running at boot.
- **SSH Hardening**: Enforced stricter SSH settings for improved security.
- **Kernel Randomization**: Ensured kernel randomization is applied persistently and at runtime.

### Fixed
- **Error Handling**: Improved error handling for services like `Fail2Ban`, `AppArmor`, and `auditd` to prevent setup failures.


---

## Version 1.1.5

### Added
- **Debian Packaging**: Added support for building Debian packages for HARDN.
- **Error Handling**: Enhanced error handling in scripts to prevent disruptions to user logins or system functionality.

### Improved
- **Script Optimization**: Removed redundant steps and consolidated repetitive code blocks in setup scripts.
- **Documentation**: Updated documentation to reflect the latest changes and features.

### Fixed
- **Cron Jobs**: Ensured cron jobs are non-intrusive and do not disrupt user workflows.
- **GRUB BUG**: removed dependant file due to PAM collision and Kernal alerting flaw.
- **AIDE Initialization**: Improved AIDE initialization process for better reliability.


---

