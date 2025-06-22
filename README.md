<p align="center">
  <img src="https://img.shields.io/badge/OS: Debian Systems-red?style=for-the-badge&labelColor=grey" alt="OS: DEBIAN 12"><br><br>
</p>

<p align="center">
  <img src="https://github.com/OpenSource-For-Freedom/HARDN-XDR/blob/main/docs/assets/HARDN%20(1).png" /><br><br>
  <img src="https://img.shields.io/badge/The_Linux_Security_Project-red?style=for-the-badge&labelColor=black" alt="The Linux Security Project"><br><br>
  <code>HARDN-XDR</code>
</p>


<p align="center">
  <img src="https://img.shields.io/endpoint?label=Views&url=https://opensource-for-freedom.github.io/HARDN-XDR/traffic-views.json" alt="Repository Views" />
  <img src="https://img.shields.io/endpoint?label=Clones&url=https://opensource-for-freedom.github.io/HARDN-XDR/traffic-clones.json" alt="Repository Clones" />
</p>


<br>
<br>
<p align="center">
  <img src="https://img.shields.io/badge/OVERVIEW-white?style=for-the-badge&labelColor=black" alt="OVERVIEW"><br><br>
</p>


## HARDN-XDR
- **Our Goal**:
  - Assist the open source community in building a Debian based **"GOLDEN IMAGE"** System.
- **Our Purpose**:
  - To empower IT administrators and users with the tools they need to ensure endpoint security, optimize performance, and maintain compliance across their organization.
- **What we have to offer**:
  - A robust and secure endpoint management solution designed to simplify and enhance the management of devices in your network.
  - Advanced features for monitoring, securing, and maintaining endpoints efficiently.
  - `STIG` COMPLIANCE to align with the [Security Technical Information Guides](https://public.cyber.mil/stigs/) provided by the [DOD Cyber Exchange](https://public.cyber.mil/).


<br>
<br>
<p align="center">
  <img src="https://img.shields.io/badge/FEATURES-white?style=for-the-badge&labelColor=black" alt="FEATURES"><br><br>
</p>

- **Comprehensive Monitoring**: Real-time insights into endpoint performance and activity.
- **Enhanced Security**: Protect endpoints with advanced security protocols.
- **Scalability**: Manage endpoints across small to large-scale networks.
- **User-Friendly Interface**: Intuitive design for seamless navigation and management.
- **STIG Compliance**: This release brings the utmost security for Debian Government based information systems.


<br>
<br>
<p align="center">
  <img src="https://img.shields.io/badge/INSTALLATION-white?style=for-the-badge&labelColor=black" alt="INSTALLATION"><br><br>
</p>

There are two ways to install HARDN-XDR. The recommended method for most users is via the pre-built Debian package. The source installation is intended for developers or advanced users.

---

### Method 1: Install via Debian Package (Recommended for Users)

This method uses the latest stable release, packaged as a `.deb` file. It's the fastest and most reliable way to get started.

#### One-Command Install

Run the following command in your terminal. It will automatically download the latest release, install it, and handle all dependencies.

```bash
wget https://raw.githubusercontent.com/OpenSource-For-Freedom/HARDN-XDR/deb-package/install.sh
sudo chmod +x install.sh
sudo bash -x install.sh
```

### How to Run

Regardless of the installation method, you can start the hardening process by running:

```bash
sudo hardn start
```

<br>

### Installation Notes
- HARDN-XDR is currently being developed and tested for **BARE-METAL installs of Debian based distributions and Virtual Machines**.
- Ensure you have the latest version of **Debian 12** or **Ubuntu 24.04**.
- By installing HARDN-XDR with the commands listed in the installation process, the following changes will be made to your system:
> - A collection of security focused packages will be installed.
> - Security tools and services will be enabled.
> - System hardening and STIG settings will be applied.
> - A malware and signature detection and response system will be set up.
> - A monitoring and reporting system will be activated.
- For a detailed list of all that will be changed, please refer to [HARDN.md](docs/HARDN.md).
- For an overview of HARDN-Debian STIG Compliance, please refer to [deb_stig.md](docs/deb_stig.md).



<br>


## Actions
- [![Build and Release](https://github.com/OpenSource-For-Freedom/HARDN-XDR/actions/workflows/build_deploy.yml/badge.svg)](https://github.com/OpenSource-For-Freedom/HARDN-XDR/actions/workflows/build_deploy.yml)
<br>

## Build Workflow: Debian Package

```mermaid
flowchart TD
  A([<b>Source Code & Scripts</b>]):::source --> B([<b>Update debian/ Packaging Files</b>]):::packaging
  B --> C([<b>Edit debian/control, install, postinst, rules</b>]):::packaging
  C --> D([<b>Build .deb Package<br>with dpkg-buildpackage</b>]):::build
  D --> E([<b>.deb Package Output</b>]):::output
  E --> F([<b>Test Install<br>on Debian/Ubuntu System</b>]):::test
  F --> G([<b>Run Lintian & QA Checks</b>]):::qa
  G --> H([<b>Push Changes<br>to GitHub</b>]):::vcs
  H --> I([<b>GitHub Actions:<br>build_deploy.yml</b>]):::ci
  I --> J([<b>CI/CD:<br>Automatic Build & Release</b>]):::ci
  J --> K(["<b>Release Assets<br>(.deb) Published</b>"]):::release

  classDef source fill:#e6f7ff,stroke:#1890ff,stroke-width:2;
  classDef packaging fill:#fffbe6,stroke:#faad14,stroke-width:2;
  classDef build fill:#f6ffed,stroke:#52c41a,stroke-width:2;
  classDef output fill:#f9f0ff,stroke:#722ed1,stroke-width:2;
  classDef test fill:#fff0f6,stroke:#eb2f96,stroke-width:2;
  classDef qa fill:#f0f5ff,stroke:#2f54eb,stroke-width:2;
  classDef vcs fill:#f0f0f0,stroke:#595959,stroke-width:2;
  classDef ci fill:#e6fffb,stroke:#13c2c2,stroke-width:2;
  classDef release fill:#fff1f0,stroke:#f5222d,stroke-width:2;
```

**Legend:**
- <span style="color:#1890ff"><b>Source</b></span>: Project code and scripts.
- <span style="color:#faad14"><b>Packaging</b></span>: Debian packaging files (`debian/`).
- <span style="color:#52c41a"><b>Build</b></span>: Building the `.deb` package.
- <span style="color:#722ed1"><b>Output</b></span>: Generated `.deb` file.
- <span style="color:#eb2f96"><b>Test</b></span>: Local install and verification.
- <span style="color:#2f54eb"><b>QA</b></span: Lintian and quality checks.
- <span style="color:#595959"><b>VCS</b></span>: Version control (GitHub).
- <span style="color:#13c2c2"><b>CI/CD</b></span>: Automated build and release.
- <span style="color:#f5222d"><b>Release</b></span>: Published assets for users.



## File Structure


```bash
HARDN-XDR/
├── .github/workflows/
│   └── build_deploy.yml
├── changelog.md
├── debian/
│   ├── control
│   ├── install
│   ├── postinst
│   └── rules
├── docs/
├── install.sh
├── LICENSE
├── README.md
├── src/
│   └── setup/
│       └── hardn-main.sh
└── usr/
    └── local/
        └── bin/
            └── hardn
```



<br>

<p align="center">
  <img src="https://img.shields.io/badge/PROJECT PARTNERS-white?style=for-the-badge&labelColor=black" alt="PROJECT PARTNERS"><br><br>
</p>


<p align="center">
  <img src="docs/assets/cybersynapse.png" alt="cybersynapse Logo" />
</p>

<br>

<p align="center">
  <img src="https://img.shields.io/badge/LICENSE-white?style=for-the-badge&labelColor=black" alt="LICENSE"><br><br>
This project is licensed under the MIT License.

</p>

<br>

<p align="center">
  <img src="https://img.shields.io/badge/CONTACT-white?style=for-the-badge&labelColor=black" alt="CONTACT"><br><br>
office@cybersynapse.ro
</p>



