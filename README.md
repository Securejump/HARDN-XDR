<p align="center">
  <img src="https://img.shields.io/badge/OS:FreeBSD-red?style=for-the-badge&labelColor=grey" alt="OS: FreeBSD 14"><br><br>
</p>

<p align="center">
  <img src="docs/assets/HARDN(1).png" alt="HARDN Logo" width="300px" /><br><br>
  <img src="https://img.shields.io/badge/The_Linux_Security_Project-red?style=for-the-badge&labelColor=black" alt="The Linux Security Project"><br><br>
  <code>HARDN-Endpoint</code>
</p>



<p align="center">
  <img src="https://img.shields.io/badge/OVERVIEW-white?style=for-the-badge&labelColor=black" alt="OVERVIEW"><br><br>
</p>


### HARDN Endpoint
- This installation is only for **BARE-METAL INSTALLS of FreeBSD 14**
-  Is a robust and secure endpoint management solution designed to simplify and enhance the management of devices in your network. It provides advanced features for monitoring, securing, and maintaining endpoints efficiently.

- We also bring you with this release `STIG` COMPLIANCE to align with the Security Technical Information Guides provided by the DOD Cyber Exchange.


```bash
HARDN/
├── .gitignore
├── README.md
├── changelog.md
├── docs/
│   ├── LICENSE
│   └── assets/
│       ├── HARDN(1).png
│       └── cybersynapse.png
├── src/
│   └── setup/
│       ├── packages.sh
│       └── setup.sh
```

</p>



<p align="center">
  <img src="https://img.shields.io/badge/FEATURES-white?style=for-the-badge&labelColor=black" alt="FEATURES"><br><br>
</p>

- **Comprehensive Monitoring**: Real-time insights into endpoint performance and activity.
- **Enhanced Security**: Protect endpoints with advanced security protocols.
- **Scalability**: Manage endpoints across small to large-scale networks.
- **User-Friendly Interface**: Intuitive design for seamless navigation and management.
- **STIG Compliance**: This release brings the utmost, security for Debian Government based informatin systems. 

<p align="center">
  <img src="https://img.shields.io/badge/PURPOSE-white?style=for-the-badge&labelColor=black" alt="PURPOSE"><br><br>
</p>

The purpose of HARDN Endpoint is to empower IT administrators and users with the tools they need to ensure endpoint security, optimize performance, and maintain compliance across their organization.

<p align="center">
  <img src="https://img.shields.io/badge/INSTALLATION-white?style=for-the-badge&labelColor=black" alt="INSTALLATION"><br><br>
</p>


1. Clone the repository from GitHub:
  ```bash
git clone --branch dev-freebsd https://github.com/OpenSource-For-Freedom/HARDN.git
  ```
2. Navigate to the `src` directory:
 ```bash
  cd HARDN/src/setup
  sudo chmod +x setup.sh
  sudo ./setup.sh

  ```


### Quick Setup for FreeBSD VM Usage

```bash
pkg update -f && pkg upgrade -y
pkg install -y git sudo python3
git clone --branch dev-freebsd https://github.com/OpenSource-For-Freedom/HARDN.git
cd HARDN/src/setup
chmod +x setup.sh
sudo ./setup.sh
```

  This will kick off the full setup of HARDN with `STIG` principles for FreeBSD 14
  ### NOTE: 

  
  #### AIDE will 20-60 minutes to fully establish the "ADVANCED INTRUSION DETECTION SYSTEM"
  - This script will run syncronously and reboot your system when complete. 
  - HARDN-Endpoint in itself once executed, will keep your Debian system secure and up to date. 

6. Follow any additional setup instructions and information provided in the `docs` directory.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/CONTRIBUTION-white?style=for-the-badge&labelColor=black" alt="CONTRIBUTION"><br><br>
We welcome contributions! 

</p>


![GitHub stats](https://github-readme-stats.vercel.app/api?username=opensource-for-freedom&show_icons=true&theme=dark)


<p align="center">
  <img src="https://img.shields.io/badge/PROJECT PARTNERS-white?style=for-the-badge&labelColor=black" alt="PROJECT PARTNERS"><br><br>
</p>


<p align="center">
  <img src="docs/assets/cybersynapse.png" alt="cybersynapse Logo" />
</p>



<p align="center">
  <img src="https://img.shields.io/badge/LICENSE-white?style=for-the-badge&labelColor=black" alt="LICENSE"><br><br>
This project is licensed under the GPLicense
  
</p>


<p align="center">
  <img src="https://img.shields.io/badge/CONTACT-white?style=for-the-badge&labelColor=black" alt="CONTACT"><br><br>
office@cybersynapse.ro
</p>



