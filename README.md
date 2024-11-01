# Hardening Script for RHEL8

## Description

This security hardening script is designed for **RHEL8** operating systems. It implements a series of security configurations to enhance system protection, including disabling unnecessary kernel modules, configuring **SELinux**, cryptographic policies, time synchronization, and network parameter settings.

## Prerequisites

- **Operating System**: Red Hat Enterprise Linux 8
- **Sudo Permissions**: The script requires superuser permissions to apply configuration changes.
- **Required Tools**: Ensure the following packages are installed:
  - `chrony`
  - `selinux-policy-targeted`

## Usage Instructions

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/StealthByte0/HardeningLinuxRhel.git

   cd HardeningLinuxRhel

   sudo ./RHEL8.8.sh


## Script Components

- **Disabling Filesystem Modules:** Disables unnecessary modules such as cramfs and hfs to minimize the attack surface.

- **Package Updates and GPG Configuration:** Ensures package signatures are validated and security updates are applied.

- **SELinux Configuration:** Enables SELinux in enforcing mode to provide an additional level of security.

- **Time Synchronization with Chrony:** Configures Chrony to keep the system clock synchronized with reliable time servers.

- **Warning Banners Configuration:** Sets warning messages (MOTD) for system access, complying with corporate policies.

- **Network Parameter Settings:** Ensures important network parameters, such as redirects and TCP syncookies, are properly configured.


## Important Notes

- **Service Disabling:** The script disables several services that may not be necessary in a secure environment. Be sure to review them before running the script to avoid disrupting any critical services in your environment.


- **SELinux:** SELinux is required in enforcing mode. If your application is not configured to work with SELinux, this could impact system functionality.
