#!/bin/bash
## by @Bl4ckD34thz - x
# Hardening security script for RHEL8.8
# This script implements security configurations to harden the security of an RHEL8.8 system.

CONFIG_FILE="/etc/modprobe.d/disable-filesystem-modules.conf"

# Function to add an entry to the configuration file if it doesn't exist
# This function adds filesystem modules to the blacklist to disable their usage.
add_blacklist_entry() {
    local module="$1"
    if ! grep -q "^blacklist $module" "$CONFIG_FILE"; then
        echo "blacklist $module" | sudo tee -a "$CONFIG_FILE"
    else
        echo "El módulo $module ya está en la lista negra."
    fi
}

# Filesystem modules to disable
# Disable certain unnecessary filesystem modules to improve system security.
FILESYSTEM_MODULES=(cramfs freevxfs hfs hfsplus jffs2)
for module in "${FILESYSTEM_MODULES[@]}"; do
    add_blacklist_entry "$module"
done

# Remove kernel modules if they are loaded
# Ensure the listed modules are not loaded in the kernel.
sudo modprobe -r "${FILESYSTEM_MODULES[@]}"

# 1.2.1.- Verify installed GPG keys
# Verify installed GPG keys to ensure that only trusted repositories are used.
sudo rpm -qa gpg-pubkey

# 1.2.2.- Ensure gpgcheck is enabled
# Enable gpgcheck in repositories to ensure that installed packages are signed and secure.
sudo sed -i 's/^gpgcheck=0/gpgcheck=1/' /etc/yum.conf
sudo sed -i 's/^gpgcheck=0/gpgcheck=1/' /etc/yum.repos.d/*.repo

# 1.2.3.- Install security updates and patches
# Install all available security updates and patches.
sudo yum update --security -y

# Generate the hash for the "soporte" password
# Generate a hash for the "root" user password and add it to the GRUB configuration.
password_hash=$(echo -e "soporte\nsoporte" | grub2-mkpasswd-pbkdf2 | grep "grub.pbkdf2" | awk '{print $7}')

# Add superuser configuration and encrypted password to the /etc/grub.d/40_custom file
if ! grep -q "^set superusers=\"root\"" /etc/grub.d/40_custom; then
    sudo tee -a /etc/grub.d/40_custom <<EOF
set superusers="root"
password_pbkdf2 root $password_hash
EOF
else
    echo "La configuración de superusuario ya está presente en /etc/grub.d/40_custom."
fi

# Update GRUB configuration
# Apply changes to the GRUB configuration.
sudo grub2-mkconfig -o /boot/grub2/grub.cfg

# 1.4.1.- Ensure ASLR is enabled
# ASLR (Address Space Layout Randomization) improves security by randomizing the location of key memory areas.
if ! grep -q "^kernel.randomize_va_space = 2" /etc/sysctl.conf; then
    sudo sysctl -w kernel.randomize_va_space=2
    echo "kernel.randomize_va_space = 2" | sudo tee -a /etc/sysctl.conf
else
    echo "ASLR ya está habilitado."
fi

# 1.4.2.- Ensure ptrace_scope is restricted
# Restrict the use of ptrace to prevent unprivileged users from tracing processes they do not own.
if ! grep -q "^kernel.yama.ptrace_scope = 1" /etc/sysctl.conf; then
    sudo sysctl -w kernel.yama.ptrace_scope=1
    echo "kernel.yama.ptrace_scope = 1" | sudo tee -a /etc/sysctl.conf
else
    echo "ptrace_scope ya está restringido."
fi

# 1.4.3.- Ensure core dump backtraces are disabled
# Disable core dumps to prevent sensitive information from being revealed in case of application failure.
if ! grep -q '^kernel.core_pattern="\|/bin/false"' /etc/sysctl.conf; then
    sudo sysctl -w kernel.core_pattern="|/bin/false"
    echo 'kernel.core_pattern="|/bin/false"' | sudo tee -a /etc/sysctl.conf
else
    echo "Core dump backtraces ya están deshabilitados."
fi

# 1.4.4.- Ensure core dump storage is disabled
# Disable the generation of core dumps for all users.
if ! grep -q '^\* hard core 0' /etc/security/limits.conf; then
    sudo ulimit -c 0
    echo '* hard core 0' | sudo tee -a /etc/security/limits.conf
else
    echo "El almacenamiento de core dumps ya está deshabilitado."
fi

# 1.5.1.1.- Ensure SELinux is installed
# Verify that SELinux is installed to provide an additional layer of access control.
if ! rpm -q selinux-policy-targeted &> /dev/null; then
    sudo yum install -y selinux-policy-targeted
fi

# 1.5.1.2.- Ensure SELinux is not disabled in the bootloader
# Ensure that SELinux is not disabled in the bootloader configuration.
if grep -q "selinux=0" /etc/default/grub; then
    sudo sed -i 's/selinux=0//g' /etc/default/grub
    sudo grub2-mkconfig -o /boot/grub2/grub.cfg
else
    echo "SELinux no está deshabilitado en el bootloader."
fi

# 1.5.1.3.- Ensure SELinux policy is configured
# Ensure that the SELinux policy is set to 'targeted'.
if [[ $(sestatus | grep "Loaded policy name" | awk '{print $4}') != "targeted" ]]; then
    sudo semanage policy -s targeted
else
    echo "La política de SELinux ya está configurada como 'targeted'."
fi

# 1.5.1.4.- Ensure SELinux mode is not disabled
# Ensure that SELinux is enabled (enforcing or permissive).
if [[ $(getenforce) == "Disabled" ]]; then
    sudo setenforce 1
else
    echo "SELinux no está deshabilitado."
fi

# 1.5.1.5.- Ensure SELinux is in 'Enforcing' mode
# Set SELinux to 'enforcing' mode to apply all configured security policies.
if [[ $(getenforce) != "Enforcing" ]]; then
    sudo setenforce 1
    sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
else
    echo "SELinux ya está en modo 'Enforcing'."
fi

# 1.6.1.- Ensure crypto policy is not set to 'legacy'
# Update the crypto policy to ensure it is not set to 'LEGACY'.
if [[ $(update-crypto-policies --show) == "LEGACY" ]]; then
    sudo update-crypto-policies --set DEFAULT
else
    echo "La política criptográfica no está configurada como 'LEGACY'."
fi

# 2.1.1.- Ensure time synchronization is in use
# Install and enable Chrony to ensure system time synchronization.
CHRONY_CONF="/etc/chrony.conf"
CHRONY_SERVICE="/usr/lib/systemd/system/chronyd.service"

if ! rpm -qa | grep -qw chrony; then
    sudo yum install -y chrony
fi

sudo systemctl enable chronyd
sudo systemctl start chronyd

if ! sudo systemctl is-active --quiet chronyd; then
    echo "Error: La sincronización de tiempo no está activa."
    exit 1
fi

# 2.1.2.- Ensure Chrony is configured
# Configure time servers for Chrony.
SERVERS=("server metadata.google.internal iburst" "server 10.5.1.251 iburst")
for server in "${SERVERS[@]}"; do
    if ! grep -Fxq "$server" "$CHRONY_CONF"; then
        echo "$server" | sudo tee -a "$CHRONY_CONF"
    else
        echo "El servidor '$server' ya está configurado."
    fi
done

sudo systemctl restart chronyd

# 2.1.3.- Ensure Chrony does not run as root
# Configure Chrony to not run as root.
if ! grep -Fxq "User=chrony" "$CHRONY_SERVICE"; then
    sudo sed -i '/\[Service\]/a User=chrony' "$CHRONY_SERVICE"
    sudo systemctl daemon-reload
    sudo systemctl restart chronyd
else
    echo "Chrony ya está configurado para no ejecutarse como root."
fi

CHRONY_USER=$(ps -o user= -p $(pgrep chronyd))
if [ "$CHRONY_USER" = "root" ]; then
    echo "Error: Chrony todavía se está ejecutando como root."
else
    echo "Chrony se está ejecutando bajo el usuario correcto: $CHRONY_USER"
fi

# Configure the message of the day (MOTD) and warning banners
# Configure the message of the day and warning banners for local and remote sessions.
BANNER_TEXT="Este equipo es privado y propiedad de \"EMPRESANAME\". El acceso esta permitido exclusivamente a personal autorizado que ha aceptado los terminos de uso de recursos. El uso de este equipo esta sujeto a auditorias por parte de la empresa, por lo que el uso indebido o no autorizado de los recursos, constituye una violacion a las politicas de seguridad y esta sujeto a las sanciones internas y legales correspondientes. El continuar con el acceso al equipo implica la aceptacion y cumplimiento de las politicas vigentes. Se recomienda terminar la sesion inmediatamente en caso de no estar de acuerdo con los terminos y condiciones descritas en este aviso."

for file in /etc/motd /etc/issue /etc/issue.net; do
    if ! grep -Fxq "$BANNER_TEXT" "$file"; then
        echo "$BANNER_TEXT" | sudo tee "$file"
    else
        echo "El banner de advertencia ya está configurado en $file."
    fi
    sudo chmod 644 "$file"
    sudo chown root:root "$file"
done

# Configure Chrony and disable unnecessary services
# Disable unnecessary services to reduce the attack surface.
SERVICES_TO_DISABLE=(autofs avahi-daemon dhcpd named dnsmasq smb vsftpd dovecot cyrus-imapd nfs-server ypserv cups rpcbind rsyncd snmpd telnet.socket tftp squid httpd xinetd gdm xorg)
for service in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl is-active --quiet "$service"; then
        sudo systemctl stop "$service"
    fi
    if systemctl is-enabled --quiet "$service"; then
        sudo systemctl disable "$service"
    fi
done

# Configure network parameters with sysctl
# Configure network parameters to harden system security.
configure_sysctl_param() {
    local param="$1"
    local value="$2"
    if grep -q "^$param" /etc/sysctl.conf; then
        if ! grep -q "^$param = $value" /etc/sysctl.conf; then
            sudo sed -i "s/^$param.*/$param = $value/" /etc/sysctl.conf
        else
            echo "$param ya está configurado con el valor correcto."
        fi
    else
        echo "$param = $value" | sudo tee -a /etc/sysctl.conf
    fi
    sudo sysctl -w "$param=$value"
}

NETWORK_PARAMS=(
    "net.ipv4.ip_forward 0"
    "net.ipv6.conf.all.forwarding 0"
    "net.ipv4.conf.all.send_redirects 0"
    "net.ipv4.conf.default.send_redirects 0"
    "net.ipv4.icmp_ignore_bogus_error_responses 1"
    "net.ipv4.icmp_echo_ignore_broadcasts 1"
    "net.ipv4.conf.all.accept_redirects 0"
    "net.ipv4.conf.default.accept_redirects 0"
    "net.ipv6.conf.all.accept_redirects 0"
    "net.ipv6.conf.default.accept_redirects 0"
    "net.ipv4.conf.all.secure_redirects 0"
    "net.ipv4.conf.default.secure_redirects 0"
    "net.ipv4.conf.all.rp_filter 1"
    "net.ipv4.conf.default.rp_filter 1"
    "net.ipv4.conf.all.accept_source_route 0"
    "net.ipv4.conf.default.accept_source_route 0"
    "net.ipv6.conf.all.accept_source_route 0"
    "net.ipv6.conf.default.accept_source_route 0"
    "net.ipv4.conf.all.log_martians 1"
    "net.ipv4.conf.default.log_martians 1"
    "net.ipv4.tcp_syncookies 1"
    "net.ipv6.conf.all.accept_ra 0"
    "net.ipv6.conf.default.accept_ra 0"
)

for param in "${NETWORK_PARAMS[@]}"; do
    configure_sysctl_param ${param}
done

# Apply all sysctl changes
sudo sysctl -p

echo "Configuración completada."
