#!/bin/sh
# Build-time setup shared by every lab host image.
set -eu

# The scan user. '*' = no valid password but not locked, so key-only SSH works.
useradd --create-home --shell /bin/bash handscheck
usermod -p '*' handscheck
install -d -m 700 -o handscheck -g handscheck /home/handscheck/.ssh

# Read-only sudo, mirroring what we ask customers to install.
install -m 440 /opt/lab/sudoers-handscheck /etc/sudoers.d/handscheck
visudo -cf /etc/sudoers.d/handscheck

# The fix user (M6): only the remediate key logs in here, and only for approved fixes.
useradd --create-home --shell /bin/bash handscheck-fix
usermod -p '*' handscheck-fix
install -d -m 700 -o handscheck-fix -g handscheck-fix /home/handscheck-fix/.ssh
install -m 440 /opt/lab/sudoers-handscheck-fix /etc/sudoers.d/handscheck-fix
visudo -cf /etc/sudoers.d/handscheck-fix

# sshd: keys only, no root.
ssh-keygen -A
mkdir -p /run/sshd
cat >> /etc/ssh/sshd_config <<'EOF'

# handscheck lab
PasswordAuthentication no
PermitRootLogin no
EOF

# PHP-FPM: a deliberately small pool so saturation is easy to reproduce later (health agent).
mkdir -p /run/php
POOL="/etc/php/${PHP_VERSION}/fpm/pool.d/www.conf"
sed -i -e 's/^pm.max_children = .*/pm.max_children = 5/' "$POOL"

# A hardened baseline: no directory listings unless a site turns them on (the directory-listing fixture does).
sed -i 's/Options Indexes FollowSymLinks/Options FollowSymLinks/' /etc/apache2/apache2.conf
! grep -q 'Options Indexes' /etc/apache2/apache2.conf

echo "ServerName localhost" > /etc/apache2/conf-available/servername.conf
a2enconf -q servername

chmod 755 /opt/lab/*.sh
