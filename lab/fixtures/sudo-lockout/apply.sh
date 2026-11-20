#!/bin/sh
# Planted sudo lockout (M2): the attacker ran `chmod 000 /usr/bin/sudo` on aws24 to lock admins out; "I can't
# sudo" was how the incident was found. Applied by hosts/common/entrypoint.sh when LAB_FIXTURES contains
# "sudo-lockout". It gets its own lab host because the scan can't use read-only sudo there either.
set -eu
chmod 000 /usr/bin/sudo
echo "lab: fixture sudo-lockout applied"
