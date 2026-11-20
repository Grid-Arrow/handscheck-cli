#!/bin/sh
# handscheck self-hosted installer. Read it before you run it; it is short.
#
#   sudo sh install.sh               install or upgrade (shows what it will do and asks first)
#   sudo sh install.sh --yes         same, without asking
#   sh install.sh --print-sudoers    print the sudoers file it installs, and exit
#   sudo sh install.sh --uninstall [--purge]
#
# It does four things, nothing else:
#   1. creates the system user `handscheck` (no password, no SSH keys, no login shell; home /var/lib/handscheck,
#      where hc keeps its local history), unless the user already exists, in which case it is left as it is;
#   2. copies this directory to /opt/handscheck, owned by root and not writable by `handscheck`;
#   3. links /usr/local/bin/hc to /opt/handscheck/bin/hc;
#   4. installs /etc/sudoers.d/handscheck (the file next to this script), after checking it with visudo.
# It downloads nothing, starts no service and sends nothing anywhere.
set -eu

PREFIX=/opt/handscheck
LINK=/usr/local/bin/hc
SUDOERS=/etc/sudoers.d/handscheck
USER_NAME=handscheck
USER_HOME=/var/lib/handscheck

here=$(cd "$(dirname "$0")" && pwd)
yes=0 action=install purge=0
for arg in "$@"; do
    case "$arg" in
        --yes|-y) yes=1 ;;
        --uninstall) action=uninstall ;;
        --purge) purge=1 ;;
        --print-sudoers) action=print ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg (see --help)" >&2; exit 2 ;;
    esac
done

die() { echo "error: $*" >&2; exit 1; }

if [ "$action" = print ]; then
    cat "$here/sudoers-handscheck"
    exit 0
fi
[ "$(id -u)" -eq 0 ] || die "run it as root (sudo sh $0 $*)"
[ "$(uname -s)" = Linux ] || die "handscheck runs on Linux only"

confirm() {
    [ "$yes" -eq 1 ] && return 0
    printf '%s [y/N] ' "$1"
    read -r answer </dev/tty || answer=
    case "$answer" in y|Y|yes|YES) return 0 ;; *) echo "nothing changed"; exit 1 ;; esac
}

if [ "$action" = uninstall ]; then
    echo "This removes $LINK, $PREFIX and $SUDOERS."
    [ "$purge" -eq 1 ] && echo "--purge: also the user $USER_NAME and $USER_HOME (local history)."
    confirm "Uninstall handscheck?"
    [ -L "$LINK" ] && rm -f "$LINK"
    rm -f "$SUDOERS"
    rm -rf "$PREFIX"
    if [ "$purge" -eq 1 ] && id "$USER_NAME" >/dev/null 2>&1; then
        home=$(getent passwd "$USER_NAME" | cut -d: -f6)
        userdel "$USER_NAME"
        [ "$home" = "$USER_HOME" ] && rm -rf "$USER_HOME"
    fi
    echo "handscheck uninstalled"
    exit 0
fi

[ -x "$here/bin/hc" ] && [ -x "$here/python/bin/python3" ] && [ -f "$here/sudoers-handscheck" ] \
    || die "run install.sh from the unpacked handscheck directory (bin/, python/, sudoers-handscheck)"
command -v visudo >/dev/null 2>&1 || die "visudo not found: install sudo first"
version=$("$here/bin/hc" version 2>/dev/null | head -n 1)
[ -n "$version" ] || die "$here/bin/hc does not run on this system"

echo "Installing $version:"
if id "$USER_NAME" >/dev/null 2>&1; then
    echo "  - user $USER_NAME: already exists, left as it is"
else
    echo "  - create the system user $USER_NAME (no password, no login shell, home $USER_HOME)"
fi
if [ "$here" = "$PREFIX" ]; then
    echo "  - files: already in $PREFIX"
else
    echo "  - copy $here to $PREFIX (replacing any earlier version)"
fi
echo "  - link $LINK -> $PREFIX/bin/hc"
echo "  - install $SUDOERS (read-only sudo; see it with: sh $0 --print-sudoers)"
confirm "Go ahead?"

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
cp "$here/sudoers-handscheck" "$tmp"
visudo -cqf "$tmp" || die "the sudoers file did not pass visudo -c; nothing changed"

if ! id "$USER_NAME" >/dev/null 2>&1; then
    nologin=/usr/sbin/nologin
    [ -x "$nologin" ] || nologin=/sbin/nologin
    useradd --system --user-group --home-dir "$USER_HOME" --create-home --shell "$nologin" \
        --comment "handscheck read-only checks" "$USER_NAME"
fi

if [ "$here" != "$PREFIX" ]; then
    rm -rf "$PREFIX.new"
    cp -R "$here" "$PREFIX.new"
    chown -R root:root "$PREFIX.new"
    chmod -R go-w "$PREFIX.new"
    rm -rf "$PREFIX"
    mv "$PREFIX.new" "$PREFIX"
fi
ln -sf "$PREFIX/bin/hc" "$LINK"
install -m 0440 -o root -g root "$tmp" "$SUDOERS"

echo "Installed $("$LINK" version | head -n 1). Check this server with:"
echo "  sudo -u $USER_NAME hc check --local"
