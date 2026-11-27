#!/usr/bin/env bash
# Guest-only operator controls. The production utility is a separately built
# executable, never an argument to the deployment helper.
set -euo pipefail
umask 077
[[ $# == 2 && $EUID == 0 && $2 =~ ^/var/tmp/dorothy-traefik-acceptance\.[[:alnum:]]+$ && ! -L $2 ]]
root=$2; mode=$1
[[ $(<"$root/.owner") == dorothy-traefik-acceptance-guest-v1 ]]
owner=$(<"$root/maintenance-owner"); sum(){ sha256sum "$1" | cut -d' ' -f1; }
owner_hash=$(printf %s "$owner" | sha256sum | cut -d' ' -f1)
bin=/usr/local/sbin/dorothy-traefik-maintenance; cfg=/etc/keroosha-iac/traefik; dyn=$cfg/dynamic/current.yml; j=$cfg/.keroosha-rollback.json; unit=keroosha-traefik.service
[[ $(<"$cfg/.keroosha-owner") == "$owner_hash" && ! -L $cfg && ! -L $j && -s $j ]]
hash=$(sum "$j"); archive=/etc/keroosha-iac/.dorothy-traefik-recovery/$owner_hash-$hash.journal
case "$mode" in
    nested-negative)
        if "$bin" recover-stopped "$owner" "$hash"; then exit 1; fi
        [[ -s $j && $(sum "$j") == "$hash" && ! -e $archive ]] ;;
    install)
        [[ ! -e $bin && ! -L $bin ]]; install -m700 -o root -g root "$root/maintenance-bin" "$bin"
        [[ $(sum "$bin") == "$(<"$root/maintenance-sha")" ]];
        helper=/var/cache/keroosha-iac/helper/linux-x64/$(<"$root/product-helper-sha")
        [[ -x $helper && $(sum "$helper") == "$(<"$root/product-helper-sha")" ]]
        sudo_policy=/etc/sudoers.d/dorothy-acceptance-maintenance-negative
        [[ ! -e $sudo_policy && ! -L $sudo_policy ]]; trap 'rm -f -- "$sudo_policy"' EXIT
        printf 'nobody ALL=(root) NOPASSWD: %s traefik-capabilities, %s traefik-v2\n' "$helper" "$helper" > "$sudo_policy"; chmod 440 "$sudo_policy"; visudo -cf "$sudo_policy" >/dev/null
        runuser -u nobody -- sudo -n -- "$helper" traefik-capabilities >/dev/null
        if runuser -u nobody -- sudo -n -- "$bin" recover-stopped "$owner" "$hash"; then exit 1; fi
        if "$helper" recover-stopped "$owner" "$hash"; then exit 1; fi ;;
    stop)
        # Operators explicitly back up BEFORE stopping. Nothing under the
        # configuration directory is discarded to get a green Apply.
        backup=$(mktemp -d "$root/backup.XXXXXXXX"); cp -a "$cfg/." "$backup/"
        systemctl stop "$unit"; [[ $(systemctl show -p ActiveState --value "$unit") == inactive ]] ;;
    negatives)
        [[ $(systemctl show -p ActiveState --value "$unit") == inactive ]]
        if "$bin" recover-stopped wrong-owner "$hash"; then exit 1; fi
        if "$bin" recover-stopped "$owner" "$(printf %064d 0)"; then exit 1; fi
        original=$(mktemp "$root/dynamic.XXXXXXXX"); cp -p "$dyn" "$original"
        printf '\n' >> "$dyn"; changed=$(sum "$dyn")
        if "$bin" recover-stopped "$owner" "$hash"; then exit 1; fi
        [[ $(sum "$j") == "$hash" && $(sum "$dyn") == "$changed" && ! -e $archive ]]; cp -p "$original" "$dyn" ;;
    interrupt)
        [[ ! -e $archive && ! -L $archive ]]; fixture=$(mktemp -d "$root/interruption.XXXXXXXX"); cp /usr/bin/systemctl "$fixture/systemctl"; cat > "$fixture/wrapper" <<EOF
#!/bin/bash
if [[ \$1 == show && -f '$archive' && \$(readlink /proc/\$PPID/exe) == '$bin' ]]; then
    : > '$fixture/fired'; kill -KILL "\$PPID"; exit 137
fi
exec '$fixture/systemctl' "\$@"
EOF
        chmod 700 "$fixture/wrapper"
        if unshare --mount --propagation private /bin/bash -ceu 'mount --bind "$1" /usr/bin/systemctl; exec "$2" recover-stopped "$3" "$4"' _ "$fixture/wrapper" "$bin" "$owner" "$hash"; then exit 1; fi
        [[ -f $fixture/fired && $(sum "$j") == "$hash" && $(sum "$archive") == "$hash" && ! -L $archive ]] ;;
    finish)
        receipt_before=$(sum "$cfg/.keroosha-static-receipt"); old_dynamic=$(jq -er .dynamic "$j" | base64 -d | sha256sum | cut -d' ' -f1)
        "$bin" recover-stopped "$owner" "$hash"; "$bin" recover-stopped "$owner" "$hash"
        [[ ! -e $j && $(sum "$archive") == "$hash" && $(sum "$dyn") == "$old_dynamic" && $(sum "$cfg/.keroosha-static-receipt") == "$receipt_before" ]]
        [[ $(stat -c '%a:%u:%g' "$archive") == 600:0:0 && $(stat -c '%a:%u:%g' "$(dirname "$archive")") == 700:0:0 && $(systemctl show -p ActiveState --value "$unit") == inactive ]] ;;
    *) exit 2 ;;
esac
