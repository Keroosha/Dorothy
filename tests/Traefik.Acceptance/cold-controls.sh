#!/usr/bin/env bash
# Runs as root only on the marked acceptance guest.
set -euo pipefail; umask 077
[[ $# == 2 && $1 =~ ^/var/tmp/dorothy-traefik-acceptance\.[[:alnum:]]+$ && $(<"$1/.owner") == dorothy-traefik-acceptance-guest-v1 ]]
root=$1; mode=$2; cfg=/etc/keroosha-iac/traefik; dyn=$cfg/dynamic/current.yml; j=$cfg/.keroosha-rollback.json; unit=keroosha-traefik.service
case $mode in
 http-inject)
   [[ ! -e $j && ! -e $root/tls-original ]]; cp -p "$dyn" "$root/tls-original"; tmp=$(mktemp "$dyn.fixture.XXXXXXXX"); jq -e '(.http.routers | to_entries | map(select(.value.tls | type=="object")) | first.key) as $r | select($r!=null) | .http.routers[$r].tls.passthrough=false' "$dyn" > "$tmp"; chmod --reference="$dyn" "$tmp"; chown --reference="$dyn" "$tmp"; mv -T "$tmp" "$dyn"; sha256sum "$dyn" > "$root/tls-edited.sha" ;;
 http-witness) [[ ! -e $j ]]; sha256sum -c "$root/tls-edited.sha"; systemctl show "$unit" -p MainPID -p InvocationID; curl -fsS --resolve shop.acceptance.test:18443:127.0.0.1 --cacert "$root/cold-root.pem" https://shop.acceptance.test:18443/secure/health | grep -F tls-backend:/secure/health ;;
 http-restore) sha256sum -c "$root/tls-edited.sha"; mv -T "$root/tls-original" "$dyn" ;;
 race-arm)
   [[ ! -e $j && ! -e /usr/local/sbin/systemctl && ! -L /usr/local/sbin/systemctl ]]; systemctl stop "$unit"; cp -p "$dyn" "$root/race-original"; cat > "$root/race-shim" <<EOF
#!/bin/bash
set -eu
if [[ \${1:-} == show && " \$* " == *' --property=InvocationID '* && -f '$j' && ! -e '$root/race-fired' ]] && ! cmp -s '$dyn' '$root/race-original'; then
    jq -e '.wasActive==false' '$j' >/dev/null
    /usr/bin/systemctl show "\${@:2}" > '$root/race-sample'; grep -Fxq ActiveState=inactive '$root/race-sample'; /usr/bin/systemctl start '$unit'; /usr/bin/systemctl show '$unit' -p InvocationID --value > '$root/race-fired'; cat '$root/race-sample'; exit 0
fi
exec /usr/bin/systemctl "\$@"
EOF
   install -m755 "$root/race-shim" /usr/local/sbin/systemctl ;;
 race-assert) cmp /usr/local/sbin/systemctl "$root/race-shim"; rm /usr/local/sbin/systemctl; [[ -s $j && $(systemctl show "$unit" -p InvocationID --value) == "$(<"$root/race-fired")" && $(sed -n 2p "$cfg/.keroosha-static-receipt") != "$(<"$root/race-fired")" ]]; jq -e '.wasActive==false' "$j" >/dev/null; systemctl is-active "$unit" ;;
 *) exit 2 ;;
esac
