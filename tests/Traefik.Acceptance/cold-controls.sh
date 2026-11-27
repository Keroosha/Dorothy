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
 nojob-arm)
   dir="$root/nojob"; mkdir -m700 "$dir"
   for tool in systemctl busctl; do [[ ! -e /usr/local/sbin/$tool && ! -L /usr/local/sbin/$tool ]]; done
   [[ ! -e $j ]]; /usr/bin/systemctl stop "$unit"; [[ $(/usr/bin/systemctl show "$unit" -p ActiveState --value) == inactive ]]
   cat > "$dir/shim" <<EOF
#!/bin/bash
set -euo pipefail
tool=\${0##*/}
if [[ \$tool == busctl && " \$* " == *' StartUnit ss keroosha-traefik.service fail '* ]]; then
    [[ ! -e '$dir/rejected' ]]
    if /usr/bin/busctl "\${@:1:\$#-1}" invalid-fixture-mode > '$dir/job-reply' 2> '$dir/manager-error'; then exit 2; fi
    [[ ! -s '$dir/job-reply' ]]; grep -iq 'job mode' '$dir/manager-error'
    : > '$dir/rejected'; exit 1
fi
if [[ \$tool == systemctl && \${1:-} == show && " \$* " == *' --property=InvocationID '* && -e '$dir/rejected' && ! -e '$dir/independent-id' ]]; then
    /usr/bin/systemctl "\$@" > '$dir/stopped-sample'
    grep -Fxq 'ActiveState=inactive' '$dir/stopped-sample'; grep -Fxq 'MainPID=0' '$dir/stopped-sample'
    jq -e '.wasActive==false' '$j' >/dev/null
    ! cmp -s '$dyn' <(jq -er .dynamic '$j'|base64 -d) || exit 3
    sha256sum '$dyn' '$cfg/static.yml' '$cfg/dns-credentials.env' '$cfg/.keroosha-static-receipt' '$j' > '$dir/staged.sha256'
    /usr/bin/systemctl start '$unit'
    /usr/bin/systemctl show '$unit' -p InvocationID --value > '$dir/independent-id'
    cat '$dir/stopped-sample'; exit 0
fi
if [[ \$tool == systemctl && \${1:-} == stop || \$tool == busctl && " \$* " == *' StopUnit '* ]]; then : > '$dir/stop-called'; fi
exec "/usr/bin/\$tool" "\$@"
EOF
   for tool in systemctl busctl; do install -m755 "$dir/shim" "/usr/local/sbin/$tool"; done ;;
 nojob-assert)
   dir="$root/nojob"
   for tool in systemctl busctl; do cmp "/usr/local/sbin/$tool" "$dir/shim"; rm "/usr/local/sbin/$tool"; done
   [[ -e $dir/rejected && ! -s $dir/job-reply && ! -e $dir/stop-called ]]
   id=$(<"$dir/independent-id"); [[ $id =~ ^[0-9a-f]{32}$ && $(systemctl show "$unit" -p InvocationID --value) == "$id" ]]
   [[ $(sed -n 2p "$cfg/.keroosha-static-receipt") != "$id" ]]; sha256sum -c "$dir/staged.sha256"
   curl -fsS --retry 5 --retry-connrefused --max-time 5 --resolve shop.acceptance.test:18443:127.0.0.1 --cacert "$root/cold-root.pem" https://shop.acceptance.test:18443/secure/health | grep -F tls-backend:/secure/health
   printf 'Independent invocation %s retained; rejected job had no ID; no stop requested.\n' "$id" ;;
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
