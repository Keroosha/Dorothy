#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 1 ]]; then
    printf 'Usage: guest-activate-fixtures.sh /var/tmp/dorothy-traefik-acceptance.XXXXXXXX\n' >&2
    exit 2
fi
root=$(realpath -e -- "$1")
case "$root" in
    /var/tmp/dorothy-traefik-acceptance.*) ;;
    *) printf 'Refusing to activate fixtures outside the private guest temp root.\n' >&2; exit 2 ;;
esac
[[ -d "$root" && -f "$root/.owner" && $(<"$root/.owner") == dorothy-traefik-acceptance-guest-v1 \
    && -f "$root/logs/barrier-fixtures.log" && -f "$root/dns/tsig.key" ]] || {
    printf 'The private barrier fixture preparation is incomplete.\n' >&2
    exit 2
}
for unit in \
    dorothy-traefik-acceptance-dns.service \
    dorothy-traefik-acceptance-otelcol.service \
    dorothy-traefik-acceptance-backends.service \
    dorothy-traefik-acceptance-tcp.service \
    dorothy-traefik-acceptance-udp.service; do
    [[ -f "/etc/systemd/system/$unit" && ! -L "/etc/systemd/system/$unit" ]] || {
        printf 'A prepared local fixture unit is missing: %s\n' "$unit" >&2
        exit 2
    }
done

# This is intentionally separate from barrier preparation: only the approved follow-on starts
# DNS, telemetry, HTTP/TLS, TCP and UDP fixtures or sends local acceptance traffic.
systemctl enable --now dorothy-traefik-acceptance-dns.service > "$root/logs/activation-dns-start.log" 2>&1
systemctl enable --now \
    dorothy-traefik-acceptance-otelcol.service \
    dorothy-traefik-acceptance-backends.service \
    dorothy-traefik-acceptance-tcp.service \
    dorothy-traefik-acceptance-udp.service > "$root/logs/activation-services-start.log" 2>&1

ready=false
for _ in $(seq 1 90); do
    if dig +time=1 +tries=1 @127.0.0.1 -p 1053 acceptance.test SOA >/dev/null 2>&1 \
       && env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin curl --disable --noproxy '*' --fail --silent --show-error \
            --cacert "$root/certs/pebble.minica.pem" https://localhost:14000/dir \
            -o "$root/logs/pebble-directory.json" 2>/dev/null \
       && env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin curl --disable --noproxy '*' --fail --silent --show-error \
            --cacert "$root/certs/pebble.minica.pem" https://localhost:14001/dir \
            -o "$root/logs/pebble-rotated-directory.json" 2>/dev/null \
       && nc -z -w 1 127.0.0.1 4318; then
        ready=true
        break
    fi
    sleep 1
done
[[ $ready == true ]] || { printf 'Approved local fixture services did not become ready.\n' >&2; exit 1; }

# Exercise only the owned loopback RFC2136 zone; the TSIG material remains in the private fixture.
dns_probe=_preflight.acceptance.test.
printf 'server 127.0.0.1 1053\nzone acceptance.test.\nupdate add %s 30 TXT "rfc2136-ready"\nsend\n' "$dns_probe" \
    | nsupdate -k "$root/dns/tsig.key" > "$root/logs/dns-update.log" 2>&1
dns_observation=$(dig +time=2 +tries=1 +short @127.0.0.1 -p 1053 TXT "$dns_probe")
[[ "$dns_observation" == '"rfc2136-ready"' ]] || {
    printf 'RFC2136 TSIG update was not visible in the local fixture zone.\n' >&2
    exit 1
}
printf 'server 127.0.0.1 1053\nzone acceptance.test.\nupdate delete %s TXT\nsend\n' "$dns_probe" \
    | nsupdate -k "$root/dns/tsig.key" >> "$root/logs/dns-update.log" 2>&1

env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin curl --disable --noproxy '*' --fail --silent \
    --output "$root/logs/activation-http-health.txt" http://127.0.0.1:8080/health \
    || { printf 'HTTP fixture failed its local health request.\n' >&2; exit 1; }
grep -Fxq http-backend-ready "$root/logs/activation-http-health.txt" || {
    printf 'HTTP fixture failed its local health probe.\n' >&2
    exit 1
}
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin curl --disable --noproxy '*' --fail --silent \
    --resolve backend.acceptance.test:8081:127.0.0.1 \
    --cacert "$root/certs/upstream-ca.pem" --output "$root/logs/activation-tls-health.txt" \
    https://backend.acceptance.test:8081/health || {
    printf 'TLS backend fixture failed its local certificate request.\n' >&2
    exit 1
}
grep -Fxq tls-backend-ready "$root/logs/activation-tls-health.txt" || {
    printf 'TLS backend fixture failed its local health probe.\n' >&2
    exit 1
}

listeners=$(ss -H -lntup)
for port in 1053 14000 14001 15000 15001 4317 4318 8080 8081 8082 19001 19002; do
    row=$(printf '%s\n' "$listeners" | awk -v suffix=":$port" '$5 ~ (suffix "$" ) || $5 ~ ("\\]:" port "$" )')
    [[ -n $row ]] || { printf 'Fixture listener %s did not start.\n' "$port" >&2; exit 1; }
    if printf '%s\n' "$row" | awk '$5 ~ /^(0\.0\.0\.0|\[::\]|:::|\*):/ { found = 1 } END { exit !found }'; then
        printf 'Fixture listener %s is not loopback-bound.\n' "$port" >&2
        exit 1
    fi
done
printf '%s\n' "$listeners" \
    | grep -E ':(1053|14000|14001|15000|15001|4317|4318|8080|8081|8082|19001|19002)([[:space:]]|$)' \
    > "$root/logs/listeners.txt"

{
    printf 'Debian '; cat /etc/debian_version
    staged_traefik_sha=$(sha256sum "$root/bin/traefik" | awk '{ print $1 }')
    [[ "$staged_traefik_sha" == 86ee2b427888d24475051fc5f5bcca94cf4fa033b6fa54205b7eb0de6914f31e ]] || {
        printf 'Staged Traefik executable digest does not match the pinned fixture.\n' >&2
        exit 1
    }
    printf 'Staged only: Traefik 3.7.16, verified SHA-256=%s; executable not run by fixture activation.\n' "$staged_traefik_sha"
    "$root/bin/pebble" -version
    "$root/bin/otelcol-contrib" --version
    named -V 2>&1 | head -n 1
    nginx -v 2>&1
    printf 'Local RFC2136 DNSUPDATE fixture, OTel collector, HTTP/TLS backends, TCP and UDP listeners passed their probes.\n'
    printf 'Pebble API directory endpoints remain on loopback; Traefik was not started by fixture activation.\n'
} > "$root/logs/baseline-observations.log" 2>&1
printf 'Approved local DNS, telemetry and backend fixtures are active on loopback; Traefik remains off.\n'
