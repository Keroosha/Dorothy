#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -lt 2 || $# -gt 4 ]]; then
    printf 'Usage: review-client-identity.sh /var/tmp/dorothy-traefik-acceptance.XXXXXXXX absent|wrong|accepted [listener-port [hostname]]\n' >&2
    exit 2
fi
root=$(realpath -e -- "$1")
mode=$2
listener_port=${TRAEFIK_ACCEPTANCE_CLIENT_IDENTITY_PORT:-${3:-18451}}
host=${TRAEFIK_ACCEPTANCE_CLIENT_IDENTITY_HOST:-${4:-sni-proof.acceptance.test}}
case "$root" in
    /var/tmp/dorothy-traefik-acceptance.*) ;;
    *) printf 'Refusing to use a path outside the private guest temp root.\n' >&2; exit 2 ;;
esac
case "$mode" in
    absent|wrong|accepted) ;;
    *) printf 'Unknown client-identity mode.\n' >&2; exit 2 ;;
esac
[[ "$listener_port" =~ ^[0-9]{1,5}$ ]] && (( listener_port > 0 && listener_port <= 65535 )) || {
    printf 'The review listener port is invalid.\n' >&2
    exit 2
}
[[ -f "$root/.owner" && "$(<"$root/.owner")" == dorothy-traefik-acceptance-guest-v1 ]] || {
    printf 'Guest fixture ownership marker is missing.\n' >&2
    exit 2
}

client_certificate="$root/certs/client.pem"
client_key="$root/certs/client.key"
client_ca="$root/certs/client-ca.pem"
upstream_ca="$root/certs/upstream-ca.pem"
wrong_certificate="$root/certs/review-wrong-client.pem"
wrong_key="$root/certs/review-wrong-client.key"
upstream_errors="$root/logs/review-client-identity-upstream-error.log"
log="$root/logs/review-client-identity-$mode.log"
for required in "$client_certificate" "$client_key" "$client_ca" "$upstream_ca" "$wrong_certificate" "$wrong_key" "$upstream_errors" "$root/certs/sni-proof.pem"; do
    [[ -f "$required" && ! -L "$required" ]] || {
        printf 'A private client-identity acceptance fixture is missing.\n' >&2
        exit 2
    }
done
exec 3>&1 >> "$log" 2>&1

fail() {
    printf 'client-identity acceptance failure: %s\n' "$1" >&2
    exit 1
}

upstream_host=backend.acceptance.test
upstream_port=18123
upstream_url="https://$upstream_host:$upstream_port/client-auth"
upstream_args=(
    --noproxy '*'
    --silent
    --show-error
    --max-time 5
    --resolve "$upstream_host:$upstream_port:127.0.0.1"
    --cacert "$upstream_ca"
)

subject_line=$(openssl x509 -in "$client_certificate" -noout -subject -nameopt RFC2253)
subject=${subject_line#subject=}
subject_cn=${subject#*CN=}
subject_cn=${subject_cn%%,*}
[[ "$subject_line" != "$subject" && -n "$subject_cn" ]] || fail 'the trusted client certificate has no CN for subject comparison'

accepted_body="$root/logs/review-client-identity-direct-accepted.body"
accepted_status=$(curl "${upstream_args[@]}" --cert "$client_certificate" --key "$client_key" \
    --output "$accepted_body" --write-out '%{http_code}' "$upstream_url") \
    || fail 'the private-CA upstream did not accept the configured trusted client certificate'
[[ "$accepted_status" == 200 ]] || fail "the trusted upstream control returned HTTP $accepted_status"
grep -Fq 'client-auth-accepted:' "$accepted_body" \
    || fail 'the verified upstream control did not return its client-authentication marker'
grep -Fq "$subject_cn" "$accepted_body" \
    || fail 'the verified upstream did not report the expected client certificate subject'

# nginx verifies the presented peer and returns its own HTTP 400. A proxy-generated status,
# a refused connection, or a failure checking the upstream server's own CA is not this result.
require_rejection() {
    local label=$1 status=$2 body=$3 prior=$4 pattern
    [[ "$status" == 400 ]] || fail "upstream $label control returned HTTP $status instead of its certificate rejection"
    if grep -Fq 'client-auth-accepted:' "$body"; then fail "upstream accepted the $label control"; fi
    case "$label" in
        absent) pattern='client sent no required SSL certificate' ;;
        wrong) pattern='client SSL certificate verify error' ;;
        *) return 2 ;;
    esac
    tail -n "+$((prior + 1))" "$upstream_errors" > "$root/logs/review-identity-last-errors.log"
    grep -Fiq "$pattern" "$root/logs/review-identity-last-errors.log" || fail "no new upstream $label certificate rejection"
}

expect_direct_rejection() {
    local label=$1 body="$root/logs/review-client-identity-direct-$1.body" prior status
    shift
    prior=$(wc -l < "$upstream_errors")
    status=$(curl "${upstream_args[@]}" "$@" --output "$body" --write-out '%{http_code}' "$upstream_url") \
        || fail "direct $label control failed before receiving the verifier's response"
    require_rejection "$label" "$status" "$body" "$prior"
}

expect_direct_rejection absent
expect_direct_rejection wrong --cert "$wrong_certificate" --key "$wrong_key"
error_lines_before=$(wc -l < "$upstream_errors")
route_body="$root/logs/review-client-identity-route.body"
route_sni=sni-proof.acceptance.test
route_url="https://$route_sni:$listener_port/client-auth"
route_status=$(curl --noproxy '*' --silent --show-error --max-time 8 \
    --resolve "$route_sni:$listener_port:127.0.0.1" \
    --cacert "$root/certs/sni-proof.pem" \
    --header "Host: $host" \
    --output "$route_body" --write-out '%{http_code}' "$route_url") \
    || fail 'the verified inbound TLS route request failed before an HTTP response'
case "$mode" in
    accepted)
        [[ "$route_status" == 200 ]] || fail "the client-authenticated route returned HTTP $route_status"
        grep -Fq 'client-auth-accepted:' "$route_body" \
            || fail 'the accepted route did not return the verified upstream marker'
        grep -Fq "$subject_cn" "$route_body" \
            || fail 'the upstream did not observe the expected client-authenticated subject'
        ;;
    absent|wrong)
        require_rejection "$mode" "$route_status" "$route_body" "$error_lines_before"
        ;;
esac

if [[ "$mode" == wrong ]]; then client_certificate=$wrong_certificate; client_sni=review-untrusted-client.acceptance.test; else client_sni=acceptance-client.test; fi
client_fingerprint=$(openssl x509 -in "$client_certificate" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr '[:upper:]' '[:lower:]')
inbound_capture="$root/logs/review-client-identity-inbound-sni.txt"
inbound_certificate="$root/logs/review-client-identity-inbound-sni.pem"
timeout 5 openssl s_client -connect "127.0.0.1:$listener_port" \
    -servername "$client_sni" -showcerts </dev/null \
    > "$inbound_capture" 2>/dev/null || true
awk 'BEGIN { capture = 0 } /-----BEGIN CERTIFICATE-----/ { capture = 1 } capture { print } /-----END CERTIFICATE-----/ { exit }' \
    "$inbound_capture" > "$inbound_certificate"
if [[ -s "$inbound_certificate" ]]; then
    inbound_fingerprint=$(openssl x509 -in "$inbound_certificate" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr '[:upper:]' '[:lower:]')
    [[ "$inbound_fingerprint" != "$client_fingerprint" ]] \
        || fail 'Traefik served the outbound client-only certificate on its inbound listener'
else
    fail 'inbound control returned no leaf; cannot compare the served identity'
fi

printf 'Client identity mode %s: private-CA upstream control passed; route HTTP %s; outbound identity not served inbound.\n' \
    "$mode" "$route_status" | tee /dev/fd/3
