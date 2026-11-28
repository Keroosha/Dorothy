#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 3 ]]; then
    printf 'Usage: client-checks.sh /var/tmp/dorothy-traefik-acceptance.XXXXXXXX protocols|after-reboot|route-update|rotation|udp-drift|udp-repaired <run-index>\n' >&2
    exit 2
fi
root=$(realpath -e -- "$1")
mode=$2
run_index=$3
[[ "$run_index" =~ ^[1-9][0-9]{0,3}$ ]] || { printf 'Invalid client evidence run index.\n' >&2; exit 2; }
case "$root" in
    /var/tmp/dorothy-traefik-acceptance.*) ;;
    *) printf 'Refusing to use a path outside the private guest temp root.\n' >&2; exit 2 ;;
esac
case "$mode" in
    protocols|after-reboot|route-update|rotation|udp-drift|udp-repaired) ;;
    *) printf 'Unknown isolated client phase.\n' >&2; exit 2 ;;
esac
[[ -f "$root/.owner" && "$(<"$root/.owner")" == dorothy-traefik-acceptance-guest-v1 ]] || {
    printf 'Guest fixture ownership marker is missing.\n' >&2
    exit 2
}

log="$root/logs/client-$mode.log"
exec >> "$log" 2>&1
fail() {
    printf 'acceptance client failure: %s\n' "$1" >&2
    exit 1
}

exact_body_checks=0
legacy_redirect_status=0
legacy_excluded_status=0
native_excluded_status=0
http2_version=not-tested
http3_version=not-tested
multi_http_count=0
multi_other_count=0
tcp_proxy_v2_verified=false
tls_passthrough_verified=false
udp_ingress_proofs=0
udp_backend_proofs=0
otel_spans_count=0
otel_metrics_count=0
post_reboot_trace_sha256=not-collected
bad_upstream_ca_rejected=null
negative_fixture_dir=''
upstream_swap_active=false
assert_exact_body() {
    local body_file=$1 expected=$2 description=$3
    printf '%s\n' "$expected" | cmp -s - "$body_file" \
        || fail "$description returned a body other than the exact backend response"
    exact_body_checks=$((exact_body_checks + 1))
}
write_metrics() {
    local destination="$root/logs/client-metrics-$run_index.json"
    [[ ! -e "$destination" && ! -L "$destination" ]] || fail 'client metrics path already exists'
    jq -n \
        --arg mode "$mode" \
        --arg runIndex "$run_index" \
        --arg http2Version "$http2_version" \
        --arg http3Version "$http3_version" \
        --arg postRebootTraceSha256 "$post_reboot_trace_sha256" \
        --argjson exactBackendBodyChecks "$exact_body_checks" \
        --argjson legacyRedirectStatus "$legacy_redirect_status" \
        --argjson legacyExcludedStatus "$legacy_excluded_status" \
        --argjson nativeExcludedStatus "$native_excluded_status" \
        --argjson multiHttpBackendResponses "$multi_http_count" \
        --argjson multiOtherBackendResponses "$multi_other_count" \
        --argjson tcpProxyV2Verified "$tcp_proxy_v2_verified" \
        --argjson tlsPassthroughVerified "$tls_passthrough_verified" \
        --argjson udpIngressProofs "$udp_ingress_proofs" \
        --argjson udpBackendProofs "$udp_backend_proofs" \
        --argjson otelResourceSpansRecords "$otel_spans_count" \
        --argjson otelResourceMetricsRecords "$otel_metrics_count" \
        --argjson badUpstreamCaRejected "$bad_upstream_ca_rejected" \
        '{
            schema: 1,
            mode: $mode,
            runIndex: ($runIndex | tonumber),
            exactBackendBodyChecks: $exactBackendBodyChecks,
            legacyRedirectStatus: $legacyRedirectStatus,
            legacyExcludedSubtreeStatus: $legacyExcludedStatus,
            nativeExcludedSubtreeStatus: $nativeExcludedStatus,
            multiUpstreamResponses: {
                catalog: $multiHttpBackendResponses,
                other: $multiOtherBackendResponses
            },
            protocols: {
                http2Version: (if $http2Version == "not-tested" then null else $http2Version end),
                http3Version: (if $http3Version == "not-tested" then null else $http3Version end),
                tcpProxyV2Verified: $tcpProxyV2Verified,
                tlsPassthroughVerified: $tlsPassthroughVerified,
                udpIngressProofs: $udpIngressProofs,
                udpBackendProofs: $udpBackendProofs
            },
            negativeControls: {
                badUpstreamCaRejected: $badUpstreamCaRejected
            },
            telemetry: {
                resourceSpansRecords: $otelResourceSpansRecords,
                resourceMetricsRecords: $otelResourceMetricsRecords,
                postRebootTraceEvidenceSha256: $postRebootTraceSha256
            }
        }' > "$destination" || fail 'could not write sanitized client metrics'
    chmod 600 "$destination"
}

check_udp_http_control() {
    local body="$root/logs/client-udp-http-control.body" status
    if status=$(curl --silent --show-error \
        --resolve shop.acceptance.test:18081:127.0.0.1 \
        --output "$body" --write-out '%{http_code}' \
        'http://shop.acceptance.test:18081/items/42?origin=udp-control'); then
        :
    else
        fail 'HTTP control request failed during the UDP route drift check'
    fi
    [[ "$status" == 200 ]] || fail "HTTP control route returned status $status during the UDP route drift check"
    grep -Fq 'http-backend:/items/42?origin=udp-control' "$body" \
        || fail 'HTTP control route did not reach the healthy catalog backend during the UDP route drift check'
}

udp_capture_pid=''
stop_udp_capture() {
    local status=0
    if [[ -n "$udp_capture_pid" ]]; then
        kill -INT "$udp_capture_pid" 2>/dev/null || true
        if wait "$udp_capture_pid"; then
            :
        else
            status=$?
        fi
        udp_capture_pid=''
    fi
    return "$status"
}
restore_upstream_fixture() {
    local certificate="$root/certs/upstream-server.pem"
    local key="$root/certs/upstream-server.key"
    local staged_certificate="$root/certs/.upstream-server.pem.restore.$$"
    local staged_key="$root/certs/.upstream-server.key.restore.$$"
    local status recovered=false
    [[ -s "$negative_fixture_dir/original-upstream-server.pem" \
       && -s "$negative_fixture_dir/original-upstream-server.key" ]] || return 1
    install -o root -g root -m 644 "$negative_fixture_dir/original-upstream-server.pem" "$staged_certificate" || return 1
    install -o root -g root -m 600 "$negative_fixture_dir/original-upstream-server.key" "$staged_key" || return 1
    mv -fT -- "$staged_certificate" "$certificate" || return 1
    mv -fT -- "$staged_key" "$key" || return 1
    systemctl restart dorothy-traefik-acceptance-backends.service \
        > "$root/logs/client-bad-upstream-restore.log" 2>&1 || return 1
    for _ in $(seq 1 30); do
        if status=$(curl --silent --show-error --fail --connect-timeout 2 --max-time 4 \
            --resolve backend.acceptance.test:8081:127.0.0.1 \
            --cacert "$root/certs/upstream-ca.pem" \
            --output "$root/logs/client-bad-upstream-restored-direct.body" --write-out '%{http_code}' \
            https://backend.acceptance.test:8081/health); then
            if [[ "$status" == 200 ]] \
               && printf '%s\n' tls-backend-ready | cmp -s - "$root/logs/client-bad-upstream-restored-direct.body"; then
                if status=$(curl --silent --show-error --insecure --connect-timeout 2 --max-time 5 \
                    --resolve shop.acceptance.test:18443:127.0.0.1 \
                    --output "$root/logs/client-bad-upstream-restored-route.body" --write-out '%{http_code}' \
                    https://shop.acceptance.test:18443/secure/health) \
                   && [[ "$status" == 200 ]] \
                   && printf '%s\n' tls-backend:/secure/health | cmp -s - "$root/logs/client-bad-upstream-restored-route.body"; then
                    recovered=true
                    break
                fi
            fi
        fi
        sleep 1
    done
    [[ "$recovered" == true ]] || return 1
    upstream_swap_active=false
}
cleanup_client_fixtures() {
    local status=$?
    trap - EXIT
    stop_udp_capture || true
    if [[ "$upstream_swap_active" == true ]] && ! restore_upstream_fixture; then
        printf 'Could not restore the original HTTPS backend certificate after a failed negative control.\n' >&2
        status=1
    fi
    if [[ -n "$negative_fixture_dir" && "$negative_fixture_dir" == "$root/logs/.negative-tls."* \
       && -d "$negative_fixture_dir" && ! -L "$negative_fixture_dir" ]]; then
        if ! rm -rf -- "$negative_fixture_dir"; then
            printf 'Could not remove private negative-control TLS fixture material.\n' >&2
            status=1
        fi
    fi
    exit "$status"
}
trap cleanup_client_fixtures EXIT

start_udp_capture() {
    local capture_file=$1 started=false
    command -v tcpdump >/dev/null 2>&1 || fail 'tcpdump is required for UDP data-plane evidence'
    tcpdump --immediate-mode -nn -l -A -s 0 -i lo 'udp and (dst port 19000 or dst port 19002)' \
        > "$capture_file" 2>&1 &
    udp_capture_pid=$!
    for _ in $(seq 1 10); do
        if grep -Fq 'listening on lo' "$capture_file"; then
            started=true
            break
        fi
        if ! kill -0 "$udp_capture_pid" 2>/dev/null; then break; fi
        sleep 0.05
    done
    [[ "$started" == true ]] || {
        stop_udp_capture || true
        fail 'bounded UDP packet capture did not start on loopback'
    }
}

udp_client_request() {
    local local_address=$1 port=$2 payload=$3 response_file=$4 error_file=$5
    timeout 1 perl -MIO::Socket::INET -e '
        use strict;
        use warnings;
        my ($local_address, $port, $payload) = @ARGV;
        my $socket = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1",
            PeerPort => $port,
            LocalAddr => $local_address,
            Proto => "udp",
            Timeout => 1,
        ) or die "UDP socket: $!";
        my $sent = $socket->send($payload);
        defined($sent) && $sent == length($payload) or die "UDP send: $!";
        my $readable = "";
        vec($readable, fileno($socket), 1) = 1;
        exit 3 unless select($readable, undef, undef, 0.75);
        my $reply = "";
        defined($socket->recv($reply, 4096, 0)) or die "UDP receive: $!";
        print $reply;
    ' "$local_address" "$port" "$payload" > "$response_file" 2> "$error_file"
}

capture_has_nonce_at() {
    local capture_file=$1 destination_port=$2 nonce=$3
    awk -v destination="> 127.0.0.1.$destination_port:" -v nonce="$nonce" '
        / > / { current = index($0, destination) > 0; next }
        current && index($0, nonce) { found = 1 }
        END { exit !found }
    ' "$capture_file"
}

probe_udp_path() {
    local name=$1 port=$2 local_address=$3 expect_reply=$4 expect_backend=$5
    local nonce="udp-${name}-${RANDOM}-${RANDOM}-$$"
    local capture_file="$root/logs/client-udp-$name.tcpdump"
    local response_file="$root/logs/client-udp-$name.response"
    local request_status=0
    start_udp_capture "$capture_file"
    if udp_client_request "$local_address" "$port" "$nonce" "$response_file" \
        "$root/logs/client-udp-$name.error"; then
        request_status=0
    else
        request_status=$?
    fi
    sleep 0.25
    stop_udp_capture || fail 'bounded UDP packet capture did not stop cleanly'
    capture_has_nonce_at "$capture_file" "$port" "$nonce" \
        || fail "UDP capture did not observe nonce ingress to listener :$port"
    udp_ingress_proofs=$((udp_ingress_proofs + 1))
    if [[ "$expect_backend" == true ]]; then
        capture_has_nonce_at "$capture_file" 19002 "$nonce" \
            || fail 'positive UDP capture did not observe the nonce at backend :19002'
        udp_backend_proofs=$((udp_backend_proofs + 1))
    elif capture_has_nonce_at "$capture_file" 19002 "$nonce"; then
        fail 'withdrawn UDP route forwarded the nonce to old backend :19002'
    fi
    if [[ "$expect_reply" == true ]]; then
        [[ "$request_status" == 0 && "$(<"$response_file")" == "$nonce" ]] \
            || fail "UDP listener :$port did not echo the complete fresh payload"
    else
        [[ "$request_status" != 0 && ! -s "$response_file" ]] \
            || fail "withdrawn UDP listener :$port returned a response to the fresh peer"
    fi
}

probe_udp_reply() {
    local name=$1 port=$2 local_address=$3
    local payload="udp-${name}-${RANDOM}-${RANDOM}-$$"
    local response_file="$root/logs/client-udp-$name.response"
    if udp_client_request "$local_address" "$port" "$payload" "$response_file" \
        "$root/logs/client-udp-$name.error"; then
        :
    else
        fail "UDP listener :$port did not return a response to a fresh peer"
    fi
    [[ "$(<"$response_file")" == "$payload" ]] \
        || fail "UDP listener :$port did not echo the complete fresh payload"
}

check_udp_api_routes() {
    local rawdata="$root/logs/client-udp-rawdata.json"
    curl --noproxy '*' --silent --show-error --fail --max-time 2 \
        --output "$rawdata" http://127.0.0.1:19080/api/rawdata \
        || fail 'live Traefik UDP rawdata API request failed'
    if [[ "$mode" == udp-drift ]]; then
        jq -e '(.udpRouters["echo-other@file"].status == "enabled") and (.udpRouters["echo@file"] == null or .udpRouters["echo@file"].service == "drift-unreachable")' \
            "$rawdata" >/dev/null \
            || fail 'UDP echo is neither withdrawn nor routed to the injected unreachable backend'
    else
        jq -e '(.udpRouters["echo@file"].service == "echo") and (.udpRouters["echo-other@file"].status == "enabled")' \
            "$rawdata" >/dev/null \
            || fail 'live Traefik rawdata did not show both UDP echo routers after repair'
    fi
}

if [[ "$mode" == udp-drift || "$mode" == udp-repaired ]]; then
    check_udp_http_control
    check_udp_api_routes
    if [[ "$mode" == udp-drift ]]; then
        probe_udp_path withdrawn 19000 127.0.0.3 false false
        probe_udp_reply surviving 19003 127.0.0.4
        printf 'UDP negative control: nonce reached :19000, not the old backend :19002; :19003 and HTTP were healthy.\n'
    else
        probe_udp_reply restored 19000 127.0.0.3
        probe_udp_reply surviving-restored 19003 127.0.0.4
        printf 'Both UDP echo routes and the independent HTTP control passed after repair.\n'
    fi
    write_metrics
    exit 0
fi



legacy_body="$root/logs/client-legacy.body"
legacy_status=$(curl --silent --show-error --insecure \
    --resolve example.org:443:127.0.0.1 \
    --output "$legacy_body" --write-out '%{http_code}' \
    https://example.org/legacy-check)
[[ "$legacy_status" == 200 ]] || fail "legacy TLS route returned status $legacy_status"
assert_exact_body "$legacy_body" 'http-backend:/legacy-check;forwarded:127.0.0.1' 'legacy TLS route'

http_body="$root/logs/client-http.body"
http_headers="$root/logs/client-http.headers"
http_status=$(curl --silent --show-error --compressed \
    --resolve shop.acceptance.test:18081:127.0.0.1 \
    --dump-header "$http_headers" --output "$http_body" --write-out '%{http_code}' \
    'http://shop.acceptance.test:18081/items/42?origin=acceptance')
[[ "$http_status" == 200 ]] || fail "HTTP route returned status $http_status"
assert_exact_body "$http_body" 'http-backend:/items/42?origin=acceptance;forwarded:127.0.0.1' 'ordered add-prefix/strip-prefix route'
grep -Eiq '^content-encoding:[[:space:]]*gzip' "$http_headers" || fail 'HTTP compression middleware did not negotiate gzip'

status_body="$root/logs/client-shared-service.body"
status_code=$(curl --silent --show-error \
    --resolve shop.acceptance.test:18081:127.0.0.1 \
    --output "$status_body" --write-out '%{http_code}' \
    http://shop.acceptance.test:18081/status)
[[ "$status_code" == 200 ]] || fail "shared HTTP service route returned status $status_code"
assert_exact_body "$status_body" 'http-backend:/status;forwarded:127.0.0.1' 'shared HTTP service route'

other_body="$root/logs/client-other-backend.body"
other_code=$(curl --silent --show-error \
    --resolve shop.acceptance.test:18081:127.0.0.1 \
    --output "$other_body" --write-out '%{http_code}' \
    http://shop.acceptance.test:18081/other/42)
[[ "$other_code" == 200 ]] || fail "second HTTP backend route returned status $other_code"
assert_exact_body "$other_body" 'other-backend:/other/42' 'second HTTP backend route'

catalog_health=$(curl --fail --silent --show-error --max-time 2 http://127.0.0.1:8080/health) \
    || fail 'direct catalog backend health control failed'
[[ "$catalog_health" == http-backend-ready ]] || fail 'direct catalog backend health control returned an unexpected body'
other_health=$(curl --fail --silent --show-error --max-time 2 http://127.0.0.1:8082/health) \
    || fail 'direct other backend health control failed'
[[ "$other_health" == other-backend-ready ]] || fail 'direct other backend health control returned an unexpected body'

multi_rawdata="$root/logs/client-multi-rawdata.json"
multi_service_state=''
for _ in $(seq 1 30); do
    if curl --noproxy '*' --silent --show-error --fail --max-time 2 \
        --output "$multi_rawdata" http://127.0.0.1:19080/api/rawdata \
        2>> "$root/logs/client-multi-rawdata.curl-error"; then
        multi_service_state=$(jq -r '(.services["multi@file"].serverStatus["http://127.0.0.1:18099"] // "") | ascii_downcase' \
            "$multi_rawdata" 2>/dev/null || true)
        if [[ "$multi_service_state" == down ]]; then break; fi
    fi
    sleep 1
done
[[ "$multi_service_state" == down ]] \
    || fail "live Traefik rawdata did not report the unreachable multi upstream as DOWN (observed: ${multi_service_state:-missing})"

multi_http=false
multi_other=false
for index in $(seq 1 12); do
    multi_body="$root/logs/client-multi-$index.body"
    if multi_status=$(curl --silent --show-error --connect-timeout 2 --max-time 5 \
        --resolve shop.acceptance.test:18081:127.0.0.1 \
        --output "$multi_body" --write-out '%{http_code}' \
        "http://shop.acceptance.test:18081/multi/request-$index"); then
        :
    else
        fail "multi-upstream request $index did not complete"
    fi
    [[ "$multi_status" == 200 ]] || fail "multi-upstream request $index returned status $multi_status"
    response=$(<"$multi_body")
    case "$response" in
        "http-backend:/multi/request-$index;forwarded:127.0.0.1")
            multi_http=true
            multi_http_count=$((multi_http_count + 1))
            assert_exact_body "$multi_body" "http-backend:/multi/request-$index;forwarded:127.0.0.1" 'multi-upstream catalog backend'
            ;;
        "other-backend:/multi/request-$index")
            multi_other=true
            multi_other_count=$((multi_other_count + 1))
            assert_exact_body "$multi_body" "other-backend:/multi/request-$index" 'multi-upstream other backend'
            ;;
        *) fail "multi-upstream request $index returned an unknown or non-exact backend response" ;;
    esac
done
[[ "$multi_http" == true && "$multi_other" == true ]] || fail 'multi-upstream load balancer did not use both healthy servers'
if ! curl --noproxy '*' --silent --show-error --fail --max-time 2 \
    --output "$multi_rawdata" http://127.0.0.1:19080/api/rawdata \
    2>> "$root/logs/client-multi-rawdata.curl-error"; then
    fail 'live Traefik rawdata health control failed after multi-upstream requests'
fi
multi_service_state_after=$(jq -r '(.services["multi@file"].serverStatus["http://127.0.0.1:18099"] // "") | ascii_downcase' \
    "$multi_rawdata" 2>/dev/null || true)
[[ "$multi_service_state_after" == down ]] || fail 'live API no longer reports the unreachable multi upstream as DOWN'

excluded_status=$(curl --silent --show-error \
    --resolve shop.acceptance.test:18081:127.0.0.1 \
    --output "$root/logs/client-excluded-subtree.body" --write-out '%{http_code}' \
    http://shop.acceptance.test:18081/multi/private/hidden)
native_excluded_status=$excluded_status
[[ "$excluded_status" == 404 ]] || fail "native excluded HTTP subtree returned status $excluded_status"

legacy_redirect_headers="$root/logs/client-legacy-redirect.headers"
legacy_redirect_status=$(curl --silent --show-error --noproxy '*' \
    --resolve redirect.acceptance.test:443:127.0.0.1 \
    --dump-header "$legacy_redirect_headers" --output "$root/logs/client-legacy-redirect.body" \
    --write-out '%{http_code}' \
    'http://redirect.acceptance.test:443/from/legacy?source=acceptance')
[[ "$legacy_redirect_status" == 301 ]] || fail "legacy permanent redirect returned status $legacy_redirect_status"
legacy_redirect_location=$(awk 'tolower($1) == "location:" { sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$legacy_redirect_headers")
[[ "$legacy_redirect_location" == 'https://target.acceptance.test/from/legacy?source=acceptance' ]] \
    || fail 'legacy redirect returned an unexpected Location header'

legacy_excluded_status=$(curl --silent --show-error --noproxy '*' \
    --resolve redirect.acceptance.test:443:127.0.0.1 \
    --output "$root/logs/client-legacy-excluded-subtree.body" --write-out '%{http_code}' \
    http://redirect.acceptance.test:443/private/hidden)
[[ "$legacy_excluded_status" == 404 ]] || fail "legacy excluded redirect subtree returned status $legacy_excluded_status"

unknown_status=$(curl --silent --show-error \
    --resolve outsider.acceptance.test:18081:127.0.0.1 \
    --output "$root/logs/client-unknown-host.body" --write-out '%{http_code}' \
    http://outsider.acceptance.test:18081/items)
[[ "$unknown_status" == 404 ]] || fail "unmatched HTTP host returned status $unknown_status"
sni_body="$root/logs/client-sni-proof.body"
sni_status=$(curl --silent --show-error --insecure \
    --resolve sni-proof.acceptance.test:18449:127.0.0.2 \
    --output "$sni_body" --write-out '%{http_code}' \
    https://sni-proof.acceptance.test:18449/sni-proof)
[[ "$sni_status" == 200 ]] || fail "SNI proof listener returned status $sni_status"
assert_exact_body "$sni_body" 'http-backend:/sni-proof;forwarded:127.0.0.1' 'SNI proof router'
proof_certificate="$root/certs/sni-proof.pem"
[[ -s "$proof_certificate" ]] || fail 'SNI proof certificate snapshot is missing'
certificate_fingerprint() {
    local address=$1 diagnostic=$2
    timeout 5 openssl s_client -connect "$address" -servername sni-proof.acceptance.test \
        -showcerts </dev/null 2>"$diagnostic" \
        | openssl x509 -noout -fingerprint -sha256 2>> "$diagnostic" \
        | awk -F= 'NR == 1 { gsub(/:/, "", $2); print tolower($2) }'
}
expected_tcp_tls_fingerprint=$(openssl x509 -in "$proof_certificate" -noout -fingerprint -sha256 \
    | awk -F= 'NR == 1 { gsub(/:/, "", $2); print tolower($2) }')
http_proof_fingerprint=$(certificate_fingerprint 127.0.0.2:18449 "$root/logs/client-tcp-tls-http-fingerprint.log") \
    || fail 'could not fingerprint the SNI proof HTTP listener certificate'
tcp_proof_fingerprint=$(certificate_fingerprint 127.0.0.1:19000 "$root/logs/client-tcp-tls-fingerprint.log") \
    || fail 'could not fingerprint the TCP TLS-terminated listener certificate'
[[ "$expected_tcp_tls_fingerprint" =~ ^[0-9a-f]{64}$ \
   && "$http_proof_fingerprint" == "$expected_tcp_tls_fingerprint" \
   && "$tcp_proof_fingerprint" == "$expected_tcp_tls_fingerprint" ]] \
    || fail 'TCP TLS termination did not present the exact SNI proof certificate used by the HTTP listener'

if ! timeout 5 openssl s_client -brief -connect 127.0.0.1:19000 \
    -servername sni-proof.acceptance.test </dev/null \
    > "$root/logs/client-tcp-tls-handshake.log" 2>&1; then
    fail 'TCP TLS-terminated router did not complete a bounded TLS handshake'
fi
grep -Eq '^Protocol version: TLSv1\.[23]$' "$root/logs/client-tcp-tls-handshake.log" \
    || fail 'TCP TLS-terminated router did not negotiate TLS 1.2 or TLS 1.3'
grep -Eq '^Ciphersuite: .+' "$root/logs/client-tcp-tls-handshake.log" \
    || fail 'TCP TLS-terminated router reported no negotiated TLS cipher suite'

tcp_tls_payload="tcp-tls-v2-${RANDOM}-${RANDOM}"
tcp_tls_echo="$root/logs/client-tcp-tls-terminated-echo.bin"
# Keep stdin open until the echo has arrived; closing it immediately sends TLS close_notify.
if ! timeout 8 perl -MIPC::Open2 - "$tcp_tls_echo" "$tcp_tls_payload" "$proof_certificate" \
    2> "$root/logs/client-tcp-tls-echo.tls" <<'PERL'
use strict;
use warnings;
my ($path, $payload, $ca) = @ARGV;
my $pid = open2(my $from, my $to, 'openssl', 's_client', '-quiet', '-no_ign_eof',
    '-connect', '127.0.0.1:19000', '-servername', 'sni-proof.acceptance.test',
    '-verify_hostname', 'sni-proof.acceptance.test', '-verify_return_error', '-CAfile', $ca);
syswrite($to, $payload) == length($payload) or die "short TLS write";
my $expected_length = 28 + length($payload);
my $response = '';
while (length($response) < $expected_length) {
    sysread($from, my $chunk, $expected_length - length($response)) or die "short TLS echo";
    $response .= $chunk;
}
close $to; close $from; waitpid($pid, 0);
open my $file, '>:raw', $path or die "open echo: $!";
print {$file} $response;
die "wrong PROXY v2 echo length" unless length($response) == $expected_length;
my ($signature, $version_command, $family_protocol, $length,
    $source, $destination, $source_port, $destination_port) =
    unpack("a12CCnNNnn", substr($response, 0, 28));
die "wrong PROXY v2 signature/version/family/length"
    unless $signature eq "\r\n\r\n\0\r\nQUIT\n"
        && $version_command == 33
        && $family_protocol == 17
        && $length == 12;
die "wrong PROXY v2 TCP endpoints"
    unless $source == 0x7f000001
        && $destination == 0x7f000001
        && $source_port > 0
        && $destination_port == 19000;
die "wrong raw TCP backend payload" unless substr($response, 28) eq $payload;
PERL
then
    fail 'TCP TLS termination did not return the raw non-TLS backend PROXY v2 frame and payload'
fi
printf 'TCP TLS termination matched the SNI proof certificate and returned a verified PROXY v2 raw echo.\n'


proxy_request() {
    local name=$1 local_address=$2 forwarded_address=$3
    local response="$root/logs/client-proxy-$name.response"
    timeout 8 perl -MIO::Socket::INET -e '
        use strict;
        use warnings;
        my $local_address = shift @ARGV;
        my $socket = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1",
            PeerPort => 18082,
            LocalAddr => $local_address,
            Proto => "tcp",
            Timeout => 3,
        ) or die "connect: $!";
        binmode($socket);
        die "unexpected connected endpoints"
            unless $socket->sockhost eq $local_address
                && $socket->peerhost eq "127.0.0.1"
                && $socket->peerport == 18082;
        my $packet = "\r\n\r\n\0\r\nQUIT\n"
            . pack("CCnNNnn", 33, 17, 12, 0xcb007137, 0x7f000001, 12345, 18082)
            . "GET /proxy/trusted HTTP/1.1\r\n"
            . "Host: shop.acceptance.test\r\n"
            . "Connection: close\r\n\r\n";
        my $offset = 0;
        while ($offset < length($packet)) {
            my $written = syswrite($socket, $packet, length($packet) - $offset, $offset);
            defined($written) && $written > 0 or die "write: $!";
            $offset += $written;
        }
        my $response = "";
        while (1) {
            my $count = sysread($socket, my $chunk, 4096);
            defined($count) or die "read: $!";
            last if $count == 0;
            $response .= $chunk;
        }
        print $response;
    ' "$local_address" > "$response"
    grep -Eq '^HTTP/1\.[01] 200([[:space:]]|$)' "$response" \
        || fail "$name inbound PROXY request did not receive HTTP 200"
    grep -Fq "http-backend:/proxy/trusted;forwarded:$forwarded_address" "$response" \
        || fail "$name inbound PROXY request did not forward the expected address $forwarded_address"
}
proxy_request trusted 127.0.0.1 203.0.113.55
proxy_request untrusted 127.0.0.2 127.0.0.2


cert_serial() {
    local address=$1
    local server_name=$2
    openssl s_client -connect "$address" -servername "$server_name" -showcerts </dev/null 2>/dev/null \
        | openssl x509 -noout -serial 2>/dev/null | awk -F= 'NR == 1 { print $2 }'
}

acme_account_manifest() {
    local destination=$1 store key_digest accounts=0
    local stores=()
    shopt -s nullglob
    stores=(/var/lib/keroosha-traefik/acme-*.json)
    shopt -u nullglob
    ((${#stores[@]} > 0)) || return 1
    : > "$destination"
    for store in "${stores[@]}"; do
        [[ -f "$store" && ! -L "$store" ]] || return 1
        # Traefik can reserve an empty store for a configured but unused resolver.
        if [[ ! -s "$store" ]]; then
            printf '%s empty\n' "${store##*/}" >> "$destination"
            continue
        fi
        if key_digest=$(jq -er 'to_entries | sort_by(.key) | .[].value.Account.PrivateKey | select(type == "string" and length > 0)' "$store" \
            | sha256sum | awk '{ print $1 }'); then
            :
        else
            return 1
        fi
        printf '%s %s\n' "${store##*/}" "$key_digest" >> "$destination"
        accounts=$((accounts + 1))
    done
    (( accounts > 0 )) || return 1
    sort -o "$destination" "$destination"
}

run_acme_check() {
    local name=$1
    shift
    if "$@" > "$root/logs/client-acme-$name.log" 2>&1; then
        printf 'ACME check passed: %s\n' "$name"
    else
        acme_failures+=("$name")
        printf 'ACME check failed: %s; see %s/logs/client-acme-%s.log\n' "$name" "$root" "$name"
    fi
}

check_dns_acme() {
    local secure_url=https://shop.acceptance.test:18443/secure/health
    local issued=false serial_before serial_after initial_file="$root/logs/acme-acceptance-serial-before.txt"
    for _ in $(seq 1 90); do
        if curl --silent --show-error --fail --cacert "$root/certs/pebble-issued-root.pem" --connect-timeout 2 --max-time 5 \
            --resolve shop.acceptance.test:18443:127.0.0.1 \
            --output "$root/logs/client-acme-trigger.body" "$secure_url" \
           && grep -Fq 'tls-backend:/secure/health' "$root/logs/client-acme-trigger.body"; then
            issued=true
            break
        fi
        sleep 1
    done
    if [[ "$issued" != true ]]; then
        printf 'DNS-01 issuance did not activate the TLS backend route.\n'
        return 1
    fi

    serial_after=$(cert_serial 127.0.0.1:18443 shop.acceptance.test)
    if [[ -z "$serial_after" ]]; then
        printf 'Could not read the DNS-issued certificate serial.\n'
        return 1
    fi
    if [[ ! -s "$initial_file" ]]; then
        printf '%s\n' "$serial_after" > "$initial_file"
    fi
    serial_before=$(<"$initial_file")
    if [[ "$serial_after" == "$serial_before" ]]; then
        for _ in $(seq 1 180); do
            sleep 1
            serial_after=$(cert_serial 127.0.0.1:18443 shop.acceptance.test)
            [[ -n "$serial_after" ]] || continue
            if [[ "$serial_after" != "$serial_before" ]]; then break; fi
        done
    fi
    if [[ -z "$serial_after" || "$serial_after" == "$serial_before" ]]; then
        printf 'The short-lived DNS-issued certificate did not renew within the acceptance window.\n'
        return 1
    fi
    if ! curl --silent --show-error --fail \
        --resolve shop.acceptance.test:18443:127.0.0.1 \
        --cacert "$root/certs/pebble-issued-root.pem" \
        --output "$root/logs/client-acme-renewed-verified.body" "$secure_url"; then
        printf 'Renewed DNS certificate did not verify against the saved CA trust snapshot.\n'
        return 1
    fi
    grep -Fq 'tls-backend:/secure/health' "$root/logs/client-acme-renewed-verified.body" || {
        printf 'Renewed DNS certificate returned an unexpected backend body.\n'
        return 1
    }
    printf '%s\n' "$serial_after" > "$root/logs/acme-acceptance-serial.txt"
    printf 'Observed DNS ACME renewal: initial serial %s, current serial %s.\n' "$serial_before" "$serial_after"
}

check_http01_acme() {
    local url=https://http01.acceptance.test:18443/http01/probe issued=false
    for _ in $(seq 1 90); do
        if curl --silent --show-error --fail --cacert "$root/certs/pebble-issued-root.pem" --connect-timeout 2 --max-time 5 \
            --resolve http01.acceptance.test:18443:127.0.0.1 \
            --output "$root/logs/client-http01-trigger.body" "$url" \
           && grep -Fq 'http-backend:/http01/probe' "$root/logs/client-http01-trigger.body"; then
            issued=true
            break
        fi
        sleep 1
    done
    if [[ "$issued" != true ]]; then
        printf 'Local HTTP-01 resolver did not serve its validation route.\n'
        return 1
    fi
    if ! curl --silent --show-error --fail \
        --resolve http01.acceptance.test:18443:127.0.0.1 \
        --cacert "$root/certs/pebble-issued-root.pem" \
        --output "$root/logs/client-http01-verified.body" "$url"; then
        printf 'HTTP-01 issued certificate did not verify against the saved CA trust snapshot.\n'
        return 1
    fi
    grep -Fq 'http-backend:/http01/probe' "$root/logs/client-http01-verified.body" || {
        printf 'Verified HTTP-01 route returned an unexpected backend body.\n'
        return 1
    }
}

check_tlsalpn_acme() {
    local url=https://tlsalpn.acceptance.test:5001/tlsalpn/probe issued=false
    for _ in $(seq 1 90); do
        if curl --silent --show-error --fail --cacert "$root/certs/pebble-issued-root.pem" --connect-timeout 2 --max-time 5 \
            --resolve tlsalpn.acceptance.test:5001:127.0.0.1 \
            --output "$root/logs/client-tlsalpn-trigger.body" "$url" \
           && grep -Fq 'http-backend:/tlsalpn/probe' "$root/logs/client-tlsalpn-trigger.body"; then
            issued=true
            break
        fi
        sleep 1
    done
    if [[ "$issued" != true ]]; then
        printf 'Local TLS-ALPN-01 resolver did not serve its validation route.\n'
        return 1
    fi
    if ! curl --silent --show-error --fail \
        --resolve tlsalpn.acceptance.test:5001:127.0.0.1 \
        --cacert "$root/certs/pebble-issued-root.pem" \
        --output "$root/logs/client-tlsalpn-verified.body" "$url"; then
        printf 'TLS-ALPN-01 issued certificate did not verify against the saved CA trust snapshot.\n'
        return 1
    fi
    grep -Fq 'http-backend:/tlsalpn/probe' "$root/logs/client-tlsalpn-verified.body" || {
        printf 'Verified TLS-ALPN-01 route returned an unexpected backend body.\n'
        return 1
    }
}


check_bad_upstream_ca() {
    local bad_ca="$negative_fixture_dir/bad-upstream-ca.pem"
    local bad_ca_key="$negative_fixture_dir/bad-upstream-ca.key"
    local bad_cert="$negative_fixture_dir/bad-upstream-server.pem"
    local bad_key="$negative_fixture_dir/bad-upstream-server.key"
    local bad_csr="$negative_fixture_dir/bad-upstream-server.csr"
    local direct_status route_status
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$bad_ca_key" -out "$bad_ca" -subj '/CN=Dorothy Untrusted Upstream CA' -days 2 \
        -addext 'basicConstraints=critical,CA:TRUE' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign' \
        > "$root/logs/client-bad-upstream-ca.log" 2>&1 \
        || fail 'could not create an independent upstream issuer'
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$bad_key" -out "$bad_csr" -subj '/CN=backend.acceptance.test' \
        > "$root/logs/client-bad-upstream-request.log" 2>&1 \
        || fail 'could not create the independent HTTPS backend identity'
    cat > "$negative_fixture_dir/bad-upstream.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:backend.acceptance.test,IP:127.0.0.1
EOF
    openssl x509 -req -in "$bad_csr" -CA "$bad_ca" -CAkey "$bad_ca_key" -CAcreateserial \
        -out "$bad_cert" -days 2 -sha256 -extfile "$negative_fixture_dir/bad-upstream.ext" \
        > "$root/logs/client-bad-upstream-sign.log" 2>&1 \
        || fail 'could not sign the independent HTTPS backend identity'
    chmod 600 "$bad_ca_key" "$bad_key"
    openssl verify -purpose sslserver -verify_hostname backend.acceptance.test -CAfile "$bad_ca" "$bad_cert" \
        > "$root/logs/client-bad-upstream-self-verify.log" 2>&1 \
        || fail 'independent upstream certificate is not a valid server-auth identity'
    if openssl verify -purpose sslserver -verify_hostname backend.acceptance.test \
        -CAfile "$root/certs/upstream-ca.pem" "$bad_cert" \
        > "$root/logs/client-bad-upstream-trusted-ca-negative.log" 2>&1; then
        fail 'independent upstream certificate chains to the configured upstream CA'
    fi
    [[ -f "$root/certs/upstream-server.pem" && ! -L "$root/certs/upstream-server.pem" \
       && -f "$root/certs/upstream-server.key" && ! -L "$root/certs/upstream-server.key" ]] \
        || fail 'original HTTPS backend certificate pair is missing or unsafe'
    cp --preserve=mode,ownership,timestamps "$root/certs/upstream-server.pem" \
        "$negative_fixture_dir/original-upstream-server.pem"
    cp --preserve=mode,ownership,timestamps "$root/certs/upstream-server.key" \
        "$negative_fixture_dir/original-upstream-server.key"

    if direct_status=$(curl --silent --show-error --fail --resolve backend.acceptance.test:8081:127.0.0.1 \
        --cacert "$root/certs/upstream-ca.pem" --output "$root/logs/client-bad-upstream-direct.body" --write-out '%{http_code}' \
        https://backend.acceptance.test:8081/health); then
        :
    else
        fail 'original HTTPS backend failed its configured CA control before substitution'
    fi
    [[ "$direct_status" == 200 ]] \
        || fail "original HTTPS backend returned status $direct_status before substitution"
    assert_exact_body "$root/logs/client-bad-upstream-direct.body" 'tls-backend-ready' 'original HTTPS backend'

    upstream_swap_active=true
    install -o root -g root -m 644 "$bad_cert" "$root/certs/.upstream-server.pem.acceptance"
    install -o root -g root -m 600 "$bad_key" "$root/certs/.upstream-server.key.acceptance"
    mv -fT -- "$root/certs/.upstream-server.pem.acceptance" "$root/certs/upstream-server.pem"
    mv -fT -- "$root/certs/.upstream-server.key.acceptance" "$root/certs/upstream-server.key"
    systemctl restart dorothy-traefik-acceptance-backends.service \
        > "$root/logs/client-bad-upstream-inject.log" 2>&1 \
        || fail 'could not activate the independent HTTPS backend certificate'
    if direct_status=$(curl --silent --show-error --fail --retry-connrefused --retry 4 --retry-max-time 8 --connect-timeout 2 --max-time 5 \
        --resolve backend.acceptance.test:8081:127.0.0.1 \
        --cacert "$bad_ca" --output "$root/logs/client-bad-upstream-direct-active.body" --write-out '%{http_code}' \
        https://backend.acceptance.test:8081/health); then
        :
    else
        fail 'active independent HTTPS backend certificate failed its own CA control'
    fi
    [[ "$direct_status" == 200 ]] \
        || fail "active independent HTTPS backend returned status $direct_status under its own CA"
    assert_exact_body "$root/logs/client-bad-upstream-direct-active.body" 'tls-backend-ready' 'active independent HTTPS backend'
    if curl --silent --show-error --fail --connect-timeout 2 --max-time 5 \
        --resolve backend.acceptance.test:8081:127.0.0.1 \
        --cacert "$root/certs/upstream-ca.pem" \
        --output "$root/logs/client-bad-upstream-direct-trusted-ca.body" \
        https://backend.acceptance.test:8081/health; then
        fail 'HTTPS backend certificate was accepted by the unrelated configured upstream CA'
    fi
    local cursor
    cursor=$(journalctl -u keroosha-traefik.service -n 1 --show-cursor --no-pager | sed -n 's/^-- cursor: //p')
    [[ -n "$cursor" ]] || fail 'missing pre-request Traefik journal cursor'
    route_status=$(curl --silent --show-error --insecure --connect-timeout 2 --max-time 5 \
        --resolve shop.acceptance.test:18443:127.0.0.1 \
        --output "$root/logs/client-bad-upstream-route.body" --write-out '%{http_code}' \
        https://shop.acceptance.test:18443/secure/health) \
        || fail 'secure Traefik route did not return an HTTP response for the upstream-CA negative control'
    [[ "$route_status" == 500 ]] || fail "unexpected upstream TLS rejection status: $route_status"
    journalctl -u keroosha-traefik.service --after-cursor="$cursor" --no-pager -o cat |
        jq -Rse 'split("\n") | any(.[]; fromjson? | .error=="tls: failed to verify certificate: x509: certificate signed by unknown authority")' \
        >/dev/null || fail 'no new Traefik verifier rejection for the substituted upstream leaf'
    bad_upstream_ca_rejected=true
    restore_upstream_fixture || fail 'original HTTPS backend certificate did not recover after the bad-CA control'
}


if [[ "$mode" == protocols || "$mode" == after-reboot ]]; then
    if [[ "$mode" == protocols ]]; then
        acme_failures=()
        run_acme_check dns-01 check_dns_acme
        run_acme_check http-01 check_http01_acme
        run_acme_check tls-alpn-01 check_tlsalpn_acme
        ((${#acme_failures[@]} == 0)) || fail "independent ACME checks failed: ${acme_failures[*]}"
        protocol_ca="$root/certs/pebble-issued-root.pem"
    else
        [[ -s "$root/certs/pebble-rotated-issued-root.pem" ]] || fail 'pre-reboot rotated CA trust snapshot is missing'
        [[ -s "$root/certs/pebble-reboot-issued-root.pem" ]] || fail 'post-reboot CA trust snapshot is missing'
        old_root="$root/certs/pebble-rotated-issued-root.pem"
        reboot_root="$root/certs/pebble-reboot-issued-root.pem"
        root_bundle="$root/certs/pebble-rotated-reboot-roots.pem"
        cat "$old_root" "$reboot_root" > "$root_bundle"
        chmod 644 "$root_bundle"
        protocol_ca=$root_bundle
    fi

    secure_url=https://shop.acceptance.test:18443/secure/health
    h2_version=$(curl --silent --show-error --fail --http2 \
        --resolve shop.acceptance.test:18443:127.0.0.1 \
        --cacert "$protocol_ca" \
        --output "$root/logs/client-http2.body" --write-out '%{http_version}' "$secure_url")
    [[ "$h2_version" == 2 ]] || fail "TLS entrypoint negotiated HTTP/$h2_version instead of HTTP/2"
    assert_exact_body "$root/logs/client-http2.body" 'tls-backend:/secure/health' 'HTTP/2 secure route'
    http2_version=$h2_version
    h3_version=$(curl --silent --show-error --fail --http3-only \
        --resolve shop.acceptance.test:18443:127.0.0.1 \
        --cacert "$protocol_ca" \
        --output "$root/logs/client-http3.body" --write-out '%{http_version}' "$secure_url")
    [[ "$h3_version" == 3 ]] || fail "TLS entrypoint negotiated HTTP/$h3_version instead of HTTP/3"
    assert_exact_body "$root/logs/client-http3.body" 'tls-backend:/secure/health' 'HTTP/3 secure route'
    http3_version=$h3_version

    if [[ "$mode" == protocols ]]; then
        negative_fixture_dir=$(mktemp -d "$root/logs/.negative-tls.XXXXXXXX") \
            || fail 'could not create a private upstream TLS negative-control directory'
        chmod 700 "$negative_fixture_dir"
        check_bad_upstream_ca
    fi

    timeout 8 perl -MIO::Socket::INET -MSocket=inet_aton -e '
        use strict;
        use warnings;
        my $socket = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1",
            PeerPort => 19000,
            LocalAddr => "127.0.0.2",
            Proto => "tcp",
            Timeout => 3,
        ) or die "connect: $!";
        binmode($socket);
        die "unexpected connected endpoints" unless $socket->sockhost eq "127.0.0.2"
            && $socket->sockport > 0
            && $socket->peerhost eq "127.0.0.1"
            && $socket->peerport == 19000;

        my $message = "dorothy TCP proof with sufficient bytes for TLS sniffing\r\n";
        my $offset = 0;
        while ($offset < length($message)) {
            my $written = syswrite($socket, $message, length($message) - $offset, $offset);
            defined($written) && $written > 0 or die "write: $!";
            $offset += $written;
        }

        my $expected_length = 28 + length($message);
        my $response = "";
        while (length($response) < $expected_length) {
            my $count = sysread($socket, my $chunk, $expected_length - length($response));
            defined($count) or die "read: $!";
            last if $count == 0;
            $response .= $chunk;
            die "oversized TCP echo" if length($response) > $expected_length;
        }
        die "short TCP echo" unless length($response) == $expected_length;

        my ($signature, $version_command, $family_protocol, $length,
            $source, $destination, $source_port, $destination_port) =
            unpack("a12CCnNNnn", substr($response, 0, 28));
        die "bad PROXY v2 signature/version/family/length"
            unless $signature eq "\r\n\r\n\0\r\nQUIT\n"
                && $version_command == 33
                && $family_protocol == 17
                && $length == 12;
        die "bad PROXY v2 addresses/ports"
            unless $source == unpack("N", inet_aton($socket->sockhost))
                && $destination == unpack("N", inet_aton($socket->peerhost))
                && $source_port == $socket->sockport
                && $destination_port == $socket->peerport;
        die "bad echoed application payload" unless substr($response, 28) eq $message;
        print "v2 signature/version/family/length/source/destination/ports/payload verified";
    ' > "$root/logs/client-proxy-v2.bin" || fail 'TCP backend did not return a complete PROXY v2 frame and full-duplex payload'
    tcp_proxy_v2_verified=true

    probe_udp_path baseline 19000 127.0.0.3 true true

    printf 'GET /tls-passthrough HTTP/1.1\r\nHost: backend.acceptance.test\r\nConnection: close\r\n\r\n' \
        | timeout 5 openssl s_client -quiet -verify_return_error \
            -connect 127.0.0.1:19000 -servername backend.acceptance.test \
            -CAfile "$root/certs/upstream-ca.pem" \
            > "$root/logs/client-tcp-passthrough.http" 2> "$root/logs/client-tcp-passthrough.tls"
    perl -0777 -ne 'my ($headers,$body)=split(/\r\n\r\n/,$_,2); defined($body) && $headers =~ /^HTTP\/1\.1 200 OK\r\n/ or die "invalid HTTP response"; print $body' \
        "$root/logs/client-tcp-passthrough.http" > "$root/logs/client-tcp-passthrough.body"
    assert_exact_body "$root/logs/client-tcp-passthrough.body" 'tls-backend:/tls-passthrough' 'TCP TLS passthrough'
    tls_passthrough_verified=true
fi

if [[ "$mode" == rotation ]]; then
    [[ -s "$root/logs/acme-acceptance-serial.txt" ]] || fail 'DNS resolver renewal evidence is missing'
    serial_before=$(<"$root/logs/acme-acceptance-serial.txt")
    rotate_url=https://shop.acceptance.test:18443/secure/health
    rotated=false
    for _ in $(seq 1 90); do
        if curl --silent --show-error --fail --cacert "$root/certs/pebble-rotated-issued-root.pem" --connect-timeout 2 --max-time 5 \
            --resolve shop.acceptance.test:18443:127.0.0.1 \
            --output "$root/logs/client-rotation-trigger.body" "$rotate_url" 2>/dev/null \
           && grep -Fq 'tls-backend:/secure/health' "$root/logs/client-rotation-trigger.body"; then
            rotated=true
            break
        fi
        sleep 1
    done
    [[ "$rotated" == true ]] || fail 'rotated DNS resolver did not load the TLS backend route'
    serial_rotated=$(cert_serial 127.0.0.1:18443 shop.acceptance.test)
    [[ -n "$serial_rotated" && "$serial_rotated" != "$serial_before" ]] || fail 'rotated resolver reused the prior certificate'
    curl --silent --show-error --fail \
        --resolve shop.acceptance.test:18443:127.0.0.1 \
        --cacert "$root/certs/pebble-rotated-issued-root.pem" \
        --output "$root/logs/client-rotation-verified.body" "$rotate_url" \
        || fail 'rotated resolver certificate did not verify against its independent CA root'
    if curl --silent --show-error --fail \
        --resolve shop.acceptance.test:18443:127.0.0.1 \
        --cacert "$root/certs/pebble-issued-root.pem" \
        --output "$root/logs/client-rotation-old-root.body" "$rotate_url"; then
        fail 'rotated resolver certificate remained trusted by the previous CA root'
    fi
    mtls_rotated_url=https://mtls.acceptance.test:18444/mtls/rotated
    mtls_rotated=false
    for _ in $(seq 1 90); do
        if curl --silent --show-error --fail --cacert "$root/certs/pebble-rotated-issued-root.pem" --connect-timeout 2 --max-time 5 \
            --resolve mtls.acceptance.test:18444:127.0.0.1 \
            --cert "$root/certs/client.pem" --key "$root/certs/client.key" \
            --output "$root/logs/client-rotation-mtls-trigger.body" "$mtls_rotated_url" 2>/dev/null \
           && grep -Fq 'http-backend:/mtls/rotated' "$root/logs/client-rotation-mtls-trigger.body"; then
            mtls_rotated=true
            break
        fi
        sleep 1
    done
    [[ "$mtls_rotated" == true ]] || fail 'rotated resolver did not issue the separate mTLS SNI certificate'
    curl --silent --show-error --fail \
        --resolve mtls.acceptance.test:18444:127.0.0.1 \
        --cacert "$root/certs/pebble-rotated-issued-root.pem" \
        --cert "$root/certs/client.pem" --key "$root/certs/client.key" \
        --output "$root/logs/client-rotation-mtls-verified.body" "$mtls_rotated_url" \
        || fail 'rotated mTLS SNI certificate did not verify against its independent CA root'
    acme_account_manifest "$root/logs/acme-account-fingerprints-before-reboot.txt" \
        || fail 'could not capture stable ACME account and store-file evidence before reboot'
    printf '%s\n' "$serial_rotated" > "$root/logs/acme-acceptance-rotated-serial.txt"
fi

if [[ "$mode" == route-update ]]; then
    extra_status=$(curl --silent --show-error \
        --resolve shop.acceptance.test:18081:127.0.0.1 \
        --output "$root/logs/client-extra-route.body" --write-out '%{http_code}' \
        http://shop.acceptance.test:18081/extra/route)
    [[ "$extra_status" == 200 ]] || fail "route-only update returned status $extra_status"
    grep -Fq 'http-backend:/extra/route' "$root/logs/client-extra-route.body" || fail 'route-only update did not add the extra path'
fi
if [[ "$mode" == after-reboot ]]; then
    [[ -s "$root/certs/pebble-rotated-issued-root.pem" ]] || fail 'pre-reboot rotated CA trust snapshot is missing'
    [[ -s "$root/certs/pebble-reboot-issued-root.pem" ]] || fail 'post-reboot CA trust snapshot is missing'
    reboot_serial=$(cert_serial 127.0.0.1:18443 shop.acceptance.test)
    [[ -n "$reboot_serial" ]] || fail 'could not read the post-reboot ACME certificate serial'
    printf '%s\n' "$reboot_serial" > "$root/logs/acme-acceptance-post-reboot-serial.txt"

    old_root="$root/certs/pebble-rotated-issued-root.pem"
    reboot_root="$root/certs/pebble-reboot-issued-root.pem"
    root_bundle="$root/certs/pebble-rotated-reboot-roots.pem"
    cat "$old_root" "$reboot_root" > "$root_bundle"
    chmod 644 "$root_bundle"
    verify_reboot_certificate() {
        local label=$1 url=$2 output=$3
        shift 3
        if curl --silent --show-error --fail \
            --cacert "$old_root" "$@" --output "$output" "$url"; then
            printf '%s verified against the pre-reboot CA snapshot.\n' "$label"
            return 0
        fi
        if curl --silent --show-error --fail \
            --cacert "$root_bundle" "$@" --output "$output" "$url"; then
            printf '%s verified against the bundle of pre- and post-reboot CA snapshots.\n' "$label"
            return 0
        fi
        return 1
    }
    verify_reboot_certificate dns \
        https://shop.acceptance.test:18443/secure/health \
        "$root/logs/client-post-reboot-tls.body" \
        --resolve shop.acceptance.test:18443:127.0.0.1 \
        || fail 'post-reboot DNS certificate was not trusted by the saved CA snapshots'
    assert_exact_body "$root/logs/client-post-reboot-tls.body" 'tls-backend:/secure/health' 'post-reboot DNS route'
    verify_reboot_certificate mtls \
        https://mtls.acceptance.test:18444/mtls/reboot \
        "$root/logs/client-post-reboot-mtls.body" \
        --resolve mtls.acceptance.test:18444:127.0.0.1 \
        --cert "$root/certs/client.pem" --key "$root/certs/client.key" \
        || fail 'post-reboot mTLS certificate or client policy was not trusted by the saved CA snapshots'
    assert_exact_body "$root/logs/client-post-reboot-mtls.body" 'http-backend:/mtls/reboot;forwarded:127.0.0.1' 'post-reboot mTLS route'

    [[ -s "$root/logs/acme-account-fingerprints-before-reboot.txt" ]] \
        || fail 'pre-reboot ACME account/store retention evidence is missing'
    acme_account_manifest "$root/logs/acme-account-fingerprints-after-reboot.txt" \
        || fail 'ACME account/store files were not retained after reboot'
    cmp -s "$root/logs/acme-account-fingerprints-before-reboot.txt" \
        "$root/logs/acme-account-fingerprints-after-reboot.txt" \
        || fail 'ACME account keys or store-file set changed across reboot'
fi

curl --fail --silent --show-error http://127.0.0.1:19080/ping \
    -o "$root/logs/client-private-ping.body"
[[ "$(<"$root/logs/client-private-ping.body")" == OK ]] || fail 'private ping endpoint returned an unexpected response'
curl --fail --silent --show-error http://127.0.0.1:19080/metrics \
    -o "$root/logs/client-private-metrics.txt"
grep -Eq '^traefik_(config_reloads|entrypoint_requests|router_requests)' "$root/logs/client-private-metrics.txt" \
    || fail 'Prometheus metrics were not available on the private admin entrypoint'

legacy_api_status=$(curl --silent --show-error --insecure \
    --resolve example.org:443:127.0.0.1 \
    --output "$root/logs/client-legacy-api.body" --write-out '%{http_code}' \
    https://example.org/api/entrypoints)
[[ "$legacy_api_status" == 200 ]] || fail "legacy traffic listener returned unexpected status $legacy_api_status for /api"
assert_exact_body "$root/logs/client-legacy-api.body" 'http-backend:/api/entrypoints;forwarded:127.0.0.1' 'legacy API router'

secure_api_status=$(curl --silent --show-error --insecure \
    --resolve shop.acceptance.test:18443:127.0.0.1 \
    --output "$root/logs/client-secure-api.body" --write-out '%{http_code}' \
    https://shop.acceptance.test:18443/api/entrypoints)
[[ "$secure_api_status" == 404 ]] || fail "Traefik API was exposed on the secure traffic entrypoint (status $secure_api_status)"
admin_socket=$(ss -H -lntup | awk '$1 == "tcp" && $5 == "127.0.0.1:19080" && /traefik/')
[[ -n "$admin_socket" ]] || fail 'private admin entrypoint is not bound to the loopback address'
guest_ip=$(ip -o -4 addr show scope global | awk 'NR == 1 { split($4, address, "/"); print address[1] }')
[[ -n "$guest_ip" ]] || fail 'could not identify the guest non-loopback address for the admin negative control'
if curl --noproxy '*' --silent --show-error --connect-timeout 2 --max-time 3 \
    --output "$root/logs/client-admin-nonloopback.body" \
    "http://$guest_ip:19080/api/entrypoints"; then
    fail 'private admin endpoint accepted a guest non-loopback connection'
fi

for port in 18081 18082 18443 18444 5001 5002 19000 19003 19080; do
    rows=$(ss -H -lntup | awk -v suffix=":$port" '$5 ~ (suffix "$") && /traefik/')
    [[ -n "$rows" ]] || fail "explicit Traefik listener $port was not active"
    if printf '%s\n' "$rows" | awk '$5 !~ /^127\.0\.0\.1:/ { found = 1 } END { exit !found }'; then
        fail "explicit Traefik listener $port did not stay loopback-bound"
    fi
done
tcp_socket=$(ss -H -lntup | awk '$1 == "tcp" && $5 == "127.0.0.1:19000" && /traefik/')
udp_socket=$(ss -H -lntup | awk '$1 == "udp" && $5 == "127.0.0.1:19000" && /traefik/')
udp_other_socket=$(ss -H -lntup | awk '$1 == "udp" && $5 == "127.0.0.1:19003" && /traefik/')
[[ -n "$tcp_socket" && -n "$udp_socket" && -n "$udp_other_socket" ]] || fail 'TCP and both UDP entrypoints did not bind their requested loopback ports'
h3_socket=$(ss -H -lntup | awk '$1 == "udp" && $5 == "127.0.0.1:18443" && /traefik/')
[[ -n "$h3_socket" ]] || fail 'HTTP/3 did not bind its loopback QUIC socket'
if ss -H -lntup | awk '$1 == "tcp" && $5 == "127.0.0.1:8080" && /traefik/ { found = 1 } END { exit !found }'; then
    fail 'Traefik created the implicit public port 8080 listener'
fi
wildcard_nonlegacy=$(ss -H -lntup | awk '$5 ~ /^(0\.0\.0\.0|\[::\]|:::|\*):/ && $5 !~ /:443$/ && /traefik/')
[[ -z "$wildcard_nonlegacy" ]] || fail 'an explicitly configured Traefik listener escaped loopback'
legacy_wildcard=$(ss -H -lntup | awk '$1 == "tcp" && $5 == "*:443" && /traefik/')
[[ -n "$legacy_wildcard" ]] || fail 'legacy numeric listen 443 no longer has its observed wildcard bind'
printf '%s\n' "$legacy_wildcard" > "$root/logs/legacy-wildcard-443.txt"


if [[ "$mode" == protocols ]]; then
    for _ in $(seq 1 60); do
        if grep -q 'ResourceSpans #' "$root/logs/otelcol.log" \
           && grep -q 'ResourceMetrics #' "$root/logs/otelcol.log"; then
            break
        fi
        sleep 2
    done
    grep -q 'ResourceSpans #' "$root/logs/otelcol.log" || fail 'OTel collector received no Traefik traces'
    grep -q 'ResourceMetrics #' "$root/logs/otelcol.log" || fail 'OTel collector received no Traefik metrics'
    otel_spans_count=$(grep -c 'ResourceSpans #' "$root/logs/otelcol.log" || true)
    otel_metrics_count=$(grep -c 'ResourceMetrics #' "$root/logs/otelcol.log" || true)
elif [[ "$mode" == after-reboot ]]; then
    offset_file="$root/logs/otel-before-reboot.bytes"
    [[ -f "$offset_file" && ! -L "$offset_file" ]] || fail 'pre-reboot OTel log boundary is missing'
    otel_offset=$(<"$offset_file")
    [[ "$otel_offset" =~ ^[0-9]+$ ]] || fail 'pre-reboot OTel log boundary is malformed'
    current_otel="$root/logs/otel-after-reboot-current.log"
    otel_evidence="$root/logs/otel-after-reboot-evidence.txt"
    for _ in $(seq 1 60); do
        current_size=$(stat --format='%s' "$root/logs/otelcol.log")
        if (( current_size > otel_offset )); then
            tail -c "+$((otel_offset + 1))" "$root/logs/otelcol.log" > "$current_otel"
            if grep -q 'ResourceSpans #' "$current_otel" \
               && grep -q 'ResourceMetrics #' "$current_otel"; then
                break
            fi
        fi
        sleep 2
    done
    grep -q 'ResourceSpans #' "$current_otel" || fail 'post-reboot OTel log contains no new Traefik traces'
    grep -q 'ResourceMetrics #' "$current_otel" || fail 'post-reboot OTel log contains no new Traefik metrics'
    grep -E 'ResourceSpans #|ResourceMetrics #' "$current_otel" > "$otel_evidence"
    otel_spans_count=$(grep -c 'ResourceSpans #' "$otel_evidence" || true)
    otel_metrics_count=$(grep -c 'ResourceMetrics #' "$otel_evidence" || true)
    post_reboot_trace_sha256=$(sha256sum "$otel_evidence" | awk '{ print $1 }')
    chmod 600 "$current_otel" "$otel_evidence"
fi

write_metrics
printf 'Protocol clients passed for %s.\n' "$mode"
