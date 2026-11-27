#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 2 ]]; then
    printf 'Usage: client-checks.sh /var/tmp/dorothy-traefik-acceptance.XXXXXXXX <positive|no-tcp|proxy-placement>\n' >&2
    exit 2
fi
root=$(realpath -e -- "$1")
mode=$2
case "$root" in
    /var/tmp/dorothy-traefik-acceptance.*) ;;
    *) printf 'Refusing to test outside the private acceptance guest root.\n' >&2; exit 2 ;;
esac
[[ -f "$root/.owner" && "$(<"$root/.owner")" == dorothy-traefik-acceptance-guest-v1 ]] || {
    printf 'Private guest ownership marker is missing.\n' >&2
    exit 2
}
case "$mode" in
    positive|no-tcp|proxy-placement|udp-conflict-control) ;;
    *) printf 'Unknown review client-check mode.\n' >&2; exit 2 ;;
esac
mkdir -m 700 -p "$root/logs"

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}
request() {
    local label=$1 port=$2 host=$3 path=$4 method=${5:-GET} status
    shift 4
    if (( $# )); then shift; fi
    local body="$root/logs/review-http-$label.body"
    local headers="$root/logs/review-http-$label.headers"
    local -a options=(--noproxy '*' --silent --show-error --connect-timeout 2 --max-time 8 -H "Host: $host")
    if [[ "$method" != GET ]]; then options+=(-X "$method"); fi
    options+=("$@")
    status=$(curl "${options[@]}" -D "$headers" -o "$body" -w '%{http_code}' "http://127.0.0.1:$port$path") \
        || fail "HTTP request $label could not reach its listener"
    [[ "$status" == 200 ]] || fail "HTTP request $label returned status $status"
}
request_secure() {
    local label=$1 port=$2 host=$3 path=$4 status
    local body="$root/logs/review-http-$label.body"
    local headers="$root/logs/review-http-$label.headers"
    status=$(curl --noproxy '*' --cacert "$root/certs/sni-proof.pem" --silent --show-error --connect-timeout 2 --max-time 8 \
        --resolve "$host:$port:127.0.0.1" -H "Host: $host" -D "$headers" -o "$body" -w '%{http_code}' \
        "https://$host:$port$path") || fail "HTTPS request $label could not reach its listener"
    [[ "$status" == 200 ]] || fail "HTTPS request $label returned status $status"
}
assert_body() {
    local label=$1 text=$2
    grep -Fq -- "$text" "$root/logs/review-http-$label.body" \
        || fail "HTTP request $label reached the wrong backend or returned the wrong path"
}
assert_header() {
    local label=$1 text=$2
    grep -Fqi -- "$text" "$root/logs/review-http-$label.headers" \
        || fail "HTTP request $label did not receive the expected middleware response header"
}
tcp_exchange() {
    local label=$1 port=$2 source=$3 packet_mode=$4 expected_source=$5
    local output="$root/logs/review-tcp-$label.bin"
    timeout 8 perl -MIO::Socket::INET -e '
        use strict;
        use warnings;
        use Errno qw(ECONNRESET);
        my ($port, $source, $mode, $expected, $output, $nonce) = @ARGV;
        my $socket = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1", PeerPort => $port, LocalAddr => $source,
            Proto => "tcp", Timeout => 3,
        ) or die "connect: $!";
        binmode($socket);
        if ($mode =~ /^middleware-/) {
            open(my $peer, ">", "$output.peer") or die "open peer: $!";
            print {$peer} $socket->sockhost . ":" . $socket->sockport or die "write peer: $!";
            close($peer) or die "close peer: $!";
        }
        my $payload = "review-proxy-payload-$mode";
        my $packet;
        if ($mode eq "v1-trusted" || $mode eq "v1-untrusted") {
            my $from = $mode eq "v1-trusted" ? "203.0.113.55" : "203.0.113.55";
            $packet = "PROXY TCP4 $from 127.0.0.1 45678 $port\r\n" . $payload;
        } elsif ($mode eq "v2-placement") {
            $packet = $payload;
        } elsif ($mode eq "v2-trusted" || $mode eq "v2-untrusted") {
            my $signature = "\r\n\r\n\0\r\nQUIT\n";
            $packet = $signature . pack("CCnNNnn", 0x21, 0x11, 12,
                0xcb00714d, 0x7f000001, 45678, $port) . $payload;
        } else {
            $packet = $nonce;
        }
        my $offset = 0;
        while ($offset < length($packet)) {
            my $written = syswrite($socket, $packet, length($packet) - $offset, $offset);
            defined($written) && $written > 0 or die "write: $!";
            $offset += $written;
        }
        shutdown($socket, 1);
        my $response = "";
        while (1) {
            my $readable = "";
            vec($readable, fileno($socket), 1) = 1;
            my $ready = select($readable, undef, undef, 3);
            die "middleware connection timed out or select failed" if $mode =~ /^middleware-/ && (!defined($ready) || !$ready);
            last if !defined($ready) || $ready == 0;
            my $count = sysread($socket, my $chunk, 4096);
            last if !defined($count) && $! == ECONNRESET && $mode eq "middleware-denied" && !length($response);
            defined($count) or die "read: $!";
            last if $count == 0;
            $response .= $chunk;
        }
        close($socket);
        open(my $file, ">:raw", $output) or die "open output: $!";
        print {$file} $response or die "write output: $!";
        close($file) or die "close output: $!";
        if ($mode eq "v1-trusted") {
            $response =~ /\APROXY TCP4 203\.0\.113\.55 \S+ \d+ \d+\r\n\Q$payload\E\z/s
                or die "named TCP v1 transport did not emit a trusted PROXY header and exact payload";
        } elsif ($mode eq "v1-untrusted") {
            if (length($response)) {
                $response =~ /\APROXY TCP4 127\.0\.0\.2 \S+ \d+ \d+\r\n/s
                    or die "untrusted PROXY v1 source replaced the actual peer address";
            }
        } elsif ($mode eq "v2-trusted") {
            my $signature = "\r\n\r\n\0\r\nQUIT\n";
            substr($response, 0, 12) eq $signature or die "named TCP v2 transport did not emit a PROXY signature";
            length($response) >= 28 or die "short TCP PROXY v2 response";
            my ($version, $family, $length) = unpack("CCn", substr($response, 12, 4));
            $version == 0x21 && $family == 0x11 && $length >= 12 or die "wrong PROXY v2 version/family";
            substr($response, 16, 4) eq pack("C4", 203, 0, 113, 77) or die "trusted PROXY v2 source address was lost";
            substr($response, 16 + $length) eq $payload or die "wrong TCP PROXY v2 payload";
        } elsif ($mode eq "v2-placement") {
            my $signature = "\r\n\r\n\0\r\nQUIT\n";
            substr($response, 0, 12) eq $signature or die "named transport did not emit a PROXY v2 signature";
            length($response) >= 28 or die "short PROXY v2 placement-control response";
            my ($version, $family, $length) = unpack("CCn", substr($response, 12, 4));
            $version == 0x21 && $family == 0x11 && $length >= 12 or die "wrong placement-control PROXY v2 version/family";
            substr($response, 16, 4) eq pack("C4", 127, 0, 0, 1) or die "placement-control PROXY v2 peer address mismatch";
            substr($response, 16 + $length) eq $payload or die "placement-control PROXY v2 payload mismatch";
        } elsif ($mode eq "v2-untrusted") {
            if (length($response)) {
                substr($response, 0, 12) eq "\r\n\r\n\0\r\nQUIT\n" or die "untrusted PROXY v2 request reached backend without an outgoing frame";
                my ($version, $family, $length) = unpack("CCn", substr($response, 12, 4));
                $version == 0x21 && $family == 0x11 && $length >= 12 or die "wrong untrusted PROXY v2 frame";
                substr($response, 16, 4) eq pack("C4", 127, 0, 0, 2) or die "untrusted PROXY v2 source replaced the actual peer address";
            }
        } elsif ($mode eq "middleware-allowed") {
            $response eq $packet or die "TCP allow-list did not echo the allowed peer payload";
        } elsif ($mode eq "middleware-denied") {
            length($response) == 0 or die "TCP allow-list forwarded a denied peer payload";
        }
    ' "$port" "$source" "$packet_mode" "$expected_source" "$output" "${6:-}" \
        > "$root/logs/review-tcp-$label.log" 2>&1 || fail "TCP probe $label did not satisfy its wire assertion"
}
udp_exchange() {
    local label=$1 port=$2 payload=$3 output="$root/logs/review-udp-$1.response"
    timeout 5 perl -MIO::Socket::INET -e '
        use strict;
        use warnings;
        my ($port, $payload, $output) = @ARGV;
        my $socket = IO::Socket::INET->new(PeerAddr => "127.0.0.1", PeerPort => $port, Proto => "udp")
            or die "socket: $!";
        $socket->send($payload) or die "send: $!";
        my $readable = "";
        vec($readable, fileno($socket), 1) = 1;
        my $ready = select($readable, undef, undef, 3);
        defined($ready) && $ready > 0 or die "UDP response timeout";
        my $response = "";
        $socket->recv($response, 2048) or die "recv: $!";
        open(my $file, ">:raw", $output) or die "open output: $!";
        print {$file} $response or die "write output: $!";
        close($file) or die "close output: $!";
        $response eq $payload or die "UDP echo mismatch";
    ' "$port" "$payload" "$output" > "$root/logs/review-udp-$label.log" 2>&1 \
        || fail "UDP router $label did not return its backend's payload"
}

check_http_routes() {
    request front 18445 sni-proof.acceptance.test /multi-entry/front
    assert_body front 'http-backend:/multi-entry/front;forwarded:'
    assert_header front 'X-Dorothy-EntryPoint: front'
    request_secure secure 18451 sni-proof.acceptance.test /multi-entry/secure
    assert_body secure 'http-backend:/multi-entry/secure;forwarded:'
    assert_header secure 'X-Dorothy-EntryPoint: secure'


    request method-get 18445 sni-proof.acceptance.test /method/dispatch GET
    assert_body method-get 'http-backend:/method/dispatch;forwarded:'
    request method-post 18445 sni-proof.acceptance.test /method/dispatch POST
    assert_body method-post 'other-backend:/method/dispatch'
    assert_header method-post 'X-Dorothy-Service: native'

    request header-target 18445 sni-proof.acceptance.test /header/dispatch GET -H 'X-Dorothy-Target: other'
    assert_body header-target 'other-backend:/header/dispatch'
    assert_header header-target 'X-Dorothy-Service: native'
    request header-default 18445 sni-proof.acceptance.test /header/dispatch
    assert_body header-default 'http-backend:/header/dispatch;forwarded:'

    request priority-zero 18445 sni-proof.acceptance.test /priority/long/selected
    assert_body priority-zero 'other-backend:/priority/long/selected'
    request priority-explicit 18445 sni-proof.acceptance.test /priority/explicit/selected
    assert_body priority-explicit 'other-backend:/priority/explicit/selected'
    assert_header priority-explicit 'X-Dorothy-Service: native'

    request chain-one 18445 sni-proof.acceptance.test /base/chain-one/leaf
    assert_body chain-one 'http-backend:/from-chain/chain-one/leaf;forwarded:'
    request chain-two 18445 sni-proof.acceptance.test /base/chain-two/leaf
    assert_body chain-two 'http-backend:/from-chain/base/chain-two/leaf;forwarded:'

    request forwarded-trusted 18445 sni-proof.acceptance.test /forwarded/trusted GET \
        -H 'X-Forwarded-For: 203.0.113.88'
    assert_body forwarded-trusted 'forwarded:203.0.113.88'
    request forwarded-untrusted 18445 sni-proof.acceptance.test /forwarded/untrusted GET \
        --interface 127.0.0.2 -H 'X-Forwarded-For: 203.0.113.88'
    assert_body forwarded-untrusted 'forwarded:127.0.0.2'

    if [[ -s "$root/review-ipv6-enabled" && "$(<"$root/review-ipv6-enabled")" == 1 ]]; then
        local body="$root/logs/review-http-forwarded-v6.body"
        local headers="$root/logs/review-http-forwarded-v6.headers"
        local status
        status=$(curl --noproxy '*' --ipv6 --interface ::1 --silent --show-error --connect-timeout 2 --max-time 8 \
            -H 'Host: sni-proof.acceptance.test' -H 'X-Forwarded-For: 2001:db8::77' \
            -D "$headers" -o "$body" -w '%{http_code}' 'http://[::1]:18182/v6-forwarded/check') \
            || fail 'IPv6 forwarded-header request could not reach its loopback listener'
        [[ "$status" == 200 ]] || fail "IPv6 forwarded-header request returned status $status"
        grep -Fq 'forwarded:2001:db8::77' "$body" || fail 'IPv6 forwarded-header trust did not preserve the trusted XFF value'
        # Real IPv6 connection (no client-supplied PROXY header). Check the backend echo,
        # including both IPv6 addresses and the actual client's ephemeral port.
        timeout 8 perl -MSocket=AF_INET6,SOCK_STREAM,SHUT_WR,inet_pton,pack_sockaddr_in6,unpack_sockaddr_in6 -e '
            use strict; use warnings;
            my $loop = inet_pton(AF_INET6, "::1");
            socket(my $s, AF_INET6, SOCK_STREAM, 0) or die "socket: $!";
            connect($s, pack_sockaddr_in6(19017, $loop)) or die "connect: $!";
            my ($port, $source) = unpack_sockaddr_in6(getsockname($s));
            my $payload = "tcp6-review-$$";
            syswrite($s, $payload) == length($payload) or die "short write";
            shutdown($s, SHUT_WR) or die "shutdown: $!";
            my $wire = do { local $/; <$s> };
            defined($wire) && length($wire) >= 52 or die "missing TCP6 frame";
            substr($wire,0,12) eq "\r\n\r\n\0\r\nQUIT\n" or die "missing signature";
            my ($v,$f,$n) = unpack("CCn", substr($wire,12,4));
            $v == 0x21 && $f == 0x21 && $n >= 36 or die "not v2 TCP6";
            substr($wire,16,32) eq $source.$loop or die "incorrect TCP6 addresses";
            substr($wire,48,4) eq pack("nn",$port,19017) or die "incorrect TCP6 ports";
            substr($wire,16+$n) eq $payload or die "incorrect TCP6 payload";
        ' || fail 'Named transport did not preserve the actual loopback IPv6 tuple'
        printf 'IPv6 forwarded header and backend-observed TCP6 PROXY v2 tuple/payload passed.\n' | tee "$root/logs/review-ipv6-evidence.log"
    else
        printf 'IPv6 loopback unavailable; IPv6 forwarded-header probe not configured.\n' > "$root/logs/review-ipv6-evidence.log"
    fi
}

case "$mode" in
    no-tcp)
        if nc -z -w 1 127.0.0.1 19012 > "$root/logs/review-no-tcp-port.log" 2>&1; then
            fail 'TCP middleware listener remained bound after its review router was disabled'
        fi
        request no-tcp-http 18445 sni-proof.acceptance.test /multi-entry/no-tcp
        assert_body no-tcp-http 'http-backend:/multi-entry/no-tcp;forwarded:'
        printf 'TCP listener removal was detected while HTTP remained healthy.\n'
        exit 0
        ;;
    proxy-placement)
        tcp_exchange placement-control 19016 127.0.0.1 v2-placement 127.0.0.1
        printf 'Named-transport PROXY v2 placement control passed.\n'
        exit 0
        ;;
    udp-conflict-control)
        nonce=$(openssl rand -hex 8)
        udp_exchange conflict-control 19015 "$nonce"
        for _ in $(seq 1 30); do
            grep -aFq -- "$nonce" "$root/logs/udp-echo.log" && break
            sleep 0.2
        done
        grep -aFq -- "$nonce" "$root/logs/udp-echo.log" \
            || fail 'Single UDP ownership control did not reach its declared backend'
        printf 'Single UDP ownership control passed.\n'
        exit 0
        ;;
    positive)
        check_http_routes
        (
            allowed=$(openssl rand -hex 12); denied=$(openssl rand -hex 12)
            cap="$root/logs/middleware-backend.pcap"; stats="$root/logs/middleware-capture.log"
            tcpdump --immediate-mode -U -i lo -s 0 -w - 'tcp dst port 19001' > "$cap" 2> "$stats" &
            pid=$!; trap 'kill -INT "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :' EXIT
            for _ in $(seq 1 40); do grep -q 'listening on' "$stats" && break; sleep .05; done
            grep -q 'listening on' "$stats" || fail 'backend capture unavailable'
            tcp_exchange middleware-allowed 19012 127.0.0.1 middleware-allowed '' "$allowed"
            cursor=$(journalctl -u keroosha-traefik.service -n 1 --show-cursor -o cat --no-pager | sed -n 's/^-- cursor: //p')
            [[ -n $cursor ]] || fail 'missing pre-connect journal cursor'
            tcp_exchange middleware-denied 19012 127.0.0.2 middleware-denied '' "$denied"
            peer=$(<"$root/logs/review-tcp-middleware-denied.bin.peer")
            [[ $peer =~ ^127\.0\.0\.2:[0-9]+$ ]] || fail 'unexpected connected peer'
            journalctl --sync
            journalctl -u keroosha-traefik.service --after-cursor="$cursor" -o cat --no-pager |
                jq -Rsce --arg peer "$peer" '[split("\n")[] | fromjson? | select(.middlewareName=="review-tcp-loopback-only@file" and .middlewareType=="IPAllowListerTCP" and .error==("\""+$peer+"\" matched none of the trusted IPs")) | {middlewareName,middlewareType,error}] | select(length>0)' > "$root/logs/middleware-deny.json" || fail 'missing fresh tuple-specific deny'
            sleep 1
            kill -INT "$pid"; wait "$pid"; trap - EXIT
            grep -Fxq '0 packets dropped by kernel' "$stats" || fail 'incomplete backend capture'
            tcpdump -nn -A -r "$cap" > "$root/logs/middleware-backend.txt" 2>/dev/null
            grep -Fq "$allowed" "$root/logs/middleware-backend.txt" || fail 'allowed nonce missing from backend'
            if grep -Fq "$denied" "$root/logs/middleware-backend.txt"; then fail 'denied nonce reached backend'; fi
        )
        tcp_exchange proxy-v1-trusted 19010 127.0.0.1 v1-trusted 203.0.113.55
        tcp_exchange proxy-v1-untrusted 19010 127.0.0.2 v1-untrusted 127.0.0.2
        tcp_exchange proxy-v2-trusted 19011 127.0.0.1 v2-trusted 203.0.113.77
        tcp_exchange proxy-v2-untrusted 19011 127.0.0.2 v2-untrusted 127.0.0.2

        # socat's hex dump renders 16 ASCII bytes per row. Match the complete random datagram.
        udp_a=$(openssl rand -hex 8)
        udp_b=$(openssl rand -hex 8)
        udp_exchange a 19013 "$udp_a"
        udp_exchange b 19014 "$udp_b"
        for _ in $(seq 1 30); do
            if grep -aFq -- "$udp_a" "$root/logs/udp-echo.log" \
               && grep -aFq -- "$udp_b" "$root/logs/review-udp-b.log"; then
                break
            fi
            sleep 0.2
        done
        grep -aFq -- "$udp_a" "$root/logs/udp-echo.log" || fail 'UDP router A did not reach its distinct backend'
        grep -aFq -- "$udp_b" "$root/logs/review-udp-b.log" || fail 'UDP router B did not reach its distinct backend'
        if grep -aFq -- "$udp_b" "$root/logs/udp-echo.log" || grep -aFq -- "$udp_a" "$root/logs/review-udp-b.log"; then
            fail 'A review datagram also reached the other backend'
        fi

        printf 'HTTP/TCP/UDP route and backend assertions passed.\n'
        ;;
esac
