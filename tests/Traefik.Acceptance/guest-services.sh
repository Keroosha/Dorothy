#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 1 ]]; then
    printf 'Usage: guest-services.sh /var/tmp/dorothy-traefik-acceptance.XXXXXXXX\n' >&2
    exit 2
fi
root=$(realpath -e -- "$1")
case "$root" in
    /var/tmp/dorothy-traefik-acceptance.*) ;;
    *) printf 'Refusing to configure outside the private guest temp root.\n' >&2; exit 2 ;;
esac
[[ -d "$root" && -x "$root/bin/pebble" && -x "$root/bin/otelcol-contrib" && -x "$root/bin/traefik" \
    && -x "$root/guest-local-issuers.sh" ]] || {
    printf 'Required pinned binaries or the local issuer guard are missing from the guest temp root.\n' >&2
    exit 2
}
[[ -f "$root/dns/tsig-secret" && -f "$root/certs/pebble.minica.pem" && -f "$root/certs/cert.pem" && -f "$root/certs/key.pem" ]] || {
    printf 'Required private fixture files are missing from the guest temp root.\n' >&2
    exit 2
}
if systemctl is-active --quiet keroosha-traefik.service; then
    printf 'Refusing barrier preparation while the managed Traefik service is active.\n' >&2
    exit 1
fi

install -d -m 755 "$root/certs" "$root/config" "$root/logs" "$root/units" "$root/dns"
chmod 755 "$root"
printf '%s\n' dorothy-traefik-acceptance-guest-v1 > "$root/.owner"
chmod 600 "$root/.owner"
chmod 700 "$root/bin" "$root/certs" "$root/config" "$root/logs" "$root/units" "$root/dns"
chmod 755 "$root/certs"
systemctl disable --now nginx.service bind9.service >/dev/null 2>&1 || true
systemctl disable --now \
    dorothy-traefik-acceptance-dns.service \
    dorothy-traefik-acceptance-pebble.service \
    dorothy-traefik-acceptance-pebble-rotated.service \
    dorothy-traefik-acceptance-otelcol.service \
    dorothy-traefik-acceptance-backends.service \
    dorothy-traefik-acceptance-tcp.service \
    dorothy-traefik-acceptance-udp.service >/dev/null 2>&1 || true

secret=$(<"$root/dns/tsig-secret")
cat > "$root/dns/tsig.key" <<EOF
key "traefik-acceptance." {
    algorithm hmac-sha256;
    secret "$secret";
};
EOF
cat > "$root/dns/named.conf" <<EOF
include "$root/dns/tsig.key";
options {
    directory "$root/dns";
    listen-on port 1053 { 127.0.0.1; };
    listen-on-v6 { none; };
    recursion no;
    allow-query { 127.0.0.1; };
    allow-transfer { none; };
    dnssec-validation no;
};
zone "acceptance.test" IN {
    type master;
    file "db.acceptance.test";
    allow-update { key "traefik-acceptance."; };
};
EOF
cat > "$root/dns/db.acceptance.test" <<'EOF'
$ORIGIN acceptance.test.
$TTL 30
@ IN SOA ns.acceptance.test. hostmaster.acceptance.test. (
    2026112601 60 60 604800 30
)
@ IN NS ns.acceptance.test.
ns IN A 127.0.0.1
shop IN A 127.0.0.1
backend IN A 127.0.0.1
tcp IN A 127.0.0.1
mtls IN A 127.0.0.1
http01 IN A 127.0.0.1
tlsalpn IN A 127.0.0.1
EOF
chown -R bind:bind "$root/dns"
chmod 750 "$root/dns"
chmod 640 "$root/dns/tsig.key" "$root/dns/named.conf" "$root/dns/db.acceptance.test"
named-checkconf "$root/dns/named.conf" > "$root/logs/named-checkconf.log" 2>&1
named-checkzone acceptance.test "$root/dns/db.acceptance.test" > "$root/logs/named-checkzone.log" 2>&1

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$root/certs/upstream-ca.key" -out "$root/certs/upstream-ca.pem" \
    -subj '/CN=Dorothy Traefik Acceptance Backend CA' -days 2 \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    > "$root/logs/pki.log" 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$root/certs/upstream-server.key" -out "$root/certs/upstream-server.csr" \
    -subj '/CN=backend.acceptance.test' -addext 'subjectAltName=DNS:backend.acceptance.test,IP:127.0.0.1' \
    >> "$root/logs/pki.log" 2>&1
cat > "$root/certs/upstream-server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:backend.acceptance.test,IP:127.0.0.1
EOF
openssl x509 -req -in "$root/certs/upstream-server.csr" \
    -CA "$root/certs/upstream-ca.pem" -CAkey "$root/certs/upstream-ca.key" -CAcreateserial \
    -out "$root/certs/upstream-server.pem" -days 2 -sha256 -extfile "$root/certs/upstream-server.ext" \
    >> "$root/logs/pki.log" 2>&1

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$root/certs/client-ca.key" -out "$root/certs/client-ca.pem" \
    -subj '/CN=Dorothy Traefik Acceptance Client CA' -days 2 \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    >> "$root/logs/pki.log" 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$root/certs/client.key" -out "$root/certs/client.csr" \
    -subj '/CN=acceptance-client' \
    >> "$root/logs/pki.log" 2>&1
cat > "$root/certs/client.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=DNS:acceptance-client.test
EOF
openssl x509 -req -in "$root/certs/client.csr" \
    -CA "$root/certs/client-ca.pem" -CAkey "$root/certs/client-ca.key" -CAcreateserial \
    -out "$root/certs/client.pem" -days 2 -sha256 -extfile "$root/certs/client.ext" \
    >> "$root/logs/pki.log" 2>&1
openssl verify -CAfile "$root/certs/upstream-ca.pem" "$root/certs/upstream-server.pem" > "$root/logs/pki-verify.log" 2>&1
openssl verify -CAfile "$root/certs/client-ca.pem" "$root/certs/client.pem" >> "$root/logs/pki-verify.log" 2>&1
chmod 644 "$root/certs/pebble.minica.pem" "$root/certs/cert.pem" \
    "$root/certs/upstream-ca.pem" "$root/certs/upstream-server.pem" "$root/certs/client-ca.pem" "$root/certs/client.pem"
chmod 600 "$root/certs/key.pem" "$root/certs/upstream-ca.key" "$root/certs/upstream-server.key" \
    "$root/certs/client-ca.key" "$root/certs/client.key" "$root/dns/tsig-secret"

install -o root -g root -m 644 "$root/certs/pebble.minica.pem" \
    /usr/local/share/ca-certificates/dorothy-traefik-acceptance-pebble.crt
update-ca-certificates > "$root/logs/ca-install.log" 2>&1
openssl verify -CAfile "$root/certs/pebble.minica.pem" "$root/certs/cert.pem" > "$root/logs/pebble-server-cert.log" 2>&1

cat > "$root/config/pebble.json" <<EOF
{
  "pebble": {
    "listenAddress": "127.0.0.1:14000",
    "managementListenAddress": "127.0.0.1:15000",
    "certificate": "$root/certs/cert.pem",
    "privateKey": "$root/certs/key.pem",
    "httpPort": 5002,
    "tlsPort": 5001,
    "keyAlgorithm": "ecdsa",
    "profiles": {
      "default": {
        "description": "long lifecycle across issuer reboot",
        "validityPeriod": 14400
      },
      "renewal": {
        "description": "short-lived isolated acceptance issuance",
        "validityPeriod": 1300
      }
    }
  }
}
EOF
cat > "$root/config/pebble-rotated.json" <<EOF
{
  "pebble": {
    "listenAddress": "127.0.0.1:14001",
    "managementListenAddress": "127.0.0.1:15001",
    "certificate": "$root/certs/cert.pem",
    "privateKey": "$root/certs/key.pem",
    "httpPort": 5004,
    "tlsPort": 5003,
    "keyAlgorithm": "ecdsa",
    "profiles": {
      "default": {
        "description": "rotated isolated acceptance issuance",
        "validityPeriod": 14400
      }
    }
  }
}
EOF
cat > "$root/config/otelcol.yaml" <<EOF
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:4317
      http:
        endpoint: 127.0.0.1:4318
exporters:
  debug:
    verbosity: detailed
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [debug]
    metrics:
      receivers: [otlp]
      exporters: [debug]
    logs:
      receivers: [otlp]
      exporters: [debug]
EOF
cat > "$root/config/nginx.conf" <<EOF
pid $root/nginx.pid;
error_log $root/logs/nginx.error.log;
events {}
http {
    access_log $root/logs/nginx.access.log;
    server {
        listen 127.0.0.1:8080;
        server_name _;
        location = /health { default_type text/plain; return 200 "http-backend-ready\\n"; }
        location / { default_type text/plain; return 200 "http-backend:\$request_uri;forwarded:\$http_x_forwarded_for\\n"; }
    }
    server {
        listen 127.0.0.1:8082;
        server_name _;
        location = /health { default_type text/plain; return 200 "other-backend-ready\\n"; }
        location / { default_type text/plain; return 200 "other-backend:\$request_uri\\n"; }
    }
    server {
        listen 127.0.0.1:8081 ssl;
        server_name backend.acceptance.test;
        ssl_certificate $root/certs/upstream-server.pem;
        ssl_certificate_key $root/certs/upstream-server.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        location = /health { default_type text/plain; return 200 "tls-backend-ready\\n"; }
        location / { default_type text/plain; return 200 "tls-backend:\$request_uri\\n"; }
    }
}
EOF

cat > "$root/units/dorothy-traefik-acceptance-dns.service" <<EOF
[Unit]
Description=Dorothy Traefik acceptance RFC2136 DNS fixture
After=network.target

[Service]
Type=simple
User=bind
Group=bind
AppArmorProfile=unconfined
ExecStart=/usr/sbin/named -g -c $root/dns/named.conf
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
cat > "$root/units/dorothy-traefik-acceptance-pebble.service" <<EOF
[Unit]
Description=Dorothy Traefik acceptance Pebble ACME CA
After=network.target

[Service]
Type=simple
Environment=PEBBLE_VA_NOSLEEP=1
ExecStart=$root/bin/pebble -config $root/config/pebble.json -dnsserver 127.0.0.1:1053
Restart=on-failure
RestartSec=2
StandardOutput=append:$root/logs/pebble.log
StandardError=append:$root/logs/pebble.log

[Install]
WantedBy=multi-user.target
EOF
cat > "$root/units/dorothy-traefik-acceptance-pebble-rotated.service" <<EOF
[Unit]
Description=Dorothy Traefik acceptance rotated Pebble ACME CA
After=network.target

[Service]
Type=simple
Environment=PEBBLE_VA_NOSLEEP=1
ExecStart=$root/bin/pebble -config $root/config/pebble-rotated.json -dnsserver 127.0.0.1:1053
Restart=on-failure
RestartSec=2
StandardOutput=append:$root/logs/pebble-rotated.log
StandardError=append:$root/logs/pebble-rotated.log

[Install]
WantedBy=multi-user.target
EOF
cat > "$root/units/dorothy-traefik-acceptance-otelcol.service" <<EOF
[Unit]
Description=Dorothy Traefik acceptance OpenTelemetry collector
After=network.target

[Service]
Type=simple
ExecStart=$root/bin/otelcol-contrib --config=$root/config/otelcol.yaml
Restart=on-failure
RestartSec=2
StandardOutput=append:$root/logs/otelcol.log
StandardError=append:$root/logs/otelcol.log

[Install]
WantedBy=multi-user.target
EOF
cat > "$root/units/dorothy-traefik-acceptance-backends.service" <<EOF
[Unit]
Description=Dorothy Traefik acceptance HTTP backends
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/nginx -c $root/config/nginx.conf -g "daemon off;"
Restart=on-failure
RestartSec=2
StandardOutput=append:$root/logs/nginx.stdout.log
StandardError=append:$root/logs/nginx.stderr.log

[Install]
WantedBy=multi-user.target
EOF
cat > "$root/units/dorothy-traefik-acceptance-tcp.service" <<EOF
[Unit]
Description=Dorothy Traefik acceptance raw TCP echo backend
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/socat -v -x TCP4-LISTEN:19001,bind=127.0.0.1,reuseaddr,fork EXEC:/bin/cat
Restart=always
RestartSec=1
StandardOutput=append:$root/logs/tcp-echo.log
StandardError=append:$root/logs/tcp-echo.log

[Install]
WantedBy=multi-user.target
EOF
cat > "$root/units/dorothy-traefik-acceptance-udp.service" <<EOF
[Unit]
Description=Dorothy Traefik acceptance UDP echo backend
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/socat -v -x UDP4-RECVFROM:19002,bind=127.0.0.1,reuseaddr,fork EXEC:/bin/cat
Restart=always
RestartSec=1
StandardOutput=append:$root/logs/udp-echo.log
StandardError=append:$root/logs/udp-echo.log

[Install]
WantedBy=multi-user.target
EOF
cat > "$root/units/dorothy-traefik-acceptance-local-issuer-check.service" <<EOF
[Unit]
Description=Dorothy fixture guard for the managed Traefik ACME issuer
Before=keroosha-traefik.service

[Service]
Type=oneshot
RemainAfterExit=no
TimeoutStartSec=20s
ExecStart=/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C /bin/bash $root/guest-local-issuers.sh check /etc/keroosha-iac/traefik/static.yml keroosha-traefik.service
EOF

chmod 644 "$root/config/pebble.json" "$root/config/pebble-rotated.json" "$root/config/otelcol.yaml" "$root/config/nginx.conf" "$root/units/"*.service
for unit in "$root/units/"*.service; do
    install -m 644 "$unit" "/etc/systemd/system/$(basename "$unit")"
done

# Add an ordered, required oneshot without changing the product-owned unit or using a drop-in.
traefik_requires=/etc/systemd/system/keroosha-traefik.service.requires
issuer_guard_unit=dorothy-traefik-acceptance-local-issuer-check.service
[[ ! -L "$traefik_requires" ]] || {
    printf 'Refusing to follow a symlink for the managed Traefik requirement directory.\n' >&2
    exit 1
}
install -d -m 755 "$traefik_requires"
issuer_link="$traefik_requires/$issuer_guard_unit"
if [[ -e "$issuer_link" || -L "$issuer_link" ]]; then
    [[ -L "$issuer_link" && $(readlink -- "$issuer_link") == "/etc/systemd/system/$issuer_guard_unit" ]] || {
        printf 'Refusing to replace an unrelated Traefik unit requirement.\n' >&2
        exit 1
    }
else
    ln -s "/etc/systemd/system/$issuer_guard_unit" "$issuer_link"
fi

# Use an active-exited target: start/restart returns only after it writes its execution marker.
# The required issuer oneshot exits inactive; every target restart must run it again.
guard_valid="$root/config/issuer-guard-valid.json"
guard_acme="$root/config/issuer-guard-acme.json"
guard_systemd_static="$root/config/issuer-guard-systemd-static.json"
guard_bad="$root/config/issuer-guard-bad.json"
guard_missing="$root/config/issuer-guard-missing.json"
guard_duplicate="$root/config/issuer-guard-duplicate.json"
guard_case="$root/config/issuer-guard-case.json"
guard_dns_fallback="$root/config/issuer-guard-dns-fallback.json"
guard_dns_provider="$root/config/issuer-guard-dns-provider.json"
guard_http="$root/config/issuer-guard-http-listener.json"
guard_tls="$root/config/issuer-guard-tls-listener.json"
guard_non_acme="$root/config/issuer-guard-non-acme.json"
guard_alias="$root/config/issuer-guard-alias.yml"
guard_dns_env="$root/config/issuer-guard-dns.env"
guard_dns_public="$root/config/issuer-guard-dns-public.env"
guard_dns_proxy="$root/config/issuer-guard-dns-proxy.env"
printf '%s\n' '{"entryPoints":{},"providers":{}}' > "$guard_valid"
cat > "$guard_acme" <<'JSON'
{"entryPoints":{"http01":{"address":"127.0.0.1:5002"},"tlsalpn":{"address":"127.0.0.1:5001"}},"certificatesResolvers":{"dns":{"acme":{"caServer":"https://localhost:14000/dir","dnsChallenge":{"provider":"dnsupdate","resolvers":["127.0.0.1:1053"]}}},"http":{"acme":{"caServer":"https://localhost:14000/dir","httpChallenge":{"entryPoint":"http01"}}},"tls":{"acme":{"caServer":"https://localhost:14001/dir","tlsChallenge":{}}}}}
JSON
cp "$guard_acme" "$guard_systemd_static"
"$root/guest-local-issuers.sh" check "$guard_valid" > "$root/logs/issuer-guard-static-valid.log"
"$root/guest-local-issuers.sh" check "$guard_acme" > "$root/logs/issuer-guard-static-acme.log"
jq '.certificatesResolvers.dns.acme.caServer="https://example.invalid/dir"' "$guard_acme" > "$guard_bad"
jq 'del(.certificatesResolvers.dns.acme.caServer)' "$guard_acme" > "$guard_missing"
jq '(.certificatesResolvers.dns.acme.caServer) as $server
    | del(.certificatesResolvers.dns.acme.caServer)
    | .certificatesResolvers.dns.acme.CaServer=$server' "$guard_acme" > "$guard_case"
jq '.certificatesResolvers.dns.acme.dnsChallenge.resolvers += ["192.0.2.53:53"]' "$guard_acme" > "$guard_dns_fallback"
jq '.certificatesResolvers.dns.acme.dnsChallenge.provider="cloudflare"' "$guard_acme" > "$guard_dns_provider"
jq '.certificatesResolvers.http.acme.httpChallenge.entryPoint="web"' "$guard_acme" > "$guard_http"
jq '.certificatesResolvers.tls.acme.tlsChallenge.entryPoint="web"' "$guard_acme" > "$guard_tls"
printf '%s\n' '{"entryPoints":{"http01":{"address":"127.0.0.1:5002/tcp"},"tlsalpn":{"address":"127.0.0.1:5001/tcp"}},"certificatesResolvers":{"duplicate":{"acme":{"caServer":"https://localhost:14000/dir","caServer":"https://localhost:14001/dir","dnsChallenge":{"provider":"dnsupdate","resolvers":["127.0.0.1:1053"]}}}}}' > "$guard_duplicate"
printf '%s\n' '{"certificatesResolvers":{"non-acme":{}}}' > "$guard_non_acme"
printf '%s\n' 'certificatesResolvers: &issuers {}' > "$guard_alias"
for rejected in "$guard_bad" "$guard_missing" "$guard_duplicate" "$guard_case" \
    "$guard_dns_fallback" "$guard_dns_provider" "$guard_http" "$guard_tls" "$guard_non_acme" "$guard_alias"; do
    if "$root/guest-local-issuers.sh" check "$rejected" >/dev/null 2>&1; then
        printf 'Local issuer guard accepted an invalid resolver fixture: %s\n' "${rejected##*/}" >&2
        exit 1
    fi
done
cat > "$guard_dns_env" <<'ENV'
DNSUPDATE_NAMESERVER="127.0.0.1:1053"
DNSUPDATE_ZONES="acceptance.test"
DNSUPDATE_TSIG_KEY="traefik-acceptance."
DNSUPDATE_TSIG_SECRET="fixture-only"
DNSUPDATE_TSIG_ALGORITHM="hmac-sha256."
ENV
printf '%s\n' 'DNSUPDATE_NAMESERVER="192.0.2.53:53"' 'DNSUPDATE_ZONES="acceptance.test"' > "$guard_dns_public"
printf '%s\n' 'DNSUPDATE_NAMESERVER="127.0.0.1:1053"' 'DNSUPDATE_ZONES="acceptance.test"' \
    'HTTPS_PROXY="http://proxy.invalid:8080"' > "$guard_dns_proxy"
"$root/guest-local-issuers.sh" check-env-file "$guard_dns_env" > "$root/logs/issuer-guard-dns-env.log"
for rejected in "$guard_dns_public" "$guard_dns_proxy"; do
    if "$root/guest-local-issuers.sh" check-env-file "$rejected" >/dev/null 2>&1; then
        printf 'Local issuer guard accepted an unsafe DNS environment fixture: %s\n' "${rejected##*/}" >&2
        exit 1
    fi
done

test_check_unit=dorothy-traefik-acceptance-issuer-guard-test-check.service
test_target_unit=dorothy-traefik-acceptance-issuer-guard-test.service
test_check_path="/run/systemd/system/$test_check_unit"
test_target_path="/run/systemd/system/$test_target_unit"
test_requires="$test_target_path.requires"
test_check_log="$root/logs/issuer-guard-systemd-check.log"
test_run_log="$root/logs/issuer-guard-systemd-target.log"
test_attempt_log="$root/logs/issuer-guard-systemd-target-attempts.log"
test_target_script="$root/units/issuer-guard-test-target.sh"
cat > "$test_target_script" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' attempted >> "$test_attempt_log"
check_count=\$(grep -cFx 'static Traefik issuer configuration accepted' "$test_check_log" || true)
run_count=\$(grep -cFx started "$test_run_log" || true)
[[ "\$check_count" -eq \$((run_count + 1)) ]]
printf '%s\n' started >> "$test_run_log"
EOF
cat > "$root/units/$test_check_unit" <<EOF
[Unit]
Description=Temporary fixture-only issuer guard ordering check
Before=$test_target_unit

[Service]
Type=oneshot
TimeoutStartSec=20s
ExecStart=/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C /bin/bash $root/guest-local-issuers.sh check $guard_systemd_static
RemainAfterExit=no
StandardOutput=append:$test_check_log
StandardError=append:$test_check_log
EOF
cat > "$root/units/$test_target_unit" <<EOF
[Unit]
Description=Temporary target for verifying required issuer checks before execution

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash $test_target_script
EOF
install -d -m 755 /run/systemd/system
install -m 644 "$root/units/$test_check_unit" "$test_check_path"
install -m 644 "$root/units/$test_target_unit" "$test_target_path"
install -d -m 755 "$test_requires"
ln -s "$test_check_path" "$test_requires/$test_check_unit"
issuer_guard_test_cleanup() {
    systemctl stop "$test_target_unit" >/dev/null 2>&1 || true
    rm -f -- "$test_requires/$test_check_unit" "$test_check_path" "$test_target_path"
    rm -f -- "$test_target_script"
    rmdir -- "$test_requires" 2>/dev/null || true
    systemctl daemon-reload >/dev/null 2>&1 || true
}
trap issuer_guard_test_cleanup EXIT
systemctl daemon-reload
: > "$test_check_log"
: > "$test_run_log"
: > "$test_attempt_log"
systemctl start "$test_target_unit" > "$root/logs/issuer-guard-systemd-start.log" 2>&1
[[ $(grep -cFx 'static Traefik issuer configuration accepted' "$test_check_log" || true) == 1 \
    && $(grep -cFx started "$test_run_log" || true) == 1 \
    && $(grep -cFx attempted "$test_attempt_log" || true) == 1 ]] || {
    printf 'Required issuer check did not run before the fixture target start.\n' >&2
    exit 1
}
systemctl restart "$test_target_unit" > "$root/logs/issuer-guard-systemd-restart.log" 2>&1
[[ $(grep -cFx 'static Traefik issuer configuration accepted' "$test_check_log" || true) == 2 \
    && $(grep -cFx started "$test_run_log" || true) == 2 \
    && $(grep -cFx attempted "$test_attempt_log" || true) == 2 ]] || {
    printf 'Required issuer check did not rerun before the fixture target restart.\n' >&2
    exit 1
}
systemctl stop "$test_target_unit" > "$root/logs/issuer-guard-systemd-stop.log" 2>&1
[[ $(grep -cFx 'static Traefik issuer configuration accepted' "$test_check_log" || true) == 2 \
    && $(grep -cFx started "$test_run_log" || true) == 2 \
    && $(grep -cFx attempted "$test_attempt_log" || true) == 2 ]] || {
    printf 'Stopping the fixture target unexpectedly reran the issuer check.\n' >&2
    exit 1
}
systemctl start "$test_target_unit" > "$root/logs/issuer-guard-systemd-start-again.log" 2>&1
[[ $(grep -cFx 'static Traefik issuer configuration accepted' "$test_check_log" || true) == 3 \
    && $(grep -cFx started "$test_run_log" || true) == 3 \
    && $(grep -cFx attempted "$test_attempt_log" || true) == 3 ]] || {
    printf 'Required issuer check did not rerun before the fixture target start.\n' >&2
    exit 1
}
jq '.certificatesResolvers.dns.acme.caServer="https://localhost:14999/dir"' "$guard_acme" > "$guard_systemd_static"
if systemctl restart "$test_target_unit" > "$root/logs/issuer-guard-systemd-reject.log" 2>&1; then
    printf 'Fixture target restarted despite a rejected local ACME issuer.\n' >&2
    exit 1
fi
if systemctl is-active --quiet "$test_target_unit" \
    || [[ $(grep -cFx started "$test_run_log" || true) != 3 \
        || $(grep -cFx attempted "$test_attempt_log" || true) != 3 ]]; then
    printf 'Failed issuer check did not block fixture target execution.\n' >&2
    exit 1
fi
cp "$guard_acme" "$guard_systemd_static"
systemctl restart "$test_target_unit" > "$root/logs/issuer-guard-systemd-recover.log" 2>&1
[[ $(grep -cFx 'static Traefik issuer configuration accepted' "$test_check_log" || true) == 4 \
    && $(grep -cFx started "$test_run_log" || true) == 4 \
    && $(grep -cFx attempted "$test_attempt_log" || true) == 4 ]] || {
    printf 'Required issuer check did not recover on the next fixture target start.\n' >&2
    exit 1
}
issuer_guard_test_cleanup
trap - EXIT

systemctl daemon-reload
systemctl enable --now \
    dorothy-traefik-acceptance-pebble.service \
    dorothy-traefik-acceptance-pebble-rotated.service > "$root/logs/barrier-pebble-start.log" 2>&1

directory_ready=false
for _ in $(seq 1 90); do
    if env -i PATH=/usr/bin:/bin curl --disable --noproxy '*' --connect-timeout 2 --max-time 4 \
        --fail --silent --show-error --cacert "$root/certs/pebble.minica.pem" \
        https://localhost:14000/dir -o "$root/logs/pebble-directory.json" 2>/dev/null \
       && env -i PATH=/usr/bin:/bin curl --disable --noproxy '*' --connect-timeout 2 --max-time 4 \
        --fail --silent --show-error --cacert "$root/certs/pebble.minica.pem" \
        https://localhost:14001/dir -o "$root/logs/pebble-rotated-directory.json" 2>/dev/null; then
        directory_ready=true
        break
    fi
    sleep 1
done
[[ $directory_ready == true ]] || {
    printf 'Loopback Pebble directory endpoints did not become ready.\n' >&2
    exit 1
}
env -i PATH=/usr/bin:/bin curl --disable --noproxy '*' --connect-timeout 2 --max-time 4 \
    --fail --silent --show-error --cacert "$root/certs/pebble.minica.pem" \
    https://localhost:15000/roots/0 -o "$root/certs/pebble-issued-root.pem"
env -i PATH=/usr/bin:/bin curl --disable --noproxy '*' --connect-timeout 2 --max-time 4 \
    --fail --silent --show-error --cacert "$root/certs/pebble.minica.pem" \
    https://localhost:15001/roots/0 -o "$root/certs/pebble-rotated-issued-root.pem"
openssl x509 -in "$root/certs/pebble-issued-root.pem" -noout -subject > "$root/logs/pebble-root.subject"
openssl x509 -in "$root/certs/pebble-rotated-issued-root.pem" -noout -subject > "$root/logs/pebble-rotated-root.subject"

{
    printf 'Debian '; cat /etc/debian_version
    staged_traefik_sha=$(sha256sum "$root/bin/traefik" | awk '{ print $1 }')
    [[ "$staged_traefik_sha" == 86ee2b427888d24475051fc5f5bcca94cf4fa033b6fa54205b7eb0de6914f31e ]] || {
        printf 'Staged Traefik executable digest does not match the pinned fixture.\n' >&2
        exit 1
    }
    printf 'Staged only: Traefik 3.7.16, verified SHA-256=%s; executable not run before clearance.\n' "$staged_traefik_sha"
    "$root/bin/pebble" -version
    printf 'Both local Pebble ACME directory endpoints and root snapshots were read over loopback.\n'
    printf 'The guest-only required issuer oneshot passed valid, invalid and restart-gating checks against a dummy unit.\n'
    printf 'Traefik was not run; DNS, telemetry, HTTP/TLS backends, TCP and UDP services remain stopped.\n'
    printf 'No DNS updates or data-plane or telemetry acceptance probes were performed during barrier preparation.\n'
} > "$root/logs/barrier-fixtures.log" 2>&1
printf 'Loopback Pebble CAs are ready; Traefik and all non-CA fixtures remain off pending approval.\n'
