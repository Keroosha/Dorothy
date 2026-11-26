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
[[ -d "$root" && -x "$root/bin/pebble" && -x "$root/bin/otelcol-contrib" && -x "$root/bin/traefik" ]] || {
    printf 'Required pinned binaries are missing from the guest temp root.\n' >&2
    exit 2
}
[[ -f "$root/dns/tsig-secret" && -f "$root/certs/pebble.minica.pem" && -f "$root/certs/cert.pem" && -f "$root/certs/key.pem" ]] || {
    printf 'Required private fixture files are missing from the guest temp root.\n' >&2
    exit 2
}

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
        "validityPeriod": 1300
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
After=network.target dorothy-traefik-acceptance-dns.service
Requires=dorothy-traefik-acceptance-dns.service

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
After=network.target dorothy-traefik-acceptance-dns.service
Requires=dorothy-traefik-acceptance-dns.service

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
chmod 644 "$root/config/pebble.json" "$root/config/pebble-rotated.json" "$root/config/otelcol.yaml" "$root/config/nginx.conf" "$root/units/"*.service
for unit in "$root/units/"*.service; do
    install -m 644 "$unit" "/etc/systemd/system/$(basename "$unit")"
done
systemctl daemon-reload
systemctl enable --now \
    dorothy-traefik-acceptance-dns.service \
    dorothy-traefik-acceptance-pebble.service \
    dorothy-traefik-acceptance-pebble-rotated.service \
    dorothy-traefik-acceptance-otelcol.service \
    dorothy-traefik-acceptance-backends.service \
    dorothy-traefik-acceptance-tcp.service \
    dorothy-traefik-acceptance-udp.service > "$root/logs/systemd-start.log" 2>&1

for _ in $(seq 1 90); do
    if dig +time=1 +tries=1 @127.0.0.1 -p 1053 acceptance.test SOA >/dev/null 2>&1 \
       && curl --fail --silent --show-error --cacert "$root/certs/pebble.minica.pem" \
            https://localhost:14000/dir -o "$root/logs/pebble-directory.json" 2>/dev/null \
       && curl --fail --silent --show-error --cacert "$root/certs/pebble.minica.pem" \
            https://localhost:14001/dir -o "$root/logs/pebble-rotated-directory.json" 2>/dev/null \
       && nc -z -w 1 127.0.0.1 4318; then
        break
    fi
    sleep 1
done
curl --fail --silent --show-error --cacert "$root/certs/pebble.minica.pem" \
    https://localhost:15001/roots/0 -o "$root/certs/pebble-rotated-issued-root.pem"
openssl x509 -in "$root/certs/pebble-rotated-issued-root.pem" -noout -subject > "$root/logs/pebble-rotated-root.subject"

dns_probe=_preflight.acceptance.test.
printf 'server 127.0.0.1 1053\nzone acceptance.test.\nupdate add %s 30 TXT "rfc2136-ready"\nsend\n' "$dns_probe" \
    | nsupdate -k "$root/dns/tsig.key" > "$root/logs/dns-update.log" 2>&1
dns_observation=$(dig +time=2 +tries=1 +short @127.0.0.1 -p 1053 TXT "$dns_probe")
[[ "$dns_observation" == '"rfc2136-ready"' ]] || { printf 'RFC2136 TSIG update was not visible in the isolated DNS zone.\n' >&2; exit 1; }
printf 'server 127.0.0.1 1053\nzone acceptance.test.\nupdate delete %s TXT\nsend\n' "$dns_probe" \
    | nsupdate -k "$root/dns/tsig.key" >> "$root/logs/dns-update.log" 2>&1

[[ "$(curl --fail --silent http://127.0.0.1:8080/health)" == http-backend-ready ]] || { printf 'HTTP fixture failed its health probe.\n' >&2; exit 1; }
[[ "$(curl --fail --silent --resolve backend.acceptance.test:8081:127.0.0.1 \
    --cacert "$root/certs/upstream-ca.pem" https://backend.acceptance.test:8081/health)" == tls-backend-ready ]] || {
    printf 'TLS backend fixture failed certificate verification or its health probe.\n' >&2
    exit 1
}
curl --fail --silent --show-error --cacert "$root/certs/pebble.minica.pem" \
    https://localhost:15000/roots/0 -o "$root/certs/pebble-issued-root.pem"
openssl x509 -in "$root/certs/pebble-issued-root.pem" -noout -subject > "$root/logs/pebble-issued-root.subject"

listeners=$(ss -H -lntup)
for port in 1053 14000 14001 15000 15001 4317 4318 8080 8081 8082 19001 19002; do
    row=$(printf '%s\n' "$listeners" | awk -v suffix=":$port" '$5 ~ (suffix "$" ) || $5 ~ ("\\]:" port "$" )')
    [[ -n "$row" ]] || { printf 'Fixture listener %s did not start.\n' "$port" >&2; exit 1; }
    if printf '%s\n' "$row" | awk '$5 ~ /^(0\.0\.0\.0|\[::\]|:::|\*):/ { found = 1 } END { exit !found }'; then
        printf 'Fixture listener %s is not loopback-bound.\n' "$port" >&2
        exit 1
    fi
done
printf '%s\n' "$listeners" | grep -E ':(1053|14000|14001|15000|15001|4317|4318|8080|8081|8082|19001|19002)([[:space:]]|$)' \
    > "$root/logs/listeners.txt"

{
    printf 'Debian '; cat /etc/debian_version
    "$root/bin/traefik" version
    "$root/bin/pebble" -version
    "$root/bin/otelcol-contrib" --version
    named -V 2>&1 | head -n 1
    nginx -v 2>&1
    printf 'RFC2136 fixture: BIND authoritative acceptance.test, signed update and TXT readback succeeded.\n'
    printf 'ACME fixtures: two independent loopback Pebble servers are active; both CA roots are captured.\n'
    printf 'TLS fixture: local backend certificate verified against its generated CA.\n'
} > "$root/logs/baseline-observations.log" 2>&1
printf 'Guest protocol endpoints, RFC2136 DNS issuer, Pebble ACME CA and OTel collector are active on loopback.\n'
