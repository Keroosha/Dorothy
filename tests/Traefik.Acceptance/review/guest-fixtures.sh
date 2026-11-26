#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 1 ]]; then
    printf 'Usage: guest-fixtures.sh /var/tmp/dorothy-traefik-acceptance.XXXXXXXX\n' >&2
    exit 2
fi
root=$(realpath -e -- "$1")
case "$root" in
    /var/tmp/dorothy-traefik-acceptance.*) ;;
    *) printf 'Refusing to configure outside the private acceptance guest root.\n' >&2; exit 2 ;;
esac
[[ -f "$root/.owner" && "$(<"$root/.owner")" == dorothy-traefik-acceptance-guest-v1 ]] || {
    printf 'Private guest ownership marker is missing.\n' >&2
    exit 2
}
[[ -s "$root/certs/upstream-server.pem" && -s "$root/certs/upstream-server.key" \
   && -s "$root/certs/client-ca.pem" ]] || {
    printf 'Required isolated TLS fixture material is missing.\n' >&2
    exit 2
}
wrong_ca_subject=''
if [[ -s "$root/certs/review-wrong-client-ca.pem" ]]; then
    wrong_ca_subject=$(openssl x509 -in "$root/certs/review-wrong-client-ca.pem" -noout -subject -nameopt RFC2253)
fi
if [[ -n "$wrong_ca_subject" && "$wrong_ca_subject" != 'subject=CN=Dorothy Traefik Acceptance Client CA' ]]; then
    rm -f -- "$root/certs/review-wrong-client.pem" "$root/certs/review-wrong-client.key" \
        "$root/certs/review-wrong-client.csr" "$root/certs/review-wrong-client.ext" \
        "$root/certs/review-wrong-client-ca.pem" "$root/certs/review-wrong-client-ca.key" \
        "$root/certs/review-wrong-client-ca.srl"
fi
if [[ ! -s "$root/certs/review-wrong-client.pem" && ! -s "$root/certs/review-wrong-client.key" ]]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$root/certs/review-wrong-client-ca.key" -out "$root/certs/review-wrong-client-ca.pem" \
        -subj '/CN=Dorothy Traefik Acceptance Client CA' -days 2 \
        -addext 'basicConstraints=critical,CA:TRUE' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign' \
        > "$root/logs/review-client-identity-pki.log" 2>&1
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$root/certs/review-wrong-client.key" -out "$root/certs/review-wrong-client.csr" \
        -subj '/CN=review-untrusted-client' \
        >> "$root/logs/review-client-identity-pki.log" 2>&1
    cat > "$root/certs/review-wrong-client.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=DNS:review-untrusted-client.acceptance.test
EOF
    openssl x509 -req -in "$root/certs/review-wrong-client.csr" \
        -CA "$root/certs/review-wrong-client-ca.pem" -CAkey "$root/certs/review-wrong-client-ca.key" \
        -CAcreateserial -out "$root/certs/review-wrong-client.pem" -days 2 -sha256 \
        -extfile "$root/certs/review-wrong-client.ext" \
        >> "$root/logs/review-client-identity-pki.log" 2>&1
elif [[ ! -s "$root/certs/review-wrong-client.pem" || ! -s "$root/certs/review-wrong-client.key" \
       || ! -s "$root/certs/review-wrong-client-ca.pem" || ! -s "$root/certs/review-wrong-client-ca.key" ]]; then
    printf 'Untrusted client identity fixture is incomplete.\n' >&2
    exit 1
fi
chmod 644 "$root/certs/review-wrong-client.pem" "$root/certs/review-wrong-client-ca.pem"
chmod 600 "$root/certs/review-wrong-client.key" "$root/certs/review-wrong-client-ca.key"
openssl verify -CAfile "$root/certs/review-wrong-client-ca.pem" "$root/certs/review-wrong-client.pem" \
    > "$root/logs/review-client-identity-wrong-chain.log" 2>&1
if openssl verify -CAfile "$root/certs/client-ca.pem" "$root/certs/review-wrong-client.pem" \
    > "$root/logs/review-client-identity-wrong-rejected.log" 2>&1; then
    printf 'Untrusted client identity unexpectedly chains to the trusted client CA.\n' >&2
    exit 1
fi

cat > "$root/config/review-mtls-nginx.conf" <<EOF
pid $root/review-mtls-nginx.pid;
error_log $root/logs/review-client-identity-upstream-error.log info;
events {}
http {
    access_log $root/logs/review-client-identity-upstream-access.log;
    server {
        listen 127.0.0.1:18123 ssl;
        server_name backend.acceptance.test;
        ssl_certificate $root/certs/upstream-server.pem;
        ssl_certificate_key $root/certs/upstream-server.key;
        ssl_client_certificate $root/certs/client-ca.pem;
        ssl_verify_client on;
        ssl_verify_depth 2;
        ssl_protocols TLSv1.2 TLSv1.3;
        location = /client-auth {
            default_type text/plain;
            return 200 "client-auth-accepted:\$ssl_client_s_dn\\n";
        }
    }
}
EOF
cat > "$root/units/dorothy-traefik-acceptance-review-mtls.service" <<EOF
[Unit]
Description=Dorothy Traefik review outbound client-auth upstream
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/nginx -c $root/config/review-mtls-nginx.conf -g "daemon off;"
Restart=on-failure
RestartSec=1
StandardOutput=append:$root/logs/review-mtls-nginx.stdout.log
StandardError=append:$root/logs/review-mtls-nginx.stderr.log

[Install]
WantedBy=multi-user.target
EOF
cat > "$root/units/dorothy-traefik-acceptance-review-udp.service" <<EOF
[Unit]
Description=Dorothy Traefik review UDP backend B
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/socat -v -x UDP4-RECVFROM:19004,bind=127.0.0.1,reuseaddr,fork EXEC:/bin/cat
Restart=always
RestartSec=1
StandardOutput=append:$root/logs/review-udp-b.log
StandardError=append:$root/logs/review-udp-b.log

[Install]
WantedBy=multi-user.target
EOF
chmod 600 "$root/config/review-mtls-nginx.conf" "$root/units/dorothy-traefik-acceptance-review-mtls.service" \
    "$root/units/dorothy-traefik-acceptance-review-udp.service"
nginx -t -c "$root/config/review-mtls-nginx.conf" > "$root/logs/review-mtls-nginx-check.log" 2>&1
install -m 644 "$root/units/dorothy-traefik-acceptance-review-mtls.service" \
    /etc/systemd/system/dorothy-traefik-acceptance-review-mtls.service
install -m 644 "$root/units/dorothy-traefik-acceptance-review-udp.service" \
    /etc/systemd/system/dorothy-traefik-acceptance-review-udp.service
systemctl daemon-reload
systemctl enable --now dorothy-traefik-acceptance-review-mtls.service \
    dorothy-traefik-acceptance-review-udp.service > "$root/logs/review-fixture-start.log" 2>&1
systemctl restart dorothy-traefik-acceptance-review-mtls.service \
    > "$root/logs/review-fixture-restart.log" 2>&1
for _ in $(seq 1 30); do
    if ss -H -lntup | grep -Fq ':18123' && ss -H -lntup | grep -Fq ':19004'; then
        printf 'Review mTLS and UDP backends are ready.\n'
        exit 0
    fi
    sleep 1
done
printf 'Review upstream fixtures did not bind their loopback listeners.\n' >&2
exit 1
