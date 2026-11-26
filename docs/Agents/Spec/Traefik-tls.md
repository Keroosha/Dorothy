# Traefik TLS and ACME field catalogue

Target: Traefik 3.7.16, including its pinned Lego v5.5.2 DNS provider code. This catalogue describes accepted input and helper-owned path/secret handling; it is not a claim that a fixture or native API response proves runtime TLS behavior.

Sources: [Traefik TLS types](https://github.com/traefik/traefik/blob/v3.7.16/pkg/tls/tls.go), [static resolver types](https://github.com/traefik/traefik/blob/v3.7.16/pkg/config/static/static_config.go), [ACME configuration](https://github.com/traefik/traefik/blob/v3.7.16/pkg/provider/acme/provider.go), [Lego dnsupdate v5.5.2](https://github.com/go-acme/lego/blob/v5.5.2/providers/dns/dnsupdate/dnsupdate.go).

## `dynamic.tls`

| Path | Accepted fields and values | Ownership / validation |
|---|---|---|
| `dynamic.tls.certificates[]` | `{"certificate":"<legacy certificate name>","stores":["default"]}` (`stores` optional) | Logical references only. Helper resolves the name to its existing protected certificate/key files; arbitrary `certFile`/`keyFile` paths and inline key material are rejected. Duplicate names are rejected. |
| `dynamic.tls.options.<name>` | `minVersion`, `maxVersion` (`VersionTLS10`, `VersionTLS11`, `VersionTLS12`, `VersionTLS13`); `cipherSuites`; `curvePreferences` (`CurveP256`, `CurveP384`, `CurveP521`, `X25519`); `clientAuth`; `sniStrict`; `alpnProtocols`; `disableSessionTickets`; `preferServerCipherSuites` | Unknown fields and enum values are rejected. Min/max versions must be ordered. Cipher suites are checked against the pinned Go TLS suite names. `preferServerCipherSuites` is retained as Traefik's deprecated native field. |
| `dynamic.tls.options.<name>.clientAuth` | `clientAuthType` (`NoClientCert`, `RequestClientCert`, `RequireAnyClientCert`, `VerifyClientCertIfGiven`, `RequireAndVerifyClientCert`) and `caFiles` | `caFiles` entries may be legacy certificate names (resolved to protected `.crt` paths) or validated inline public certificate PEM. Private-key PEM and arbitrary paths are rejected. Verification modes require at least one CA reference/content. |
| `dynamic.tls.stores.default` | `defaultCertificate: {"certificate":"<legacy certificate name>"}` or `defaultGeneratedCert: {"resolver":"<resolver name>","domain":{"main":"...","sans":[...]}}` | Only the native `default` store is supported. The two default-certificate modes cannot both be set. Generated cert resolver names must reference a legacy or structured ACME resolver. |

`dynamic.tls` accepts only `certificates`, `options`, and `stores`. Router references to named TLS options and certificate resolvers are validated with the HTTP/TCP graph. Literal TLS `Host(...)` rules and explicit TLS domains can be probed by the helper; `HostRegexp`, catch-all rules, and settings that do not disclose a concrete hostname remain opaque. A probe does not positively verify mTLS because no client certificate/key is supplied.

## Outbound TLS trust and client credentials

| Path | Accepted reference/content | Helper transformation |
|---|---|---|
| `dynamic.http.serversTransports.<name>.rootCAs` | Array of legacy certificate names or public certificate PEM strings | Names resolve to protected `.crt` paths; public PEM remains FileOrContent. |
| `dynamic.tcp.serversTransports.<name>.tls.rootCAs` | Same as HTTP `rootCAs` | Same resolution and PEM validation. |
| `dynamic.http.serversTransports.<name>.certificates[]` | `{"certificate":"<legacy certificate name>"}` | Expands to the existing protected `certFile`/`keyFile` pair. |
| `dynamic.tcp.serversTransports.<name>.tls.certificates[]` | Same named reference | Expands to the protected pair. |
| `dynamic.http.middlewares.<name>.forwardAuth.tls` | `caCertificate` is a legacy name or public PEM; `clientCertificate` is a legacy name; optional `insecureSkipVerify`/`caOptional` | Converts the CA to native `ca` and the client certificate name to its protected `cert`/`key` paths. |

Inline CA content is parsed as X.509 certificate PEM and rejected if it contains a private key. Legacy references must resolve in the resource certificate inventory. Native file/content fields never accept caller-selected filesystem paths. Server-name validation and transport TLS field validation are handled by the HTTP/TCP graph.


## `static.certificatesResolvers`

A resolver must contain exactly one `acme` block. The accepted ACME fields are:

- `email`, `caServer`, `keyType` (`RSA2048`, `RSA4096`, `RSA8192`, `EC256`, `EC384`), `preferredChain`, `profile`, `emailAddresses`, `disableCommonName`, `certificatesDuration`, `clientTimeout`, `clientResponseHeaderTimeout`, `certificateTimeout`, `caSystemCertPool`, `caServerName`, and `eab {kid,hmacEncoded}`.
- Exactly one challenge block: `httpChallenge {entryPoint,delay}`, `tlsChallenge {delay}`, or `dnsChallenge {provider,resolvers,propagation,delayBeforeCheck,disablePropagationCheck}`.
- `dnsChallenge.propagation` accepts `disableChecks`, `disableANSChecks`, `requireAllRNS`, and `delayBeforeChecks`.

All object fields, value kinds, names, domains, durations, enum values, and resolver references are validated offline. HTTP challenge entry points must be declared. The helper replaces ACME storage with `acme-<sha256 resolver name>.json` beneath its private Traefik state directory; callers cannot choose a storage path. ACME `caCertificates` is excluded because the pinned native field is a path-only list, so exposing it would allow arbitrary host file reads. The non-ACME Tailscale resolver is excluded because its machine identity/state lifecycle is outside this helper's ACME boundary.

## DNS provider credentials

The optional `dnsCredentials` object is keyed by the exact `dnsChallenge.provider` name, then by a provider-specific environment name. Only the following vetted names are accepted:

| Provider | Allowed environment names | Required values |
|---|---|---|
| `dnsupdate` | `DNSUPDATE_NAMESERVER`, `DNSUPDATE_DNS_TIMEOUT`, `DNSUPDATE_ZONES`, `DNSUPDATE_TTL`, `DNSUPDATE_PROPAGATION_TIMEOUT`, `DNSUPDATE_POLLING_INTERVAL`, `DNSUPDATE_SEQUENCE_INTERVAL`, `DNSUPDATE_TSIG_KEY`, `DNSUPDATE_TSIG_SECRET`, `DNSUPDATE_TSIG_ALGORITHM` | `DNSUPDATE_NAMESERVER`; TSIG key and secret must be supplied together. |
| `cloudflare` | `CLOUDFLARE_DNS_API_TOKEN`, `CLOUDFLARE_ZONE_API_TOKEN` | `CLOUDFLARE_DNS_API_TOKEN` |
| `digitalocean` | `DO_AUTH_TOKEN` | `DO_AUTH_TOKEN` |
| `linode` | `LINODE_TOKEN` | `LINODE_TOKEN` |
| `vultr` | `VULTR_API_KEY` | `VULTR_API_KEY` |

The `dnsupdate` name and `DNSUPDATE_` prefix are from the pinned Lego source; the historical `rfc2136` provider spelling and `RFC2136_` variables are not used by this Traefik version. Environment names not listed above—including every `*_FILE` name, DNSUPDATE TSIG files/GSS keytab variables, custom API endpoints, cloud SDK ambient credentials, and arbitrary environment names—are rejected. Credential values never appear in validation errors or Read output. The helper writes only allowlisted values to `/etc/keroosha-iac/traefik/dns-credentials.env` (mode 0600, root:root), read by systemd before the service drops privileges, and removes that file on resource deletion; ACME account/certificate storage is retained.

## Evidence limits

Read remains observational: credential drift, certificate expiry, missing ACME issuance, and a concrete SNI fingerprint mismatch are reported without repairing files or restarting the service. The helper bounds TLS handshake probes to 16 unique loopback host/port pairs across legacy and structured routes. Omitted opaque domains and client-auth-required handshakes are reported as unprobed rather than treated as passed. Provider acceptance and renewal remain separate isolated-guest gates in [the host coverage plan](Traefik-file-provider.md).
