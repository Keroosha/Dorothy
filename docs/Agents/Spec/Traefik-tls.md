# Traefik TLS and ACME field catalogue

Target: Traefik 3.7.16, including its pinned Lego v5.5.2 DNS provider code. This catalogue describes accepted input and helper-owned path/secret handling; it is not a claim that a fixture or native API response proves runtime TLS behavior.

Sources: [Traefik TLS types](https://github.com/traefik/traefik/blob/v3.7.16/pkg/tls/tls.go), [static resolver types](https://github.com/traefik/traefik/blob/v3.7.16/pkg/config/static/static_config.go), [ACME configuration](https://github.com/traefik/traefik/blob/v3.7.16/pkg/provider/acme/provider.go), [Lego dnsupdate v5.5.2](https://github.com/go-acme/lego/blob/v5.5.2/providers/dns/dnsupdate/dnsupdate.go).

## `dynamic.tls`

| Path | Accepted fields and values | Ownership / validation |
|---|---|---|
| `dynamic.tls.certificates[]` | `{"certificate":"<server certificate name>","stores":["default"]}` (`stores` optional) | Logical references only. Helper resolves the name to its protected certificate/key files; only `server`-use material is accepted and auto-registration never includes client-only identities. Arbitrary `certFile`/`keyFile` paths and inline key material are rejected. Duplicate names are rejected. |
| `dynamic.tls.options.<name>` | `minVersion`, `maxVersion` (`VersionTLS10`, `VersionTLS11`, `VersionTLS12`, `VersionTLS13`); pinned Traefik cipher suite names (including the three TLS 1.3 suites); `curvePreferences` (`CurveP256`, `CurveP384`, `CurveP521`, `X25519`, `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`); `clientAuth`; `sniStrict`; `alpnProtocols`; `disableSessionTickets`; `preferServerCipherSuites` | Unknown fields and enum values are rejected. Min/max versions must be ordered. Cipher suites and key exchange groups follow the pinned Traefik 3.7.16 / Go 1.26 maps. `preferServerCipherSuites` is retained as Traefik's deprecated native field. |
| `dynamic.tls.options.<name>.clientAuth` | `clientAuthType` (`NoClientCert`, `RequestClientCert`, `RequireAnyClientCert`, `VerifyClientCertIfGiven`, `RequireAndVerifyClientCert`) and `caFiles` | `caFiles` entries may be named protected certificate identities (resolved to `.crt` paths) or validated inline public certificate PEM. Private-key PEM and arbitrary paths are rejected. Verification modes require at least one CA reference/content. |
| `dynamic.tls.stores.default` | `defaultCertificate: {"certificate":"<server certificate name>"}` or `defaultGeneratedCert: {"resolver":"<resolver name>","domain":{"main":"...","sans":[...]}}` | Only the native `default` store is supported. Client-only identities cannot be selected as a default certificate. The two default-certificate modes cannot both be set. Generated cert resolver names must reference a legacy or structured ACME resolver. |

`dynamic.tls` accepts only `certificates`, `options`, and `stores`. Router references to named TLS options and certificate resolvers are validated with the HTTP/TCP graph. Literal TLS `Host(...)` rules and explicit TLS domains can be probed by the helper; `HostRegexp`, catch-all rules, and settings that do not disclose a concrete hostname remain opaque. A probe does not positively verify mTLS because no client certificate/key is supplied.
Typed `pemCertificate` and `pkcs12Certificate` inputs are inbound `server` identities and retain serverAuth EKU validation. `pemClientCertificate` and `pkcs12ClientCertificate` declare outbound-only `client` identities and require clientAuth EKU. Client-only pairs remain in the same secret certificate map and content-addressed protected-file lifecycle, but are never registered in `dynamic.tls.certificates` or accepted for an inbound router/default certificate. Older certificate inputs without `usage` remain `server`. The `certificateRef` helpers reference those names in outbound transports and ForwardAuth TLS; no PEM or key material is copied into configuration, outputs, or process arguments.

## Outbound TLS trust and client credentials

| Path | Accepted reference/content | Helper transformation |
|---|---|---|
| `dynamic.http.serversTransports.<name>.rootCAs` | Array of named protected certificate identities or public certificate PEM strings | Names resolve to protected `.crt` paths; public PEM remains FileOrContent. |
| `dynamic.tcp.serversTransports.<name>.tls.rootCAs` | Same as HTTP `rootCAs` | Same resolution and PEM validation. |
| `dynamic.http.serversTransports.<name>.certificates[]` | `{"certificate":"<named identity>"}` | Expands to the protected `certFile`/`keyFile` pair. Client-only identities are accepted here for outbound client authentication; existing server identities remain usable for compatibility. |
| `dynamic.tcp.serversTransports.<name>.tls.certificates[]` | Same named reference | Expands to the protected pair and may use a client-only identity. |
| `dynamic.http.middlewares.<name>.forwardAuth.tls` | `caCertificate` is a named identity or public PEM; `clientCertificate` is a named identity; optional `insecureSkipVerify`/`caOptional` | Converts the CA to native `ca` and the client certificate name to its protected `cert`/`key` paths. |

Inline CA content is parsed as X.509 certificate PEM and rejected if it contains a private key. Named references must resolve in the resource certificate inventory. Native file/content fields never accept caller-selected filesystem paths. Server-name validation and transport TLS field validation are handled by the HTTP/TCP graph. A clientAuth-only identity must be tested against a verified upstream that distinguishes missing, wrong-issuer, and accepted client certificates; an inbound SNI check confirms the outbound identity is not served as a router certificate.


## `static.certificatesResolvers`

A resolver must contain exactly one `acme` block. The accepted ACME fields are:

- `email`, `caServer`, `keyType` (`RSA2048`, `RSA4096`, `RSA8192`, `EC256`, `EC384`), `preferredChain`, `profile`, `emailAddresses`, `disableCommonName`, `certificatesDuration`, `clientTimeout`, `clientResponseHeaderTimeout`, `certificateTimeout`, `caSystemCertPool`, `caServerName`, and `eab {kid,hmacEncoded}`. EAB `hmacEncoded` accepts the URL-safe padded or raw Base64 forms supported by the pinned Lego client; standard `+/` Base64 is rejected.
- Exactly one challenge block: `httpChallenge {entryPoint,delay}`, `tlsChallenge {delay}`, or `dnsChallenge {provider,resolvers,propagation,delayBeforeCheck,disablePropagationCheck}`.
- `dnsChallenge.propagation` accepts `disableChecks`, `disableANSChecks`, `requireAllRNS`, and `delayBeforeChecks`.

All object fields, value kinds, names, domains, durations, enum values, and resolver references are validated offline. HTTP challenge entry points must be declared. Managed storage is keyed by the resolver name and exact `caServer` directory URL; the historical name-only path is reused only when the captured prior static configuration names that exact URL and path. Otherwise a new issuer-keyed path is used and prior ACME files are retained. If no prior static snapshot exists, an old name-only file proves only its account authority, not a same-origin directory/tenant, and is not reused. Callers cannot choose storage paths. ACME `caCertificates` is excluded because the pinned native field is a path-only list, so exposing it would allow arbitrary host file reads. The non-ACME Tailscale resolver is excluded because its machine identity/state lifecycle is outside this helper's ACME boundary.

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

Every Read returns aggregate `tlsProbeSummary` counts, including legacy-only configurations: `legacyProbesAttempted` counts actual legacy handshakes and `nativeProbesAttempted` counts actual structured handshakes; both are deduplicated by physical target with legacy taking precedence. `opaqueRouterCount`, `unprobedCount`, and `truncated` (0 or 1) qualify what Read could not verify. Probes use the listener's numeric local address and family; wildcards use family-appropriate loopback, and legacy numeric listeners keep their IPv4 loopback probe. A bounded worker pool checks every eligible known target, including configurations with more than 16 targets, under one 15-second wall budget; budget-exhausted mandatory targets are unprobed, mark the result truncated, and cannot yield `inSync`. No DNS lookup chooses the destination. Positive leading literal `Host`/`HostSNI` predicates (including the grouped form emitted by the DSL) can identify a name. Ambiguous expressions, nonlocal destinations, passthrough and client-auth-required handshakes remain explicitly unprobed. ACME leaves, matching private keys, account identity, and protected store metadata are validated independently, including for mTLS routes whose handshake cannot be probed. See the [live acceptance ledger](Traefik-file-provider.md) for the independent positive/negative client tests.
