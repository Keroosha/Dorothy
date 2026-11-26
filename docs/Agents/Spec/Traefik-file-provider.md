# Traefik host and file-provider coverage

Target: [Traefik 3.7.16](https://github.com/traefik/traefik/tree/v3.7.16/pkg/config). This is a plan and acceptance ledger, not a support claim. A version bump requires a fresh comparison with the upstream static, dynamic, TLS and ACME types. Scope: one owned systemd process, one watched directory and one private observation endpoint. No new provider, plugin installation, firewall policy or arbitrary commands.

## Representation and ownership

Keep `keroosha:debian:Traefik`, its parent, name, resource ID, legacy inputs, ACME storage names and redirect/backend generation. Existing declarations need no checkpoint rewrite. New declarations contribute structured fields to an optional `configuration` input; omit this input for a legacy-only resource. Common operations build native objects; an object or field declared twice is an error, not a last-write-wins merge. Maps are unordered; arrays (for example middleware chains) preserve order. Secret/dependent Pulumi values stay secret/dependent. Validate known inputs offline; never collapse preview unknowns to defaults.

Example intended native shapes (JSON paths relative to `configuration`):

| Path | Example value | Binding |
|---|---|---|
| `static.entryPoints.front` | `{"address":"127.0.0.1:8443/tcp"}` | Add a listener, not a firewall opening |
| `dynamic.http.routers.catalog` | `{"rule":"Host(`shop.test`) && PathPrefix(`/items`)","entryPoints":["front"],"service":"catalog"}` | Resolve within the HTTP graph |
| `dynamic.tcp.services.echo` | `{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}],"proxyProtocol":{"version":2}}}` | PROXY to the upstream is independent of trusted inbound peers |

## Coverage matrix and acceptance gates

All rows start **planned**. Runtime is the pinned binary; a file hash, fixture, schema or preview alone cannot discharge a runtime gate.

| Native capability (source) | DSL / wire | Helper and Read | Independent acceptance |
|---|---|---|---|
| [Entry points](https://github.com/traefik/traefik/blob/v3.7.16/pkg/config/static/entrypoints.go): bind, protocol, trusted forwarded/PROXY peers, timeouts/grace, H2/H3 | Address plus port/protocol; structured per-entrypoint fields under `static.entryPoints` | Check wildcard, private admin and implicit QUIC sockets; restart only on static change | Loopback-only exposure, same port TCP+UDP, reject overlap, client negotiation and PID change |
| [HTTP](https://github.com/traefik/traefik/blob/v3.7.16/pkg/config/dynamic/http_config.go): rule language, entrypoints, priority, services, middleware, transports | Combinators or native rule; named objects under `dynamic.http` | Resolve typed edges and cycles; merge disjoint legacy objects; compare accepted file-owned graph | Two paths on one host, shared service, ordered middleware, health checks, TLS upstream, unchanged redirect and subtree semantics |
| [TCP](https://github.com/traefik/traefik/blob/v3.7.16/pkg/config/dynamic/tcp_config.go): raw/SNI, termination, passthrough, middleware, transports, outgoing PROXY | Named `dynamic.tcp` objects; independent inbound trust on static entrypoint | Check protocol, references and accepted TCP graph, not HTTP health | Echo bytes, backend verifies PROXY version/address, SNI cert and end-to-end passthrough |
| [UDP](https://github.com/traefik/traefik/blob/v3.7.16/pkg/config/dynamic/udp_config.go): routers/services | Named `dynamic.udp` objects; no HTTP matchers | Validate listener and service protocol; check loaded UDP graph | Datagram request/reply; remove route while HTTP stays healthy |
| [TLS](https://github.com/traefik/traefik/tree/v3.7.16/pkg/tls): certs, options, client auth, default store | Existing protected certificate inputs, `dynamic.tls` and transport trust | Helper owns private files and generation paths; do not treat an unloaded option as proven by file alone | SNI selection, mTLS positive and negative, backend CA verification |
| [ACME](https://github.com/traefik/traefik/tree/v3.7.16/pkg/provider/acme): HTTP-01, DNS-01, TLS-ALPN-01 | `static.certificatesResolvers`, protected DNS credentials; no operator-selected storage path | Stable helper-owned storage; never echo credentials or delete issued data | Isolated CA + DNS issuance, renewal, resolver rotation, retained store after delete |
| [Static operational controls](https://github.com/traefik/traefik/blob/v3.7.16/pkg/config/static/static_config.go): logging, access log, metrics, tracing, transport defaults | Structured `static` settings; helper reserves admin, discovery, filesystem and unit identity | Bounded service activation; static bytes and live acceptance, distinguish fields the API omits | Observe local collector/log/client, restore previous state after rejection |
| Ownership, transactions, compatibility | Same resource and optional additive input | Read never mutates; verify old graph after rollback; reject unowned content before writes | Real create/refresh/no-op/update/drift/repair/delete, reboot, invalid config, offline old checkpoint |

Out of scope: alternate discovery providers and API/dashboard publishing; third-party plugins and template execution; changing service identity, binary, unit, watched paths or ACME storage; arbitrary host file access. Native field exclusions must identify the reason. Use only isolated loopback endpoints and a disposable Debian guest for acceptance; no public CA or DNS credentials.
