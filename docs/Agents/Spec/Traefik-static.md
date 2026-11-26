# Traefik static configuration boundary

Target: Traefik 3.7.16. This is the implemented offline validation boundary for the `static` object in the optional `configuration` input; it is not a claim that every accepted knob has been exercised against a running Traefik process. The pinned inventory is the generated [static configuration catalogue](https://github.com/traefik/traefik/blob/v3.7.16/docs/content/reference/static-configuration/file.yaml); field definitions are cross-checked against [`pkg/config/static/entrypoints.go`](https://github.com/traefik/traefik/blob/v3.7.16/pkg/config/static/entrypoints.go), [`pkg/config/static/static_config.go`](https://github.com/traefik/traefik/blob/v3.7.16/pkg/config/static/static_config.go), [`pkg/observability/types`](https://github.com/traefik/traefik/tree/v3.7.16/pkg/observability/types), [`pkg/types/host_resolver.go`](https://github.com/traefik/traefik/blob/v3.7.16/pkg/types/host_resolver.go), [`pkg/types/file_or_content.go`](https://github.com/traefik/traefik/blob/v3.7.16/pkg/types/file_or_content.go), and [`pkg/types/tls.go`](https://github.com/traefik/traefik/blob/v3.7.16/pkg/types/tls.go).
The generated YAML is an example, not a complete field schema. Safe fields in the pinned v3.7.16 Go types are supported even when absent from that example; omissions below identify a concrete path, network, credential, route, or alias boundary.

Unknown fields, wrong JSON types, case aliases, duplicate names differing only by case, and `{{` template expressions are rejected with fixed diagnostics. JSON field names must use the exact native JSON spelling shown below. All entries are bounded; accepted arbitrary maps and arrays have fixed item and text-length caps.

Concrete caps: at most 64 combined legacy and native entrypoints; entrypoint names are at most 63 characters; scalar strings are at most 4,096 characters; generic maps have at most 256 members and keys are at most 256 characters; arrays have at most 128 items. Individual fields impose tighter limits where noted.

## Accepted field matrix

| Native path | Accepted fields and limits | Notes |
|---|---|---|
| `entryPoints.<name>` | `address`, `allowACMEByPass`, `asDefault`, `transport`, `proxyProtocol`, `forwardedHeaders`, `http`, `http2`, `http3`, `udp`, `observability`; `reusePort` only when false | Names are bounded ASCII identifiers; both `traefik` and helper-owned `keroosha-admin` are reserved. Bind addresses use numeric IP literals (or an empty host wildcard), port 1–65535, optional `/tcp` or `/udp`. Omitted protocol defaults to TCP; output normalizes to lower-case. DNS names and Unix sockets are rejected. |
| `entryPoints.*.transport` | `lifeCycle.requestAcceptGraceTimeout`, `lifeCycle.graceTimeOut`, `respondingTimeouts.{readTimeout,writeTimeout,idleTimeout}`, `keepAliveMaxTime`, `keepAliveMaxRequests` | Go durations; request count is 0–1,000,000. |
| `entryPoints.*.proxyProtocol`, `forwardedHeaders` | `trustedIPs`; forwarded headers also allow `connection`, `notAppendXForwardedFor`; `insecure` only when false | Trust lists are numeric IP/CIDR values, bounded to 64 entries; `/0` and trust-all `insecure:true` are rejected. |
| `entryPoints.*.http` | `redirections.entryPoint.{to,scheme,permanent,priority}`, `middlewares`, `tls.{options,certResolver,domains}`, `encodedCharacters` booleans, `encodeQuerySemicolons`, `sanitizePath`, `maxHeaderBytes`, `aliasHeadersStrategy`, `underscoreHeadersStrategy` | Middleware refs resolve as `name@file`; TLS options are `default` or a resolvable `name@file`; cert resolvers are checked separately. Redirect targets must name a declared TCP entrypoint and may not target either reserved name. Header strategies are valid individually; setting both old and new names is ambiguous and rejected. |
| `entryPoints.*.http2` | `maxConcurrentStreams`, `maxDecoderHeaderTableSize`, `maxEncoderHeaderTableSize` | Streams capped at 1,000,000; header tables capped at 1 MiB. |
| `entryPoints.*.http3` | `advertisedPort` | 0–65535; HTTP/3 requires a TCP entrypoint and implies UDP on its actual address/port. Advertisement does not change the bind. |
| `entryPoints.*.udp` | `timeout` | Bounded Go duration. |
| `entryPoints.*.observability` | `accessLogs`, `metrics`, `tracing`, `traceVerbosity` | Verbosity is `minimal` or `detailed`. |
| `global` | `checkNewVersion`, `sendAnonymousUsage`, `notAppendXForwardedFor` | Boolean controls. `checkNewVersion` and `sendAnonymousUsage` use Traefik's fixed upstream endpoints when true. |
| `core` | `strictTLSOptions`, `defaultRuleSyntax` | Both upstream syntaxes, `v2` and `v3`, are accepted. |
| `hostResolver` | `cnameFlattening`, `resolvDepth` | DNS depth is 0–64. The user-selected `resolvConfig` path is not accepted. |
| `serversTransport` | `insecureSkipVerify` only when false, `rootCAs`, `maxIdleConnsPerHost`, `forwardingTimeouts.{dialTimeout,responseHeaderTimeout,idleConnTimeout}` | `rootCAs` has at most 16 inline PEM entries; each must contain currently valid CA certificates. File paths, private keys, and non-CA certificates fail. |
| `tcpServersTransport` | `dialKeepAlive`, `dialTimeout`, `terminationDelay`, `tls.{insecureSkipVerify,rootCAs}` | TLS bypass only when false; TLS root CAs are validated inline PEM. All durations use Go syntax. |
| `log` | `level`, `format`, `noColor`, `otlp.{serviceName,resourceAttributes,grpc,http}` | Output stays on stdout. OTLP supports local HTTP/gRPC collectors and headers; custom TLS file/content fields are not accepted. |
| `accessLog` | `format`, `filters.{statusCodes,retryAttempts,minDuration}`, `fields.{defaultMode,names,headers.{defaultMode,names},queryParameters.defaultMode}`, `bufferingSize`, `addInternals`, `dualOutput`, `otlp.{serviceName,resourceAttributes,grpc,http}` | Output stays on stdout. OTLP uses local collectors with fixed signal paths; field modes are `keep`, `drop`, or header `redact`. |
| `metrics` | `addInternals`, `prometheus`, `datadog`, `statsD`, `influxDB2`, `otlp` | All exporter destinations are loopback-only. Datadog requires an explicit address; StatsD and Influx defaults are local. Influx token is not accepted. |
| `metrics.datadog` | `address`, `pushInterval`, `addEntryPointsLabels`, `addRoutersLabels`, `addServicesLabels`, `prefix` | Address is required and must be loopback host:port; its upstream environment-derived default is not used. |
| `metrics.statsD` | `address`, `pushInterval`, `addEntryPointsLabels`, `addRoutersLabels`, `addServicesLabels`, `prefix` | Explicit address is loopback host:port; omitted address retains Traefik's fixed `localhost:8125` default. |
| `metrics.influxDB2` | `address`, `pushInterval`, `org`, `bucket`, `addEntryPointsLabels`, `addRoutersLabels`, `addServicesLabels`, `additionalLabels` | Address is local HTTP(S) with root path only; `token` is rejected because it is `FileOrContent`. |
| `metrics.prometheus` | `buckets`, `addEntryPointsLabels`, `addRoutersLabels`, `addServicesLabels`, `entryPoint`, `manualRouting`, `headerLabels` | `entryPoint` is required and must be `keroosha-admin`; the `/metrics` route cannot use upstream's implicit `traefik`/`:8080` endpoint. Buckets are finite, positive, increasing, max 128. |
| `metrics.otlp` | `grpc`, `http`, `addEntryPointsLabels`, `addRoutersLabels`, `addServicesLabels`, `explicitBoundaries`, `pushInterval`, `serviceName`, `resourceAttributes` | Local collector only; HTTP path is `/` or `/v1/metrics`, gRPC is host:port. |
| `tracing` | `serviceName`, `resourceAttributes` or deprecated `globalAttributes`, `capturedRequestHeaders`, `capturedResponseHeaders`, `safeQueryParams`, `sampleRate`, `addInternals`, `otlp.{grpc,http}` | Attribute aliases cannot be combined. Sample rate is 0–1; OTLP paths are limited to local `/v1/traces` collectors. |
| `ping` | `entryPoint`, `manualRouting`, `terminatingStatusCode` | `entryPoint` is required and must be `keroosha-admin`; implicit upstream `traefik` defaults are rejected. Status is 100–599. |

`certificatesResolvers` is intentionally not walked by `TraefikStatic.validate`: the TLS/ACME validator owns that whole root subtree. `TraefikStatic.validateReferences` separately resolves static entrypoint middleware and TLS references against `dynamic.http.middlewares`, `dynamic.tls.options`, and the validated resolver-name set. Static references require `@file`; `@internal`, other namespaces, and unresolved names are rejected. The built-in `default` TLS option is accepted without a dynamic declaration.

## Bind and reference safety

Legacy entrypoints enter the result as TCP sockets. Every native entrypoint is returned by name with lower-case `tcp` or `udp`; HTTP/3's implied UDP socket is used for bind-conflict detection but does not add a second name. Same-protocol sockets overlap when they use the same IP/port or either bind is wildcard. TCP and UDP may use the same numeric port. User sockets may not overlap the private administration TCP port. `reusePort:true` is rejected to prevent sharing a managed socket with another process.

Default middleware and TLS option references are resolved only after the dynamic graph is validated. The static TLS option `default` is the built-in default; all other static TLS options must be qualified `name@file` and present under `dynamic.tls.options`. `entryPoint.http.middlewares` uses the same `name@file` rule against `dynamic.http.middlewares`. EntryPoint TLS certificate resolvers must exist in the validated resolver set. Ping and Prometheus require the helper-owned `keroosha-admin` endpoint; redirects cannot target it or Traefik's implicit `traefik` endpoint.

## Explicit safety exclusions

| Native field/subtree | Decision | Reason |
|---|---|---|
| `api` (dashboard, insecure API, debug routes), `providers` (including `providers.file`), alternate provider trees | Reject | The helper owns API exposure and provider activation; user configuration cannot add routes, providers, or watched paths. |
| `experimental` (plugins, local plugins, unsafe mounts/env) | Reject | Avoid arbitrary plugin code, commands, mounts, and template execution. |
| `entryPoints.*.address` Unix path or hostname; `reusePort:true` | Reject | Bind analysis must be deterministic and owned; no filesystem socket or shared listener. |
| `entryPoints.*.proxyProtocol.insecure:true`, `forwardedHeaders.insecure:true`, trusted CIDR `/0` | Reject | Do not allow trust-all client/proxy headers. |
| `aliasHeadersStrategy` with `underscoreHeadersStrategy`; `resourceAttributes` with `globalAttributes` | Reject | Each deprecated/current field is supported alone; supplying both aliases is ambiguous. |
| Non-loopback OTLP, Datadog, StatsD, or InfluxDB2 destinations; non-signal OTLP HTTP paths | Reject | Native exporters are limited to loopback collectors and fixed signal paths to prevent operator-controlled network egress. |
| `metrics.influxDB2.token` | Reject | Upstream `FileOrContent.Read` calls `os.Stat` and reads an existing path; the validator cannot distinguish a remote helper-local file from token content. |
| `log.filePath`, `accessLog.filePath`, log rotation fields | Reject | Prevent filesystem writes; logging remains on helper-owned stdout/stderr. |
| `serversTransport.insecureSkipVerify:true`, `tcpServersTransport.tls.insecureSkipVerify:true` | Reject | TLS verification bypass would weaken backend identity validation. |
| `serversTransport.spiffe`, `tcpServersTransport.tls.spiffe`, `spiffe.workloadAPIAddr` | Reject | These fields connect to an operator-selected workload API socket. |
| `hostResolver.resolvConfig` | Reject | This field selects a local resolver configuration path; safe `cnameFlattening` and `resolvDepth` remain available. |
| `metrics.prometheus.entryPoint` or `ping.entryPoint` omitted/non-private | Reject | Traefik defaults to internal name `traefik` and may synthesize `:8080`; handlers must explicitly use helper-owned `keroosha-admin`. |
| `OTLP.*.tls` | Reject | Client TLS CA/cert/key are path-or-content strings; local collectors use system trust or plain HTTP, and custom path resolution is outside the boundary. |
| `ocsp.responderOverrides` | Reject | Overrides can redirect certificate-status checks to operator-selected network responders. |
| `certificatesResolvers` descendants | TLS slice | The separate certificate resolver/ACME boundary owns credentials, storage, and challenge settings. |

This inventory is pinned, not open-ended. A Traefik version upgrade requires rechecking the generated catalogue and the corresponding source definitions, then updating this matrix and its tests. Static validation alone does not prove that Traefik activated, bound, or served a configured listener/exporter.