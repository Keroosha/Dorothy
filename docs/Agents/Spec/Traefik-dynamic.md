# Traefik native dynamic configuration

Target: [Traefik 3.7.16](https://github.com/traefik/traefik/tree/v3.7.16). The field inventory is pinned to the upstream generated [file-provider catalogue](https://github.com/traefik/traefik/blob/v3.7.16/docs/content/reference/dynamic-configuration/file.yaml), not inferred from labels, Gateway API, or provider-only Go fields. A Traefik version change requires rechecking that catalogue and its source types. This validator establishes accepted input shape and graph safety; it is not runtime acceptance evidence.

## Boundary and references

`Dorothy.DSL.TraefikDynamic.validate entryPoints resolvers tlsOptions legacyRouters dynamicRoot` is shared with the native helper. It validates the `http`, `tcp`, and `udp` subtrees. The dynamic root allows only `http`, `tcp`, `udp`, and `tls`; `tls` is intentionally handed to the TLS validator without inspection here.

All object maps use local names only. Names are bounded ASCII identifiers. References accept an unqualified local name or explicit `name@file`, which canonicalize to the same object; other provider qualifiers (including `@internal`) are rejected. Every router must name its service and list one or more explicit entry points. HTTP and TCP routers resolve only TCP entry points; UDP routers resolve only UDP entry points. The private `keroosha-admin` entry point/router is reserved. HTTP/TCP routers resolve only same-protocol services, middlewares, and transports. Native HTTP router names may not collide with legacy routers; the generated `keroosha-backend-` service and `keroosha-redirect-` middleware namespaces are reserved.

HTTP and TCP routers validate ordered middleware references. HTTP chain arrays retain their input order and resolve only HTTP middleware. HTTP service compositions (`weighted`, `highestRandomWeight`, `mirroring`, and `failover`) resolve only HTTP services. TCP and UDP weighted services resolve only services of the same protocol. The validator rejects service-composition cycles and HTTP middleware-chain cycles, including unreferenced objects. HTTP `errors.service` is a typed HTTP service reference. HTTP load balancers and TCP load balancers resolve only their same-protocol `serversTransports` maps. Router `tls.options` resolves to a declared option or the built-in `default`; `tls.certResolver` resolves to a configured resolver. Certificate, store, and TLS-option bodies are the TLS validator's responsibility.

## Pinned supported field inventory

Only the fields below are accepted in each position. Every other field is rejected, even if a newer Traefik build or another provider recognizes it.

| Area | Supported fields |
|---|---|
| `http.routers.<name>` | `entryPoints`, `middlewares`, `service`, `rule`, `ruleSyntax`, `priority`, `tls`, `observability` |
| HTTP router `tls` | `options`, `certResolver`, `domains` (`main`, `sans`) |
| HTTP router `observability` | `accessLogs`, `metrics`, `tracing`, `traceVerbosity` |
| `http.services.<name>` | Exactly one of `loadBalancer`, `weighted`, `highestRandomWeight`, `mirroring`, `failover` |
| HTTP service `loadBalancer` | `sticky.cookie` (`name`, `secure`, `httpOnly`, `sameSite`, `maxAge`, `path`, `domain`), `servers` (`url`, `weight`, `preservePath`), `strategy`, `healthCheck` (`scheme`, `mode`, `path`, `method`, `status`, `port`, `interval`, `unhealthyInterval`, `timeout`, `hostname`, `followRedirects`, `headers`), `passiveHealthCheck` (`failureWindow`, `maxFailedAttempts`), `passHostHeader`, `responseForwarding.flushInterval`, `serversTransport` |
| HTTP service `weighted` / `highestRandomWeight` | `services` (`name`, `weight`), `healthCheck`; `weighted` additionally accepts `sticky.cookie` with the cookie fields above |
| HTTP service `mirroring` | `service`, `mirrorBody`, `maxBodySize`, `mirrors` (`name`, `percent`), `healthCheck` |
| HTTP service `failover` | `service`, `fallback`, `healthCheck`, `errors` (`maxRequestBodyBytes`, `status`) |
| `http.middlewares.<name>` | One built-in kind: `addPrefix`, `basicAuth`, `buffering`, `chain`, `circuitBreaker`, `compress`, `contentType`, `digestAuth`, `errors`, `forwardAuth`, `grpcWeb`, `headers`, `ipAllowList`, `ipWhiteList`, `inFlightReq`, `passTLSClientCert`, `rateLimit`, `redirectRegex`, `redirectScheme`, `replacePath`, `replacePathRegex`, `retry`, `stripPrefix`, or `stripPrefixRegex`. Each kind accepts only the fields in the 3.7.16 file-provider catalogue; ForwardAuth `tls` is narrowed to `caCertificate`, `clientCertificate`, `insecureSkipVerify`, and `caOptional`; `plugin` is not supported. |
| `http.serversTransports.<name>` | `serverName`, `insecureSkipVerify`, `rootCAs` (public PEM or legacy name), `certificates[].certificate` (legacy name), `cipherSuites`, `minVersion`, `maxVersion`, `maxIdleConnsPerHost`, `forwardingTimeouts` (`dialTimeout`, `responseHeaderTimeout`, `idleConnTimeout`, `readIdleTimeout`, `pingTimeout`), `disableHTTP2`, `peerCertURI` |
| `tcp.routers.<name>` | `entryPoints`, `middlewares`, `service`, `rule`, `ruleSyntax`, `priority`, `tls` |
| TCP router `tls` | `passthrough`, `options`, `certResolver`, `domains` (`main`, `sans`) |
| `tcp.services.<name>` | Exactly one of `loadBalancer` (`servers` with `address` and `tls`, `serversTransport`, `proxyProtocol.version`, `terminationDelay`) or `weighted` (`services` with `name`, `weight`) |
| `tcp.middlewares.<name>` | Exactly one of `inFlightConn.amount`, `ipAllowList.sourceRange`, or `ipWhiteList.sourceRange` |
| `tcp.serversTransports.<name>` | `dialKeepAlive`, `dialTimeout`, `proxyProtocol.version`, `terminationDelay`, and `tls` (`serverName`, `insecureSkipVerify`, `rootCAs`, `certificates[].certificate`, `peerCertURI`) |
| `udp.routers.<name>` | `entryPoints`, `service` |
| `udp.services.<name>` | Exactly one of `loadBalancer.servers[].address` or `weighted.services[]` (`name`, `weight`) |

Middleware field names and nested inventories are intentionally copied from the pinned generated file. Go types that are not exposed by that file-provider catalogue are not accepted.

## Upstream and host-access restrictions

Native fields cannot install plugins, evaluate templates, or select arbitrary host files. References are local and typed; unqualified names and explicit `name@file` qualifiers resolve to the same local object, while other provider qualifiers fail. HTTP upstream URLs are absolute `http`, `https`, or `h2c` URLs without user information or fragments; pinned [SmartBuilder](https://github.com/traefik/traefik/blob/v3.7.16/pkg/proxy/smart_builder.go) explicitly routes `h2c` targets through its regular HTTP/2-capable proxy builder. TCP and UDP upstream addresses are host-and-port values, not URLs or filesystem paths.

HTTP and TCP server-transport TLS always keeps certificate verification enabled: `insecureSkipVerify: true` is rejected. `rootCAs` and ForwardAuth `tls.caCertificate` accept either an existing legacy certificate name or validated inline public `CERTIFICATE` PEM; private-key PEM, paths, and malformed PEM are rejected. Server-transport `certificates` uses only `[{certificate: <legacy-name>}]`, and ForwardAuth `tls.clientCertificate` uses only a legacy name; the TLS validation pass checks reference existence. TLS protocol bounds are limited to TLS 1.2 and TLS 1.3. The TCP server transport can set an explicit `tls.serverName` for upstream SNI and can send PROXY protocol v1 or v2; the TCP load balancer's outgoing `proxyProtocol.version` is also supported. These are upstream settings, independent of trusted inbound PROXY peers on entry points.

Fields that can read arbitrary files are not exposed: this includes HTTP basic/digest `usersFile`, Redis TLS, native ForwardAuth `ca`/`cert`/`key`, and transport `certFile`/`keyFile`. Instead, transport client certificates use `certificates: [{certificate: <legacy-name>}]`; ForwardAuth TLS uses `caCertificate` (public PEM or legacy name), `clientCertificate` (legacy name), `insecureSkipVerify`, and `caOptional`. A cross-boundary TLS validation pass checks every logical name against the configured legacy certificates before the transform resolves protected paths. File-backed or code-executing extensions such as plugins, template snippets, provider-specific middleware, and unrecognized additions fail closed. Direct provider-internal references are not accepted; the helper rejects native URL/address destinations that reach its configured admin listener.

## Tests and acceptance

`TraefikDynamicTests.fs` covers a mixed HTTP/TCP/UDP graph, ordered chain preservation, unqualified and explicit `@file` references, rejection of other providers and generated-name collisions, cycle detection, explicit entry-point protocols, TLS option/resolver references, h2c upstreams, public-PEM and logical CA inputs, rejection of private-key PEM and paths, legacy client-certificate reference shapes, and TCP PROXY/SNI settings. These tests establish validator behavior only. They do not prove that the pinned Traefik binary loads or routes a configuration; runtime acceptance remains an isolated guest gate in the main Traefik plan.
