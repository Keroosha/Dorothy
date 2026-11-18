# Cloudflare DNS records

## Scope and consumer API

Add an independent opt-in `Dorothy.DSL.Cloudflare` module beside `Host.deploy`. It owns typed DNS record declarations only: no `HostSpec`/`DebianSpec` fields, SSH, native helper, zone resource, Pulumi component, SOA, pseudo-SPF/DKIM/DMARC record types, or raw provider data bag. `Cloudflare.deploy` registers exactly one `Pulumi.Cloudflare.DnsRecord` per declared record and returns those resources. The CE builds immutable specs and performs local validation only.

```fsharp
module CloudflareQuickstart =
    open Dorothy.DSL.Cloudflare

    let dns =
        cloudflare {
            domain "cybergulag.today" {
                // Optional: accountId "..." filters lookup; zoneId "..." bypasses it.
                dns {
                    a "edge-wildcard" {
                        name "*"
                        address "192.0.2.10"
                        proxy DnsOnly
                        // ttl Auto is the default; comment and tags are optional.
                    }
                }
            }
        }

    type Stack() =
        inherit Pulumi.Stack()
        do deploy dns |> ignore
```

`domain` accepts `accountId` or explicit `zoneId` (mutually exclusive), an optional `zoneProvider` (`Pulumi.ProviderResource`), and one or more `dns` blocks. `zoneProvider` is applied to both the `getZones` invoke and every record. Each DNS block composes named record blocks; logical keys are stable identities and are independent of owner names. All 21 type builders and payload fields are listed below.

| Block | Required record value / data | Additional typed fields |
| --- | --- | --- |
| `a`, `aaaa` | `address` | `proxy` (defaults to `DnsOnly`) |
| `cname`, `ns`, `ptr` | `target` | — |
| `mx` | `target` | `priority` (including zero) |
| `openpgpkey` | `content` | — |
| `txt` | `text` or explicit `segments` | — |
| `caa` | `flags`, `tag`, `value` | — |
| `cert` | `algorithm`, `certificate`, `keyTag`, `certificateType` | numeric fields remain integers |
| `dnskey` | `flags`, `algorithm`, `protocol`, `publicKey` | numeric fields remain integers |
| `ds` | `algorithm`, `digest`, `digestType`, `keyTag` | numeric fields remain integers |
| `https`, `svcb` | typed `priority`, `target`, opaque SvcParams `value` |
| `loc` | `latitude`, `longitude` via typed coordinates | optional `altitude`, `size`, `precisionHorz`, `precisionVert` |
| `naptr` | string `naptrFlags`, numeric `order`/`preference`, `regex`, `replacement`, `service` | strings remain distinct; only `replacement` is a DNS target |
| `smimea`, `tlsa` | `certificate`, `matchingType`, `selector`, `usage` | numeric fields remain integers |
| `srv` | `port`, `priority`, `target`, `weight` | one `priority` input is sent in both API locations (`data.priority` and top-level `priority`) |
| `sshfp` | `algorithm`, `fingerprint`, `fingerprintType` | numeric fields remain integers |
| `uri` | `target`, `weight` | top-level `priority`; URI target is opaque and never hostname-expanded |

Common fields are `name`, optional `ttl`, `comment`, and `tags`; per-record Pulumi safety options are `Fields.protect` and `Fields.aliases`. `ttl` is `Auto` (API value `1`, default) or `Fixed seconds`; fixed values are locally limited to 30–86400 because Enterprise zones allow a 30-second minimum, while other plans may require 60 seconds. Proxy settings are expressible only for A/AAAA/CNAME; `Proxied` requires automatic TTL. Generic field helpers live in the `[<RequireQualifiedAccess>] Fields` module (`Fields.target`, `Fields.priority`, `Fields.comment`, etc.) so opening the opt-in module does not shadow other Dorothy builders.

Tags follow Cloudflare `name:value` syntax: maximum 20, name 1–32 ASCII letters/digits/`-`/`_`, value at most 100 Unicode characters. The grammar validates this shape but does not infer plan-based tag availability. Comments reject CR/LF; no plan-specific length limit is assumed locally. See [Cloudflare record attributes](https://developers.cloudflare.com/dns/manage-dns-records/reference/record-attributes/).

## Canonicalization, identity, and validation

 - Normalize U+3002, U+FF0E, and U+FF61 to ASCII dots before trailing-dot handling or splitting. Canonicalize the zone to lowercase label-wise IDNA/Punycode without a final dot; validate DNS label/overall length and a 32-hex explicit `zoneId`.
 - Owner names are relative to the zone: `@` is apex, `_dmarc`, `_sip._tcp`, `foo.bar`, and wildcard owners are accepted; `*` is allowed only as the leftmost label. A final-dot absolute owner must be in-zone, and an already-qualified owner is not suffixed again.
 - DNS hostname targets are canonicalized label-wise to lowercase Punycode without a final dot; external and in-zone FQDNs remain valid and single-label hostnames are rejected. Root `.` is preserved. Wildcards are rejected in targets; URI values and NAPTR regex/service and TXT payloads are never treated as hostnames.
 - A accepts only canonical four-octet dotted-decimal IPv4 (no legacy, abbreviated, hex, or leading-zero spellings); AAAA accepts bare, unscoped IPv6 literals only, rejecting bracketed endpoints and `%` scope syntax before parsing, and emits `IPAddress.ToString()` canonical form. Known Output values are normalized and validated via `Apply`; unknown outputs remain dependencies and are not forced.
 - TXT `text` is emitted as DNS presentation strings, quoted and escaped, with UTF-8 octets split at character boundaries into at most 255-octet strings. Explicit `segments` preserves boundaries and rejects any segment over 255 octets. SPF/DKIM/TXT payload bytes are preserved.
 - Reject invalid logical keys, missing required fields, duplicate `(canonical domain, logical key)` identities, duplicate static records after canonicalization, repeated singleton fields, unsupported proxy/TTL combinations, and the provider-hard numeric limits below. Distinct RRset members at one owner remain allowed.

Each resource name is exactly `cloudflare-dns-{canonicalDomain.Length}-{canonicalDomain}-{logicalKey.Length}-{logicalKey}`; domain is lowercase Punycode without a final dot and key is the validated caller spelling. Length fields make domains/keys unambiguous. For the example, the resource name is `cloudflare-dns-16-cybergulag.today-13-edge-wildcard`. Import uses `cloudflare:index/dnsRecord:DnsRecord` and `<zoneId>/<recordId>`:

```sh
pulumi import cloudflare:index/dnsRecord:DnsRecord cloudflare-dns-16-cybergulag.today-13-edge-wildcard <zoneId>/<recordId>
```

## Zone resolution and package policy
Without `zoneId`, invoke `cloudflare:index/getZones:getZones` once per canonical domain, querying by exact normalized name and optional account ID, then filter returned results for exact canonical equality. Reject zero and multiple exact matches; never select the first result. A supplied `zoneId` bypasses lookup. Cloudflare credentials remain provider configuration only: Pulumi secret `cloudflare:apiToken` or `CLOUDFLARE_API_TOKEN`.

Pin `Pulumi.Cloudflare` 6.24.0 and raise Dorothy's direct `Pulumi` dependency from 3.116.2 to its minimum compatible 3.118.0. The package uses exact project-level `PackageReference` versions; no central package management policy exists in this repository.

`Fields.protect true`, `Fields.aliases [ alias ]`, and domain-level `zoneProvider provider` are the narrow Pulumi lifecycle hook. The same provider resource is passed to zone lookup and each `DnsRecord`. The DSL intentionally does not accept a blanket `CustomResourceOptions`/`InvokeOptions` bag; other options such as arbitrary timeouts or `DependsOn` are not currently surfaced. Review `pulumi preview --diff` before applying imported records; this grammar only models its declared fields and no import/update behavior was live-verified.

## Verification boundaries

Use `Deployment.TestAsync`/`IMocks` to inspect exact serialized arguments for all 21 record types, mocked zone lookup/provider routing, unknown preview inputs and output dependencies. Cover IDN and Unicode dot separators, wildcard/underscore owners, explicit-zone bypass, zero/multiple exact zones, same-owner RRsets and canonical duplicate rejection, IPv4/IPv6 normalization, MX/LOC numeric limits, SRV dual priority, long TXT, scoped Host+Cloudflare composition, and resource options. Tests must not use Cloudflare credentials or contact a live zone. TXT presentation round-trip, import/refresh, apply, and production behavior remain unverified; those require a separate isolated sandbox/migration review.
