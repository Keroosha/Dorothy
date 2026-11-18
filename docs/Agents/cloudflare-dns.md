# Cloudflare DNS records

The opt-in `Dorothy.DSL.Cloudflare` module is independent of `Host.deploy`. Open it only where its short DNS vocabulary is wanted.

```fsharp
module CloudflareQuickstart =
    open Dorothy.DSL.Cloudflare

    let records =
        cloudflare {
            domain "cybergulag.today" {
                dns {
                    a "edge-wildcard" {
                        name "*"
                        address "192.0.2.10"
                        proxy DnsOnly
                        Fields.comment "Edge wildcard"
                        Fields.tags [ "owner:dns" ]
                    }
                }
            }
        }

    type Stack() =
        inherit Pulumi.Stack()
        do deploy records |> ignore
```

Keep the Cloudflare `open` in a scope that does not also open another Dorothy DSL module. `name`, `address`, `proxy`, record blocks, and the root CE retain the compact vocabulary; other generic helpers use `[<RequireQualifiedAccess>]` `Fields` (for example `Fields.target`, `Fields.port`, and `Fields.content`) so they cannot shadow host builders. Output-valued fields use `Fields.*Output`, such as `Fields.addressOutput source.Ip`, preserving the Pulumi dependency without awaiting it.

## Zone selection and credentials

By default, each canonical domain is resolved through `cloudflare:index/getZones:getZones` using its normalized name. Optional `accountId` narrows that lookup:

```fsharp
module AccountFilteredDns =
    open Dorothy.DSL.Cloudflare

    let records =
        cloudflare {
            domain "cybergulag.today" {
                accountId "cloudflare-account-id"
                dns { a "apex" { name "@"; address "192.0.2.10" } }
            }
        }
```

The lookup filters for exact normalized domain equality and fails if zero or multiple exact zones are returned. It never takes the first result. Use `zoneId` to bypass lookup entirely:

```fsharp
module ExplicitZoneDns =
    open Dorothy.DSL.Cloudflare

    let records =
        cloudflare {
            domain "cybergulag.today" {
                zoneId "023e105f4ecef8ad9ca31a8372d0c353"
                dns { a "apex" { name "@"; address "192.0.2.10" } }
            }
        }
```

`zoneId` and `accountId` are mutually exclusive. Cloudflare provider credentials stay outside the spec: configure Pulumi's secret `cloudflare:apiToken` or `CLOUDFLARE_API_TOKEN`. The package does not place tokens in source or DNS declarations.

### Provider and resource lifecycle options

`zoneProvider` accepts an existing `Pulumi.ProviderResource` on a domain and sends that same provider to both `getZones` and every record. `Fields.protect true` prevents deletion; `Fields.aliases [ alias ]` supplies Pulumi aliases for a record-key migration. The DSL exposes these specific controls rather than a blanket `CustomResourceOptions`/`InvokeOptions` escape hatch; options such as arbitrary timeouts and `DependsOn` are not currently surfaced.

## Record types

Every record has a required owner `name`; type payload fields are listed below. `ttl` defaults to `Auto` (API value `1`); `Fields.ttl (Fixed seconds)`, `Fields.comment`, and `Fields.tags` are common options. Records accept per-record `Fields.protect` and `Fields.aliases`. Proxy settings are limited to A/AAAA/CNAME; `Proxied` requires automatic TTL. Other types are DNS-only.

| Block | Type-specific fields |
| --- | --- |
| `a`, `aaaa` | `address`; optional `proxy DnsOnly` or `proxy Proxied` |
| `cname`, `ns`, `ptr` | `Fields.target` |
| `mx` | `Fields.target`, top-level `Fields.priority` (0–65535; zero is valid for null MX) |
| `openpgpkey` | `Fields.content` |
| `txt` | exactly one of `Fields.text` or explicit `Fields.segments` |
| `caa` | numeric `Fields.flags`, `Fields.tag`, `Fields.value` (CAA tag is canonicalized to lowercase) |
| `cert` | `Fields.algorithm`, `Fields.certificate`, `Fields.keyTag`, numeric `Fields.certificateType` |
| `dnskey` | numeric `Fields.flags`/`Fields.algorithm`, protocol 3, `Fields.publicKey` |
| `ds` | numeric `Fields.algorithm`, `Fields.digest`, `Fields.digestType`, `Fields.keyTag` |
| `https`, `svcb` | `Fields.priority`, `Fields.target`, opaque SvcParams `Fields.value` inside typed data; no top-level priority |
| `loc` | `Fields.latitude`, `Fields.longitude` as `coordinate degrees minutes seconds hemisphere`; optional numeric `Fields.altitude`, `Fields.size`, `Fields.precisionHorz`, `Fields.precisionVert` |
| `naptr` | string `Fields.naptrFlags`, numeric `Fields.order`/`Fields.preference`, `Fields.regex`, `Fields.replacement`, `Fields.service` |
| `smimea`, `tlsa` | `Fields.certificate`, numeric `Fields.matchingType`, `Fields.selector`, `Fields.usage` |
| `srv` | numeric `Fields.port`, `Fields.priority`, `Fields.target`, `Fields.weight`; the one DSL priority is emitted in both `data.priority` and top-level `priority` |
| `sshfp` | numeric `Fields.algorithm`, `Fields.fingerprint`, `Fields.fingerprintType` |
| `uri` | opaque URI `Fields.target`, numeric `Fields.weight`, top-level `Fields.priority` |

The API intentionally does not expose SOA, pseudo-SPF/DKIM/DMARC types, or raw provider `data` objects. TXT text is quoted and DNS-presentation escaped; UTF-8 content is split at character boundaries into character strings no larger than 255 octets. Explicit `segments` preserves caller string boundaries and rejects segments over that limit. SPF/DKIM payload bytes are not rewritten.

`Fields.tags` accepts Cloudflare `name:value` tags: at most 20 tags, a 1–32 character ASCII name using letters, digits, `-`, or `_`, and a value of at most 100 Unicode characters. Cloudflare may restrict tag availability by zone plan; this DSL does not infer plan or entitlement. Comments reject CR/LF; no plan-specific comment-length cap is assumed locally. See [Cloudflare record attributes](https://developers.cloudflare.com/dns/manage-dns-records/reference/record-attributes/).

Owners are relative to the zone: `@`, `*`, `_dmarc`, `_sip._tcp`, `foo.bar`, and wildcard subdomains are accepted. U+3002, U+FF0E, and U+FF61 separators are normalized before splitting. Unicode labels become lowercase Punycode; ASCII underscores remain valid. Wildcards are allowed only in the leftmost owner label. A trailing-dot absolute owner must be in-zone; an owner already ending in the zone is not suffixed again.

DNS hostname targets can be external or in-zone. They are canonicalized label-wise and lose a final dot, so `host.example.` and `HOST.EXAMPLE` have one identity. Root `.` remains `.`; single-label hostnames and target wildcards are rejected. URI targets and NAPTR regex/service and TXT values are opaque. A requires canonical four-octet dotted-decimal IPv4 (legacy `0x7f000001`, abbreviated, and leading-zero forms are rejected); AAAA is emitted via `IPAddress.ToString()`. Output addresses and DNS targets are validated/canonicalized with `Apply`, preserving dependencies and leaving unknown preview values unknown.

LOC uses the pinned provider bounds: latitude/longitude seconds `0…59.999`, altitude `−100000…42849672.95`, and size/precision `0…90000000`. Latitude degrees are 0…90, longitude 0…180, minutes 0…59, and values at the maximum degree require zero minutes/seconds. Fixed TTL is 30…86400; Cloudflare may require 60 seconds outside Enterprise plans. Zone IDs are 32 hexadecimal characters.

## Stable names and import

The Pulumi logical resource name is exactly:

```text
cloudflare-dns-{canonicalDomain.Length}-{canonicalDomain}-{logicalKey.Length}-{logicalKey}
```

`canonicalDomain` is lowercase Punycode without a final dot; the validated ASCII logical key keeps its caller spelling. Length fields make the pair unambiguous. This name does not change with record type/content, order, TTL, or zone selector. For the example above it is `cloudflare-dns-16-cybergulag.today-13-edge-wildcard`.

Import one record with Pulumi's Cloudflare DnsRecord token and `<zoneId>/<recordId>` provider ID:

```sh
pulumi import cloudflare:index/dnsRecord:DnsRecord cloudflare-dns-16-cybergulag.today-13-edge-wildcard <zoneId>/<recordId>
```

Duplicate `(canonical domain, logical key)` identities and exact duplicate static records are rejected. Distinct keys can represent distinct members of the same RRset. `Dorothy.DSL.Cloudflare.deploy` registers one `Pulumi.Cloudflare.DnsRecord` per declaration; it does not create zones or wrapper components. Construction validates locally; no live apply or refresh has been verified. After CLI import, inspect `pulumi preview --diff` before applying because this DSL owns only its declared fields and does not model unrelated DNS settings.
