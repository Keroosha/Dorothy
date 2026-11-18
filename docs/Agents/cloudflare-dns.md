# Cloudflare DNS records

The opt-in `Dorothy.DSL.Cloudflare` module is independent of `Host.deploy`. Open it only where its short DNS vocabulary is wanted.

```fsharp
open Pulumi
open Dorothy.DSL.Cloudflare

let records =
    cloudflare {
        domain "cybergulag.today" {
            dns {
                a "edge-wildcard" {
                    name "*"
                    address "192.0.2.10"
                    proxy DnsOnly
                    comment "Edge wildcard"
                    tags [ "owner:dns" ]
                }
            }
        }
    }

type Stack() =
    inherit Pulumi.Stack()
    do Cloudflare.deploy records |> ignore
```

A named record key (here `edge-wildcard`) is its stable Pulumi identity; `name` is the DNS owner. Static values use field helpers such as `address` and `target`; output-valued fields use their `*Output` counterpart (`addressOutput`, `targetOutput`, `contentOutput`, `textOutput`, `valueOutput`, `certificateOutput`, `publicKeyOutput`, `digestOutput`, `regexOutput`, `replacementOutput`, `serviceOutput`, `fingerprintOutput`). For example, `addressOutput source.Ip` accepts a `Pulumi.Output<string>` and preserves the Pulumi dependency; the DSL never awaits it.

## Zone selection and credentials

By default, each canonical domain is resolved through `cloudflare:index/getZones:getZones` using its normalized name. Optional `accountId` narrows that lookup:

```fsharp
domain "cybergulag.today" {
    accountId "cloudflare-account-id"
    dns { a "apex" { name "@"; address "192.0.2.10" } }
}
```

The lookup filters for exact normalized domain equality and fails if zero or multiple exact zones are returned. It never takes the first result. Use `zoneId` to bypass lookup entirely:

```fsharp
domain "cybergulag.today" {
    zoneId "023e105f4ecef8ad9ca31a8372d0c353"
    dns { a "apex" { name "@"; address "192.0.2.10" } }
}
```

`zoneId` and `accountId` are mutually exclusive. Cloudflare provider credentials stay outside the spec: configure Pulumi's secret `cloudflare:apiToken` or `CLOUDFLARE_API_TOKEN`. The package does not place tokens in source or DNS declarations.

## Record types

Every block has a required owner `name` and required type payload. `ttl` defaults to `Auto` (Cloudflare API value `1`); `Fixed seconds`, `comment`, and `tags` are common optional fields. Proxy options are limited to A/AAAA/CNAME; `Proxied` requires automatic TTL. Other types are DNS-only.

| Block | Type-specific fields |
| --- | --- |
| `a`, `aaaa` | `address`; optional `proxy DnsOnly` or `proxy Proxied` |
| `cname`, `ns`, `ptr` | `target` |
| `mx` | `target`, top-level `priority` (zero is valid; use `target "."; priority 0` for null MX) |
| `openpgpkey` | `content` |
| `txt` | exactly one of `text` or `segments` |
| `caa` | `flags`, `tag`, `value` |
| `cert` | `algorithm`, `certificate`, `keyTag`, numeric `certificateType` |
| `dnskey` | numeric `flags`, `algorithm`, `protocol`, `publicKey` |
| `ds` | `algorithm`, `digest`, `digestType`, `keyTag` |
| `https`, `svcb` | structured `priority`, `target`, `value` |
| `loc` | `latitude`, `longitude` as `coordinate degrees minutes seconds hemisphere`; optional numeric `altitude`, `size`, `precisionHorz`, `precisionVert` |
| `naptr` | string `naptrFlags`, numeric `order`/`preference`, `regex`, `replacement`, `service` |
| `smimea`, `tlsa` | `certificate`, numeric `matchingType`, `selector`, `usage` |
| `srv` | numeric `port`, `priority`, `target`, `weight`; the one DSL priority is emitted in both `data.priority` and top-level `priority` |
| `sshfp` | numeric `algorithm`, `fingerprint`, `fingerprintType` |
| `uri` | URI `target`, numeric `weight`, top-level `priority` |

The API intentionally does not expose SOA, pseudo-SPF/DKIM/DMARC types, or raw provider `data` objects. TXT text is quoted and DNS-presentation escaped; UTF-8 content is split at character boundaries into character strings no larger than 255 octets. Explicit `segments` preserves caller string boundaries and rejects segments over that limit. SPF/DKIM payload bytes are not rewritten.

Owners are relative to their domain: `@`, `*`, `_dmarc`, `_sip._tcp`, `foo.bar`, and wildcard subdomains are accepted. Unicode labels are converted label-by-label to lowercase Punycode; valid ASCII underscores and wildcard labels remain intact. A trailing-dot absolute owner must be in-zone; an owner already ending in the zone is not suffixed a second time. DNS-name targets can be external or in-zone and are canonicalized label-wise without appending the zone. Root target `.` remains `.`. URI values and NAPTR regex/service and TXT payloads are not treated as hostnames.

Fixed TTLs are limited locally to 30–86400 seconds. Cloudflare permits 30 seconds on Enterprise zones; other plans may require 60 seconds, which can only be confirmed by the selected zone. Numeric zero and root targets are preserved.

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

Duplicate `(canonical domain, logical key)` identities and exact duplicate static records are rejected. Distinct keys can represent distinct members of the same RRset. `Cloudflare.deploy` registers one `Pulumi.Cloudflare.DnsRecord` per declaration; it does not create zones or wrapper components. CE construction validates local shape and constraints only. No live apply, refresh, or migration is implied; those need a separate isolated migration/sandbox review.
