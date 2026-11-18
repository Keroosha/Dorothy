# Cloudflare DNS records

## Scope and consumer API

Add an independent opt-in `Dorothy.DSL.Cloudflare` module beside `Host.deploy`. It owns typed DNS record declarations only: no `HostSpec`/`DebianSpec` fields, SSH, native helper, zone resource, Pulumi component, SOA, pseudo-SPF/DKIM/DMARC record types, or raw provider data bag. `Cloudflare.deploy` registers exactly one `Pulumi.Cloudflare.DnsRecord` per declared record and returns those resources. The CE builds immutable specs and performs local validation only.

```fsharp
open Pulumi
open Dorothy.DSL.Cloudflare

let dns =
    cloudflare {
        domain "cybergulag.today" {
            // Optional: accountId "..." filters the lookup; zoneId "..." bypasses it.
            dns {
                a "edge-wildcard" {
                    name "*"
                    address "192.0.2.10"
                    proxy DnsOnly
                    // ttl Auto is the default; comment and tags are optional common fields.
                }
            }
        }
    }

type Stack() =
    inherit Pulumi.Stack()
    do Cloudflare.deploy dns |> ignore
```

`domain` accepts `accountId` or an explicit `zoneId` (mutually exclusive), plus one or more `dns` blocks. Each DNS block composes named record blocks. Logical keys are stable identities and are independent of owner names. The type builders and their type-specific fields are:

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
| `https`, `svcb` | `priority`, `target`, `value` | structured `data` only |
| `loc` | `latitude`, `longitude` via typed coordinates | optional `altitude`, `size`, `precisionHorz`, `precisionVert` |
| `naptr` | string `naptrFlags`, numeric `order`/`preference`, `regex`, `replacement`, `service` | strings remain distinct; only `replacement` is a DNS target |
| `smimea`, `tlsa` | `certificate`, `matchingType`, `selector`, `usage` | numeric fields remain integers |
| `srv` | `port`, `priority`, `target`, `weight` | one `priority` input is sent in both API locations (`data.priority` and top-level `priority`) |
| `sshfp` | `algorithm`, `fingerprint`, `fingerprintType` | numeric fields remain integers |
| `uri` | `target`, `weight` | top-level `priority`; URI target is opaque and never hostname-expanded |

All records share `name`, optional `ttl`, `comment`, and `tags`. `ttl` is `Auto` (API value `1`, default) or `Fixed seconds`; fixed values are limited locally to 30–86400 because Enterprise zones allow a 30-second minimum, while Cloudflare may require 60 seconds on other plans. `DnsOnly`/`Proxied` are expressible only for A/AAAA/CNAME; `Proxied` requires automatic TTL, and all other types are DNS-only. Static string fields use their base helper; the corresponding `*Output` helpers accept `Pulumi.Output<string>` and preserve dependencies without awaiting them.

## Canonicalization, identity, and validation

- Canonicalize the zone to lowercase label-wise IDNA/Punycode without a final dot. Validate a non-empty DNS zone and enforce DNS label/overall length limits.
- Owner names are relative to the zone: `@` is apex, `*`, `_dmarc`, `_sip._tcp`, `foo.bar`, and wildcard labels are preserved. An absolute owner with a final dot must be in-zone; a full owner already ending in the canonical zone is recognized without appending the zone again. Convert each label to Punycode while allowing valid ASCII underscores and `*` labels.
- DNS hostname targets are not restricted to the managed zone; external and in-zone names remain valid. Preserve root `.`. Canonicalize DNS-name targets label-wise, but never treat TXT, NAPTR regex/service, or URI values as hostnames.
- TXT `text` is emitted as DNS presentation strings, quoted and escaped, with UTF-8 octets split on boundaries into at most 255-octet character strings. `segments` retains caller-supplied string boundaries and rejects any segment over 255 octets. Escaping preserves SPF/DKIM/TXT payload bytes.
- Reject empty/invalid logical keys, missing required record fields, duplicate `(canonical domain, logical key)` identities, repeated singleton fields, unsupported proxy/TTL combinations, and provider-hard local numeric/format violations. Do not infer zone-plan facts or resolve outputs/tasks during validation. Distinct keys allow distinct RRset members at one owner.

Each resource name is exactly `cloudflare-dns-{canonicalDomain.Length}-{canonicalDomain}-{logicalKey.Length}-{logicalKey}`; domain is lowercase Punycode without a final dot and key is the validated caller spelling. Length fields make domains/keys unambiguous. For the example, the resource name is `cloudflare-dns-16-cybergulag.today-13-edge-wildcard`. Import uses `cloudflare:index/dnsRecord:DnsRecord` and `<zoneId>/<recordId>`:

```sh
pulumi import cloudflare:index/dnsRecord:DnsRecord cloudflare-dns-16-cybergulag.today-13-edge-wildcard <zoneId>/<recordId>
```

## Zone resolution and package policy

Without `zoneId`, invoke `cloudflare:index/getZones:getZones` once per canonical domain, querying by exact normalized name and optional account ID, then filter returned results for exact canonical name equality. Reject zero and multiple exact matches; never select the first result. Use the resulting `Output<string>` as each record's `zoneId`, constructing resources outside `Apply`. A supplied `zoneId` bypasses lookup. Cloudflare credentials are provider configuration only: use Pulumi's secret `cloudflare:apiToken` or `CLOUDFLARE_API_TOKEN`; no token belongs in a spec.

Pin `Pulumi.Cloudflare` 6.24.0 and raise Dorothy's direct `Pulumi` dependency from 3.116.2 to its minimum compatible 3.118.0. The package uses exact project-level `PackageReference` versions; no central package management policy exists in this repository.

## Verification boundaries

Use `Deployment.TestAsync`/`IMocks` to inspect real Pulumi serialized arguments for all 21 record types, with mocked zone lookups only. Cover IDN, wildcard/underscore owners, explicit-zone lookup bypass, zero/multiple exact zones, separate same-owner RRset members, MX zero/root target, SRV dual priority, long quoted TXT, validation failures, and an A/AAAA `Output<string>` dependency using `addressOutput`. Tests must not use Cloudflare credentials or contact a live zone. No apply/refresh claim is made; those require a separate migration/sandbox review.
