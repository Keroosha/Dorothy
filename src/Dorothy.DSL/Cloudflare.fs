namespace Dorothy.DSL

open System
open System.Collections.Generic
open System.Globalization
open System.Net
open System.Net.Sockets
open System.Text
open Pulumi

module Cloudflare =
    type Proxy =
        | DnsOnly
        | Proxied

    type Ttl =
        | Auto
        | Fixed of seconds: int

    type Hemisphere =
        | North
        | South
        | East
        | West

    type Coordinate =
        { Degrees: int
          Minutes: int
          Seconds: float
          Hemisphere: Hemisphere }

    type internal StringInput =
        | LiteralString of string
        | OutputString of Output<string>

    type internal RecordKind =
        | A
        | Aaaa
        | Cname
        | Mx
        | Ns
        | OpenPgpKey
        | Ptr
        | Txt
        | Caa
        | Cert
        | DnsKey
        | Ds
        | Https
        | Loc
        | Naptr
        | Smimea
        | Srv
        | Sshfp
        | Svcb
        | Tlsa
        | Uri

    type internal DnsData =
        | CaaData of flags: int * tag: string * value: StringInput
        | CertData of algorithm: int * certificate: StringInput * keyTag: int * certificateType: int
        | DnsKeyData of flags: int * algorithm: int * protocol: int * publicKey: StringInput
        | DsData of algorithm: int * digest: StringInput * digestType: int * keyTag: int
        | HttpsData of priority: int * target: StringInput * value: StringInput
        | LocData of latitude: Coordinate * longitude: Coordinate * altitude: float option * size: float option * precisionHorz: float option * precisionVert: float option
        | NaptrData of flags: string * order: int * preference: int * regex: StringInput * replacement: StringInput * service: StringInput
        | SmimeaData of certificate: StringInput * matchingType: int * selector: int * usage: int
        | SrvData of port: int * priority: int * target: StringInput * weight: int
        | SshfpData of algorithm: int * fingerprint: StringInput * fingerprintType: int
        | SvcbData of priority: int * target: StringInput * value: StringInput
        | TlsaData of certificate: StringInput * matchingType: int * selector: int * usage: int
        | UriData of target: StringInput * weight: int

    type internal RecordValue =
        | AddressValue of StringInput
        | TargetValue of StringInput
        | ContentValue of StringInput
        | TxtTextValue of StringInput
        | TxtSegmentsValue of string list

    type RecordField =
        internal
        | OwnerName of string
        | RecordAddress of StringInput
        | RecordTarget of StringInput
        | RecordContent of StringInput
        | TxtText of StringInput
        | TxtSegments of string list
        | NumberFlags of int
        | TextFlags of string
        | CaaTag of string
        | DataValue of StringInput
        | Algorithm of int
        | Certificate of StringInput
        | KeyTag of int
        | CertificateType of int
        | Protocol of int
        | PublicKey of StringInput
        | Digest of StringInput
        | DigestType of int
        | Priority of int
        | Port of int
        | Weight of int
        | Latitude of Coordinate
        | Longitude of Coordinate
        | Altitude of float
        | Size of float
        | PrecisionHorz of float
        | PrecisionVert of float
        | NaptrOrder of int
        | Preference of int
        | Regex of StringInput
        | Replacement of StringInput
        | Service of StringInput
        | MatchingType of int
        | Selector of int
        | Usage of int
        | Fingerprint of StringInput
        | FingerprintType of int
        | Ttl of Ttl
        | Proxy of Proxy
        | Comment of string
        | RecordTags of string list
        | Protect of bool
        | RecordAliases of Alias list

    [<Sealed>]
    type RecordSpec internal
        (logicalKey: string,
         kind: RecordKind,
         ownerName: string,
         value: RecordValue option,
         data: DnsData option,
         priority: int option,
         ttl: Ttl,
         proxy: Proxy,
         comment: string option,
         tags: string list,
         protect: bool option,
         aliases: Alias list,
         fingerprint: string option) =
        member _.LogicalKey = logicalKey
        member _.OwnerName = ownerName
        member _.RecordType =
            match kind with
            | A -> "A"
            | Aaaa -> "AAAA"
            | Cname -> "CNAME"
            | Mx -> "MX"
            | Ns -> "NS"
            | OpenPgpKey -> "OPENPGPKEY"
            | Ptr -> "PTR"
            | Txt -> "TXT"
            | Caa -> "CAA"
            | Cert -> "CERT"
            | DnsKey -> "DNSKEY"
            | Ds -> "DS"
            | Https -> "HTTPS"
            | Loc -> "LOC"
            | Naptr -> "NAPTR"
            | Smimea -> "SMIMEA"
            | Srv -> "SRV"
            | Sshfp -> "SSHFP"
            | Svcb -> "SVCB"
            | Tlsa -> "TLSA"
            | Uri -> "URI"
        member internal _.Kind = kind
        member internal _.Value = value
        member internal _.Data = data
        member internal _.Priority = priority
        member internal _.Ttl = ttl
        member internal _.Proxy = proxy
        member internal _.Comment = comment
        member internal _.Tags = tags
        member internal _.Protect = protect
        member internal _.Aliases = aliases
        member internal _.Fingerprint = fingerprint

    [<Sealed>]
    type DnsSpec internal (records: RecordSpec list) =
        member _.Records = records

    type DomainField =
        internal
        | AccountId of string
        | ZoneId of string
        | ZoneProvider of ProviderResource
        | Dns of DnsSpec

    [<Sealed>]
    type DomainSpec internal (name: string, accountId: string option, zoneId: string option, provider: ProviderResource option, records: RecordSpec list) =
        member _.Name = name
        member _.AccountId = accountId
        member _.ZoneId = zoneId
        member _.Provider = provider
        member _.Records = records

    [<Sealed>]
    type Spec internal (domains: DomainSpec list) =
        member _.Domains = domains



    module private Validation =
        let private invalid label message = invalidArg label message

        let private isAscii value = value |> Seq.forall (fun character -> int character <= 0x7f)
        let private validateZoneId (value: string) =
            if String.IsNullOrWhiteSpace value
               || value.Length <> 32
               || not (value |> Seq.forall (fun character ->
                   Char.IsAsciiDigit character
                   || (character >= 'a' && character <= 'f')
                   || (character >= 'A' && character <= 'F'))) then
                invalid "zoneId" "A Cloudflare zone ID must be 32 hexadecimal characters."

        let private idnAscii label (value: string) =
            try
                let idn = IdnMapping()
                idn.UseStd3AsciiRules <- true
                idn.GetAscii(value).ToLowerInvariant()
            with :? ArgumentException -> invalid "name" (sprintf "Invalid DNS label '%s'." label)
        let private normalizeSeparators (value: string) =
            value.Replace('\u3002', '.').Replace('\uff0e', '.').Replace('\uff61', '.')

        let private ownerLabel (label: string) =
            if String.IsNullOrEmpty label then invalid "name" "DNS names cannot contain empty labels."
            if label = "*" then label
            elif isAscii label && label.Contains('*') then invalid "name" "A wildcard must be an entire DNS label."
            elif isAscii label && label.Contains('_') then
                if label.Length > 63
                   || label[0] = '-'
                   || label[label.Length - 1] = '-'
                   || not (label |> Seq.forall (fun character -> Char.IsAsciiLetterOrDigit character || character = '_' || character = '-')) then
                    invalid "name" (sprintf "Invalid DNS label '%s'." label)
                label.ToLowerInvariant()
            else
                let ascii = idnAscii label label
                if ascii.Length > 63 || ascii.StartsWith("-", StringComparison.Ordinal) || ascii.EndsWith("-", StringComparison.Ordinal) then
                    invalid "name" (sprintf "Invalid DNS label '%s'." label)
                ascii

        let normalizeDomain (value: string) =
            if String.IsNullOrWhiteSpace value then invalid "domain" "A non-empty Cloudflare zone name is required."
            let value = normalizeSeparators value
            let withoutFinalDot = if value.EndsWith(".", StringComparison.Ordinal) then value.Substring(0, value.Length - 1) else value
            if String.IsNullOrEmpty withoutFinalDot then invalid "domain" "A non-empty Cloudflare zone name is required."
            let labels = withoutFinalDot.Split('.')
            if labels |> Array.exists String.IsNullOrEmpty then invalid "domain" "A DNS zone cannot contain empty labels."
            let canonical = labels |> Array.map (fun label -> idnAscii label label)
            if canonical |> Array.exists (fun label -> label.Length > 63 || label.StartsWith("-", StringComparison.Ordinal) || label.EndsWith("-", StringComparison.Ordinal)) then
                invalid "domain" "Each DNS zone label must be at most 63 octets and cannot start or end with a hyphen."
            let name = String.Join(".", canonical)
            if Encoding.ASCII.GetByteCount(name) > 253 then invalid "domain" "A DNS zone name cannot exceed 253 octets."
            name

        let normalizeOwner (domain: string) (value: string) =
            if String.IsNullOrWhiteSpace value then invalid "name" "A DNS record owner name is required."
            let value = normalizeSeparators value
            if value = "@" then domain
            else
                let trailingDot = value.EndsWith(".", StringComparison.Ordinal)
                let withoutFinalDot = if trailingDot then value.Substring(0, value.Length - 1) else value
                if String.IsNullOrEmpty withoutFinalDot then invalid "name" "A DNS record owner name is required."
                let labels = withoutFinalDot.Split('.')
                if labels |> Array.exists String.IsNullOrEmpty then invalid "name" "A DNS record owner cannot contain empty labels."
                let canonicalLabels = labels |> Array.map ownerLabel
                if canonicalLabels |> Array.mapi (fun index label -> index, label) |> Array.exists (fun (index, label) -> label = "*" && index <> 0) then
                    invalid "name" "A wildcard owner label is only valid at the leftmost position."
                let canonical = String.Join(".", canonicalLabels)
                let inZone =
                    String.Equals(canonical, domain, StringComparison.OrdinalIgnoreCase)
                    || canonical.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase)
                if trailingDot && not inZone then invalid "name" "An absolute DNS owner name must be inside its declared zone."
                let owner =
                    if inZone then canonical
                    else canonical + "." + domain
                if Encoding.ASCII.GetByteCount(owner) > 253 then invalid "name" "A DNS record owner name cannot exceed 253 octets."
                owner

        let normalizeTarget (value: string) =
            if isNull value then invalid "target" "A DNS target cannot be null."
            let value = normalizeSeparators value
            if value = "." then "."
            else
                if String.IsNullOrWhiteSpace value then invalid "target" "A DNS target cannot be empty."
                let trailingDot = value.EndsWith(".", StringComparison.Ordinal)
                let withoutFinalDot = if trailingDot then value.Substring(0, value.Length - 1) else value
                if String.IsNullOrEmpty withoutFinalDot then invalid "target" "A DNS target cannot be empty."
                let labels = withoutFinalDot.Split('.')
                if labels |> Array.exists String.IsNullOrEmpty then invalid "target" "A DNS target cannot contain empty labels."
                let canonicalLabels = labels |> Array.map ownerLabel
                if canonicalLabels |> Array.exists ((=) "*") then invalid "target" "DNS hostname targets cannot contain wildcard labels."
                if canonicalLabels.Length < 2 then invalid "target" "DNS hostname targets must contain at least two labels, or be root '.'."
                let canonical = String.Join(".", canonicalLabels)
                if Encoding.ASCII.GetByteCount(canonical) > 253 then invalid "target" "A DNS target cannot exceed 253 octets."
                canonical


        let private mapInput (transform: string -> string) (value: StringInput) : Input<string> =
            match value with
            | LiteralString text -> Input<string>.op_Implicit (transform text)
            | OutputString output -> Input<string>.op_Implicit (output.Apply(Func<string, string>(transform)))

        let private byteEscape (bytes: byte array) =
            let builder = StringBuilder(bytes.Length + 8)
            for value in bytes do
                if value = 0x22uy then builder.Append("\\\"") |> ignore
                elif value = 0x5cuy then builder.Append("\\\\") |> ignore
                elif value >= 0x20uy && value <= 0x7euy then builder.Append(char value) |> ignore
                else
                    builder.Append('\\').Append(int value |> fun number -> number.ToString("D3", CultureInfo.InvariantCulture)) |> ignore
            builder.ToString()

        let private txtSegment (value: string) =
            let bytes = Encoding.UTF8.GetBytes(value)
            if bytes.Length > 255 then invalid "segments" "A TXT segment cannot exceed 255 UTF-8 octets."
            "\"" + byteEscape bytes + "\""

        let private encodeTxtSegments (segments: string list) =
            if List.isEmpty segments then invalid "segments" "A TXT record requires at least one segment."
            segments |> List.map txtSegment |> String.concat " "

        let private encodeTxtText (text: string) =
            if isNull text then invalid "text" "TXT text cannot be null."
            let bytes = Encoding.UTF8.GetBytes(text)
            if bytes.Length = 0 then "\"\""
            else
                let chunks = ResizeArray<string>()
                let mutable start = 0
                while start < bytes.Length do
                    let mutable finish = min bytes.Length (start + 255)
                    if finish < bytes.Length then
                        while finish > start && (bytes[finish] &&& 0xc0uy) = 0x80uy do
                            finish <- finish - 1
                    if finish = start then invalid "text" "Unable to split TXT text at a UTF-8 boundary."
                    let chunk = Array.sub bytes start (finish - start)
                    chunks.Add("\"" + byteEscape chunk + "\"")
                    start <- finish
                String.Join(" ", chunks)

        let private fieldName = function
            | OwnerName _ -> "name"
            | RecordAddress _ -> "address"
            | RecordTarget _ -> "target"
            | RecordContent _ -> "content"
            | TxtText _ -> "text"
            | TxtSegments _ -> "segments"
            | NumberFlags _ -> "flags"
            | TextFlags _ -> "naptrFlags"
            | CaaTag _ -> "tag"
            | DataValue _ -> "value"
            | Algorithm _ -> "algorithm"
            | Certificate _ -> "certificate"
            | KeyTag _ -> "keyTag"
            | CertificateType _ -> "certificateType"
            | Protocol _ -> "protocol"
            | PublicKey _ -> "publicKey"
            | Digest _ -> "digest"
            | DigestType _ -> "digestType"
            | Priority _ -> "priority"
            | Port _ -> "port"
            | Weight _ -> "weight"
            | Latitude _ -> "latitude"
            | Longitude _ -> "longitude"
            | Altitude _ -> "altitude"
            | Size _ -> "size"
            | PrecisionHorz _ -> "precisionHorz"
            | PrecisionVert _ -> "precisionVert"
            | NaptrOrder _ -> "order"
            | Preference _ -> "preference"
            | Regex _ -> "regex"
            | Replacement _ -> "replacement"
            | Service _ -> "service"
            | MatchingType _ -> "matchingType"
            | Selector _ -> "selector"
            | Usage _ -> "usage"
            | Fingerprint _ -> "fingerprint"
            | FingerprintType _ -> "fingerprintType"
            | Ttl _ -> "ttl"
            | Proxy _ -> "proxy"
            | Comment _ -> "comment"
            | RecordTags _ -> "tags"
            | Protect _ -> "protect"
            | RecordAliases _ -> "aliases"

        let private recordType = function
            | A -> "A"
            | Aaaa -> "AAAA"
            | Cname -> "CNAME"
            | Mx -> "MX"
            | Ns -> "NS"
            | OpenPgpKey -> "OPENPGPKEY"
            | Ptr -> "PTR"
            | Txt -> "TXT"
            | Caa -> "CAA"
            | Cert -> "CERT"
            | DnsKey -> "DNSKEY"
            | Ds -> "DS"
            | Https -> "HTTPS"
            | Loc -> "LOC"
            | Naptr -> "NAPTR"
            | Smimea -> "SMIMEA"
            | Srv -> "SRV"
            | Sshfp -> "SSHFP"
            | Svcb -> "SVCB"
            | Tlsa -> "TLSA"
            | Uri -> "URI"

        let private allowedFields kind =
            let common = [ "name"; "ttl"; "comment"; "tags"; "protect"; "aliases" ]
            let specific =
                match kind with
                | A | Aaaa -> [ "address"; "proxy" ]
                | Cname -> [ "target"; "proxy" ]
                | Ns | Ptr -> [ "target" ]
                | Mx -> [ "target"; "priority" ]
                | OpenPgpKey -> [ "content" ]
                | Txt -> [ "text"; "segments" ]
                | Caa -> [ "flags"; "tag"; "value" ]
                | Cert -> [ "algorithm"; "certificate"; "keyTag"; "certificateType" ]
                | DnsKey -> [ "flags"; "algorithm"; "protocol"; "publicKey" ]
                | Ds -> [ "algorithm"; "digest"; "digestType"; "keyTag" ]
                | Https | Svcb -> [ "priority"; "target"; "value" ]
                | Loc -> [ "latitude"; "longitude"; "altitude"; "size"; "precisionHorz"; "precisionVert" ]
                | Naptr -> [ "naptrFlags"; "order"; "preference"; "regex"; "replacement"; "service" ]
                | Smimea | Tlsa -> [ "certificate"; "matchingType"; "selector"; "usage" ]
                | Srv -> [ "port"; "priority"; "target"; "weight" ]
                | Sshfp -> [ "algorithm"; "fingerprint"; "fingerprintType" ]
                | Uri -> [ "priority"; "target"; "weight" ]
            Set.ofList (common @ specific)

        let private getText key (parts: RecordField list) =
            parts
            |> List.tryPick (fun part ->
                if fieldName part <> key then None
                else
                    match part with
                    | RecordAddress value
                    | RecordTarget value
                    | RecordContent value
                    | TxtText value
                    | DataValue value
                    | Certificate value
                    | PublicKey value
                    | Digest value
                    | Regex value
                    | Replacement value
                    | Service value
                    | Fingerprint value -> Some value
                    | _ -> None)

        let private getInt key (parts: RecordField list) =
            parts
            |> List.tryPick (fun part ->
                if fieldName part <> key then None
                else
                    match part with
                    | NumberFlags value
                    | Algorithm value
                    | KeyTag value
                    | CertificateType value
                    | Protocol value
                    | DigestType value
                    | Priority value
                    | Port value
                    | Weight value
                    | NaptrOrder value
                    | Preference value
                    | MatchingType value
                    | Selector value
                    | Usage value
                    | FingerprintType value -> Some value
                    | _ -> None)

        let private getFloat key (parts: RecordField list) =
            parts
            |> List.tryPick (fun part ->
                if fieldName part <> key then None
                else
                    match part with
                    | Altitude value
                    | Size value
                    | PrecisionHorz value
                    | PrecisionVert value -> Some value
                    | _ -> None)

        let private getCoordinate key (parts: RecordField list) =
            parts
            |> List.tryPick (fun part ->
                if fieldName part <> key then None
                else
                    match part with
                    | Latitude value
                    | Longitude value -> Some value
                    | _ -> None)

        let private getString key (parts: RecordField list) =
            parts
            |> List.tryPick (fun part ->
                if fieldName part <> key then None
                else
                    match part with
                    | OwnerName value
                    | CaaTag value
                    | TextFlags value
                    | Comment value -> Some value
                    | _ -> None)

        let private requiredText kind key parts =
            getText key parts
            |> Option.defaultWith (fun () -> invalid "record" (sprintf "A %s record requires '%s'." (recordType kind) key))

        let private requiredInt kind key parts =
            getInt key parts
            |> Option.defaultWith (fun () -> invalid "record" (sprintf "A %s record requires '%s'." (recordType kind) key))

        let private checkedRange key minimum maximum value =
            if value < minimum || value > maximum then
                invalid key (sprintf "%s must be between %d and %d." key minimum maximum)
            value

        let private checkedFloatRange label minimum maximum value =
            if not (Double.IsFinite value) || value < minimum || value > maximum then
                invalid label (sprintf "%s must be between %s and %s." label (minimum.ToString("R", CultureInfo.InvariantCulture)) (maximum.ToString("R", CultureInfo.InvariantCulture)))
            value

        let private validateCoordinate label allowedHemispheres maxDegrees coordinate =
            if coordinate.Degrees < 0 || coordinate.Degrees > maxDegrees then invalid label (label + " degrees are out of range.")
            if coordinate.Minutes < 0 || coordinate.Minutes > 59 then invalid label (label + " minutes must be between 0 and 59.")
            if not (Double.IsFinite coordinate.Seconds) || coordinate.Seconds < 0.0 || coordinate.Seconds > 59.999 then
                invalid label (label + " seconds must be between 0 and 59.999.")
            if coordinate.Degrees = maxDegrees && (coordinate.Minutes <> 0 || coordinate.Seconds <> 0.0) then
                invalid label (label + " cannot exceed its maximum degree value.")
            if not (List.contains coordinate.Hemisphere allowedHemispheres) then
                invalid label (label + " has an invalid hemisphere.")
            coordinate

        let private normalizeAddressText label family (text: string) =
            if isNull text then invalid label (label + " cannot be null.")
            match family with
            | AddressFamily.InterNetwork ->
                let octets = text.Split('.')
                if octets.Length <> 4 then invalid label (label + " must use canonical dotted-decimal IPv4 notation.")
                let parsed =
                    octets
                    |> Array.map (fun octet ->
                        if String.IsNullOrEmpty octet || not (octet |> Seq.forall (fun value -> value >= '0' && value <= '9')) then
                            invalid label (label + " must use canonical dotted-decimal IPv4 notation.")
                        match Int32.TryParse(octet, NumberStyles.None, CultureInfo.InvariantCulture) with
                        | true, value when value >= 0 && value <= 255 && octet = string value -> value
                        | _ -> invalid label (label + " must use canonical dotted-decimal IPv4 notation."))
                String.Join(".", parsed)
            | AddressFamily.InterNetworkV6 ->
                if text.IndexOf('[') >= 0 || text.IndexOf(']') >= 0 || text.IndexOf('%') >= 0 then
                    invalid label (label + " must be a bare, unscoped IPv6 address.")
                else
                    match IPAddress.TryParse text with
                    | true, address when address.AddressFamily = AddressFamily.InterNetworkV6 && address.ScopeId = 0L ->
                        address.ToString().ToLowerInvariant()
                    | _ -> invalid label (label + " must be a valid unscoped IPv6 address.")
            | _ -> invalidArg "family" "Only IPv4 and IPv6 DNS address families are supported."

        let private normalizeAddress label family = function
            | LiteralString text -> LiteralString(normalizeAddressText label family text)
            | OutputString output -> OutputString(output.Apply(Func<string, string>(normalizeAddressText label family)))

        let private validateStringValue label allowEmpty = function
            | LiteralString value when isNull value -> invalid label (label + " cannot be null.")
            | LiteralString value when not allowEmpty && String.IsNullOrWhiteSpace value -> invalid label (label + " cannot be empty.")
            | _ -> ()


        let private validCaaTag (value: string) =
            not (String.IsNullOrEmpty value)
            && value.Length <= 15
            && (value |> Seq.forall (fun character -> Char.IsAsciiLetterOrDigit character || character = '-'))

        let private validateComment (comment: string option) =
            comment
            |> Option.iter (fun value ->
                if isNull value then invalid "comment" "A DNS record comment cannot be null."
                if value.IndexOf('\n') >= 0 || value.IndexOf('\r') >= 0 then
                    invalid "comment" "A DNS record comment cannot contain line breaks.")

        let private validateTags (tags: string list) =
            if tags.Length > 20 then invalid "tags" "A DNS record cannot have more than 20 tags."
            for tag in tags do
                if isNull tag then invalid "tags" "A DNS record tag cannot be null."
                let separator = tag.IndexOf(':')
                if separator <= 0 then invalid "tags" "A DNS record tag must use name:value syntax."
                let name = tag.Substring(0, separator)
                let value = tag.Substring(separator + 1)
                if name.Length > 32
                   || not (name |> Seq.forall (fun character -> Char.IsAsciiLetterOrDigit character || character = '-' || character = '_')) then
                    invalid "tags" "A DNS record tag name must use at most 32 ASCII letters, digits, hyphens or underscores."
                if value.IndexOf('\n') >= 0 || value.IndexOf('\r') >= 0 then
                    invalid "tags" "A DNS record tag value cannot contain line breaks."
                let mutable valueLength = 0
                for _ in value.EnumerateRunes() do valueLength <- valueLength + 1
                if valueLength > 100 then invalid "tags" "A DNS record tag value cannot exceed 100 Unicode characters."

        let private fieldFingerprint kind (parts: RecordField list) =
            let values = ResizeArray<string * string>()
            let mutable dynamic = false
            let addString key value transform =
                match value with
                | LiteralString text ->
                    validateStringValue key true value
                    values.Add(key, transform text)
                | OutputString _ -> dynamic <- true
            let addNumber key value = values.Add(key, Convert.ToString(box value, CultureInfo.InvariantCulture))
            for part in parts do
                match part with
                | OwnerName _ | Ttl _ | Proxy _ | Comment _ | RecordTags _ | Protect _ | RecordAliases _ -> ()
                | RecordAddress value ->
                    let family = if kind = A then AddressFamily.InterNetwork else AddressFamily.InterNetworkV6
                    addString "address" value (normalizeAddressText "address" family)
                | RecordTarget value ->
                    addString "target" value (if kind = Uri then id else normalizeTarget)
                | RecordContent value -> addString "content" value id
                | TxtText value -> addString "content" value encodeTxtText
                | TxtSegments segments -> values.Add("content", encodeTxtSegments segments)
                | NumberFlags value -> addNumber "flags" value
                | TextFlags value -> values.Add("naptrFlags", value)
                | CaaTag value -> values.Add("tag", value.ToLowerInvariant())
                | DataValue value -> addString "value" value id
                | Algorithm value -> addNumber "algorithm" value
                | Certificate value -> addString "certificate" value id
                | KeyTag value -> addNumber "keyTag" value
                | CertificateType value -> addNumber "certificateType" value
                | Protocol value -> addNumber "protocol" value
                | PublicKey value -> addString "publicKey" value id
                | Digest value -> addString "digest" value id
                | DigestType value -> addNumber "digestType" value
                | Priority value -> addNumber "priority" value
                | Port value -> addNumber "port" value
                | Weight value -> addNumber "weight" value
                | Latitude value ->
                    values.Add("latitude", sprintf "%d:%d:%s:%A" value.Degrees value.Minutes (value.Seconds.ToString("R", CultureInfo.InvariantCulture)) value.Hemisphere)
                | Longitude value ->
                    values.Add("longitude", sprintf "%d:%d:%s:%A" value.Degrees value.Minutes (value.Seconds.ToString("R", CultureInfo.InvariantCulture)) value.Hemisphere)
                | Altitude value -> addNumber "altitude" value
                | Size value -> addNumber "size" value
                | PrecisionHorz value -> addNumber "precisionHorz" value
                | PrecisionVert value -> addNumber "precisionVert" value
                | NaptrOrder value -> addNumber "order" value
                | Preference value -> addNumber "preference" value
                | Regex value -> addString "regex" value id
                | Replacement value -> addString "replacement" value normalizeTarget
                | Service value -> addString "service" value id
                | MatchingType value -> addNumber "matchingType" value
                | Selector value -> addNumber "selector" value
                | Usage value -> addNumber "usage" value
                | Fingerprint value -> addString "fingerprint" value id
                | FingerprintType value -> addNumber "fingerprintType" value
            if dynamic then None
            else
                let encode ((key, value): string * string) = string key.Length + ":" + key + string value.Length + ":" + value
                values |> Seq.sortBy fst |> Seq.map encode |> String.concat "" |> fun body -> Some(recordType kind + ":" + body)

        let buildRecord kind logicalKey (parts: RecordField list) =
            if String.IsNullOrWhiteSpace logicalKey
               || logicalKey.Length > 128
               || not (logicalKey |> Seq.forall (fun character -> Char.IsAsciiLetterOrDigit character || character = '_' || character = '-')) then
                invalid "logicalKey" "A Cloudflare DNS logical key must be 1–128 ASCII letters, digits, underscores or hyphens."

            let allowed = allowedFields kind
            let seen = HashSet<string>(StringComparer.Ordinal)
            for part in parts do
                let field = fieldName part
                if not (seen.Add field) then invalid "record" (sprintf "Field '%s' may only be declared once." field)
                if not (allowed.Contains field) then invalid "record" (sprintf "Field '%s' is not supported for %s records." field (recordType kind))

            let rawOwner = getString "name" parts |> Option.defaultWith (fun () -> invalid "record" (sprintf "A %s record requires 'name'." (recordType kind)))
            if String.IsNullOrWhiteSpace rawOwner then invalid "name" "A DNS record owner name is required."
            let ttl =
                match parts |> List.tryPick (function Ttl value -> Some value | _ -> None) with
                | None | Some Auto -> Auto
                | Some (Fixed seconds) when seconds >= 30 && seconds <= 86400 -> Fixed seconds
                | Some (Fixed _) -> invalid "ttl" "A fixed DNS TTL must be between 30 and 86400 seconds; use Auto for Cloudflare automatic TTL."
            let proxy = parts |> List.tryPick (function Proxy value -> Some value | _ -> None) |> Option.defaultValue DnsOnly
            let proxyable = kind = A || kind = Aaaa || kind = Cname
            if proxy = Proxied && not proxyable then invalid "proxy" "Only A, AAAA and CNAME records support Cloudflare proxying."
            if proxy = Proxied && ttl <> Auto then invalid "proxy" "Proxied records require automatic TTL."
            let comment = parts |> List.tryPick (function Comment value -> Some value | _ -> None)
            let tags = parts |> List.tryPick (function RecordTags values -> Some values | _ -> None) |> Option.defaultValue []
            validateComment comment
            validateTags tags
            let protect = parts |> List.tryPick (function Protect value -> Some value | _ -> None)
            let aliases = parts |> List.tryPick (function RecordAliases values -> Some values | _ -> None) |> Option.defaultValue []
            let priority = if kind = Mx || kind = Srv || kind = Uri then getInt "priority" parts else None
            let value, data =
                match kind with
                | A ->
                    let address = requiredText kind "address" parts |> normalizeAddress "address" AddressFamily.InterNetwork
                    Some(AddressValue address), None
                | Aaaa ->
                    let address = requiredText kind "address" parts |> normalizeAddress "address" AddressFamily.InterNetworkV6
                    Some(AddressValue address), None
                | Cname | Mx | Ns | Ptr ->
                    let target = requiredText kind "target" parts
                    validateStringValue "target" false target
                    Some(TargetValue target), None
                | OpenPgpKey ->
                    let content = requiredText kind "content" parts
                    validateStringValue "content" true content
                    Some(ContentValue content), None
                | Txt ->
                    match getText "text" parts, parts |> List.tryPick (function TxtSegments segments -> Some segments | _ -> None) with
                    | Some text, None ->
                        validateStringValue "text" true text
                        Some(TxtTextValue text), None
                    | None, Some segments -> encodeTxtSegments segments |> ignore; Some(TxtSegmentsValue segments), None
                    | Some _, Some _ -> invalid "record" "A TXT record accepts either text or explicit segments, not both."
                    | None, None -> invalid "record" "A TXT record requires text or explicit segments."
                | Caa ->
                    let flags = requiredInt kind "flags" parts |> checkedRange "flags" 0 255
                    let tag = getString "tag" parts |> Option.defaultWith (fun () -> invalid "record" "A CAA record requires 'tag'.")
                    if not (validCaaTag tag) then invalid "tag" "A CAA tag must contain 1–15 ASCII letters, digits or hyphens."
                    let value = requiredText kind "value" parts
                    validateStringValue "value" true value
                    None, Some(CaaData(flags, tag.ToLowerInvariant(), value))
                | Cert ->
                    let algorithm = requiredInt kind "algorithm" parts |> checkedRange "algorithm" 0 255
                    let certificate = requiredText kind "certificate" parts
                    validateStringValue "certificate" false certificate
                    let keyTag = requiredInt kind "keyTag" parts |> checkedRange "keyTag" 0 65535
                    let certificateType = requiredInt kind "certificateType" parts |> checkedRange "certificateType" 0 65535
                    None, Some(CertData(algorithm, certificate, keyTag, certificateType))
                | DnsKey ->
                    let flags = requiredInt kind "flags" parts |> checkedRange "flags" 0 65535
                    let algorithm = requiredInt kind "algorithm" parts |> checkedRange "algorithm" 0 255
                    let protocol = requiredInt kind "protocol" parts |> checkedRange "protocol" 0 255
                    if protocol <> 3 then invalid "protocol" "A DNSKEY record protocol must be 3."
                    let publicKey = requiredText kind "publicKey" parts
                    validateStringValue "publicKey" false publicKey
                    None, Some(DnsKeyData(flags, algorithm, protocol, publicKey))
                | Ds ->
                    let algorithm = requiredInt kind "algorithm" parts |> checkedRange "algorithm" 0 255
                    let digest = requiredText kind "digest" parts
                    validateStringValue "digest" false digest
                    let digestType = requiredInt kind "digestType" parts |> checkedRange "digestType" 0 255
                    let keyTag = requiredInt kind "keyTag" parts |> checkedRange "keyTag" 0 65535
                    None, Some(DsData(algorithm, digest, digestType, keyTag))
                | Https ->
                    let priority = requiredInt kind "priority" parts |> checkedRange "priority" 0 65535
                    let target = requiredText kind "target" parts
                    validateStringValue "target" false target
                    let dataValue = requiredText kind "value" parts
                    validateStringValue "value" true dataValue
                    None, Some(HttpsData(priority, target, dataValue))
                | Loc ->
                    let latitude = getCoordinate "latitude" parts |> Option.defaultWith (fun () -> invalid "record" "A LOC record requires 'latitude'.")
                    let longitude = getCoordinate "longitude" parts |> Option.defaultWith (fun () -> invalid "record" "A LOC record requires 'longitude'.")
                    let latitude = validateCoordinate "latitude" [ North; South ] 90 latitude
                    let longitude = validateCoordinate "longitude" [ East; West ] 180 longitude
                    let altitude, size, precisionHorz, precisionVert = getFloat "altitude" parts, getFloat "size" parts, getFloat "precisionHorz" parts, getFloat "precisionVert" parts
                    altitude |> Option.iter (checkedFloatRange "altitude" (-100000.0) 42849672.95 >> ignore)
                    for label, value in [ "size", size; "precisionHorz", precisionHorz; "precisionVert", precisionVert ] do
                        value |> Option.iter (checkedFloatRange label 0.0 90000000.0 >> ignore)
                    None, Some(LocData(latitude, longitude, altitude, size, precisionHorz, precisionVert))
                | Naptr ->
                    let flags = getString "naptrFlags" parts |> Option.defaultWith (fun () -> invalid "record" "A NAPTR record requires 'naptrFlags'.")
                    if not (flags |> Seq.forall Char.IsAsciiLetterOrDigit) then invalid "naptrFlags" "NAPTR flags must contain only ASCII letters and digits."
                    let order = requiredInt kind "order" parts |> checkedRange "order" 0 65535
                    let preference = requiredInt kind "preference" parts |> checkedRange "preference" 0 65535
                    let regex = requiredText kind "regex" parts
                    let replacement = requiredText kind "replacement" parts
                    let service = requiredText kind "service" parts
                    validateStringValue "regex" true regex
                    validateStringValue "replacement" false replacement
                    validateStringValue "service" true service
                    None, Some(NaptrData(flags, order, preference, regex, replacement, service))
                | Smimea ->
                    let certificate = requiredText kind "certificate" parts
                    validateStringValue "certificate" false certificate
                    let matchingType = requiredInt kind "matchingType" parts |> checkedRange "matchingType" 0 255
                    let selector = requiredInt kind "selector" parts |> checkedRange "selector" 0 255
                    let usage = requiredInt kind "usage" parts |> checkedRange "usage" 0 255
                    None, Some(SmimeaData(certificate, matchingType, selector, usage))
                | Srv ->
                    let port = requiredInt kind "port" parts |> checkedRange "port" 0 65535
                    let priority = requiredInt kind "priority" parts |> checkedRange "priority" 0 65535
                    let target = requiredText kind "target" parts
                    validateStringValue "target" false target
                    let weight = requiredInt kind "weight" parts |> checkedRange "weight" 0 65535
                    None, Some(SrvData(port, priority, target, weight))
                | Sshfp ->
                    let algorithm = requiredInt kind "algorithm" parts |> checkedRange "algorithm" 0 255
                    let fingerprint = requiredText kind "fingerprint" parts
                    validateStringValue "fingerprint" false fingerprint
                    let fingerprintType = requiredInt kind "fingerprintType" parts |> checkedRange "fingerprintType" 0 255
                    None, Some(SshfpData(algorithm, fingerprint, fingerprintType))
                | Svcb ->
                    let priority = requiredInt kind "priority" parts |> checkedRange "priority" 0 65535
                    let target = requiredText kind "target" parts
                    validateStringValue "target" false target
                    let dataValue = requiredText kind "value" parts
                    validateStringValue "value" true dataValue
                    None, Some(SvcbData(priority, target, dataValue))
                | Tlsa ->
                    let certificate = requiredText kind "certificate" parts
                    validateStringValue "certificate" false certificate
                    let matchingType = requiredInt kind "matchingType" parts |> checkedRange "matchingType" 0 255
                    let selector = requiredInt kind "selector" parts |> checkedRange "selector" 0 255
                    let usage = requiredInt kind "usage" parts |> checkedRange "usage" 0 255
                    None, Some(TlsaData(certificate, matchingType, selector, usage))
                | Uri ->
                    let priority = requiredInt kind "priority" parts |> checkedRange "priority" 0 65535
                    let target = requiredText kind "target" parts
                    validateStringValue "target" true target
                    let weight = requiredInt kind "weight" parts |> checkedRange "weight" 0 65535
                    None, Some(UriData(target, weight))

            match kind, priority with
            | Mx, None -> invalid "record" "An MX record requires 'priority'."
            | Mx, Some value -> checkedRange "priority" 0 65535 value |> ignore
            | Uri, None -> invalid "record" "A URI record requires top-level 'priority'."
            | Srv, Some value -> checkedRange "priority" 0 65535 value |> ignore
            | _ -> ()

            let fingerprint = fieldFingerprint kind parts
            RecordSpec(logicalKey, kind, rawOwner, value, data, priority, ttl, proxy, comment, tags, protect, aliases, fingerprint)

        let private mergeOption label left right =
            match left, right with
            | Some first, Some second when first <> second -> invalid "domain" (sprintf "Conflicting %s declarations for the same canonical zone." label)
            | Some value, _ | _, Some value -> Some value
            | None, None -> None

        let buildDomain name (fields: DomainField list) =
            let canonicalName = normalizeDomain name
            let mutable accountId = None
            let mutable zoneId = None
            let mutable provider = None
            let records = ResizeArray<RecordSpec>()
            let seen = HashSet<string>(StringComparer.Ordinal)
            for field in fields do
                match field with
                | AccountId value ->
                    if not (seen.Add "accountId") then invalid "domain" "accountId may only be declared once per domain block."
                    if String.IsNullOrWhiteSpace value then invalid "accountId" "A Cloudflare account ID cannot be empty."
                    accountId <- Some value
                | ZoneId value ->
                    if not (seen.Add "zoneId") then invalid "domain" "zoneId may only be declared once per domain block."
                    validateZoneId value
                    zoneId <- Some value
                | ZoneProvider value ->
                    if not (seen.Add "zoneProvider") then invalid "domain" "zoneProvider may only be declared once per domain block."
                    if isNull (box value) then invalid "zoneProvider" "A Cloudflare provider resource cannot be null."
                    provider <- Some value
                | Dns dns -> records.AddRange dns.Records
            if accountId.IsSome && zoneId.IsSome then invalid "domain" "Choose accountId lookup or explicit zoneId, not both."
            let records =
                records
                |> Seq.map (fun record ->
                    let ownerName = normalizeOwner canonicalName record.OwnerName
                    let fingerprint = record.Fingerprint |> Option.map (fun value -> ownerName + ":" + value)
                    RecordSpec(record.LogicalKey, record.Kind, ownerName, record.Value, record.Data, record.Priority, record.Ttl, record.Proxy, record.Comment, record.Tags, record.Protect, record.Aliases, fingerprint))
                |> Seq.toList
            DomainSpec(canonicalName, accountId, zoneId, provider, records)

        let mergeDomains (domains: DomainSpec list) =
            let merged = Dictionary<string, DomainSpec>(StringComparer.Ordinal)
            for domain in domains do
                match merged.TryGetValue domain.Name with
                | false, _ -> merged.Add(domain.Name, domain)
                | true, previous ->
                    let account = mergeOption "accountId" previous.AccountId domain.AccountId
                    let zone = mergeOption "zoneId" previous.ZoneId domain.ZoneId
                    let provider = mergeOption "zoneProvider" previous.Provider domain.Provider
                    if account.IsSome && zone.IsSome then invalid "domain" "Choose accountId lookup or explicit zoneId, not both."
                    merged[domain.Name] <- DomainSpec(domain.Name, account, zone, provider, previous.Records @ domain.Records)
            let result = merged.Values |> Seq.sortBy (fun domain -> domain.Name) |> Seq.toList
            for domain in result do
                let keys = HashSet<string>(StringComparer.Ordinal)
                let fingerprints = HashSet<string>(StringComparer.Ordinal)
                for record in domain.Records do
                    if not (keys.Add record.LogicalKey) then invalid "dns" (sprintf "Duplicate Cloudflare DNS logical key '%s' in zone '%s'." record.LogicalKey domain.Name)
                    record.Fingerprint |> Option.iter (fun value -> if not (fingerprints.Add value) then invalid "dns" (sprintf "Duplicate %s record at '%s' in zone '%s'." record.RecordType record.OwnerName domain.Name))
            result

        let resourceName (domain: string) (logicalKey: string) =
            sprintf "cloudflare-dns-%d-%s-%d-%s" domain.Length domain logicalKey.Length logicalKey

        let private inputString (value: StringInput) : Input<string> =
            match value with
            | LiteralString text -> Input<string>.op_Implicit text
            | OutputString output -> Input<string>.op_Implicit output

        let private transformedInput (transform: string -> string) (value: StringInput) : Input<string> = mapInput transform value

        let private setDouble (setter: Input<double> -> unit) (value: float) = setter (Input<double>.op_Implicit value)
        let private setInteger (setter: Input<double> -> unit) (value: int) = setDouble setter (float value)

        let private createData (data: DnsData) : Pulumi.Cloudflare.Inputs.DnsRecordDataArgs =
            let args = Pulumi.Cloudflare.Inputs.DnsRecordDataArgs()
            let setNumber (name: string) (value: float) =
                match name with
                | "algorithm" -> setDouble (fun input -> args.Algorithm <- input) value
                | "altitude" -> args.Altitude <- Input<double>.op_Implicit value
                | "digestType" -> setDouble (fun input -> args.DigestType <- input) value
                | "keyTag" -> setDouble (fun input -> args.KeyTag <- input) value
                | "matchingType" -> setDouble (fun input -> args.MatchingType <- input) value
                | "port" -> setDouble (fun input -> args.Port <- input) value
                | "order" -> setDouble (fun input -> args.Order <- input) value
                | "preference" -> setDouble (fun input -> args.Preference <- input) value
                | "precisionHorz" -> args.PrecisionHorz <- Input<double>.op_Implicit value
                | "precisionVert" -> args.PrecisionVert <- Input<double>.op_Implicit value
                | "priority" -> setDouble (fun input -> args.Priority <- input) value
                | "protocol" -> setDouble (fun input -> args.Protocol <- input) value
                | "selector" -> setDouble (fun input -> args.Selector <- input) value
                | "size" -> args.Size <- Input<double>.op_Implicit value
                | "type" -> setDouble (fun input -> args.Type <- input) value
                | "usage" -> setDouble (fun input -> args.Usage <- input) value
                | "weight" -> setDouble (fun input -> args.Weight <- input) value
                | _ -> invalidOp ("Unsupported Cloudflare DNS data numeric field " + name)
            let setCoordinate (prefix: string) (coordinate: Coordinate) =
                let degrees = float coordinate.Degrees
                let minutes = float coordinate.Minutes
                let seconds = coordinate.Seconds
                let direction =
                    match coordinate.Hemisphere with
                    | North -> "N"
                    | South -> "S"
                    | East -> "E"
                    | West -> "W"
                match prefix with
                | "lat" ->
                    args.LatDegrees <- Input<double>.op_Implicit degrees
                    args.LatMinutes <- Input<double>.op_Implicit minutes
                    args.LatSeconds <- Input<double>.op_Implicit seconds
                    args.LatDirection <- Input<string>.op_Implicit direction
                | "long" ->
                    args.LongDegrees <- Input<double>.op_Implicit degrees
                    args.LongMinutes <- Input<double>.op_Implicit minutes
                    args.LongSeconds <- Input<double>.op_Implicit seconds
                    args.LongDirection <- Input<string>.op_Implicit direction
                | _ -> invalidOp "Unsupported Cloudflare LOC coordinate."
            match data with
            | CaaData(flags, tag, value) ->
                args.Flags <- Input<obj>.op_Implicit (box flags)
                args.Tag <- Input<string>.op_Implicit tag
                args.Value <- inputString value
            | CertData(algorithm, certificate, keyTag, certificateType) ->
                setNumber "algorithm" (float algorithm)
                args.Certificate <- inputString certificate
                setNumber "keyTag" (float keyTag)
                setNumber "type" (float certificateType)
            | DnsKeyData(flags, algorithm, protocol, publicKey) ->
                args.Flags <- Input<obj>.op_Implicit (box flags)
                setNumber "algorithm" (float algorithm)
                setNumber "protocol" (float protocol)
                args.PublicKey <- inputString publicKey
            | DsData(algorithm, digest, digestType, keyTag) ->
                setNumber "algorithm" (float algorithm)
                args.Digest <- inputString digest
                setNumber "digestType" (float digestType)
                setNumber "keyTag" (float keyTag)
            | HttpsData(priority, target, value) ->
                setNumber "priority" (float priority)
                args.Target <- transformedInput normalizeTarget target
                args.Value <- inputString value
            | LocData(latitude, longitude, altitude, size, precisionHorz, precisionVert) ->
                setCoordinate "lat" latitude
                setCoordinate "long" longitude
                altitude |> Option.iter (setNumber "altitude")
                size |> Option.iter (setNumber "size")
                precisionHorz |> Option.iter (setNumber "precisionHorz")
                precisionVert |> Option.iter (setNumber "precisionVert")
            | NaptrData(flags, order, preference, regex, replacement, service) ->
                args.Flags <- Input<obj>.op_Implicit (box flags)
                setNumber "order" (float order)
                setNumber "preference" (float preference)
                args.Regex <- inputString regex
                args.Replacement <- transformedInput normalizeTarget replacement
                args.Service <- inputString service
            | SmimeaData(certificate, matchingType, selector, usage)
            | TlsaData(certificate, matchingType, selector, usage) ->
                args.Certificate <- inputString certificate
                setNumber "matchingType" (float matchingType)
                setNumber "selector" (float selector)
                setNumber "usage" (float usage)
            | SrvData(port, priority, target, weight) ->
                setNumber "port" (float port)
                setNumber "priority" (float priority)
                args.Target <- transformedInput normalizeTarget target
                setNumber "weight" (float weight)
            | SshfpData(algorithm, fingerprint, fingerprintType) ->
                setNumber "algorithm" (float algorithm)
                args.Fingerprint <- inputString fingerprint
                setNumber "type" (float fingerprintType)
            | SvcbData(priority, target, value) ->
                setNumber "priority" (float priority)
                args.Target <- transformedInput normalizeTarget target
                args.Value <- inputString value
            | UriData(target, weight) ->
                args.Target <- inputString target
                setNumber "weight" (float weight)
            args

        let private setContent (kind: RecordKind) (args: Pulumi.Cloudflare.DnsRecordArgs) (value: RecordValue) =
            match kind, value with
            | (A | Aaaa), AddressValue address -> args.Content <- inputString address
            | (Cname | Mx | Ns | Ptr), TargetValue target -> args.Content <- transformedInput normalizeTarget target
            | OpenPgpKey, ContentValue content -> args.Content <- inputString content
            | Txt, TxtTextValue text -> args.Content <- transformedInput encodeTxtText text
            | Txt, TxtSegmentsValue segments -> args.Content <- Input<string>.op_Implicit (encodeTxtSegments segments)
            | _ -> invalidOp "Cloudflare DNS record payload does not match its record type."

        let private setZoneId (domain: DomainSpec) : Output<string> =
            match domain.ZoneId with
            | Some zoneId -> Output.Create<string>(zoneId)
            | None ->
                let invokeOptions = InvokeOptions()
                domain.Provider |> Option.iter (fun provider -> invokeOptions.Provider <- provider)
                let lookup = Pulumi.Cloudflare.GetZonesInvokeArgs()
                lookup.Name <- Input<string>.op_Implicit domain.Name
                lookup.Match <- Input<string>.op_Implicit "all"
                lookup.MaxItems <- Input<int>.op_Implicit 1000
                domain.AccountId
                |> Option.iter (fun accountId ->
                    let account = Pulumi.Cloudflare.Inputs.GetZonesAccountInputArgs()
                    account.Id <- Input<string>.op_Implicit accountId
                    lookup.Account <- Input<Pulumi.Cloudflare.Inputs.GetZonesAccountInputArgs>.op_Implicit account)
                Pulumi.Cloudflare.GetZones.Invoke(lookup, invokeOptions).Apply(Func<Pulumi.Cloudflare.GetZonesResult, string>(fun result ->
                    let exact =
                        result.Results
                        |> Seq.filter (fun zone ->
                            not (String.IsNullOrWhiteSpace zone.Name)
                            && String.Equals(normalizeDomain zone.Name, domain.Name, StringComparison.Ordinal))
                        |> Seq.toArray
                    match exact with
                    | [| one |] -> one.Id
                    | [||] -> invalidOp (sprintf "Cloudflare zone lookup found no exact match for '%s'." domain.Name)
                    | _ -> invalidOp (sprintf "Cloudflare zone lookup found multiple exact matches for '%s'; specify zoneId or accountId." domain.Name)))

        let deploy (spec: Spec) =
            let resources = ResizeArray<Pulumi.Cloudflare.DnsRecord>()
            for domain in spec.Domains do
                if not domain.Records.IsEmpty then
                    let zoneId = setZoneId domain
                    for record in domain.Records do
                        let args = Pulumi.Cloudflare.DnsRecordArgs()
                        args.ZoneId <- Input<string>.op_Implicit zoneId
                        args.Name <- Input<string>.op_Implicit record.OwnerName
                        args.Type <- Input<string>.op_Implicit record.RecordType
                        args.Ttl <- Input<double>.op_Implicit (match record.Ttl with Auto -> 1.0 | Fixed seconds -> float seconds)
                        if record.Kind = A || record.Kind = Aaaa || record.Kind = Cname then
                            args.Proxied <- Input<bool>.op_Implicit (record.Proxy = Proxied)
                        record.Priority |> Option.iter (fun value -> setInteger (fun input -> args.Priority <- input) value)
                        record.Comment |> Option.iter (fun value -> args.Comment <- Input<string>.op_Implicit value)
                        for tag in record.Tags do args.Tags.Add(Input<string>.op_Implicit tag)
                        record.Value |> Option.iter (setContent record.Kind args)
                        record.Data |> Option.iter (fun data -> args.Data <- Input<Pulumi.Cloudflare.Inputs.DnsRecordDataArgs>.op_Implicit (createData data))
                        let options = CustomResourceOptions()
                        domain.Provider |> Option.iter (fun provider -> options.Provider <- provider)
                        record.Protect |> Option.iter (fun protect -> options.Protect <- Nullable protect)
                        for alias in record.Aliases do options.Aliases.Add(Input<Alias>.op_Implicit alias)
                        resources.Add(Pulumi.Cloudflare.DnsRecord(resourceName domain.Name record.LogicalKey, args, options))
            List.ofSeq resources

    type RecordBuilder internal (kind: RecordKind, logicalKey: string) =
        member _.Yield(field: RecordField) = [ field ]
        member _.YieldFrom(fields: seq<RecordField>) = Seq.toList fields
        member _.Zero() = []
        member _.Combine(left: RecordField list, right: RecordField list) = left @ right
        member _.Delay(body: unit -> RecordField list) = body()
        member _.For(values: seq<'T>, body: 'T -> RecordField list) = values |> Seq.collect body |> Seq.toList
        member _.Run(fields: RecordField list) = Validation.buildRecord kind logicalKey fields

    type DnsBuilder internal () =
        member _.Yield(record: RecordSpec) = [ record ]
        member _.YieldFrom(records: seq<RecordSpec>) = Seq.toList records
        member _.Zero() = []
        member _.Combine(left: RecordSpec list, right: RecordSpec list) = left @ right
        member _.Delay(body: unit -> RecordSpec list) = body()
        member _.For(values: seq<'T>, body: 'T -> RecordSpec list) = values |> Seq.collect body |> Seq.toList
        member _.Run(records: RecordSpec list) = DnsSpec records

    type DomainBuilder internal (name: string) =
        member _.Yield(field: DomainField) = [ field ]
        member _.Yield(dns: DnsSpec) = [ Dns dns ]
        member _.YieldFrom(fields: seq<DomainField>) = Seq.toList fields
        member _.YieldFrom(blocks: seq<DnsSpec>) = blocks |> Seq.map Dns |> Seq.toList
        member _.Zero() = []
        member _.Combine(left: DomainField list, right: DomainField list) = left @ right
        member _.Delay(body: unit -> DomainField list) = body()
        member _.For(values: seq<'T>, body: 'T -> DomainField list) = values |> Seq.collect body |> Seq.toList
        member _.Run(fields: DomainField list) = Validation.buildDomain name fields

    type CloudflareBuilder internal () =
        member _.Yield(domain: DomainSpec) = [ domain ]
        member _.YieldFrom(domains: seq<DomainSpec>) = Seq.toList domains
        member _.Zero() = []
        member _.Combine(left: DomainSpec list, right: DomainSpec list) = left @ right
        member _.Delay(body: unit -> DomainSpec list) = body()
        member _.For(values: seq<'T>, body: 'T -> DomainSpec list) = values |> Seq.collect body |> Seq.toList
        member _.Run(domains: DomainSpec list) = Spec(Validation.mergeDomains domains)

    let coordinate degrees minutes seconds hemisphere =
        { Degrees = degrees; Minutes = minutes; Seconds = seconds; Hemisphere = hemisphere }

    let private record kind logicalKey = RecordBuilder(kind, logicalKey)

    let cloudflare = CloudflareBuilder()
    let domain name = DomainBuilder(name)
    let dns = DnsBuilder()
    let a logicalKey = record A logicalKey
    let aaaa logicalKey = record Aaaa logicalKey
    let cname logicalKey = record Cname logicalKey
    let mx logicalKey = record Mx logicalKey
    let ns logicalKey = record Ns logicalKey
    let openpgpkey logicalKey = record OpenPgpKey logicalKey
    let ptr logicalKey = record Ptr logicalKey
    let txt logicalKey = record Txt logicalKey
    let caa logicalKey = record Caa logicalKey
    let cert logicalKey = record Cert logicalKey
    let dnskey logicalKey = record DnsKey logicalKey
    let ds logicalKey = record Ds logicalKey
    let https logicalKey = record Https logicalKey
    let loc logicalKey = record Loc logicalKey
    let naptr logicalKey = record Naptr logicalKey
    let smimea logicalKey = record Smimea logicalKey
    let srv logicalKey = record Srv logicalKey
    let sshfp logicalKey = record Sshfp logicalKey
    let svcb logicalKey = record Svcb logicalKey
    let tlsa logicalKey = record Tlsa logicalKey
    let uri logicalKey = record Uri logicalKey

    let accountId value = AccountId value
    let zoneId value = ZoneId value
    let zoneProvider (provider: ProviderResource) = ZoneProvider provider
    let name value = OwnerName value
    let address (value: string) = RecordAddress(LiteralString value)
    let proxy value = Proxy value

    [<RequireQualifiedAccess>]
    module Fields =
        let addressOutput (value: Output<string>) = RecordAddress(OutputString value)
        let target (value: string) = RecordTarget(LiteralString value)
        let targetOutput (value: Output<string>) = RecordTarget(OutputString value)
        let content (value: string) = RecordContent(LiteralString value)
        let contentOutput (value: Output<string>) = RecordContent(OutputString value)
        let text (value: string) = TxtText(LiteralString value)
        let textOutput (value: Output<string>) = TxtText(OutputString value)
        let segments values = TxtSegments(Seq.toList values)
        let flags (value: int) = NumberFlags value
        let naptrFlags (value: string) = TextFlags value
        let tag value = CaaTag value
        let value (input: string) = DataValue(LiteralString input)
        let valueOutput (input: Output<string>) = DataValue(OutputString input)
        let algorithm value = Algorithm value
        let certificate (input: string) = Certificate(LiteralString input)
        let certificateOutput (input: Output<string>) = Certificate(OutputString input)
        let keyTag value = KeyTag value
        let certificateType value = CertificateType value
        let protocol value = Protocol value
        let publicKey (input: string) = PublicKey(LiteralString input)
        let publicKeyOutput (input: Output<string>) = PublicKey(OutputString input)
        let digest (input: string) = Digest(LiteralString input)
        let digestOutput (input: Output<string>) = Digest(OutputString input)
        let digestType value = DigestType value
        let priority value = Priority value
        let port value = Port value
        let weight value = Weight value
        let latitude value = Latitude value
        let longitude value = Longitude value
        let altitude value = Altitude value
        let size value = Size value
        let precisionHorz value = PrecisionHorz value
        let precisionVert value = PrecisionVert value
        let order value = NaptrOrder value
        let preference value = Preference value
        let regex (input: string) = Regex(LiteralString input)
        let regexOutput (input: Output<string>) = Regex(OutputString input)
        let replacement (input: string) = Replacement(LiteralString input)
        let replacementOutput (input: Output<string>) = Replacement(OutputString input)
        let service (input: string) = Service(LiteralString input)
        let serviceOutput (input: Output<string>) = Service(OutputString input)
        let matchingType value = MatchingType value
        let selector value = Selector value
        let usage value = Usage value
        let fingerprint (input: string) = Fingerprint(LiteralString input)
        let fingerprintOutput (input: Output<string>) = Fingerprint(OutputString input)
        let fingerprintType value = FingerprintType value
        let ttl value = Ttl value
        let comment value = Comment value
        let tags values = RecordTags(Seq.toList values)
        let protect value = Protect value
        let aliases values = RecordAliases(Seq.toList values)

    let deploy spec = Validation.deploy spec
