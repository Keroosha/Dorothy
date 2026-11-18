namespace Dorothy.Tests

open System
open System.Collections.Concurrent
open System.Collections.Immutable
open System.Globalization
open System.Threading.Tasks
open Dorothy.DSL.Cloudflare
open NUnit.Framework
open Pulumi
open Pulumi.Testing

module CF = Dorothy.DSL.Cloudflare
module private CloudflareTestFields =
    let addressOutput = CF.Fields.addressOutput
    let target = CF.Fields.target
    let targetOutput = CF.Fields.targetOutput
    let content = CF.Fields.content
    let text = CF.Fields.text
    let segments = CF.Fields.segments
    let flags = CF.Fields.flags
    let naptrFlags = CF.Fields.naptrFlags
    let tag = CF.Fields.tag
    let value = CF.Fields.value
    let algorithm = CF.Fields.algorithm
    let certificate = CF.Fields.certificate
    let keyTag = CF.Fields.keyTag
    let certificateType = CF.Fields.certificateType
    let protocol = CF.Fields.protocol
    let publicKey = CF.Fields.publicKey
    let digest = CF.Fields.digest
    let digestType = CF.Fields.digestType
    let priority = CF.Fields.priority
    let port = CF.Fields.port
    let weight = CF.Fields.weight
    let latitude = CF.Fields.latitude
    let longitude = CF.Fields.longitude
    let altitude = CF.Fields.altitude
    let size = CF.Fields.size
    let precisionHorz = CF.Fields.precisionHorz
    let precisionVert = CF.Fields.precisionVert
    let order = CF.Fields.order
    let preference = CF.Fields.preference
    let regex = CF.Fields.regex
    let replacement = CF.Fields.replacement
    let service = CF.Fields.service
    let matchingType = CF.Fields.matchingType
    let selector = CF.Fields.selector
    let usage = CF.Fields.usage
    let fingerprint = CF.Fields.fingerprint
    let fingerprintType = CF.Fields.fingerprintType
    let ttl = CF.Fields.ttl
    let comment = CF.Fields.comment
    let tags = CF.Fields.tags
    let protect = CF.Fields.protect
    let aliases = CF.Fields.aliases

open CloudflareTestFields


type internal CloudflareMocks(zones: (string * string) list) =
    let resources = ConcurrentDictionary<string, MockResourceArgs>()
    let calls = ConcurrentBag<MockCallArgs>()
    let mutable unknownOutputFor: string option = None

    member _.Resources = resources
    member _.Calls = calls
    member _.UnknownOutputFor
        with get () = unknownOutputFor
        and set value = unknownOutputFor <- value

    interface IMocks with
        member _.NewResourceAsync(args) =
            resources[args.Name] <- args
            let outputs =
                if unknownOutputFor = Some args.Name then args.Inputs.Remove("content")
                else args.Inputs
            Task.FromResult(args.Name + "-id", box outputs)

        member _.CallAsync(args) =
            calls.Add args
            let results =
                zones
                |> Seq.map (fun (name, id) -> ImmutableDictionary<string, obj>.Empty.Add("name", box name).Add("id", box id))
                |> ImmutableArray.CreateRange
            let outputs = ImmutableDictionary<string, obj>.Empty.Add("results", box results)
            Task.FromResult(box outputs)

        member _.RegisterResourceOutputs(_) = Task.CompletedTask
        member _.RegisterTransform(_) = Task.CompletedTask
        member _.RegisterInvokeTransform(_) = Task.CompletedTask

[<TestFixture; NonParallelizable>]
type CloudflareTests() =
    let testZoneId = "0123456789abcdef0123456789abcdef"
    let run (mocks: CloudflareMocks) (spec: CF.Spec) =
        Deployment.TestAsync(mocks, TestOptions(), Action(fun () -> CF.deploy spec |> ignore)).GetAwaiter().GetResult() |> ignore

    let dnsResources (mocks: CloudflareMocks) =
        mocks.Resources.Values
        |> Seq.filter (fun resource -> resource.Type = "cloudflare:index/dnsRecord:DnsRecord")
        |> Seq.toArray

    let stringInput (resource: MockResourceArgs) (name: string) = unbox<string> resource.Inputs.[name]
    let stringListInput (resource: MockResourceArgs) (name: string) =
        (resource.Inputs.[name] :?> System.Collections.IEnumerable)
        |> Seq.cast<obj>
        |> Seq.map unbox<string>
        |> Seq.toList
    let numericValue (value: obj) =
        match value with
        | :? double as number -> number
        | :? float32 as number -> float number
        | :? int as number -> float number
        | :? int64 as number -> float number
        | :? decimal as number -> float number
        | _ -> invalidOp (sprintf "Expected a serialized numeric Pulumi input, found %s." (value.GetType().FullName))
    let numberInput (resource: MockResourceArgs) (name: string) = numericValue resource.Inputs.[name]
    let data (resource: MockResourceArgs) = resource.Inputs.["data"] :?> ImmutableDictionary<string, obj>
    let dataString (resource: MockResourceArgs) (name: string) =
        let values = data resource
        unbox<string> values.[name]
    let dataNumber (resource: MockResourceArgs) (name: string) =
        let values = data resource
        numericValue values.[name]
    let dataKeys (resource: MockResourceArgs) =
        if resource.Inputs.ContainsKey "data" then data resource |> fun values -> values.Keys |> Set.ofSeq else Set.empty

    let allTypesSpec =
        cloudflare {
            domain "cybergulag.today" {
                zoneId testZoneId
                dns {
                    a "edge-wildcard" { name "*"; address "192.0.2.10"; proxy DnsOnly; comment "edge"; tags [ "owner:dns"; "env:test" ] }
                    aaaa "ipv6" { name "ipv6"; address "2001:db8::10" }
                    cname "alias" { name "alias"; target "origin.example.net."; proxy Proxied }
                    mx "null-mx" { name "@"; target "."; priority 0 }
                    ns "delegation" { name "delegated"; target "ns1.example.net" }
                    openpgpkey "openpgp" { name "openpgpkey"; content "AQID" }
                    ptr "reverse" { name "1"; target "host.example.net" }
                    txt "spf" { name "@"; text "v=spf1 include:example.net -all" }
                    caa "caa" { name "@"; flags 0; tag "ISSUE"; value "letsencrypt.org" }
                    cert "cert" { name "cert"; algorithm 8; certificate "AQID"; keyTag 0; certificateType 1 }
                    dnskey "dnskey" { name "@"; flags 0; algorithm 8; protocol 3; publicKey "AQID" }
                    ds "ds" { name "@"; algorithm 8; digest "abcd"; digestType 2; keyTag 0 }
                    https "https" { name "@"; priority 1; target "."; value "alpn=h2" }
                    loc "loc" {
                        name "loc"
                        latitude (coordinate 37 46 49.0 North)
                        longitude (coordinate 122 25 9.0 West)
                        altitude 0.0
                        size 0.0
                        precisionHorz 10.0
                        precisionVert 0.0
                    }
                    naptr "naptr" {
                        name "_service._tcp"
                        naptrFlags "s"
                        order 0
                        preference 0
                        regex ""
                        replacement "."
                        service ""
                    }
                    smimea "smimea" { name "smimea"; certificate "abcd"; matchingType 0; selector 1; usage 3 }
                    srv "srv" { name "_sip._tcp"; port 5222; priority 5; target "talk.example.net"; weight 0 }
                    sshfp "sshfp" { name "sshfp"; algorithm 1; fingerprint "abcd"; fingerprintType 2 }
                    svcb "svcb" { name "@"; priority 0; target "."; value "alpn=h2" }
                    tlsa "tlsa" { name "_443._tcp"; certificate "abcd"; matchingType 1; selector 0; usage 3 }
                    uri "uri" { name "_service"; priority 0; target "https://example.net/path"; weight 0 }
                }
            }
        }

    [<Test>]
    member _.``All 21 record builders serialize exact typed provider inputs``() =
        let mocks = CloudflareMocks([])
        run mocks allTypesSpec
        let records = dnsResources mocks
        Assert.That(records, Has.Length.EqualTo 21)
        let byType = records |> Array.map (fun record -> stringInput record "type", record) |> Map.ofArray
        let kinds =
            [ "A"; "AAAA"; "CNAME"; "MX"; "NS"; "OPENPGPKEY"; "PTR"; "TXT"; "CAA"; "CERT"; "DNSKEY"; "DS"; "HTTPS"; "LOC"; "NAPTR"; "SMIMEA"; "SRV"; "SSHFP"; "SVCB"; "TLSA"; "URI" ]
        Assert.That(byType.Keys, Is.EquivalentTo kinds)
        let record kind = byType[kind]
        let text kind field = stringInput (record kind) field
        let number kind field = numberInput (record kind) field
        let dataText kind field = dataString (record kind) field
        let dataNum kind field = dataNumber (record kind) field
        let owners =
            Map.ofList [
                "A", "*.cybergulag.today"; "AAAA", "ipv6.cybergulag.today"; "CNAME", "alias.cybergulag.today"
                "MX", "cybergulag.today"; "NS", "delegated.cybergulag.today"; "OPENPGPKEY", "openpgpkey.cybergulag.today"
                "PTR", "1.cybergulag.today"; "TXT", "cybergulag.today"; "CAA", "cybergulag.today"
                "CERT", "cert.cybergulag.today"; "DNSKEY", "cybergulag.today"; "DS", "cybergulag.today"
                "HTTPS", "cybergulag.today"; "LOC", "loc.cybergulag.today"; "NAPTR", "_service._tcp.cybergulag.today"
                "SMIMEA", "smimea.cybergulag.today"; "SRV", "_sip._tcp.cybergulag.today"; "SSHFP", "sshfp.cybergulag.today"
                "SVCB", "cybergulag.today"; "TLSA", "_443._tcp.cybergulag.today"; "URI", "_service.cybergulag.today"
            ]
        for KeyValue(kind, owner) in owners do
            Assert.That(text kind "name", Is.EqualTo owner, kind)
            Assert.That(number kind "ttl", Is.EqualTo 1.0, kind)
            Assert.That(text kind "zoneId", Is.EqualTo testZoneId, kind)
        let contentValues =
            Map.ofList [
                "A", "192.0.2.10"; "AAAA", "2001:db8::10"; "CNAME", "origin.example.net"
                "MX", "."; "NS", "ns1.example.net"; "OPENPGPKEY", "AQID"; "PTR", "host.example.net"
                "TXT", "\"v=spf1 include:example.net -all\""
            ]
        for KeyValue(kind, expected) in contentValues do
            Assert.That(text kind "content", Is.EqualTo expected, kind)
        for kind in [ "CAA"; "CERT"; "DNSKEY"; "DS"; "HTTPS"; "LOC"; "NAPTR"; "SMIMEA"; "SRV"; "SSHFP"; "SVCB"; "TLSA"; "URI" ] do
            Assert.That((record kind).Inputs.ContainsKey "content", Is.False, kind)
        for kind in [ "A"; "AAAA"; "CNAME"; "MX"; "NS"; "OPENPGPKEY"; "PTR"; "TXT" ] do
            Assert.That((record kind).Inputs.ContainsKey "data", Is.False, kind)
        let dataFields =
            Map.ofList [
                "CAA", set [ "flags"; "tag"; "value" ]
                "CERT", set [ "algorithm"; "certificate"; "keyTag"; "type" ]
                "DNSKEY", set [ "algorithm"; "flags"; "protocol"; "publicKey" ]
                "DS", set [ "algorithm"; "digest"; "digestType"; "keyTag" ]
                "HTTPS", set [ "priority"; "target"; "value" ]
                "LOC", set [ "altitude"; "latDegrees"; "latDirection"; "latMinutes"; "latSeconds"; "longDegrees"; "longDirection"; "longMinutes"; "longSeconds"; "precisionHorz"; "precisionVert"; "size" ]
                "NAPTR", set [ "flags"; "order"; "preference"; "regex"; "replacement"; "service" ]
                "SMIMEA", set [ "certificate"; "matchingType"; "selector"; "usage" ]
                "SRV", set [ "port"; "priority"; "target"; "weight" ]
                "SSHFP", set [ "algorithm"; "fingerprint"; "type" ]
                "SVCB", set [ "priority"; "target"; "value" ]
                "TLSA", set [ "certificate"; "matchingType"; "selector"; "usage" ]
                "URI", set [ "target"; "weight" ]
            ]
        for KeyValue(kind, expected) in dataFields do
            Assert.That(dataKeys (record kind), Is.EquivalentTo expected, kind)
        let priorityKinds = set [ "MX"; "SRV"; "URI" ]
        let proxyKinds = set [ "A"; "AAAA"; "CNAME" ]
        let contentKinds = set [ "A"; "AAAA"; "CNAME"; "MX"; "NS"; "OPENPGPKEY"; "PTR"; "TXT" ]
        let structuredKinds = kinds |> List.filter (fun kind -> not (contentKinds.Contains kind)) |> Set.ofList
        for kind in kinds do
            let mutable expectedKeys = set [ "name"; "type"; "zoneId"; "ttl" ]
            if contentKinds.Contains kind then expectedKeys <- expectedKeys.Add "content"
            if structuredKinds.Contains kind then expectedKeys <- expectedKeys.Add "data"
            if priorityKinds.Contains kind then expectedKeys <- expectedKeys.Add "priority"
            if proxyKinds.Contains kind then expectedKeys <- expectedKeys.Add "proxied"
            if kind = "A" then
                expectedKeys <- expectedKeys.Add "comment"
                expectedKeys <- expectedKeys.Add "tags"
            Assert.That((record kind).Inputs.Keys |> Set.ofSeq, Is.EquivalentTo expectedKeys, kind)
            Assert.That((record kind).Inputs.ContainsKey "priority", Is.EqualTo(priorityKinds.Contains kind), kind)
            Assert.That((record kind).Inputs.ContainsKey "proxied", Is.EqualTo(proxyKinds.Contains kind), kind)
        Assert.That(unbox<bool> (record "A").Inputs["proxied"], Is.False)
        Assert.That(unbox<bool> (record "AAAA").Inputs["proxied"], Is.False)
        Assert.That(unbox<bool> (record "CNAME").Inputs["proxied"], Is.True)
        Assert.That(dataNum "URI" "weight", Is.EqualTo 0.0)
        Assert.That((record "A").Inputs["comment"], Is.EqualTo "edge")
        Assert.That(stringListInput (record "A") "tags", Is.EquivalentTo [ "owner:dns"; "env:test" ])
        Assert.That(text "MX" "content", Is.EqualTo ".")
        Assert.That(number "MX" "priority", Is.EqualTo 0.0)
        Assert.That(number "SRV" "priority", Is.EqualTo 5.0)
        Assert.That(dataNum "SRV" "priority", Is.EqualTo 5.0)
        Assert.That(number "URI" "priority", Is.EqualTo 0.0)
        Assert.That(dataText "URI" "target", Is.EqualTo "https://example.net/path")
        Assert.That(dataNum "CAA" "flags", Is.EqualTo 0.0)
        Assert.That(dataText "CAA" "tag", Is.EqualTo "issue")
        Assert.That(dataText "CAA" "value", Is.EqualTo "letsencrypt.org")
        Assert.That(dataNum "CERT" "algorithm", Is.EqualTo 8.0)
        Assert.That(dataText "CERT" "certificate", Is.EqualTo "AQID")
        Assert.That(dataNum "CERT" "keyTag", Is.EqualTo 0.0)
        Assert.That(dataNum "CERT" "type", Is.EqualTo 1.0)
        Assert.That(dataNum "DNSKEY" "flags", Is.EqualTo 0.0)
        Assert.That(dataNum "DNSKEY" "algorithm", Is.EqualTo 8.0)
        Assert.That(dataNum "DNSKEY" "protocol", Is.EqualTo 3.0)
        Assert.That(dataText "DNSKEY" "publicKey", Is.EqualTo "AQID")
        Assert.That(dataNum "DS" "algorithm", Is.EqualTo 8.0)
        Assert.That(dataText "DS" "digest", Is.EqualTo "abcd")
        Assert.That(dataNum "DS" "digestType", Is.EqualTo 2.0)
        Assert.That(dataNum "DS" "keyTag", Is.EqualTo 0.0)
        Assert.That(dataNum "HTTPS" "priority", Is.EqualTo 1.0)
        Assert.That(dataText "HTTPS" "target", Is.EqualTo ".")
        Assert.That(dataText "HTTPS" "value", Is.EqualTo "alpn=h2")
        for key, expected in [ "latDegrees", 37.0; "latMinutes", 46.0; "latSeconds", 49.0; "longDegrees", 122.0; "longMinutes", 25.0; "longSeconds", 9.0; "altitude", 0.0; "size", 0.0; "precisionHorz", 10.0; "precisionVert", 0.0 ] do
            Assert.That(dataNum "LOC" key, Is.EqualTo expected, key)
        Assert.That(dataText "LOC" "latDirection", Is.EqualTo "N")
        Assert.That(dataText "LOC" "longDirection", Is.EqualTo "W")
        Assert.That(dataText "NAPTR" "flags", Is.EqualTo "s")
        Assert.That(dataNum "NAPTR" "order", Is.EqualTo 0.0)
        Assert.That(dataNum "NAPTR" "preference", Is.EqualTo 0.0)
        Assert.That(dataText "NAPTR" "regex", Is.EqualTo "")
        Assert.That(dataText "NAPTR" "replacement", Is.EqualTo ".")
        Assert.That(dataText "NAPTR" "service", Is.EqualTo "")
        Assert.That(dataText "SMIMEA" "certificate", Is.EqualTo "abcd")
        Assert.That(dataNum "SMIMEA" "matchingType", Is.EqualTo 0.0)
        Assert.That(dataNum "SMIMEA" "selector", Is.EqualTo 1.0)
        Assert.That(dataNum "SMIMEA" "usage", Is.EqualTo 3.0)
        Assert.That(dataNum "SRV" "port", Is.EqualTo 5222.0)
        Assert.That(dataText "SRV" "target", Is.EqualTo "talk.example.net")
        Assert.That(dataNum "SRV" "weight", Is.EqualTo 0.0)
        Assert.That(dataNum "SSHFP" "algorithm", Is.EqualTo 1.0)
        Assert.That(dataText "SSHFP" "fingerprint", Is.EqualTo "abcd")
        Assert.That(dataNum "SSHFP" "type", Is.EqualTo 2.0)
        Assert.That(dataNum "SVCB" "priority", Is.EqualTo 0.0)
        Assert.That(dataText "SVCB" "target", Is.EqualTo ".")
        Assert.That(dataText "SVCB" "value", Is.EqualTo "alpn=h2")
        Assert.That(dataText "TLSA" "certificate", Is.EqualTo "abcd")
        Assert.That(dataNum "TLSA" "matchingType", Is.EqualTo 1.0)
        Assert.That(dataNum "TLSA" "selector", Is.EqualTo 0.0)
        Assert.That(dataNum "TLSA" "usage", Is.EqualTo 3.0)
        Assert.That((record "A").Inputs["comment"], Is.EqualTo "edge")
        Assert.That((record "A").Inputs.ContainsKey "tags", Is.True)
        Assert.That(mocks.Calls, Is.Empty)
        Assert.That((record "A").Name, Is.EqualTo "cloudflare-dns-16-cybergulag.today-13-edge-wildcard")

    [<Test>]
    member _.``IDN owners preserve underscores wildcards and avoid double zone suffixes``() =
        let spec =
            cloudflare {
                domain "münich.example" {
                    zoneId testZoneId
                    dns {
                        a "underscore" { name "_sip._tcp"; address "192.0.2.1" }
                        a "wildcard" { name "*.bücher"; address "192.0.2.2" }
                        a "absolute" { name "www.xn--mnich-kva.example."; address "192.0.2.3" }
                        a "apex" { name "@"; address "192.0.2.4" }
                    }
                }
            }
        let mocks = CloudflareMocks([])
        run mocks spec
        let byKey = dnsResources mocks |> Array.map (fun resource -> resource.Name, resource) |> Map.ofArray
        Assert.That(stringInput byKey["cloudflare-dns-21-xn--mnich-kva.example-10-underscore"] "name", Is.EqualTo "_sip._tcp.xn--mnich-kva.example")
        Assert.That(stringInput byKey["cloudflare-dns-21-xn--mnich-kva.example-8-wildcard"] "name", Is.EqualTo "*.xn--bcher-kva.xn--mnich-kva.example")
        Assert.That(stringInput byKey["cloudflare-dns-21-xn--mnich-kva.example-8-absolute"] "name", Is.EqualTo "www.xn--mnich-kva.example")
        Assert.That(stringInput byKey["cloudflare-dns-21-xn--mnich-kva.example-4-apex"] "name", Is.EqualTo "xn--mnich-kva.example")

    [<Test>]
    member _.``Zone lookup requires one exact normalized match and accepts an account filter``() =
        let spec =
            cloudflare {
                domain "CYBERGULAG\u3002today\uFF0e" {
                    accountId "account-id"
                    dns { a "edge" { name "@"; address "192.0.2.1" } }
                }
            }
        let mocks = CloudflareMocks([ "other.example", "other-zone"; "CYBERGULAG.TODAY.", "exact-zone" ])
        run mocks spec
        Assert.That(mocks.Calls, Has.Count.EqualTo 1)
        let call = mocks.Calls |> Seq.exactlyOne
        Assert.That(call.Args["name"], Is.EqualTo "cybergulag.today")
        let account = call.Args["account"] :?> ImmutableDictionary<string, obj>
        Assert.That(account["id"], Is.EqualTo "account-id")
        Assert.That(stringInput (dnsResources mocks |> Array.exactlyOne) "zoneId", Is.EqualTo "exact-zone")

    [<TestCase(false)>]
    [<TestCase(true)>]
    member _.``Zone lookup rejects zero or multiple exact matches``(multiple: bool) =
        let spec = cloudflare { domain "example.test" { dns { a "edge" { name "@"; address "192.0.2.1" } } } }
        let zones = if multiple then [ "example.test", "one"; "EXAMPLE.TEST.", "two" ] else [ "other.test", "other" ]
        let failure = Assert.Catch<Exception>(TestDelegate(fun () -> run (CloudflareMocks(zones)) spec))
        Assert.That(failure, Is.Not.Null)
        Assert.That(failure.ToString(), Does.Contain(if multiple then "multiple" else "no exact match"))

    [<Test>]
    member _.``Same-owner RRset members stay separate while identical values are rejected``() =
        let spec =
            cloudflare {
                domain "example.test" {
                    zoneId testZoneId
                    dns {
                        a "first" { name "@"; address "192.0.2.1" }
                        a "second" { name "@"; address "192.0.2.2" }
                    }
                }
            }
        let mocks = CloudflareMocks([])
        run mocks spec
        Assert.That(dnsResources mocks, Has.Length.EqualTo 2)
        Assert.Throws<ArgumentException>(fun () ->
            cloudflare {
                domain "example.test" {
                    zoneId testZoneId
                    dns {
                        a "first" { name "@"; address "192.0.2.1" }
                        a "duplicate" { name "@"; address "192.0.2.1" }
                    }
                }
            } |> ignore) |> ignore

    [<Test>]
    member _.``TXT presentation quotes escapes and segments UTF-8 without changing payload``() =
        let longText = String.replicate 300 "x" + "\"\\\n"
        let spec =
            cloudflare {
                domain "example.test" {
                    zoneId testZoneId
                    dns {
                        txt "long" { name "@"; text longText }
                        txt "spf" { name "_spf"; text "v=spf1 include:example.net -all" }
                        txt "segments" { name "_dkim"; segments [ String.replicate 255 "x"; "p=abc" ] }
                        txt "unicode" { name "unicode"; text (String.replicate 128 "é") }
                    }
                }
            }
        let mocks = CloudflareMocks([])
        run mocks spec
        let records = dnsResources mocks |> Array.map (fun resource -> resource.Name, resource) |> Map.ofArray
        let longContent = stringInput records["cloudflare-dns-12-example.test-4-long"] "content"
        Assert.That(longContent, Does.StartWith("\"" + String.replicate 255 "x" + "\" \""))
        Assert.That(longContent, Does.Contain("\\\""))
        Assert.That(longContent, Does.Contain("\\\\"))
        Assert.That(longContent, Does.Contain("\\010"))
        Assert.That(stringInput records["cloudflare-dns-12-example.test-3-spf"] "content", Is.EqualTo "\"v=spf1 include:example.net -all\"")
        Assert.That(stringInput records["cloudflare-dns-12-example.test-8-segments"] "content", Is.EqualTo("\"" + String.replicate 255 "x" + "\" \"p=abc\""))
        Assert.That(stringInput records["cloudflare-dns-12-example.test-7-unicode"] "content", Is.EqualTo("\"" + String.replicate 127 "\\195\\169" + "\" \"\\195\\169\""))
        Assert.Throws<ArgumentException>(fun () ->
            cloudflare {
                domain "example.test" {
                    zoneId testZoneId
                    dns { txt "too-long" { name "@"; segments [ String.replicate 256 "x" ] } }
                }
            } |> ignore) |> ignore

    [<Test>]
    member _.``Pulumi Output values flow into records without blocking``() =
        let mocks = CloudflareMocks([])
        Deployment.TestAsync(
            mocks,
            TestOptions(),
            Action(fun () ->
                let source (name: string) (recordType: string) (content: string) =
                    let args = Pulumi.Cloudflare.DnsRecordArgs()
                    args.ZoneId <- Input<string>.op_Implicit "zone"
                    args.Name <- Input<string>.op_Implicit (name + ".example.test")
                    args.Type <- Input<string>.op_Implicit recordType
                    args.Ttl <- Input<double>.op_Implicit 1.0
                    args.Content <- Input<string>.op_Implicit content
                    Pulumi.Cloudflare.DnsRecord(name, args)
                let ipv4 = source "output-source" "A" "192.0.2.99"
                let ipv6 = source "ipv6-source" "AAAA" "2001:0DB8:0:0::1"
                let host = source "host-source" "A" "HOST.Example.NET."
                let spec =
                    cloudflare {
                        domain "example.test" {
                            zoneId testZoneId
                            dns {
                                a "from-output" { name "@"; addressOutput ipv4.Content }
                                aaaa "from-v6-output" { name "v6"; addressOutput ipv6.Content }
                                cname "from-target-output" { name "alias"; targetOutput host.Content }
                            }
                        }
                    }
                CF.deploy spec |> ignore)
        ).GetAwaiter().GetResult() |> ignore
        let records = dnsResources mocks |> Array.map (fun resource -> resource.Name, resource) |> Map.ofArray
        Assert.That(stringInput records["cloudflare-dns-12-example.test-11-from-output"] "content", Is.EqualTo "192.0.2.99")
        Assert.That(stringInput records["cloudflare-dns-12-example.test-14-from-v6-output"] "content", Is.EqualTo "2001:db8::1")
        Assert.That(stringInput records["cloudflare-dns-12-example.test-18-from-target-output"] "content", Is.EqualTo "host.example.net")
        for source in [ "output-source"; "ipv6-source"; "host-source" ] do
            Assert.That(mocks.Resources.ContainsKey source, Is.True, source)

    [<Test>]
    member _.``Pulumi names stay stable across declaration reordering and record changes``() =
        let first =
            cloudflare {
                domain "example.test" {
                    zoneId testZoneId
                    dns {
                        a "stable-key" { name "@"; address "192.0.2.1"; ttl Auto }
                        a "second-key" { name "second"; address "192.0.2.2" }
                    }
                }
            }
        let second =
            cloudflare {
                domain "example.test" {
                    dns {
                        aaaa "second-key" { name "changed"; address "2001:db8::2" }
                        aaaa "stable-key" { name "_changed"; address "2001:db8::1"; ttl (Fixed 300) }
                    }
                }
            }
        let firstMocks = CloudflareMocks([])
        let secondMocks = CloudflareMocks([ "example.test", "lookup-zone" ])
        run firstMocks first
        run secondMocks second
        let names mocks = dnsResources mocks |> Array.map (fun resource -> resource.Name) |> Set.ofArray
        Assert.That(names firstMocks, Is.EquivalentTo(names secondMocks))
        Assert.That(names firstMocks, Does.Contain "cloudflare-dns-12-example.test-10-stable-key")
        Assert.That(secondMocks.Calls, Has.Count.EqualTo 1)

    [<Test>]
    member _.``Absolute owners outside the zone and invalid proxy TTL combinations fail locally``() =
        Assert.Throws<ArgumentException>(fun () ->
            cloudflare {
                domain "example.test" {
                    zoneId testZoneId
                    dns { a "outside" { name "outside.other.test."; address "192.0.2.1" } }
                }
            } |> ignore) |> ignore
        Assert.Throws<ArgumentException>(fun () ->
            cloudflare {
                domain "example.test" {
                    zoneId testZoneId
                    dns { a "proxied" { name "@"; address "192.0.2.1"; proxy Proxied; ttl (Fixed 300) } }
                }
            } |> ignore) |> ignore
 
    [<Test>]
    member _.``Unicode DNS separators normalize zones and owners before splitting``() =
        let spellings = [ "EXAMPLE.test."; "example.test\u3002"; "example\uFF0Etest\uFF0E"; "example\uFF61test\uFF61" ]
        let nameSets =
            spellings
            |> List.map (fun zone ->
                let spec =
                    cloudflare {
                        domain zone {
                            zoneId testZoneId
                            dns {
                                a "apex" { name "@"; address "192.0.2.1" }
                                a "absolute-apex" { name "example.test\u3002"; address "192.0.2.2" }
                                cname "target" { name "www"; target "origin.example\uFF61" }
                            }
                        }
                    }
                let mocks = CloudflareMocks([])
                run mocks spec
                let byType = dnsResources mocks |> Array.map (fun resource -> stringInput resource "type", resource) |> Map.ofArray
                Assert.That(stringInput byType["A"] "name", Is.EqualTo "example.test")
                Assert.That(stringInput byType["CNAME"] "content", Is.EqualTo "origin.example")
                dnsResources mocks |> Array.map (fun resource -> resource.Name) |> Set.ofArray)
        Assert.That(nameSets |> List.distinct, Has.Length.EqualTo 1)
        Assert.Throws<ArgumentException>(fun () ->
            cloudflare {
                domain "example.test" {
                    zoneId testZoneId
                    dns { a "foreign" { name "other.test\u3002"; address "192.0.2.1" } }
                }
            } |> ignore) |> ignore
        Assert.Throws<ArgumentException>(fun () ->
            cloudflare {
                domain "example.test" {
                    zoneId testZoneId
                    dns { a "misplaced-wildcard" { name "api.*.example.test"; address "192.0.2.1" } }
                }
            } |> ignore) |> ignore
        for targetValue in [ "*.edge.example.net"; "single-label" ] do
            Assert.Throws<ArgumentException>(fun () ->
                cloudflare {
                    domain "example.test" {
                        zoneId testZoneId
                        dns { cname "bad-target" { name "www"; target targetValue } }
                    }
                } |> ignore) |> ignore

    [<Test>]
    member _.``IPv4 IPv6 and DNS targets canonicalize before duplicate detection``() =
        let spec =
            cloudflare {
                domain "example.test" {
                    zoneId testZoneId
                    dns {
                        a "ipv4" { name "ipv4"; address "192.0.2.1" }
                        aaaa "ipv6" { name "ipv6"; address "2001:0DB8:0:0::1" }
                        cname "canonical-target" { name "alias"; target "HOST.Example.NET." }
                    }
                }
            }
        let mocks = CloudflareMocks([])
        run mocks spec
        let byType = dnsResources mocks |> Array.map (fun resource -> stringInput resource "type", resource) |> Map.ofArray
        Assert.That(stringInput byType["A"] "content", Is.EqualTo "192.0.2.1")
        Assert.That(stringInput byType["AAAA"] "content", Is.EqualTo "2001:db8::1")
        Assert.That(stringInput byType["CNAME"] "content", Is.EqualTo "host.example.net")
        for legacy in [ "0x7f000001"; "127.1"; "010.0.0.1"; "0x7f.0.0.1" ] do
            Assert.Throws<ArgumentException>(fun () ->
                cloudflare {
                    domain "example.test" {
                        zoneId testZoneId
                        dns { a "legacy" { name "@"; address legacy } }
                    }
                } |> ignore) |> ignore
        Assert.Throws<ArgumentException>(fun () ->
            cloudflare {
                domain "example.test" {
                    zoneId testZoneId
                    dns {
                        aaaa "compact" { name "v6"; address "2001:db8::1" }
                        aaaa "expanded" { name "v6"; address "2001:0db8:0:0::1" }
                    }
                }
            } |> ignore) |> ignore
        Assert.Throws<ArgumentException>(fun () ->
            cloudflare {
                domain "example.test" {
                    zoneId testZoneId
                    dns {
                        cname "without-dot" { name "alias"; target "host.example.net" }
                        cname "with-dot" { name "alias"; target "HOST.EXAMPLE.NET." }
                    }
                }
            } |> ignore) |> ignore

    [<Test>]
    member _.``MX and LOC accept provider boundaries and reject values outside them``() =
        let valid =
            cloudflare {
                domain "example.test" {
                    zoneId testZoneId
                    dns {
                        mx "mx-max" { name "mail"; target "mail.example.net"; priority 65535 }
                        loc "loc-min" {
                            name "loc-min"
                            latitude (coordinate 0 0 0.0 North)
                            longitude (coordinate 0 0 0.0 East)
                            altitude -100000.0
                            size 0.0
                            precisionHorz 0.0
                            precisionVert 0.0
                        }
                        loc "loc-max" {
                            name "loc-max"
                            latitude (coordinate 90 0 0.0 South)
                            longitude (coordinate 180 0 0.0 West)
                            altitude 42849672.95
                            size 90000000.0
                            precisionHorz 90000000.0
                            precisionVert 90000000.0
                        }
                        loc "loc-seconds" {
                            name "loc-seconds"
                            latitude (coordinate 0 0 59.999 North)
                            longitude (coordinate 0 0 59.999 East)
                        }
                    }
                }
            }
        let mocks = CloudflareMocks([])
        run mocks valid
        let records = dnsResources mocks
        let mxRecord = records |> Array.find (fun record -> stringInput record "type" = "MX")
        let locMax = records |> Array.find (fun record -> stringInput record "name" = "loc-max.example.test")
        Assert.That(numberInput mxRecord "priority", Is.EqualTo 65535.0)
        Assert.That(dataNumber locMax "altitude", Is.EqualTo 42849672.95)
        Assert.That(dataNumber locMax "size", Is.EqualTo 90000000.0)
        Assert.That(dataNumber locMax "precisionHorz", Is.EqualTo 90000000.0)
        Assert.That(dataNumber locMax "precisionVert", Is.EqualTo 90000000.0)
        let invalidLoc label latitudeSeconds longitudeSeconds altitudeValue sizeValue precisionHorzValue precisionVertValue =
            fun () ->
                cloudflare {
                    domain "example.test" {
                        zoneId testZoneId
                        dns {
                            loc label {
                                name label
                                latitude (coordinate 0 0 latitudeSeconds North)
                                longitude (coordinate 0 0 longitudeSeconds East)
                                altitude altitudeValue
                                size sizeValue
                                precisionHorz precisionHorzValue
                                precisionVert precisionVertValue
                            }
                        }
                    }
                } |> ignore
        let invalidValues =
            [ invalidLoc "lat-seconds-low" -0.001 0.0 0.0 0.0 0.0 0.0
              invalidLoc "lat-seconds-high" 59.9991 0.0 0.0 0.0 0.0 0.0
              invalidLoc "long-seconds-low" 0.0 -0.001 0.0 0.0 0.0 0.0
              invalidLoc "long-seconds-high" 0.0 59.9991 0.0 0.0 0.0 0.0
              invalidLoc "altitude-low" 0.0 0.0 -100000.01 0.0 0.0 0.0
              invalidLoc "altitude-high" 0.0 0.0 42849672.96 0.0 0.0 0.0
              invalidLoc "size-low" 0.0 0.0 0.0 -0.01 0.0 0.0
              invalidLoc "size-high" 0.0 0.0 0.0 90000000.01 0.0 0.0
              invalidLoc "precision-horz-low" 0.0 0.0 0.0 0.0 -0.01 0.0
              invalidLoc "precision-horz-high" 0.0 0.0 0.0 0.0 90000000.01 0.0
              invalidLoc "precision-vert-low" 0.0 0.0 0.0 0.0 0.0 -0.01
              invalidLoc "precision-vert-high" 0.0 0.0 0.0 0.0 0.0 90000000.01 ]
        for invalid in invalidValues do
            Assert.Throws<ArgumentException>(TestDelegate invalid) |> ignore
        for priorityValue in [ -1; 65536 ] do
            Assert.Throws<ArgumentException>(fun () ->
                cloudflare {
                    domain "example.test" {
                        zoneId testZoneId
                        dns { mx "invalid-priority" { name "mail"; target "."; priority priorityValue } }
                    }
                } |> ignore) |> ignore

    [<Test>]
    member _.``DNSKEY NAPTR and record metadata honor documented value constraints``() =
        let valid =
            cloudflare {
                domain "example.test" {
                    zoneId testZoneId
                    dns {
                        dnskey "key" { name "key"; flags 0; algorithm 8; protocol 3; publicKey "AQID" }
                        naptr "service" {
                            name "_service._tcp"
                            naptrFlags "A1"
                            order 0
                            preference 0
                            regex ""
                            replacement "."
                            service ""
                        }
                        a "metadata" {
                            name "@"
                            address "192.0.2.1"
                            comment "reviewed"
                            tags [ "owner:dns"; "purpose:préview" ]
                        }
                    }
                }
            }
        let mocks = CloudflareMocks([])
        run mocks valid
        let records = dnsResources mocks
        let metadata = records |> Array.find (fun record -> stringInput record "type" = "A")
        Assert.That(stringInput metadata "comment", Is.EqualTo "reviewed")
        Assert.That(stringListInput metadata "tags", Is.EquivalentTo [ "owner:dns"; "purpose:préview" ])
        let assertInvalid (create: unit -> CF.Spec) =
            Assert.Throws<ArgumentException>(TestDelegate(fun () -> create() |> ignore)) |> ignore
        let dnskeySpec protocolValue () =
            cloudflare {
                domain "example.test" {
                    zoneId testZoneId
                    dns { dnskey "invalid-protocol" { name "@"; flags 0; algorithm 8; protocol protocolValue; publicKey "AQID" } }
                }
            }
        for protocolValue in [ 0; 4 ] do assertInvalid (dnskeySpec protocolValue)
        let naptrSpec flags () =
            cloudflare {
                domain "example.test" {
                    zoneId testZoneId
                    dns {
                        naptr "invalid-flags" {
                            name "_service._tcp"
                            naptrFlags flags
                            order 0
                            preference 0
                            regex ""
                            replacement "."
                            service ""
                        }
                    }
                }
            }
        for flags in [ "s-"; "ñ" ] do assertInvalid (naptrSpec flags)
        let metadataSpec commentText tagValues () =
            cloudflare {
                domain "example.test" {
                    zoneId testZoneId
                    dns { a "metadata" { name "@"; address "192.0.2.1"; comment commentText; tags tagValues } }
                }
            }
        for tag in [ "missing-separator"; "bad name:value"; String.replicate 33 "x" + ":value"; "key:" + String.replicate 101 "x"; "key:line\nbreak" ] do
            assertInvalid (metadataSpec "valid" [ tag ])
        assertInvalid (metadataSpec "line\nbreak" [ "owner:dns" ])
        let invalidZoneSpec zoneIdValue () =
            cloudflare {
                domain "example.test" {
                    zoneId zoneIdValue
                    dns { a "edge" { name "@"; address "192.0.2.1" } }
                }
            }
        for zoneIdValue in [ "short"; String.replicate 32 "g" ] do assertInvalid (invalidZoneSpec zoneIdValue)
