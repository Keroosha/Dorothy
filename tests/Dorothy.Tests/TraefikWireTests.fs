namespace Dorothy.Tests

open System
open System.Collections.Immutable
open System.Threading
open System.Text.Json
open Dorothy.DSL.Provider
open Dorothy.DSL
open NUnit.Framework
open Pulumi.Experimental
open Pulumi.Experimental.Provider

[<TestFixture>]
type TraefikWireTests() =
    let empty = ImmutableDictionary<string, PropertyValue>.Empty
    let urn = Pulumi.Urn("urn:pulumi:test::test::keroosha:debian:Traefik::ingress")
    let connection = empty.Add("address", PropertyValue("unreachable.invalid")).Add("user", PropertyValue("operator"))
    let legacy =
        empty.Add("connection", PropertyValue(connection)).Add("entryPoints", PropertyValue(empty.Add("web", PropertyValue(8000.))))
            .Add("resolvers", PropertyValue(empty)).Add("routers", PropertyValue(empty)).Add("certificates", PropertyValue(empty))
    let check inputs =
        TraefikProvider().Check(CheckRequest(urn, empty, inputs, ImmutableArray<byte>.Empty), CancellationToken.None).GetAwaiter().GetResult()
    let diff oldInputs newInputs =
        let outputs = oldInputs |> fun (inputs: ImmutableDictionary<string, PropertyValue>) -> inputs.Add("inSync", PropertyValue(true))
        let request = DiffRequest(urn, "existing-id", outputs, newInputs, ImmutableArray<string>.Empty, oldInputs)
        TraefikProvider().Diff(request, CancellationToken.None).GetAwaiter().GetResult()
    let configured (json: string) = legacy.Add("configuration", PropertyValue(json))
    let withRouterBackend (backend: string) =
        let tls = empty.Add("kind", PropertyValue("none")).Add("name", PropertyValue(""))
        let router =
            empty.Add("host", PropertyValue("site.example.test"))
                .Add("entryPoint", PropertyValue("web"))
                .Add("backend", PropertyValue(backend))
                .Add("tls", PropertyValue(tls))
        legacy.SetItem("routers", PropertyValue(empty.Add("site", PropertyValue(router))))

    let healthCheckConfiguration (serverUrl: string) =
        sprintf """{"dynamic":{"http":{"services":{"upstream":{"loadBalancer":{"servers":[{"url":"%s"}],"healthCheck":{"port":19080}}}}}}}""" serverUrl


    [<Test>]
    member _.``Legacy checkpoint has no synthetic native input or replacement``() =
        let checkedInputs = check legacy
        Assert.That(checkedInputs.Failures, Is.Empty)
        Assert.That(checkedInputs.Inputs.ContainsKey("configuration"), Is.False)
        let result = diff legacy legacy
        Assert.That(result.Changes.Value, Is.False)
        Assert.That(result.Replaces, Is.Empty)

    [<Test>]
    member _.``Computed native input stays unknown and secret in preview``() =
        let inputs = legacy.Add("configuration", PropertyValue.Computed)
        let response = check inputs
        Assert.That(response.Failures, Is.Empty)
        let preview = TraefikProvider().Create(CreateRequest(urn, inputs, TimeSpan.Zero, true), CancellationToken.None).Result
        Assert.That(preview.Outputs["configuration"].IsComputed, Is.True)
        Assert.That(preview.Outputs["configuration"].IsSecret, Is.True)

    [<Test>]
    member _.``Secrets are protected even when a direct caller forgets and validation fails``() =
        let secret = "sentinel-not-for-diagnostics"
        let response = check (configured ("{\"bad\":\"" + secret + "\"}"))
        Assert.That(response.Failures, Is.Not.Empty)
        Assert.That(response.Inputs["configuration"].IsSecret, Is.True)
        for failure in response.Failures do Assert.That(failure.Reason, Does.Not.Contain(secret))

    [<Test>]
    member _.``Diff ignores JSON map order but changing an actual setting is an update``() =
        let before = configured """{"static":{"log":{"level":"INFO","format":"json"}}}"""
        let reordered = configured """{ "static": {"log": {"format":"json", "level":"INFO"}}}"""
        let after = configured """{"static":{"log":{"level":"WARN","format":"json"}}}"""
        Assert.That((check before).Failures, Is.Empty)
        Assert.That((diff before reordered).Changes.Value, Is.False)
        let changed = diff before after
        Assert.That(changed.Diffs, Is.EquivalentTo([ "configuration" ]))
        Assert.That(changed.Replaces, Is.Empty)
        Assert.That(changed.DetailedDiff.Count, Is.EqualTo(1))

    [<TestCase("{\"static\":{},\"static\":{}}")>]
    [<TestCase("""{"dynamic":{"tcp":{"services":{"hidden":{"loadBalancer":{"servers":[{"address":"alias.test:19080"}]}}}}}}""")>]
    [<TestCase("{\"dynamic\":{\"http\":{\"middlewares\":{\"a\":{\"headers\":{\"customResponseHeaders\":{\"X-Test\":\"{{ . }}\"}}}}}}}")>]
    member _.``Check rejects ambiguous or unsafe native configuration before SSH``(json: string) =
        Assert.That((check (configured json)).Failures, Is.Not.Empty)

    [<Test>]
    member _.``Legacy preview projects TLS summary as output only``() =
        let preview = TraefikProvider().Create(CreateRequest(urn, legacy, TimeSpan.Zero, true), CancellationToken.None).Result
        Assert.That(preview.Outputs.ContainsKey("tlsProbeSummary"), Is.True)
        Assert.That(preview.Outputs["tlsProbeSummary"].IsComputed, Is.True)
        Assert.That(preview.Outputs.ContainsKey("configuration"), Is.False)

    [<Test>]
    member _.``Combined schema declares TLS summary output-only and defaults certificate use``() =
        let response = DorothyProvider().GetSchema(GetSchemaRequest(0, "", ""), CancellationToken.None).GetAwaiter().GetResult()
        use schema = JsonDocument.Parse(response.Schema)
        let resource = schema.RootElement.GetProperty("resources").GetProperty("keroosha:debian:Traefik")
        let inputProperties = resource.GetProperty("inputProperties")
        let outputProperties = resource.GetProperty("properties")
        let mutable summary = Unchecked.defaultof<JsonElement>
        Assert.That(inputProperties.TryGetProperty("tlsProbeSummary", &summary), Is.False)
        Assert.That(outputProperties.TryGetProperty("tlsProbeSummary", &summary), Is.True)
        let summarySchema = outputProperties.GetProperty("tlsProbeSummary")
        Assert.That(
            summarySchema.GetProperty("additionalProperties").GetProperty("type").GetString(),
            Is.EqualTo("integer")
        )
        Assert.That(summarySchema.GetProperty("description").GetString(), Does.Contain("legacyProbesAttempted"))
        let requiredResourceOutputs =
            resource.GetProperty("required").EnumerateArray()
            |> Seq.map (fun field -> field.GetString())
            |> Set.ofSeq
        Assert.That(Set.contains "tlsProbeSummary" requiredResourceOutputs, Is.True)
        let usage =
            inputProperties.GetProperty("certificates").GetProperty("additionalProperties")
                .GetProperty("properties").GetProperty("usage")
        Assert.That(usage.GetProperty("default").GetString(), Is.EqualTo("server"))
        Assert.That(usage.GetProperty("enum").GetArrayLength(), Is.EqualTo(2))

    [<TestCase("http://192.0.2.31:19080", true)>]
    [<TestCase("http://127.0.0.1:19080", false)>]
    [<TestCase("http://[::1]:19080", false)>]
    [<TestCase("http://admin-alias.example.test:19080", false)>]
    member _.``Numeric remote admin port is allowed while local and ambiguous targets fail closed``(backend: string, allowed: bool) =
        let response = check (withRouterBackend backend)
        Assert.That(response.Failures.Count = 0, Is.EqualTo(allowed))
        if not allowed then
            Assert.That(response.Failures[0].Reason, Does.Contain("proxy destination").And.Not.Contain(backend))

    [<TestCase("http://192.0.2.31:8000", true)>]
    [<TestCase("http://127.0.0.1:8000", false)>]
    [<TestCase("http://health-alias.example.test:8000", false)>]
    member _.``Health-check port override protects the local admin listener``(serverUrl: string, allowed: bool) =
        let response = check (configured (healthCheckConfiguration serverUrl))
        Assert.That(response.Failures.Count = 0, Is.EqualTo(allowed))

    [<Test>]
    member _.``Secret configuration diff reports safe static dynamic and credential categories``() =
        let before =
            configured """{"static":{"log":{"level":"INFO"}},"dynamic":{"http":{"routers":{"private-route":{"rule":"Host(`site.example.test`)","service":"backend"}}}},"dnsCredentials":{"cloudflare":{"API_TOKEN":"secret-before"}}}"""
        let after =
            configured """{"static":{"log":{"level":"WARN"}},"dynamic":{"http":{"routers":{"private-route":{"rule":"Host(`site.example.test`)","service":"backend-v2"}}}},"dnsCredentials":{"cloudflare":{"API_TOKEN":"secret-after"}}}"""
        let result = diff before after
        Assert.That(
            result.DetailedDiff.Keys,
            Is.EquivalentTo([ "configuration.static"; "configuration.dynamic"; "configuration.credentials" ])
        )
        for path in result.DetailedDiff.Keys do
            Assert.That(path, Does.Not.Contain("private-route"))
            Assert.That(path, Does.Not.Contain("cloudflare"))
            Assert.That(path, Does.Not.Contain("API_TOKEN"))

    [<Test>]
    member _.``Legacy serving certificates keep their original encrypted input shape``() =
        let certificate = TestSupport.createValidCertificateFixture "legacy.example.test" [ "legacy.example.test" ]
        let fields =
            empty.Add("certificatePem", PropertyValue(certificate.ChainPem))
                .Add("privateKeyPem", PropertyValue(certificate.PrivateKeyPem))
                .Add("fingerprint", PropertyValue(certificate.Fingerprint))
        let certificates = empty.Add("legacy-certificate", PropertyValue(fields))
        let response = check (legacy.SetItem("certificates", PropertyValue(certificates)))
        Assert.That(response.Failures, Is.Empty)
        Assert.That(response.Inputs["certificates"].IsSecret, Is.True)
        let mutable normalizedCertificates = ImmutableDictionary<string, PropertyValue>.Empty
        Assert.That(response.Inputs["certificates"].TryGetMap(&normalizedCertificates), Is.True)
        let mutable normalizedCertificate = ImmutableDictionary<string, PropertyValue>.Empty
        Assert.That(normalizedCertificates["legacy-certificate"].TryGetMap(&normalizedCertificate), Is.True)
        Assert.That(normalizedCertificate.ContainsKey("usage"), Is.False)

    [<Test>]
    member _.``Certificate material diff hides names and PEM paths``() =
        let makeInputs material =
            let certificate =
                empty.Add("certificatePem", PropertyValue("pem-" + material))
                    .Add("privateKeyPem", PropertyValue("key-" + material))
                    .Add("fingerprint", PropertyValue(String.replicate 64 "a"))
            let certificates = empty.Add("sensitive-certificate-name", PropertyValue(certificate))
            legacy.SetItem("certificates", PropertyValue(certificates))
        let result = diff (makeInputs "before") (makeInputs "after")
        Assert.That(result.DetailedDiff.Keys, Is.EquivalentTo([ "certificates" ]))
        for path in result.DetailedDiff.Keys do
            Assert.That(path, Does.Not.Contain("sensitive-certificate-name"))
            Assert.That(path, Does.Not.Contain("privateKeyPem"))
        Assert.That(result.Diffs, Is.EquivalentTo([ "certificates" ]))

    [<Test>]
    member _.``Helper TLS report requires a nonnegative legacy probe count``() =
        let report =
            sprintf
                """{"inSync":true,"actualConfigHash":"%s","certificateFingerprints":{},"tlsObservations":{"legacyProbesAttempted":17,"nativeProbesAttempted":0,"unprobedCount":0,"opaqueRouterCount":0,"truncated":false}}"""
                (String.replicate 64 "a")
        let snapshot = TraefikBackend.parseSnapshot Set.empty report
        Assert.That(snapshot.TlsProbeSummary["legacyProbesAttempted"], Is.EqualTo(17))

        let missing = report.Replace("\"legacyProbesAttempted\":17,", "")
        let negative = report.Replace("\"legacyProbesAttempted\":17", "\"legacyProbesAttempted\":-1")
        for invalidReport in [ missing; negative ] do
            let failure = TestDelegate(fun () -> TraefikBackend.parseSnapshot Set.empty invalidReport |> ignore)
            Assert.Throws<InvalidOperationException>(failure) |> ignore

    [<Test>]
    member _.``Helper request serializes certificate usage and update-only prior UDP state``() =
        let certificate: NormalizedCertificate =
            { Name = "client-id"
              CertificatePem = "certificate"
              PrivateKeyPem = "key"
              Fingerprint = String.replicate 64 "a"
              Usage = "client" }
        let desired: TraefikConfig =
            { EntryPoints = ImmutableDictionary<string, int>.Empty
              Resolvers = ImmutableDictionary<string, TraefikResolver>.Empty
              Routers = ImmutableDictionary<string, TraefikRouter>.Empty
              Certificates = ImmutableDictionary<string, NormalizedCertificate>.Empty.Add("client-id", certificate)
              Configuration = None
              AdminPort = 19080 }

        use apply = JsonDocument.Parse(TraefikBackend.serializeRequest "apply" "owner" desired (Some [| "dns" |]))
        use create = JsonDocument.Parse(TraefikBackend.serializeRequest "apply" "owner" desired None)
        use read = JsonDocument.Parse(TraefikBackend.serializeRequest "read" "owner" desired (Some [| "dns" |]))
        Assert.That(apply.RootElement.GetProperty("certificates").GetProperty("client-id").GetProperty("usage").GetString(), Is.EqualTo("client"))
        Assert.That(apply.RootElement.GetProperty("previousUdpEntryPoints").[0].GetString(), Is.EqualTo("dns"))
        let mutable previous = Unchecked.defaultof<JsonElement>
        Assert.That(create.RootElement.TryGetProperty("previousUdpEntryPoints", &previous), Is.False)
        Assert.That(read.RootElement.TryGetProperty("previousUdpEntryPoints", &previous), Is.False)

        use delete = JsonDocument.Parse(TraefikBackend.serializeDeleteRequest "owner")
        let deleteFields = delete.RootElement.EnumerateObject() |> Seq.map (fun field -> field.Name) |> Set.ofSeq
        Assert.That(deleteFields, Is.EquivalentTo([ "operation"; "ownerId" ]))
