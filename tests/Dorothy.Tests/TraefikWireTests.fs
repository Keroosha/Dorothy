namespace Dorothy.Tests

open System
open System.Collections.Immutable
open System.Threading
open Dorothy.DSL.Provider
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
