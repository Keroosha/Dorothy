namespace Dorothy.Tests

open System
open System.Collections.Generic
open System.Collections.Immutable
open System.Threading
open Dorothy.DSL.Provider
open NUnit.Framework
open Pulumi.Experimental
open Pulumi.Experimental.Provider

[<RequireQualifiedAccess>]
module private ProviderTestValues =
    let map (entries: seq<string * PropertyValue>) =
        let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
        for key, value in entries do builder.Add(key, value)
        PropertyValue(builder.ToImmutable())

    let inputMap (entries: seq<string * PropertyValue>) =
        let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
        for key, value in entries do builder.Add(key, value)
        builder.ToImmutable()

    let array (values: seq<PropertyValue>) = PropertyValue(ImmutableArray.CreateRange(values))

    let string (value: string) = PropertyValue(value)
    let number (value: int) = PropertyValue(float value)
    let boolean (value: bool) = PropertyValue(value)

    let emptyMap = map Seq.empty

    let mapContents (value: PropertyValue) =
        let mutable values = ImmutableDictionary<string, PropertyValue>.Empty
        if value.TryGetMap(&values) then values else failwith "Expected a map property value."

    let requestUrn (token: string) (name: string) = Pulumi.Urn(sprintf "urn:pulumi:unit::unit::%s::%s" token name)

    let checkRequest (token: string) (inputs: ImmutableDictionary<string, PropertyValue>) =
        CheckRequest(
            requestUrn token "test-resource",
            ImmutableDictionary<string, PropertyValue>.Empty,
            inputs,
            ImmutableArray<byte>.Empty
        )

    let diffRequest
        (token: string)
        (id: string)
        (oldInputs: ImmutableDictionary<string, PropertyValue>)
        (oldOutputs: ImmutableDictionary<string, PropertyValue>)
        (newInputs: ImmutableDictionary<string, PropertyValue>)
        =
        DiffRequest(
            requestUrn token "test-resource",
            id,
            oldOutputs,
            newInputs,
            ImmutableArray<string>.Empty,
            oldInputs
        )

[<TestFixture>]
type ProviderTests() =
    let check
        (provider: DorothyProvider)
        (token: string)
        (inputs: ImmutableDictionary<string, PropertyValue>)
        =
        provider.Check(ProviderTestValues.checkRequest token inputs, CancellationToken.None).GetAwaiter().GetResult()

    let diff
        (provider: DorothyProvider)
        (token: string)
        (id: string)
        (oldInputs: ImmutableDictionary<string, PropertyValue>)
        (oldOutputs: ImmutableDictionary<string, PropertyValue>)
        (newInputs: ImmutableDictionary<string, PropertyValue>)
        =
        provider.Diff(ProviderTestValues.diffRequest token id oldInputs oldOutputs newInputs, CancellationToken.None).GetAwaiter().GetResult()

    let connection (address: string) (user: string) =
        ProviderTestValues.map [
            "address", ProviderTestValues.string address
            "user", ProviderTestValues.string user
        ]

    let aptPackages (packageValues: seq<string * PropertyValue>) = ProviderTestValues.map packageValues

    let aptInput (address: string) (packages: PropertyValue) =
        ProviderTestValues.inputMap [
            "connection", connection address "root"
            "packages", packages
        ]

    let ufwInput (port: int) =
        ProviderTestValues.inputMap [
            "connection", connection "192.0.2.1" "root"
            "rules", ProviderTestValues.array [
                ProviderTestValues.array (
                    [ "allow"; "in"; "proto"; "tcp"; "to"; "any"; "port"; string port ]
                    |> List.map ProviderTestValues.string
                )
            ]
            "enabled", ProviderTestValues.boolean true
            "defaultIn", ProviderTestValues.string "deny"
            "defaultOut", ProviderTestValues.string "allow"
        ]

    let traefikInput (backend: string) (adminPort: int) =
        let router =
            ProviderTestValues.map [
                "host", ProviderTestValues.string "example.org"
                "entryPoint", ProviderTestValues.string "websecure"
                "backend", ProviderTestValues.string backend
                "tls", ProviderTestValues.map [
                    "kind", ProviderTestValues.string "none"
                    "name", ProviderTestValues.string ""
                ]
            ]
        ProviderTestValues.inputMap [
            "connection", connection "192.0.2.1" "root"
            "entryPoints", ProviderTestValues.map [ "websecure", ProviderTestValues.number 443 ]
            "resolvers", ProviderTestValues.emptyMap
            "routers", ProviderTestValues.map [ "example", router ]
            "certificates", ProviderTestValues.emptyMap
            "adminPort", ProviderTestValues.number adminPort
        ]


    [<Test>]
    member _.``Provider Check normalizes APT connection defaults without host access``() =
        // Arrange
        let provider = DorothyProvider()
        let packages = aptPackages [ "nginx", ProviderTestValues.emptyMap ]
        let inputs = aptInput "192.0.2.10" packages

        // Act
        let response = check provider "keroosha:debian:AptPackageSet" inputs
        let checkedConnection = ProviderTestValues.mapContents response.Inputs["connection"]
        let mutable port = 0.0
        let hasPort = checkedConnection["port"].TryGetNumber(&port)

        // Assert
        Assert.That(response.Failures, Is.Empty)
        Assert.That(hasPort, Is.True)
        Assert.That(port, Is.EqualTo(22.0))
        Assert.That((ProviderTestValues.mapContents response.Inputs["packages"]).ContainsKey("nginx"), Is.True)

    [<Test>]
    member _.``Provider Check rejects malformed UFW rule arguments``() =
        // Arrange
        let provider = DorothyProvider()
        let invalidInputs =
            ProviderTestValues.inputMap [
                "connection", connection "192.0.2.1" "root"
                "rules", ProviderTestValues.array [
                    ProviderTestValues.array (
                        [ "allow"; "in"; "443/tcp"; "comment"; "injected" ]
                        |> List.map ProviderTestValues.string
                    )
                ]
            ]

        // Act
        let response = check provider "keroosha:debian:Ufw" invalidInputs
        let failures = response.Failures |> Seq.toList
        let rejectedCommentToken = failures |> List.exists (fun failure -> failure.Property = "rules[0][3]")

        // Assert
        Assert.That(failures, Is.Not.Empty)
        Assert.That(rejectedCommentToken, Is.True)

    [<Test>]
    member _.``Provider Check preserves nested unknown entry-point values``() =
        // Arrange
        let provider = DorothyProvider()
        let unknownPort = PropertyValue.Computed
        let inputs =
            ProviderTestValues.inputMap [
                "connection", connection "192.0.2.1" "root"
                "entryPoints", ProviderTestValues.map [ "websecure", ProviderTestValues.number 443; "dynamic", unknownPort ]
                "resolvers", ProviderTestValues.emptyMap
                "routers", ProviderTestValues.emptyMap
                "certificates", ProviderTestValues.emptyMap
            ]

        // Act
        let response = check provider "keroosha:debian:Traefik" inputs
        let checkedEntryPoints = ProviderTestValues.mapContents response.Inputs["entryPoints"]

        // Assert
        Assert.That(response.Failures, Is.Empty)
        Assert.That(checkedEntryPoints["dynamic"].IsComputed, Is.True)

    [<Test>]
    member _.``Provider Diff reports exact APT package version update``() =
        // Arrange
        let provider = DorothyProvider()
        let oldPackages = aptPackages [ "mc", ProviderTestValues.map [ "version", ProviderTestValues.string "4.8.33" ] ]
        let newPackages = aptPackages [ "mc", ProviderTestValues.map [ "version", ProviderTestValues.string "4.8.34" ] ]
        let oldInputs = aptInput "192.0.2.1" oldPackages
        let newInputs = aptInput "192.0.2.1" newPackages
        let oldOutputs =
            ProviderTestValues.inputMap [
                "installedVersions", ProviderTestValues.map [ "mc", ProviderTestValues.string "4.8.33" ]
                "managedPackages", ProviderTestValues.array [ ProviderTestValues.string "mc" ]
            ]

        // Act
        let response = diff provider "keroosha:debian:AptPackageSet" "owned-id" oldInputs oldOutputs newInputs

        // Assert
        Assert.That(response.Changes.HasValue, Is.True)
        Assert.That(response.Changes.Value, Is.True)
        Assert.That(response.Diffs.Contains("packages"), Is.True)
        Assert.That(response.DetailedDiff.ContainsKey("packages[\"mc\"].version"), Is.True)

    [<Test>]
    member _.``Provider Diff reports a nested UFW port update``() =
        // Arrange
        let provider = DorothyProvider()
        let oldInputs = ufwInput 80
        let newInputs = ufwInput 443
        let oldOutputs =
            ProviderTestValues.inputMap [
                "actualRules", ProviderTestValues.array [ ProviderTestValues.string "80/tcp ALLOW IN Anywhere" ]
                "actualEnabled", ProviderTestValues.boolean true
                "actualDefaultIn", ProviderTestValues.string "deny"
                "actualDefaultOut", ProviderTestValues.string "allow"
                "inSync", ProviderTestValues.boolean true
            ]

        // Act
        let response = diff provider "keroosha:debian:Ufw" "owned-id" oldInputs oldOutputs newInputs

        // Assert
        Assert.That(response.Changes.HasValue, Is.True)
        Assert.That(response.Changes.Value, Is.True)
        Assert.That(response.Diffs.Contains("rules"), Is.True)
        Assert.That(response.DetailedDiff.ContainsKey("rules[0][7]"), Is.True)

    [<Test>]
    member _.``Provider Diff reports nested Traefik router and admin-port changes``() =
        // Arrange
        let provider = DorothyProvider()
        let oldInputs = traefikInput "http://127.0.0.1:12345" 19080
        let newInputs = traefikInput "http://127.0.0.1:12346" 19081
        let oldOutputs = ProviderTestValues.inputMap [ "inSync", ProviderTestValues.boolean true ]

        // Act
        let response = diff provider "keroosha:debian:Traefik" "owned-id" oldInputs oldOutputs newInputs

        // Assert
        Assert.That(response.Changes.HasValue, Is.True)
        Assert.That(response.Changes.Value, Is.True)
        Assert.That(response.Diffs.Contains("routers"), Is.True)
        Assert.That(response.Diffs.Contains("adminPort"), Is.True)
        Assert.That(response.DetailedDiff.ContainsKey("routers.example.backend"), Is.True)
        Assert.That(response.DetailedDiff.ContainsKey("adminPort"), Is.True)

