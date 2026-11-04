namespace Dorothy.Tests

open System
open System.Collections.Immutable
open System.Threading
open Dorothy.DSL.Provider
open NUnit.Framework
open Pulumi.Experimental
open Pulumi.Experimental.Provider

[<TestFixture>]
type SshProviderTests() =
    let map (entries: seq<string * PropertyValue>) =
        let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
        for key, value in entries do builder.Add(key, value)
        PropertyValue(builder.ToImmutable())

    let inputMap (entries: seq<string * PropertyValue>) =
        let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
        for key, value in entries do builder.Add(key, value)
        builder.ToImmutable()

    let array (values: seq<PropertyValue>) = PropertyValue(ImmutableArray.CreateRange(values))
    let stringValue (value: string) = PropertyValue(value)
    let numberValue (value: int) = PropertyValue(float value)
    let booleanValue (value: bool) = PropertyValue(value)

    let stringOf (value: PropertyValue) =
        let mutable result = Unchecked.defaultof<string>
        if value.TryGetString(&result) then result else failwith "Expected a string value."

    let booleanOf (value: PropertyValue) =
        let mutable result = false
        if value.TryGetBool(&result) then result else failwith "Expected a boolean value."

    let connection (address: string) =
        map [ "address", stringValue address; "user", stringValue "debian" ]

    let sshdInputs (address: string) (settings: seq<string * PropertyValue>) =
        inputMap [ "connection", connection address; "settings", map settings ]

    let fail2banInputs (address: string) (ports: seq<int>) =
        inputMap [
            "connection", connection address
            "ports", array (ports |> Seq.map numberValue)
        ]

    let checkRequest (token: string) (inputs: ImmutableDictionary<string, PropertyValue>) =
        let urn = Pulumi.Urn(sprintf "urn:pulumi:unit::unit::%s::provider-test" token)
        CheckRequest(urn, ImmutableDictionary<string, PropertyValue>.Empty, inputs, ImmutableArray<byte>.Empty)

    let check (provider: Pulumi.Experimental.Provider.Provider) (token: string) (inputs: ImmutableDictionary<string, PropertyValue>) =
        provider.Check(checkRequest token inputs, CancellationToken.None).GetAwaiter().GetResult()

    let diffRequest
        (token: string)
        (id: string)
        (oldInputs: ImmutableDictionary<string, PropertyValue>)
        (oldOutputs: ImmutableDictionary<string, PropertyValue>)
        (newInputs: ImmutableDictionary<string, PropertyValue>)
        =
        let urn = Pulumi.Urn(sprintf "urn:pulumi:unit::unit::%s::provider-test" token)
        DiffRequest(urn, id, oldOutputs, newInputs, ImmutableArray<string>.Empty, oldInputs)

    let findFailure (property: string) (failures: seq<CheckFailure>) =
        failures |> Seq.exists (fun failure -> failure.Property = property)

    let mapContents (value: PropertyValue) =
        let mutable result = ImmutableDictionary<string, PropertyValue>.Empty
        if value.TryGetMap(&result) then result else failwith "Expected a map value."

    let arrayContents (value: PropertyValue) =
        let mutable result = ImmutableArray<PropertyValue>.Empty
        if value.TryGetArray(&result) then result else failwith "Expected an array value."

    let numberOf (value: PropertyValue) =
        let mutable result = 0.0
        if value.TryGetNumber(&result) then result else failwith "Expected a number value."


    [<Test>]
    member _.``SSHD Check validates canonical settings and preserves nested secrets and unknowns``() =
        let provider = SshdProvider()
        let secret = PropertyValue("no", IsSecret = true)
        let unknown = PropertyValue.Computed
        let inputs =
            sshdInputs
                "192.0.2.10"
                [ "PasswordAuthentication", secret
                  "KbdInteractiveAuthentication", unknown
                  "Port", stringValue "2202"
                  "PermitRootLogin", stringValue "prohibit-password" ]

        let response = check provider SshdProvider.ResourceToken inputs
        let normalizedSettings = mapContents response.Inputs["settings"]

        Assert.That(response.Failures, Is.Empty)
        Assert.That(normalizedSettings["PasswordAuthentication"].IsSecret, Is.True)
        Assert.That(normalizedSettings["KbdInteractiveAuthentication"].IsComputed, Is.True)
        Assert.That(SshdBackend.isValidSetting "Port" "022", Is.False)
        Assert.That(SshdBackend.isValidSetting "PermitRootLogin" "prohibit-password", Is.True)

    [<Test>]
    member _.``SSHD Check rejects unsupported and noncanonical OpenSSH settings``() =
        let provider = SshdProvider()
        let inputs =
            sshdInputs
                "192.0.2.10"
                [ "passwordAuthentication", stringValue "yes"
                  "PasswordAuthentication", stringValue "true" ]
        let failures = check provider SshdProvider.ResourceToken inputs |> fun result -> result.Failures

        Assert.That(findFailure "settings.passwordAuthentication" failures, Is.True)
        Assert.That(findFailure "settings.PasswordAuthentication" failures, Is.True)

    [<Test>]
    member _.``SSHD Diff reports setting changes and address replacements without host access``() =
        let provider = SshdProvider()
        let oldInputs = sshdInputs "192.0.2.10" [ "PasswordAuthentication", stringValue "yes" ]
        let newInputs = sshdInputs "192.0.2.11" [ "PasswordAuthentication", stringValue "no" ]
        let oldOutputs =
            inputMap [
                "owned", booleanValue true
                "actualSettings", map [ "PasswordAuthentication", stringValue "yes" ]
                "ports", array [ numberValue 22 ]
                "inSync", booleanValue true
            ]
        let response =
            provider.Diff(
                diffRequest SshdProvider.ResourceToken "resource-id" oldInputs oldOutputs newInputs,
                CancellationToken.None
            ).GetAwaiter().GetResult()

        Assert.That(response.Changes.Value, Is.True)
        Assert.That(response.Diffs.Contains("settings"), Is.True)
        Assert.That(response.DetailedDiff.ContainsKey("settings.PasswordAuthentication"), Is.True)
        Assert.That(response.Replaces.Contains("connection.address"), Is.True)
        Assert.That(response.DeleteBeforeReplace, Is.True)

    [<Test>]
    member _.``Fail2Ban Check materializes policy defaults and validates whole-second inputs``() =
        let provider = Fail2BanProvider()
        let defaults = check provider Fail2BanProvider.ResourceToken (inputMap [ "connection", connection "192.0.2.10" ])
        let normalizedIps = arrayContents defaults.Inputs["ignoreIps"]

        Assert.That(defaults.Failures, Is.Empty)
        Assert.That(booleanOf defaults.Inputs["enabled"], Is.True)
        Assert.That(numberOf defaults.Inputs["maxRetry"], Is.EqualTo(5.0))
        Assert.That(numberOf defaults.Inputs["findTimeSeconds"], Is.EqualTo(600.0))
        Assert.That(numberOf defaults.Inputs["banTimeSeconds"], Is.EqualTo(3600.0))
        Assert.That(normalizedIps.Length, Is.EqualTo(2))
        Assert.That(stringOf normalizedIps[0], Is.EqualTo("127.0.0.0/8"))
        Assert.That(stringOf normalizedIps[1], Is.EqualTo("::1"))
        Assert.That(Fail2BanBackend.tryCanonicalIgnoreIp "2001:DB8::1" |> Option.get, Is.EqualTo("2001:db8::1"))
        Assert.That(Fail2BanBackend.tryCanonicalIgnoreIp "127.0.0.1/8" |> Option.get, Is.EqualTo("127.0.0.0/8"))
        Assert.That(Fail2BanBackend.tryCanonicalIgnoreIp "192.0.2.1/32" |> Option.get, Is.EqualTo("192.0.2.1/32"))
        Assert.That(Fail2BanBackend.tryCanonicalIgnoreIp "2001:db8::1/128" |> Option.get, Is.EqualTo("2001:db8::1/128"))
        Assert.That(Fail2BanBackend.tryCanonicalIgnoreIp "::ffff:192.0.2.1" |> Option.get, Is.EqualTo("192.0.2.1"))
        Assert.That(Fail2BanBackend.tryCanonicalIgnoreIp "::ffff:192.0.2.1/128", Is.EqualTo(None))
        Assert.That(Fail2BanBackend.tryCanonicalIgnoreIp "::ffff:192.0.2.1/120", Is.EqualTo(None))
        Assert.That(Fail2BanBackend.tryCanonicalIgnoreIp "0.0.0.0/0", Is.EqualTo(None))
        Assert.That(Fail2BanBackend.tryCanonicalIgnoreIp "::/0", Is.EqualTo(None))
        Assert.That(Fail2BanBackend.tryCanonicalIgnoreIp "0.0.0.0/32", Is.EqualTo(None))
        Assert.That(Fail2BanBackend.tryCanonicalIgnoreIp "::/128", Is.EqualTo(None))
        Assert.That(Fail2BanBackend.tryCanonicalIgnoreIp "0.0.0.0", Is.EqualTo(None))
        Assert.That(Fail2BanBackend.tryCanonicalIgnoreIp "::", Is.EqualTo(None))

        let fractional =
            inputMap [ "connection", connection "192.0.2.10"; "findTimeSeconds", PropertyValue(10.5) ]
            |> check provider Fail2BanProvider.ResourceToken
        let duplicatePorts = check provider Fail2BanProvider.ResourceToken (fail2banInputs "192.0.2.10" [ 22; 22 ])
        let unknownPorts =
            check
                provider
                Fail2BanProvider.ResourceToken
                (inputMap [ "connection", connection "192.0.2.10"; "ports", array [ PropertyValue.Computed ] ])
        let secretRetry =
            check
                provider
                Fail2BanProvider.ResourceToken
                (inputMap [ "connection", connection "192.0.2.10"; "maxRetry", PropertyValue(5.0, IsSecret = true) ])
        let normalizedUnknownPorts = arrayContents unknownPorts.Inputs["ports"]
        Assert.That(findFailure "findTimeSeconds" fractional.Failures, Is.True)
        Assert.That(findFailure "ports[1]" duplicatePorts.Failures, Is.True)
        Assert.That(unknownPorts.Failures, Is.Empty)
        Assert.That(normalizedUnknownPorts[0].IsComputed, Is.True)
        Assert.That(secretRetry.Inputs["maxRetry"].IsSecret, Is.True)
        let invalidMappedCidr =
            check
                provider
                Fail2BanProvider.ResourceToken
                (inputMap [
                    "connection", connection "192.0.2.10"
                    "ignoreIps", array [ stringValue "::ffff:192.0.2.1/120" ]
                ])
        Assert.That(findFailure "ignoreIps[0]" invalidMappedCidr.Failures, Is.True)
        let invalidAnyNetwork =
            check
                provider
                Fail2BanProvider.ResourceToken
                (inputMap [ "connection", connection "192.0.2.10"; "ignoreIps", array [ stringValue "0.0.0.0/0" ] ])
        let invalidUnspecifiedHost =
            check
                provider
                Fail2BanProvider.ResourceToken
                (inputMap [ "connection", connection "192.0.2.10"; "ignoreIps", array [ stringValue "::/128" ] ])
        Assert.That(findFailure "ignoreIps[0]" invalidAnyNetwork.Failures, Is.True)
        Assert.That(findFailure "ignoreIps[0]" invalidUnspecifiedHost.Failures, Is.True)

    [<Test>]
    member _.``Fail2Ban Diff consumes observed SSHD ports and reports drift-free policy changes``() =
        let provider = Fail2BanProvider()
        let oldInputs = fail2banInputs "192.0.2.10" [ 22 ]
        let newInputs = fail2banInputs "192.0.2.10" [ 2222 ]
        let oldOutputs =
            inputMap [
                "owned", booleanValue true
                "active", booleanValue true
                "actualPorts", array [ numberValue 22 ]
                "actualMaxRetry", numberValue 5
                "actualFindTimeSeconds", numberValue 600
                "actualBanTimeSeconds", numberValue 3600
                "actualIgnoreIps", array [ stringValue "127.0.0.0/8"; stringValue "::1" ]
                "inSync", booleanValue true
            ]
        let response =
            provider.Diff(
                diffRequest Fail2BanProvider.ResourceToken "resource-id" oldInputs oldOutputs newInputs,
                CancellationToken.None
            ).GetAwaiter().GetResult()

        Assert.That(response.Changes.Value, Is.True)
        Assert.That(response.Diffs.Contains("ports"), Is.True)
        Assert.That(response.DetailedDiff.ContainsKey("ports[0]"), Is.True)

    [<Test>]
    member _.``Fail2Ban Diff trusts the helper synchronization result for lossy host-mask strings``() =
        let provider = Fail2BanProvider()
        let inputs =
            inputMap [
                "connection", connection "192.0.2.10"
                "ignoreIps", array [ stringValue "192.0.2.1/32" ]
                "ports", array [ numberValue 22 ]
            ]
        let oldOutputs =
            inputMap [
                "owned", booleanValue true
                "active", booleanValue true
                "actualPorts", array [ numberValue 22 ]
                "actualMaxRetry", numberValue 5
                "actualFindTimeSeconds", numberValue 600
                "actualBanTimeSeconds", numberValue 3600
                "actualIgnoreIps", array [ stringValue "192.0.2.1" ]
                "inSync", booleanValue true
            ]
        let response =
            provider.Diff(
                diffRequest Fail2BanProvider.ResourceToken "resource-id" inputs oldOutputs inputs,
                CancellationToken.None
            ).GetAwaiter().GetResult()

        Assert.That(response.Changes.Value, Is.False)

    [<Test>]
    member _.``Provider preview returns unknown observations without contacting a host``() =
        let provider = SshdProvider()
        let inputs = sshdInputs "host-that-must-not-be-contacted.invalid" [ "PubkeyAuthentication", stringValue "yes" ]
        let request =
            CreateRequest(
                Pulumi.Urn(sprintf "urn:pulumi:unit::unit::%s::preview" SshdProvider.ResourceToken),
                inputs,
                TimeSpan.FromSeconds(1.0),
                true
            )
        let response = provider.Create(request, CancellationToken.None).GetAwaiter().GetResult()

        Assert.That(response.Id, Is.Empty)
        Assert.That(response.Outputs["owned"].IsComputed, Is.True)

    [<Test>]
    member _.``Backend snapshots accept valid observed values outside desired input bounds``() =
        let sshdSnapshot =
            SshdBackend.parseSnapshot
                (Map.ofList [ "MaxAuthTries", "5"; "PermitRootLogin", "no" ])
                """{"owned":false,"actualSettings":{"MaxAuthTries":"0","PermitRootLogin":"without-password"},"ports":[22],"inSync":false,"pendingToken":""}"""
        let fail2banSnapshot =
            Fail2BanBackend.parseSnapshot
                """{"owned":true,"active":true,"actualPorts":[22],"actualMaxRetry":0,"actualFindTimeSeconds":-600,"actualBanTimeSeconds":-1,"actualIgnoreIps":["127.0.0.0/8","::1"],"inSync":false}"""
        let runtimeSnapshot =
            Fail2BanBackend.parseSnapshot
                """{"owned":false,"active":false,"actualPorts":[],"actualMaxRetry":0,"actualFindTimeSeconds":0,"actualBanTimeSeconds":0,"actualIgnoreIps":["0.0.0.0","::"],"inSync":false}"""

        Assert.That(SshdBackend.isValidSetting "MaxAuthTries" "0", Is.False)
        Assert.That(SshdBackend.isValidObservedSetting "MaxAuthTries" "0", Is.True)
        Assert.That(SshdBackend.isValidObservedSetting "PermitRootLogin" "without-password", Is.True)
        Assert.That(sshdSnapshot.ActualSettings["PermitRootLogin"], Is.EqualTo("without-password"))
        Assert.That(sshdSnapshot.ActualSettings["MaxAuthTries"], Is.EqualTo("0"))
        Assert.That(sshdSnapshot.Owned, Is.False)
        Assert.That(sshdSnapshot.InSync, Is.False)
        Assert.That(fail2banSnapshot.ActualBanTimeSeconds, Is.EqualTo(-1))
        Assert.That(fail2banSnapshot.ActualMaxRetry, Is.EqualTo(0))
        Assert.That(fail2banSnapshot.ActualFindTimeSeconds, Is.EqualTo(-600))
        Assert.That(String.concat "," runtimeSnapshot.ActualIgnoreIps, Is.EqualTo("0.0.0.0,::"))

        let malformedSshd = TestDelegate(fun () -> SshdBackend.parseSnapshot Map.empty """{"owned":false}""" |> ignore)
        Assert.Throws<InvalidOperationException>(malformedSshd) |> ignore
        let malformedFail2Ban =
            TestDelegate(fun () ->
                Fail2BanBackend.parseSnapshot
                    """{"owned":true,"active":true,"actualPorts":[22],"actualMaxRetry":5,"actualFindTimeSeconds":600,"actualBanTimeSeconds":-1,"actualIgnoreIps":["127.0.0.0/8","::1"],"inSync":false,"extra":true}"""
                |> ignore)
        Assert.Throws<InvalidOperationException>(malformedFail2Ban) |> ignore
