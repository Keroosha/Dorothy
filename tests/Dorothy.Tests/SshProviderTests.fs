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
        let builder =
            ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)

        for key, value in entries do
            builder.Add(key, value)

        PropertyValue(builder.ToImmutable())

    let inputMap (entries: seq<string * PropertyValue>) =
        let builder =
            ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)

        for key, value in entries do
            builder.Add(key, value)

        builder.ToImmutable()

    let array (values: seq<PropertyValue>) =
        PropertyValue(ImmutableArray.CreateRange(values))

    let stringValue (value: string) = PropertyValue(value)
    let numberValue (value: int) = PropertyValue(float value)
    let booleanValue (value: bool) = PropertyValue(value)

    let stringOf (value: PropertyValue) =
        let mutable result = Unchecked.defaultof<string>

        if value.TryGetString(&result) then
            result
        else
            failwith "Expected a string value."

    let booleanOf (value: PropertyValue) =
        let mutable result = false

        if value.TryGetBool(&result) then
            result
        else
            failwith "Expected a boolean value."

    let numberOf (value: PropertyValue) =
        let mutable result = 0.0

        if value.TryGetNumber(&result) then
            result
        else
            failwith "Expected a number value."

    let connection (address: string) =
        map [ "address", stringValue address; "user", stringValue "debian" ]

    let sshdInputs (address: string) (configuration: PropertyValue) =
        inputMap [ "connection", connection address; "configuration", configuration ]

    let fail2banInputs
        (address: string)
        (files: PropertyValue)
        (manageSshdPorts: PropertyValue option)
        (sshdPorts: PropertyValue option)
        =
        [
            yield "connection", connection address
            yield "files", files
            match manageSshdPorts with
            | Some value -> yield "manageSshdPorts", value
            | None -> ()
            match sshdPorts with
            | Some value -> yield "sshdPorts", value
            | None -> ()
        ]
        |> inputMap

    let checkRequest (token: string) (inputs: ImmutableDictionary<string, PropertyValue>) =
        let urn = Pulumi.Urn(sprintf "urn:pulumi:unit::unit::%s::provider-test" token)
        CheckRequest(urn, ImmutableDictionary<string, PropertyValue>.Empty, inputs, ImmutableArray<byte>.Empty)

    let check
        (provider: Pulumi.Experimental.Provider.Provider)
        (token: string)
        (inputs: ImmutableDictionary<string, PropertyValue>)
        =
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

        if value.TryGetMap(&result) then
            result
        else
            failwith "Expected a map value."

    let arrayContents (value: PropertyValue) =
        let mutable result = ImmutableArray<PropertyValue>.Empty

        if value.TryGetArray(&result) then
            result
        else
            failwith "Expected an array value."

    [<Test>]
    member _.``SSHD Check preserves complete native configuration text and input metadata``() =
        let provider = SshdProvider()

        let configuration =
            "Port 22\nPort 2222\nAcceptEnv LANG LC_*\nMatch User deploy\n    AllowTcpForwarding local\n"

        let secret = PropertyValue(configuration, IsSecret = true)

        let response =
            check provider SshdProvider.ResourceToken (sshdInputs "192.0.2.10" secret)

        let normalized = response.Inputs["configuration"]

        Assert.That(response.Failures, Is.Empty)
        Assert.That(stringOf normalized, Is.EqualTo(configuration))
        Assert.That(normalized.IsSecret, Is.True)

        let unknown =
            check provider SshdProvider.ResourceToken (sshdInputs "192.0.2.10" PropertyValue.Computed)

        Assert.That(unknown.Failures, Is.Empty)
        Assert.That(unknown.Inputs["configuration"].IsComputed, Is.True)

    [<Test>]
    member _.``SSHD Check rejects the retired settings-map input``() =
        let provider = SshdProvider()

        let inputs =
            inputMap
                [
                    "connection", connection "192.0.2.10"
                    "settings", map [ "PasswordAuthentication", stringValue "no" ]
                    "configuration", stringValue "PasswordAuthentication no\n"
                ]

        let response = check provider SshdProvider.ResourceToken inputs

        Assert.That(findFailure "settings" response.Failures, Is.True)

    [<Test>]
    member _.``SSHD Diff compares native text and replaces resources when the host changes``() =
        let provider = SshdProvider()
        let oldConfiguration = "PasswordAuthentication yes\n"
        let newConfiguration = "PasswordAuthentication no\n"
        let oldInputs = sshdInputs "192.0.2.10" (stringValue oldConfiguration)
        let newInputs = sshdInputs "192.0.2.11" (stringValue newConfiguration)

        let oldOutputs =
            inputMap
                [
                    "owned", booleanValue true
                    "actualConfiguration", stringValue "PasswordAuthentication yes\n"
                    "actualConnectionConfiguration", stringValue "passwordauthentication yes\n"
                    "ports", array [ numberValue 22 ]
                    "inSync", booleanValue true
                ]

        let response =
            provider
                .Diff(
                    diffRequest SshdProvider.ResourceToken "resource-id" oldInputs oldOutputs newInputs,
                    CancellationToken.None
                )
                .GetAwaiter()
                .GetResult()

        Assert.That(response.Changes.Value, Is.True)
        Assert.That(response.Diffs.Contains("configuration"), Is.True)
        Assert.That(response.DetailedDiff.ContainsKey("configuration"), Is.True)
        Assert.That(response.Replaces.Contains("connection.address"), Is.True)
        Assert.That(response.DeleteBeforeReplace, Is.True)

    [<Test>]
    member _.``Fail2Ban Check defaults generic fields and preserves native file text and metadata``() =
        let provider = Fail2BanProvider()

        let defaults =
            check provider Fail2BanProvider.ResourceToken (inputMap [ "connection", connection "192.0.2.10" ])

        let defaultFiles = mapContents defaults.Inputs["files"]
        let defaultPorts = arrayContents defaults.Inputs["sshdPorts"]
        Assert.That(defaults.Failures, Is.Empty)
        Assert.That(defaultFiles.Count, Is.Zero)
        Assert.That(booleanOf defaults.Inputs["manageSshdPorts"], Is.False)
        Assert.That(defaultPorts.Length, Is.Zero)

        let actionSource = "class Action:\n    def ban(self, ticket):\n        return\n"
        let customFile = "[sshd]\nbantime = -1\nfindtime = -30\n"
        let unknown = PropertyValue.Computed

        let inputs =
            fail2banInputs
                "192.0.2.10"
                (map
                    [
                        "custom.ini", stringValue customFile
                        "action.d/custom.py", PropertyValue(actionSource, IsSecret = true)
                        "filter.d/custom.local", unknown
                    ])
                (Some(PropertyValue(true)))
                (Some(array [ numberValue 2222 ]))

        let response = check provider Fail2BanProvider.ResourceToken inputs
        let normalizedFiles = mapContents response.Inputs["files"]

        Assert.That(response.Failures, Is.Empty)
        Assert.That(stringOf normalizedFiles["custom.ini"], Is.EqualTo(customFile))
        Assert.That(normalizedFiles["action.d/custom.py"].IsSecret, Is.True)
        Assert.That(normalizedFiles["filter.d/custom.local"].IsComputed, Is.True)
        Assert.That(booleanOf response.Inputs["manageSshdPorts"], Is.True)
        Assert.That(numberOf (arrayContents response.Inputs["sshdPorts"]).[0], Is.EqualTo(2222.0))

    [<Test>]
    member _.``Fail2Ban Check validates only safe file paths and structural port inputs``() =
        let provider = Fail2BanProvider()

        let unsafePath =
            check
                provider
                Fail2BanProvider.ResourceToken
                (fail2banInputs "192.0.2.10" (map [ "../outside.ini", stringValue "anything" ]) None None)

        let absolutePath =
            check
                provider
                Fail2BanProvider.ResourceToken
                (fail2banInputs "192.0.2.10" (map [ "/tmp/outside.ini", stringValue "anything" ]) None None)

        let invalidPorts =
            check
                provider
                Fail2BanProvider.ResourceToken
                (fail2banInputs "192.0.2.10" (map []) None (Some(array [ numberValue 0 ])))

        Assert.That(findFailure "files[\"../outside.ini\"]" unsafePath.Failures, Is.True)
        Assert.That(findFailure "files[\"/tmp/outside.ini\"]" absolutePath.Failures, Is.True)
        Assert.That(findFailure "sshdPorts[0]" invalidPorts.Failures, Is.True)

    [<Test>]
    member _.``Fail2Ban Diff compares generic files and linked SSH ports``() =
        let provider = Fail2BanProvider()

        let oldInputs =
            fail2banInputs
                "192.0.2.10"
                (map [ "jail.d/custom.local", stringValue "[sshd]\nport = 22\n" ])
                (Some(booleanValue true))
                (Some(array [ numberValue 22 ]))

        let newInputs =
            fail2banInputs
                "192.0.2.10"
                (map [ "jail.d/custom.local", stringValue "[sshd]\nport = 2222\n" ])
                (Some(booleanValue true))
                (Some(array [ numberValue 2222 ]))

        let oldOutputs =
            inputMap
                [
                    "owned", booleanValue true
                    "actualFiles", map [ "jail.d/custom.local", stringValue "[sshd]\nport = 22\n" ]
                    "active", booleanValue true
                    "activeJails", array [ stringValue "sshd" ]
                    "socket", stringValue "/run/fail2ban/fail2ban.sock"
                    "inSync", booleanValue true
                ]

        let response =
            provider
                .Diff(
                    diffRequest Fail2BanProvider.ResourceToken "resource-id" oldInputs oldOutputs newInputs,
                    CancellationToken.None
                )
                .GetAwaiter()
                .GetResult()

        Assert.That(response.Changes.Value, Is.True)
        Assert.That(response.Diffs.Contains("files"), Is.True)
        Assert.That(response.DetailedDiff.ContainsKey("files[\"jail.d/custom.local\"]"), Is.True)
        Assert.That(response.Diffs.Contains("sshdPorts"), Is.True)
        Assert.That(response.DetailedDiff.ContainsKey("sshdPorts[0]"), Is.True)

    [<Test>]
    member _.``Provider preview returns unknown observations without contacting a host``() =
        let provider = SshdProvider()

        let inputs =
            sshdInputs "host-that-must-not-be-contacted.invalid" (stringValue "PubkeyAuthentication yes\n")

        let request =
            CreateRequest(
                Pulumi.Urn(sprintf "urn:pulumi:unit::unit::%s::preview" SshdProvider.ResourceToken),
                inputs,
                TimeSpan.FromSeconds(1.0),
                true
            )

        let response =
            provider.Create(request, CancellationToken.None).GetAwaiter().GetResult()

        Assert.That(response.Id, Is.Empty)
        Assert.That(response.Outputs["owned"].IsComputed, Is.True)
        Assert.That(response.Outputs["actualConfiguration"].IsComputed, Is.True)

    [<Test>]
    member _.``Backend snapshots preserve full observed configuration without value allowlists``() =
        let sshdConfiguration =
            "FutureOption native-value\nPermitRootLogin without-password\n"

        let connectionConfiguration =
            "futureoption native-value\npermitrootlogin without-password\n"

        let sshdSnapshot =
            SshdBackend.parseSnapshot
                """{"owned":false,"actualConfiguration":"FutureOption native-value\nPermitRootLogin without-password\n","actualConnectionConfiguration":"futureoption native-value\npermitrootlogin without-password\n","ports":[22],"inSync":false,"pendingToken":""}"""

        let fail2banSnapshot =
            Fail2BanBackend.parseSnapshot
                """{"owned":true,"actualFiles":{"custom.ini":"[sshd]\nbantime = -1\n","action.d/custom.py":"class Action:\n    pass\n"},"active":true,"activeJails":["sshd","custom"],"socket":"/run/fail2ban/custom.sock","inSync":false}"""

        Assert.That(sshdSnapshot.ActualConfiguration, Is.EqualTo(sshdConfiguration))
        Assert.That(sshdSnapshot.ActualConnectionConfiguration, Is.EqualTo(connectionConfiguration))
        Assert.That(sshdSnapshot.Ports, Is.EquivalentTo([ 22 ]))
        Assert.That(fail2banSnapshot.ActualFiles["custom.ini"], Is.EqualTo("[sshd]\nbantime = -1\n"))
        Assert.That(fail2banSnapshot.ActualFiles["action.d/custom.py"], Is.EqualTo("class Action:\n    pass\n"))
        Assert.That(fail2banSnapshot.ActiveJails, Is.EquivalentTo([ "sshd"; "custom" ]))
        Assert.That(fail2banSnapshot.Socket, Is.EqualTo("/run/fail2ban/custom.sock"))

        let malformedSshd =
            TestDelegate(fun () -> SshdBackend.parseSnapshot """{"owned":false}""" |> ignore)

        Assert.Throws<InvalidOperationException>(malformedSshd) |> ignore

        let malformedFail2Ban =
            TestDelegate(fun () ->
                Fail2BanBackend.parseSnapshot
                    """{"owned":true,"actualFiles":{},"active":true,"activeJails":[],"socket":"/run/fail2ban.sock","inSync":false,"extra":true}"""
                |> ignore)

        Assert.Throws<InvalidOperationException>(malformedFail2Ban) |> ignore
