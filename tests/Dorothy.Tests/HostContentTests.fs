namespace Dorothy.Tests

open System
open System.Collections.Immutable
open System.Text.Json.Nodes
open System.Threading
open System.Threading.Tasks
open Dorothy.DSL
open Dorothy.DSL.HostContent
open Dorothy.DSL.Provider
open NUnit.Framework
open Pulumi
open Pulumi.Testing
open Pulumi.Utilities
open Pulumi.Experimental
open Pulumi.Experimental.Provider

module private HostContentTestValues =
    let map entries = ImmutableDictionary.CreateRange<string, PropertyValue>(entries |> Seq.map (fun (key, value) -> System.Collections.Generic.KeyValuePair(key, value)))
    let resolve output = OutputUtilities.GetValueAsync(output).GetAwaiter().GetResult()
    let inputs item =
        let spec, payload = HostContentInputs.resolve item
        map [ "connection", PropertyValue(map [ "address", PropertyValue "192.0.2.1"; "user", PropertyValue "operator" ])
              "specification", PropertyValue(resolve spec)
              "payload", PropertyValue(resolve payload) ]
    let urn token = Urn("urn:pulumi:test::test::" + token + "::example")
    let check token inputs =
        DorothyProvider().Check(CheckRequest(urn token, ImmutableDictionary.Empty, inputs, ImmutableArray<byte>.Empty), CancellationToken.None).GetAwaiter().GetResult()
    let diff oldInputs oldOutputs newInputs =
        DorothyProvider().Diff(DiffRequest(urn ContentServicesProvider.ContentToken, "existing", oldOutputs, newInputs, ImmutableArray<string>.Empty, oldInputs), CancellationToken.None).GetAwaiter().GetResult()
    let stringValue (value: PropertyValue) =
        let mutable text = ""
        if not (value.TryGetString(&text)) then failwith "Expected string."
        text

[<Sealed>]
type private ContentMocks() =
    let resources = ResizeArray<MockResourceArgs>()
    member _.Resources = resources.ToArray()
    interface IMocks with
        member _.NewResourceAsync(args: MockResourceArgs) =
            lock resources (fun () -> resources.Add args)
            let outputs = args.Inputs.ToBuilder()
            if args.Type = ContentServicesProvider.ContentToken then outputs["fingerprint"] <- box (args.Name + "-digest")
            Task.FromResult((args.Name + "-id", box (outputs.ToImmutable())))
        member _.CallAsync(_: MockCallArgs) = Task.FromResult(box ImmutableDictionary<string, obj>.Empty)
        member _.RegisterResourceOutputs(_: MockRegisterResourceOutputsRequest) = Task.CompletedTask
        member _.RegisterTransform(_: ResourceTransform) = Task.CompletedTask
        member _.RegisterInvokeTransform(_: InvokeTransform) = Task.CompletedTask

[<TestFixture>]
type HostContentTests() =
    [<Test>]
    member _.``Grouping rejects duplicate paths duplicate names and multiple environment blocks``() =
        let first = text "first" { value "one"; installTo "/etc/example" }
        let second = text "second" { value "two"; installTo "/etc/example" }
        Assert.Throws<ArgumentException>(fun () -> content { first; second } |> ignore) |> ignore
        Assert.Throws<ArgumentException>(fun () -> content { first; first } |> ignore) |> ignore
        Assert.Throws<ArgumentException>(fun () -> debian { content { first }; content { second } } |> ignore) |> ignore
        let foreign = text "foreign" { value "x"; installTo "/other" }
        Assert.Throws<ArgumentException>(fun () -> debian { content { first }; service "test" { exec "/bin/true"; uses [ foreign ] } } |> ignore) |> ignore

    [<Test>]
    member _.``URL content requires digest and safe extraction while package units reject owned directives``() =
        Assert.Throws<ArgumentException>(fun () -> download "missing" { url "https://example.test/a"; installTo "/a" } |> ignore) |> ignore
        Assert.Throws<ArgumentException>(fun () -> archive "traversal" { url "https://example.test/a.zip"; sha256 (String.replicate 64 "a"); extract "../file" "/a" } |> ignore) |> ignore
        Assert.Throws<ArgumentException>(fun () -> systemdUnit "vendor" { exec "/bin/true" } |> ignore) |> ignore
        Assert.Throws<ArgumentException>(fun () -> service "empty" { uses [] } |> ignore) |> ignore

    [<Test>]
    member _.``Typed service renders native sections and environment escaping``() =
        let unit =
            service "rapi" {
                exec "/usr/local/bin/rapi"
                runAs "lainvpn"
                runAsGroup "lainvpn"
                supplementaryGroups [ "video"; "render" ]
                env "MESSAGE" "quote \" and 50%"
                workingDirectory "/home/lainvpn"
                restart ServiceRestart.OnFailure
                restartSec 2.5
                after [ "network-online.target" ]
                requires [ "docker.service" ]
                wants [ "network-online.target" ]
                limitNoFile 1048576
                raw "Type=exec"
            }
        Assert.That(unit.Name, Is.EqualTo "rapi.service")
        Assert.That(unit.Configuration, Does.Contain "[Unit]\nAfter=network-online.target\nRequires=docker.service\nWants=network-online.target")
        Assert.That(unit.Configuration, Does.Contain "Environment=\"MESSAGE=quote \\\" and 50%%\"")
        Assert.That(unit.Configuration, Does.Contain "Restart=on-failure\nRestartSec=2.5")
        Assert.That(unit.Configuration, Does.Contain "WantedBy=multi-user.target")

    [<Test>]
    member _.``Literal headers are secret inputs and never resource outputs``() =
        let item = download "agent" { url "https://example.test/agent"; sha256 (String.replicate 64 "a"); header "Authorization" "Bearer sensitive"; installTo "/bin/agent" }
        let specification, payload = HostContentInputs.resolve item
        Assert.That(Output.IsSecretAsync(payload).GetAwaiter().GetResult(), Is.True)
        Assert.That(HostContentTestValues.resolve specification, Does.Not.Contain "sensitive")
        let inputs = HostContentTestValues.inputs item
        let checkedInputs = HostContentTestValues.check ContentServicesProvider.ContentToken inputs
        Assert.That(checkedInputs.Failures, Is.Empty)
        Assert.That(checkedInputs.Inputs["payload"].IsSecret, Is.True)
        let preview = DorothyProvider().Create(CreateRequest(HostContentTestValues.urn ContentServicesProvider.ContentToken, inputs, TimeSpan.FromSeconds 1., true), CancellationToken.None).GetAwaiter().GetResult()
        Assert.That(preview.Outputs.ContainsKey "payload", Is.False)
        Assert.That(HostContentTestValues.stringValue preview.Outputs["specification"], Does.Not.Contain "sensitive")
        let helperPayload = ContentBackend.payload "apply" (HostContentTestValues.resolve specification) (HostContentTestValues.resolve payload) "{}"
        Assert.That(JsonNode.Parse(helperPayload).["headers"].["Authorization"].GetValue<string>(), Is.EqualTo "Bearer sensitive")

    [<Test>]
    member _.``URL token and header-name rotation does not change content identity``() =
        let make uri headerName token = download "agent" { url uri; sha256 (String.replicate 64 "b"); header headerName token; installTo "/bin/agent" }
        let original = HostContentTestValues.inputs (make "https://example.test/one" "Authorization" "first")
        let rotated = HostContentTestValues.inputs (make "https://mirror.example.test/two" "X-Token" "second")
        let snapshot = original.SetItem("inSync", PropertyValue true)
        let diff = HostContentTestValues.diff original snapshot rotated
        Assert.That(diff.Changes.Value, Is.False)

    [<Test>]
    member _.``CreateOnly content edits are updates without SSH or restart fingerprint``() =
        let make seed = text "seed" { value seed; installTo "/etc/wg.conf" { mode 0o600 }; ownership ContentOwnership.CreateOnly }
        let old = HostContentTestValues.inputs (make "old")
        let fresh = HostContentTestValues.inputs (make "new")
        let outputs = old.Remove("payload").SetItem("exists", PropertyValue true).SetItem("inSync", PropertyValue true).SetItem("hashes", PropertyValue "{}")
        let diff = HostContentTestValues.diff old outputs fresh
        Assert.That(diff.Changes.Value, Is.True)
        Assert.That(diff.Replaces, Is.Empty)
        let update = UpdateRequest(HostContentTestValues.urn ContentServicesProvider.ContentToken, "existing", outputs, fresh, TimeSpan.FromSeconds 1., ImmutableArray<string>.Empty, false, old)
        let result = DorothyProvider().Update(update, CancellationToken.None).GetAwaiter().GetResult()
        Assert.That(HostContentTestValues.stringValue result.Outputs["fingerprint"], Is.Empty)
        Assert.That(HostContentTestValues.stringValue result.Outputs["specification"], Is.EqualTo(HostContentTestValues.stringValue fresh["specification"]))
        Assert.That(result.Outputs.ContainsKey "payload", Is.False)

    [<Test>]
    member _.``Provider Check rejects conflicting destinations independently of DSL``() =
        let item = archive "a" { url "https://example.test/a.zip"; sha256 (String.replicate 64 "a"); extract "a" "/a"; extract "b" "/b" }
        let inputs = HostContentTestValues.inputs item
        let spec = JsonNode.Parse(HostContentTestValues.stringValue inputs["specification"])
        spec["targets"].[1].["path"] <- JsonValue.Create "/a"
        let checkedInputs = HostContentTestValues.check ContentServicesProvider.ContentToken (inputs.SetItem("specification", PropertyValue(spec.ToJsonString())))
        Assert.That(checkedInputs.Failures, Is.Not.Empty)

    [<Test>]
    [<NonParallelizable>]
    member _.``Host and Docker DSL coexist and register independent content with managed-only restart triggers``() =
        let managed = text "managed" { value "binary"; installTo "/bin/managed" }
        let seed = text "seed" { value "seed"; installTo "/etc/seed"; ownership ContentOwnership.CreateOnly }
        let dockerFile = containerFile "/etc/config" { DockerBuilders.content (DockerContent.text "docker"); permissions "0600" }
        Assert.That(dockerFile.Path, Is.EqualTo "/etc/config")
        let host = sshHost "content-host" { Address "192.0.2.1"; User "operator"; debian { content { managed; seed }; service "app" { exec "/bin/managed"; uses [ managed; seed ] }; systemdUnit "wg-quick@wg0" { uses [ seed ]; restartOnChange false } } }
        let mocks = ContentMocks()
        Deployment.TestAsync(mocks, TestOptions(), Action(fun () -> Host.deploy host |> ignore)).GetAwaiter().GetResult() |> ignore
        let resources = mocks.Resources
        let contents = resources |> Array.filter (fun resource -> resource.Type = ContentServicesProvider.ContentToken)
        Assert.That(contents, Has.Length.EqualTo 2)
        let services = resources |> Array.filter (fun resource -> resource.Type = ContentServicesProvider.ServiceToken)
        let app = services |> Array.find (fun resource -> resource.Name.EndsWith "app.service")
        let wg = services |> Array.find (fun resource -> resource.Name.Contains "wg-quick")
        Assert.That(unbox<string> app.Inputs["triggers"], Does.Contain "managed-digest")
        Assert.That(unbox<string> app.Inputs["triggers"], Does.Not.Contain "seed-digest")
        Assert.That(unbox<string> wg.Inputs["triggers"], Is.EqualTo "[]")
