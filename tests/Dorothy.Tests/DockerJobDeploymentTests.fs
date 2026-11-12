namespace Dorothy.Tests

open System
open System.Collections.Concurrent
open System.Collections.Immutable
open System.Security.Cryptography
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open System.Threading.Tasks
open Dorothy.DSL
open NUnit.Framework
open Pulumi
open Pulumi.Testing

module private DockerJobDeploymentValues =
    let id name = SHA256.HashData(Encoding.UTF8.GetBytes(name: string)) |> Convert.ToHexStringLower
    let name (resource: Resource) =
        let urn = Utilities.OutputUtilities.GetValueAsync(resource.Urn).GetAwaiter().GetResult()
        urn.Substring(urn.LastIndexOf("::", StringComparison.Ordinal) + 2)

    type Mocks() =
        let resources = ConcurrentDictionary<string, MockResourceArgs>()
        member _.Resources = resources
        interface IMocks with
            member _.NewResourceAsync(args) =
                resources[args.Name] <- args
                let outputs =
                    match args.Type with
                    | "docker:index/remoteImage:RemoteImage" -> args.Inputs.SetItem("imageId", box ("sha256:" + String('b', 64)))
                    | "keroosha:debian:DockerJob" -> args.Inputs.SetItem("completed", box true)
                    | _ -> args.Inputs
                Task.FromResult(id args.Name, box outputs)
            member _.CallAsync(_) = Task.FromResult(box ImmutableDictionary<string, obj>.Empty)
            member _.RegisterResourceOutputs(_) = Task.CompletedTask
            member _.RegisterTransform(_) = Task.CompletedTask
            member _.RegisterInvokeTransform(_) = Task.CompletedTask

    let stackOptions (captured: ConcurrentDictionary<Resource, ResourceTransformationArgs>) =
        let options = StackOptions()
        options.ResourceTransformations.Add(ResourceTransformation(fun args ->
            captured[args.Resource] <- args
            Nullable<ResourceTransformationResult>()))
        options

    let host name timeout =
        let database = container "mariadb" {
            image "mariadb:12"
            restart unlessStopped
            healthcheck { healthExec [ "healthcheck.sh"; "--connect" ] }
            waitHealthy (TimeSpan.FromMinutes 1.)
        }
        let migration = container "migrator" {
            image "web:1"
            command [ "--migrator" ]
            runOnce timeout
            dependsOn database
            env "PUBLIC_FLAG" "1"
            env "PUBLIC_OUTPUT" (Output.Create("true"))
            env "SECRET_PIN" (Output.CreateSecret("s7"))
        }
        let web = container "web" { image "web:1"; restart unlessStopped; dependsOn migration }
        let telegram = container "telegram" { image "telegram:1"; restart unlessStopped; dependsOn web }
        sshHost name {
            Address "192.0.2.1"
            User "root"
            debian { docker { telegram; web; migration; database } }
        }

/// Instance-local capture: no static test state survives another Deployment.TestAsync call.
type DockerJobCompositionStack(captured: ConcurrentDictionary<Resource, ResourceTransformationArgs>) =
    inherit Stack(DockerJobDeploymentValues.stackOptions captured)
    do
        Host.deploy (DockerJobDeploymentValues.host "short" (TimeSpan.FromMinutes 5.)) |> ignore
        Host.deploy (DockerJobDeploymentValues.host "long" (TimeSpan.FromMinutes 10.)) |> ignore
    new() = DockerJobCompositionStack(ConcurrentDictionary<Resource, ResourceTransformationArgs>())
    member _.Captured = captured

[<TestFixture>]
type DockerJobDeploymentTests() =
    [<Test>]
    [<NonParallelizable>]
    member _.``Host deployment gates services on successful jobs and keeps timeout outside execution identity``() =
        let mocks = DockerJobDeploymentValues.Mocks()
        let resources = Deployment.TestAsync<DockerJobCompositionStack>(mocks, TestOptions()).GetAwaiter().GetResult()
        let stack = resources |> Seq.pick (function :? DockerJobCompositionStack as stack -> Some stack | _ -> None)
        let captured = stack.Captured |> Seq.map (fun entry -> DockerJobDeploymentValues.name entry.Key, entry.Value) |> Map.ofSeq
        let jobOptions = captured["short-container-migrator"].Options :?> CustomResourceOptions
        let prepared = mocks.Resources["short-container-migrator"]
        Assert.That(prepared.Type, Is.EqualTo("docker:index/container:Container"))
        Assert.That(unbox<bool> prepared.Inputs["start"], Is.False)
        Assert.That(unbox<bool> prepared.Inputs["mustRun"], Is.False)
        Assert.That(unbox<string> prepared.Inputs["restart"], Is.EqualTo("no"))
        Assert.That(jobOptions.ReplaceOnChanges, Is.EquivalentTo([ "*" ]))
        Assert.That(jobOptions.DeleteBeforeReplace.Value, Is.True)
        Assert.That(jobOptions.AdditionalSecretOutputs, Does.Contain("envs"))
        let preparedArgs = captured["short-container-migrator"].Args :?> Pulumi.Docker.ContainerArgs
        Assert.That(Output.IsSecretAsync(preparedArgs.Envs.ToOutput()).GetAwaiter().GetResult(), Is.True)

        let barrier = mocks.Resources["short-container-migrator-completion"]
        Assert.That(barrier.Type, Is.EqualTo("keroosha:debian:DockerJob"))
        Assert.That(unbox<string> barrier.Inputs["containerId"], Is.EqualTo(DockerJobDeploymentValues.id prepared.Name))
        let secretKeys = barrier.Inputs["secretEnvironmentKeys"] :?> System.Collections.IEnumerable |> Seq.cast<obj> |> Seq.map unbox<string>
        Assert.That(secretKeys, Is.EquivalentTo([ "SECRET_PIN" ]))
        Assert.That(unbox<bool> mocks.Resources["short-container-mariadb"].Inputs["wait"], Is.True)

        let dependencies name =
            Utilities.OutputUtilities.GetValueAsync(captured[name].Options.DependsOn.ToOutput()).GetAwaiter().GetResult()
            |> Seq.map DockerJobDeploymentValues.name
            |> Set.ofSeq
        Assert.That(dependencies "short-container-web", Is.EquivalentTo([ "short"; "short-container-migrator-completion" ]))
        Assert.That(dependencies "short-container-migrator-completion", Is.EquivalentTo([ "short-container-migrator" ]))
        Assert.That(dependencies "short-container-migrator", Is.EquivalentTo([ "short"; "short-container-mariadb" ]))
        Assert.That(dependencies "short-container-telegram", Is.EquivalentTo([ "short"; "short-container-web" ]))

        // Identical execution specs with a different timeout must produce identical container inputs.
        let firstInputs = JsonSerializer.SerializeToNode(prepared.Inputs.Remove("name"))
        let secondInputs = JsonSerializer.SerializeToNode(mocks.Resources["long-container-migrator"].Inputs.Remove("name"))
        Assert.That(JsonNode.DeepEquals(firstInputs, secondInputs), Is.True)
        Assert.That(Convert.ToInt32(barrier.Inputs["timeoutSeconds"]), Is.EqualTo(300))
        Assert.That(Convert.ToInt32(mocks.Resources["long-container-migrator-completion"].Inputs["timeoutSeconds"]), Is.EqualTo(600))
