namespace Dorothy.Tests

open System
open System.Collections.Immutable
open System.Threading.Tasks
open Dorothy.DSL
open Dorothy.DSL.Firewalld
open NUnit.Framework
open Pulumi
open Pulumi.Testing
open Pulumi.Utilities

module private FirewalldDeploymentFixture =
    let mutable host: HostSpec option = None
    let captured = ResizeArray<ResourceTransformationArgs>()
    let options () =
        let options = StackOptions()
        options.ResourceTransformations.Add(ResourceTransformation(fun args ->
            captured.Add args
            Nullable<ResourceTransformationResult>()))
        options

    type Mocks() =
        interface IMocks with
            member _.NewResourceAsync(args) = Task.FromResult(args.Name + "-id", box ImmutableDictionary<string, obj>.Empty)
            member _.CallAsync(_) = Task.FromResult(box ImmutableDictionary<string, obj>.Empty)
            member _.RegisterResourceOutputs(_) = Task.CompletedTask
            member _.RegisterTransform(_) = Task.CompletedTask
            member _.RegisterInvokeTransform(_) = Task.CompletedTask

type FirewalldDependencyStack() =
    inherit Stack(FirewalldDeploymentFixture.options())
    do Host.deploy FirewalldDeploymentFixture.host.Value |> ignore

[<TestFixture; NonParallelizable>]
type FirewalldDeploymentTests() =
    [<TestCase(false); TestCase(true)>]
    member _.``Docker startup and docker policy wait for firewalld including explicit package version``(explicitVersion: bool) =
        let host =
            sshHost "ordered" {
                Address "192.0.2.2"
                User "root"
                debian {
                    if explicitVersion then apt { packageVersion "docker.io" "26.1.5+dfsg1-9" }
                    docker { }
                    firewalld {
                        zone "external" { services [ "ssh" ]; interfaces [ "eth0" ] }
                        policy "docker-block" {
                            ingressZones [ "external" ]; egressZones [ "docker" ]
                            target FirewalldTarget.Drop; priority -10
                        }
                    }
                }
            }
        FirewalldDeploymentFixture.captured.Clear()
        FirewalldDeploymentFixture.host <- Some host
        Deployment.TestAsync<FirewalldDependencyStack>(FirewalldDeploymentFixture.Mocks(), TestOptions()).GetAwaiter().GetResult() |> ignore
        let name (resource: Resource) = OutputUtilities.GetValueAsync(resource.Urn).Result.Split("::") |> Array.last
        let captured = FirewalldDeploymentFixture.captured |> Seq.filter (fun a -> not (a.Resource :? Stack)) |> Seq.toArray
        let byName = captured |> Array.map (fun a -> name a.Resource, a) |> Map.ofArray
        let dependencies key =
            let output: Output<ImmutableArray<Resource>> = InputList<Resource>.op_Implicit byName[key].Options.DependsOn
            OutputUtilities.GetValueAsync(output).Result |> Seq.map name |> Set.ofSeq
        Assert.That(dependencies "ordered-docker-package", Does.Contain "ordered-firewalld-package")
        // Resource names may match across different tokens; locate the engine by its arguments.
        let engine = captured |> Array.find (fun a -> a.Args :? DockerEngineArgs)
        let engineDependencies: Output<ImmutableArray<Resource>> = InputList<Resource>.op_Implicit engine.Options.DependsOn
        Assert.That(OutputUtilities.GetValueAsync(engineDependencies).Result |> Seq.map name, Does.Contain "ordered-docker-package")
        Assert.That(dependencies "ordered-firewalld-policy-docker-block", Does.Contain "ordered")
        let main = captured |> Array.find (fun a -> a.Args :? AptPackageSetArgs && name a.Resource = "ordered")
        let packages = (main.Args :?> AptPackageSetArgs).Packages
        let packageOutput: Output<ImmutableDictionary<string, AptPackageArgs>> = InputMap<AptPackageArgs>.op_Implicit packages
        Assert.That(OutputUtilities.GetValueAsync(packageOutput).Result.ContainsKey "docker.io", Is.False)
