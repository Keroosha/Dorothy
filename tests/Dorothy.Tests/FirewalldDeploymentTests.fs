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

module private FirewalldMixedDslConsumer =
    open Dorothy.DSL.HostContent
    open Dorothy.DSL.Firewalld

    let hostService = service "mixed-unit" { exec "/bin/true" }
    let firewalldService = Defined.service "mixed-firewall-service" { servicePorts [ tcpPort 8443 ] }
    let userDescription = description "Legacy user description"
    let alternate = ufw { reject { toPort 9443; proto Tcp } }

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
    member _.``Docker ordering preserves explicit package ownership when adding firewalld``(explicitVersion: bool) =
        let host =
            sshHost "ordered" {
                Address "192.0.2.2"
                User "root"
                debian {
                    if explicitVersion then apt {
                        packageVersion "docker.io" "26.1.5+dfsg1-9"
                        packageVersion "firewalld" "2.3.1-1+deb13u1"
                    }
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
        Assert.That(byName["ordered-firewalld-package"].Options.RetainOnDelete, Is.EqualTo(Nullable(not explicitVersion)))
        let dependencies key =
            let output: Output<ImmutableArray<Resource>> = InputList<Resource>.op_Implicit byName[key].Options.DependsOn
            OutputUtilities.GetValueAsync(output).Result |> Seq.map name |> Set.ofSeq
        if explicitVersion then Assert.That(byName.ContainsKey "ordered-docker-package", Is.False)
        else Assert.That(dependencies "ordered-docker-package", Does.Contain "ordered-firewalld-package")
        // Resource names may match across different tokens; locate the engine by its arguments.
        let engine = captured |> Array.find (fun a -> a.Args :? DockerEngineArgs)
        let engineDependencies: Output<ImmutableArray<Resource>> = InputList<Resource>.op_Implicit engine.Options.DependsOn
        let engineResources = OutputUtilities.GetValueAsync(engineDependencies).Result
        Assert.That(engineResources |> Seq.map name, Does.Contain(if explicitVersion then "ordered" else "ordered-docker-package"))
        Assert.That(engineResources |> Seq.map name, Does.Contain "ordered-firewalld-package")
        let policyDependencies: Output<ImmutableArray<Resource>> =
            InputList<Resource>.op_Implicit byName["ordered-firewalld-policy-docker-block"].Options.DependsOn
        Assert.That(OutputUtilities.GetValueAsync(policyDependencies).Result, Does.Contain engine.Resource)
        let main = captured |> Array.find (fun a -> a.Args :? AptPackageSetArgs && name a.Resource = "ordered")
        let packages = (main.Args :?> AptPackageSetArgs).Packages
        let packageOutput: Output<ImmutableDictionary<string, AptPackageArgs>> = InputMap<AptPackageArgs>.op_Implicit packages
        let resolvedPackages = OutputUtilities.GetValueAsync(packageOutput).Result
        Assert.That(resolvedPackages.ContainsKey "docker.io", Is.EqualTo explicitVersion)
        if explicitVersion then
            let mainDependencies: Output<ImmutableArray<Resource>> = InputList<Resource>.op_Implicit main.Options.DependsOn
            Assert.That(OutputUtilities.GetValueAsync(mainDependencies).Result |> Seq.map name, Does.Contain "ordered-firewalld-package")
            let versionOutput: Output<string> = Input<string>.op_Implicit resolvedPackages["docker.io"].Version
            let version = OutputUtilities.GetValueAsync(versionOutput).Result
            Assert.That(version, Is.EqualTo "26.1.5+dfsg1-9")
            // The existing main APT owner previously owned this exact package. Feed the new
            // deployment declaration to the real planner: adopting firewalld must not remove it.
            let installed: Dorothy.HostHelper.PackageRecord =
                { BinaryName = "docker.io"; Name = "docker.io"; Architecture = "amd64"
                  Status = "ii "; Version = version; Essential = false; Protected = false }
            let state: Dorothy.HostHelper.PackageState =
                { NativeArchitecture = "amd64"; Records = Map.ofList [ "docker.io", installed ]
                  ByName = Map.ofList [ "docker.io", [ installed ] ] }
            let desired =
                resolvedPackages |> Seq.map (fun p -> p.Key, Some version) |> Map.ofSeq
            let plan = Dorothy.HostHelper.Apt.planTransaction [ "docker.io" ] desired state
            Assert.That(plan.Removals, Is.Empty)
            Assert.That(plan.Installs, Is.Empty)

    [<Test>]
    member _.``Compiled Firewalld catalogue resolves declared references and keeps typed consumer syntax``() =
        let specification =
            firewalld {
                Defined.service "application" { includes [ "transport" ] }
                zone "external" {
                    interfaces [ "enp+" ]
                    services [ "application" ]
                    transportPorts [ tcpPortRange 8440 8443; udpPort 53 ]
                    sourcePorts [ tcpPort 1024 ]
                    Zone.ingressPriority -20
                    Zone.egressPriority 10
                    forwardPort (tcpPort 8444) (Some "192.0.2.50") (Some (tcpPort 444))
                    icmpBlocks [ "echo-request" ]
                    icmpBlockInversion
                    sources [ sourceIPSet "trusted"; sourceAddress "203.0.113.0/24"; sourceMac "02:00:00:00:00:01" ]
                    richRules
                        [ richRule {
                              family FirewalldFamily.IPv4
                              sourceAddress "198.51.100.0/24"
                              richService "application"
                              RichRule.accept
                              RichRule.limitBurst 10 FirewalldLimitUnit.Minute 3
                          }
                          richRule {
                              family FirewalldFamily.IPv4
                              sourceMac "02:00:00:00:00:02"
                              richService "application"
                              RichRule.drop
                          }
                          richRule {
                              family FirewalldFamily.IPv4
                              sourceAddress "192.0.2.0/24"
                              forwardPort (tcpPort 8443) (Some "192.0.2.50") (Some (tcpPort 443))
                          }
                          richRule {
                              family FirewalldFamily.IPv4
                              RichRule.tcpMssClamp
                          } ]
                }
                ipset "trusted" {
                    ipsetType "hash:ip"
                    ipsetOptions [ "family", "inet" ]
                    entries [ "192.0.2.0/24" ]
                }
                Defined.service "transport" {
                    servicePorts [ tcpPortRange 8440 8443; udpPort 53 ]
                    sourcePorts [ tcpPort 1024 ]
                    includes [ "vendor-base" ]
                    helpers [ "ftp" ]
                    modules [ "nf_conntrack_ftp" ]
                }
                helper "ftp" {
                    helperModule "nf_conntrack_ftp"
                    helperFamily FirewalldFamily.IPv4
                    helperPorts [ tcpPort 21 ]
                }
                icmpType "echo-request" { icmpDestinations [ FirewalldFamily.IPv4 ] }
                setting "DefaultZone" "public"
                policy "host-web" {
                    ingressZones [ "external" ]
                    egressZones [ "HOST" ]
                    services [ "application" ]
                    sourcePorts [ udpPort 5353 ]
                    target FirewalldTarget.Accept
                    priority -10
                }
                policy "inactive-stage" {
                    ingressZones []
                    egressZones [ "external" ]
                    priority -2
                }
            }
        let ordered = specification.Objects |> List.map (fun item -> item.Kind, item.Name)
        let index identity = ordered |> List.findIndex ((=) identity)
        Assert.That(index ("helper", "ftp"), Is.LessThan(index ("service", "transport")))
        Assert.That(index ("service", "transport"), Is.LessThan(index ("service", "application")))
        Assert.That(index ("service", "application"), Is.LessThan(index ("zone", "external")))
        Assert.That(index ("ipset", "trusted"), Is.LessThan(index ("zone", "external")))
        Assert.That(ordered, Does.Contain(("settings", "DefaultZone")))

        let application =
            specification.Objects |> List.find (fun item -> item.Kind = "service" && item.Name = "application")
        let applicationConfiguration = FirewalldModel.parse application.Configuration
        Assert.That(applicationConfiguration.Elements |> List.exists (fun element -> element.Name = "include"), Is.True)

        let external = specification.Objects |> List.find (fun item -> item.Kind = "zone" && item.Name = "external")
        let externalConfiguration = FirewalldModel.parse external.Configuration
        Assert.That(externalConfiguration.Ports, Does.Contain("8440-8443/tcp"))
        Assert.That(externalConfiguration.Attributes["ingress-priority"], Is.EqualTo "-20")
        Assert.That(externalConfiguration.Attributes["egress-priority"], Is.EqualTo "10")
        Assert.That(externalConfiguration.Elements |> List.exists (fun element -> element.Name = "source-port"), Is.True)
        let transport = specification.Objects |> List.find (fun item -> item.Kind = "service" && item.Name = "transport")
        Assert.That(FirewalldModel.references transport.Value, Does.Contain(("helper", "ftp")))
        let inactive = specification.Objects |> List.find (fun item -> item.Kind = "policy" && item.Name = "inactive-stage")
        Assert.That(inactive.Value.Ingress, Is.Empty)
        Assert.That(inactive.Value.Egress, Is.EquivalentTo [ "external" ])
        let hostWeb = specification.Objects |> List.find (fun item -> item.Kind = "policy" && item.Name = "host-web")
        let hostWebConfiguration = FirewalldModel.parse hostWeb.Configuration
        Assert.That(hostWebConfiguration.Elements |> List.exists (fun element -> element.Name = "source-port"), Is.True)
        Assert.That(FirewalldModel.references external.Value, Does.Contain(("service", "application")))
        Assert.That(FirewalldModel.references external.Value, Does.Contain(("ipset", "trusted")))
        Assert.That(FirewalldModel.references external.Value, Does.Contain(("icmptype", "echo-request")))

        let legacy = zone "legacy" { ports [ 80, Tcp ] }
        Assert.That((FirewalldModel.parse legacy.Configuration).Ports, Does.Contain("80/tcp"))

    [<Test>]
    member _.``Mixed DSL keeps legacy host service, user description and UFW reject resolvable``() =
        Assert.That(FirewalldMixedDslConsumer.hostService.Configuration, Does.Contain "ExecStart=/bin/true")
        Assert.That(FirewalldMixedDslConsumer.firewalldService.Value.Ports, Is.EquivalentTo ["8443/tcp"])
        Assert.That(FirewalldMixedDslConsumer.userDescription, Is.EqualTo(UserDescription "Legacy user description"))
        Assert.That(FirewalldMixedDslConsumer.alternate.Rules, Does.Contain ["reject"; "in"; "proto"; "tcp"; "to"; "any"; "port"; "9443"])

    [<Test>]
    member _.``Public richRules accept only rules and rich forward-ports require a family``() =
        let sourcePort : FirewalldModel.Element =
            { Name = "source-port"; Attributes = Map.ofList [ "port", "1024"; "protocol", "tcp" ]; Text = None; Children = [] }
        Assert.Throws<ArgumentException>(fun () ->
            zone "smuggled" { richRules [ sourcePort ] } |> ignore) |> ignore
        let portOnly = richRule { forwardPort (tcpPort 8123) None (Some (tcpPort 8124)) }
        Assert.Throws<ArgumentException>(fun () ->
            zone "missing-family" { richRules [ portOnly ] } |> ignore) |> ignore

    [<Test>]
    member _.``Firewalld rejects dependency cycles and ambiguous ownership``() =
        let invalid =
            [ (fun () ->
                  firewalld {
                      Defined.service "first" { includes [ "second" ] }
                      Defined.service "second" { includes [ "first" ] }
                  }
                  |> ignore)
              (fun () ->
                  firewalld {
                      zone "shared" {}
                      policy "shared" { ingressZones [ "HOST" ]; egressZones [ "public" ] }
                  }
                  |> ignore)
              (fun () ->
                  firewalld {
                      zone "wildcard" { interfaces [ "enp+" ] }
                      zone "literal" { interfaces [ "enp0s3" ] }
                  }
                  |> ignore)
              (fun () ->
                  firewalld {
                      zone "first" { sources [ sourceAddress "192.0.2.0/24" ] }
                      zone "second" { sources [ sourceAddress "192.0.2.0/24" ] }
                  }
                  |> ignore) ]
        for action in invalid do
            Assert.Throws<ArgumentException>(TestDelegate action) |> ignore

    [<Test>]
    member _.``Strict Docker gate rejects perforated or bypassed guards but keeps HOST services``() =
        let hostService =
            policy "host-ssh" {
                ingressZones [ "public" ]
                egressZones [ "HOST" ]
                services [ "ssh" ]
                target FirewalldTarget.Accept
                priority -20
            }
        let guard =
            policy "docker-block" {
                ingressZones [ "public" ]
                egressZones [ "docker" ]
                target FirewalldTarget.Drop
                priority -10
            }
        let perforatedGuard =
            policy "docker-block" {
                ingressZones [ "public" ]
                egressZones [ "docker" ]
                target FirewalldTarget.Drop
                priority -10
                richRules [ richRule { richService "ssh"; RichRule.accept } ]
            }
        let safeRichGuard =
            policy "docker-block" {
                ingressZones [ "public" ]
                egressZones [ "docker" ]
                target FirewalldTarget.Drop
                priority -10
                richRules [ richRule { richService "ssh"; RichRule.drop } ]
            }
        let earlierAllow =
            policy "docker-allow" {
                ingressZones [ "public" ]
                egressZones [ "docker" ]
                target FirewalldTarget.Accept
                priority -20
            }
        let hostRichService =
            policy "host-rich-service" {
                ingressZones [ "public" ]
                egressZones [ "HOST" ]
                target FirewalldTarget.Accept
                priority -15
                richRules [ richRule { richService "ssh"; RichRule.accept } ]
            }
        let hostOriginated =
            policy "host-originated" {
                ingressZones [ "HOST" ]
                egressZones [ "ANY" ]
                services [ "ssh" ]
                target FirewalldTarget.Accept
                priority -20
            }
        let continues =
            policy "continue-docker" {
                ingressZones [ "ANY" ]
                egressZones [ "docker" ]
                target FirewalldTarget.Continue
                priority -20
            }
        let anyGuard =
            policy "docker-any-block" {
                ingressZones [ "ANY" ]
                egressZones [ "docker" ]
                target FirewalldTarget.Drop
                priority -10
            }
        let compile (policies: FirewalldObjectSpec list) (containerGuard: FirewalldObjectSpec) =
            let firewall =
                firewalld {
                    strictForwardPorts true
                    zone "public" {}
                    hostService
                    yield! policies
                    containerGuard
                }
            let docker =
                docker {
                    container "web" {
                        image "nginx:1.27"
                        restart unlessStopped
                        dependsOnFirewalld containerGuard
                    }
                }
            debian {
                docker
                firewall
            }
        Assert.DoesNotThrow(fun () -> compile [] guard |> ignore)
        Assert.Throws<ArgumentException>(fun () -> compile [] perforatedGuard |> ignore) |> ignore
        Assert.Throws<ArgumentException>(fun () -> compile [ earlierAllow ] guard |> ignore) |> ignore
        Assert.DoesNotThrow(fun () -> compile [ hostOriginated ] anyGuard |> ignore)
        Assert.DoesNotThrow(fun () -> compile [ continues ] anyGuard |> ignore)
        Assert.Throws<ArgumentException>(fun () -> compile [] safeRichGuard |> ignore) |> ignore
        Assert.DoesNotThrow(fun () -> compile [ hostRichService ] guard |> ignore)
        let externalOnly (fence: FirewalldObjectSpec) =
            let stackFirewall = firewalld { strictForwardPorts true; fence }
            let engine = docker { yield! ([]: DockerContainerSpec list) }
            debian { engine; stackFirewall }
        Assert.Throws<ArgumentException>(fun () -> externalOnly perforatedGuard |> ignore) |> ignore
        match externalOnly guard with
        | Debian spec -> Assert.That(spec.Docker.Value.Containers, Is.Empty)
        | _ -> Assert.Fail("Expected the validated Debian engine declaration.")

    [<Test>]
    member _.``Docker readiness unit depends only on effective docker guard and preserves old resource names``() =
        let hostService =
            policy "host-ssh" {
                ingressZones [ "public" ]
                egressZones [ "HOST" ]
                services [ "ssh" ]
                target FirewalldTarget.Accept
                priority -20
            }
        let guard =
            policy "docker-block" {
                ingressZones [ "public" ]
                egressZones [ "docker" ]
                target FirewalldTarget.Drop
                priority -10
            }
        let host =
            sshHost "guarded" {
                Address "192.0.2.2"
                User "root"
                debian {
                    docker {
                        container "web" {
                            image "nginx:1.27"
                            restart unlessStopped
                            dependsOnFirewalld guard
                        }
                    }
                    firewalld {
                        strictForwardPorts true
                        zone "public" {}
                        hostService
                        guard
                    }
                }
            }
        FirewalldDeploymentFixture.captured.Clear()
        FirewalldDeploymentFixture.host <- Some host
        Deployment.TestAsync<FirewalldDependencyStack>(FirewalldDeploymentFixture.Mocks(), TestOptions()).GetAwaiter().GetResult() |> ignore
        let name (resource: Resource) = OutputUtilities.GetValueAsync(resource.Urn).Result.Split("::") |> Array.last
        let captured = FirewalldDeploymentFixture.captured |> Seq.filter (fun args -> not (args.Resource :? Stack)) |> Seq.toArray
        let guardResource =
            captured
            |> Array.find (fun args -> args.Args :? HostServiceArgs && name args.Resource = "guarded-docker-firewall-guard")
        let specification: Output<string> = Input<string>.op_Implicit((guardResource.Args :?> HostServiceArgs).Specification)
        let encoded = OutputUtilities.GetValueAsync(specification).Result
        let fences = FirewalldGateModel.decode (System.Text.Json.Nodes.JsonNode.Parse(encoded)["dockerFence"])
        Assert.That(fences, Is.EquivalentTo [ FirewalldGateModel.ofPolicy guard.Value ])
        let dependencies: Output<ImmutableArray<Resource>> = InputList<Resource>.op_Implicit guardResource.Options.DependsOn
        let dependencyNames = OutputUtilities.GetValueAsync(dependencies).Result |> Seq.map name |> Set.ofSeq
        Assert.That(dependencyNames, Does.Contain("guarded-firewalld-policy-docker-block"))
        Assert.That(dependencyNames, Does.Not.Contain("guarded-firewalld-policy-host-ssh"))

    [<Test>]
    member _.``Firewalld resources depend on declared parents and ignore external definitions``() =
        let baseService = Defined.service "base" { servicePorts [ tcpPort 8080 ] }
        let apiService = Defined.service "api" { includes [ "base"; "vendor-base" ] }
        let firewall =
            firewalld {
                apiService
                zone "public" {
                    services [ "api" ]
                    sources [ sourceIPSet "trusted" ]
                }
                setting "DefaultZone" "public"
                ipset "trusted" {
                    ipsetType "hash:ip"
                    entries [ "192.0.2.0/24" ]
                }
                baseService
            }
        let host =
            sshHost "graph" {
                Address "192.0.2.2"
                User "root"
                debian { firewall }
            }
        FirewalldDeploymentFixture.captured.Clear()
        FirewalldDeploymentFixture.host <- Some host
        Deployment.TestAsync<FirewalldDependencyStack>(FirewalldDeploymentFixture.Mocks(), TestOptions()).GetAwaiter().GetResult() |> ignore
        let name (resource: Resource) = OutputUtilities.GetValueAsync(resource.Urn).Result.Split("::") |> Array.last
        let captured = FirewalldDeploymentFixture.captured |> Seq.filter (fun args -> not (args.Resource :? Stack)) |> Seq.toArray
        let firewalldResource resourceName =
            captured |> Array.find (fun args -> args.Args :? FirewalldArgs && name args.Resource = resourceName)
        let dependencies (args: ResourceTransformationArgs) =
            let output: Output<ImmutableArray<Resource>> = InputList<Resource>.op_Implicit args.Options.DependsOn
            OutputUtilities.GetValueAsync(output).Result |> Seq.map name |> Set.ofSeq
        let apiDependencies = firewalldResource "graph-firewalld-service-api" |> dependencies
        Assert.That(apiDependencies, Does.Contain("graph-firewalld-service-base"))
        Assert.That(apiDependencies, Does.Not.Contain("graph-firewalld-service-vendor-base"))
        let zoneDependencies = firewalldResource "graph-firewalld-zone-public" |> dependencies
        Assert.That(zoneDependencies, Does.Contain("graph-firewalld-service-api"))
        Assert.That(zoneDependencies, Does.Contain("graph-firewalld-ipset-trusted"))
        let settingDependencies = firewalldResource "graph-firewalld-setting-DefaultZone" |> dependencies
        Assert.That(settingDependencies, Does.Contain("graph-firewalld-zone-public"))
