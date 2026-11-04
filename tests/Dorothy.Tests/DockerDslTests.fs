namespace Dorothy.Tests

open System
open System.IO
open System.Text
open System.Threading
open System.Threading.Tasks
open Dorothy.DSL
open NUnit.Framework

module private DockerDslTestHelpers =
    let expectArgumentException (operation: unit -> 'T) =
        Assert.Throws<ArgumentException>(TestDelegate(fun () -> operation() |> ignore)) |> ignore

    let service name =
        container name {
            image "registry.example.test/team/service:1.2.3"
            restart unlessStopped
        }

    let publishedPort address hostPortNumber containerPortNumber protocol =
        publish {
            hostAddress address
            hostPort hostPortNumber
            containerPort containerPortNumber
            proto protocol
        }

    type TrackingMemoryStream(bytes: byte array, onDispose: unit -> unit) =
        inherit MemoryStream(bytes)

        override this.Dispose(disposing) =
            if disposing then onDispose()
            base.Dispose(disposing)

[<TestFixture>]
type DockerDslTests() =
    [<Test>]
    member _.``Docker root supports conditional loop and yield-from composition with stable ordering``() =
        // Arrange
        let includeBackend = true
        let extraNetworks = [ network "z-network" { driver Bridge }; network "a-network" { driver Bridge } ]

        // Act
        let spec =
            docker {
                if includeBackend then network "backend" { driver Bridge }
                yield! extraNetworks
                for name in [ "z-volume"; "a-volume" ] do
                    volume name { protect true }
                for name in [ "z-container"; "a-container" ] do
                    container name {
                        image ("registry.example.test/team/" + name + ":1.0")
                        restart unlessStopped
                    }
            }

        // Assert
        Assert.That(spec.Networks |> List.map (fun item -> item.Name), Is.EqualTo(box [ "a-network"; "backend"; "z-network" ]))
        Assert.That(spec.Volumes |> List.map (fun item -> item.Name), Is.EqualTo(box [ "a-volume"; "z-volume" ]))
        Assert.That(spec.Containers |> List.map (fun item -> item.Name), Is.EqualTo(box [ "a-container"; "z-container" ]))
        Assert.That((volume "data" {}).Protect, Is.True)

    [<Test>]
    member _.``Docker root validates managed references by identity and accepts external references``() =
        // Arrange
        let declaredNetwork = network "backend" { driver Bridge }
        let declaredVolume = volume "data" { protect false }
        let sameNamedUnregisteredNetwork = network "backend" { driver Bridge }
        let sameNamedUnregisteredVolume = volume "data" { protect false }
        let missingNetwork = fun () ->
            docker {
                declaredNetwork
                declaredVolume
                container "api" {
                    image "registry.example.test/team/api:1.0"
                    restart unlessStopped
                    attach sameNamedUnregisteredNetwork
                }
            }
        let missingVolume = fun () ->
            docker {
                declaredNetwork
                declaredVolume
                container "api" {
                    image "registry.example.test/team/api:1.0"
                    restart unlessStopped
                    mount { source sameNamedUnregisteredVolume; target "/data" }
                }
            }

        // Act / Assert
        DockerDslTestHelpers.expectArgumentException (fun () -> missingNetwork () |> ignore)
        DockerDslTestHelpers.expectArgumentException (fun () -> missingVolume () |> ignore)

        let externalNetwork = existingNetwork "shared-backend"
        let externalVolume = existingVolume "shared-data"
        let externalSpec =
            docker {
                container "api" {
                    image "registry.example.test/team/api:1.0"
                    restart unlessStopped
                    attach externalNetwork
                    mount { source externalVolume; target "/data"; access ReadOnly }
                }
            }

        Assert.That(externalSpec.Networks, Is.Empty)
        Assert.That(externalSpec.Volumes, Is.Empty)
        match externalSpec.Containers[0].Networks with
        | [ DockerNetworkAttachment.ExistingNetwork(network, []) ] ->
            Assert.That(network.Name, Is.EqualTo("shared-backend"))
        | actual -> Assert.Fail(sprintf "Expected an explicit external network attachment, received %A." actual)
        match externalSpec.Containers[0].Mounts[0].Source with
        | DockerMountSource.ExistingVolume(volume) -> Assert.That(volume.Name, Is.EqualTo("shared-data"))
        | actual -> Assert.Fail(sprintf "Expected an explicit external volume source, received %A." actual)

    [<Test>]
    member _.``Docker declarations reject duplicate logical names and repeated Debian Docker configuration``() =
        // Arrange
        let duplicateNetwork = fun () -> docker { network "backend" { driver Bridge }; network "backend" { driver Bridge } }
        let duplicateContainer = fun () -> docker { DockerDslTestHelpers.service "api"; DockerDslTestHelpers.service "api" }
        let duplicateDebianDocker = fun () -> debian { docker {}; docker {} }

        // Act / Assert
        DockerDslTestHelpers.expectArgumentException (fun () -> duplicateNetwork () |> ignore)
        DockerDslTestHelpers.expectArgumentException (fun () -> duplicateContainer () |> ignore)
        DockerDslTestHelpers.expectArgumentException (fun () -> duplicateDebianDocker () |> ignore)

    [<Test>]
    member _.``Docker containers require an image and restart policy and validate names``() =
        // Arrange
        let missingImage = fun () -> container "api" { restart unlessStopped }
        let missingRestart = fun () -> container "api" { image "registry.example.test/team/api:1.0" }
        let emptyImage = fun () -> container "api" { image " "; restart unlessStopped }
        let invalidName = fun () -> container "bad/name" { image "registry.example.test/team/api:1.0"; restart unlessStopped }

        // Act / Assert
        DockerDslTestHelpers.expectArgumentException (fun () -> missingImage () |> ignore)
        DockerDslTestHelpers.expectArgumentException (fun () -> missingRestart () |> ignore)
        DockerDslTestHelpers.expectArgumentException (fun () -> emptyImage () |> ignore)
        DockerDslTestHelpers.expectArgumentException (fun () -> invalidName () |> ignore)


    [<Test>]
    member _.``Docker container rejects duplicate environment keys mount targets and uploaded paths``() =
        // Arrange
        let duplicateEnvironment = fun () ->
            container "api" {
                image "registry.example.test/team/api:1.0"
                restart unlessStopped
                env "MODE" "first"
                env "MODE" "second"
            }
        let duplicateMountTarget = fun () ->
            container "api" {
                image "registry.example.test/team/api:1.0"
                restart unlessStopped
                mount { source (existingVolume "first"); target "/data" }
                mount { source (existingVolume "second"); target "/data" }
            }
        let duplicateFilePath = fun () ->
            container "api" {
                image "registry.example.test/team/api:1.0"
                restart unlessStopped
                containerFile "/etc/service.conf" { content (DockerContent.text "first") }
                containerFile "/etc/service.conf" { content (DockerContent.text "second") }
            }

        // Act / Assert
        DockerDslTestHelpers.expectArgumentException (fun () -> duplicateEnvironment () |> ignore)
        DockerDslTestHelpers.expectArgumentException (fun () -> duplicateMountTarget () |> ignore)
        DockerDslTestHelpers.expectArgumentException (fun () -> duplicateFilePath () |> ignore)


    [<Test>]
    member _.``Docker mounts preserve managed bind and tmpfs sources and reject invalid paths or sizes``() =
        // Arrange
        let state = volume "state" { protect false }
        let invalidRelativeBind = fun () -> mount { source (bind "var/lib/service"); target "/host" }
        let invalidTmpfsSize = fun () -> mount { source (tmpfsSize 0<MiB>); target "/cache" }
        let oversizedTmpfs = fun () -> mount { source (tmpfsSize 2048<MiB>); target "/cache" }
        let relativeTarget = fun () -> mount { source tmpfs; target "temporary" }

        // Act / Assert
        DockerDslTestHelpers.expectArgumentException (fun () -> invalidRelativeBind () |> ignore)
        DockerDslTestHelpers.expectArgumentException (fun () -> invalidTmpfsSize () |> ignore)
        DockerDslTestHelpers.expectArgumentException (fun () -> oversizedTmpfs () |> ignore)
        DockerDslTestHelpers.expectArgumentException (fun () -> relativeTarget () |> ignore)

        let spec =
            docker {
                state
                container "api" {
                    image "registry.example.test/team/api:1.0"
                    restart unlessStopped
                    mount { source state; target "/state"; access ReadWrite }
                    mount { source (bind "/var/lib/service"); target "/host"; access ReadOnly }
                    mount { source tmpfs; target "/tmp" }
                    mount { source (tmpfsSize 64<MiB>); target "/cache" }
                }
            }
        let mounts = spec.Containers[0].Mounts |> List.map (fun item -> item.Target, item) |> Map.ofList
        Assert.That((mounts["/state"]).Access, Is.EqualTo(ReadWrite))
        Assert.That((mounts["/host"]).Access, Is.EqualTo(ReadOnly))
        Assert.That((mounts["/host"]).Source, Is.EqualTo(Bind "/var/lib/service"))
        Assert.That((mounts["/tmp"]).Source, Is.EqualTo(Tmpfs(DockerTmpfs None)))
        Assert.That((mounts["/cache"]).Source, Is.EqualTo(Tmpfs(DockerTmpfs(Some 64<MiB>))))

    [<Test>]
    member _.``Docker uploaded files require valid absolute paths and permissions``() =
        // Arrange
        let missingContent = fun () -> containerFile "/etc/service.conf" {}
        let relativePath = fun () -> containerFile "service.conf" { content (DockerContent.text "value") }
        let invalidPermissions = fun () -> containerFile "/etc/service.conf" { content (DockerContent.text "value"); permissions "8888" }

        // Act / Assert
        DockerDslTestHelpers.expectArgumentException (fun () -> missingContent () |> ignore)
        DockerDslTestHelpers.expectArgumentException (fun () -> relativePath () |> ignore)
        DockerDslTestHelpers.expectArgumentException (fun () -> invalidPermissions () |> ignore)

        let defaultFile = containerFile "/etc/service.conf" { content (DockerContent.text "value") }
        let secretFile =
            containerFile "/run/secrets/service-token" {
                content (DockerContent.text "sensitive")
                permissions "0400"
                secret true
            }
        Assert.That(defaultFile.Permissions, Is.EqualTo("0644"))
        Assert.That(defaultFile.Secret, Is.False)
        Assert.That(secretFile.Permissions, Is.EqualTo("0400"))
        Assert.That(secretFile.Secret, Is.True)

    [<Test>]
    member _.``Docker port publication requires valid address and all four fields``() =
        // Arrange
        let invalidPublications: (string * (unit -> unit)) list = [
            "missing host address", (fun () -> publish { hostPort 10000; containerPort 8080; proto Tcp } |> ignore)
            "missing host port", (fun () -> publish { hostAddress "127.0.0.1"; containerPort 8080; proto Tcp } |> ignore)
            "missing container port", (fun () -> publish { hostAddress "127.0.0.1"; hostPort 10000; proto Tcp } |> ignore)
            "missing protocol", (fun () -> publish { hostAddress "127.0.0.1"; hostPort 10000; containerPort 8080 } |> ignore)
            "non-literal address", (fun () -> publish { hostAddress "localhost"; hostPort 10000; containerPort 8080; proto Tcp } |> ignore)
            "host port below range", (fun () -> publish { hostAddress "127.0.0.1"; hostPort 0; containerPort 8080; proto Tcp } |> ignore)
            "host port above range", (fun () -> publish { hostAddress "127.0.0.1"; hostPort 65536; containerPort 8080; proto Tcp } |> ignore)
            "container port below range", (fun () -> publish { hostAddress "127.0.0.1"; hostPort 10000; containerPort 0; proto Tcp } |> ignore)
            "container port above range", (fun () -> publish { hostAddress "127.0.0.1"; hostPort 10000; containerPort 65536; proto Tcp } |> ignore)
        ]

        // Act / Assert
        for _, action in invalidPublications do
            DockerDslTestHelpers.expectArgumentException action

        let valid = DockerDslTestHelpers.publishedPort "127.0.0.1" 10000 8080 Tcp
        Assert.That(valid.HostAddress, Is.EqualTo("127.0.0.1"))
        Assert.That(valid.HostPort, Is.EqualTo(10000))
        Assert.That(valid.ContainerPort, Is.EqualTo(8080))
        Assert.That(valid.Protocol, Is.EqualTo(Tcp))
        let boundary = DockerDslTestHelpers.publishedPort "127.0.0.1" 1 65535 Tcp
        Assert.That(boundary.HostPort, Is.EqualTo(1))
        Assert.That(boundary.ContainerPort, Is.EqualTo(65535))

    [<Test>]
    member _.``Docker host port overlap accounts for wildcard addresses across containers and transports``() =
        // Arrange
        let sameContainerOverlap = fun () ->
            container "api" {
                image "registry.example.test/team/api:1.0"
                restart unlessStopped
                DockerDslTestHelpers.publishedPort "127.0.0.1" 8080 80 Tcp
                DockerDslTestHelpers.publishedPort "127.0.0.1" 8080 81 Tcp
            }
        let wildcardAcrossContainers = fun () ->
            docker {
                container "api-v4" {
                    image "registry.example.test/team/api:1.0"
                    restart unlessStopped
                    DockerDslTestHelpers.publishedPort "0.0.0.0" 8080 80 Tcp
                }
                container "api-loopback" {
                    image "registry.example.test/team/api:1.0"
                    restart unlessStopped
                    DockerDslTestHelpers.publishedPort "127.0.0.1" 8080 80 Tcp
                }
            }
        let combinedTransportConflict = fun () ->
            docker {
                container "api-both" {
                    image "registry.example.test/team/api:1.0"
                    restart unlessStopped
                    DockerDslTestHelpers.publishedPort "::" 8080 80 TcpAndUdp
                }
                container "api-tcp" {
                    image "registry.example.test/team/api:1.0"
                    restart unlessStopped
                    DockerDslTestHelpers.publishedPort "2001:db8::1" 8080 80 Tcp
                }
            }

        // Act / Assert
        DockerDslTestHelpers.expectArgumentException (fun () -> sameContainerOverlap () |> ignore)
        DockerDslTestHelpers.expectArgumentException (fun () -> wildcardAcrossContainers () |> ignore)
        DockerDslTestHelpers.expectArgumentException (fun () -> combinedTransportConflict () |> ignore)

        let separateTransports =
            docker {
                container "api-tcp" {
                    image "registry.example.test/team/api:1.0"
                    restart unlessStopped
                    DockerDslTestHelpers.publishedPort "127.0.0.1" 8080 80 Tcp
                }
                container "api-udp" {
                    image "registry.example.test/team/api:1.0"
                    restart unlessStopped
                    DockerDslTestHelpers.publishedPort "127.0.0.1" 8080 80 Udp
                }
            }
        let protocols = separateTransports.Containers |> List.collect (fun item -> item.PublishedPorts |> List.map (fun port -> port.Protocol))
        Assert.That(protocols, Is.EquivalentTo([ Tcp; Udp ]))

    [<Test>]
    member _.``Docker host networking excludes attachments and published ports``() =
        // Arrange
        let withAttachment = fun () ->
            container "api" {
                image "registry.example.test/team/api:1.0"
                restart unlessStopped
                networkMode HostNetwork
                attach (existingNetwork "shared")
            }
        let withPublication = fun () ->
            container "api" {
                image "registry.example.test/team/api:1.0"
                restart unlessStopped
                networkMode HostNetwork
                DockerDslTestHelpers.publishedPort "127.0.0.1" 8080 80 Tcp
            }

        // Act / Assert
        DockerDslTestHelpers.expectArgumentException (fun () -> withAttachment () |> ignore)
        DockerDslTestHelpers.expectArgumentException (fun () -> withPublication () |> ignore)

        let valid = container "host-api" { image "registry.example.test/team/api:1.0"; restart unlessStopped; networkMode HostNetwork }
        Assert.That(valid.NetworkMode, Is.EqualTo(Some HostNetwork))
        Assert.That(valid.Networks, Is.Empty)
        Assert.That(valid.PublishedPorts, Is.Empty)

    [<Test>]
    member _.``Docker quantities and retry counts must be positive and CPU finite``() =
        // Arrange
        let invalidCpuValues: float<cpu> list = [
            0.0<cpu>
            -0.5<cpu>
            Double.NaN * 1.0<cpu>
            Double.PositiveInfinity * 1.0<cpu>
        ]
        let maximumMemory = (Int32.MaxValue / 2) * 1<MiB>

        // Act / Assert
        for value in invalidCpuValues do
            DockerDslTestHelpers.expectArgumentException (fun () ->
                container "api" { image "registry.example.test/team/api:1.0"; restart unlessStopped; cpu value } |> ignore)

        for value in [ 0<MiB>; -1<MiB>; maximumMemory + 1<MiB> ] do
            DockerDslTestHelpers.expectArgumentException (fun () ->
                container "api" { image "registry.example.test/team/api:1.0"; restart unlessStopped; memory value } |> ignore)

        let maximumMemoryContainer =
            container "max-memory" {
                image "registry.example.test/team/api:1.0"
                restart unlessStopped
                memory maximumMemory
            }
        Assert.That(maximumMemoryContainer.Memory, Is.EqualTo(Some maximumMemory))

        DockerDslTestHelpers.expectArgumentException (fun () ->
            container "api" { image "registry.example.test/team/api:1.0"; restart (onFailure (Some 0)) } |> ignore)

    [<Test>]
    member _.``Docker health readiness requires an explicit healthcheck with positive timings``() =
        // Arrange
        let waitWithoutHealthcheck = fun () ->
            container "api" {
                image "registry.example.test/team/api:1.0"
                restart unlessStopped
                waitHealthy (TimeSpan.FromSeconds(30.0))
            }
        let invalidDurations = [
            fun () -> healthcheck { healthExec [ "/usr/bin/true" ]; interval TimeSpan.Zero } |> ignore
            fun () -> healthcheck { healthExec [ "/usr/bin/true" ]; timeout (TimeSpan.FromSeconds(-1.0)) } |> ignore
            fun () -> healthcheck { healthExec [ "/usr/bin/true" ]; startPeriod TimeSpan.Zero } |> ignore
            fun () -> healthcheck { healthExec [ "/usr/bin/true" ]; retries 0 } |> ignore
            fun () -> healthcheck { retries 3 } |> ignore
            fun () ->
                container "api" {
                    image "registry.example.test/team/api:1.0"
                    restart unlessStopped
                    healthcheck { healthExec [ "/usr/bin/true" ] }
                    waitHealthy TimeSpan.Zero
                } |> ignore
            fun () -> healthcheck { healthExec [ "/usr/bin/true" ]; interval TimeSpan.MaxValue } |> ignore
        ]

        let durationLimit = TimeSpan.FromTicks(Int64.MaxValue / 100L)
        let withWaitHealthy name timeout =
            container name {
                image "registry.example.test/team/api:1.0"
                restart unlessStopped
                healthcheck { healthExec [ "/usr/bin/true" ] }
                waitHealthy timeout
            }
        let maximumWait = TimeSpan.FromTicks(int64 Int32.MaxValue * int64 TimeSpan.TicksPerSecond)
        let overMaximumWait = TimeSpan.FromTicks(maximumWait.Ticks + 1L)

        // Act / Assert
        DockerDslTestHelpers.expectArgumentException (fun () -> waitWithoutHealthcheck () |> ignore)
        for action in invalidDurations do DockerDslTestHelpers.expectArgumentException action
        DockerDslTestHelpers.expectArgumentException (fun () ->
            withWaitHealthy "over-maximum-wait" overMaximumWait |> ignore)

        let valid =
            container "healthy-api" {
                image "registry.example.test/team/api:1.0"
                restart unlessStopped
                healthcheck {
                    healthExec [ "/usr/bin/healthcheck"; "--ready" ]
                    interval (TimeSpan.FromSeconds(30.0))
                    timeout (TimeSpan.FromSeconds(5.0))
                    startPeriod (TimeSpan.FromSeconds(10.0))
                    retries 3
                }
                waitHealthy (TimeSpan.FromSeconds(90.0))
            }
        Assert.That(valid.Healthcheck.IsSome, Is.True)
        Assert.That(valid.WaitHealthy, Is.EqualTo(Some(TimeSpan.FromSeconds(90.0))))
        let durationBoundary =
            container "maximum-duration" {
                image "registry.example.test/team/api:1.0"
                restart unlessStopped
                healthcheck {
                    healthExec [ "/usr/bin/true" ]
                    interval durationLimit
                }
            }
        Assert.That(durationBoundary.Healthcheck.Value.Interval, Is.EqualTo(Some durationLimit))
        let maximumWaitContainer = withWaitHealthy "maximum-wait" maximumWait
        Assert.That(maximumWaitContainer.WaitHealthy, Is.EqualTo(Some maximumWait))
        let subsecondWaitContainer = withWaitHealthy "subsecond-wait" (TimeSpan.FromTicks(1L))
        Assert.That(subsecondWaitContainer.WaitHealthy, Is.EqualTo(Some(TimeSpan.FromTicks(1L))))

    [<Test>]
    member _.``Docker service CE coexists with UFW and shares its transport helper``() =
        // Arrange
        let declaration =
            sshHost "docker-host" {
                Address "192.0.2.10"
                User "debian"
                debian {
                    ufw {
                        allow { toPort 22; proto Tcp }
                    }
                    docker {
                        container "api" {
                            image "registry.example.test/team/api:1.0"
                            restart unlessStopped
                            publish {
                                hostAddress "127.0.0.1"
                                hostPort 8443
                                containerPort 8443
                                proto Tcp
                            }
                        }
                    }
                }
            }

        // Act / Assert
        Assert.That(declaration.Ufw.IsSome, Is.True)
        Assert.That(declaration.Docker.IsSome, Is.True)
        let firewall = declaration.Ufw.Value
        let dockerSpec = declaration.Docker.Value
        let expectedFirewallRules: string list list = [ [ "allow"; "in"; "proto"; "tcp"; "to"; "any"; "port"; "22" ] ]
        Assert.That(firewall.Rules, Is.EqualTo(box expectedFirewallRules))
        Assert.That(dockerSpec.Containers[0].PublishedPorts[0].Protocol, Is.EqualTo(Tcp))
        Assert.That(dockerSpec.Containers[0].PublishedPorts[0].HostPort, Is.EqualTo(8443))

    [<Test>]
    member _.``Docker registries require exactly one username and credential``() =
        // Arrange
        let missingUsername = fun () -> registry "registry.example.test" { registryPassword "password" }
        let missingCredential = fun () -> registry "registry.example.test" { username "robot" }
        let duplicateUsername = fun () -> registry "registry.example.test" { username "first"; username "second"; registryToken "token" }
        let multipleCredentials = fun () -> registry "registry.example.test" { username "robot"; registryPassword "password"; registryToken "token" }
        let invalidServer = fun () -> registry "https://registry.example.test" { username "robot"; registryToken "token" }

        // Act / Assert
        DockerDslTestHelpers.expectArgumentException (fun () -> missingUsername () |> ignore)
        DockerDslTestHelpers.expectArgumentException (fun () -> missingCredential () |> ignore)
        DockerDslTestHelpers.expectArgumentException (fun () -> duplicateUsername () |> ignore)
        DockerDslTestHelpers.expectArgumentException (fun () -> multipleCredentials () |> ignore)
        DockerDslTestHelpers.expectArgumentException (fun () -> invalidServer () |> ignore)

    [<Test>]
    member _.``Docker content stream stays unopened during CE construction and resolves once when requested``() : Task =
        task {
            // Arrange
            let mutable opens = 0
            let mutable disposals = 0
            let payload = Encoding.UTF8.GetBytes("deferred docker file")
            let streamFactory (_: CancellationToken) =
                opens <- opens + 1
                let stream =
                    new DockerDslTestHelpers.TrackingMemoryStream(payload, fun () -> disposals <- disposals + 1)
                Task.FromResult(stream :> Stream)

            let deferredContent = DockerContent.stream streamFactory
            let file = containerFile "/etc/service/credentials" { content deferredContent }
            let builtContainer =
                container "api" {
                    image "registry.example.test/team/api:1.0"
                    restart unlessStopped
                    file
                }

            Assert.That(opens, Is.EqualTo(0))
            Assert.That(disposals, Is.EqualTo(0))

            // Act
            let resolved = DockerContent.resolve CancellationToken.None builtContainer.Files[0].Content builtContainer.Files[0].Secret
            let! encoded = Pulumi.Utilities.OutputUtilities.GetValueAsync(resolved)

            // Assert
            Assert.That(opens, Is.EqualTo(1))
            Assert.That(disposals, Is.EqualTo(1))
            Assert.That(encoded, Is.EqualTo(Convert.ToBase64String(payload)))
            let! secret = Pulumi.Output.IsSecretAsync(resolved)
            Assert.That(secret, Is.False)
        }

    [<Test>]
    member _.``Docker output inputs retain secrecy and registry credentials are secret outputs``() : Task =
        task {
            // Arrange
            let secretImage = Pulumi.Output.CreateSecret<string>("private/image:tag")
            let secretEnvironment = Pulumi.Output.CreateSecret<string>("sensitive-value")
            let builtContainer =
                container "api" {
                    image secretImage
                    restart unlessStopped
                    env "TOKEN" secretEnvironment
                }
            let builtRegistry =
                registry "registry.example.test" {
                    username "robot"
                    registryPassword "password"
                }

            let builtTokenRegistry =
                registry "registry.example.test" {
                    username "robot"
                    registryToken (Pulumi.Output.Create<string>("registry token"))
                }

            // Act
            let! imageIsSecret = Pulumi.Output.IsSecretAsync(DockerStringInput.resolve builtContainer.Image)
            let! environmentIsSecret = Pulumi.Output.IsSecretAsync(DockerStringInput.resolve builtContainer.Environment["TOKEN"])
            let! registryCredentialIsSecret = Pulumi.Output.IsSecretAsync(DockerStringInput.resolveSecret builtRegistry.Credential)
            let! registryTokenIsSecret = Pulumi.Output.IsSecretAsync(DockerStringInput.resolveSecret builtTokenRegistry.Credential)
            let contentOutput =
                DockerContent.text (Pulumi.Output.CreateSecret<string>("file secret"))
                |> fun content -> DockerContent.resolve CancellationToken.None content false
            let! contentIsSecret = Pulumi.Output.IsSecretAsync(contentOutput)
            let explicitlySecretContent =
                DockerContent.resolve CancellationToken.None (DockerContent.text "explicit file secret") true
            let! explicitlySecretContentIsSecret = Pulumi.Output.IsSecretAsync(explicitlySecretContent)

            // Assert
            Assert.That(imageIsSecret, Is.True)
            Assert.That(environmentIsSecret, Is.True)
            Assert.That(registryCredentialIsSecret, Is.True)
            Assert.That(registryTokenIsSecret, Is.True)
            Assert.That(contentIsSecret, Is.True)
            Assert.That(explicitlySecretContentIsSecret, Is.True)
        }
