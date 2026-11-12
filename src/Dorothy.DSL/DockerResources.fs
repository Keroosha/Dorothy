namespace Dorothy.DSL

open System
open System.Collections.Generic
open System.Globalization
open System.Security.Cryptography
open System.Text
open System.Threading
open Pulumi
open Pulumi.Docker.Inputs

/// Translates declarations to independent Docker resources; no resources are created inside Apply.
module internal DockerDeployment =
    let private input (value: 'T) : Input<'T> = Input<'T>.op_Implicit value
    let private output (value: Output<'T>) : Input<'T> = Input<'T>.op_Implicit value
    let private strings (values: string list) = InputList<string>.op_Implicit (List.toArray values)

    let private physicalName (host: HostSpec) (name: string) =
        let identity = String.concat "/" [ Deployment.Instance.ProjectName; Deployment.Instance.StackName; host.Name; name ]
        let digest = SHA256.HashData(Encoding.UTF8.GetBytes identity) |> Convert.ToHexStringLower
        let readable =
            host.Name + "-" + name
            |> Seq.map (fun ch -> if Char.IsAsciiLetterOrDigit ch || ch = '-' || ch = '_' || ch = '.' then ch else '-')
            |> Seq.truncate 100
            |> Seq.toArray
            |> String
        "keroosha-" + readable + "-" + digest.Substring(0, 12)

    /// Docker returns Go's canonical duration spelling; equivalent noncanonical strings cause drift.
    let duration (value: TimeSpan) =
        let ticks = value.Ticks
        let number (value: decimal) = value.ToString("0.#######", CultureInfo.InvariantCulture)
        if ticks = 0L then "0s"
        elif ticks < TimeSpan.TicksPerMicrosecond then
            (ticks * 100L).ToString(CultureInfo.InvariantCulture) + "ns"
        elif ticks < TimeSpan.TicksPerMillisecond then
            number (decimal ticks / decimal TimeSpan.TicksPerMicrosecond) + "µs"
        elif ticks < TimeSpan.TicksPerSecond then
            number (decimal ticks / decimal TimeSpan.TicksPerMillisecond) + "ms"
        else
            let hours = ticks / TimeSpan.TicksPerHour
            let minutes = ticks / TimeSpan.TicksPerMinute % 60L
            let seconds = number (decimal (ticks % TimeSpan.TicksPerMinute) / decimal TimeSpan.TicksPerSecond)
            let hourPart = if hours > 0L then hours.ToString(CultureInfo.InvariantCulture) + "h" else ""
            let minutePart = if hours > 0L || minutes > 0L then minutes.ToString(CultureInfo.InvariantCulture) + "m" else ""
            hourPart + minutePart + seconds + "s"

    let deploy (host: HostSpec) (engine: CustomResource) (specification: DockerSpec) (completeJob: string -> Pulumi.Docker.Container -> TimeSpan -> Resource) =
        let endpoint = UriBuilder("ssh", host.Address, host.Port)
        endpoint.UserName <- host.User
        let providerArgs = Pulumi.Docker.ProviderArgs()
        providerArgs.Host <- input (endpoint.Uri.GetLeftPart(UriPartial.Authority))
        providerArgs.Context <- input ""
        providerArgs.DisableDockerDaemonCheck <- input true
        let sshOptions =
            [ "-o"; "BatchMode=yes"; "-o"; "StrictHostKeyChecking=yes"; "-o"; "ConnectTimeout=15"
              "-o"; "ControlMaster=no"; "-o"; "ControlPath=none" ]
            @ (host.IdentityFile |> Option.map (fun path -> [ "-i"; path; "-o"; "IdentitiesOnly=yes" ]) |> Option.defaultValue [])
        providerArgs.SshOpts <- strings sshOptions
        for registry in specification.Registries do
            let auth = ProviderRegistryAuthArgs()
            auth.Address <- input registry.Server
            auth.Username <- output (DockerStringInput.resolveRequired "registry username" registry.Username)
            auth.Password <- output (DockerStringInput.resolveSecretRequired "registry credential" registry.Credential)
            // Disable the provider's implicit ~/.docker/config.json credential source.
            auth.ConfigFile <- input ""
            providerArgs.RegistryAuth.Add(input auth)
        let providerOptions = CustomResourceOptions()
        providerOptions.Version <- "5.2.0"
        providerOptions.DependsOn <- InputList<Resource>.op_Implicit [| engine :> Resource |]
        let provider = Pulumi.Docker.Provider(host.Name + "-docker", providerArgs, providerOptions)
        let options () =
            let value = CustomResourceOptions()
            value.Provider <- provider
            value.DependsOn <- InputList<Resource>.op_Implicit [| engine :> Resource |]
            value
        let existingNetworks = Dictionary<string, Input<string>>(StringComparer.Ordinal)
        let existingVolumes = Dictionary<string, Input<string>>(StringComparer.Ordinal)
        let existingNetworkName name =
            match existingNetworks.TryGetValue name with
            | true, value -> value
            | false, _ ->
                // Offline previews cannot validate external state. Read-only lookups on every
                // apply prevent Docker from silently creating a misspelled external volume.
                let value =
                    if Deployment.Instance.IsDryRun then input name
                    else
                        let id = engine.Id.Apply(Func<string, string>(fun _ -> name))
                        let resource = Pulumi.Docker.Network.Get(host.Name + "-existing-network-" + name, output id, null, options ())
                        output resource.Name
                existingNetworks.Add(name, value)
                value
        let existingVolumeName name =
            match existingVolumes.TryGetValue name with
            | true, value -> value
            | false, _ ->
                let value =
                    if Deployment.Instance.IsDryRun then input name
                    else
                        let id = engine.Id.Apply(Func<string, string>(fun _ -> name))
                        let resource = Pulumi.Docker.Volume.Get(host.Name + "-existing-volume-" + name, output id, null, options ())
                        output resource.Name
                existingVolumes.Add(name, value)
                value
        let networks = Dictionary<string, Pulumi.Docker.Network>(StringComparer.Ordinal)
        for network in specification.Networks do
            let args = Pulumi.Docker.NetworkArgs()
            args.Name <- input (physicalName host network.Name)
            args.Driver <- input (match network.Driver with Bridge -> "bridge")
            networks.Add(network.Name, Pulumi.Docker.Network(host.Name + "-network-" + network.Name, args, options ()))
        let volumes = Dictionary<string, Pulumi.Docker.Volume>(StringComparer.Ordinal)
        for volume in specification.Volumes do
            let args = Pulumi.Docker.VolumeArgs()
            args.Name <- input (physicalName host volume.Name)
            let resourceOptions = options ()
            resourceOptions.Protect <- Nullable volume.Protect
            volumes.Add(volume.Name, Pulumi.Docker.Volume(host.Name + "-volume-" + volume.Name, args, resourceOptions))

        let containers = ResizeArray<Resource>()
        let ready = Dictionary<string, Resource>(StringComparer.Ordinal)
        for container in specification.Containers do
            let imageArgs = Pulumi.Docker.RemoteImageArgs()
            imageArgs.Name <- output (DockerStringInput.resolveRequired "image reference" container.Image)
            // Image cache is shared by other containers and is not a data-deletion boundary.
            imageArgs.KeepLocally <- input true
            let image = Pulumi.Docker.RemoteImage(host.Name + "-image-" + container.Name, imageArgs, options ())
            let args = Pulumi.Docker.ContainerArgs()
            args.Name <- input (physicalName host container.Name)
            args.Image <- output image.ImageId
            // Jobs are created stopped: only the native completion resource may start them.
            args.MustRun <- input container.RunOnce.IsNone
            args.Start <- input container.RunOnce.IsNone
            args.Rm <- input false
            args.RemoveVolumes <- input false
            args.DestroyGraceSeconds <- input 10
            args.Restart <-
                input (match container.Restart with NoRestart -> "no" | Always -> "always" | UnlessStopped -> "unless-stopped" | OnFailure _ -> "on-failure")
            match container.Restart with
            | OnFailure(Some retries) -> args.MaxRetryCount <- input retries
            | _ -> ()
            container.Cpu |> Option.iter (fun value -> args.Cpus <- input ((float value).ToString("G", CultureInfo.InvariantCulture)))
            container.Memory |> Option.iter (fun value ->
                args.Memory <- input (int value)
                args.MemorySwap <- input (Checked.(*) (int value) 2))
            container.Command |> Option.iter (fun value -> args.Command <- strings value)
            container.Entrypoint |> Option.iter (fun value -> args.Entrypoints <- strings value)
            container.WorkingDirectory |> Option.iter (fun value -> args.WorkingDir <- input value)
            container.RunAs |> Option.iter (fun value -> args.User <- input value)
            container.ReadOnlyRootFilesystem |> Option.iter (fun value -> args.ReadOnly <- input value)
            container.Init |> Option.iter (fun value -> args.Init <- input value)
            for KeyValue(key, value) in container.Environment do
                args.Envs.Add(output ((DockerStringInput.resolveSecret value).Apply(Func<string, string>(fun text -> key + "=" + text))))
            for KeyValue(key, value) in container.Labels do
                let label = ContainerLabelArgs()
                label.Label <- input key
                label.Value <- input value
                args.Labels.Add(input label)
            container.RunOnce |> Option.iter (fun timeout ->
                let label = ContainerLabelArgs()
                label.Label <- input "io.dorothy.run-once-timeout"
                label.Value <- input (timeout.Ticks.ToString(CultureInfo.InvariantCulture))
                args.Labels.Add(input label))
            match container.NetworkMode with
            | Some HostNetwork -> args.NetworkMode <- input "host"
            | None -> args.NetworkMode <- input "bridge"
            for attachment in container.Networks do
                let network = ContainerNetworksAdvancedArgs()
                let name, aliases =
                    match attachment with
                    | ManagedNetwork(spec, aliases) -> output networks[spec.Name].Name, aliases
                    | ExistingNetwork(spec, aliases) -> existingNetworkName spec.Name, aliases
                network.Name <- name
                network.Aliases <- strings aliases
                args.NetworksAdvanced.Add(input network)
            for mount in container.Mounts do
                let value = ContainerMountArgs()
                value.Target <- input mount.Target
                value.ReadOnly <- input (mount.Access = ReadOnly)
                match mount.Source with
                | ManagedVolume spec ->
                    value.Type <- input "volume"
                    value.Source <- output volumes[spec.Name].Name
                | ExistingVolume spec ->
                    value.Type <- input "volume"
                    value.Source <- existingVolumeName spec.Name
                | Bind path ->
                    value.Type <- input "bind"
                    value.Source <- input path
                | Tmpfs(DockerTmpfs size) ->
                    value.Type <- input "tmpfs"
                    size |> Option.iter (fun size ->
                        let tmpfs = ContainerMountTmpfsOptionsArgs()
                        tmpfs.SizeBytes <- input (Checked.(*) (int size) (1024 * 1024))
                        value.TmpfsOptions <- input tmpfs)
                args.Mounts.Add(input value)
            for port in container.PublishedPorts do
                let protocols = match port.Protocol with Tcp -> [ "tcp" ] | Udp -> [ "udp" ] | TcpAndUdp -> [ "tcp"; "udp" ]
                for protocol in protocols do
                    let value = ContainerPortArgs()
                    value.Ip <- input port.HostAddress
                    value.External <- input port.HostPort
                    value.Internal <- input port.ContainerPort
                    value.Protocol <- input protocol
                    args.Ports.Add(input value)
            container.Healthcheck |> Option.iter (fun health ->
                let value = ContainerHealthcheckArgs()
                value.Tests <- strings (match health.Command with DockerExec command -> "CMD" :: command | DockerShell command -> [ "CMD-SHELL"; command ])
                health.Interval |> Option.iter (fun interval -> value.Interval <- input (duration interval))
                health.Timeout |> Option.iter (fun timeout -> value.Timeout <- input (duration timeout))
                health.StartPeriod |> Option.iter (fun period -> value.StartPeriod <- input (duration period))
                health.Retries |> Option.iter (fun retries -> value.Retries <- input retries)
                args.Healthcheck <- input value)
            container.WaitHealthy |> Option.iter (fun timeout ->
                args.Wait <- input true
                args.WaitTimeout <- input (DockerValidation.waitHealthySeconds timeout))
            for file in container.Files do
                let value = ContainerUploadArgs()
                value.File <- input file.Path
                value.Permissions <- input file.Permissions
                value.ContentBase64 <- output (DockerContent.resolve CancellationToken.None file.Content file.Secret)
                args.Uploads.Add(input value)
            let resourceOptions = options ()
            resourceOptions.DependsOn <-
                InputList<Resource>.op_Implicit
                    (Array.ofList ((engine :> Resource) :: (container.Dependencies |> List.map (fun dependency -> ready[dependency.Name]))))
            // Even Docker's normally mutable inputs describe a new job generation.
            if container.RunOnce.IsSome then resourceOptions.ReplaceOnChanges <- List<string>([ "*" ])
            // Fixed names and published ports cannot coexist during a replacement.
            resourceOptions.DeleteBeforeReplace <- Nullable true
            resourceOptions.AdditionalSecretOutputs <- List<string>([| "envs"; "uploads" |])
            let resource = Pulumi.Docker.Container(host.Name + "-container-" + container.Name, args, resourceOptions)
            let completed =
                match container.RunOnce with
                | Some timeout -> completeJob (host.Name + "-container-" + container.Name + "-completion") resource timeout
                | None -> resource :> Resource
            ready.Add(container.Name, completed)
            containers.Add(completed)
        List.ofSeq containers
