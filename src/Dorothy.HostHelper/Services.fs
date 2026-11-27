namespace Dorothy.HostHelper

open System
open System.IO
open System.Text
open System.Text.Json
open System.Text.Json.Nodes

module Services =
    type BackendError(message: string) =
        inherit InvalidOperationException(message)

    let private fail message = raise (BackendError message)
    let private text (request: JsonElement) (name: string) = request.GetProperty(name).GetString()

    let unitName (name: string) =
        if String.IsNullOrWhiteSpace name || name.StartsWith('-') || name.Length > 240
           || name |> Seq.exists (fun c -> not (Char.IsAsciiLetterOrDigit c || "_.@:-\\".Contains c)) then
            fail "Invalid systemd unit name."
        if name.EndsWith(".service", StringComparison.Ordinal) then name else name + ".service"

    // Debian 13 amd64 cold-install profile. These generators come from the
    // measured Debian packages; an installed name alone does not authenticate
    // its implementation. Refresh deliberately when qualifying another image.
    let private stockGenerators =
        Map.ofList [
            "netplan", "177488cdedb8637758cc2ec6521d1076609095f199499911b0a34a1f9b3f3c51"
            "systemd-debug-generator", "0ed5110c491db1663a505b27658464d18516be2436310ab3e7074872a6b78d57"
            "systemd-fstab-generator", "48b1e471ae09e84b1077275bf3e3620c28b7aa915837bf333cef20147ef370ea"
            "systemd-getty-generator", "03b892ea431712300685687841c23ed8927317e7f52a2dcaa5d59a92a3b024c6"
            "systemd-gpt-auto-generator", "5cab1473324acfe319121786aa49cb3a34e73ad715c673c34068799827abf2ff"
            "systemd-hibernate-resume-generator", "2230099ee3150e2b5568d0a8a602d2f64a43346a1fd64f61acd9975230a625cf"
            "systemd-rc-local-generator", "4924e494016eb3fac64c7d224d570d8d6b63dfdda44e2e5f50096c47ed21b966"
            "systemd-run-generator", "ef797a9f83c1052c10f60194dd25f0cd051418b76ef89d598feeb3a25f0ffba5"
            "systemd-ssh-generator", "7dcfab738a560149936db7b11ebfa5ca9317b50902cabbd48739ba77b001c649"
            "systemd-system-update-generator", "a4530d6dc256d902786acb32372b678f196a4a760db135a0bbd68e35c4ce9824"
            "systemd-sysv-generator", "662f91830e6f76e08a47be605ba2480ae87add1eac44aa095629bc0a4484cb11"
            "systemd-tpm2-generator", "07dd5f254baa1f830c1ce97d9155b79fdde4e61a6ff84b0161439f63fc250f77" ]
    // cat-config is the persisted view now, not proof of the files PID 1 read at boot.
    // The live manager/PID1 environments are checked separately; qualification still
    // assumes the trusted policy was present at boot and was not independently changed.

    let private managerConfigurationMatches (environment: HostEnvironment) =
        let result =
            environment.Run "/usr/bin/systemd-analyze"
                [ "--no-pager"; "--tldr"; "cat-config"; "systemd/system.conf" ] None
        if result.ExitCode <> 0 || result.Stderr <> "" || isNull result.Stdout then false
        else
            let active =
                result.Stdout.Split('\n')
                |> Array.map (fun line ->
                    if line.EndsWith("\r", StringComparison.Ordinal) then line.Substring(0, line.Length - 1)
                    else line)
                |> Array.filter (fun line -> not (String.IsNullOrWhiteSpace line) && not (line.StartsWith("#", StringComparison.Ordinal)))
            active = [| "[Manager]"; "DefaultLimitCORE=0:infinity" |]


    let internal coldGeneratorProfile (environment: HostEnvironment) =
        let path = HostEnvironment.path environment
        let known vendor (file: string) =
            match Map.tryFind (Path.GetFileName file) stockGenerators with
            | Some hash when vendor ->
                // Do not open a FIFO/device even if given a stock filename.
                let info = environment.Run "/usr/bin/stat" [ "-L"; "-c"; "%f"; "--"; file ] None
                info.ExitCode = 0 && info.Stderr = ""
                && (Convert.ToInt32(info.Stdout.Trim(), 16) &&& 0xf000) = 0x8000
                && (use stream = File.OpenRead file
                    Convert.ToHexStringLower(Security.Cryptography.SHA256.HashData stream) = hash)
            | _ -> false
        let directory prefix kind =
            let dir = path (prefix + "/systemd/" + kind)
            let attributes =
                try Some(File.GetAttributes dir)
                with :? DirectoryNotFoundException | :? FileNotFoundException -> None
            match attributes with
            | None -> true
            | Some attrs ->
                attrs.HasFlag FileAttributes.Directory && not (attrs.HasFlag FileAttributes.ReparsePoint)
                && (Directory.EnumerateFileSystemEntries dir
                    |> Seq.forall (known (prefix = "/usr/lib" && kind = "system-generators")))
        let ordinaryEnvironment (separator: char) (text: string) =
            let entries = text.Split(separator, StringSplitOptions.RemoveEmptyEntries)
            entries.Length > 0 && entries |> Array.forall (fun entry ->
                let i = entry.IndexOf '='
                i > 0 &&
                match entry.Substring(0, i) with
                | "PATH" ->
                    entry.Substring(i + 1).Split(':')
                    |> Array.forall (function "/usr/local/sbin" | "/usr/local/bin" | "/usr/sbin" | "/usr/bin" | "/sbin" | "/bin" -> true | _ -> false)
                | "LANG" | "HOME" | "PWD" | "TERM" | "SHLVL" | "init" | "rootmnt" | "drop_caps" -> true
                | _ -> false)
        try
            let manager = environment.Run "/usr/bin/systemctl" [ "show-environment" ] None
            let exe = path "/proc/1/exe"
            let pid1 = environment.Run "/usr/bin/sha256sum" [ "--"; exe ] None
            File.ReadAllText(path "/etc/debian_version").Trim() = "13.8"
            && pid1.ExitCode = 0 && pid1.Stderr = ""
            && pid1.Stdout.TrimEnd('\n') = "799fd89964a716fb5f26c4506047190b6e842ac2745b473bd45351c4d8cbd929  " + exe
            && ordinaryEnvironment '\000' (File.ReadAllText(path "/proc/1/environ"))
            && manager.ExitCode = 0 && manager.Stderr = "" && ordinaryEnvironment '\n' manager.Stdout
            && managerConfigurationMatches environment
            && [ "/etc"; "/run"; "/usr/local/lib"; "/usr/lib" ]
               |> List.forall (fun p -> directory p "system-generators" && directory p "system-environment-generators")
        with _ -> false


    // A missing unit has no merged ExecStartPre in PID 1. Ask systemd's own
    // offline loader whether this exact drop-in slot would contribute a
    // mandatory command once a service fragment exists. Never load or start
    // a substitute docker.service in the live manager.
    let internal coldHookEffective (environment: HostEnvironment) (path: string) (body: byte[]) =
        try
            let paths = environment.Run "/usr/bin/busctl"
                            [ "--system"; "--json=short"; "get-property"; "org.freedesktop.systemd1"
                              "/org/freedesktop/systemd1"; "org.freedesktop.systemd1.Manager"; "UnitPath" ] None
            if paths.ExitCode <> 0 || paths.Stderr <> "" then false
            else
                use reply = JsonDocument.Parse(paths.Stdout)
                let root = reply.RootElement
                let lookup = root.GetProperty("data").EnumerateArray() |> Seq.map _.GetString() |> Seq.toArray
                let ownerDir = Path.GetDirectoryName(Path.GetDirectoryName path)
                let validDir (d: string) =
                    Path.IsPathFullyQualified d && Path.GetFullPath(d) = d && not (d.Contains ':') && not (d |> Seq.exists Char.IsControl)
                let missingFragment d =
                    try File.GetAttributes(Path.Combine(d, "docker.service")) |> ignore; false
                    with :? FileNotFoundException | :? DirectoryNotFoundException -> true
                if root.GetProperty("type").GetString() <> "as" || not (Array.forall validDir lookup)
                   || (lookup |> Array.filter ((=) ownerDir)).Length <> 1
                   || not (Array.forall missingFragment lookup) then false
                else
                    let stage = Directory.CreateTempSubdirectory("dorothy-unit-proof-")
                    try
                        let fragment = stage.CreateSubdirectory("fragment")
                        let shadow = stage.CreateSubdirectory("slot")
                        let empty = stage.CreateSubdirectory("no-generators")
                        let main = Path.Combine(fragment.FullName, "docker.service")
                        File.WriteAllText(main, "[Service]\nType=notify\nExecStart=/usr/bin/false\n")
                        // Preserve PID 1's priority order, including .control
                        // and generator output. Only the owned basename is
                        // shadowed, immediately ahead of its real directory.
                        let dirs = lookup |> Array.collect (fun d -> if d = ownerDir then [| shadow.FullName; d |] else [| d |])
                        let probe = Path.Combine(shadow.CreateSubdirectory("docker.service.d").FullName, Path.GetFileName path)
                        File.WriteAllBytes(probe, body)
                        let argv =
                            [ "-i"; "LC_ALL=C"; "PATH=/usr/sbin:/usr/bin:/sbin:/bin"
                              "SYSTEMD_UNIT_PATH=" + String.concat ":" dirs
                              "SYSTEMD_ENVIRONMENT_GENERATOR_PATH=" + empty.FullName; "SYSTEMD_GENERATOR_PATH=" + empty.FullName
                              "/usr/bin/systemd-analyze"; "--system"; "--man=no"; "--generators=no"; "--recursive-errors=no"; "verify"; main ]
                        let verify () = environment.Run "/usr/bin/env" argv None
                        let clean = verify ()
                        if clean.ExitCode <> 0 || clean.Stdout <> "" || clean.Stderr <> "" then false
                        else
                            // Success alone also happens when a later drop-in
                            // reset the command list. Only this *required*,
                            // private, absent executable may cause the second
                            // verification to fail. No target command runs.
                            let witness = Path.Combine(stage.FullName, "must-not-exist")
                            File.AppendAllText(probe, "ExecStartPre=" + witness + "\n")
                            let error = "docker.service: Command " + witness + " is not executable: No such file or directory"
                            let observed = verify ()
                            observed.ExitCode = 1 && observed.Stdout = "" && (observed.Stderr = error || observed.Stderr = error + "\n")
                    finally
                        stage.Delete(true)
        with _ -> false

    let private hookReceipt hash = "# Dorothy docker.service per-start SHA-256: " + hash

    let internal handleWithExecutable (executable: string) (environment: HostEnvironment) (request: JsonElement) : JsonNode =

        let operation = text request "operation"
        if not ([ "read"; "apply"; "delete" ] |> List.contains operation) then fail "Unsupported service operation."
        let name = unitName (text request "name")
        let managed = request.GetProperty("managed").GetBoolean()
        let suppliedConfiguration = text request "configuration"
        let fences, configuration, hook =
            match request.TryGetProperty "dockerFence" with
            | true, value ->
                if not managed || suppliedConfiguration <> "" then fail "Invalid typed Docker firewall gate."
                let fences = FirewalldGateModel.decodeService name (JsonNode.Parse(value.GetRawText()))
                let commands = FirewalldDockerGate.startCommands executable fences

                let body = Encoding.UTF8.GetBytes(FirewalldDockerGate.renderStartHook name commands)
                let hash = Security.Cryptography.SHA256.HashData(body) |> Convert.ToHexString |> _.ToLowerInvariant()
                let unit = FirewalldDockerGate.renderUnit commands + hookReceipt hash + "\n"
                let path = HostEnvironment.path environment ("/etc/systemd/system/docker.service.d/90-dorothy-" + name + ".conf")
                Some fences, unit, Some(path, body, hash, commands)
            | _ -> None, suppliedConfiguration, None
        if not managed && configuration <> "" then fail "Package units cannot have a managed configuration."
        let path = HostEnvironment.path environment ("/etc/systemd/system/" + name)
        if managed then Content.ensureSafePath path
        let lockPath = HostEnvironment.path environment "/run/lock/keroosha-iac-services.lock"
        Directory.CreateDirectory(Path.GetDirectoryName lockPath) |> ignore
        use held = HostFiles.lockFile lockPath
        let invoke arguments = environment.Run "/usr/bin/systemctl" arguments None
        let run arguments =
            if (invoke arguments).ExitCode <> 0 then fail "A systemd service operation failed."
        let verifyGate = function
            | [] -> FirewalldDockerGate.verifyReadiness environment
            | policies -> FirewalldDockerGate.verify environment policies
        let mutable coldBootstrap = false
        let hookLoaded () =
            coldBootstrap <- false
            match hook with
            | None -> true
            | Some(p, body, _, commands) ->
                // systemctl omits an empty command list, even with --all,
                // and emits a separate ExecStartPre property for each command.
                let parseProperties (output: string) =
                    let mutable load = None
                    let mutable reload = None
                    let hooks = ResizeArray<string>()
                    let mutable valid = not (isNull output)
                    if valid then
                        for line in output.TrimEnd('\n').Split('\n') do
                            if line.StartsWith("LoadState=", StringComparison.Ordinal) && load.IsNone then
                                load <- Some(line.Substring("LoadState=".Length))
                            elif line = "NeedDaemonReload=no" && reload.IsNone then reload <- Some false
                            elif line = "NeedDaemonReload=yes" && reload.IsNone then reload <- Some true
                            elif line.StartsWith("ExecStartPre=", StringComparison.Ordinal) then
                                if line.Length > "ExecStartPre=".Length then hooks.Add line
                            else valid <- false
                    match valid, load, reload with
                    | true, Some state, Some stale -> Some(state, stale, hooks)
                    | _ -> None
                let invalidObservation () =
                    if operation = "apply" && fences = Some [] then
                        fail "Cannot safely classify Docker's native systemd state before publishing its bootstrap admission gate."
                    false
                let queried =
                    try Some(invoke [ "show"; "--property=LoadState,ExecStartPre,NeedDaemonReload"; "--"; "docker.service" ])
                    with _ -> None
                match queried with
                | None -> invalidObservation ()
                | Some r ->
                    match parseProperties r.Stdout with
                    | None -> invalidObservation ()
                    | Some(state, stale, hooks) ->
                        match state with
                        | "not-found" when not stale && hooks.Count = 0 && (r.ExitCode = 0 || r.ExitCode = 4) && r.Stderr = "" ->
                            coldBootstrap <- true
                            let supported = fences = Some [] && coldGeneratorProfile environment
                            if operation = "apply" && fences = Some [] && not supported then
                                fail "Cannot establish the supported Debian cold-install generator profile; refusing before Docker package installation. This is an observed refusal, not recovery proof: restore the qualified manager policy and perform an ordinary controlled boot before retrying; daemon-reload does not re-establish the boot-time manager state."
                            supported && coldHookEffective environment p body
                        | "loaded" when r.ExitCode = 0 && r.Stderr = "" ->
                            let packageKnown =
                                if fences <> Some [] then true
                                else
                                    try
                                        let result = environment.Run "/usr/bin/dpkg-query" [ "--show"; "--showformat=${Status}\\n"; "docker.io" ] None
                                        result.ExitCode = 0 && result.Stderr = "" &&
                                        match result.Stdout.Split(' ') with
                                        | [| ("install" | "hold" | "deinstall" | "purge"); "ok"; "installed\n" |] -> true
                                        | _ -> false
                                    with _ -> false
                            if not packageKnown then invalidObservation ()
                            else
                                not stale && commands |> List.forall (fun c ->
                                    let wanted = "path=" + executable + " ; argv[]=" + c + " ; ignore_errors=no ;"
                                    hooks |> Seq.exists (fun h -> h.Contains(wanted, StringComparison.Ordinal)))
                        | _ -> invalidObservation ()

        let hookOnDisk =
            match hook with
            | None -> true
            | Some(p, _, wanted, _) ->
                Content.ensureSafePath p
                let dir = Path.GetDirectoryName p
                let requireSafe logical =
                    let r = environment.Run "/usr/bin/stat" [ "-c"; "%u:%g"; "--"; logical ] None
                    if r.ExitCode <> 0 || r.Stdout.Trim() <> "0:0" || (int (File.GetUnixFileMode logical) &&& 0o022) <> 0 then
                        fail "The Docker start hook must be root-owned and not group/world-writable."
                if Directory.Exists dir then requireSafe dir
                let receipts =
                    if not (File.Exists path) then [||]
                    else
                        requireSafe path
                        let lines = File.ReadAllLines path
                        let alreadyOwned = lines |> Array.exists (fun line -> line.StartsWith(hookReceipt "", StringComparison.Ordinal))
                        let legacyGuard = fences <> Some [] && (lines |> Array.exists (fun line ->
                            line = "Description=Dorothy strict firewalld Docker start gate"
                            || line = "Description=Dorothy strict Firewalld readiness gate for Docker"))
                        if not (alreadyOwned || legacyGuard) then fail "A foreign unit occupies the declared Docker admission gate."
                        lines
                if Directory.Exists p then fail "A directory occupies the Docker start hook."
                if not (File.Exists p) then false
                else
                    requireSafe p
                    let actual = Content.hashFile p
                    // Check the old gate's exact content receipt before changing
                    // or deleting an existing drop-in. Never take over a sibling.
                    let claimed = receipts |> Array.contains (hookReceipt actual)
                    // Recovery after publishing a new hook but before its unit.
                    let staged = actual = wanted && (receipts |> Array.exists (fun line -> line.StartsWith(hookReceipt "", StringComparison.Ordinal)))
                    if not (claimed || staged) then fail "Unowned or independently changed Docker start hook; refusing to replace or delete it."
                    actual = wanted && int (File.GetUnixFileMode p) = 0o644
        let observed () =
            let result = invoke [ "show"; "--property=LoadState,ActiveState,UnitFileState"; "--"; name ]
            if result.ExitCode <> 0 then fail "Unable to inspect systemd service state."
            result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            |> Array.map (fun line ->
                let parts = line.Split('=', 2)
                if parts.Length <> 2 then fail "Invalid systemd service state response."
                parts[0], parts[1])
            |> Map.ofArray
        let initial = observed ()
        let loaded state = Map.tryFind "LoadState" state <> Some "not-found"
        let active state = Map.tryFind "ActiveState" state = Some "active"
        let enabled state = Map.tryFind "UnitFileState" state = Some "enabled"
        if operation = "apply" then
            // Check the new gate now. Restarting an already active RequiredBy unit to
            // perform the check also stops its dependent Docker service and workloads.
            // Before APT, reject an opaque/conflicting site configuration
            // without publishing files or activating our bootstrap oneshot.
            if fences = Some [] && not (hookLoaded ()) && coldBootstrap then
                fail "Cannot prove a required Docker bootstrap check in the prospective systemd configuration; refusing before package installation."
            fences |> Option.iter verifyGate
            let fileChanged = managed && (not (File.Exists path) || File.ReadAllText path <> configuration || int (File.GetUnixFileMode path) <> 0o644)
            let writeUnit () =
                if fileChanged then
                    Directory.CreateDirectory(Path.GetDirectoryName path) |> ignore
                    HostFiles.atomicWrite path (Encoding.UTF8.GetBytes configuration) (enum<UnixFileMode> 0o644)
            match hook with
            | Some(p, body, _, _) when not hookOnDisk ->
                let exists = File.Exists p
                if not exists then writeUnit ()
                Directory.CreateDirectory(Path.GetDirectoryName p) |> ignore
                HostFiles.atomicWrite p body (enum<UnixFileMode> 0o644)
                if exists then writeUnit ()
            | _ -> writeUnit ()
            if fileChanged || not hookOnDisk || not (hookLoaded ()) then
                run [ "daemon-reload" ]
                if not (hookLoaded ()) then fail "Docker's effective ExecStartPre does not include the declared firewall check."
            if fileChanged then run [ "reenable"; "--"; name ]
            elif not (enabled initial) then run [ "enable"; "--"; name ]
            let restart = request.GetProperty("restart").GetBoolean()
            if active initial && fences.IsNone && (fileChanged || restart) then run [ "restart"; "--"; name ]
            elif not (active initial || coldBootstrap) then run [ "start"; "--"; name ]
        elif operation = "delete" then
            if loaded initial then
                if fences.IsNone then run [ "stop"; "--"; name ]
                run [ "disable"; "--"; name ]
                if fences.IsSome then
                    // Detach docker.service's Requires edge before stopping the gate.
                    run [ "daemon-reload" ]
                    run [ "stop"; "--"; name ]
            match hook with
            | Some(p, _, _, _) when File.Exists p ->
                File.Delete p
                HostFiles.syncDirectory (Path.GetDirectoryName p)
                run [ "daemon-reload" ]
            | _ -> ()
            if managed && File.Exists path then
                File.Delete path
                run [ "daemon-reload" ]
        let state = if operation = "read" then initial else observed ()
        let fileMatches = not managed || (File.Exists path && File.ReadAllText path = configuration && int (File.GetUnixFileMode path) = 0o644)
        let gateMatches =
            match fences with
            | Some values when operation = "read" && fileMatches && enabled state ->
                try hookOnDisk && hookLoaded () && (verifyGate values; true)
                with :? Firewalld.BackendError -> false
            | _ -> true
        let result = JsonObject()
        result["exists"] <- JsonValue.Create(loaded state && (not managed || File.Exists path))
        let readyState = active state || (coldBootstrap && Map.tryFind "ActiveState" state = Some "inactive")
        result["inSync"] <- JsonValue.Create(fileMatches && gateMatches && readyState && enabled state)
        result["active"] <- JsonValue.Create(active state)
        result["enabled"] <- JsonValue.Create(enabled state)
        result :> JsonNode
    let handle (environment: HostEnvironment) (request: JsonElement) : JsonNode =
        handleWithExecutable Environment.ProcessPath environment request
