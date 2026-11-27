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

    let private hookReceipt hash = "# Dorothy docker.service per-start SHA-256: " + hash

    let handle (environment: HostEnvironment) (request: JsonElement) : JsonNode =
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
                let commands = FirewalldDockerGate.startCommands Environment.ProcessPath fences
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
        let hookLoaded () =
            match hook with
            | None -> true
            | Some(_, _, _, commands) ->
                let r = invoke [ "show"; "--property=LoadState,ExecStartPre,NeedDaemonReload"; "--"; "docker.service" ]
                let lines = r.Stdout.Split('\n')
                let absent = Array.contains "LoadState=not-found" lines
                if absent then fences = Some [] && (r.ExitCode = 0 || r.ExitCode = 4) && String.IsNullOrWhiteSpace r.Stderr
                else
                    r.ExitCode = 0 && String.IsNullOrWhiteSpace r.Stderr
                    && Array.contains "LoadState=loaded" lines && Array.contains "NeedDaemonReload=no" lines
                    && (commands |> List.forall (fun c -> lines |> Array.exists (fun line ->
                        line.StartsWith("ExecStartPre=", StringComparison.Ordinal)
                        && line.Contains("path=" + Environment.ProcessPath + " ; argv[]=" + c + " ; ignore_errors=no ;", StringComparison.Ordinal))))
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
            elif not (active initial) then run [ "start"; "--"; name ]
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
            | Some values when operation = "read" && fileMatches && active state && enabled state ->
                try hookOnDisk && hookLoaded () && (verifyGate values; true)
                with :? Firewalld.BackendError -> false
            | _ -> true
        let result = JsonObject()
        result["exists"] <- JsonValue.Create(loaded state && (not managed || File.Exists path))
        result["inSync"] <- JsonValue.Create(fileMatches && gateMatches && active state && enabled state)
        result["active"] <- JsonValue.Create(active state)
        result["enabled"] <- JsonValue.Create(enabled state)
        result :> JsonNode
