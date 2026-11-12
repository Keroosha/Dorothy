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

    let handle (environment: HostEnvironment) (request: JsonElement) : JsonNode =
        let operation = text request "operation"
        if not ([ "read"; "apply"; "delete" ] |> List.contains operation) then fail "Unsupported service operation."
        let name = unitName (text request "name")
        let managed = request.GetProperty("managed").GetBoolean()
        let configuration = text request "configuration"
        if not managed && configuration <> "" then fail "Package units cannot have a managed configuration."
        let path = HostEnvironment.path environment ("/etc/systemd/system/" + name)
        if managed then Content.ensureSafePath path
        let lockPath = HostEnvironment.path environment "/run/lock/keroosha-iac-services.lock"
        Directory.CreateDirectory(Path.GetDirectoryName lockPath) |> ignore
        use held = HostFiles.lockFile lockPath
        let invoke arguments = environment.Run "/usr/bin/systemctl" arguments None
        let run arguments =
            if (invoke arguments).ExitCode <> 0 then fail "A systemd service operation failed."
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
            let fileChanged = managed && (not (File.Exists path) || File.ReadAllText path <> configuration || int (File.GetUnixFileMode path) <> 0o644)
            if fileChanged then
                Directory.CreateDirectory(Path.GetDirectoryName path) |> ignore
                HostFiles.atomicWrite path (Encoding.UTF8.GetBytes configuration) (enum<UnixFileMode> 0o644)
                run [ "daemon-reload" ]
            if fileChanged then run [ "reenable"; "--"; name ]
            elif not (enabled initial) then run [ "enable"; "--"; name ]
            let restart = request.GetProperty("restart").GetBoolean()
            if active initial && (fileChanged || restart) then run [ "restart"; "--"; name ]
            elif not (active initial) then run [ "start"; "--"; name ]
        elif operation = "delete" then
            if loaded initial then
                run [ "stop"; "--"; name ]
                run [ "disable"; "--"; name ]
            if managed && File.Exists path then
                File.Delete path
                run [ "daemon-reload" ]
        let state = if operation = "read" then initial else observed ()
        let fileMatches = not managed || (File.Exists path && File.ReadAllText path = configuration && int (File.GetUnixFileMode path) = 0o644)
        let result = JsonObject()
        result["exists"] <- JsonValue.Create(loaded state && (not managed || File.Exists path))
        result["inSync"] <- JsonValue.Create(fileMatches && active state && enabled state)
        result["active"] <- JsonValue.Create(active state)
        result["enabled"] <- JsonValue.Create(enabled state)
        result :> JsonNode
