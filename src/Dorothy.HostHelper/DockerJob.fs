namespace Dorothy.HostHelper

open System
open System.Globalization
open System.IO
open System.Text.Json
open System.Text.Json.Nodes

/// A completion barrier for a Docker-provider-owned container, never a shell command runner.
module DockerJob =
    type BackendError(message: string) =
        inherit Exception(message)

    let private fail message = raise (BackendError(message))

    let private run (environment: HostEnvironment) seconds arguments =
        // Bound even daemon/API failures. Only container IDs and fixed Docker options enter argv.
        environment.Run "timeout" ([ "--signal=KILL"; string seconds + "s"; "docker" ] @ arguments) None

    let private requireSuccess result =
        // Docker errors may echo config or application data; do not forward unfiltered diagnostics.
        if result.ExitCode <> 0 then fail "Docker job command failed; daemon details withheld."
        result.Stdout

    let private inspect environment id =
        // Listing distinguishes absence from an unreachable daemon without matching error prose.
        let listed = run environment 30 [ "container"; "ls"; "--all"; "--no-trunc"; "--quiet"; "--filter"; "id=" + id ] |> requireSuccess
        if not (listed.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries) |> Array.contains id) then None
        else
            let text = run environment 30 [ "container"; "inspect"; id ] |> requireSuccess
            try
                use document = JsonDocument.Parse(text)
                if document.RootElement.GetArrayLength() <> 1 then invalidOp "Invalid inspection."
                let container = document.RootElement[0]
                if container.GetProperty("Id").GetString() <> id then invalidOp "Invalid identity."
                Some(container.Clone())
            with _ -> fail "Docker job inspection returned invalid data."

    let private status (container: JsonElement) = container.GetProperty("State").GetProperty("Status").GetString()
    let private completed (container: JsonElement) =
        status container = "exited" && container.GetProperty("State").GetProperty("ExitCode").GetInt32() = 0

    let private logTail environment id (container: JsonElement) =
        try
            let secrets =
                container.GetProperty("Config").GetProperty("Env").EnumerateArray()
                |> Seq.collect (fun entry ->
                    let value = entry.GetString()
                    let separator = value.IndexOf('=')
                    if separator < 0 then Seq.empty
                    else
                        let value = value.Substring(separator + 1)
                        seq {
                            yield value
                            // Also redact separately printed lines of multiline environment values.
                            yield! value.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
                        })
                |> Seq.filter (String.IsNullOrEmpty >> not)
                |> Seq.distinct
                |> Seq.sortByDescending String.length
                |> Seq.toArray
            let logs = run environment 10 [ "container"; "logs"; "--tail"; "50"; id ]
            if logs.ExitCode <> 0 then "[container logs unavailable]"
            else
                let mutable text = logs.Stdout + logs.Stderr
                for secret in secrets do text <- text.Replace(secret, "[redacted]", StringComparison.Ordinal)
                // Redact BEFORE truncation so a boundary cannot disclose part of a secret.
                text <- String(text |> Seq.map (fun c -> if Char.IsControl c then ' ' else c) |> Seq.toArray)
                if text.Length > 4096 then text.Substring(text.Length - 4096) else text
        with _ -> "[container logs withheld: environment redaction unavailable]"

    let private jobFailure environment id container reason =
        fail (reason + " Container log tail (environment values redacted): " + logTail environment id container)

    let private apply environment id timeoutSeconds =
        let container =
            match inspect environment id with
            | Some value -> value
            | None -> fail "Docker job container is absent; recreate its container resource."
        let restart = container.GetProperty("HostConfig").GetProperty("RestartPolicy").GetProperty("Name").GetString()
        if restart <> "no" && restart <> "" then fail "Docker jobs require the no-restart policy."
        match status container with
        | "exited" ->
            if not (completed container) then
                let exitCode = container.GetProperty("State").GetProperty("ExitCode").GetInt32()
                jobFailure environment id container (sprintf "Docker job exited with code %d." exitCode)
        | "created" | "running" ->
            if status container = "created" then
                let started = run environment 30 [ "container"; "start"; id ]
                if started.ExitCode <> 0 then jobFailure environment id container "Docker job could not start."
            // docker wait also returns immediately for a container that exited between start and wait.
            let waited = run environment timeoutSeconds [ "container"; "wait"; id ]
            if waited.ExitCode = 137 || waited.ExitCode = 124 then
                let killed = run environment 30 [ "container"; "kill"; id ]
                let reason =
                    if killed.ExitCode = 0 then "Docker job timed out; container killed."
                    else "Docker job timed out; container termination could not be confirmed."
                jobFailure environment id container reason
            if waited.ExitCode <> 0 then jobFailure environment id container "Docker job wait failed."
            let mutable exitCode = 0
            if not (Int32.TryParse(waited.Stdout.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, &exitCode)) then
                fail "Docker job wait returned an invalid exit code."
            if exitCode <> 0 then jobFailure environment id container (sprintf "Docker job exited with code %d." exitCode)
        | _ -> jobFailure environment id container "Docker job is in an unsupported state."
        match inspect environment id with
        | Some actual when completed actual -> ()
        | _ -> fail "Docker job completion could not be verified."

    let handle (environment: HostEnvironment) (request: JsonElement) : JsonNode =
        let properties = request.EnumerateObject() |> Seq.toArray
        if properties.Length <> 3 || (properties |> Array.map (fun p -> p.Name) |> Set.ofArray) <> Set.ofList [ "operation"; "containerId"; "timeoutSeconds" ] then
            invalidArg "request" "A Docker job request requires operation, containerId, and timeoutSeconds."
        let operation = request.GetProperty("operation").GetString()
        let id = request.GetProperty("containerId").GetString()
        if isNull id || id.Length <> 64 || not (id |> Seq.forall (fun c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) then
            invalidArg "containerId" "A Docker job requires a full lowercase hexadecimal container ID."
        let timeoutSeconds = request.GetProperty("timeoutSeconds").GetInt32()
        if timeoutSeconds < 1 || timeoutSeconds > 86400 then invalidArg "timeoutSeconds" "Docker job timeout must be between 1 and 86400 seconds."
        if operation <> "read" && operation <> "apply" && operation <> "delete" then invalidArg "operation" "Unsupported Docker job operation."
        // Per-container host lock prevents concurrent starts without serializing unrelated jobs.
        let directory = HostEnvironment.path environment "/run/lock"
        Directory.CreateDirectory(directory) |> ignore
        use jobLock = HostFiles.lockFile (Path.Combine(directory, "keroosha-docker-job-" + id + ".lock"))
        if operation = "apply" then apply environment id timeoutSeconds
        if operation = "delete" then
            match inspect environment id with
            // The Docker provider is the sole removal owner; its Delete stops then removes.
            // Removing here would make that later stop fail with "No such container".
            | Some container when status container = "running" ->
                run environment 30 [ "container"; "kill"; id ] |> requireSuccess |> ignore
            | _ -> ()
        let actual = inspect environment id
        let response = JsonObject()
        response["exists"] <- JsonValue.Create(actual.IsSome)
        response["completed"] <- JsonValue.Create(actual |> Option.exists completed)
        response :> JsonNode
