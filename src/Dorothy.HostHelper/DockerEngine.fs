namespace Dorothy.HostHelper

open System
open System.Globalization
open System.Collections.Generic
open System.Text.Json
open System.Text.Json.Nodes
open System.Text.RegularExpressions

module DockerEngine =
    type BackendError(message: string) =
        inherit Exception(message)
    let private usernamePattern = Regex("^[a-zA-Z0-9_.][a-zA-Z0-9_.-]*[$]?$", RegexOptions.CultureInvariant)

    let private validateUsername (user: string) =
        if String.IsNullOrWhiteSpace user
           || user.Length > 32
           || user.StartsWith("-", StringComparison.Ordinal)
           || not (usernamePattern.IsMatch(user)) then
            invalidArg "user" "The Docker Engine SSH user is not a valid local account name."

    let private parseRequest (request: JsonElement) =
        if request.ValueKind <> JsonValueKind.Object then
            invalidArg "request" "The Docker Engine request must be an object."

        let properties = request.EnumerateObject() |> Seq.toArray
        let names = properties |> Array.map (fun property -> property.Name) |> Set.ofArray

        if properties.Length <> 2 || names <> Set.ofList [ "operation"; "user" ] then
            invalidArg "request" "The Docker Engine request must contain only operation and user."

        let readString (name: string) =
            let value = request.GetProperty(name)
            if value.ValueKind <> JsonValueKind.String then
                invalidArg "request" ("The Docker Engine " + name + " must be a string.")
            let text = value.GetString()
            if isNull text then invalidArg "request" ("The Docker Engine " + name + " must not be null.")
            text

        let operation = readString "operation"
        let user = readString "user"
        validateUsername user
        operation, user

    let private run (environment: HostEnvironment) (executable: string) (arguments: string list) =
        let result = environment.Run executable arguments None
        if result.ExitCode <> 0 then
            let diagnostic =
                if String.IsNullOrWhiteSpace result.Stderr then result.Stdout.Trim()
                else result.Stderr.Trim()

            let safeDiagnostic =
                diagnostic
                |> Seq.map (fun character -> if Char.IsControl character then ' ' else character)
                |> Array.ofSeq
                |> fun characters -> String(characters)

            let detail =
                if String.IsNullOrWhiteSpace safeDiagnostic then
                    "exit code " + result.ExitCode.ToString(CultureInfo.InvariantCulture)
                else
                    safeDiagnostic

            raise (BackendError("Docker Engine command '" + executable + "' failed: " + detail))
        result.Stdout

    let private readServiceState (environment: HostEnvironment) =
        let output =
            run environment "systemctl" [ "show"; "--no-pager"; "--property=LoadState"; "--property=UnitFileState"; "--property=ActiveState"; "docker.service" ]

        let values = Dictionary<string, string>(StringComparer.Ordinal)

        for line in output.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries) do
            let separator = line.IndexOf('=')
            if separator <= 0 then
                raise (BackendError("Docker Engine service inspection returned malformed systemd state."))

            let name = line.Substring(0, separator)
            if name <> "LoadState" && name <> "UnitFileState" && name <> "ActiveState" then
                raise (BackendError("Docker Engine service inspection returned an unsupported systemd property."))

            if values.ContainsKey(name) then
                raise (BackendError("Docker Engine service inspection returned duplicate systemd state."))

            values.Add(name, line.Substring(separator + 1))

        if values.Count <> 3 then
            raise (BackendError("Docker Engine service inspection omitted systemd state."))

        let loadState = values["LoadState"]

        if loadState = "not-found" then
            false, false
        elif loadState = "error" then
            raise (BackendError("Docker Engine service is present but systemd could not load it."))
        elif loadState = "loaded" || loadState = "masked" then
            values["UnitFileState"] = "enabled", values["ActiveState"] = "active"
        else
            raise (BackendError("Docker Engine service inspection returned an unknown load state."))

    let private readGroupMembership (environment: HostEnvironment) (user: string) =
        if user = "root" then
            true
        else
            let groups = run environment "id" [ "-nG"; "--"; user ]
            groups.Split([| ' '; '\t'; '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
            |> Array.exists (fun group -> group = "docker")

    let private snapshotNode (environment: HostEnvironment) (user: string) =
        let serviceEnabled, serviceActive = readServiceState environment
        let dockerGroupMembership = readGroupMembership environment user
        let response = JsonObject()
        response["serviceEnabled"] <- JsonValue.Create(serviceEnabled)
        response["serviceActive"] <- JsonValue.Create(serviceActive)
        response["dockerGroupMembership"] <- JsonValue.Create(dockerGroupMembership)
        response

    let private apply (environment: HostEnvironment) (user: string) =
        run environment "systemctl" [ "unmask"; "docker.service" ] |> ignore
        run environment "systemctl" [ "enable"; "docker.service" ] |> ignore
        run environment "systemctl" [ "start"; "docker.service" ] |> ignore

        if user <> "root" && not (readGroupMembership environment user) then
            run environment "gpasswd" [ "-a"; user; "docker" ] |> ignore

        snapshotNode environment user

    let handle (environment: HostEnvironment) (request: JsonElement) : JsonNode =
        let operation, user = parseRequest request

        match operation with
        | "read" -> snapshotNode environment user :> JsonNode
        | "apply" -> apply environment user :> JsonNode
        | _ -> invalidArg "operation" "Unsupported Docker Engine operation."
