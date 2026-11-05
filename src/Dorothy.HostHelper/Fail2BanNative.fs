namespace Dorothy.HostHelper

open System
open System.Collections.Generic
open System.Globalization
open System.IO
open System.Numerics
open System.Security.Cryptography
open System.Text
open System.Text.Json
open Fail2BanCliData

module Fail2BanNative =
    type BackendError(message: string) =
        inherit InvalidOperationException(message)

    type internal DirectCheck =
        | DnsMode of string
        | Text of string
        | Boolean of bool
        | Integer of BigInteger
        | Duration of PythonLiteral
        | ActionNames of Set<string>
        | ActionProperties of Set<string>

    type internal GetterExpectation =
        {
            Arguments: string list
            DirectCheck: DirectCheck option
        }

    type internal RuntimePlan =
        {
            Getters: GetterExpectation list
        }

    type Configuration internal
        (
            socket: string,
            pidFile: string,
            fingerprint: string,
            startupFingerprint: string,
            enabledJails: string list,
            runtimePlan: RuntimePlan
        ) =
        member _.Socket = socket
        member _.PidFile = pidFile
        member _.Fingerprint = fingerprint
        member _.StartupFingerprint = startupFingerprint
        member _.EnabledJails = enabledJails
        member internal _.RuntimePlan = runtimePlan

    type private ConfigurationSeed =
        {
            Socket: string
            PidFile: string
            Fingerprint: string
            StartupFingerprint: string
            EnabledJails: string list
        }

    type internal RuntimeBaseline =
        {
            Fingerprint: string
            StartupFingerprint: string
            ObservationFingerprint: string
        }

    type Runtime =
        {
            ActiveJails: string list
            InSync: bool
        }
    type private PythonLiteral = Fail2BanCliData.PythonLiteral


    let private fail (message: string) = raise (BackendError(message))

    let private runClient
        (environment: HostEnvironment)
        (arguments: string list)
        (standardInput: string option)
        =
        try
            Some(environment.Run "fail2ban-client" arguments standardInput)
        with _ ->
            None

    let private runRuntimeClient (environment: HostEnvironment) (arguments: string list) =
        try
            let boundedArguments =
                [ "--kill-after=1s"; "5s"; "fail2ban-client" ] @ arguments

            Some(environment.Run "timeout" boundedArguments None)
        with _ ->
            None

    let private runGetterClient (environment: HostEnvironment) (arguments: string list) =
        runRuntimeClient environment ([ "-v"; "-v"; "-v" ] @ arguments)

    let private mappedPath (environment: HostEnvironment) (logicalPath: string) =
        try
            HostEnvironment.path environment logicalPath
        with _ ->
            fail "The native Fail2Ban path is invalid."


    let private hashJson (write: Utf8JsonWriter -> unit) =
        use stream = new MemoryStream()
        use writer = new Utf8JsonWriter(stream)
        write writer
        writer.Flush()
        SHA256.HashData(stream.GetBuffer().AsSpan(0, int stream.Length))
        |> Convert.ToHexString
        |> fun value -> value.ToLowerInvariant()

    let private pythonActionSources (root: string) =
        let directory = Path.Combine(root, "action.d")

        if not (Directory.Exists directory) then
            []
        else
            try
                Directory.EnumerateFiles directory
                |> Seq.choose (fun path ->
                    let name = Path.GetFileName path

                    if name.EndsWith(".py", StringComparison.Ordinal) && File.Exists path then
                        use source = File.OpenRead path
                        let digest =
                            SHA256.HashData source
                            |> Convert.ToHexString
                            |> fun value -> value.ToLowerInvariant()

                        Some(name, digest)
                    else
                        None)
                |> Seq.sortWith (fun (left, _) (right, _) -> StringComparer.Ordinal.Compare(left, right))
                |> Seq.toList
            with _ ->
                fail "The native Fail2Ban Python action sources could not be read."

    let private startupKeys =
        set [ "thread"; "syslogsocket"; "loglevel"; "logtarget"; "allowipv6"; "dbfile" ]

    let private isStartupCommand command =
        match commandFields command with
        | Some fields when indexedString fields 0 = Some "set" ->
            match indexedString fields 1, indexedString fields 2 with
            | Some key, _ when fields.Length = 3 && Set.contains key startupKeys -> true
            | Some "thread", Some "stacksize" when fields.Length >= 4 -> true
            | _ -> false
        | _ -> false

    let private createConfiguration root socket pidFile commands =
        let normalizedCommands = commands |> List.map (normalizeLiteral root)
        let sources = pythonActionSources root

        let fingerprint =
            hashJson (fun writer ->
                writer.WriteStartObject()
                writer.WriteString("socket", normalizeRoot root socket)
                writer.WriteString("pidFile", normalizeRoot root pidFile)
                writer.WritePropertyName("commands")
                writer.WriteStartArray()

                for command in normalizedCommands do
                    writeLiteral writer command

                writer.WriteEndArray()
                writer.WritePropertyName("pythonActionSources")
                writer.WriteStartArray()

                for name, digest in sources do
                    writer.WriteStartArray()
                    writer.WriteStringValue name
                    writer.WriteStringValue digest
                    writer.WriteEndArray()

                writer.WriteEndArray()
                writer.WriteEndObject())

        let startupCommands =
            commands
            |> List.filter isStartupCommand
            |> List.map (normalizeLiteral root)

        let startupFingerprint =
            hashJson (fun writer ->
                writer.WriteStartObject()
                writer.WriteString("socket", normalizeRoot root socket)
                writer.WriteString("pidFile", normalizeRoot root pidFile)
                writer.WritePropertyName("commands")
                writer.WriteStartArray()

                for command in startupCommands do
                    writeLiteral writer command

                writer.WriteEndArray()
                writer.WriteEndObject())

        let enabledJails =
            commands
            |> List.choose (fun command ->
                match commandFields command with
                | Some fields when indexedString fields 0 = Some "start" -> indexedString fields 1
                | _ -> None)
            |> List.distinct
            |> List.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right))

        {
            Socket = socket
            PidFile = pidFile
            Fingerprint = fingerprint
            StartupFingerprint = startupFingerprint
            EnabledJails = enabledJails
        }

    let private numericValue literal =
        let asNumber = function
            | (PyInteger _ | PyFloat _ | PyNone) as number -> Some number
            | PyBoolean value -> Some(PyInteger(if value then BigInteger.One else BigInteger.Zero))
            | _ -> None

        match literal with
        | PyString text -> tryParseResponse text |> Option.bind asNumber
        | value -> asNumber value

    let private numericEqual left right =
        let integerEqualsFloat integer number =
            Double.IsFinite number
            && Math.Truncate number = number
            && BigInteger(number) = integer

        match left, right with
        | PyInteger left, PyInteger right -> left = right
        | PyFloat left, PyFloat right -> not (Double.IsNaN left || Double.IsNaN right) && left = right
        | PyInteger integer, PyFloat number
        | PyFloat number, PyInteger integer -> integerEqualsFloat integer number
        | PyNone, PyNone -> true
        | _ -> false

    let private numericMarker = function
        | PyInteger value -> value.ToString(CultureInfo.InvariantCulture)
        | PyFloat value when Double.IsFinite value && Math.Truncate value = value ->
            BigInteger(value).ToString(CultureInfo.InvariantCulture)
        | PyFloat value -> value.ToString("R", CultureInfo.InvariantCulture)
        | PyNone -> "none"
        | _ -> fail "The native Fail2Ban numeric response is malformed."

    let rec private readNativeConfiguration (environment: HostEnvironment) (root: string) =
        match runClient environment [ "-v"; "-c"; root; "-d" ] None with
        | None -> fail "The native Fail2Ban configuration could not be read."
        | Some result when result.ExitCode <> 0 -> fail "The native Fail2Ban configuration could not be read."
        | Some result ->
            let socket, pidFile =
                match tryEndpointFromDiagnostics result.Stderr with
                | Some paths -> paths
                | None -> fail "The native Fail2Ban client did not report its configured socket and PID paths."
            let commands = parseDump result.Stdout
            let seed = createConfiguration root socket pidFile commands
            let plan = runtimePlan environment seed.EnabledJails commands

            let configuration =
                Configuration(
                    seed.Socket,
                    seed.PidFile,
                    seed.Fingerprint,
                    seed.StartupFingerprint,
                    seed.EnabledJails,
                    plan
                )

            configuration, commands

    and private runtimePlan (environment: HostEnvironment) (enabledJails: string list) (commands: PythonLiteral list) =
        let getters = Dictionary<string, GetterExpectation>(StringComparer.Ordinal)
        let actionNames = Dictionary<string, HashSet<string>>(StringComparer.Ordinal)
        let actionProperties = Dictionary<string * string, HashSet<string>>()
        let durationCache = Dictionary<string, PythonLiteral>(StringComparer.Ordinal)

        let keyForArguments (arguments: string list) =
            let builder = StringBuilder()

            for argument in arguments do
                builder.Append(argument.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(argument)
                |> ignore

            builder.ToString()

        let addGetter arguments directCheck =
            let key = keyForArguments arguments
            getters[key] <- { Arguments = arguments; DirectCheck = directCheck }
        let directString value = value |> valueText |> Option.map Text

        let directInteger value =
            let parsed =
                match value with
                | PyInteger number -> Some number
                | PyString text ->
                    match BigInteger.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture) with
                    | true, number -> Some number
                    | _ -> None
                | _ -> None

            parsed |> Option.map Integer

        let directBoolean value =
            let parsed =
                match value with
                | PyBoolean boolean -> Some boolean
                | PyInteger number when number.IsZero -> Some false
                | PyInteger number when number.IsOne -> Some true
                | PyString text ->
                    match text.Trim().ToLowerInvariant() with
                    | "true"
                    | "yes"
                    | "on"
                    | "1" -> Some true
                    | "false"
                    | "no"
                    | "off"
                    | "0" -> Some false
                    | _ -> None
                | _ -> None

            parsed |> Option.map Boolean
        let nativeUsedns = function
            | PyBoolean true -> "yes"
            | PyBoolean false -> "no"
            | value ->
                match valueText value with
                | Some text ->
                    match text.ToLowerInvariant() with
                    | "yes" -> "yes"
                    | "warn" -> "warn"
                    | "no" -> "no"
                    | "raw" -> "raw"
                    | _ -> "no"
                | None -> "no"

        let nativeDurationSeconds (text: string) =
            match durationCache.TryGetValue text with
            | true, seconds -> seconds
            | _ ->
                let seconds =
                    match runClient environment [ "--str2sec"; text ] None with
                    | Some result when result.ExitCode = 0 ->
                        tryParseResponse (result.Stdout.Trim()) |> Option.bind numericValue
                    | _ -> None

                match seconds with
                | Some value ->
                    durationCache.Add(text, value)
                    value
                | None -> fail "The native Fail2Ban client could not normalize a configured duration."

        let directDuration value =
            match value with
            | (PyInteger _ | PyFloat _ | PyNone) as seconds -> Some(Duration seconds)
            | PyString text -> Some(Duration(nativeDurationSeconds text))
            | _ -> None

        let globalCheck key value =
            match key with
            | "loglevel" -> directString value
            | "logtarget"
            | "syslogsocket"
            | "dbfile" -> directString value
            | "dbmaxmatches" -> directInteger value
            | "dbpurgeage" -> directDuration value
            | _ -> None

        let jailCheck key value =
            match key with
            | "maxretry"
            | "maxmatches"
            | "maxlines" -> directInteger value
            | "findtime"
            | "bantime"
            | "bantime.maxtime"
            | "bantime.rndtime" -> directDuration value
            | "usedns" -> Some(DnsMode(nativeUsedns value))
            | "ignoreself" -> directBoolean value
            | "ignorecommand" -> directString value
            | _ -> None

        let addActionName jail action =
            match actionNames.TryGetValue jail with
            | true, names -> names.Add action |> ignore
            | _ ->
                let names = HashSet<string>(StringComparer.Ordinal)
                names.Add action |> ignore
                actionNames.Add(jail, names)

        let addActionProperty jail action property value =
            let key = jail, action

            let properties =
                match actionProperties.TryGetValue key with
                | true, existing -> existing
                | _ ->
                    let created = HashSet<string>(StringComparer.Ordinal)
                    actionProperties.Add(key, created)
                    created

            properties.Add property |> ignore

            let direct = if property = "timeout" then directDuration value else None
            addGetter [ "get"; jail; "action"; action; property ] direct

        let enabled = Set.ofList enabledJails
        let mutable jailValues = Map.empty<string, Map<string, PythonLiteral>>
        let mutable globalValues = Map.empty<string, PythonLiteral>

        let recordJailValue jail key value =
            let current = jailValues |> Map.tryFind jail |> Option.defaultValue Map.empty
            jailValues <- Map.add jail (Map.add key value current) jailValues

        let handleSet fields =
            match fields with
            | [ PyString "set"; PyString key; value ] ->
                globalValues <- Map.add key value globalValues
                match key with
                | "loglevel" | "logtarget" | "syslogsocket" | "dbfile" | "dbmaxmatches" | "dbpurgeage" ->
                    addGetter [ "get"; key ] (globalCheck key value)
                | _ -> ()
            | PyString "set" :: PyString jail :: PyString "action" :: PyString action :: PyString property :: value :: _ ->
                if enabled.Contains jail then
                    addActionName jail action
                    addActionProperty jail action property value
            | PyString "set" :: PyString jail :: PyString option :: rest when rest.Length > 0 ->
                if option = "addaction" then
                    match rest |> List.tryHead |> Option.bind stringValue with
                    | Some action -> addActionName jail action
                    | None -> ()
                elif option = "addignoreip" then
                    if enabled.Contains jail then addGetter [ "get"; jail; "ignoreip" ] None
                elif option = "addlogpath" then
                    if enabled.Contains jail then addGetter [ "get"; jail; "logpath" ] None
                elif option = "addjournalmatch" then
                    if enabled.Contains jail then addGetter [ "get"; jail; "journalmatch" ] None
                elif option = "addfailregex" then
                    if enabled.Contains jail then addGetter [ "get"; jail; "failregex" ] None
                elif option = "addignoreregex" then
                    if enabled.Contains jail then addGetter [ "get"; jail; "ignoreregex" ] None
                else
                    match rest |> List.tryHead with
                    | Some value -> recordJailValue jail option value
                    | None -> ()
            | _ -> ()

        let handleMultiSet fields =
            match fields with
            | PyString "multi-set" :: PyString jail :: PyString option :: rest ->
                if option = "action" && rest.Length >= 2 then
                    match rest.[0] |> stringValue, sequenceValues rest.[1] with
                    | Some action, Some pairs when enabled.Contains jail ->
                        addActionName jail action

                        for pair in pairs do
                            match sequenceValues pair with
                            | Some [ PyString property; value ] -> addActionProperty jail action property value
                            | _ -> ()
                    | _ -> ()
                elif enabled.Contains jail && option = "addfailregex" then
                    addGetter [ "get"; jail; "failregex" ] None
                elif enabled.Contains jail && option = "addignoreregex" then
                    addGetter [ "get"; jail; "ignoreregex" ] None
                elif enabled.Contains jail && option = "addignoreip" then
                    addGetter [ "get"; jail; "ignoreip" ] None
                else
                    ()
            | _ -> ()

        for command in commands do
            match commandFields command with
            | Some fields ->
                handleSet fields
                handleMultiSet fields
            | None -> ()

        let databaseDisabled =
            globalValues
            |> Map.tryFind "dbfile"
            |> Option.exists (fun value ->
                match valueText value with
                | Some text -> text.Equals("None", StringComparison.OrdinalIgnoreCase)
                | None -> false)

        if databaseDisabled then
            getters.Remove(keyForArguments [ "get"; "dbmaxmatches" ]) |> ignore
            getters.Remove(keyForArguments [ "get"; "dbpurgeage" ]) |> ignore

        for jail in enabledJails do
            let names =
                match actionNames.TryGetValue jail with
                | true, values -> values |> Seq.toList |> Set.ofList
                | _ -> Set.empty

            addGetter [ "get"; jail; "actions" ] (Some(ActionNames names))

            for action in names do
                let key = jail, action

                let properties =
                    match actionProperties.TryGetValue key with
                    | true, values -> values |> Seq.toList |> Set.ofList
                    | _ -> Set.empty

                addGetter
                    [ "get"; jail; "actionproperties"; action ]
                    (Some(ActionProperties properties))

        for KeyValue(jail, values) in jailValues do
            if enabled.Contains jail then
                for KeyValue(key, value) in values do
                    addGetter [ "get"; jail; key ] (jailCheck key value)

        getters.Values
        |> Seq.sortWith (fun left right ->
            StringComparer.Ordinal.Compare(keyForArguments left.Arguments, keyForArguments right.Arguments))
        |> Seq.toList
        |> fun values -> { Getters = values }


    let validate (environment: HostEnvironment) (configRoot: string) =
        let root = mappedPath environment configRoot

        match runClient environment [ "-c"; root; "-t" ] None with
        | Some result when result.ExitCode = 0 -> ()
        | _ -> fail "The native Fail2Ban configuration could not be validated."

    let inspect (environment: HostEnvironment) (configRoot: string) =
        let root = mappedPath environment configRoot
        readNativeConfiguration environment root |> fst

    let private getterKey (arguments: string list) =
        let builder = StringBuilder()

        for argument in arguments do
            builder.Append(argument.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(argument)
            |> ignore

        builder.ToString()

    let private parseActiveJails (output: string) =
        let matches = ResizeArray<string>()

        for rawLine in output.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries) do
            let line = rawLine.Trim()
            let marker = "Jail list:"
            let position = line.IndexOf(marker, StringComparison.Ordinal)

            if position >= 0 then
                let rawNames = line.Substring(position + marker.Length).Trim()

                if rawNames.Length > 0 then
                    for name in rawNames.Split(',', StringSplitOptions.RemoveEmptyEntries) do
                        let normalized = name.Trim()

                        if normalized.Length = 0 then
                            fail "The native Fail2Ban status response is malformed."

                        matches.Add normalized

        if matches.Count = 0
           && not (output.Contains("Jail list:", StringComparison.Ordinal)) then
            None
        elif matches.Count <> (matches |> Seq.distinct |> Seq.length) then
            None
        else
            matches
            |> Seq.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right))
            |> Seq.toList
            |> Some

    let private booleanValue = function
        | PyBoolean value -> Some value
        | PyInteger value when value.IsOne -> Some true
        | PyInteger value when value.IsZero -> Some false
        | PyString value ->
            match value.Trim().ToLowerInvariant() with
            | "true" | "yes" | "on" | "1" -> Some true
            | "false" | "no" | "off" | "0" -> Some false
            | _ -> None
        | _ -> None

    let private namesValue literal =
        match sequenceValues literal with
        | Some values ->
            let names = values |> List.choose stringValue
            if names.Length = values.Length then Some(Set.ofList names) else None
        | None -> None

    let private directMarker (kind: string) (values: string list) =
        hashJson (fun writer ->
            writer.WriteStartArray()
            writer.WriteStringValue kind

            for value in values do
                writer.WriteStringValue value

            writer.WriteEndArray())

    let private canonicalText (arguments: string list) (value: string) =
        match arguments, value.ToLowerInvariant() with
        | [ "get"; "loglevel" ], _ -> value.ToUpperInvariant()
        | [ "get"; "dbfile" ], "none" -> "none"
        | [ "get"; "logtarget" ], ("stdout" | "stderr" | "syslog" | "sysout" | "systemd-journal") ->
            value.ToLowerInvariant()
        | [ "get"; "syslogsocket" ], "auto" -> "auto"
        | [ "get"; _; "usedns" ], dns -> dns
        | _ -> value

    let private nativeUsednsText (value: string) =
        match value.Trim().ToLowerInvariant() with
        | "yes" -> "yes"
        | "warn" -> "warn"
        | "no" -> "no"
        | "raw" -> "raw"
        | _ -> "no"

    let private directCheckObservation
        (arguments: string list)
        (expected: DirectCheck)
        (actual: PythonLiteral)
        =
        match expected with
        | Text value ->
            let wanted = canonicalText arguments value
            let matches = valueText actual |> Option.exists (fun text -> canonicalText arguments text = wanted)
            matches, directMarker "text" [ wanted ]
        | DnsMode expectedMode ->
            let actualMode =
                match actual with
                | PyBoolean value -> Some(if value then "yes" else "no")
                | value -> valueText value |> Option.map nativeUsednsText

            actualMode = Some expectedMode, directMarker "usedns" [ expectedMode ]
        | Boolean value ->
            booleanValue actual = Some value, directMarker "boolean" [ if value then "true" else "false" ]
        | Integer value ->
            let matches = numericValue actual |> Option.exists (numericEqual (PyInteger value))
            matches, directMarker "integer" [ value.ToString(CultureInfo.InvariantCulture) ]
        | Duration seconds ->
            let matches = numericValue actual |> Option.exists (numericEqual seconds)
            matches, directMarker "duration" [ numericMarker seconds ]
        | ActionNames expectedNames ->
            let actualNames = namesValue actual
            actualNames = Some expectedNames, directMarker "actions" (Set.toList expectedNames)
        | ActionProperties expectedNames ->
            let actualNames = namesValue actual
            let matches = actualNames |> Option.exists (Set.isSubset expectedNames)
            let values = actualNames |> Option.defaultValue Set.empty |> Set.toList
            matches, directMarker "action-properties" values

    let private isUnsupportedGetter (result: CommandResult) =
        result.ExitCode <> 0
        && result.ExitCode <> 124
        && result.ExitCode <> 137
        && result.Stdout.Trim().Equals("Invalid command (no get action or not yet implemented)", StringComparison.Ordinal)
        && result.Stderr.Contains("NOK:", StringComparison.Ordinal)

    let private rawGetterResponse (diagnostics: string) =
        if isNull diagnostics then
            None
        else
            let responses =
                diagnostics.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
                |> Array.choose (tryDiagnosticMessage "fail2ban" "HEAVY")
                |> Array.filter (fun message -> message.StartsWith("OK :", StringComparison.Ordinal))

            match responses with
            | [| response |] -> tryParseResponse (response.Substring(4).Trim())
            | _ -> None

    let private createObservationFingerprint (activeJails: string list) (observations: (string * string) list) =
        hashJson (fun writer ->
            writer.WriteStartObject()
            writer.WritePropertyName("activeJails")
            writer.WriteStartArray()

            for jail in activeJails do
                writer.WriteStringValue jail

            writer.WriteEndArray()
            writer.WritePropertyName("getters")
            writer.WriteStartArray()

            for key, observation in observations |> List.sortWith (fun (left, _) (right, _) -> StringComparer.Ordinal.Compare(left, right)) do
                writer.WriteStartArray()
                writer.WriteStringValue key
                writer.WriteStringValue observation
                writer.WriteEndArray()

            writer.WriteEndArray()
            writer.WriteEndObject())

    let internal observeWithBaseline
        (environment: HostEnvironment)
        (configRoot: string)
        (configuration: Configuration)
        (baseline: RuntimeBaseline option)
        =
        let root = mappedPath environment configRoot
        let statusResult = runRuntimeClient environment [ "-c"; root; "status" ]

        match statusResult with
        | None ->
            { ActiveJails = []; InSync = false }, None
        | Some status when status.ExitCode <> 0 ->
            { ActiveJails = []; InSync = false }, None
        | Some status ->
            match parseActiveJails status.Stdout with
            | None -> { ActiveJails = []; InSync = false }, None
            | Some activeJails ->
                let jailSetMatches = activeJails = configuration.EnabledJails
                let observations = ResizeArray<string * string>()
                let mutable directChecksMatch = true
                let mutable allGettersAnswered = jailSetMatches

                for getter in configuration.RuntimePlan.Getters do
                    if allGettersAnswered then
                        let key = getterKey getter.Arguments
                        let arguments = "-c" :: root :: getter.Arguments

                        match runGetterClient environment arguments with
                        | None -> allGettersAnswered <- false
                        | Some result when result.ExitCode = 0 ->
                            match rawGetterResponse result.Stderr with
                            | None -> allGettersAnswered <- false
                            | Some raw ->
                                match getter.DirectCheck with
                                | Some check ->
                                    let matches, marker =
                                        directCheckObservation getter.Arguments check raw

                                    if not matches then
                                        directChecksMatch <- false

                                    observations.Add(key, "direct:" + marker)
                                | None ->
                                    let fingerprint = hashJson (fun writer -> writeLiteral writer raw)
                                    observations.Add(key, "native:" + fingerprint)
                        | Some result when isUnsupportedGetter result ->
                            if getter.DirectCheck.IsSome then
                                directChecksMatch <- false

                            observations.Add(key, "unsupported")
                        | Some _ -> allGettersAnswered <- false

                let observationFingerprint =
                    createObservationFingerprint activeJails (List.ofSeq observations)

                let configurationMatches =
                    baseline
                    |> Option.forall (fun expected ->
                        expected.Fingerprint = configuration.Fingerprint
                        && expected.StartupFingerprint = configuration.StartupFingerprint
                        && expected.ObservationFingerprint = observationFingerprint)

                let ready =
                    jailSetMatches
                    && directChecksMatch
                    && allGettersAnswered

                let capturedBaseline =
                    if ready then
                        Some
                            {
                                Fingerprint = configuration.Fingerprint
                                StartupFingerprint = configuration.StartupFingerprint
                                ObservationFingerprint = observationFingerprint
                            }
                    else
                        None

                {
                    ActiveJails = activeJails
                    InSync = ready && configurationMatches
                }, capturedBaseline


    let reload (environment: HostEnvironment) (configuration: Configuration) =
        let configRoot = mappedPath environment "/etc/fail2ban"
        let result = runClient environment [ "-c"; configRoot; "reload"; "--restart"; "--all" ] None

        match result with
        | Some command when command.ExitCode = 0 -> ()
        | _ -> fail "The native Fail2Ban reload failed."
