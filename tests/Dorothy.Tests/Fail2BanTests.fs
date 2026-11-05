namespace Dorothy.Tests

open System
open System.Globalization
open System.Collections.Generic
open System.IO
open System.Text.Json
open System.Text.Json.Nodes
open Dorothy.DSL
open Dorothy.HostHelper
open NUnit.Framework

module private Fail2BanTestRequests =
    let json
        (operation: string)
        (owner: string)
        (files: Map<string, string>)
        (manageSshdPorts: bool)
        (sshdPorts: int list)
        =
        let request = JsonObject()
        request["operation"] <- JsonValue.Create operation
        request["ownerId"] <- JsonValue.Create owner
        let fileObject = JsonObject()

        for KeyValue(path, contents) in files do
            fileObject[path] <- JsonValue.Create contents

        request["files"] <- fileObject
        request["manageSshdPorts"] <- JsonValue.Create manageSshdPorts
        let ports = JsonArray()

        for port in sshdPorts do
            ports.Add(JsonValue.Create port)

        request["sshdPorts"] <- ports
        request.ToJsonString()

    let invoke (environment: HostEnvironment) (request: string) =
        use document = JsonDocument.Parse request
        Fail2Ban.handle environment document.RootElement

    let emptyFiles = Map.empty<string, string>
    let privateFileMode = UnixFileMode.UserRead ||| UnixFileMode.UserWrite

    let actualFile (snapshot: JsonNode) (path: string) =
        let files = snapshot["actualFiles"].AsObject()
        files[path].GetValue<string>()

    let nativeGetterTrace (payload: string) =
        " +   14 7F56DB271780 fail2ban                  HEAVY OK : " + payload

    let nativeInfoLog (message: string) =
        "2026-11-05 14:01:28,969 fail2ban                [2726]: INFO    " + message

[<Sealed>]
type private FakeFail2BanHost() =
    let temporary = new TemporaryDirectory("dorothy-fail2ban-")
    let root = temporary.Path
    let calls = ResizeArray<string * string list>()
    let rawGetterDiagnostics = ResizeArray<string>()
    let getterHumanOutputs = ResizeArray<string>()

    let serviceEvents = ResizeArray<string * Map<string, string>>()
    let mutable serviceEnabled = false
    let mutable serviceActive = false
    let mutable serviceFailed = false
    let mutable failNextReload = false
    let mutable failNextStart = false
    let mutable failValidation = false
    let mutable runtimeDrift = false
    let mutable timeoutNextGetter = false
    let mutable transportFailureNextGetter = false
    let mutable nextGetterResponse: (string list * string) option = None
    let mutable injectedDiagnosticSeen = false
    let mutable getterCallsAfterInjectedDiagnostic = 0
    let mutable runtimeDbpurgeage: string option = None
    let mutable staleMaxretryAfterReload = false
    let mutable staleMaxretryValue: string option = None
    let mutable notReadyObservations = 0
    let mutable nativeObserveCount = 0
    let mutable runtimeSettings = Map.empty<string, string>
    let mutable runtimeJails: string list = []
    let sshdOutput = "listenaddress 127.0.0.1:22\nlistenaddress [::1]:2222\n"

    let path (logicalPath: string) =
        Path.Combine(root, logicalPath.TrimStart([| '/'; '\\' |]))

    let configPath = path "/etc/fail2ban"
    let baseDaemonPath = path "/etc/fail2ban/fail2ban.conf"
    let baseJailPath = path "/etc/fail2ban/jail.conf"

    let captureFiles () =
        if not (Directory.Exists configPath) then
            Map.empty
        else
            Directory.EnumerateFiles(configPath, "*", SearchOption.AllDirectories)
            |> Seq.choose (fun file ->
                let relative =
                    Path.GetRelativePath(configPath, file).Replace(Path.DirectorySeparatorChar, '/')

                try
                    Some(relative, File.ReadAllText file)
                with
                | :? FileNotFoundException -> None
                | :? DirectoryNotFoundException -> None)
            |> Map.ofSeq

    let daemonValues (directory: string) =
        let values = Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        let orderedFiles = ResizeArray<string>()
        let baseConfig = Path.Combine(directory, "fail2ban.conf")

        if File.Exists baseConfig then
            orderedFiles.Add baseConfig

        let daemonDropins = Path.Combine(directory, "fail2ban.d")

        if Directory.Exists daemonDropins then
            Directory.EnumerateFiles(daemonDropins, "*.conf")
            |> Seq.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right))
            |> Seq.iter orderedFiles.Add

        let localConfig = Path.Combine(directory, "fail2ban.local")

        if File.Exists localConfig then
            orderedFiles.Add localConfig

        if Directory.Exists daemonDropins then
            Directory.EnumerateFiles(daemonDropins, "*.local")
            |> Seq.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right))
            |> Seq.iter orderedFiles.Add

        for file in orderedFiles do
            let mutable section = ""

            for rawLine in File.ReadAllLines file do
                let line = rawLine.Trim()

                if line.StartsWith("[", StringComparison.Ordinal) && line.EndsWith("]", StringComparison.Ordinal) then
                    section <- line.Substring(1, line.Length - 2).Trim()
                elif
                    line.Length > 0
                    && not (
                        line.StartsWith("#", StringComparison.Ordinal)
                        || line.StartsWith(";", StringComparison.Ordinal)
                    )
                then
                    let separator = line.IndexOf('=')

                    if separator > 0 then
                        let name = line.Substring(0, separator).Trim()
                        let value = line.Substring(separator + 1).Trim()
                        values[section + "/" + name] <- value

        values

    let parseSectionFiles (files: string list) =
        let sections = Dictionary<string, Dictionary<string, string>>(StringComparer.Ordinal)

        for file in files do
            if File.Exists file then
                let mutable section = ""

                for rawLine in File.ReadAllLines file do
                    let line = rawLine.Trim()

                    if line.StartsWith("[", StringComparison.Ordinal) && line.EndsWith("]", StringComparison.Ordinal) then
                        section <- line.Substring(1, line.Length - 2).Trim()
                    elif
                        line.Length > 0
                        && not (
                            line.StartsWith("#", StringComparison.Ordinal)
                            || line.StartsWith(";", StringComparison.Ordinal)
                        )
                    then
                        let separator = line.IndexOf('=')

                        if separator > 0 && section.Length > 0 then
                            let name = line.Substring(0, separator).Trim()
                            let value = line.Substring(separator + 1).Trim()

                            let values =
                                match sections.TryGetValue section with
                                | true, existing -> existing
                                | _ ->
                                    let created = Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                                    sections[section] <- created
                                    created

                            values[name] <- value

        sections

    let jailFiles (directory: string) =
        let paths = ResizeArray<string>()

        for name in [ "jail.conf"; "jail.local" ] do
            let file = Path.Combine(directory, name)

            if File.Exists file then
                paths.Add file

        let dropins = Path.Combine(directory, "jail.d")

        if Directory.Exists dropins then
            Directory.EnumerateFiles(dropins)
            |> Seq.filter (fun file ->
                file.EndsWith(".conf", StringComparison.Ordinal)
                || file.EndsWith(".local", StringComparison.Ordinal))
            |> Seq.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right))
            |> Seq.iter paths.Add

        List.ofSeq paths

    let jailValues (directory: string) =
        let sections = parseSectionFiles (jailFiles directory)
        let defaults = Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)

        match sections.TryGetValue "DEFAULT" with
        | true, values ->
            for KeyValue(name, value) in values do
                defaults[name] <- value
        | _ -> ()

        sections
        |> Seq.choose (fun pair ->
            if pair.Key.Equals("DEFAULT", StringComparison.OrdinalIgnoreCase) then
                None
            else
                let values = Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)

                for KeyValue(name, value) in defaults do
                    values[name] <- value

                for KeyValue(name, value) in pair.Value do
                    values[name] <- value

                Some(pair.Key, values))
        |> Map.ofSeq

    let enabledJails (directory: string) =
        jailValues directory
        |> Seq.choose (fun pair ->
            if pair.Key.Equals("DEFAULT", StringComparison.OrdinalIgnoreCase) then
                None
            else
                let mutable enabled = ""

                if pair.Value.TryGetValue("enabled", &enabled)
                   && (enabled.Equals("true", StringComparison.OrdinalIgnoreCase)
                       || enabled.Equals("yes", StringComparison.OrdinalIgnoreCase)) then
                    Some pair.Key
                else
                    None)
        |> Seq.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right))
        |> Seq.toList

    let filterValues (directory: string) (jail: string) =
        let settings = jailValues directory |> Map.tryFind jail

        let filterName =
            match settings with
            | Some values ->
                match values.TryGetValue "filter" with
                | true, value -> value
                | _ -> jail
            | None -> jail

        let basePath = Path.Combine(directory, "filter.d", filterName)
        let sections = parseSectionFiles [ basePath + ".conf"; basePath + ".local" ]

        match sections.TryGetValue "Definition" with
        | true, values -> values
        | _ -> Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)

    let filterLists (directory: string) (jail: string) =
        let values = filterValues directory jail
        [ "failregex"; "ignoreregex" ]
        |> List.choose (fun name ->
            match values.TryGetValue name with
            | true, value -> Some(name, [ value ])
            | _ -> None)
        |> Map.ofList

    let jailLists (directory: string) (jail: string) =
        let settings = jailValues directory |> Map.tryFind jail
        let lists = Dictionary<string, string list>(StringComparer.OrdinalIgnoreCase)

        match settings with
        | Some values ->
            for name in [ "ignoreip"; "logpath" ] do
                match values.TryGetValue name with
                | true, value ->
                    let items =
                        value.Split([| ','; ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
                        |> Array.toList

                    lists[name] <- items
                | _ -> ()
        | None -> ()

        for KeyValue(name, values) in filterLists directory jail do
            lists[name] <- values

        lists

    let actionNames (directory: string) (jail: string) =
        match jailValues directory |> Map.tryFind jail with
        | None -> []
        | Some values ->
            match values.TryGetValue "action" with
            | true, value ->
                value.Split([| ','; ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
                |> Array.toList
            | _ -> []

    let actionProperties (directory: string) (action: string) =
        let basePath = Path.Combine(directory, "action.d", action)
        let sections = parseSectionFiles [ basePath + ".conf"; basePath + ".local" ]

        match sections.TryGetValue "Definition" with
        | true, values -> values
        | _ -> Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)

    let pythonString (value: string) =
        "'"
        + value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("'", "\\'", StringComparison.Ordinal)
            .Replace("\r", "\\r", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal)
            .Replace("\t", "\\t", StringComparison.Ordinal)
        + "'"

    let pythonValue (value: string) =
        let mutable number = 0

        if Int32.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, &number) then
            string number
        elif value.Equals("true", StringComparison.OrdinalIgnoreCase) then
            "True"
        elif value.Equals("false", StringComparison.OrdinalIgnoreCase) then
            "False"
        else
            pythonString value

    let pythonCommand (values: string list) =
        values |> List.map pythonValue |> String.concat ", " |> fun body -> "[" + body + "]"

    let pythonStringList (values: string list) =
        values |> List.map pythonString |> String.concat ", " |> fun body -> "[" + body + "]"

    let nativeSettings (directory: string) =
        let daemon = daemonValues directory

        let getDaemon name fallback =
            match daemon.TryGetValue("Definition/" + name) with
            | true, value -> value
            | _ -> fallback

        let globalValues =
            [
                "syslogsocket", getDaemon "syslogsocket" "auto"
                "loglevel", getDaemon "loglevel" "INFO"
                "logtarget", getDaemon "logtarget" "STDOUT"
                "allowipv6", getDaemon "allowipv6" "auto"
                "dbfile", getDaemon "dbfile" "/var/lib/fail2ban/fail2ban.sqlite3"
                "dbmaxmatches", getDaemon "dbmaxmatches" "10"
                "dbpurgeage", getDaemon "dbpurgeage" "1d"
            ]

        let globals = globalValues |> List.map (fun (name, value) -> "global/" + name, value) |> Map.ofList

        let globals =
            match daemon.TryGetValue "Thread/stacksize" with
            | true, value -> Map.add "global/thread.stacksize" value globals
            | _ -> globals

        let defaults =
            [
                "backend", "auto"
                "maxretry", "5"
                "maxmatches", "5"
                "maxlines", "1"
                "findtime", "10m"
                "bantime", "10m"
                "usedns", "warn"
                "ignoreself", "true"
                "ignorecommand", ""
                "logencoding", "auto"
            ]

        enabledJails directory
        |> List.fold (fun settings jail ->
            let explicit = jailValues directory |> Map.find jail

            defaults
            |> List.fold (fun state (name, fallback) ->
                let mutable value = ""
                let actual = if explicit.TryGetValue(name, &value) then value else fallback
                Map.add (jail + "/" + name) actual state) settings) globals

    let nativeDump (directory: string) =
        let settings = nativeSettings directory
        let lines = ResizeArray<string>()

        for name in [ "syslogsocket"; "loglevel"; "logtarget"; "allowipv6"; "dbfile"; "dbmaxmatches"; "dbpurgeage" ] do
            if name = "loglevel" then
                lines.Add("['set', 'loglevel', " + pythonString settings["global/loglevel"] + "]")
            else
                lines.Add(pythonCommand [ "set"; name; settings["global/" + name] ])

        match settings.TryFind "global/thread.stacksize" with
        | Some value -> lines.Add(pythonCommand [ "set"; "thread"; "stacksize"; value ])
        | None -> ()

        for jail in enabledJails directory do
            lines.Add(pythonCommand [ "add"; jail; settings[jail + "/backend"] ])

            for option in
                [
                    "maxretry"; "maxmatches"; "maxlines"; "findtime"; "bantime"; "usedns"
                    "ignoreself"; "ignorecommand"; "logencoding"
                ] do
                lines.Add(pythonCommand [ "set"; jail; option; settings[jail + "/" + option] ])

            for KeyValue(option, values) in jailLists directory jail do
                match option with
                | "failregex" ->
                    lines.Add(
                        "['multi-set', "
                        + pythonString jail
                        + ", 'addfailregex', "
                        + pythonStringList values
                        + "]"
                    )
                | "ignoreregex" ->
                    lines.Add(
                        "['multi-set', "
                        + pythonString jail
                        + ", 'addignoreregex', "
                        + pythonStringList values
                        + "]"
                    )
                | "ignoreip" ->
                    for value in values do
                        lines.Add(pythonCommand [ "set"; jail; "addignoreip"; value ])
                | "logpath" ->
                    for value in values do
                        lines.Add(pythonCommand [ "set"; jail; "addlogpath"; value ])
                | _ -> ()

            for action in actionNames directory jail do
                lines.Add(pythonCommand [ "set"; jail; "addaction"; action ])

                let properties = actionProperties directory action

                if properties.Count > 0 then
                    let pairs =
                        properties
                        |> Seq.map (fun pair -> "[" + pythonString pair.Key + ", " + pythonString pair.Value + "]")
                        |> String.concat ", "

                    lines.Add(
                        "['multi-set', "
                        + pythonString jail
                        + ", 'action', "
                        + pythonString action
                        + ", ["
                        + pairs
                        + "]]"
                    )

            lines.Add(pythonCommand [ "start"; jail ])

        String.concat "\n" lines + "\n"



    let durationSeconds =
        Map.ofList
            [
                "-1", "-1"
                "0", "0"
                "1d", "86400"
                "10m", "600"
                "1.5s", "1.5"
                "1.75s", "1.75"
                "0.00000000000000000000000000001s", "1e-29"
            ]

    let seconds (value: string) = Map.tryFind value durationSeconds

    let pythonFloat (value: string) =
        let number = Double.Parse(value, NumberStyles.Float, CultureInfo.InvariantCulture)
        let representation = number.ToString("R", CultureInfo.InvariantCulture).ToLowerInvariant()

        if representation.Contains(".", StringComparison.Ordinal)
           || representation.Contains("e", StringComparison.Ordinal) then
            representation
        else
            representation + ".0"

    let nativeSuccess stdout stderr =
        {
            ExitCode = 0
            Stdout = stdout
            Stderr = stderr
        }

    let nativeFailure exitCode stdout stderr =
        {
            ExitCode = exitCode
            Stdout = stdout
            Stderr = stderr
        }

    let nativeGetterResult payload stdout =
        let trace = Fail2BanTestRequests.nativeGetterTrace payload
        rawGetterDiagnostics.Add trace
        getterHumanOutputs.Add stdout

        let beautifier =
            " +   14 7F56DB271780 fail2ban.beautifier HEAVY Beautify 'fail2ban HEAVY OK : "
            + payload
            + "' ..."

        let command =
            Fail2BanTestRequests.nativeInfoLog ("CMD: get response contains fail2ban HEAVY OK : " + payload)

        nativeSuccess stdout (String.concat "\n" [ beautifier; command; trace ] + "\n")

    let scalarOutput jail option =
        let key =
            if String.IsNullOrEmpty jail then
                "global/" + option
            else
                jail + "/" + option

        let value =
            if option = "dbpurgeage" && runtimeDbpurgeage.IsSome then
                runtimeDbpurgeage
            elif option = "maxretry" && runtimeDrift then
                Some "99"
            elif option = "maxretry" && not (String.IsNullOrEmpty jail) && staleMaxretryValue.IsSome then
                let stale = staleMaxretryValue.Value
                staleMaxretryValue <- None
                Some stale
            else
                runtimeSettings.TryFind key

        match value with
        | Some actual when option = "findtime" || option = "bantime" || option = "dbpurgeage" ->
            match seconds actual with
            | Some reported ->
                let raw = pythonFloat reported

                if option = "dbpurgeage" then
                    let humanSeconds =
                        Double.Parse(reported, NumberStyles.Float, CultureInfo.InvariantCulture)
                        |> Math.Truncate
                        |> fun value -> value.ToString("0", CultureInfo.InvariantCulture)

                    nativeGetterResult
                        raw
                        ("Current database purge age is:\n`- " + humanSeconds + "seconds\n")
                else
                    nativeGetterResult raw (raw + "\n")
            | None -> nativeFailure 255 "" ("ERROR unsupported duration fixture: " + actual + "\n")
        | Some actual when option = "ignoreself" ->
            let normalized = if actual.Equals("true", StringComparison.OrdinalIgnoreCase) then "True" else "False"
            nativeGetterResult normalized (normalized + "\n")
        | Some actual when
            option = "maxretry"
            || option = "maxmatches"
            || option = "maxlines"
            || option = "dbmaxmatches"
            || option = "stacksize"
            ->
            let mutable number = 0

            if Int32.TryParse(actual, NumberStyles.Integer, CultureInfo.InvariantCulture, &number) then
                nativeGetterResult (string number) (string number + "\n")
            else
                nativeGetterResult (pythonString actual) (actual + "\n")
        | Some actual ->
            let stdout =
                match option, actual with
                | "loglevel", value -> "Current logging level is '" + value + "'\n"
                | "logtarget", value -> "Current logging target is:\n`- " + value + "\n"
                | "syslogsocket", value -> "Current syslog socket is:\n`- " + value + "\n"
                | "dbfile", "None" -> "Database currently disabled\n"
                | "dbfile", ":memory:" -> "Current database file is:\n`- :memory\n"
                | "dbfile", value -> "Current database file is:\n`- " + value + "\n"
                | _ -> actual + "\n"

            nativeGetterResult (pythonString actual) stdout
        | None ->
            nativeFailure
                255
                "Invalid command (no get action or not yet implemented)\n"
                "ERROR NOK: (no get action or not yet implemented)\n"

    let listOutput jail option values =
        let stdout =
            if List.isEmpty values then
                match option with
                | "failregex"
                | "ignoreregex" -> "No regular expression is defined\n"
                | "logpath" -> "No file is currently monitored\n"
                | "ignoreip" -> "No IP address is currently ignored\n"
                | _ -> ""
            else
                let header =
                    match option with
                    | "failregex" -> "The jail " + jail + " has the following failregexes:"
                    | "ignoreregex" -> "The jail " + jail + " has the following ignoreregexes:"
                    | "logpath" -> "Currently monitored log files:"
                    | "ignoreip" -> "Currently ignored IP addresses:"
                    | _ -> ""

                let body =
                    values
                    |> List.mapi (fun index value -> string (index + 1) + ". " + value)
                    |> String.concat "\n"

                header + "\n" + body + "\n"

        nativeGetterResult (pythonStringList values) stdout

    let handleGet (directory: string) (arguments: string list) =
        let getIndex = arguments |> List.findIndex ((=) "get")
        let query = arguments |> List.skip (getIndex + 1)

        match query with
        | [ jail; "actions" ] ->
            let names = actionNames directory jail

            let stdout =
                if List.isEmpty names then
                    "No actions for jail " + jail + "\n"
                else
                    "The jail "
                    + jail
                    + " has the following actions:\n"
                    + String.concat ", " names
                    + "\n"

            nativeGetterResult (pythonStringList names) stdout
        | [ jail; "actionproperties"; action ] ->
            let properties = actionProperties directory action

            let names =
                properties
                |> Seq.map (fun pair -> pair.Key)
                |> Seq.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right))
                |> Seq.toList

            let stdout =
                if List.isEmpty names then
                    "No properties for jail " + jail + " action " + action + "\n"
                else
                    "The jail " + jail + " action " + action + " has the following properties:\n"
                    + String.concat ", " names
                    + "\n"

            nativeGetterResult (pythonStringList names) stdout
        | [ _jail; "action"; action; property ] ->
            let properties = actionProperties directory action

            match properties.TryGetValue property with
            | true, value -> nativeGetterResult (pythonString value) (value + "\n")
            | _ ->
                nativeFailure
                    255
                    "Invalid command (no get action or not yet implemented)\n"
                    "ERROR NOK: (no get action or not yet implemented)\n"
        | [ jail; option ] when
            option = "failregex"
            || option = "ignoreregex"
            || option = "ignoreip"
            || option = "logpath"
            ->
            let lists = jailLists directory jail
            let values = match lists.TryGetValue option with | true, values -> values | _ -> []
            listOutput jail option values
        | [ jail; option ] -> scalarOutput jail option
        | [ "loglevel" ] -> scalarOutput "" "loglevel"
        | [ "logtarget" ] -> scalarOutput "" "logtarget"
        | [ "syslogsocket" ] -> scalarOutput "" "syslogsocket"
        | [ "dbfile" ] -> scalarOutput "" "dbfile"
        | [ "dbpurgeage" ] -> scalarOutput "" "dbpurgeage"
        | [ "allowipv6" ] ->
            nativeFailure 255 "Sorry but the command is invalid\n" "ERROR NOK ('list index out of range',)\n"

        | [ option ] -> scalarOutput "" option
        | _ ->
            nativeFailure
                255
                "Invalid command (no get action or not yet implemented)\n"
                "ERROR NOK: (no get action or not yet implemented)\n"

    let refreshRuntime directory =
        runtimeSettings <- nativeSettings directory
        runtimeJails <- enabledJails directory

    let run executable arguments _standardInput =
        let executable, arguments, timed =
            match executable, arguments with
            | "timeout", "--kill-after=1s" :: "5s" :: "fail2ban-client" :: wrappedArguments
                when List.contains "status" wrappedArguments || List.contains "get" wrappedArguments ->
                "fail2ban-client", wrappedArguments, true
            | _ -> executable, arguments, false

        calls.Add(executable, arguments)

        match executable, arguments with
        | "/usr/sbin/sshd", [ "-T" ] ->
            nativeSuccess sshdOutput ""
        | "fail2ban-client", [ "-c"; directory; "-t" ] ->
            if failValidation && directory <> configPath then
                nativeFailure
                    255
                    ""
                    "2026-11-05 14:03:08,094 fail2ban                [3010]: ERROR   Failed during configuration: Bad value substitution: option 'maxretry' in section 'dorothy-bad' contains an interpolation key 'missing_retry' which is not a valid option name. Raw value: '%(missing_retry)s'\n2026-11-05 14:03:08,094 fail2ban                [3010]: ERROR   ERROR: test configuration failed\n"
            else
                nativeSuccess "OK: configuration test is successful\n" ""
        | "fail2ban-client", [ "-v"; "-c"; directory; "-d" ] ->
            let daemon = daemonValues directory

            let get name fallback =
                match daemon.TryGetValue("Definition/" + name) with
                | true, value -> value
                | _ -> fallback

            let stderr =
                [
                    Fail2BanTestRequests.nativeInfoLog
                        ("Using socket file " + get "socket" "/var/run/fail2ban/fail2ban.sock")
                    Fail2BanTestRequests.nativeInfoLog
                        ("Using pid file "
                         + get "pidfile" "/var/run/fail2ban/fail2ban.pid"
                         + ", [DEBUG] logging to "
                         + get "logtarget" "STDOUT")
                ]
                |> String.concat "\n"
                |> fun lines -> lines + "\n"

            nativeSuccess (nativeDump directory) stderr
        | "fail2ban-client", [ "--str2sec"; value ] ->
            match seconds value with
            | Some converted -> nativeSuccess (pythonFloat converted + "\n") ""
            | None -> nativeFailure 255 "" ("ERROR unsupported duration fixture: " + value + "\n")
        | "fail2ban-client", [ "-c"; directory; "status" ] when timed ->
            nativeObserveCount <- nativeObserveCount + 1

            if not serviceActive then
                let daemon = daemonValues directory

                let socket =
                    match daemon.TryGetValue "Definition/socket" with
                    | true, value -> value
                    | _ -> "/var/run/fail2ban/fail2ban.sock"

                nativeFailure 255 "" ("ERROR Failed to access socket path: " + socket + ". Is fail2ban running?\n")
            else
                let ready = notReadyObservations = 0

                if not ready then
                    notReadyObservations <- notReadyObservations - 1

                let active = if ready then runtimeJails else []

                nativeSuccess
                    ("Status\n|- Number of jail:\t"
                     + string active.Length
                     + "\n|- Jail list:\t"
                     + String.concat "," active
                     + "\n")
                    ""
        | "fail2ban-client",
          "-v" :: "-v" :: "-v" :: "-c" :: directory :: "get" :: query when timed && not (List.isEmpty query) ->
            if injectedDiagnosticSeen then
                getterCallsAfterInjectedDiagnostic <- getterCallsAfterInjectedDiagnostic + 1

            if timeoutNextGetter then
                timeoutNextGetter <- false
                nativeFailure 124 "" ""
            elif transportFailureNextGetter then
                transportFailureNextGetter <- false
                nativeFailure 1 "" "connect: Connection refused\n"
            else
                match nextGetterResponse with
                | Some(targetQuery, stderr) when query = targetQuery ->
                    nextGetterResponse <- None
                    injectedDiagnosticSeen <- true
                    let rawDiagnosticsBefore = rawGetterDiagnostics.Count
                    let response = handleGet directory arguments
                    rawGetterDiagnostics.RemoveRange(rawDiagnosticsBefore, rawGetterDiagnostics.Count - rawDiagnosticsBefore)
                    { response with Stderr = stderr }
                | _ -> handleGet directory arguments
        | "fail2ban-client", [ "-c"; _directory; "reload"; "--restart"; "--all" ] ->
            if failNextReload then
                failNextReload <- false
                nativeFailure 1 "" "reload failure\n"
            else
                let previousMaxretry = runtimeSettings.TryFind "sshd/maxretry" |> Option.defaultValue "5"
                refreshRuntime configPath

                if staleMaxretryAfterReload then
                    staleMaxretryValue <- Some previousMaxretry
                    staleMaxretryAfterReload <- false

                nativeSuccess "OK\n" ""
        | "systemctl", args when
            not (List.isEmpty args)
            && List.head args = "show"
            && List.last args = "fail2ban.service"
            ->
            let activeState =
                if serviceFailed then "failed"
                elif serviceActive then "active"
                else "inactive"

            let subState =
                if serviceFailed then "failed"
                elif serviceActive then "running"
                else "dead"

            let result = if serviceFailed then "exit-code" else "success"

            nativeSuccess
                ("LoadState=loaded\nUnitFileState="
                 + (if serviceEnabled then "enabled" else "disabled")
                 + "\nActiveState="
                 + activeState
                 + "\nSubState="
                 + subState
                 + "\nResult="
                 + result
                 + "\n")
                ""
        | "systemctl", [ "enable"; "fail2ban.service" ] ->
            serviceEvents.Add("enable", captureFiles ())
            serviceEnabled <- true
            nativeSuccess "" ""
        | "systemctl", [ "disable"; "fail2ban.service" ] ->
            serviceEvents.Add("disable", captureFiles ())
            serviceEnabled <- false
            nativeSuccess "" ""
        | "systemctl", [ "stop"; "fail2ban.service" ] ->
            serviceEvents.Add("stop", captureFiles ())
            serviceActive <- false
            serviceFailed <- false
            nativeSuccess "" ""
        | "systemctl", [ "start"; "fail2ban.service" ] ->
            serviceEvents.Add("start", captureFiles ())

            if failNextStart then
                failNextStart <- false
                serviceActive <- false
                serviceFailed <- true
                nativeSuccess "" ""
            else
                serviceActive <- true
                serviceFailed <- false
                refreshRuntime configPath
                nativeSuccess "" ""
        | _ ->
            nativeFailure 99 "" "unexpected fake host command\n"

    let environment =
        TestSupport.fakeHostEnvironment root run (fun () -> DateTimeOffset.UnixEpoch)

    let makeRequest operation files manageSshdPorts sshdPorts =
        let request =
            Fail2BanTestRequests.json
                operation
                "urn:pulumi:test::test::keroosha:debian:Fail2Ban::full"
                files
                manageSshdPorts
                sshdPorts

        Fail2BanTestRequests.invoke environment request

    do
        for directory in
            [
                "/run/lock"
                "/etc/fail2ban/fail2ban.d"
                "/etc/fail2ban/jail.d"
                "/etc/fail2ban/action.d"
                "/etc/fail2ban/filter.d"
                "/var/lib/fail2ban"
            ] do
            Directory.CreateDirectory(path directory) |> ignore

        Directory.CreateDirectory(path "/var/lib") |> ignore
        Directory.CreateDirectory(path "/etc") |> ignore

        File.WriteAllText(
            baseDaemonPath,
            "[Definition]\nsocket = /var/run/fail2ban/fail2ban.sock\npidfile = /var/run/fail2ban/fail2ban.pid\ndbfile = /var/lib/fail2ban/fail2ban.sqlite3\n[Thread]\nstacksize = 0\n"
        )

        File.WriteAllText(baseJailPath, "[DEFAULT]\nenabled = false\n")

    member _.Environment = environment
    member _.Calls = calls.ToArray()
    member _.RawGetterDiagnostics = rawGetterDiagnostics.ToArray()
    member _.GetterHumanOutputs = getterHumanOutputs.ToArray()
    member _.GetterCallsAfterInjectedDiagnostic = getterCallsAfterInjectedDiagnostic



    member _.ServiceEvents = serviceEvents.ToArray()
    member _.Path(logicalPath: string) = path logicalPath

    member _.FailNextReload
        with get () = failNextReload
        and set value = failNextReload <- value

    member _.FailNextStart
        with get () = failNextStart
        and set value = failNextStart <- value

    member _.FailValidation
        with get () = failValidation
        and set value = failValidation <- value

    member _.RuntimeDrift
        with get () = runtimeDrift
        and set value = runtimeDrift <- value

    member _.TimeoutNextGetter
        with get () = timeoutNextGetter
        and set value = timeoutNextGetter <- value

    member _.TransportFailureNextGetter
        with get () = transportFailureNextGetter
        and set value = transportFailureNextGetter <- value

    member _.NextGetterResponse
        with get () = nextGetterResponse
        and set value = nextGetterResponse <- value

    member _.RuntimeDbpurgeage
        with get () = runtimeDbpurgeage
        and set value = runtimeDbpurgeage <- value


    member _.StaleMaxretryAfterReload
        with get () = staleMaxretryAfterReload
        and set value = staleMaxretryAfterReload <- value

    member _.NotReadyObservations
        with get () = notReadyObservations
        and set value = notReadyObservations <- value

    member _.NativeObserveCount = nativeObserveCount
    member _.ServiceActive = serviceActive
    member _.ServiceEnabled = serviceEnabled
    member _.Invoke(operation: string, files: Map<string, string>) = makeRequest operation files false []

    member _.InvokeWithPorts
        (operation: string, files: Map<string, string>, manageSshdPorts: bool, sshdPorts: int list)
        =
        makeRequest operation files manageSshdPorts sshdPorts

    interface IDisposable with
        member _.Dispose() = (temporary :> IDisposable).Dispose()
[<TestFixture>]
type Fail2BanTests() =
    let empty = Fail2BanTestRequests.emptyFiles

    let readOnlyFiles =
        Map.ofList [ "operator/untouched.local", "[operator]\nvalue = keep\n" ]

    let jailFile = "jail.d/90-dorothy.local"
    let actionFile = "action.d/custom.local"
    let filterFile = "filter.d/custom.local"
    let daemonFile = "fail2ban.d/90-dorothy.local"

    let statePath (host: FakeFail2BanHost) =
        host.Path "/var/lib/keroosha-iac/fail2ban/configuration.json"

    [<Test>]
    member _.``Generic file maps preserve exact native text and isolate owned snapshot``() =
        use host = new FakeFail2BanHost()
        let operatorPath = host.Path "/etc/fail2ban/operator/untouched.local"
        Directory.CreateDirectory(Path.GetDirectoryName operatorPath) |> ignore
        File.WriteAllText(operatorPath, readOnlyFiles["operator/untouched.local"])
        let databasePath = host.Path "/var/lib/fail2ban/existing.sqlite3"
        File.WriteAllText(databasePath, "existing ban database")

        let files =
            Map.ofList
                [
                    jailFile, "[custom]\nenabled = true\nfilter = custom\naction = custom\nbantime = -1\n"
                    filterFile,
                    "[INCLUDES]\nbefore = common.conf\n[Definition]\nfailregex = ^custom 100%% <HOST>$\nignoreregex = ^ignore me$\n"
                    actionFile,
                    "[Definition]\nactionstart = printf '%s' '<ip>'\nactionstop = true\nactioncheck = true\nactionban = printf '%s' '<ip>'\nactionunban = true\n"
                ]

        let snapshot = host.Invoke("apply", files)

        Assert.That(snapshot["owned"].GetValue<bool>(), Is.True)
        Assert.That(snapshot["active"].GetValue<bool>(), Is.True)
        Assert.That(snapshot["inSync"].GetValue<bool>(), Is.True)
        Assert.That(Fail2BanTestRequests.actualFile snapshot jailFile, Is.EqualTo(files[jailFile]))
        Assert.That(Fail2BanTestRequests.actualFile snapshot filterFile, Is.EqualTo(files[filterFile]))
        Assert.That(Fail2BanTestRequests.actualFile snapshot actionFile, Is.EqualTo(files[actionFile]))
        Assert.That(snapshot.AsObject().Count, Is.EqualTo(6))
        Assert.That(snapshot["actualFiles"].AsObject().Count, Is.EqualTo(3))
        Assert.That(snapshot["activeJails"].ToJsonString(), Is.EqualTo("[\"custom\"]"))
        Assert.That(snapshot["socket"].GetValue<string>(), Is.EqualTo("/var/run/fail2ban/fail2ban.sock"))
        Assert.That(File.ReadAllText(operatorPath), Is.EqualTo(readOnlyFiles["operator/untouched.local"]))
        Assert.That(File.ReadAllText(databasePath), Is.EqualTo("existing ban database"))

        Assert.That(
            File.GetUnixFileMode(host.Path("/etc/fail2ban/" + actionFile)),
            Is.EqualTo(Fail2BanTestRequests.privateFileMode)
        )

        Assert.That(File.GetUnixFileMode(statePath host), Is.EqualTo(Fail2BanTestRequests.privateFileMode))

        let readBack = host.Invoke("read", files)
        Assert.That(readBack["inSync"].GetValue<bool>(), Is.True)
        Assert.That(Fail2BanTestRequests.actualFile readBack filterFile, Is.EqualTo(files[filterFile]))

        Assert.That(
            host.Calls
            |> Array.exists (fun (executable, arguments) -> executable = "systemctl" && List.contains "stop" arguments),
            Is.False
        )



    [<Test>]
    member _.``Native action getters preserve multiple actions and empty action lists``() =
        use host = new FakeFail2BanHost()
        let files =
            Map.ofList
                [
                    jailFile,
                    "[sshd]\nenabled = true\naction = custom, empty\n[noaction]\nenabled = true\naction =\n"
                    actionFile, "[Definition]\nactionban = logger <ip>\n"
                ]

        let snapshot = host.Invoke("apply", files)
        Assert.That(snapshot["inSync"].GetValue<bool>(), Is.True)
        Assert.That(
            host.RawGetterDiagnostics,
            Does.Contain(Fail2BanTestRequests.nativeGetterTrace "['custom', 'empty']")
        )
        Assert.That(host.RawGetterDiagnostics, Does.Contain(Fail2BanTestRequests.nativeGetterTrace "['actionban']"))
        Assert.That(host.RawGetterDiagnostics, Does.Contain(Fail2BanTestRequests.nativeGetterTrace "[]"))

    [<Test>]
    member _.``Apply waits for native configuration convergence after service start``() =
        use host = new FakeFail2BanHost()
        host.NotReadyObservations <- 2
        let files = Map.ofList [ jailFile, "[sshd]\nenabled = true\n" ]
        let snapshot = host.Invoke("apply", files)

        Assert.That(snapshot["inSync"].GetValue<bool>(), Is.True)
        Assert.That(host.NativeObserveCount, Is.EqualTo(3))
        Assert.That(host.ServiceActive, Is.True)
        let beforeReload = host.NativeObserveCount
        host.NotReadyObservations <- 2
        let updatedFiles = Map.add jailFile "[sshd]\nenabled = true\nmaxretry = 7\n" files
        let updated = host.Invoke("apply", updatedFiles)
        Assert.That(updated["inSync"].GetValue<bool>(), Is.True)
        Assert.That(host.NativeObserveCount, Is.EqualTo(beforeReload + 3))

    [<Test>]
    member _.``Fractional dbpurgeage uses exact raw seconds despite identical human output``() =
        use host = new FakeFail2BanHost()
        let files = Map.ofList [ daemonFile, "[Definition]\ndbpurgeage = 1.5s\n" ]
        let applied = host.Invoke("apply", files)
        let humanOutput = "Current database purge age is:\n`- 1seconds\n"
        let conversionCount () =
            host.Calls
            |> Array.filter (fun (executable, arguments) ->
                executable = "fail2ban-client" && arguments = [ "--str2sec"; "1.5s" ])
            |> Array.length

        Assert.That(applied["inSync"].GetValue<bool>(), Is.True)
        Assert.That(host.RawGetterDiagnostics, Does.Contain(Fail2BanTestRequests.nativeGetterTrace "1.5"))
        Assert.That(host.GetterHumanOutputs, Does.Contain(humanOutput))

        let journalBefore = File.ReadAllText(statePath host)
        host.RuntimeDbpurgeage <- Some "1.75s"
        let conversionsBeforeRead = conversionCount ()

        let drift = host.Invoke("read", files)

        Assert.That(drift["inSync"].GetValue<bool>(), Is.False)
        Assert.That(host.RawGetterDiagnostics, Does.Contain(Fail2BanTestRequests.nativeGetterTrace "1.75"))
        let sameHumanOutputCount = host.GetterHumanOutputs |> Array.filter ((=) humanOutput) |> Array.length
        Assert.That(conversionCount (), Is.EqualTo(conversionsBeforeRead + 1))
        Assert.That(sameHumanOutputCount, Is.GreaterThanOrEqualTo(2))
        Assert.That(File.ReadAllText(statePath host), Is.EqualTo(journalBefore))

    [<Test>]
    member _.``Binary64 subnormal-scale durations remain distinct from zero``() =
        use host = new FakeFail2BanHost()
        let files =
            Map.ofList
                [ daemonFile, "[Definition]\ndbpurgeage = 0.00000000000000000000000000001s\n" ]

        let applied = host.Invoke("apply", files)
        Assert.That(applied["inSync"].GetValue<bool>(), Is.True)
        Assert.That(host.RawGetterDiagnostics, Does.Contain(Fail2BanTestRequests.nativeGetterTrace "1e-29"))

        host.RuntimeDbpurgeage <- Some "0"
        let drift = host.Invoke("read", files)

        Assert.That(drift["inSync"].GetValue<bool>(), Is.False)
        Assert.That(host.RawGetterDiagnostics, Does.Contain(Fail2BanTestRequests.nativeGetterTrace "0.0"))

    [<Test>]
    member _.``Numeric loglevel remains a Python string in raw diagnostics``() =
        use host = new FakeFail2BanHost()
        let files = Map.ofList [ daemonFile, "[Definition]\nloglevel = 5\n" ]
        let snapshot = host.Invoke("apply", files)

        Assert.That(snapshot["inSync"].GetValue<bool>(), Is.True)
        Assert.That(host.RawGetterDiagnostics, Does.Contain(Fail2BanTestRequests.nativeGetterTrace "'5'"))

    [<Test>]
    member _.``Marker-like response data in Beautifier and CMD logs is not parsed as the response``() =
        use host = new FakeFail2BanHost()
        let logtarget = "/var/log/fail2ban HEAVY OK : embedded.log"
        let files = Map.ofList [ daemonFile, "[Definition]\nlogtarget = " + logtarget + "\n" ]
        let snapshot = host.Invoke("apply", files)

        Assert.That(snapshot["inSync"].GetValue<bool>(), Is.True)
        Assert.That(
            host.RawGetterDiagnostics,
            Does.Contain(Fail2BanTestRequests.nativeGetterTrace ("'" + logtarget + "'"))
        )

    [<Test>]
    member _.``Missing empty duplicate and malformed raw success diagnostics fail closed``() =
        let rawInfo = Fail2BanTestRequests.nativeGetterTrace "'INFO'"

        let cases =
            [
                "missing", ""
                "empty", Fail2BanTestRequests.nativeGetterTrace "" + "\n"
                "duplicate", String.concat "\n" [ rawInfo; rawInfo ] + "\n"
                "malformed", Fail2BanTestRequests.nativeGetterTrace "not-a-python-literal" + "\n"
            ]

        for _caseName, diagnostics in cases do
            use host = new FakeFail2BanHost()
            let files = Map.ofList [ jailFile, "[sshd]\nenabled = true\nmaxretry = 5\n" ]
            host.Invoke("apply", files) |> ignore
            let journalBefore = File.ReadAllText(statePath host)
            host.NextGetterResponse <- Some([ "loglevel" ], diagnostics)
            let snapshot = host.Invoke("read", files)

            Assert.That(snapshot["inSync"].GetValue<bool>(), Is.False)
            Assert.That(host.GetterCallsAfterInjectedDiagnostic, Is.Zero)
            Assert.That(
                host.GetterHumanOutputs,
                Does.Contain("Current logging level is 'INFO'\n")
            )
            Assert.That(File.ReadAllText(statePath host), Is.EqualTo(journalBefore))


    [<Test>]
    member _.``Runtime drift is reported by read without rebaselining or reloading``() =
        use host = new FakeFail2BanHost()
        let files = Map.ofList [ jailFile, "[sshd]\nenabled = true\nmaxretry = 7\n" ]
        host.Invoke("apply", files) |> ignore
        let journalBefore = File.ReadAllText(statePath host)

        let reloadCount () =
            host.Calls
            |> Array.filter (fun (executable, arguments) ->
                executable = "fail2ban-client" && List.contains "reload" arguments)
            |> Array.length

        let reloadsBefore = reloadCount ()
        let serviceEventsBefore = host.ServiceEvents.Length
        host.RuntimeDrift <- true

        let first = host.Invoke("read", files)
        let second = host.Invoke("read", files)

        Assert.That(first["inSync"].GetValue<bool>(), Is.False)
        Assert.That(second["inSync"].GetValue<bool>(), Is.False)
        Assert.That(File.ReadAllText(statePath host), Is.EqualTo(journalBefore))
        Assert.That(host.ServiceEvents.Length, Is.EqualTo(serviceEventsBefore))
        Assert.That(reloadCount (), Is.EqualTo(reloadsBefore))

    [<Test>]
    member _.``Stale scalar after successful reload delays readiness until direct getters converge``() =
        use host = new FakeFail2BanHost()
        let firstFiles = Map.ofList [ jailFile, "[sshd]\nenabled = true\nmaxretry = 5\n" ]
        host.Invoke("apply", firstFiles) |> ignore
        let observationsBefore = host.NativeObserveCount

        let reloadCount () =
            host.Calls
            |> Array.filter (fun (executable, arguments) ->
                executable = "fail2ban-client" && List.contains "reload" arguments)
            |> Array.length

        let reloadsBefore = reloadCount ()
        host.StaleMaxretryAfterReload <- true
        let targetFiles = Map.add jailFile "[sshd]\nenabled = true\nmaxretry = 7\n" firstFiles
        let updated = host.Invoke("apply", targetFiles)

        Assert.That(updated["inSync"].GetValue<bool>(), Is.True)
        Assert.That(host.NativeObserveCount, Is.GreaterThanOrEqualTo(observationsBefore + 3))
        Assert.That(reloadCount (), Is.EqualTo(reloadsBefore + 1))

    [<Test>]
    member _.``Getter timeout and transport failures stop later native probes``() =
        for failure in [ "timeout"; "transport" ] do
            use host = new FakeFail2BanHost()
            let files = Map.ofList [ jailFile, "[sshd]\nenabled = true\nmaxretry = 7\n" ]
            host.Invoke("apply", files) |> ignore
            let journalBefore = File.ReadAllText(statePath host)

            let getterCount () =
                host.Calls
                |> Array.filter (fun (executable, arguments) ->
                    executable = "fail2ban-client" && List.contains "get" arguments)
                |> Array.length

            let gettersBefore = getterCount ()

            if failure = "timeout" then
                host.TimeoutNextGetter <- true
            else
                host.TransportFailureNextGetter <- true

            let snapshot = host.Invoke("read", files)

            Assert.That(snapshot["inSync"].GetValue<bool>(), Is.False)
            Assert.That(getterCount (), Is.EqualTo(gettersBefore + 1))
            Assert.That(File.ReadAllText(statePath host), Is.EqualTo(journalBefore))
    [<Test>]
    member _.``Apply updates and removes only journaled paths while delete preserves unrelated files``() =
        use host = new FakeFail2BanHost()
        let foreignPath = host.Path "/etc/fail2ban/jail.d/10-operator.local"
        let foreignText = "[operator]\nenabled = true\n"
        File.WriteAllText(foreignPath, foreignText)

        let first =
            Map.ofList
                [
                    jailFile, "[sshd]\nenabled = false\n"
                    filterFile, "[Definition]\nfailregex = ^old$\n"
                ]

        host.Invoke("apply", first) |> ignore

        let second =
            Map.ofList
                [
                    jailFile, "[sshd]\nenabled = true\n"
                    actionFile, "[Definition]\nactionban = logger <ip>\n"
                ]

        let updated = host.Invoke("apply", second)

        Assert.That(updated["inSync"].GetValue<bool>(), Is.True)
        Assert.That(File.Exists(host.Path("/etc/fail2ban/" + filterFile)), Is.False)
        Assert.That(File.ReadAllText(host.Path("/etc/fail2ban/" + jailFile)), Is.EqualTo(second[jailFile]))
        Assert.That(File.ReadAllText foreignPath, Is.EqualTo(foreignText))
        Assert.That(host.Invoke("delete", empty).AsObject().Count, Is.EqualTo(0))
        Assert.That(File.Exists(host.Path("/etc/fail2ban/" + jailFile)), Is.False)
        Assert.That(File.Exists(host.Path("/etc/fail2ban/" + actionFile)), Is.False)
        Assert.That(File.ReadAllText foreignPath, Is.EqualTo(foreignText))
        Assert.That(File.Exists(statePath host), Is.False)
        Assert.That(host.ServiceActive, Is.True)

    [<Test>]
    member _.``Partial multi-file reload failure restores exact prior files and service state``() =
        use host = new FakeFail2BanHost()

        let first =
            Map.ofList
                [
                    jailFile, "[sshd]\nenabled = false\n"
                    filterFile, "[Definition]\nfailregex = ^old$\n"
                ]

        host.Invoke("apply", first) |> ignore
        host.FailNextReload <- true

        let changed =
            Map.ofList
                [
                    jailFile, "[sshd]\nenabled = true\n"
                    filterFile, "[Definition]\nfailregex = ^new$\n"
                    actionFile, "[Definition]\nactionban = logger <ip>\n"
                ]

        let action = TestDelegate(fun () -> host.Invoke("apply", changed) |> ignore)

        Assert.Throws<Fail2Ban.BackendError>(action) |> ignore
        Assert.That(File.ReadAllText(host.Path("/etc/fail2ban/" + jailFile)), Is.EqualTo(first[jailFile]))
        Assert.That(File.ReadAllText(host.Path("/etc/fail2ban/" + filterFile)), Is.EqualTo(first[filterFile]))
        Assert.That(File.Exists(host.Path("/etc/fail2ban/" + actionFile)), Is.False)
        Assert.That(host.ServiceActive, Is.True)
        let readBack = host.Invoke("read", first)
        Assert.That(readBack["inSync"].GetValue<bool>(), Is.True)

        let reloads =
            host.Calls
            |> Array.filter (fun (executable, arguments) ->
                executable = "fail2ban-client" && List.contains "reload" arguments)

        Assert.That(reloads.Length, Is.EqualTo(2))

    [<Test>]
    member _.``Startup socket pid database and thread changes stop old service before file switch and roll back``() =
        use host = new FakeFail2BanHost()

        let initial =
            Map.ofList
                [
                    daemonFile,
                    "[Definition]\nsocket = /run/fail2ban/old.sock\npidfile = /run/fail2ban/old.pid\ndbfile = /var/lib/fail2ban/old.sqlite3\n[Thread]\nstacksize = 64\n"
                    jailFile, "[custom]\nenabled = true\n"
                ]

        host.Invoke("apply", initial) |> ignore
        let databasePath = host.Path "/var/lib/fail2ban/old.sqlite3"
        File.WriteAllText(databasePath, "do not migrate or delete")
        host.FailNextStart <- true

        let target =
            Map.add
                daemonFile
                "[Definition]\nsocket = /run/fail2ban/new.sock\npidfile = /run/fail2ban/new.pid\ndbfile = /var/lib/fail2ban/new.sqlite3\n[Thread]\nstacksize = 128\n"
                initial

        let action = TestDelegate(fun () -> host.Invoke("apply", target) |> ignore)

        Assert.Throws<Fail2Ban.BackendError>(action) |> ignore

        let serviceStops =
            host.ServiceEvents |> Array.filter (fun (name, _) -> name = "stop")

        Assert.That(serviceStops.Length, Is.EqualTo(1))
        Assert.That(serviceStops.[0] |> snd |> Map.find daemonFile, Is.EqualTo(initial[daemonFile]))
        let starts = host.ServiceEvents |> Array.filter (fun (name, _) -> name = "start")
        Assert.That(starts.Length, Is.EqualTo(3))
        Assert.That((snd starts.[1])[daemonFile], Is.EqualTo(target[daemonFile]))
        Assert.That((snd starts.[2])[daemonFile], Is.EqualTo(initial[daemonFile]))
        Assert.That(File.ReadAllText(host.Path("/etc/fail2ban/" + daemonFile)), Is.EqualTo(initial[daemonFile]))
        Assert.That(File.ReadAllText(databasePath), Is.EqualTo("do not migrate or delete"))
        let readBack = host.Invoke("read", initial)
        Assert.That(readBack["socket"].GetValue<string>(), Is.EqualTo("/run/fail2ban/old.sock"))
        Assert.That(host.ServiceActive, Is.True)

    [<Test>]
    member _.``Staged validation follows configuration symlinks into the candidate tree``() =
        use host = new FakeFail2BanHost()
        let targetPath = "operator/daemon.local"
        let physicalTarget = host.Path("/etc/fail2ban/" + targetPath)
        Directory.CreateDirectory(Path.GetDirectoryName physicalTarget) |> ignore

        let initial =
            Map.ofList
                [
                    targetPath,
                    "[Definition]\nsocket = /var/run/fail2ban/fail2ban.sock\npidfile = /var/run/fail2ban/fail2ban.pid\ndbfile = /var/lib/fail2ban/fail2ban.sqlite3\n[Thread]\nstacksize = 0\n"
                ]

        let firstSnapshot = host.Invoke("apply", initial)
        Assert.That(firstSnapshot["socket"].GetValue<string>(), Is.EqualTo("/var/run/fail2ban/fail2ban.sock"))

        File.CreateSymbolicLink(host.Path("/etc/fail2ban/fail2ban.local"), physicalTarget)
        |> ignore

        let linkedSnapshot = host.Invoke("apply", initial)
        Assert.That(linkedSnapshot["inSync"].GetValue<bool>(), Is.True)

        let updatedFiles =
            Map.add
                targetPath
                "[Definition]\nsocket = /run/fail2ban/new.sock\npidfile = /run/fail2ban/new.pid\ndbfile = /var/lib/fail2ban/new.sqlite3\n[Thread]\nstacksize = 128\n"
                initial

        let updated = host.Invoke("apply", updatedFiles)

        Assert.That(updated["socket"].GetValue<string>(), Is.EqualTo("/run/fail2ban/new.sock"))
        Assert.That(updated["inSync"].GetValue<bool>(), Is.True)
        Assert.That(File.Exists(host.Path("/etc/fail2ban/fail2ban.local")), Is.True)

    [<Test>]
    member _.``Custom Python action source changes cause a real service restart``() =
        use host = new FakeFail2BanHost()
        let pythonPath = "action.d/custom.py"

        let first =
            Map.ofList [ pythonPath, "class Action:\n    def start(self):\n        pass\n" ]

        host.Invoke("apply", first) |> ignore

        let reloadCount =
            host.Calls
            |> Array.filter (fun (executable, arguments) ->
                executable = "fail2ban-client" && List.contains "reload" arguments)
            |> Array.length

        let second =
            Map.add pythonPath "class Action:\n    def start(self):\n        self.changed = True\n" first

        let updated = host.Invoke("apply", second)
        Assert.That(updated["inSync"].GetValue<bool>(), Is.True)

        let events = host.ServiceEvents |> Array.map fst
        Assert.That(events |> Array.filter ((=) "stop") |> Array.length, Is.EqualTo(1))
        Assert.That(events |> Array.filter ((=) "start") |> Array.length, Is.EqualTo(2))

        let reloadCountAfter =
            host.Calls
            |> Array.filter (fun (executable, arguments) ->
                executable = "fail2ban-client" && List.contains "reload" arguments)
            |> Array.length

        Assert.That(reloadCountAfter, Is.EqualTo(reloadCount))
        Assert.That(File.ReadAllText(host.Path("/etc/fail2ban/" + pythonPath)), Is.EqualTo(second[pythonPath]))

    [<Test>]
    member _.``Read leaves interrupted multi-file ownership journal untouched and delete recovers it``() =
        use host = new FakeFail2BanHost()
        let firstPath = "jail.d/10-first.local"
        let secondPath = "jail.d/20-second.local"

        let firstFiles =
            Map.ofList
                [
                    firstPath, "[first]\nenabled = false\n"
                    secondPath, "[second]\nenabled = false\n"
                ]

        host.Invoke("apply", firstFiles) |> ignore

        let targetFiles =
            Map.ofList
                [
                    firstPath, "[first]\nenabled = true\n"
                    secondPath, "[second]\nenabled = true\n"
                ]

        File.WriteAllText(host.Path("/etc/fail2ban/" + firstPath), targetFiles[firstPath])
        let journal = JsonObject()
        journal["version"] <- JsonValue.Create 2
        journal["ownerId"] <- JsonValue.Create "urn:pulumi:test::test::keroosha:debian:Fail2Ban::full"
        let priorNode = JsonObject()

        for KeyValue(path, text) in firstFiles do
            priorNode[path] <- JsonValue.Create text

        journal["files"] <- priorNode
        let pending = JsonObject()
        pending["operation"] <- JsonValue.Create "apply"
        pending["priorOwned"] <- JsonValue.Create true
        pending["priorActive"] <- JsonValue.Create true
        pending["priorEnabled"] <- JsonValue.Create true
        pending["startupChanged"] <- JsonValue.Create false
        pending["pythonChanged"] <- JsonValue.Create false
        let targetNode = JsonObject()

        for KeyValue(path, text) in targetFiles do
            targetNode[path] <- JsonValue.Create text

        pending["targetFiles"] <- targetNode
        let mutations = JsonArray()

        for path in [ firstPath; secondPath ] do
            let mutation = JsonObject()
            mutation["path"] <- JsonValue.Create path
            mutation["prior"] <- JsonValue.Create firstFiles[path]
            mutation["target"] <- JsonValue.Create targetFiles[path]
            mutations.Add mutation

        pending["mutations"] <- mutations
        journal["pending"] <- pending
        let rawJournal = journal.ToJsonString() + "\n"
        Directory.CreateDirectory(Path.GetDirectoryName(statePath host)) |> ignore
        File.WriteAllText(statePath host, rawJournal)
        File.SetUnixFileMode(statePath host, Fail2BanTestRequests.privateFileMode)

        host.FailValidation <- true
        let read = host.Invoke("read", firstFiles)
        Assert.That(read["owned"].GetValue<bool>(), Is.True)
        Assert.That(read["inSync"].GetValue<bool>(), Is.False)
        Assert.That(Fail2BanTestRequests.actualFile read firstPath, Is.EqualTo(targetFiles[firstPath]))
        Assert.That(Fail2BanTestRequests.actualFile read secondPath, Is.EqualTo(firstFiles[secondPath]))
        Assert.That(File.ReadAllText(statePath host), Is.EqualTo(rawJournal))
        Assert.That(host.ServiceEvents |> Array.exists (fun (name, _) -> name = "stop"), Is.False)
        host.FailValidation <- false

        host.Invoke("delete", empty) |> ignore
        Assert.That(File.Exists(host.Path("/etc/fail2ban/" + firstPath)), Is.False)
        Assert.That(File.Exists(host.Path("/etc/fail2ban/" + secondPath)), Is.False)
        Assert.That(File.Exists(statePath host), Is.False)
        Assert.That(host.ServiceActive, Is.True)

    [<Test>]
    member _.``Legacy v2 journal reads without a baseline and migrates only after explicit apply``() =
        use host = new FakeFail2BanHost()
        let files = Map.ofList [ jailFile, "[sshd]\nenabled = true\nmaxretry = 5\n" ]
        host.Invoke("apply", files) |> ignore
        let owned = JsonObject()

        for KeyValue(path, text) in files do
            owned[path] <- JsonValue.Create text

        let rawV2 =
            "{\"version\":2,\"ownerId\":"
            + JsonValue.Create("urn:pulumi:test::test::keroosha:debian:Fail2Ban::full").ToJsonString()
            + ",\"files\":"
            + owned.ToJsonString()
            + ",\"pending\":null}\n"

        File.WriteAllText(statePath host, rawV2)
        File.SetUnixFileMode(statePath host, Fail2BanTestRequests.privateFileMode)

        let reloadCount () =
            host.Calls
            |> Array.filter (fun (executable, arguments) ->
                executable = "fail2ban-client" && List.contains "reload" arguments)
            |> Array.length

        let reloadsBeforeRead = reloadCount ()
        let legacyRead = host.Invoke("read", files)
        Assert.That(legacyRead["owned"].GetValue<bool>(), Is.True)
        Assert.That(legacyRead["inSync"].GetValue<bool>(), Is.False)
        Assert.That(File.ReadAllText(statePath host), Is.EqualTo(rawV2))
        Assert.That(reloadCount (), Is.EqualTo(reloadsBeforeRead))
        Assert.That(host.ServiceActive, Is.True)

        let applied = host.Invoke("apply", files)
        Assert.That(applied["inSync"].GetValue<bool>(), Is.True)
        Assert.That(reloadCount (), Is.GreaterThan reloadsBeforeRead)

        let migrated = JsonNode.Parse(File.ReadAllText(statePath host))
        Assert.That(migrated["version"].GetValue<int>(), Is.EqualTo(3))
        Assert.That(migrated["runtimeBaseline"], Is.Not.Null)

        for name in [ "fingerprint"; "startupFingerprint"; "observationFingerprint" ] do
            Assert.That((migrated["runtimeBaseline"][name]).GetValue<string>(), Is.Not.Empty)

        let migratedJournal = File.ReadAllText(statePath host)
        let readBack = host.Invoke("read", files)
        Assert.That(readBack["inSync"].GetValue<bool>(), Is.True)
        Assert.That(File.ReadAllText(statePath host), Is.EqualTo(migratedJournal))

    [<Test>]
    member _.``Legacy pending v2 read stays unbaselined until apply rolls back and migrates``() =
        use host = new FakeFail2BanHost()
        let path = "jail.d/40-legacy.local"
        let priorFiles = Map.ofList [ path, "[sshd]\nenabled = true\nmaxretry = 5\n" ]
        let targetFiles = Map.add path "[sshd]\nenabled = true\nmaxretry = 7\n" priorFiles
        host.Invoke("apply", priorFiles) |> ignore
        File.WriteAllText(host.Path("/etc/fail2ban/" + path), targetFiles[path])

        let journal = JsonObject()
        journal["version"] <- JsonValue.Create 2
        journal["ownerId"] <- JsonValue.Create "urn:pulumi:test::test::keroosha:debian:Fail2Ban::full"
        let priorNode = JsonObject()
        let targetNode = JsonObject()

        for KeyValue(filePath, text) in priorFiles do
            priorNode[filePath] <- JsonValue.Create text

        for KeyValue(filePath, text) in targetFiles do
            targetNode[filePath] <- JsonValue.Create text

        journal["files"] <- priorNode
        let pending = JsonObject()
        pending["operation"] <- JsonValue.Create "apply"
        pending["priorOwned"] <- JsonValue.Create true
        pending["priorActive"] <- JsonValue.Create true
        pending["priorEnabled"] <- JsonValue.Create true
        pending["startupChanged"] <- JsonValue.Create false
        pending["pythonChanged"] <- JsonValue.Create false
        pending["targetFiles"] <- targetNode
        let mutations = JsonArray()
        let mutation = JsonObject()
        mutation["path"] <- JsonValue.Create path
        mutation["prior"] <- JsonValue.Create priorFiles[path]
        mutation["target"] <- JsonValue.Create targetFiles[path]
        mutations.Add mutation
        pending["mutations"] <- mutations
        journal["pending"] <- pending
        let rawPendingJournal = journal.ToJsonString() + "\n"
        File.WriteAllText(statePath host, rawPendingJournal)
        File.SetUnixFileMode(statePath host, Fail2BanTestRequests.privateFileMode)

        let pendingRead = host.Invoke("read", priorFiles)
        Assert.That(pendingRead["inSync"].GetValue<bool>(), Is.False)
        Assert.That(File.ReadAllText(statePath host), Is.EqualTo(rawPendingJournal))
        Assert.That(File.ReadAllText(host.Path("/etc/fail2ban/" + path)), Is.EqualTo(targetFiles[path]))

        let recovered = host.Invoke("apply", priorFiles)
        Assert.That(recovered["inSync"].GetValue<bool>(), Is.True)
        Assert.That(File.ReadAllText(host.Path("/etc/fail2ban/" + path)), Is.EqualTo(priorFiles[path]))

        let migrated = JsonNode.Parse(File.ReadAllText(statePath host))
        Assert.That(migrated["version"].GetValue<int>(), Is.EqualTo(3))
        Assert.That(migrated["runtimeBaseline"], Is.Not.Null)

    [<Test>]
    member _.``Foreign files and drifted owned files are never taken over or deleted``() =
        use foreignHost = new FakeFail2BanHost()
        let foreignPath = foreignHost.Path("/etc/fail2ban/" + jailFile)
        let foreign = "[operator]\nenabled = true\n"
        File.WriteAllText(foreignPath, foreign)
        let request = Map.ofList [ jailFile, "[sshd]\nenabled = true\n" ]

        Assert.Throws<Fail2Ban.BackendError>(TestDelegate(fun () -> foreignHost.Invoke("apply", request) |> ignore))
        |> ignore

        foreignHost.Invoke("delete", empty) |> ignore
        Assert.That(File.ReadAllText foreignPath, Is.EqualTo(foreign))

        use driftedHost = new FakeFail2BanHost()
        let managed = Map.ofList [ jailFile, "[sshd]\nenabled = true\n" ]
        driftedHost.Invoke("apply", managed) |> ignore
        File.WriteAllText(driftedHost.Path("/etc/fail2ban/" + jailFile), "[sshd]\nenabled = false\n")
        let snapshot = driftedHost.Invoke("read", managed)
        Assert.That(snapshot["owned"].GetValue<bool>(), Is.True)
        Assert.That(snapshot["inSync"].GetValue<bool>(), Is.False)
        Assert.That(Fail2BanTestRequests.actualFile snapshot jailFile, Is.EqualTo("[sshd]\nenabled = false\n"))

        Assert.Throws<Fail2Ban.BackendError>(TestDelegate(fun () -> driftedHost.Invoke("apply", managed) |> ignore))
        |> ignore

        Assert.Throws<Fail2Ban.BackendError>(TestDelegate(fun () -> driftedHost.Invoke("delete", empty) |> ignore))
        |> ignore

        Assert.That(
            File.ReadAllText(driftedHost.Path("/etc/fail2ban/" + jailFile)),
            Is.EqualTo("[sshd]\nenabled = false\n")
        )

    [<Test>]
    member _.``Readable permissions on owned secrets are reported and refused as drift``() =
        use host = new FakeFail2BanHost()
        let path = "action.d/custom.py"
        let files = Map.ofList [ path, "class Action:\n    pass\n" ]
        host.Invoke("apply", files) |> ignore
        let physicalPath = host.Path("/etc/fail2ban/" + path)

        let readableByOthers =
            UnixFileMode.UserRead
            ||| UnixFileMode.UserWrite
            ||| UnixFileMode.GroupRead
            ||| UnixFileMode.OtherRead

        File.SetUnixFileMode(physicalPath, readableByOthers)

        let snapshot = host.Invoke("read", files)
        Assert.That(snapshot["owned"].GetValue<bool>(), Is.True)
        Assert.That(snapshot["inSync"].GetValue<bool>(), Is.False)

        Assert.Throws<Fail2Ban.BackendError>(TestDelegate(fun () -> host.Invoke("apply", files) |> ignore))
        |> ignore

        Assert.Throws<Fail2Ban.BackendError>(TestDelegate(fun () -> host.Invoke("delete", empty) |> ignore))
        |> ignore

        Assert.That(File.GetUnixFileMode(physicalPath), Is.EqualTo(readableByOthers))

    [<Test>]
    member _.``Automatic sshd port linking owns and removes only the reserved native drop-in``() =
        use host = new FakeFail2BanHost()
        let auto = host.InvokeWithPorts("apply", empty, true, [])

        Assert.That(
            Fail2BanTestRequests.actualFile auto "jail.d/99-dorothy-sshd-ports.local",
            Is.EqualTo("# Managed by Dorothy for the linked sshd configuration.\n[sshd]\nport = 22,2222\n")
        )


        host.Invoke("delete", empty) |> ignore
        Assert.That(File.Exists(host.Path("/etc/fail2ban/jail.d/99-dorothy-sshd-ports.local")), Is.False)

    [<Test>]
    member _.``Invalid staged tree fails before journal files or service changes``() =
        use host = new FakeFail2BanHost()
        let files = Map.ofList [ jailFile, "[sshd]\nenabled = true\nmaxretry = %(missing_retry)s\n" ]
        host.FailValidation <- true
        let action = TestDelegate(fun () -> host.Invoke("apply", files) |> ignore)
        let error = Assert.Throws<Fail2Ban.BackendError>(action)
        Assert.That(error.Message, Does.Not.Contain("Bad value substitution"))
        Assert.That(error.Message, Does.Not.Contain("missing_retry"))
        Assert.That(error.Message, Does.Not.Contain("ERROR: test configuration failed"))
        Assert.That(File.Exists(host.Path("/etc/fail2ban/" + jailFile)), Is.False)
        Assert.That(File.Exists(statePath host), Is.False)
        Assert.That(host.ServiceEvents, Is.Empty)
        Assert.That(host.ServiceActive, Is.False)

[<TestFixture>]
type Fail2BanDslTests() =
    [<Test>]
    member _.``Typed scalar helpers render exact invariant native values``() =
        let originalCulture = CultureInfo.CurrentCulture

        try
            CultureInfo.CurrentCulture <- CultureInfo("fr-FR")

            let input =
                fail2ban {
                    Fail2BanSections.daemon {
                        Fail2BanDaemonOptions.loglevel (Fail2BanLogLevel.Numeric 20)
                        Fail2BanDaemonOptions.logtarget (Fail2BanLogTarget.File "/var/log/fail2ban.log")
                        Fail2BanDaemonOptions.syslogsocket Fail2BanSyslogSocket.Auto
                        Fail2BanDaemonOptions.allowipv6 Fail2BanIpv6Mode.Disabled
                        Fail2BanDaemonOptions.dbfile Fail2BanDatabase.InMemory
                        Fail2BanDaemonOptions.dbmaxmatches 20
                        Fail2BanDaemonOptions.dbpurgeage (TimeSpan.FromTicks 12_500_000L)
                    }

                    Fail2BanSections.thread {
                        Fail2BanDaemonOptions.stacksize (Fail2BanStackSize.Size 64<KiB>)
                    }

                    Fail2BanSections.defaults {
                        Fail2BanOptions.bantime (Fail2BanBanTime.Finite (TimeSpan.FromMinutes 1.))
                        Fail2BanOptions.findtime (TimeSpan.FromTicks 12_500_000L)
                        Fail2BanOptions.maxretry 5
                        Fail2BanOptions.maxmatches 10
                        Fail2BanOptions.bantimeFactor 1.5M
                        Fail2BanOptions.bantimeMultipliers [ 1; 2; 4; 8 ]
                        Fail2BanOptions.bantimeMaxtime (TimeSpan.FromTicks 25_000_000L)
                        Fail2BanOptions.bantimeRndtime (TimeSpan.FromTicks 1L)
                        Fail2BanOptions.ignorecache
                            (Fail2BanIgnoreCache.Enabled
                                {
                                    Key = "<F-USER>@<ip-host>"
                                    MaxCount = Some 100
                                    MaxTime = Some (TimeSpan.FromTicks 12_500_000L)
                                })
                    }

                    Fail2BanSections.jail "sshd" {
                        Fail2BanOptions.backend Fail2BanBackend.Systemd
                        Fail2BanOptions.usedns Fail2BanDnsMode.Raw
                    }

                    Fail2BanSections.actionInit "custom" {
                        Fail2BanActionOptions.timeout (TimeSpan.FromTicks 12_500_000L)
                        Fail2BanActionOptions.actionstartOnDemand true
                        Fail2BanActionOptions.actionrepairOnUnban false

                        Fail2BanActionOptions.families
                            (Fail2BanFamilies.Only [ Fail2BanAddressFamily.Inet4; Fail2BanAddressFamily.Inet6 ])

                        Fail2BanActionOptions.norestored true
                    }
                }

            let files = (Fail2BanConfigurationMerge.combine [ input, false ]).Files

            Assert.That(
                files["fail2ban.d/90-dorothy.local"],
                Does.Contain(
                    "[Definition]\nloglevel = 20\nlogtarget = /var/log/fail2ban.log\nsyslogsocket = auto\nallowipv6 = no\ndbfile = :memory:\ndbmaxmatches = 20\ndbpurgeage = 1.25s\n"
                )
            )

            Assert.That(
                files["fail2ban.d/90-dorothy.local"],
                Does.Contain("[Thread]\nstacksize = 64\n")
            )

            Assert.That(
                files["jail.d/90-dorothy.local"],
                Does.Contain(
                    "[DEFAULT]\nbantime = 60\nfindtime = 1.25s\nmaxretry = 5\nmaxmatches = 10\nbantime.factor = 1.5\nbantime.multipliers = 1 2 4 8\nbantime.maxtime = 2.5s\nbantime.rndtime = 0.0000001s\nignorecache = key=\"<F-USER>@<ip-host>\", max-count=100, max-time=1.25s\n"
                )
            )

            Assert.That(
                files["jail.d/90-dorothy.local"],
                Does.Contain("[sshd]\nbackend = systemd\nusedns = raw\n")
            )

            Assert.That(
                files["action.d/custom.local"],
                Does.Contain(
                    "[Init]\ntimeout = 1.25s\nactionstart_on_demand = true\nactionrepair_on_unban = false\nfamilies = inet4 inet6\nnorestored = true\n"
                )
            )
        finally
            CultureInfo.CurrentCulture <- originalCulture

    [<Test>]
    member _.``Native month durations remain available through explicit custom text``() =
        let input = fail2ban { Fail2BanOptions.custom "bantime" "1mo" }
        let files = (Fail2BanConfigurationMerge.combine [ input, false ]).Files

        Assert.That(
            files["jail.d/90-dorothy.local"],
            Is.EqualTo("[DEFAULT]\nbantime = 1mo\n")
        )

        Assert.That(
            (Fail2BanOptions.bantime Fail2BanBanTime.Permanent).Value,
            Is.EqualTo("-1")
        )

        let defaults: Fail2BanIgnoreCacheSettings =
            {
                Key = "ip"
                MaxCount = None
                MaxTime = None
            }

        Assert.That(
            (Fail2BanOptions.ignorecache (Fail2BanIgnoreCache.Enabled defaults)).Value,
            Is.EqualTo("key=\"ip\"")
        )

        Assert.That(
            (Fail2BanOptions.ignorecache Fail2BanIgnoreCache.Disabled).Value,
            Is.Empty
        )

        Assert.That(
            (Fail2BanDaemonOptions.stacksize Fail2BanStackSize.PlatformDefault).Value,
            Is.EqualTo("0")
        )

        Assert.That(
            (Fail2BanDaemonOptions.allowipv6 Fail2BanIpv6Mode.Auto).Value,
            Is.EqualTo("auto")
        )

        Assert.That(
            (Fail2BanDaemonOptions.dbfile Fail2BanDatabase.Disabled).Value,
            Is.EqualTo("None")
        )

        Assert.That(
            (Fail2BanDaemonOptions.dbfile Fail2BanDatabase.InMemory).Value,
            Is.EqualTo(":memory:")
        )

        Assert.That(
            (Fail2BanDaemonOptions.syslogsocket
                (Fail2BanSyslogSocket.Path "/run/fail2ban/log.sock"))
                .Value,
            Is.EqualTo("/run/fail2ban/log.sock")
        )

        Assert.That(
            (Fail2BanActionOptions.families Fail2BanFamilies.Default).Value,
            Is.Empty
        )

    [<Test>]
    member _.``Typed native sentinels and limits reject ambiguous or truncated values``() =
        let expectInvalid action =
            Assert.Throws<ArgumentException>(TestDelegate action) |> ignore

        expectInvalid (fun () ->
            Fail2BanOptions.bantime
                (Fail2BanBanTime.Finite (TimeSpan.FromMilliseconds 1500.))
            |> ignore)

        expectInvalid (fun () ->
            Fail2BanOptions.bantime (Fail2BanBanTime.Finite (TimeSpan.FromSeconds(-1.)))
            |> ignore)

        expectInvalid (fun () ->
            Fail2BanDaemonOptions.stacksize (Fail2BanStackSize.Size 31<KiB>)
            |> ignore)

        expectInvalid (fun () ->
            Fail2BanOptions.ignorecache
                (Fail2BanIgnoreCache.Enabled
                    {
                        Key = "ip"
                        MaxCount = None
                        MaxTime = Some (TimeSpan.FromSeconds(-1.))
                    })
            |> ignore)

        expectInvalid (fun () ->
            Fail2BanDaemonOptions.dbfile (Fail2BanDatabase.File "None")
            |> ignore)

        expectInvalid (fun () ->
            Fail2BanDaemonOptions.syslogsocket (Fail2BanSyslogSocket.Path "auto")
            |> ignore)

        expectInvalid (fun () ->
            Fail2BanDaemonOptions.logtarget (Fail2BanLogTarget.File "stdout")
            |> ignore)

        expectInvalid (fun () ->
            Fail2BanActionOptions.families (Fail2BanFamilies.Only [])
            |> ignore)

        expectInvalid (fun () ->
            Fail2BanDaemonOptions.loglevel (Fail2BanLogLevel.Numeric -1)
            |> ignore)
