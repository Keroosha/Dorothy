namespace Dorothy.Tests

open System
open System.Globalization
open System.Collections.Generic
open System.IO
open System.Security.Cryptography
open System.Text
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

[<Sealed>]
type private FakeFail2BanHost() =
    let temporary = new TemporaryDirectory("dorothy-fail2ban-")
    let root = temporary.Path
    let calls = ResizeArray<string * string list>()
    let serviceEvents = ResizeArray<string * Map<string, string>>()
    let mutable serviceEnabled = false
    let mutable serviceActive = false
    let mutable serviceFailed = false
    let mutable failNextReload = false
    let mutable failNextStart = false
    let mutable failValidation = false
    let mutable runtimeDrift = false
    let mutable notReadyObservations = 0
    let mutable nativeObserveCount = 0
    let mutable runningFingerprint = ""
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

    let configFingerprint (directory: string) =
        let builder = StringBuilder()

        if Directory.Exists directory then
            Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
            |> Seq.sortWith (fun left right ->
                StringComparer.Ordinal.Compare(
                    Path.GetRelativePath(directory, left),
                    Path.GetRelativePath(directory, right)
                ))
            |> Seq.iter (fun file ->
                builder
                    .Append(Path.GetRelativePath(directory, file).Replace(Path.DirectorySeparatorChar, '/'))
                    .Append('\u0000')
                |> ignore

                try
                    builder.Append(File.ReadAllText file).Append('\u0000') |> ignore
                with
                | :? FileNotFoundException -> builder.Append("<unreadable>\u0000") |> ignore
                | :? DirectoryNotFoundException -> builder.Append("<unreadable>\u0000") |> ignore)

        SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString()))
        |> Convert.ToHexString
        |> fun value -> value.ToLowerInvariant()

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

                if
                    line.StartsWith("[", StringComparison.Ordinal)
                    && line.EndsWith("]", StringComparison.Ordinal)
                then
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

    let enabledJails (directory: string) =
        let states = Dictionary<string, bool>(StringComparer.Ordinal)
        let paths = ResizeArray<string>()

        for baseName in [ "jail.conf"; "jail.local" ] do
            let candidate = Path.Combine(directory, baseName)

            if File.Exists candidate then
                paths.Add candidate

        let jailDropins = Path.Combine(directory, "jail.d")

        if Directory.Exists jailDropins then
            Directory.EnumerateFiles(jailDropins)
            |> Seq.filter (fun file ->
                file.EndsWith(".conf", StringComparison.Ordinal)
                || file.EndsWith(".local", StringComparison.Ordinal))
            |> Seq.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right))
            |> Seq.iter paths.Add

        for file in paths do
            let mutable section = ""

            for rawLine in File.ReadAllLines file do
                let line = rawLine.Trim()

                if
                    line.StartsWith("[", StringComparison.Ordinal)
                    && line.EndsWith("]", StringComparison.Ordinal)
                then
                    section <- line.Substring(1, line.Length - 2).Trim()
                elif
                    section.Length > 0
                    && not (section.Equals("DEFAULT", StringComparison.OrdinalIgnoreCase))
                then
                    let separator = line.IndexOf('=')

                    if
                        separator > 0
                        && line.Substring(0, separator).Trim().Equals("enabled", StringComparison.OrdinalIgnoreCase)
                    then
                        let value = line.Substring(separator + 1).Trim()

                        states[section] <-
                            value.Equals("true", StringComparison.OrdinalIgnoreCase)
                            || value.Equals("yes", StringComparison.OrdinalIgnoreCase)

        states
        |> Seq.choose (fun pair -> if pair.Value then Some pair.Key else None)
        |> Seq.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right))
        |> Seq.toList

    let nativeResult (result: JsonObject) =
        let envelope = JsonObject()
        envelope["ok"] <- JsonValue.Create true
        envelope["result"] <- result

        {
            ExitCode = 0
            Stdout = envelope.ToJsonString()
            Stderr = ""
        }

    let nativeFailure () =
        {
            ExitCode = 2
            Stdout = ""
            Stderr = "native configuration diagnostic must not escape"
        }

    let handleBridge (requestText: string) =
        use request = JsonDocument.Parse requestText
        let body = request.RootElement
        let operation = body.GetProperty("operation").GetString()
        let directory = body.GetProperty("configRoot").GetString()
        let fingerprint = configFingerprint directory
        let values = daemonValues directory

        let get key fallback =
            match values.TryGetValue key with
            | true, value -> value
            | _ -> fallback

        let socket = get "Definition/socket" "/var/run/fail2ban/fail2ban.sock"
        let pidFile = get "Definition/pidfile" "/var/run/fail2ban/fail2ban.pid"

        let startupValues =
            [
                "Definition/socket", socket
                "Definition/pidfile", pidFile
                "Definition/dbfile", get "Definition/dbfile" "/var/lib/fail2ban/fail2ban.sqlite3"
                "Definition/allowipv6", get "Definition/allowipv6" "auto"
                "Definition/loglevel", get "Definition/loglevel" "INFO"
                "Definition/logtarget", get "Definition/logtarget" "STDOUT"
                "Definition/syslogsocket", get "Definition/syslogsocket" "auto"
                "Thread/stacksize", get "Thread/stacksize" "0"
            ]

        let startupText =
            startupValues
            |> List.map (fun (key, value) -> key + "=" + value)
            |> String.concat "\n"

        let startupFingerprint =
            SHA256.HashData(Encoding.UTF8.GetBytes startupText)
            |> Convert.ToHexString
            |> fun value -> value.ToLowerInvariant()

        let jails = enabledJails directory
        let result = JsonObject()

        match operation with
        | "validate" ->
            let containsInvalid =
                Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
                |> Seq.exists (fun file ->
                    try
                        File.ReadAllText(file).Contains("native-invalid", StringComparison.Ordinal)
                    with
                    | :? FileNotFoundException -> false
                    | :? DirectoryNotFoundException -> false)

            if containsInvalid then
                nativeFailure ()
            else
                result["validated"] <- JsonValue.Create true
                nativeResult result
        | "inspect" ->
            result["socket"] <- JsonValue.Create socket
            result["pidfile"] <- JsonValue.Create pidFile
            result["fingerprint"] <- JsonValue.Create fingerprint
            result["startupFingerprint"] <- JsonValue.Create startupFingerprint
            let jailArray = JsonArray()

            for jail in jails do
                jailArray.Add(JsonValue.Create jail)

            result["enabledJails"] <- jailArray
            nativeResult result
        | "observe" ->
            nativeObserveCount <- nativeObserveCount + 1
            let configuration = body.GetProperty "configuration"
            let expectedFingerprint = configuration.GetProperty("fingerprint").GetString()

            let expectedStartupFingerprint =
                configuration.GetProperty("startupFingerprint").GetString()

            result["fingerprint"] <- JsonValue.Create fingerprint
            result["startupFingerprint"] <- JsonValue.Create startupFingerprint
            let active = if serviceActive then jails else []
            let jailArray = JsonArray()

            for jail in active do
                jailArray.Add(JsonValue.Create jail)

            result["activeJails"] <- jailArray
            let stillStarting = notReadyObservations > 0

            if stillStarting then
                notReadyObservations <- notReadyObservations - 1

            result["inSync"] <-
                JsonValue.Create(
                    serviceActive
                    && not stillStarting
                    && not runtimeDrift
                    && runningFingerprint = fingerprint
                    && expectedFingerprint = fingerprint
                    && expectedStartupFingerprint = startupFingerprint
                )

            nativeResult result
        | _ -> nativeFailure ()

    let run executable arguments standardInput =
        calls.Add(executable, arguments)

        match executable, arguments with
        | "python3", [ "-c"; _ ] ->
            match standardInput with
            | Some request -> handleBridge request
            | None ->
                {
                    ExitCode = 99
                    Stdout = ""
                    Stderr = "missing bridge request"
                }
        | "/usr/sbin/sshd", [ "-T" ] ->
            {
                ExitCode = 0
                Stdout = sshdOutput
                Stderr = ""
            }
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

            {
                ExitCode = 0
                Stdout =
                    "LoadState=loaded\nUnitFileState="
                    + (if serviceEnabled then "enabled" else "disabled")
                    + "\nActiveState="
                    + activeState
                    + "\nSubState="
                    + subState
                    + "\nResult="
                    + result
                    + "\n"
                Stderr = ""
            }
        | "systemctl", [ "enable"; "fail2ban.service" ] ->
            serviceEvents.Add("enable", captureFiles ())
            serviceEnabled <- true

            {
                ExitCode = 0
                Stdout = ""
                Stderr = ""
            }
        | "systemctl", [ "disable"; "fail2ban.service" ] ->
            serviceEvents.Add("disable", captureFiles ())
            serviceEnabled <- false

            {
                ExitCode = 0
                Stdout = ""
                Stderr = ""
            }
        | "systemctl", [ "stop"; "fail2ban.service" ] ->
            serviceEvents.Add("stop", captureFiles ())
            serviceActive <- false
            serviceFailed <- false

            {
                ExitCode = 0
                Stdout = ""
                Stderr = ""
            }
        | "systemctl", [ "start"; "fail2ban.service" ] ->
            serviceEvents.Add("start", captureFiles ())

            if failNextStart then
                failNextStart <- false
                serviceActive <- false
                serviceFailed <- true

                {
                    ExitCode = 0
                    Stdout = ""
                    Stderr = ""
                }
            else
                serviceActive <- true
                serviceFailed <- false
                runningFingerprint <- configFingerprint configPath

                {
                    ExitCode = 0
                    Stdout = ""
                    Stderr = ""
                }
        | "fail2ban-client", args when List.contains "reload" args ->
            if failNextReload then
                failNextReload <- false

                {
                    ExitCode = 1
                    Stdout = ""
                    Stderr = "reload failure"
                }
            else
                runningFingerprint <- configFingerprint configPath

                {
                    ExitCode = 0
                    Stdout = "OK\n"
                    Stderr = ""
                }
        | _ ->
            {
                ExitCode = 99
                Stdout = ""
                Stderr = "unexpected fake host command"
            }

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
                    firstPath, "[first]\nenabled = true\nnative-invalid\n"
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

        Assert.That(
            host.Calls
            |> Array.exists (fun (executable, arguments) -> executable = "/usr/sbin/sshd" && arguments = [ "-T" ]),
            Is.True
        )

        host.Invoke("delete", empty) |> ignore
        Assert.That(File.Exists(host.Path("/etc/fail2ban/jail.d/99-dorothy-sshd-ports.local")), Is.False)

    [<Test>]
    member _.``Invalid staged tree fails before journal files or service changes``() =
        use host = new FakeFail2BanHost()
        let files = Map.ofList [ jailFile, "native-invalid\n" ]
        let action = TestDelegate(fun () -> host.Invoke("apply", files) |> ignore)

        Assert.Throws<Fail2Ban.BackendError>(action) |> ignore
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
