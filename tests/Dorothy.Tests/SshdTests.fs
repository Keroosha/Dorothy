namespace Dorothy.Tests

open System
open System.Collections.Generic
open System.Globalization
open System.IO
open System.Security.Cryptography
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open Dorothy.HostHelper
open NUnit.Framework

[<Sealed>]
type private SshdFakeHost(root: string) =
    let calls = ResizeArray<string * string list>()
    let mutable reloadCount = 0
    let mutable startCount = 0
    let mutable timerEnabled = false
    let mutable socketActive = false
    let mutable socketEnabled = false
    let mutable serviceActive = true
    let mutable rejectPasswordNo = false
    let mutable failNextReload = false
    let helperBytes = Encoding.UTF8.GetBytes("fake immutable native helper executable")

    let helperDigest =
        SHA256.HashData(helperBytes)
        |> Convert.ToHexString
        |> fun value -> value.ToLowerInvariant()

    let helperPath = "/var/cache/keroosha-iac/helper/linux-x64/" + helperDigest

    let mappedPath (logicalPath: string) =
        Path.Combine(root, logicalPath.TrimStart('/').Replace('/', Path.DirectorySeparatorChar))

    let success (stdout: string) =
        {
            ExitCode = 0
            Stdout = stdout
            Stderr = ""
        }

    let failure (message: string) =
        {
            ExitCode = 1
            Stdout = ""
            Stderr = message
        }

    let status (code: int) (stdout: string) =
        {
            ExitCode = code
            Stdout = stdout
            Stderr = ""
        }

    let normalizeName (name: string) =
        match name.ToLowerInvariant() with
        | "passwordauthentication" -> Some "PasswordAuthentication"
        | "kbdinteractiveauthentication" -> Some "KbdInteractiveAuthentication"
        | "pubkeyauthentication" -> Some "PubkeyAuthentication"
        | "permitrootlogin" -> Some "PermitRootLogin"
        | "maxauthtries" -> Some "MaxAuthTries"
        | "port" -> Some "Port"
        | "listenaddress" -> Some "ListenAddress"
        | _ -> Some(name.ToLowerInvariant())

    let contextUser (arguments: string list) =
        match arguments |> List.tryFindIndex ((=) "-C") with
        | Some index when index + 1 < arguments.Length ->
            arguments[index + 1].Split([| ',' |], StringSplitOptions.RemoveEmptyEntries)
            |> Array.tryPick (fun field ->
                if field.StartsWith("user=", StringComparison.Ordinal) then
                    Some(field.Substring(5))
                else
                    None)
        | _ -> None

    let effectiveConfiguration (user: string option) =
        let values = Dictionary<string, string>(StringComparer.Ordinal)
        let contextualValues = Dictionary<string, string>(StringComparer.Ordinal)
        let ports = ResizeArray<int>()
        let listenAddresses = ResizeArray<string>()
        let mutable invalid: string option = None
        let mutable managedConfigurationLoaded = false
        let mutable managedConfigurationTracePath = "/etc/ssh/sshd_config.d/00-dorothy.conf"

        let rec processFile (path: string) (tracePath: string) (visited: Set<string>) =
            let fullPath = Path.GetFullPath path

            if File.Exists(fullPath) && not (Set.contains fullPath visited) then
                if
                    StringComparer.Ordinal.Equals(
                        fullPath,
                        Path.GetFullPath(mappedPath "/etc/ssh/sshd_config.d/00-dorothy.conf")
                    )
                then
                    managedConfigurationLoaded <- true
                    managedConfigurationTracePath <- tracePath

                let nextVisited = Set.add fullPath visited
                let mutable matchActive = true
                let mutable insideMatch = false

                for rawLine in File.ReadAllLines(fullPath) do
                    let line = rawLine.Trim()

                    if line <> "" && not (line.StartsWith("#", StringComparison.Ordinal)) then
                        let fields = line.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)

                        if fields.Length > 0 then
                            match fields[0].ToLowerInvariant() with
                            | "include" ->
                                for pattern in fields |> Array.skip 1 do
                                    let logicalPattern =
                                        if Path.IsPathRooted pattern then
                                            pattern
                                        else
                                            Path.Combine("/etc/ssh", pattern)

                                    let actualPattern = mappedPath logicalPattern

                                    if pattern.Contains('*') || pattern.Contains('?') then
                                        let directory = Path.GetDirectoryName actualPattern
                                        let search = Path.GetFileName actualPattern

                                        if Directory.Exists(directory) then
                                            Directory.GetFiles(directory, search)
                                            |> Array.sortWith (fun left right ->
                                                StringComparer.Ordinal.Compare(left, right))
                                            |> Array.iter (fun included ->
                                                let tracePath =
                                                    Path.Combine(
                                                        Path.GetDirectoryName logicalPattern,
                                                        Path.GetFileName included
                                                    )

                                                processFile included tracePath nextVisited)
                                    elif File.Exists(actualPattern) then
                                        processFile actualPattern logicalPattern nextVisited
                            | "match" ->
                                insideMatch <- true

                                if
                                    fields.Length >= 2
                                    && fields[1].Equals("all", StringComparison.OrdinalIgnoreCase)
                                then
                                    matchActive <- true
                                elif
                                    fields.Length = 3
                                    && fields[1].Equals("user", StringComparison.OrdinalIgnoreCase)
                                then
                                    matchActive <- user = Some fields[2]
                                else
                                    matchActive <- false
                            | _ when matchActive ->
                                if fields.Length < 2 then
                                    invalid <- Some line
                                else
                                    let value = String.Join(" ", fields, 1, fields.Length - 1)

                                    match normalizeName fields[0] with
                                    | Some "Port" ->
                                        let mutable port = 0

                                        if not (Int32.TryParse(value, &port)) || port < 1 || port > 65535 then
                                            invalid <- Some line
                                        else
                                            ports.Add(port)
                                    | Some "ListenAddress" -> listenAddresses.Add(value)
                                    | Some name when insideMatch ->
                                        if not (contextualValues.ContainsKey(name)) then
                                            contextualValues[name] <- value
                                    | Some name ->
                                        if not (values.ContainsKey(name)) then
                                            values[name] <- value
                                    | None -> ()
                            | _ -> ()

        processFile (mappedPath "/etc/ssh/sshd_config") "/etc/ssh/sshd_config" Set.empty

        let defaults =
            [
                "PasswordAuthentication", "yes"
                "KbdInteractiveAuthentication", "yes"
                "PubkeyAuthentication", "yes"
                "PermitRootLogin", "prohibit-password"
                "MaxAuthTries", "6"
            ]
            |> Map.ofList

        let globalSettings =
            defaults
            |> Map.map (fun name fallback -> if values.ContainsKey(name) then values[name] else fallback)

        let settings =
            globalSettings
            |> Map.map (fun name value ->
                if contextualValues.ContainsKey(name) then
                    contextualValues[name]
                else
                    value)

        let configuredPorts =
            if ports.Count = 0 then
                [ 22 ]
            else
                ports |> Seq.distinct |> Seq.sort |> Seq.toList

        let actualListeners =
            if listenAddresses.Count > 0 then
                listenAddresses |> Seq.toList
            else
                configuredPorts
                |> List.collect (fun port ->
                    [
                        "0.0.0.0:" + port.ToString(CultureInfo.InvariantCulture)
                        "[::]:" + port.ToString(CultureInfo.InvariantCulture)
                    ])

        let allValues = Dictionary<string, string>(StringComparer.Ordinal)

        for KeyValue(name, value) in values do
            allValues[name] <- value

        for KeyValue(name, value) in contextualValues do
            allValues[name] <- value

        let knownNames =
            set
                [
                    "PasswordAuthentication"
                    "KbdInteractiveAuthentication"
                    "PubkeyAuthentication"
                    "PermitRootLogin"
                    "MaxAuthTries"
                    "Port"
                    "ListenAddress"
                ]

        let additionalSettings =
            allValues
            |> Seq.filter (fun item -> not (Set.contains item.Key knownNames))
            |> Seq.map (fun item -> item.Key.ToLowerInvariant() + " " + item.Value)
            |> Seq.sort
            |> Seq.toList

        invalid,
        settings,
        configuredPorts,
        actualListeners,
        additionalSettings,
        managedConfigurationLoaded,
        managedConfigurationTracePath

    let sshdResult (arguments: string list) =
        let isTest = List.contains "-t" arguments
        let context = contextUser arguments

        let (invalid,
             settings,
             ports,
             listeners,
             additionalSettings,
             managedConfigurationLoaded,
             managedConfigurationTracePath) =
            effectiveConfiguration context

        let candidatePath = mappedPath "/etc/ssh/sshd_config.d/00-dorothy.conf"

        let result =
            if
                isTest
                && rejectPasswordNo
                && File.Exists(candidatePath)
                && File.ReadAllText(candidatePath).Contains("PasswordAuthentication no", StringComparison.Ordinal)
            then
                failure "injected sshd candidate validation failure"
            else
                match invalid with
                | Some line -> failure ("invalid sshd directive: " + line)
                | None when isTest -> success ""
                | None ->
                    let output = ResizeArray<string>()

                    for port in ports do
                        output.Add("port " + port.ToString(CultureInfo.InvariantCulture))

                    for listener in listeners do
                        output.Add("listenaddress " + listener)

                    for setting in additionalSettings do
                        output.Add(setting)

                    output.Add("passwordauthentication " + settings["PasswordAuthentication"])
                    output.Add("kbdinteractiveauthentication " + settings["KbdInteractiveAuthentication"])
                    output.Add("pubkeyauthentication " + settings["PubkeyAuthentication"])
                    output.Add("permitrootlogin " + settings["PermitRootLogin"])
                    output.Add("maxauthtries " + settings["MaxAuthTries"])
                    success (String.concat "\n" output + "\n")

        if List.contains "-ddd" arguments && managedConfigurationLoaded then
            { result with
                Stderr =
                    "debug2: /etc/ssh/sshd_config line 1: including "
                    + managedConfigurationTracePath
                    + "\n"
            }
        else
            result

    let run (executable: string) (arguments: string list) (_: string option) =
        calls.Add((executable, arguments))

        match executable, arguments with
        | "/usr/bin/systemctl", [ "show"; "--no-pager"; "--property=ExecStart"; "--value"; "ssh.service" ] ->
            success
                "{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D $SSHD_OPTS ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n"
        | "/usr/bin/systemctl", [ "show"; "--no-pager"; "--property=ExecReload"; "--value"; "ssh.service" ] ->
            success
                "{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -t ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 } ; { path=/bin/kill ; argv[]=/bin/kill -HUP $MAINPID ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n"
        | "/usr/bin/systemctl", [ "show"; "--no-pager"; "--property=Environment"; "--value"; "ssh.service" ] ->
            success "SSHD_OPTS=\n"
        | "/usr/bin/systemctl", [ "show"; "--no-pager"; "--property=EnvironmentFiles"; "--value"; "ssh.service" ] ->
            success "- /etc/default/ssh (ignore_errors=yes)\n"
        | "/usr/bin/readlink", [ "-f"; "/proc/self/exe" ] -> success (helperPath + "\n")
        | "/usr/sbin/sshd", _ -> sshdResult arguments
        | "/usr/bin/systemctl", [ "is-active"; "ssh.socket" ] ->
            if socketActive then
                success "active\n"
            else
                status 3 "inactive\n"
        | "/usr/bin/systemctl", [ "is-enabled"; "ssh.socket" ] ->
            if socketEnabled then
                success "enabled\n"
            else
                status 1 "disabled\n"
        | "/usr/bin/systemctl", [ "is-active"; "ssh.service" ] ->
            if serviceActive then
                success "active\n"
            else
                status 3 "inactive\n"
        | "/usr/bin/systemctl", [ "start"; "ssh.service" ] ->
            serviceActive <- true
            startCount <- startCount + 1
            success ""
        | "/usr/bin/systemctl", [ "reload"; "ssh.service" ] ->
            reloadCount <- reloadCount + 1

            if failNextReload then
                failNextReload <- false
                failure "injected ssh.service reload failure"
            else
                success ""
        | "/usr/bin/systemctl", [ "daemon-reload" ] -> success ""
        | "/usr/bin/systemctl", [ "enable"; "--now"; "keroosha-iac-sshd-rollback.timer" ] ->
            timerEnabled <- true
            success ""
        | "/usr/bin/systemctl", [ "disable"; "--now"; "keroosha-iac-sshd-rollback.timer" ] ->
            timerEnabled <- false
            success ""
        | _ -> failure ("unexpected host command: " + executable + " " + String.concat " " arguments)

    do
        for logicalPath in
            [
                "/etc/ssh/sshd_config.d"
                "/etc/systemd/system"
                "/etc/default"
                "/run/keroosha-iac"
                "/var/cache/keroosha-iac/helper/linux-x64"
            ] do
            Directory.CreateDirectory(mappedPath logicalPath) |> ignore

        File.WriteAllText(mappedPath "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n")
        File.WriteAllText(mappedPath "/etc/default/ssh", "SSHD_OPTS=\n")
        File.WriteAllBytes(mappedPath helperPath, helperBytes)

    member _.Environment =
        TestSupport.fakeHostEnvironment root run (fun () -> DateTimeOffset.UtcNow)

    member _.ConfigurationPath = mappedPath "/etc/ssh/sshd_config.d/00-dorothy.conf"
    member _.OwnerStatePath = mappedPath "/var/lib/keroosha-iac/sshd/owner.json"

    member _.RollbackRequestPath =
        mappedPath "/var/lib/keroosha-iac/sshd/rollback-request.json"

    member _.TimerPath = mappedPath "/etc/systemd/system/keroosha-iac-sshd-rollback.timer"

    member _.ServicePath =
        mappedPath "/etc/systemd/system/keroosha-iac-sshd-rollback.service"

    member _.StateDirectory = mappedPath "/var/lib/keroosha-iac/sshd"
    member _.TransactionPath = mappedPath "/var/lib/keroosha-iac/sshd/rollback.json"
    member _.HelperPath = helperPath
    member _.TimerEnabled = timerEnabled
    member _.ReloadCount = reloadCount
    member _.StartCount = startCount
    member _.Calls = calls.ToArray()
    member _.MainConfigurationPath = mappedPath "/etc/ssh/sshd_config"
    member _.NativeDefaultConfiguration = (sshdResult [ "-T" ]).Stdout

    member _.RejectPasswordNo
        with get () = rejectPasswordNo
        and set value = rejectPasswordNo <- value

    member _.FailNextReload
        with get () = failNextReload
        and set value = failNextReload <- value

    member _.SocketActive
        with get () = socketActive
        and set value = socketActive <- value

    member _.SocketEnabled
        with get () = socketEnabled
        and set value = socketEnabled <- value

    member _.ServiceActive
        with get () = serviceActive
        and set value = serviceActive <- value

    member _.SetPrecedenceDirectives(contents: string) =
        File.WriteAllText(mappedPath "/etc/ssh/sshd_config.d/00-before.conf", contents)

    member this.SetPrecedenceDirective(name: string, value: string) =
        this.SetPrecedenceDirectives(name + " " + value + "\n")

    member _.SetMainConfiguration(contents: string) =
        File.WriteAllText(mappedPath "/etc/ssh/sshd_config", contents)

    member _.SetConfigurationFile(logicalPath: string, contents: string) =
        let path = mappedPath logicalPath
        Directory.CreateDirectory(Path.GetDirectoryName path) |> ignore
        File.WriteAllText(path, contents)

    member _.ArmTimerForTest() = timerEnabled <- true

    member this.FireRollbackTimer() =
        if not timerEnabled then
            invalidOp "The fake SSHD rollback timer is not armed."

        let payload = File.ReadAllText(this.RollbackRequestPath)
        Sshd.execute this.Environment payload

module private SshdTestHelpers =
    let configuration (directives: (string * string) list) =
        match directives with
        | [] -> ""
        | values ->
            values
            |> List.map (fun (name, value) -> name + " " + value)
            |> String.concat "\n"
            |> fun text -> text + "\n"

    let connectionUser =
        let sudoUser = Environment.GetEnvironmentVariable("SUDO_USER")

        if String.IsNullOrWhiteSpace sudoUser then
            Environment.UserName
        else
            sudoUser

    let execute
        (host: SshdFakeHost)
        (operation: string)
        (ownerId: string)
        (configuration: string)
        (token: string option)
        : JsonObject =
        let request = JsonObject()
        request["operation"] <- JsonValue.Create(operation)
        request["ownerId"] <- JsonValue.Create(ownerId)
        request["configuration"] <- JsonValue.Create(configuration)

        match token with
        | Some value -> request["transactionToken"] <- JsonValue.Create(value)
        | None -> ()

        use document = JsonDocument.Parse(request.ToJsonString())
        Sshd.handle host.Environment document.RootElement :?> JsonObject

    let keys (node: JsonObject) : string[] =
        node |> Seq.map (fun item -> item.Key) |> Seq.sort |> Seq.toArray

    let bool (node: JsonObject) (key: string) = node[key].GetValue<bool>()
    let string (node: JsonObject) (key: string) = node[key].GetValue<string>()

    let ints (node: JsonObject) (key: string) =
        node[key].AsArray()
        |> Seq.map (fun value -> value.GetValue<int>())
        |> Seq.toArray

    let contains (node: JsonObject) (key: string) (text: string) =
        string node key |> fun value -> value.Contains(text, StringComparison.Ordinal)

    let stagePendingApply (host: SshdFakeHost) (ownerId: string) (configuration: string) (token: string) =
        let digest =
            SHA256.HashData(Encoding.UTF8.GetBytes(ownerId))
            |> Convert.ToHexString
            |> fun value -> value.ToLowerInvariant()

        let marker = "# Dorothy sshd owner-sha256=" + digest
        let configBytes = Encoding.UTF8.GetBytes(marker + "\n" + configuration)
        let ownerState = JsonObject()
        ownerState["version"] <- JsonValue.Create(2)
        ownerState["owner"] <- JsonValue.Create(digest)
        ownerState["configuration"] <- JsonValue.Create(configuration)
        let ownerBytes = Encoding.UTF8.GetBytes(ownerState.ToJsonString())
        let baseline = host.NativeDefaultConfiguration
        let context = JsonObject()
        context["user"] <- JsonValue.Create(connectionUser)
        context["host"] <- (null: JsonNode)
        context["addr"] <- (null: JsonNode)
        context["laddr"] <- (null: JsonNode)
        context["lport"] <- (null: JsonNode)
        let journal = JsonObject()
        journal["version"] <- JsonValue.Create(2)
        journal["owner"] <- JsonValue.Create(digest)
        journal["ownerId"] <- JsonValue.Create(ownerId)
        journal["action"] <- JsonValue.Create("apply")
        journal["token"] <- JsonValue.Create(token)
        journal["status"] <- JsonValue.Create("pending")
        journal["oldConfig"] <- (null: JsonNode)
        journal["newConfig"] <- JsonValue.Create(Convert.ToBase64String(configBytes))
        journal["oldState"] <- (null: JsonNode)
        journal["newState"] <- JsonValue.Create(Convert.ToBase64String(ownerBytes))
        journal["helperPath"] <- JsonValue.Create(host.HelperPath)
        journal["context"] <- context
        journal["baselineConfiguration"] <- JsonValue.Create(baseline)
        journal["baselineConnectionConfiguration"] <- JsonValue.Create(baseline)
        journal["reloadCompleted"] <- JsonValue.Create(false)
        let request = JsonObject()
        request["operation"] <- JsonValue.Create("rollback")
        request["ownerId"] <- JsonValue.Create(ownerId)
        request["configuration"] <- JsonValue.Create("")
        request["transactionToken"] <- JsonValue.Create(token)

        let service =
            String.concat
                "\n"
                [
                    marker
                    "[Unit]"
                    "Description=Dorothy SSHD configuration rollback"
                    "After=network.target"
                    "[Service]"
                    "Type=oneshot"
                    "ExecStart=" + host.HelperPath + " sshd"
                    "StandardInput=file:/var/lib/keroosha-iac/sshd/rollback-request.json"
                    ""
                ]

        let timer =
            String.concat
                "\n"
                [
                    marker
                    "[Unit]"
                    "Description=Dorothy SSHD rollback watchdog"
                    "[Timer]"
                    "OnActiveSec=2min"
                    "OnUnitInactiveSec=2min"
                    "AccuracySec=1s"
                    "Unit=keroosha-iac-sshd-rollback.service"
                    "[Install]"
                    "WantedBy=timers.target"
                    ""
                ]

        Directory.CreateDirectory(host.StateDirectory) |> ignore
        File.WriteAllBytes(host.ConfigurationPath, configBytes)
        File.WriteAllBytes(host.OwnerStatePath, ownerBytes)
        File.WriteAllText(host.TransactionPath, journal.ToJsonString())
        File.WriteAllText(host.RollbackRequestPath, request.ToJsonString())
        File.WriteAllText(host.ServicePath, service)
        File.WriteAllText(host.TimerPath, timer)
        host.ArmTimerForTest()

[<TestFixture>]
type SshdBackendTests() =
    [<Test>]
    member _.``Read returns full native SSHD configurations and resolved listener ports``() =
        use temporary = new TemporaryDirectory("dorothy-sshd-read-")
        let host = SshdFakeHost(temporary.Path)
        let requested = "KexAlgorithms curve25519-sha256\n"

        let response = SshdTestHelpers.execute host "read" "resource-a" requested None

        Assert.That(
            SshdTestHelpers.keys response,
            Is.EquivalentTo(
                [|
                    "owned"
                    "actualConfiguration"
                    "actualConnectionConfiguration"
                    "ports"
                    "inSync"
                    "pendingToken"
                |]
            )
        )

        Assert.That(SshdTestHelpers.bool response "owned", Is.False)
        Assert.That(SshdTestHelpers.bool response "inSync", Is.False)
        Assert.That(SshdTestHelpers.string response "pendingToken", Is.Empty)
        Assert.That(SshdTestHelpers.ints response "ports", Is.EqualTo(box ([| 22 |]: int array)))
        Assert.That(SshdTestHelpers.contains response "actualConfiguration" "passwordauthentication yes", Is.True)
        Assert.That(SshdTestHelpers.contains response "actualConfiguration" "maxauthtries 6", Is.True)
        Assert.That(SshdTestHelpers.contains response "actualConnectionConfiguration" "listenaddress [::]:22", Is.True)
        Assert.That(File.Exists(host.ConfigurationPath), Is.False)

    [<Test>]
    member _.``Apply preserves native directive ordering Includes repeats Match blocks and multiline values``() =
        use temporary = new TemporaryDirectory("dorothy-sshd-native-config-")
        let host = SshdFakeHost(temporary.Path)
        let mainContents = File.ReadAllText(host.MainConfigurationPath)

        host.SetConfigurationFile(
            "/etc/ssh/extra.d/20-context.conf",
            "Match User "
            + SshdTestHelpers.connectionUser
            + "\n    AllowTcpForwarding no\n    PermitOpen example.test:443\n"
        )

        let config =
            "# Native SSHD body; keep ordering and comments.\r\n"
            + "Port 2222\n"
            + "Port 2200\n"
            + "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org\n"
            + "Include /etc/ssh/extra.d/*.conf\n"
            + "UsePAM yes\n"
            + "Match User "
            + SshdTestHelpers.connectionUser
            + "\n    AuthenticationMethods publickey,password\n"

        let applied = SshdTestHelpers.execute host "apply" "resource-a" config None

        Assert.That(
            File.ReadAllText(host.ConfigurationPath),
            Is.EqualTo(
                "# Dorothy sshd owner-sha256="
                + (SHA256.HashData(Encoding.UTF8.GetBytes("resource-a"))
                   |> Convert.ToHexString
                   |> fun value -> value.ToLowerInvariant())
                + "\n"
                + config
            )
        )

        Assert.That(int (File.GetUnixFileMode(host.ConfigurationPath)) &&& 0o777, Is.EqualTo(0o600))
        Assert.That(File.ReadAllText(host.MainConfigurationPath), Is.EqualTo(mainContents))
        Assert.That(SshdTestHelpers.ints applied "ports", Is.EqualTo(box ([| 2200; 2222 |]: int array)))

        Assert.That(
            SshdTestHelpers.contains
                applied
                "actualConfiguration"
                "kexalgorithms curve25519-sha256,curve25519-sha256@libssh.org",
            Is.True
        )

        Assert.That(SshdTestHelpers.contains applied "actualConfiguration" "usepam yes", Is.True)
        Assert.That(SshdTestHelpers.contains applied "actualConnectionConfiguration" "allowtcpforwarding no", Is.True)

        Assert.That(
            SshdTestHelpers.contains applied "actualConnectionConfiguration" "authenticationmethods publickey,password",
            Is.True
        )

        Assert.That(SshdTestHelpers.string applied "pendingToken", Is.Not.Empty)

    [<Test>]
    member _.``Native precedence and multiple listener directives are not compared to scalar desired values``() =
        use temporary = new TemporaryDirectory("dorothy-sshd-native-precedence-")
        let host = SshdFakeHost(temporary.Path)
        host.SetPrecedenceDirective("PasswordAuthentication", "yes")
        let config = "PasswordAuthentication no\nPort 2200\nPort 2222\n"

        let applied = SshdTestHelpers.execute host "apply" "resource-a" config None
        let token = SshdTestHelpers.string applied "pendingToken"

        SshdTestHelpers.execute host "confirm" "resource-a" config (Some token)
        |> ignore

        let observed = SshdTestHelpers.execute host "read" "resource-a" config None

        Assert.That(SshdTestHelpers.bool observed "inSync", Is.True)
        Assert.That(SshdTestHelpers.contains observed "actualConfiguration" "passwordauthentication yes", Is.True)
        Assert.That(SshdTestHelpers.ints observed "ports", Is.EqualTo(box ([| 2200; 2222 |]: int array)))

    [<Test>]
    member _.``Native include trace detects an ignored owned drop-in``() =
        use temporary = new TemporaryDirectory("dorothy-sshd-ignored-dropin-")
        let host = SshdFakeHost(temporary.Path)
        let config = "PasswordAuthentication no\n"
        let applied = SshdTestHelpers.execute host "apply" "resource-a" config None
        let token = SshdTestHelpers.string applied "pendingToken"

        SshdTestHelpers.execute host "confirm" "resource-a" config (Some token)
        |> ignore

        let managedBytes = File.ReadAllBytes(host.ConfigurationPath)
        host.SetMainConfiguration("Port 22\n")

        let observed = SshdTestHelpers.execute host "read" "resource-a" config None

        let error =
            Assert.Throws<Sshd.BackendError>(
                TestDelegate(fun () -> SshdTestHelpers.execute host "apply" "resource-a" config None |> ignore)
            )

        Assert.That(SshdTestHelpers.bool observed "inSync", Is.False)

        Assert.That(
            error.Message.Contains("did not load Dorothy's managed SSHD configuration", StringComparison.Ordinal),
            Is.True
        )

        Assert.That(File.ReadAllBytes(host.ConfigurationPath), Is.EqualTo(box managedBytes))
        Assert.That(File.ReadAllText(host.MainConfigurationPath), Is.EqualTo("Port 22\n"))
        Assert.That(host.ReloadCount, Is.EqualTo(1))
        Assert.That(host.TimerEnabled, Is.False)

    [<Test>]
    member _.``Native include trace normalizes equivalent lexical paths``() =
        use temporary = new TemporaryDirectory("dorothy-sshd-include-path-")
        let host = SshdFakeHost(temporary.Path)
        let mainConfiguration = "Include /etc/ssh/./sshd_config.d/*.conf\n"
        host.SetMainConfiguration(mainConfiguration)
        let config = "PasswordAuthentication no\n"
        let applied = SshdTestHelpers.execute host "apply" "resource-a" config None
        let token = SshdTestHelpers.string applied "pendingToken"

        SshdTestHelpers.execute host "confirm" "resource-a" config (Some token)
        |> ignore

        let observed = SshdTestHelpers.execute host "read" "resource-a" config None

        Assert.That(SshdTestHelpers.bool observed "inSync", Is.True)
        Assert.That(File.ReadAllText(host.MainConfigurationPath), Is.EqualTo(mainConfiguration))

    [<Test>]
    member _.``Native syntax failure restores prior contents without exposing diagnostics``() =
        use temporary = new TemporaryDirectory("dorothy-sshd-native-failure-")
        let host = SshdFakeHost(temporary.Path)
        let oldConfiguration = "PasswordAuthentication yes\n"

        let initial =
            SshdTestHelpers.execute host "apply" "resource-a" oldConfiguration None

        let initialToken = SshdTestHelpers.string initial "pendingToken"

        SshdTestHelpers.execute host "confirm" "resource-a" oldConfiguration (Some initialToken)
        |> ignore

        let oldConfigBytes = File.ReadAllBytes(host.ConfigurationPath)
        let oldStateBytes = File.ReadAllBytes(host.OwnerStatePath)
        host.RejectPasswordNo <- true

        let invalidConfiguration =
            "AuthorizedKeysCommand /usr/bin/echo secret-native-argument\nPasswordAuthentication no\n"

        let error =
            Assert.Throws<Sshd.BackendError>(
                TestDelegate(fun () ->
                    SshdTestHelpers.execute host "apply" "resource-a" invalidConfiguration None
                    |> ignore)
            )

        Assert.That(error.Message.Contains("secret-native-argument", StringComparison.Ordinal), Is.False)

        Assert.That(
            error.Message.Contains("injected sshd candidate validation failure", StringComparison.Ordinal),
            Is.False
        )

        Assert.That(File.ReadAllBytes(host.ConfigurationPath), Is.EqualTo(box oldConfigBytes))
        Assert.That(File.ReadAllBytes(host.OwnerStatePath), Is.EqualTo(box oldStateBytes))
        Assert.That(host.TimerEnabled, Is.False)
        Assert.That(host.ReloadCount, Is.EqualTo(2))

        let observed =
            SshdTestHelpers.execute host "read" "resource-a" oldConfiguration None

        Assert.That(SshdTestHelpers.bool observed "owned", Is.True)
        Assert.That(SshdTestHelpers.bool observed "inSync", Is.True)

    [<Test>]
    member _.``Read leaves pending transactions and watchdog state untouched``() =
        use temporary = new TemporaryDirectory("dorothy-sshd-observational-read-")
        let host = SshdFakeHost(temporary.Path)
        let config = "PasswordAuthentication no\n"
        let token = String.replicate 32 "a"
        SshdTestHelpers.stagePendingApply host "resource-a" config token
        let before = File.ReadAllBytes(host.TransactionPath)

        let observed = SshdTestHelpers.execute host "read" "resource-a" config None

        Assert.That(SshdTestHelpers.bool observed "owned", Is.True)
        Assert.That(SshdTestHelpers.bool observed "inSync", Is.False)
        Assert.That(SshdTestHelpers.string observed "pendingToken", Is.EqualTo(token))
        Assert.That(File.ReadAllBytes(host.TransactionPath), Is.EqualTo(box before))
        Assert.That(host.ReloadCount, Is.EqualTo(0))
        Assert.That(host.TimerEnabled, Is.True)

    [<Test>]
    member _.``Apply confirm unchanged read and delete form one recoverable lifecycle``() =
        use temporary = new TemporaryDirectory("dorothy-sshd-lifecycle-")
        let host = SshdFakeHost(temporary.Path)

        let desired =
            SshdTestHelpers.configuration [ "PasswordAuthentication", "no"; "PermitRootLogin", "no" ]

        let applied = SshdTestHelpers.execute host "apply" "resource-a" desired None
        let token = SshdTestHelpers.string applied "pendingToken"

        Assert.That(
            SshdTestHelpers.keys applied,
            Is.EquivalentTo(
                [|
                    "owned"
                    "actualConfiguration"
                    "actualConnectionConfiguration"
                    "ports"
                    "inSync"
                    "pendingToken"
                |]
            )
        )

        Assert.That(token, Is.Not.Empty)
        Assert.That(SshdTestHelpers.bool applied "owned", Is.True)
        Assert.That(SshdTestHelpers.bool applied "inSync", Is.False)
        Assert.That(host.TimerEnabled, Is.True)
        Assert.That(File.Exists(host.TimerPath), Is.True)
        Assert.That(File.Exists(host.RollbackRequestPath), Is.True)
        Assert.That(host.ReloadCount, Is.EqualTo(1))
        let timerConfiguration = File.ReadAllText(host.TimerPath)
        Assert.That(timerConfiguration.Contains("OnActiveSec=2min", StringComparison.Ordinal), Is.True)
        Assert.That(timerConfiguration.Contains("OnUnitInactiveSec=2min", StringComparison.Ordinal), Is.True)
        let repeatedPending = SshdTestHelpers.execute host "apply" "resource-a" desired None
        Assert.That(SshdTestHelpers.string repeatedPending "pendingToken", Is.EqualTo(token))
        Assert.That(SshdTestHelpers.bool repeatedPending "inSync", Is.False)
        Assert.That(host.ReloadCount, Is.EqualTo(1))

        let confirmed =
            SshdTestHelpers.execute host "confirm" "resource-a" desired (Some token)

        Assert.That(SshdTestHelpers.keys confirmed, Is.Empty)
        Assert.That(host.TimerEnabled, Is.False)
        Assert.That(File.Exists(host.RollbackRequestPath), Is.False)

        let retriedConfirm =
            SshdTestHelpers.execute host "confirm" "resource-a" desired (Some token)

        Assert.That(SshdTestHelpers.keys retriedConfirm, Is.Empty)

        let repeatedApply = SshdTestHelpers.execute host "apply" "resource-a" desired None
        Assert.That(SshdTestHelpers.string repeatedApply "pendingToken", Is.Empty)
        Assert.That(SshdTestHelpers.bool repeatedApply "inSync", Is.True)
        Assert.That(host.ReloadCount, Is.EqualTo(1))

        let observed = SshdTestHelpers.execute host "read" "resource-a" desired None
        Assert.That(SshdTestHelpers.bool observed "owned", Is.True)
        Assert.That(SshdTestHelpers.bool observed "inSync", Is.True)

        let deleted = SshdTestHelpers.execute host "delete" "resource-a" desired None
        let deleteToken = SshdTestHelpers.string deleted "pendingToken"
        Assert.That(SshdTestHelpers.keys deleted, Is.EqualTo(box ([| "pendingToken" |]: string array)))
        Assert.That(deleteToken, Is.Not.Empty)
        Assert.That(File.Exists(host.ConfigurationPath), Is.False)
        Assert.That(host.TimerEnabled, Is.True)
        Assert.That(host.ReloadCount, Is.EqualTo(2))

        let deleteConfirmed =
            SshdTestHelpers.execute host "confirm" "resource-a" desired (Some deleteToken)

        Assert.That(SshdTestHelpers.keys deleteConfirmed, Is.Empty)
        Assert.That(host.TimerEnabled, Is.False)
        Assert.That(File.Exists(host.OwnerStatePath), Is.False)

        let absent = SshdTestHelpers.execute host "read" "resource-a" desired None
        Assert.That(SshdTestHelpers.bool absent "owned", Is.False)
        Assert.That(SshdTestHelpers.bool absent "inSync", Is.False)
        let repeatedDelete = SshdTestHelpers.execute host "delete" "resource-a" desired None
        Assert.That(SshdTestHelpers.string repeatedDelete "pendingToken", Is.Empty)
        Assert.That(host.ReloadCount, Is.EqualTo(2))

    [<Test>]
    member _.``Large native configuration snapshots remain deletable``() =
        use temporary = new TemporaryDirectory("dorothy-sshd-large-snapshots-")
        let host = SshdFakeHost(temporary.Path)
        let configuration = String.replicate 2000 ("# " + String.replicate 500 "\"" + "\n")

        let applied = SshdTestHelpers.execute host "apply" "resource-a" configuration None
        let applyToken = SshdTestHelpers.string applied "pendingToken"
        Assert.That(FileInfo(host.OwnerStatePath).Length, Is.GreaterThan(1024L * 1024L))
        Assert.That(FileInfo(host.TransactionPath).Length, Is.GreaterThan(1024L * 1024L))

        SshdTestHelpers.execute host "confirm" "resource-a" configuration (Some applyToken)
        |> ignore

        let deleted = SshdTestHelpers.execute host "delete" "resource-a" configuration None
        let deleteToken = SshdTestHelpers.string deleted "pendingToken"
        Assert.That(deleteToken, Is.Not.Empty)

        SshdTestHelpers.execute host "confirm" "resource-a" configuration (Some deleteToken)
        |> ignore

        let repeatedDelete =
            SshdTestHelpers.execute host "delete" "resource-a" configuration None

        Assert.That(SshdTestHelpers.string repeatedDelete "pendingToken", Is.Empty)
        Assert.That(File.Exists(host.OwnerStatePath), Is.False)
        Assert.That(File.Exists(host.TransactionPath), Is.False)

    [<Test>]
    member _.``Retry after staging but before reload activates candidate before returning token``() =
        use temporary = new TemporaryDirectory("dorothy-sshd-staged-retry-")
        let host = SshdFakeHost(temporary.Path)

        let desired =
            SshdTestHelpers.configuration [ "PasswordAuthentication", "no"; "KexAlgorithms", "curve25519-sha256" ]

        let token = String.replicate 32 "a"
        SshdTestHelpers.stagePendingApply host "resource-a" desired token

        Assert.That(host.ReloadCount, Is.EqualTo(0))
        let resumed = SshdTestHelpers.execute host "apply" "resource-a" desired None
        Assert.That(SshdTestHelpers.string resumed "pendingToken", Is.EqualTo(token))
        Assert.That(host.ReloadCount, Is.EqualTo(1))
        use journal = JsonDocument.Parse(File.ReadAllText(host.TransactionPath))
        Assert.That(journal.RootElement.GetProperty("reloadCompleted").GetBoolean(), Is.True)

        SshdTestHelpers.execute host "confirm" "resource-a" desired (Some token)
        |> ignore

        let observed = SshdTestHelpers.execute host "read" "resource-a" desired None
        Assert.That(SshdTestHelpers.bool observed "owned", Is.True)
        Assert.That(SshdTestHelpers.bool observed "inSync", Is.True)

    [<Test>]
    member _.``Ownership and transaction tokens cannot be replayed by another resource``() =
        use temporary = new TemporaryDirectory("dorothy-sshd-owner-")
        let host = SshdFakeHost(temporary.Path)
        let desired = "PasswordAuthentication no\n"
        let applied = SshdTestHelpers.execute host "apply" "resource-a" desired None
        let token = SshdTestHelpers.string applied "pendingToken"

        Assert.Throws<Sshd.BackendError>(
            TestDelegate(fun () ->
                SshdTestHelpers.execute host "confirm" "resource-b" desired (Some token)
                |> ignore)
        )
        |> ignore

        Assert.That(host.TimerEnabled, Is.True)

        Assert.That(
            SshdTestHelpers.string (SshdTestHelpers.execute host "read" "resource-a" desired None) "pendingToken",
            Is.EqualTo(token)
        )

        Assert.Throws<Sshd.BackendError>(
            TestDelegate(fun () -> SshdTestHelpers.execute host "apply" "resource-b" desired None |> ignore)
        )
        |> ignore

        Assert.That(File.Exists(host.ConfigurationPath), Is.True)
        Assert.That(host.ReloadCount, Is.EqualTo(1))

        SshdTestHelpers.execute host "confirm" "resource-a" desired (Some token)
        |> ignore

        Assert.Throws<Sshd.BackendError>(
            TestDelegate(fun () -> SshdTestHelpers.execute host "apply" "resource-b" desired None |> ignore)
        )
        |> ignore

        Assert.That(File.Exists(host.ConfigurationPath), Is.True)

    [<Test>]
    member _.``A pending watchdog transaction rolls back independently after service loss``() =
        use temporary = new TemporaryDirectory("dorothy-sshd-watchdog-")
        let host = SshdFakeHost(temporary.Path)
        let desired = "PasswordAuthentication no\n"
        let applied = SshdTestHelpers.execute host "apply" "resource-a" desired None
        Assert.That(host.TimerEnabled, Is.True)
        let token = SshdTestHelpers.string applied "pendingToken"
        host.ServiceActive <- false

        let rollbackResponse = host.FireRollbackTimer()
        use rollbackDocument = JsonDocument.Parse(rollbackResponse)
        Assert.That(rollbackDocument.RootElement.EnumerateObject() |> Seq.length, Is.EqualTo(0))
        Assert.That(File.Exists(host.ConfigurationPath), Is.False)
        Assert.That(File.Exists(host.OwnerStatePath), Is.False)
        Assert.That(host.TimerEnabled, Is.False)
        Assert.That(host.ReloadCount, Is.EqualTo(1))
        Assert.That(host.StartCount, Is.EqualTo(1))
        let absent = SshdTestHelpers.execute host "read" "resource-a" desired None
        Assert.That(SshdTestHelpers.bool absent "owned", Is.False)
        Assert.That(SshdTestHelpers.string absent "pendingToken", Is.Empty)
        Assert.That(token, Is.Not.Empty)

    [<Test>]
    member _.``Failed daemon reload restores the previous file and runtime``() =
        use temporary = new TemporaryDirectory("dorothy-sshd-reload-failure-")
        let host = SshdFakeHost(temporary.Path)
        let oldConfiguration = "PasswordAuthentication yes\n"

        let initial =
            SshdTestHelpers.execute host "apply" "resource-a" oldConfiguration None

        let initialToken = SshdTestHelpers.string initial "pendingToken"

        SshdTestHelpers.execute host "confirm" "resource-a" oldConfiguration (Some initialToken)
        |> ignore

        let oldFile = File.ReadAllBytes(host.ConfigurationPath)
        host.FailNextReload <- true
        let changed = "PasswordAuthentication no\n"

        Assert.Throws<Sshd.BackendError>(
            TestDelegate(fun () -> SshdTestHelpers.execute host "apply" "resource-a" changed None |> ignore)
        )
        |> ignore

        Assert.That(File.ReadAllBytes(host.ConfigurationPath), Is.EqualTo(box oldFile))
        Assert.That(host.ReloadCount, Is.EqualTo(3))
        Assert.That(host.TimerEnabled, Is.False)

        let observed =
            SshdTestHelpers.execute host "read" "resource-a" oldConfiguration None

        Assert.That(SshdTestHelpers.bool observed "inSync", Is.True)

    [<Test>]
    member _.``Delete refuses an externally modified owned file``() =
        use temporary = new TemporaryDirectory("dorothy-sshd-drift-")
        let host = SshdFakeHost(temporary.Path)
        let desired = "PasswordAuthentication no\n"
        let applied = SshdTestHelpers.execute host "apply" "resource-a" desired None
        let token = SshdTestHelpers.string applied "pendingToken"

        SshdTestHelpers.execute host "confirm" "resource-a" desired (Some token)
        |> ignore

        File.AppendAllText(host.ConfigurationPath, "ListenAddress 127.0.0.1\n")

        Assert.Throws<Sshd.BackendError>(
            TestDelegate(fun () -> SshdTestHelpers.execute host "delete" "resource-a" desired None |> ignore)
        )
        |> ignore

        Assert.That(File.Exists(host.ConfigurationPath), Is.True)
        Assert.That(host.ReloadCount, Is.EqualTo(1))
        Assert.That(host.TimerEnabled, Is.False)

    [<Test>]
    member _.``Socket activation and foreign SSHD files are never replaced``() =
        use temporary = new TemporaryDirectory("dorothy-sshd-preconditions-")
        let host = SshdFakeHost(temporary.Path)
        let desired = "PasswordAuthentication no\n"
        host.SocketActive <- true

        Assert.Throws<Sshd.BackendError>(
            TestDelegate(fun () -> SshdTestHelpers.execute host "apply" "resource-a" desired None |> ignore)
        )
        |> ignore

        Assert.That(File.Exists(host.ConfigurationPath), Is.False)
        host.SocketActive <- false
        host.SocketEnabled <- true

        Assert.Throws<Sshd.BackendError>(
            TestDelegate(fun () -> SshdTestHelpers.execute host "apply" "resource-a" desired None |> ignore)
        )
        |> ignore

        Assert.That(File.Exists(host.ConfigurationPath), Is.False)
        host.SocketEnabled <- false
        let foreignConfig = "PasswordAuthentication no\n"
        File.WriteAllText(host.ConfigurationPath, foreignConfig)

        Assert.Throws<Sshd.BackendError>(
            TestDelegate(fun () -> SshdTestHelpers.execute host "apply" "resource-a" desired None |> ignore)
        )
        |> ignore

        Assert.That(File.ReadAllText(host.ConfigurationPath), Is.EqualTo(foreignConfig))
        Assert.That(host.ReloadCount, Is.EqualTo(0))
