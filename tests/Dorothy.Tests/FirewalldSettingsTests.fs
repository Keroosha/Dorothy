namespace Dorothy.Tests

open System
open System.IO
open System.Text.Json
open System.Text.Json.Nodes
open Dorothy.DSL
open NUnit.Framework

module NativeFirewalldSettings = Dorothy.HostHelper.Firewalld

module private FirewalldSettingsTestSupport =
    let success (stdout: string) : Dorothy.HostHelper.CommandResult = { ExitCode = 0; Stdout = stdout; Stderr = "" }

    let withHost (overrideCommand: string -> string list -> Dorothy.HostHelper.CommandResult option) action =
        let previous = Environment.GetEnvironmentVariable "SSH_CONNECTION"
        Environment.SetEnvironmentVariable("SSH_CONNECTION", "192.0.2.1 49200 192.0.2.2 22")
        let root = Path.Combine(Path.GetTempPath(), "dorothy-firewalld-settings-" + Guid.NewGuid().ToString("N"))
        Directory.CreateDirectory root |> ignore
        for directory in
            [ "etc/firewalld/zones"; "etc/firewalld/policies"
              "usr/lib/firewalld/zones"; "usr/lib/firewalld/policies"; "usr/lib/firewalld/services"
              "usr/lib/firewalld/ipsets"; "usr/lib/firewalld/icmptypes"; "usr/lib/firewalld/helpers"
              "run/lock"; "var/lib" ] do
            Directory.CreateDirectory(Path.Combine(root, directory)) |> ignore
        File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/zones/public.xml"), "<zone><service name=\"ssh\"/></zone>")
        File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/zones/trusted.xml"), "<zone target=\"ACCEPT\"/>")
        File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/zones/external.xml"), "<zone><service name=\"ssh\"/><masquerade/></zone>")
        File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/services/ssh.xml"), "<service><port port=\"22\" protocol=\"tcp\"/></service>")
        let icmpDirectory = Path.Combine(root, "usr/lib/firewalld/icmptypes")
        for name in [ "neighbour-advertisement"; "neighbour-solicitation"; "router-advertisement"; "redirect" ] do
            File.WriteAllText(Path.Combine(icmpDirectory, name + ".xml"), "<icmptype><destination ipv6=\"yes\"/></icmptype>")
        let policy = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures/Firewalld/allow-host-ipv6.xml"))
        File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/policies/allow-host-ipv6.xml"), policy)
        let calls = ResizeArray<string list>()
        try
            let baseRun = FirewalldCommandFixture.commands root
            let run executable arguments _ =
                calls.Add(executable :: arguments)
                match overrideCommand executable arguments with
                | Some result -> result
                | None ->
                    match baseRun executable arguments with
                    | Some "no zone\n" -> { ExitCode = 2; Stdout = "no zone\n"; Stderr = "" }
                    | Some output -> success output
                    | None ->
                        let output =
                            match executable, arguments with
                            | "stat", [ "-c"; "%u:%g"; "--"; _ ] -> "0:0"
                            | "stat", [ "-c"; "%Z"; "--"; _ ] -> "1"
                            | "stat", [ "-c"; "%a"; "--"; _ ] ->
                                File.GetUnixFileMode(List.last arguments) |> int |> fun value -> Convert.ToString(value, 8)
                            | "stat", _ ->
                                let mode = File.GetUnixFileMode(List.last arguments) |> int |> fun value -> Convert.ToString(value, 8)
                                "0:" + mode
                            | "ip", [ "-j"; "link"; "show" ] -> """[{"ifname":"lo","link_type":"loopback","operstate":"UNKNOWN"},{"ifname":"eth0","link_type":"ether","operstate":"UP"}]"""
                            | "ip", _ -> "[{\"dev\":\"eth0\"}]"
                            | "firewall-cmd", [ "--state" ] -> "running"
                            | "firewall-cmd", [ "--check-config" ] -> "success"
                            | ("systemctl" | "/usr/bin/systemctl"), [ "is-active"; "firewalld.service" ] -> "active"
                            | ("systemctl" | "/usr/bin/systemctl"), [ "show"; "--timestamp=unix"; "--property=InvocationID"; "--value"; "firewalld.service" ] -> "test-invocation"
                            | ("systemctl" | "/usr/bin/systemctl"), [ "show"; "--timestamp=unix"; "--property=ExecMainStartTimestamp"; "--value"; "firewalld.service" ] ->
                                "@" + string (DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds())
                            | ("systemctl" | "/usr/bin/systemctl"), _ -> ""
                            | _ -> failwith ("Unexpected fixture command: " + String.concat " " (executable :: arguments))
                        let exitCode = if output = "no zone\n" then 2 else 0
                        { ExitCode = exitCode; Stdout = output; Stderr = "" }
            let environment: Dorothy.HostHelper.HostEnvironment =
                { Root = root; Run = run; UtcNow = fun () -> DateTimeOffset.UnixEpoch }
            action environment root calls
        finally
            Environment.SetEnvironmentVariable("SSH_CONNECTION", previous)
            if Directory.Exists root then Directory.Delete(root, true)

    let configuration key value =
        { FirewalldModel.empty "settings" key with SettingValue = Some value }
        |> FirewalldModel.toJson

    let invoke environment operation owner configuration (nonce: string option) =
        let request = JsonObject()
        request["operation"] <- JsonValue.Create(operation: string)
        request["ownerId"] <- JsonValue.Create(owner: string)
        request["configuration"] <- JsonValue.Create(configuration: string)
        nonce |> Option.iter (fun value -> request["transactionNonce"] <- JsonValue.Create value)
        use document = JsonDocument.Parse(request.ToJsonString())
        NativeFirewalldSettings.handle environment document.RootElement

    let applyAndConfirm environment owner configuration =
        let staged = invoke environment "apply" owner configuration None
        match staged["transactionNonce"] with
        | null -> staged
        | nonce ->
            invoke environment "confirm" owner configuration (Some(nonce.GetValue<string>())) |> ignore
            invoke environment "read" owner configuration None

    let settingsPath root = Path.Combine(root, "etc/firewalld/firewalld.conf")

    let strictIptablesRules bypass =
        let bypassRule = if bypass then "-A FORWARD -m conntrack --ctstate DNAT -j ACCEPT\n" else ""
        String.concat "\n"
            [ "*filter"
              ":INPUT ACCEPT [0:0]"
              ":FORWARD ACCEPT [0:0]"
              ":OUTPUT ACCEPT [0:0]"
              ":INPUT_POLICIES - [0:0]"
              ":FORWARD_POLICIES - [0:0]"
              ":OUTPUT_POLICIES - [0:0]"
              ":INPUT_dnat - [0:0]"
              ":FORWARD_dnat - [0:0]"
              ":OUTPUT_dnat - [0:0]"
              "-A INPUT -m comment --comment DNAT -j LOG"
              "-A INPUT -m conntrack --ctstate DNAT -j INPUT_dnat"
              "-A INPUT_dnat -m conntrack --ctstate DNAT --ctdir ORIGINAL --ctorigdstport 80 -j ACCEPT"
              "-A INPUT_dnat -j REJECT"
              bypassRule.TrimEnd('\n')
              "-A FORWARD -m conntrack --ctstate DNAT -j FORWARD_dnat"
              "-A FORWARD_dnat -m conntrack --ctstate DNAT --ctdir ORIGINAL --ctorigdstport 80 -j ACCEPT"
              "-A FORWARD_dnat -j REJECT"
              "-A OUTPUT -m conntrack --ctstate DNAT -j OUTPUT_dnat"
              "-A OUTPUT_dnat -m conntrack --ctstate DNAT --ctdir ORIGINAL --ctorigdstport 80 -j ACCEPT"
              "-A OUTPUT_dnat -j REJECT"
              "COMMIT"
              "" ]

[<TestFixture; NonParallelizable>]
type FirewalldSettingsTests() =
    let success = FirewalldSettingsTestSupport.success

    [<Test>]
    member _.``Settings update and delete merge only the owned key and restore its original line``() =
        FirewalldSettingsTestSupport.withHost (fun _ _ -> None) (fun environment root _ ->
            let path = FirewalldSettingsTestSupport.settingsPath root
            Directory.CreateDirectory(Path.GetDirectoryName path) |> ignore
            let originalLine = "  ReloadPolicy = INPUT:REJECT,FORWARD:DROP,OUTPUT:DROP  "
            let original = "; original comment\n" + originalLine + "\nLogDenied=off\n"
            File.WriteAllText(path, original)
            let owner = "reload-policy-owner"
            let first = FirewalldSettingsTestSupport.configuration "ReloadPolicy" "INPUT:REJECT,FORWARD:DROP,OUTPUT:DROP"
            let second = FirewalldSettingsTestSupport.configuration "ReloadPolicy" "INPUT:ACCEPT,FORWARD:DROP,OUTPUT:DROP"
            FirewalldSettingsTestSupport.applyAndConfirm environment owner first |> ignore
            Assert.That(File.ReadAllText path, Is.EqualTo original)
            File.WriteAllText(path, "LogDenied=all\n# later comment\nReloadPolicy=INPUT:REJECT,FORWARD:DROP,OUTPUT:DROP\n")
            let repaired = FirewalldSettingsTestSupport.applyAndConfirm environment owner second
            Assert.That(repaired["inSync"].GetValue<bool>(), Is.True)
            Assert.That(File.ReadAllText path, Is.EqualTo "LogDenied=all\n# later comment\nReloadPolicy=INPUT:ACCEPT,FORWARD:DROP,OUTPUT:DROP\n")
            FirewalldSettingsTestSupport.invoke environment "delete" owner second None |> ignore
            Assert.That(File.ReadAllText path, Is.EqualTo("LogDenied=all\n# later comment\n" + originalLine + "\n")))

    [<Test>]
    member _.``Settings confirmation preserves unrelated edits made after staging``() =
        FirewalldSettingsTestSupport.withHost (fun _ _ -> None) (fun environment root _ ->
            let path = FirewalldSettingsTestSupport.settingsPath root
            Directory.CreateDirectory(Path.GetDirectoryName path) |> ignore
            File.WriteAllText(path, "ReloadPolicy=INPUT:REJECT,FORWARD:DROP,OUTPUT:DROP\n")
            let owner = "pending-settings-owner"
            let configuration = FirewalldSettingsTestSupport.configuration "ReloadPolicy" "INPUT:REJECT,FORWARD:DROP,OUTPUT:DROP"
            let staged = FirewalldSettingsTestSupport.invoke environment "apply" owner configuration None
            let nonce = staged["transactionNonce"].GetValue<string>()
            File.AppendAllText(path, "LogDenied=all\n# concurrent comment\n")
            FirewalldSettingsTestSupport.invoke environment "confirm" owner configuration (Some nonce) |> ignore
            Assert.That(File.ReadAllText path, Is.EqualTo "ReloadPolicy=INPUT:REJECT,FORWARD:DROP,OUTPUT:DROP\nLogDenied=all\n# concurrent comment\n")
            let observed = FirewalldSettingsTestSupport.invoke environment "read" owner configuration None
            Assert.That(observed["inSync"].GetValue<bool>(), Is.True))

    [<Test>]
    member _.``Failed settings activation rolls back its key without losing concurrent foreign edits``() =
        let mutable reloads = 0
        let mutable path = ""
        let mutable shouldFail = false
        FirewalldSettingsTestSupport.withHost
            (fun executable arguments ->
                if executable = "firewall-cmd" && arguments = [ "--reload" ] then
                    reloads <- reloads + 1
                    if shouldFail && reloads = 1 then
                        File.AppendAllText(path, "LogDenied=all\n")
                        Some { ExitCode = 1; Stdout = ""; Stderr = "injected reload failure" }
                    else None
                else None)
            (fun environment root _ ->
                path <- FirewalldSettingsTestSupport.settingsPath root
                Directory.CreateDirectory(Path.GetDirectoryName path) |> ignore
                let original = "ReloadPolicy=INPUT:REJECT,FORWARD:DROP,OUTPUT:DROP\n"
                File.WriteAllText(path, original)
                let owner = "failed-settings-owner"
                let initial = FirewalldSettingsTestSupport.configuration "ReloadPolicy" "INPUT:REJECT,FORWARD:DROP,OUTPUT:DROP"
                FirewalldSettingsTestSupport.applyAndConfirm environment owner initial |> ignore
                reloads <- 0
                shouldFail <- true
                let changed = FirewalldSettingsTestSupport.configuration "ReloadPolicy" "INPUT:ACCEPT,FORWARD:DROP,OUTPUT:DROP"
                Assert.Throws<NativeFirewalldSettings.BackendError>(fun () -> FirewalldSettingsTestSupport.invoke environment "apply" owner changed None |> ignore) |> ignore
                Assert.That(reloads, Is.GreaterThanOrEqualTo 2)
                Assert.That(File.ReadAllText path, Is.EqualTo(original + "LogDenied=all\n")))

    [<Test>]
    member _.``Unobservable matching setting requires a completed activation receipt``() =
        FirewalldSettingsTestSupport.withHost (fun _ _ -> None) (fun environment root calls ->
            let path = FirewalldSettingsTestSupport.settingsPath root
            Directory.CreateDirectory(Path.GetDirectoryName path) |> ignore
            let value = "INPUT:DROP,FORWARD:DROP,OUTPUT:DROP"
            File.WriteAllText(path, "ReloadPolicy=" + value + "\n")
            let configuration = FirewalldSettingsTestSupport.configuration "ReloadPolicy" value
            let snapshot = FirewalldSettingsTestSupport.applyAndConfirm environment "adopt-settings-owner" configuration
            Assert.That(snapshot["activationReceipt"].GetValue<bool>(), Is.True)
            Assert.That(snapshot["inSync"].GetValue<bool>(), Is.True)
            Assert.That(calls |> Seq.filter (fun call -> call = [ "firewall-cmd"; "--reload" ]) |> Seq.length, Is.EqualTo 1))

    [<Test>]
    member _.``Unobservable change uses a trusted clean-boot preimage``() =
        FirewalldSettingsTestSupport.withHost (fun _ _ -> None) (fun environment root calls ->
            let path = FirewalldSettingsTestSupport.settingsPath root
            Directory.CreateDirectory(Path.GetDirectoryName path) |> ignore
            File.WriteAllText(path, "ReloadPolicy=INPUT:DROP,FORWARD:DROP,OUTPUT:DROP\n")
            let configuration = FirewalldSettingsTestSupport.configuration "ReloadPolicy" "INPUT:REJECT,FORWARD:DROP,OUTPUT:DROP"
            let snapshot = FirewalldSettingsTestSupport.applyAndConfirm environment "clean-boot-settings-owner" configuration
            Assert.That(snapshot["activationReceipt"].GetValue<bool>(), Is.True)
            Assert.That(snapshot["inSync"].GetValue<bool>(), Is.True)
            Assert.That(File.ReadAllText path, Is.EqualTo "ReloadPolicy=INPUT:REJECT,FORWARD:DROP,OUTPUT:DROP\n")
            Assert.That(calls |> Seq.filter (fun call -> call = [ "firewall-cmd"; "--reload" ]) |> Seq.length, Is.EqualTo 1))

    [<Test>]
    member _.``Unobservable post-start setting without proof stays unknown and refuses mutation``() =
        FirewalldSettingsTestSupport.withHost (fun _ _ -> None) (fun environment root calls ->
            let path = FirewalldSettingsTestSupport.settingsPath root
            Directory.CreateDirectory(Path.GetDirectoryName path) |> ignore
            let value = "INPUT:DROP,FORWARD:DROP,OUTPUT:DROP"
            File.WriteAllText(path, "ReloadPolicy=" + value + "\n")
            let owner = "legacy-settings-owner"
            let configuration = FirewalldSettingsTestSupport.configuration "ReloadPolicy" value
            FirewalldSettingsTestSupport.applyAndConfirm environment owner configuration |> ignore
            let journalPath = Path.Combine(root, "var/lib/keroosha-iac/firewalld/settings-ReloadPolicy.json")
            let journal = JsonNode.Parse(File.ReadAllText journalPath).AsObject()
            journal.Remove "settingsActivation" |> ignore
            File.WriteAllText(journalPath, journal.ToJsonString())
            let afterStart: Dorothy.HostHelper.HostEnvironment =
                { environment with
                    Run = fun executable arguments input ->
                        match executable, arguments with
                        | ("/usr/bin/systemctl" | "systemctl"), [ "show"; "--timestamp=unix"; "--property=InvocationID"; "--value"; "firewalld.service" ] ->
                            success "post-start-invocation"
                        | ("/usr/bin/systemctl" | "systemctl"), [ "show"; "--timestamp=unix"; "--property=ExecMainStartTimestamp"; "--value"; "firewalld.service" ] ->
                            success "@1"
                        | "stat", [ "-c"; "%Z"; "--"; _ ] -> success "2"
                        | _ -> environment.Run executable arguments input }
            let unknown = FirewalldSettingsTestSupport.invoke afterStart "read" owner configuration None
            Assert.That(unknown["activationReceipt"].GetValue<bool>(), Is.False)
            Assert.That(unknown["inSync"].GetValue<bool>(), Is.False)
            let priorReloads = calls |> Seq.filter (fun call -> call = [ "firewall-cmd"; "--reload" ]) |> Seq.length
            Assert.Throws<NativeFirewalldSettings.BackendError>(fun () -> FirewalldSettingsTestSupport.invoke afterStart "apply" owner configuration None |> ignore) |> ignore
            let reloads = calls |> Seq.filter (fun call -> call = [ "firewall-cmd"; "--reload" ]) |> Seq.length
            Assert.That(reloads, Is.EqualTo priorReloads))

    [<Test>]
    member _.``Settings read observes managed file mode drift``() =
        FirewalldSettingsTestSupport.withHost (fun _ _ -> None) (fun environment root _ ->
            let path = FirewalldSettingsTestSupport.settingsPath root
            Directory.CreateDirectory(Path.GetDirectoryName path) |> ignore
            File.WriteAllText(path, "ReloadPolicy=INPUT:REJECT,FORWARD:DROP,OUTPUT:DROP\n")
            File.SetUnixFileMode(path, enum<UnixFileMode> 0o644)
            let configuration = FirewalldSettingsTestSupport.configuration "ReloadPolicy" "INPUT:REJECT,FORWARD:DROP,OUTPUT:DROP"
            FirewalldSettingsTestSupport.applyAndConfirm environment "mode-drift-owner" configuration |> ignore
            File.SetUnixFileMode(path, enum<UnixFileMode> 0o600)
            let snapshot = FirewalldSettingsTestSupport.invoke environment "read" "mode-drift-owner" configuration None
            Assert.That(snapshot["permanentInSync"].GetValue<bool>(), Is.False)
            Assert.That(snapshot["inSync"].GetValue<bool>(), Is.False))


    [<TestCase(false); TestCase(true)>]
    member _.``Legacy vendor-seeded override is removed only when its remaining text is pristine``(compact: bool) =
        let runCase (addition: string) (expectedExists: bool) (expectedContents: string) =
            FirewalldSettingsTestSupport.withHost (fun _ _ -> None) (fun environment root _ ->
                let vendor = "StrictForwardPorts=no\nLogDenied=all\n"
                let vendorPath = Path.Combine(root, "usr/lib/firewalld/firewalld.conf")
                let path = FirewalldSettingsTestSupport.settingsPath root
                Directory.CreateDirectory(Path.GetDirectoryName vendorPath) |> ignore
                Directory.CreateDirectory(Path.GetDirectoryName path) |> ignore
                File.WriteAllText(vendorPath, vendor)
                let configuration =
                    { FirewalldModel.empty "settings" "strict-forward-ports" with StrictForwardPorts = Some true }
                    |> FirewalldModel.toJson
                FirewalldSettingsTestSupport.applyAndConfirm environment "legacy-vendor-owner" configuration |> ignore
                let current =
                    "StrictForwardPorts=yes\n"
                    + (if addition = "" then "LogDenied=all\n" else addition)
                File.WriteAllText(path, current)
                let journalPath = Path.Combine(root, "var/lib/keroosha-iac/firewalld/settings-strict-forward-ports.json")
                let journal = JsonNode.Parse(File.ReadAllText journalPath).AsObject()
                let baseline = JsonObject()
                baseline["etcExists"] <- JsonValue.Create false
                baseline["etcMode"] <- JsonValue.Create 0o600
                if compact then
                    baseline["etcStrictValue"] <- null
                else
                    baseline["version"] <- JsonValue.Create 3
                    baseline["key"] <- JsonValue.Create "StrictForwardPorts"
                    baseline["etcContents"] <- null
                    baseline["etcValue"] <- null
                    baseline["originEtcExists"] <- JsonValue.Create false
                    baseline["originVendorContents"] <- JsonValue.Create vendor
                    baseline["originVendorMode"] <- JsonValue.Create 0o644
                journal["baseline"] <- JsonValue.Create(baseline.ToJsonString())
                journal["managed"] <- JsonValue.Create(current: string)
                journal.Remove "settingsScopeVersion" |> ignore
                File.WriteAllText(journalPath, journal.ToJsonString())
                let staged = FirewalldSettingsTestSupport.invoke environment "delete" "legacy-vendor-owner" configuration None
                let nonce = staged["transactionNonce"].GetValue<string>()
                FirewalldSettingsTestSupport.invoke environment "confirm" "legacy-vendor-owner" configuration (Some nonce) |> ignore
                Assert.That(File.Exists path, Is.EqualTo expectedExists)
                if expectedExists then Assert.That(File.ReadAllText path, Is.EqualTo expectedContents))
        runCase "" false ""
        runCase "LogDenied=off\n# operator comment\n" true "LogDenied=off\n# operator comment\n"
    [<Test>]
    member _.``Settings read reports a non-root override owner``() =
        FirewalldSettingsTestSupport.withHost (fun _ _ -> None) (fun environment root _ ->
            let path = FirewalldSettingsTestSupport.settingsPath root
            Directory.CreateDirectory(Path.GetDirectoryName path) |> ignore
            let original = "ReloadPolicy=INPUT:REJECT,FORWARD:DROP,OUTPUT:DROP\n"
            File.WriteAllText(path, original)
            let configuration = FirewalldSettingsTestSupport.configuration "ReloadPolicy" "INPUT:REJECT,FORWARD:DROP,OUTPUT:DROP"
            FirewalldSettingsTestSupport.applyAndConfirm environment "owner-drift-owner" configuration |> ignore
            let changedOwner =
                { environment with
                    Run =
                        fun executable arguments input ->
                            if executable = "stat" && arguments = [ "-c"; "%u:%g"; "--"; path ] then
                                { ExitCode = 0; Stdout = "1000:0"; Stderr = "" }
                            else environment.Run executable arguments input }
            Assert.Throws<NativeFirewalldSettings.BackendError>(fun () -> FirewalldSettingsTestSupport.invoke changedOwner "read" "owner-drift-owner" configuration None |> ignore) |> ignore
            Assert.That(File.ReadAllText path, Is.EqualTo original))

    [<Test>]
    member _.``Owned observable setting drift is repaired and Delete restores only its original line``() =
        FirewalldSettingsTestSupport.withHost (fun _ _ -> None) (fun environment root _ ->
            let path = FirewalldSettingsTestSupport.settingsPath root
            Directory.CreateDirectory(Path.GetDirectoryName path) |> ignore
            let originalLine = "  LogDenied = off  "
            File.WriteAllText(path, "# initial comment\n" + originalLine + "\nDefaultZone=public\n")
            let owner = "log-denied-owner"
            let configuration = FirewalldSettingsTestSupport.configuration "LogDenied" "unicast"
            FirewalldSettingsTestSupport.applyAndConfirm environment owner configuration |> ignore
            File.WriteAllText(path, "DefaultZone=public\nLogDenied=all\n# foreign comment\n")
            File.SetUnixFileMode(path, enum<UnixFileMode> 0o600)
            let reload = environment.Run "firewall-cmd" [ "--reload" ] None
            Assert.That(reload.ExitCode, Is.EqualTo 0)
            let drift = FirewalldSettingsTestSupport.invoke environment "read" owner configuration None
            Assert.That(drift["inSync"].GetValue<bool>(), Is.False)
            Assert.That(drift["runtimeActual"].GetValue<string>(), Is.EqualTo "all")
            let repaired = FirewalldSettingsTestSupport.applyAndConfirm environment owner configuration
            Assert.That(repaired["inSync"].GetValue<bool>(), Is.True)
            Assert.That(int (File.GetUnixFileMode path), Is.EqualTo 0o600)
            Assert.That(File.ReadAllText path, Is.EqualTo "DefaultZone=public\nLogDenied=unicast\n# foreign comment\n")
            FirewalldSettingsTestSupport.invoke environment "delete" owner configuration None |> ignore
            Assert.That(int (File.GetUnixFileMode path), Is.EqualTo 0o600)
            Assert.That(File.ReadAllText path, Is.EqualTo("DefaultZone=public\n" + originalLine + "\n# foreign comment\n")))

    [<Test>]
    member _.``An absent key can be released without adding a newline to a foreign file``() =
        FirewalldSettingsTestSupport.withHost (fun _ _ -> None) (fun environment root _ ->
            let path = FirewalldSettingsTestSupport.settingsPath root
            File.WriteAllText(path, "# unterminated")
            let c = FirewalldSettingsTestSupport.configuration "LogDenied" "all"
            FirewalldSettingsTestSupport.applyAndConfirm environment "newline-owner" c |> ignore
            FirewalldSettingsTestSupport.invoke environment "delete" "newline-owner" c None |> ignore
            Assert.That(File.ReadAllText path, Is.EqualTo "# unterminated"))

    [<Test>]
    member _.``A default-valued setting has a logical owner despite an absent override``() =
        FirewalldSettingsTestSupport.withHost (fun _ _ -> None) (fun environment root _ ->
            let c = FirewalldSettingsTestSupport.configuration "LogDenied" "off"
            let result = FirewalldSettingsTestSupport.applyAndConfirm environment "default-owner" c
            Assert.That(result["exists"].GetValue<bool>(), Is.True)
            Assert.That(File.Exists(FirewalldSettingsTestSupport.settingsPath root), Is.False)
            let observed = FirewalldSettingsTestSupport.invoke environment "read" "default-owner" c None
            Assert.That(observed["inSync"].GetValue<bool>(), Is.True))

    [<Test>]
    member _.``Loaded strict detection ignores DNAT comments but rejects an ACCEPT bypass``() =
        FirewalldSettingsTestSupport.withHost
            (fun executable arguments ->
                match executable, arguments with
                | "nft", _ -> Some { ExitCode = 1; Stdout = ""; Stderr = "no nftables table" }
                | "iptables-save", [ "-t"; "filter" ]
                | "ip6tables-save", [ "-t"; "filter" ] -> Some(success (FirewalldSettingsTestSupport.strictIptablesRules false))
                | "/usr/bin/busctl", _ -> Some(success "b true")
                | _ -> None)
            (fun environment root _ ->
                let configPath = FirewalldSettingsTestSupport.settingsPath root
                Directory.CreateDirectory(Path.GetDirectoryName configPath) |> ignore
                File.WriteAllText(configPath, "StrictForwardPorts=yes\n")
                Assert.That(NativeFirewalldSettings.strictForwardPortsConfigured environment, Is.True)
                Assert.That(NativeFirewalldSettings.strictForwardPortsLoaded environment, Is.True))
        FirewalldSettingsTestSupport.withHost
            (fun executable arguments ->
                match executable, arguments with
                | "nft", _ -> Some { ExitCode = 1; Stdout = ""; Stderr = "no nftables table" }
                | "iptables-save", [ "-t"; "filter" ]
                | "ip6tables-save", [ "-t"; "filter" ] -> Some(success (FirewalldSettingsTestSupport.strictIptablesRules true))
                | "/usr/bin/busctl", _ -> Some(success "b true")
                | _ -> None)
            (fun environment _ _ -> Assert.That(NativeFirewalldSettings.strictForwardPortsLoaded environment, Is.False))
