namespace Dorothy.Tests

open System
open System.IO
open System.Security.Cryptography
open System.Text.Json
open System.Text.Json.Nodes
open Dorothy.HostHelper
open NUnit.Framework

module private Fail2BanTestRequests =
    let json (operation: string) (owner: string) (enabled: bool) (maxRetry: int) (findTimeSeconds: int) (banTimeSeconds: int) (ignoreIps: string list) (ports: int list) =
        let request = JsonObject()
        request["operation"] <- JsonValue.Create operation
        request["ownerId"] <- JsonValue.Create owner
        request["enabled"] <- JsonValue.Create enabled
        request["maxRetry"] <- JsonValue.Create maxRetry
        request["findTimeSeconds"] <- JsonValue.Create findTimeSeconds
        request["banTimeSeconds"] <- JsonValue.Create banTimeSeconds
        let ips = JsonArray()
        for ip in ignoreIps do ips.Add(JsonValue.Create ip)
        request["ignoreIps"] <- ips
        let portArray = JsonArray()
        for port in ports do portArray.Add(JsonValue.Create port)
        request["ports"] <- portArray
        request.ToJsonString()

    let invoke (environment: HostEnvironment) (request: string) =
        use document = JsonDocument.Parse request
        Fail2Ban.handle environment document.RootElement

[<Sealed>]
type private FakeFail2BanHost() =
    let temporary = new TemporaryDirectory("keroosha-fail2ban-")
    let root = temporary.Path
    let calls = ResizeArray<string * string list>()
    let mutable serviceEnabled = false
    let mutable serviceActive = false
    let mutable failValidationWhenOwned = false
    let mutable forceEffectiveSshdJail = false
    let mutable runtimeBanTimeOverride: int option = None
    let mutable runtimeActionBanOverride: string option = None
    let mutable runtimeIgnoreRegexOverride: string option = None
    let mutable runtimeActionsOverride: string array option = None
    let mutable dumpAdditionalAction = false
    let mutable dumpIgnoreRegex = false
    let mutable sshdOutput = "port 22\nport 2222\nlistenaddress 0.0.0.0:22\nlistenaddress [::]:22\nlistenaddress 0.0.0.0:2222\nlistenaddress [::]:2222\n"
    let mutable sshdExecReloadProperties =
        [| "ExecReload={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -t ; ignore_errors=no }"
           "ExecReload={ path=/bin/kill ; argv[]=/bin/kill -HUP $MAINPID ; ignore_errors=no }" |]
    let mutable packageConffiles = ""
    let stockFilterPath = Path.Combine(root, "etc", "fail2ban", "filter.d", "sshd.conf")
    let stockCommonFilterPath = Path.Combine(root, "etc", "fail2ban", "filter.d", "common.conf")
    let stockActionPath = Path.Combine(root, "etc", "fail2ban", "action.d", "nftables.conf")
    let digest path =
        MD5.HashData(File.ReadAllBytes path) |> Convert.ToHexString |> fun value -> value.ToLowerInvariant()
    let jailPath = Path.Combine(root, "etc", "fail2ban", "jail.d", "90-dorothy-sshd.local")
    let journalPath = Path.Combine(root, "var", "lib", "keroosha-iac", "fail2ban", "sshd.json")
    let path (logicalPath: string) = Path.Combine(root, logicalPath.TrimStart([| '/'; '\\' |]))

    let setting name =
        if not (File.Exists jailPath) then ""
        else
            File.ReadAllLines jailPath
            |> Array.tryPick (fun line ->
                let trimmed = line.Trim()
                let prefix = name + " ="
                if trimmed.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) then
                    Some(trimmed.Substring(prefix.Length).Trim())
                else None)
            |> Option.defaultValue ""

    let ignoreIps () =
        (setting "ignoreip").Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)

    let pythonString (value: string) =
        "'" + value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("'", "\\'", StringComparison.Ordinal).Replace("\r", "\\r", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal) + "'"

    let actionValues port =
        let actionStart =
            String.concat "\n" [
                "nft add table inet f2b-table"
                "nft -- add chain inet f2b-table f2b-chain \\{ type filter hook input priority -1 \\; \\}"
                "nft add set inet f2b-table <addr_set> \\{ type <addr_type>\\; \\}"
                "for proto in $(echo 'tcp' | sed 's/,/ /g'); do"
                "nft add rule inet f2b-table f2b-chain $proto dport \\{ $(echo '" + port + "' | sed s/:/-/g) \\} <addr_family> saddr @<addr_set> reject"
                "done"
            ]
        let actionStop =
            String.concat "\n" [
                "{ nft -a list chain inet f2b-table f2b-chain | grep -oP '@<addr_set>\\s+.*\\s+\\Khandle\\s+(\\d+)$'; } | while read -r hdl; do"
                "nft delete rule inet f2b-table f2b-chain $hdl; done"
                "nft delete set inet f2b-table <addr_set>"
                "{ nft list table inet f2b-table | grep -qP '^\\s+set\\s+'; } || {"
                "nft delete table inet f2b-table"
                "}"
            ]
        let actionCheck = "nft list chain inet f2b-table f2b-chain | grep -q '@<addr_set>[ \\t]'"
        [ "type", "multiport"
          "actionstart", actionStart
          "actionstop", actionStop
          "actioncheck", actionCheck
          "actionban", "nft add element inet f2b-table <addr_set> \\{ <ip> \\}"
          "actionunban", "nft delete element inet f2b-table <addr_set> \\{ <ip> \\}"
          "port", port
          "protocol", "tcp" ]

    let actionOutput property =
        match property with
        | "actionban" -> runtimeActionBanOverride |> Option.defaultValue (actionValues (setting "port") |> List.find (fun (name, _) -> name = property) |> snd)
        | _ -> actionValues (setting "port") |> List.tryPick (fun (name, value) -> if name = property then Some value else None) |> Option.defaultValue ""

    let policyDump () =
        if not (File.Exists jailPath) || (setting "enabled" <> "true" && not forceEffectiveSshdJail) then "[]\n"
        else
            let port = setting "port"
            let ignoreCommands = ignoreIps () |> Array.map (fun ip -> "['set', 'sshd', 'addignoreip', " + pythonString ip + "]")
            let actionProperties =
                actionValues port
                |> List.map (fun (name, value) -> "[" + pythonString name + ", " + pythonString value + "]")
                |> String.concat ", "
            let actionLine = "['multi-set', 'sshd', 'action', 'nftables', [" + actionProperties + "]]"
            let extraActions =
                if dumpAdditionalAction then [| "['set', 'sshd', 'addaction', 'allports']" |]
                else [||]
            let ignoreRegexCommand =
                if dumpIgnoreRegex then [| "['set', 'sshd', 'addignoreregex', '^Ignore this authentication failure$']" |]
                else [||]
            String.concat "\n" (Array.concat [
                [| "['add', 'sshd', 'systemd']"
                   "['set', 'sshd', 'usedns', 'no']"
                   "['set', 'sshd', 'maxretry', " + setting "maxretry" + "]"
                   "['set', 'sshd', 'findtime', " + pythonString (setting "findtime") + "]"
                   "['set', 'sshd', 'bantime', " + pythonString (setting "bantime") + "]" |]
                ignoreCommands
                [| "['set', 'sshd', 'addaction', 'nftables']"
                   actionLine |]
                extraActions
                ignoreRegexCommand
                [| "['multi-set', 'sshd', 'addfailregex', ['^Failed password for invalid user.*$', '^Invalid user .*$', '^Too many authentication failures.*$']]"
                   "['set', 'sshd', 'addjournalmatch', '_SYSTEMD_UNIT=ssh.service']"
                   "['set', 'sshd', 'addjournalmatch', '+']"
                   "['set', 'sshd', 'addjournalmatch', '_COMM=sshd']"
                   "['start', 'sshd']" |]
            ]) + "\n"

    let runtimeOutput field =
        match field with
        | "maxretry" -> setting "maxretry"
        | "findtime" -> setting "findtime"
        | "bantime" -> runtimeBanTimeOverride |> Option.map string |> Option.defaultValue (setting "bantime")
        | "usedns" -> setting "usedns"
        | "ignoreip" -> "The following IP addresses/networks are ignored:\n|- " + String.Join("\n|- ", ignoreIps ()) + "\n"
        | "failregex" -> "1) ^Failed password for invalid user.*$\n2) ^Invalid user .*$\n3) ^Too many authentication failures.*$\n"
        | "ignoreregex" -> runtimeIgnoreRegexOverride |> Option.defaultValue "No regular expression is defined\n"
        | "journalmatch" -> "Current match filter:\n_SYSTEMD_UNIT=ssh.service + _COMM=sshd\n"
        | _ -> ""

    let run executable arguments _ =
        calls.Add(executable, arguments)
        match executable, arguments with
        | "/usr/sbin/sshd", [ "-T" ] ->
            { ExitCode = 0; Stdout = sshdOutput; Stderr = "" }
        | "dpkg-query", [ "-W"; "-f=${Conffiles}"; "fail2ban" ] ->
            { ExitCode = 0; Stdout = packageConffiles; Stderr = "" }
        | "fail2ban-client", [ "--str2sec"; "10m" ] ->
            { ExitCode = 0; Stdout = "600\n"; Stderr = "" }
        | "fail2ban-client", [ "--str2sec"; "1h" ] ->
            { ExitCode = 0; Stdout = "3600\n"; Stderr = "" }
        | "fail2ban-client", [ "-t" ] when failValidationWhenOwned && File.Exists jailPath ->
            { ExitCode = 1; Stdout = ""; Stderr = "invalid jail configuration" }
        | "fail2ban-client", [ "-t" ] ->
            { ExitCode = 0; Stdout = "OK\n"; Stderr = "" }
        | "fail2ban-client", [ "-d" ] ->
            { ExitCode = 0; Stdout = policyDump (); Stderr = "" }
        | "systemctl", [ "show"; "--no-pager"; "--property=LoadState"; "--property=ActiveState"; "--property=ExecStart"; "--property=ExecReload"; "--property=Environment"; "--property=EnvironmentFiles"; "ssh.service" ] ->
            { ExitCode = 0
              Stdout =
                "LoadState=loaded\nActiveState=active\n"
                + "ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D $SSHD_OPTS ; ignore_errors=no }\n"
                + String.concat "\n" sshdExecReloadProperties
                + "\nEnvironment=\nEnvironmentFiles=/etc/default/ssh (ignore_errors=yes)\n"
              Stderr = "" }
        | "systemctl", [ "show"; "--no-pager"; "--property=LoadState"; "--property=UnitFileState"; "--property=ActiveState"; "ssh.socket" ] ->
            { ExitCode = 0; Stdout = "LoadState=not-found\nUnitFileState=disabled\nActiveState=inactive\n"; Stderr = "" }
        | "systemctl", [ "show"; "--no-pager"; "--property=LoadState"; "--property=UnitFileState"; "--property=ActiveState"; "fail2ban.service" ] ->
            { ExitCode = 0
              Stdout =
                "LoadState=loaded\nUnitFileState=" + (if serviceEnabled then "enabled" else "disabled")
                + "\nActiveState=" + (if serviceActive then "active" else "inactive") + "\n"
              Stderr = "" }
        | "systemctl", [ "enable"; "fail2ban.service" ] ->
            serviceEnabled <- true
            { ExitCode = 0; Stdout = ""; Stderr = "" }
        | "systemctl", [ "start"; "fail2ban.service" ] ->
            serviceActive <- true
            { ExitCode = 0; Stdout = ""; Stderr = "" }
        | "fail2ban-client", [ "reload" ] ->
            { ExitCode = 0; Stdout = "OK\n"; Stderr = "" }
        | "fail2ban-client", [ "status" ] ->
            let active = File.Exists jailPath && setting "enabled" = "true"
            { ExitCode = 0
              Stdout = "Status\n|- Number of jail: " + (if active then "1" else "0") + "\n`- Jail list: " + (if active then "sshd" else "") + "\n"
              Stderr = "" }
        | "fail2ban-client", [ "get"; "sshd"; "action"; "nftables"; property ] ->
            { ExitCode = 0; Stdout = actionOutput property; Stderr = "" }
        | "fail2ban-client", [ "get"; "sshd"; "actions" ] ->
            let actions = runtimeActionsOverride |> Option.defaultValue [| "nftables" |]
            { ExitCode = 0
              Stdout = "The jail sshd has the following actions:\n" + String.concat "\n" actions + "\n"
              Stderr = "" }
        | "fail2ban-client", [ "get"; "sshd"; field ] ->
            { ExitCode = 0; Stdout = runtimeOutput field; Stderr = "" }
        | _ ->
            { ExitCode = 99
              Stdout = ""
              Stderr = "unexpected command: " + executable + " " + String.concat " " arguments }
    do
        Directory.CreateDirectory(path "/run/lock") |> ignore
        Directory.CreateDirectory(path "/etc/default") |> ignore
        Directory.CreateDirectory(path "/etc/fail2ban/jail.d") |> ignore
        Directory.CreateDirectory(path "/etc/fail2ban/filter.d") |> ignore
        Directory.CreateDirectory(path "/etc/fail2ban/action.d") |> ignore
        Directory.CreateDirectory(path "/var/lib") |> ignore
        File.WriteAllText(path "/etc/services", "ssh 22/tcp\n")
        File.WriteAllText(path "/etc/default/ssh", "SSHD_OPTS=\"\"\n")
        File.WriteAllText(stockFilterPath, "packaged sshd filter\n")
        File.WriteAllText(stockCommonFilterPath, "packaged common filter\n")
        File.WriteAllText(stockActionPath, "packaged nftables action\n")
        packageConffiles <-
            "/etc/fail2ban/filter.d/sshd.conf " + digest stockFilterPath + "\n"
            + "/etc/fail2ban/filter.d/common.conf " + digest stockCommonFilterPath + "\n"
            + "/etc/fail2ban/action.d/nftables.conf " + digest stockActionPath + "\n"

    member _.Environment =
        TestSupport.fakeHostEnvironment root run (fun () -> DateTimeOffset.UnixEpoch)

    member _.Calls = calls.ToArray()
    member _.SshdOutput with get () = sshdOutput and set value = sshdOutput <- value
    member _.SshdExecReloadProperties with get () = sshdExecReloadProperties and set value = sshdExecReloadProperties <- value
    member _.RuntimeIgnoreRegexOverride with get () = runtimeIgnoreRegexOverride and set value = runtimeIgnoreRegexOverride <- value
    member _.RuntimeActionsOverride with get () = runtimeActionsOverride and set value = runtimeActionsOverride <- value
    member _.DumpAdditionalAction with get () = dumpAdditionalAction and set value = dumpAdditionalAction <- value
    member _.DumpIgnoreRegex with get () = dumpIgnoreRegex and set value = dumpIgnoreRegex <- value
    member _.ManagedPath = jailPath
    member _.JournalPath = journalPath
    member this.Path(logicalPath: string) = path logicalPath
    member _.FailValidationWhenOwned with get () = failValidationWhenOwned and set value = failValidationWhenOwned <- value
    member _.ForceEffectiveSshdJail with get () = forceEffectiveSshdJail and set value = forceEffectiveSshdJail <- value
    member _.RuntimeBanTimeOverride with get () = runtimeBanTimeOverride and set value = runtimeBanTimeOverride <- value
    member _.RuntimeActionBanOverride with get () = runtimeActionBanOverride and set value = runtimeActionBanOverride <- value

    member this.Invoke(request: string) = Fail2BanTestRequests.invoke this.Environment request

    interface IDisposable with
        member _.Dispose() = (temporary :> IDisposable).Dispose()

[<TestFixture>]
type Fail2BanTests() =
    let owner = "urn:pulumi:unit::unit::keroosha:debian:Fail2BanSshd::sshd"
    let desired enabled operation ports =
        Fail2BanTestRequests.json operation owner enabled 5 600 3600 [ "127.0.0.0/8"; "::1" ] ports

    [<Test>]
    member _.``Malformed ignore addresses fail before native commands``() =
        use host = new FakeFail2BanHost()
        let request = Fail2BanTestRequests.json "apply" owner true 5 600 3600 [ "example.test" ] [ 22; 2222 ]
        let action = TestDelegate(fun () -> host.Invoke request |> ignore)

        Assert.Throws<Fail2Ban.BackendError>(action) |> ignore
        Assert.That(host.Calls, Is.Empty)
        Assert.That(File.Exists host.ManagedPath, Is.False)

    [<Test>]
    member _.``Retry windows ban times ports and CIDR values are strictly bounded``() =
        use host = new FakeFail2BanHost()
        let invalidRequests =
            [ Fail2BanTestRequests.json "apply" owner true 0 600 3600 [ "127.0.0.0/8" ] [ 22 ]
              Fail2BanTestRequests.json "apply" owner true 5 0 3600 [ "127.0.0.0/8" ] [ 22 ]
              Fail2BanTestRequests.json "apply" owner true 5 600 0 [ "127.0.0.0/8" ] [ 22 ]
              Fail2BanTestRequests.json "apply" owner true 5 600 3600 [ "192.0.2.1/33" ] [ 22 ]
              Fail2BanTestRequests.json "apply" owner true 5 600 3600 [ "127.0.0.0/8" ] [ 0 ]
              Fail2BanTestRequests.json "apply" owner true 5 600 3600 [ "127.0.0.0/8" ] [ 22; 22 ]
              Fail2BanTestRequests.json "apply" owner true 5 600 3600 [ "0.0.0.0/0" ] [ 22 ]
              Fail2BanTestRequests.json "apply" owner true 5 600 3600 [ "192.0.2.1/0" ] [ 22 ]
              Fail2BanTestRequests.json "apply" owner true 5 600 3600 [ "0.0.0.0" ] [ 22 ]
              Fail2BanTestRequests.json "apply" owner true 5 600 3600 [ "0.0.0.0/32" ] [ 22 ]
              Fail2BanTestRequests.json "apply" owner true 5 600 3600 [ "::" ] [ 22 ]
              Fail2BanTestRequests.json "apply" owner true 5 600 3600 [ "::/128" ] [ 22 ]
              Fail2BanTestRequests.json "apply" owner true 5 600 3600 [ "::ffff:192.0.2.1/128" ] [ 22 ] ]
        for request in invalidRequests do
            let action = TestDelegate(fun () -> host.Invoke request |> ignore)
            Assert.Throws<Fail2Ban.BackendError>(action) |> ignore
        Assert.That(host.Calls, Is.Empty)

    [<Test>]
    member _.``Bare mapped IPv6 hosts and noncanonical networks normalize to IPv4 CIDRs``() =
        use host = new FakeFail2BanHost()
        let request =
            Fail2BanTestRequests.json "apply" owner true 5 600 3600
                [ "::ffff:192.0.2.1"; "192.0.2.129/24" ] [ 22; 2222 ]
        let snapshot = host.Invoke request
        let config = File.ReadAllText host.ManagedPath

        Assert.That(config, Does.Contain("ignoreip = 127.0.0.0/8 192.0.2.0/24 192.0.2.1 ::1"))
        Assert.That(snapshot["actualIgnoreIps"].ToJsonString(), Is.EqualTo("[\"127.0.0.0/8\",\"192.0.2.0/24\",\"192.0.2.1\",\"::1\"]"))
        Assert.That(snapshot["inSync"].GetValue<bool>(), Is.True)

    [<Test>]
    member _.``Observed mapped IPv6 CIDRs remain readable as runtime drift``() =
        use host = new FakeFail2BanHost()
        host.Invoke(desired true "apply" [ 22; 2222 ]) |> ignore
        let config = File.ReadAllText host.ManagedPath
        File.WriteAllText(host.ManagedPath, config.Replace("127.0.0.0/8 ::1", "::ffff:192.0.2.1/128", StringComparison.Ordinal))
        let snapshot = host.Invoke(desired true "read" [])

        Assert.That(snapshot["actualIgnoreIps"].ToJsonString(), Is.EqualTo("[\"::ffff:192.0.2.1/128\"]"))
        Assert.That(snapshot["inSync"].GetValue<bool>(), Is.False)

    [<Test>]
    member _.``Native sshd ExecReload validation sequence and HUP-only variant are accepted``() =
        use host = new FakeFail2BanHost()
        let snapshot = host.Invoke(desired true "read" [])
        Assert.That(snapshot["inSync"].GetValue<bool>(), Is.False)

        host.SshdExecReloadProperties <-
            [| "ExecReload={ path=/bin/kill ; argv[]=/bin/kill -HUP $MAINPID ; ignore_errors=no }" |]
        let hupOnlySnapshot = host.Invoke(desired true "read" [])
        Assert.That(hupOnlySnapshot["inSync"].GetValue<bool>(), Is.False)

    [<Test>]
    member _.``Unexpected sshd ExecReload commands are rejected``() =
        use host = new FakeFail2BanHost()
        host.SshdExecReloadProperties <-
            [| "ExecReload={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -t ; ignore_errors=no }"
               "ExecReload={ path=/usr/local/bin/kill ; argv[]=/usr/local/bin/kill -HUP $MAINPID ; ignore_errors=no }" |]
        let action = TestDelegate(fun () -> host.Invoke(desired true "read" []) |> ignore)

        Assert.Throws<Fail2Ban.BackendError>(action) |> ignore

    [<Test>]
    member _.``Stock common filter checksum is verified from dpkg conffiles``() =
        use host = new FakeFail2BanHost()
        let commonFilterPath = host.Path "/etc/fail2ban/filter.d/common.conf"
        File.WriteAllText(commonFilterPath, "locally modified common filter\n")
        let action = TestDelegate(fun () -> host.Invoke(desired true "read" []) |> ignore)

        Assert.Throws<Fail2Ban.BackendError>(action) |> ignore
        Assert.That(host.Calls |> Array.exists (fun (exe, args) -> exe = "dpkg-query" && args = [ "-W"; "-f=${Conffiles}"; "fail2ban" ]), Is.True)

    [<Test>]
    member _.``Listener ports come from all IPv4 and IPv6 listenaddress entries``() =
        use host = new FakeFail2BanHost()
        host.SshdOutput <-
            "port 22\nlistenaddress 192.0.2.10:22\nlistenaddress [2001:db8::1]:2222\nlistenaddress 0.0.0.0:2222\n"
        let snapshot = host.Invoke(desired true "apply" [ 22; 2222 ])

        Assert.That(snapshot["actualPorts"].ToJsonString(), Is.EqualTo("[22,2222]"))
        Assert.That(snapshot["inSync"].GetValue<bool>(), Is.True)
        Assert.That(host.Calls |> Array.exists (fun (exe, args) -> exe = "/usr/sbin/sshd" && args = [ "-T" ]), Is.True)

    [<Test>]
    member _.``Enabled false applies an owned disabled jail and starts the shared service``() =
        use host = new FakeFail2BanHost()
        let snapshot =
            host.Invoke(Fail2BanTestRequests.json "apply" owner false 5 600 3600 [ "127.0.0.1/8"; "::1" ] [ 22; 2222 ])
        let config = File.ReadAllText host.ManagedPath

        Assert.That(config.Contains("enabled = false", StringComparison.Ordinal), Is.True)
        Assert.That(config.Contains("ignoreip = 127.0.0.0/8 ::1", StringComparison.Ordinal), Is.True)
        Assert.That(snapshot["owned"].GetValue<bool>(), Is.True)
        Assert.That(snapshot["active"].GetValue<bool>(), Is.False)
        Assert.That(snapshot["inSync"].GetValue<bool>(), Is.True)
        Assert.That(snapshot["actualPorts"].ToJsonString(), Is.EqualTo("[22,2222]"))
        Assert.That(host.Calls |> Array.exists (fun (exe, args) -> exe = "systemctl" && args = [ "enable"; "fail2ban.service" ]), Is.True)
        Assert.That(host.Calls |> Array.exists (fun (exe, args) -> exe = "systemctl" && args = [ "start"; "fail2ban.service" ]), Is.True)
        Assert.That(host.Calls |> Array.exists (fun (exe, args) -> exe = "systemctl" && List.contains "stop" args), Is.False)
        Assert.That(host.Calls |> Array.exists (fun (exe, _) -> exe = "ufw" || exe = "nft" || exe = "apt"), Is.False)

    [<Test>]
    member _.``Native dump runtime policy and repeat apply converge without a second reload``() =
        use host = new FakeFail2BanHost()
        let first = host.Invoke(desired true "apply" [ 22; 2222 ])
        let reloadCount = host.Calls |> Array.filter (fun (exe, args) -> exe = "fail2ban-client" && args = [ "reload" ]) |> Array.length
        let second = host.Invoke(desired true "apply" [ 22; 2222 ])
        let reloadCountAfter = host.Calls |> Array.filter (fun (exe, args) -> exe = "fail2ban-client" && args = [ "reload" ]) |> Array.length

        Assert.That(first["inSync"].GetValue<bool>(), Is.True)
        Assert.That(second["inSync"].GetValue<bool>(), Is.True)
        Assert.That(second["active"].GetValue<bool>(), Is.True)
        Assert.That(second["actualMaxRetry"].GetValue<int>(), Is.EqualTo(5))
        Assert.That(second["actualFindTimeSeconds"].GetValue<int>(), Is.EqualTo(600))
        Assert.That(second["actualBanTimeSeconds"].GetValue<int>(), Is.EqualTo(3600))
        Assert.That(second["actualIgnoreIps"].ToJsonString(), Is.EqualTo("[\"127.0.0.0/8\",\"::1\"]"))
        Assert.That(reloadCountAfter, Is.EqualTo(reloadCount))
        Assert.That(host.Calls |> Array.exists (fun (exe, args) -> exe = "/usr/sbin/sshd" && args = [ "-T" ]), Is.True)

    [<Test>]
    member _.``Runtime actionban changes are reported as policy drift``() =
        use host = new FakeFail2BanHost()
        host.Invoke(desired true "apply" [ 22; 2222 ]) |> ignore
        host.RuntimeActionBanOverride <- Some "nft add element inet f2b-table unexpected-set \\{ <ip> \\}"
        let snapshot = host.Invoke(desired true "read" [])

        Assert.That(snapshot["inSync"].GetValue<bool>(), Is.False)
        Assert.That(host.Calls |> Array.exists (fun (exe, args) -> exe = "fail2ban-client" && args = [ "get"; "sshd"; "action"; "nftables"; "actionban" ]), Is.True)

    [<Test>]
    member _.``Nonempty runtime ignoreregex is reported as policy drift``() =
        use host = new FakeFail2BanHost()
        host.Invoke(desired true "apply" [ 22; 2222 ]) |> ignore
        host.RuntimeIgnoreRegexOverride <- Some "1) ^Ignore this authentication failure$"
        let snapshot = host.Invoke(desired true "read" [])

        Assert.That(snapshot["inSync"].GetValue<bool>(), Is.False)
        Assert.That(host.Calls |> Array.exists (fun (exe, args) -> exe = "fail2ban-client" && args = [ "get"; "sshd"; "ignoreregex" ]), Is.True)

    [<Test>]
    member _.``Nonempty effective ignoreregex is reported as policy drift``() =
        use host = new FakeFail2BanHost()
        host.Invoke(desired true "apply" [ 22; 2222 ]) |> ignore
        host.DumpIgnoreRegex <- true
        let snapshot = host.Invoke(desired true "read" [])

        Assert.That(snapshot["inSync"].GetValue<bool>(), Is.False)

    [<Test>]
    member _.``Multiple effective or runtime actions are reported as policy drift``() =
        use host = new FakeFail2BanHost()
        host.Invoke(desired true "apply" [ 22; 2222 ]) |> ignore
        host.DumpAdditionalAction <- true
        host.RuntimeActionsOverride <- Some [| "nftables"; "allports" |]
        let snapshot = host.Invoke(desired true "read" [])

        Assert.That(snapshot["inSync"].GetValue<bool>(), Is.False)
        Assert.That(host.Calls |> Array.exists (fun (exe, args) -> exe = "fail2ban-client" && args = [ "get"; "sshd"; "actions" ]), Is.True)

    [<Test>]
    member _.``Observed ten-minute duration is converted from native Fail2Ban syntax``() =
        use host = new FakeFail2BanHost()
        host.Invoke(desired true "apply" [ 22; 2222 ]) |> ignore
        let config = File.ReadAllText host.ManagedPath
        File.WriteAllText(host.ManagedPath, config.Replace("findtime = 600", "findtime = 10m", StringComparison.Ordinal))
        let snapshot = host.Invoke(desired true "read" [])

        Assert.That(snapshot["actualFindTimeSeconds"].GetValue<int>(), Is.EqualTo(600))
        Assert.That(snapshot["inSync"].GetValue<bool>(), Is.False)
        Assert.That(host.Calls |> Array.exists (fun (exe, args) -> exe = "fail2ban-client" && args = [ "--str2sec"; "10m" ]), Is.True)

    [<Test>]
    member _.``Permanent runtime ban time is reported as drift instead of an invalid snapshot``() =
        use host = new FakeFail2BanHost()
        host.Invoke(desired true "apply" [ 22; 2222 ]) |> ignore
        host.RuntimeBanTimeOverride <- Some -1
        let snapshot = host.Invoke(desired true "read" [])

        Assert.That(snapshot["actualBanTimeSeconds"].GetValue<int>(), Is.EqualTo(-1))
        Assert.That(snapshot["active"].GetValue<bool>(), Is.True)
        Assert.That(snapshot["inSync"].GetValue<bool>(), Is.False)

    [<Test>]
    member _.``Invalid complete configuration rolls back the override and ownership journal``() =
        use host = new FakeFail2BanHost()
        host.FailValidationWhenOwned <- true
        let otherPath = host.Path "/etc/fail2ban/jail.d/10-operator.local"
        let otherConfig = "[other]\nenabled = true\n"
        File.WriteAllText(otherPath, otherConfig)
        let action = TestDelegate(fun () -> host.Invoke(desired true "apply" [ 22; 2222 ]) |> ignore)

        Assert.Throws<Fail2Ban.BackendError>(action) |> ignore
        Assert.That(File.Exists host.ManagedPath, Is.False)
        Assert.That(File.Exists host.JournalPath, Is.False)
        Assert.That(File.ReadAllText otherPath, Is.EqualTo(otherConfig))
        Assert.That(host.Calls |> Array.exists (fun (exe, args) -> exe = "systemctl" && args = [ "start"; "fail2ban.service" ]), Is.False)

    [<Test>]
    member _.``Later effective config cannot re-enable a disabled managed jail``() =
        use host = new FakeFail2BanHost()
        host.ForceEffectiveSshdJail <- true
        let action = TestDelegate(fun () -> host.Invoke(desired false "apply" [ 22; 2222 ]) |> ignore)

        Assert.Throws<Fail2Ban.BackendError>(action) |> ignore
        Assert.That(File.Exists host.ManagedPath, Is.False)
        Assert.That(File.Exists host.JournalPath, Is.False)
        Assert.That(host.Calls |> Array.exists (fun (exe, args) -> exe = "systemctl" && (args = [ "enable"; "fail2ban.service" ] || args = [ "start"; "fail2ban.service" ])), Is.False)

    [<Test>]
    member _.``Delete removes only the managed override and reloads the retained baseline``() =
        use host = new FakeFail2BanHost()
        let baselinePath = host.Path "/etc/fail2ban/jail.d/10-operator.local"
        let baseline = "[other]\nenabled = true\n"
        File.WriteAllText(baselinePath, baseline)
        host.Invoke(desired true "apply" [ 22; 2222 ]) |> ignore
        let removed = host.Invoke(desired true "delete" [])

        let reloadCount = host.Calls |> Array.filter (fun (exe, args) -> exe = "fail2ban-client" && args = [ "reload" ]) |> Array.length
        let removedAgain = host.Invoke(desired true "delete" [])
        let reloadCountAfter = host.Calls |> Array.filter (fun (exe, args) -> exe = "fail2ban-client" && args = [ "reload" ]) |> Array.length
        Assert.That(removedAgain.AsObject().Count, Is.EqualTo(0))
        Assert.That(reloadCountAfter, Is.EqualTo(reloadCount))
        Assert.That(removed.AsObject().Count, Is.EqualTo(0))
        Assert.That(File.Exists host.ManagedPath, Is.False)
        Assert.That(File.Exists host.JournalPath, Is.False)
        Assert.That(File.ReadAllText baselinePath, Is.EqualTo(baseline))
        Assert.That(host.Calls |> Array.exists (fun (exe, args) -> exe = "fail2ban-client" && args = [ "reload" ]), Is.True)
        Assert.That(host.Calls |> Array.exists (fun (exe, args) -> exe = "systemctl" && List.contains "stop" args), Is.False)

    [<Test>]
    member _.``Read observes an interrupted apply and delete recovers without touching other jails``() =
        use host = new FakeFail2BanHost()
        let baselinePath = host.Path "/etc/fail2ban/jail.d/10-operator.local"
        let baseline = "[other]\nenabled = true\n"
        File.WriteAllText(baselinePath, baseline)
        host.Invoke(desired true "apply" [ 22; 2222 ]) |> ignore
        let journal = JsonNode.Parse(File.ReadAllText host.JournalPath).AsObject()
        let managedContent = journal["managedContent"].GetValue<string>()
        journal["managedContent"] <- null
        let pending = JsonObject()
        pending["operation"] <- JsonValue.Create "apply"
        pending["priorContent"] <- null
        pending["targetContent"] <- JsonValue.Create managedContent
        journal["pending"] <- pending
        File.WriteAllText(host.JournalPath, journal.ToJsonString())
        File.SetUnixFileMode(host.JournalPath, UnixFileMode.UserRead ||| UnixFileMode.UserWrite)
        let pendingJournal = File.ReadAllText host.JournalPath

        let snapshot = host.Invoke(desired true "read" [])
        Assert.That(snapshot["owned"].GetValue<bool>(), Is.True)
        Assert.That(snapshot["inSync"].GetValue<bool>(), Is.False)
        Assert.That(File.ReadAllText host.ManagedPath, Is.EqualTo(managedContent))
        Assert.That(File.ReadAllText host.JournalPath, Is.EqualTo(pendingJournal))

        host.Invoke(desired true "delete" []) |> ignore

        let afterDelete = host.Invoke(desired true "read" [])
        Assert.That(afterDelete["owned"].GetValue<bool>(), Is.False)
        Assert.That(File.Exists host.ManagedPath, Is.False)
        Assert.That(File.Exists host.JournalPath, Is.False)
        Assert.That(File.ReadAllText baselinePath, Is.EqualTo(baseline))
        Assert.That(host.Calls |> Array.exists (fun (exe, args) -> exe = "fail2ban-client" && args = [ "reload" ]), Is.True)

    [<Test>]
    member _.``Foreign override and journal drift are never overwritten or deleted``() =
        use foreignHost = new FakeFail2BanHost()
        let foreign = "[sshd]\nenabled = false\n# operator-owned\n"
        File.WriteAllText(foreignHost.ManagedPath, foreign)
        let applyForeign = TestDelegate(fun () -> foreignHost.Invoke(desired true "apply" [ 22; 2222 ]) |> ignore)
        let deleteForeign = TestDelegate(fun () -> foreignHost.Invoke(desired true "delete" []) |> ignore)
        Assert.Throws<Fail2Ban.BackendError>(applyForeign) |> ignore
        Assert.Throws<Fail2Ban.BackendError>(deleteForeign) |> ignore
        Assert.That(File.ReadAllText foreignHost.ManagedPath, Is.EqualTo(foreign))

        use driftedHost = new FakeFail2BanHost()
        driftedHost.Invoke(desired true "apply" [ 22; 2222 ]) |> ignore
        let content = File.ReadAllText driftedHost.ManagedPath
        let driftedContent = content.Replace("maxretry = 5", "maxretry = 7", StringComparison.Ordinal).Replace("port = 22,2222", "port = 22", StringComparison.Ordinal)
        File.WriteAllText(driftedHost.ManagedPath, driftedContent)
        let snapshot = driftedHost.Invoke(desired true "read" [])
        let applyDrift = TestDelegate(fun () -> driftedHost.Invoke(desired true "apply" [ 22; 2222 ]) |> ignore)
        let deleteDrift = TestDelegate(fun () -> driftedHost.Invoke(desired true "delete" []) |> ignore)

        Assert.That(snapshot["owned"].GetValue<bool>(), Is.True)
        Assert.That(snapshot["inSync"].GetValue<bool>(), Is.False)
        Assert.That(snapshot["actualMaxRetry"].GetValue<int>(), Is.EqualTo(7))
        Assert.That(snapshot["actualPorts"].ToJsonString(), Is.EqualTo("[22]"))
        Assert.Throws<Fail2Ban.BackendError>(applyDrift) |> ignore
        Assert.Throws<Fail2Ban.BackendError>(deleteDrift) |> ignore
        Assert.That(File.ReadAllText driftedHost.ManagedPath, Does.Contain("maxretry = 7"))

    [<Test>]
    member _.``Stale declared sshd ports fail before a jail mutation``() =
        use host = new FakeFail2BanHost()
        let action = TestDelegate(fun () -> host.Invoke(desired true "apply" [ 2222 ]) |> ignore)

        Assert.Throws<Fail2Ban.BackendError>(action) |> ignore
        Assert.That(File.Exists host.ManagedPath, Is.False)
        Assert.That(host.Calls |> Array.exists (fun (exe, args) -> exe = "/usr/sbin/sshd" && args = [ "-T" ]), Is.True)
        Assert.That(host.Calls |> Array.exists (fun (exe, _) -> exe = "fail2ban-client"), Is.False)
