namespace Dorothy.Tests

open System
open System.Collections.Generic
open System.Collections.Immutable
open System.IO
open System.Text.Json
open System.Threading
open Dorothy.DSL
open Dorothy.DSL.Firewalld
open Dorothy.DSL.Provider
open NUnit.Framework
open Pulumi.Experimental
open Pulumi.Experimental.Provider

module NativeFirewalld = Dorothy.HostHelper.Firewalld

[<TestFixture; NonParallelizable>]
type FirewalldTests() =
    let xml = "<zone><service name=\"ssh\"/><interface name=\"eth0\"/></zone>"
    let context = NativeFirewalld.parseSshContext "192.0.2.1 49200 192.0.2.2 22" "[{\"dev\":\"eth0\"}]"
    let service name = if name = "ssh" then Some "<service><port port=\"22\" protocol=\"tcp\"/></service>" else None
    let guard ssh zones policies = NativeFirewalld.validateSshGuard ssh "public" zones policies service
    let map entries =
        ImmutableDictionary.CreateRange<string, PropertyValue>(entries |> Seq.map (fun (k, v) -> KeyValuePair(k, v)))
    let inputs (configuration: string) =
        map [ "connection", PropertyValue(map [ "address", PropertyValue "192.0.2.2"; "user", PropertyValue "root" ])
              "configuration", PropertyValue configuration ]
    let urn token = Pulumi.Urn("urn:pulumi:test::test::" + token + "::firewall")
    let zoneConfiguration = (zone "external" { services [ "ssh" ]; interfaces [ "eth0" ] }).Configuration
    let strictConfiguration =
        { FirewalldModel.empty "settings" "strict-forward-ports" with StrictForwardPorts = Some true }
        |> FirewalldModel.toJson
    // Upstream firewalld v2.3.1, as shipped in Debian 13.
    let vendorPolicy = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures/Firewalld/allow-host-ipv6.xml"))

    [<Test>]
    member _.``Lain topology expresses full zone and policy ownership``() =
        let spec =
            firewalld {
                zone "external" {
                    services [ "http"; "https"; "ssh" ]
                    interfaces [ "enp0s3" ]
                    ports [ 8443, Tcp; 222, Tcp; 51280, Udp; 51821, Udp ]
                    forward true
                }
                zone "lainvpn-public" {
                    target FirewalldTarget.Drop
                    interfaces [ "wg-lain-public" ]
                    services [ "ssh"; "http"; "https" ]
                    ports [ 222, Tcp ]
                }
                zone "trusted" { target FirewalldTarget.Accept; interfaces [ "wg-lain" ]; forward true }
                policy "lvpn2ext" {
                    ingressZones [ "lainvpn-public" ]; egressZones [ "external" ]
                    target FirewalldTarget.Accept; masquerade true; priority -2
                }
                policy "lvpnblkdoc" {
                    ingressZones [ "lainvpn-public" ]; egressZones [ "docker" ]
                    target FirewalldTarget.Drop; priority -10
                }
                policy "lvpnblktr" {
                    ingressZones [ "lainvpn-public" ]; egressZones [ "trusted" ]
                    target FirewalldTarget.Drop; priority -10
                }
            }
        let configs = spec.Objects |> List.map (fun value -> FirewalldModel.parse value.Configuration)
        let nat = configs |> List.find (fun c -> c.Name = "lvpn2ext")
        Assert.That(nat.Masquerade, Is.True)
        Assert.That(nat.Target, Is.EqualTo "ACCEPT")
        let blockers = configs |> List.filter (fun c -> c.Kind = "policy" && c.Target = "DROP")
        Assert.That(blockers |> List.forall (fun c -> c.Priority < -1), Is.True)
        let external = configs |> List.find (fun c -> c.Name = "external")
        Assert.That(external.Ports, Is.EquivalentTo [ "8443/tcp"; "222/tcp"; "51280/udp"; "51821/udp" ])

    [<Test>]
    member _.``Debian rejects competing firewalls and duplicate firewalld blocks``() =
        Assert.Throws<ArgumentException>(fun () -> debian { ufw { }; firewalld { } } |> ignore) |> ignore
        Assert.Throws<ArgumentException>(fun () -> debian { firewalld { }; firewalld { } } |> ignore) |> ignore

    [<Test>]
    member _.``DSL rejects duplicate names interfaces singleton fields and unsupported settings``() =
        let invalid =
            [ (fun () -> firewalld { zone "a" { }; zone "a" { } } |> ignore)
              (fun () -> firewalld { zone "a" { interfaces [ "wg0" ] }; zone "b" { interfaces [ "wg0" ] } } |> ignore)
              (fun () -> zone "a" { services []; services [] } |> ignore)
              (fun () -> zone "../a" { } |> ignore)
              (fun () -> zone "a" { ports [ 0, Tcp ] } |> ignore)
              (fun () -> zone "a" { priority -1 } |> ignore)
              (fun () -> policy "a" { ingressZones [ "ANY"; "public" ]; egressZones [ "external" ] } |> ignore)
              (fun () -> policy "a" { ingressZones [ "public" ]; egressZones [ "external" ]; priority 0 } |> ignore)
              (fun () -> policy "a" { ingressZones [ "public" ]; egressZones [ "external" ]; forward false } |> ignore) ]
        for action in invalid do Assert.Throws<ArgumentException>(TestDelegate action) |> ignore

    [<Test>]
    member _.``Permanent XML comparison accounts for metadata as well as filtering``() =
        let reordered = "<zone version=\"1\" target=\"default\"><short>External</short><interface name=\"eth0\"/><service name=\"ssh\"/></zone>"
        Assert.That(NativeFirewalld.canonicalXml "zone" xml, Is.Not.EqualTo(NativeFirewalld.canonicalXml "zone" reordered))
        let rich = "<zone><service name=\"ssh\"/><interface name=\"eth0\"/><rule><drop/></rule></zone>"
        Assert.That(NativeFirewalld.canonicalXml "zone" xml, Is.Not.EqualTo(NativeFirewalld.canonicalXml "zone" rich))
        Assert.Throws<System.Xml.XmlException>(fun () -> NativeFirewalld.parseXml "zone" "<!DOCTYPE zone [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><zone>&x;</zone>" |> ignore) |> ignore

    [<Test>]
    member _.``Guard honors current SSH port ranges services protocols and IPv6 route``() =
        guard context (Map.ofList [ "public", xml ]) Map.empty
        let custom = { context with Port = 2222 }
        Assert.Throws<NativeFirewalld.BackendError>(fun () -> guard custom (Map.ofList [ "public", xml ]) Map.empty) |> ignore
        let range = "<zone><port port=\"2200-2300\" protocol=\"tcp\"/></zone>"
        guard custom (Map.ofList [ "public", range ]) Map.empty
        guard custom (Map.ofList [ "public", "<zone><protocol value=\"tcp\"/></zone>" ]) Map.empty
        let ipv6 = NativeFirewalld.parseSshContext "2001:db8::1 34567 2001:db8::2 2222" "[{\"dev\":\"wg0\"}]"
        guard ipv6 (Map.ofList [ "public", range ]) Map.empty
        Assert.That(ipv6.Interface, Is.EqualTo "wg0")
        Assert.Throws<NativeFirewalld.BackendError>(fun () -> NativeFirewalld.parseSshContext "" "[]" |> ignore) |> ignore

    [<Test>]
    member _.``Guard evaluates final interface zone and rejects ambiguous or blocking policy state``() =
        let unsafe = "<zone target=\"DROP\"><interface name=\"eth0\"/></zone>"
        Assert.Throws<NativeFirewalld.BackendError>(fun () -> guard context (Map.ofList [ "public", "<zone target=\"ACCEPT\"/>"; "vpn", unsafe ]) Map.empty) |> ignore
        let source = "<zone><source address=\"192.0.2.0/24\"/></zone>"
        Assert.Throws<NativeFirewalld.BackendError>(fun () -> guard context (Map.ofList [ "public", xml; "source", source ]) Map.empty) |> ignore
        let drop = "<policy target=\"DROP\"><ingress-zone name=\"ANY\"/><egress-zone name=\"HOST\"/></policy>"
        Assert.Throws<NativeFirewalld.BackendError>(fun () -> guard context (Map.ofList [ "public", xml ]) (Map.ofList [ "block", drop ])) |> ignore
        let forwardDrop = "<policy target=\"DROP\"><ingress-zone name=\"public\"/><egress-zone name=\"docker\"/></policy>"
        guard context (Map.ofList [ "public", xml ]) (Map.ofList [ "block", forwardDrop ])

    [<Test>]
    member _.``Guard does not assume a service named ssh allows custom or destination restricted traffic``() =
        let restricted _ = Some "<service><destination ipv4=\"192.0.2.99\"/><port port=\"22\" protocol=\"tcp\"/></service>"
        Assert.Throws<NativeFirewalld.BackendError>(fun () -> NativeFirewalld.validateSshGuard context "public" (Map.ofList [ "public", xml ]) Map.empty restricted) |> ignore

    [<Test>]
    member _.``Check and preview validate without SSH and canonicalize set order``() =
        let provider = DorothyProvider()
        let token = FirewalldProvider.ZoneToken
        let check = CheckRequest(urn token, ImmutableDictionary.Empty, inputs zoneConfiguration, ImmutableArray<byte>.Empty)
        let result = provider.Check(check, CancellationToken.None).Result
        Assert.That(result.Failures, Is.Empty)
        let invalid = CheckRequest(urn token, ImmutableDictionary.Empty, inputs "{}", ImmutableArray<byte>.Empty)
        Assert.That(provider.Check(invalid, CancellationToken.None).Result.Failures, Is.Not.Empty)
        let create = CreateRequest(urn token, inputs zoneConfiguration, TimeSpan.Zero, true)
        let preview = provider.Create(create, CancellationToken.None).Result
        Assert.That(preview.Id, Is.Empty)
        Assert.That(preview.Outputs["inSync"].IsComputed, Is.True)
        let settingsCheck =
            CheckRequest(urn FirewalldProvider.SettingsToken, ImmutableDictionary.Empty, inputs strictConfiguration, ImmutableArray<byte>.Empty)
        Assert.That(provider.Check(settingsCheck, CancellationToken.None).Result.Failures, Is.Empty)
        let settingsPreview =
            provider.Create(CreateRequest(urn FirewalldProvider.SettingsToken, inputs strictConfiguration, TimeSpan.Zero, true), CancellationToken.None).Result
        Assert.That(settingsPreview.Id, Is.Empty)

    [<Test>]
    member _.``Diff repairs drift replaces renamed zones and never contacts SSH``() =
        let provider = DorothyProvider()
        let token = FirewalldProvider.ZoneToken
        let oldInputs = inputs zoneConfiguration
        let oldOutputs = map [ "inSync", PropertyValue false; "exists", PropertyValue true; "actual", PropertyValue xml ]
        let request = DiffRequest(urn token, "owner", oldOutputs, oldInputs, ImmutableArray<string>.Empty, oldInputs)
        let drift = provider.Diff(request, CancellationToken.None).Result
        Assert.That(drift.Changes.Value, Is.True)
        Assert.That(drift.DetailedDiff["inSync"].InputDiff, Is.False)
        let renamed = (zone "renamed" { services [ "ssh" ]; interfaces [ "eth0" ] }).Configuration
        let changed = DiffRequest(urn token, "owner", oldOutputs.SetItem("inSync", PropertyValue true), inputs renamed, ImmutableArray<string>.Empty, oldInputs)
        Assert.That(provider.Diff(changed, CancellationToken.None).Result.Replaces, Does.Contain "configuration")
        let same = DiffRequest(urn token, "owner", oldOutputs.SetItem("inSync", PropertyValue true), oldInputs, ImmutableArray<string>.Empty, oldInputs)
        Assert.That(provider.Diff(changed, CancellationToken.None).Result.DeleteBeforeReplace, Is.False)
        Assert.That(provider.Diff(same, CancellationToken.None).Result.Changes.Value, Is.False)

    [<Test>]
    member _.``New provider can preview a checkpoint with only the legacy firewalld observations``() =
        // Prior provider's wire payload and outputs; do not construct them using the current serializer.
        let previous = """{"kind":"settings","name":"strict-forward-ports","target":"CONTINUE","interfaces":[],"services":[],"ports":[],"protocols":[],"ingress":[],"egress":[],"masquerade":false,"forward":false,"strictForwardPorts":true,"priority":-1}"""
        let oldInputs = inputs previous
        let oldOutputs = oldInputs.SetItems(map [ "actual", PropertyValue "yes"; "exists", PropertyValue true; "inSync", PropertyValue true ])
        let provider = DorothyProvider()
        let token = FirewalldProvider.SettingsToken
        let diff = DiffRequest(urn token, "legacy-generation", oldOutputs, inputs strictConfiguration, ImmutableArray<string>.Empty, oldInputs)
        let migrated = provider.Diff(diff, CancellationToken.None).Result
        Assert.That(migrated.Changes.Value, Is.False)
        Assert.That(migrated.Replaces, Is.Empty)
        let unknown = (inputs strictConfiguration).SetItem("configuration", PropertyValue.Computed)
        let pending = provider.Create(CreateRequest(urn token, unknown, TimeSpan.Zero, true), CancellationToken.None).Result
        for key in [ "configuration"; "permanentInSync"; "runtimeInSync" ] do
            Assert.That(pending.Outputs[key].IsComputed, Is.True, key)

    [<Test>]
    member _.``Provider advertises each new definition and rejects it under the wrong resource token``() =
        use schema = JsonDocument.Parse FirewalldProvider.Schema
        let resources = schema.RootElement.GetProperty("resources")
        let provider = DorothyProvider()
        let configurations =
            [ "FirewalldService", { FirewalldModel.empty "service" "app" with Ports = [ "8443/tcp" ] }
              "FirewalldIPSet", { FirewalldModel.empty "ipset" "clients" with Attributes = Map.ofList [ "type", "hash:net" ] }
              "FirewalldIcmpType", FirewalldModel.empty "icmptype" "echo-request"
              "FirewalldHelper", { FirewalldModel.empty "helper" "alt-ftp" with Attributes = Map.ofList [ "module", "nf_conntrack_ftp" ]; Ports = [ "2121/tcp" ] } ]
        for suffix, config in configurations do
            let token = "keroosha:debian:" + suffix
            let check resourceToken =
                let request = CheckRequest(urn resourceToken, ImmutableDictionary.Empty, inputs (FirewalldModel.toJson config), ImmutableArray<byte>.Empty)
                provider.Check(request, CancellationToken.None).Result
            let properties = resources.GetProperty(token).GetProperty("properties")
            for observation in [ "permanentInSync"; "runtimeInSync" ] do
                Assert.That(properties.GetProperty(observation).GetProperty("type").GetString(), Is.EqualTo "boolean")
            Assert.That((check token).Failures, Is.Empty, suffix)
            Assert.That((check FirewalldProvider.ZoneToken).Failures, Is.Not.Empty, suffix)

    member private _.WithHost(action: Dorothy.HostHelper.HostEnvironment -> string -> ResizeArray<string list> -> unit) =
        let root = Path.Combine(Path.GetTempPath(), "dorothy-firewalld-" + Guid.NewGuid().ToString("N"))
        let previous = Environment.GetEnvironmentVariable "SSH_CONNECTION"
        try
            for directory in [ "etc/firewalld/zones"; "etc/firewalld/policies"; "usr/lib/firewalld/zones"; "usr/lib/firewalld/services"; "usr/lib/firewalld/policies"; "run/lock"; "var/lib" ] do
                Directory.CreateDirectory(Path.Combine(root, directory)) |> ignore
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/zones/public.xml"), "<zone><service name=\"ssh\"/></zone>")
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/zones/trusted.xml"), "<zone target=\"ACCEPT\"/>")
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/zones/external.xml"), "<zone><service name=\"ssh\"/><masquerade/></zone>")
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/services/ssh.xml"), "<service><port port=\"22\" protocol=\"tcp\"/></service>")
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/policies/allow-host-ipv6.xml"), vendorPolicy)
            Environment.SetEnvironmentVariable("SSH_CONNECTION", "192.0.2.1 49200 192.0.2.2 22")
            let calls = ResizeArray<string list>()
            let activated = FirewalldCommandFixture.commands root
            let run executable arguments _ : Dorothy.HostHelper.CommandResult =
                calls.Add(executable :: arguments)
                let output =
                    match activated executable arguments with
                    | Some text -> text
                    | None ->
                      match executable, arguments with
                      | "stat", [ "-c"; "%u:%g"; "--"; _ ] -> "0:0"
                      | "stat", _ ->
                          let mode = File.GetUnixFileMode(List.last arguments) |> int |> fun value -> Convert.ToString(value, 8)
                          "0:" + mode
                      | "ip", _ -> "[{\"dev\":\"eth0\"}]"
                      | "firewall-cmd", [ "--state" ] -> "running"
                      | "firewall-cmd", [ "--check-config" ] -> "success"
                      | ("systemctl" | "/usr/bin/systemctl"), [ "is-active"; "firewalld.service" ] -> "active"
                      | ("systemctl" | "/usr/bin/systemctl"), _ -> ""
                      | _ -> failwith ("Unexpected fixture command: " + String.concat " " (executable :: arguments))
                let exitCode = if output = "no zone\n" then 2 else 0
                { ExitCode = exitCode; Stdout = output; Stderr = "" }
            let environment: Dorothy.HostHelper.HostEnvironment = { Root = root; Run = run; UtcNow = fun () -> DateTimeOffset.UnixEpoch }
            action environment root calls
        finally
            Environment.SetEnvironmentVariable("SSH_CONNECTION", previous)
            if Directory.Exists root then Directory.Delete(root, true)

    member private _.InvokeOwner environment owner operation configuration =
        let node = System.Text.Json.Nodes.JsonObject()
        node["operation"] <- System.Text.Json.Nodes.JsonValue.Create(operation: string)
        node["ownerId"] <- System.Text.Json.Nodes.JsonValue.Create(owner: string)
        node["configuration"] <- System.Text.Json.Nodes.JsonValue.Create(configuration: string)
        let call () =
            use document = JsonDocument.Parse(node.ToJsonString())
            NativeFirewalld.handle environment document.RootElement
        let result = call ()
        if operation = "apply" || operation = "delete" then
            match result["transactionNonce"] with
            | null when operation = "apply" && result.AsObject().ContainsKey("unchanged") ->
                Assert.That(result["unchanged"].GetValue<bool>(), Is.True)
                node["operation"] <- System.Text.Json.Nodes.JsonValue.Create "read"
                call ()
            | null -> result
            | nonce ->
                node["operation"] <- System.Text.Json.Nodes.JsonValue.Create "confirm"
                node["transactionNonce"] <- nonce.DeepClone()
                call () |> ignore
                if operation = "delete" then System.Text.Json.Nodes.JsonObject() :> System.Text.Json.Nodes.JsonNode
                else
                    node.Remove "transactionNonce" |> ignore
                    node["operation"] <- System.Text.Json.Nodes.JsonValue.Create "read"
                    call ()
        else result

    member private this.Invoke environment operation configuration =
        this.InvokeOwner environment "test-owner" operation configuration

    [<Test>]
    member this.``Pending confirmation does not report drift in unrelated objects``() =
        this.WithHost(fun env _ _ ->
            this.InvokeOwner env "stable-owner" "apply" zoneConfiguration |> ignore
            let next = (zone "waiting" { target FirewalldTarget.Drop }).Configuration
            let request = System.Text.Json.Nodes.JsonObject()
            request["configuration"] <- System.Text.Json.Nodes.JsonValue.Create next
            request["ownerId"] <- System.Text.Json.Nodes.JsonValue.Create "waiting-owner"
            request["operation"] <- System.Text.Json.Nodes.JsonValue.Create "apply"
            use payload = JsonDocument.Parse(request.ToJsonString())
            let staged = NativeFirewalld.handle env payload.RootElement
            Assert.That(staged["transactionNonce"].GetValue<string>(), Is.Not.Empty)
            let stable = this.InvokeOwner env "stable-owner" "read" zoneConfiguration
            let waiting = this.InvokeOwner env "waiting-owner" "read" next
            Assert.That(stable["inSync"].GetValue<bool>(), Is.True)
            Assert.That(waiting["inSync"].GetValue<bool>(), Is.False))

    [<Test>]
    member this.``Helper owns only declared permanent zone and restores absent built-in override``() =
        this.WithHost(fun env root calls ->
            let unrelated = Path.Combine(root, "etc/firewalld/zones/docker.xml")
            File.WriteAllText(unrelated, "<zone target=\"ACCEPT\"><interface name=\"docker0\"/></zone>")
            let result = this.Invoke env "apply" zoneConfiguration
            Assert.That(result["inSync"].GetValue<bool>(), Is.True)
            let applied = File.ReadAllText(Path.Combine(root, "etc/firewalld/zones/external.xml"))
            Assert.That(applied, Does.Contain "eth0")
            let journal = Path.Combine(root, "var/lib/keroosha-iac/firewalld/zone-external.json")
            Assert.That(int (File.GetUnixFileMode journal), Is.EqualTo 0o600)
            let read = this.Invoke env "read" zoneConfiguration
            Assert.That(read["inSync"].GetValue<bool>(), Is.True)
            this.Invoke env "delete" zoneConfiguration |> ignore
            Assert.That(File.Exists(Path.Combine(root, "etc/firewalld/zones/external.xml")), Is.False)
            Assert.That(File.ReadAllText unrelated, Is.EqualTo "<zone target=\"ACCEPT\"><interface name=\"docker0\"/></zone>")
            Assert.That(calls |> Seq.filter (fun args -> args = [ "firewall-cmd"; "--reload" ]) |> Seq.length, Is.EqualTo 2)
            Assert.That(File.Exists journal, Is.False))
    [<Test>]
    member _.``StrictForwardPorts is a global firewalld setting and not a policy field``() =
        let spec = firewalld { strictForwardPorts true }
        Assert.That(spec.StrictForwardPorts, Is.EqualTo(Some true))
        let configuration = FirewalldModel.parse strictConfiguration
        Assert.That(configuration.Kind, Is.EqualTo "settings")
        Assert.That(configuration.StrictForwardPorts, Is.EqualTo(Some true))
        let invalidPolicy =
            { FirewalldModel.empty "policy" "invalid" with
                Ingress = [ "public" ]
                Egress = [ "docker" ]
                StrictForwardPorts = Some true }
        Assert.Throws<ArgumentException>(fun () -> FirewalldModel.toJson invalidPolicy |> ignore) |> ignore

    [<Test>]
    member this.``StrictForwardPorts apply persists and delete restores the vendor baseline``() =
        this.WithHost(fun env root calls ->
            let vendorPath = Path.Combine(root, "usr/lib/firewalld/firewalld.conf")
            let vendor = "DefaultZone=public\nStrictForwardPorts=no\n"
            File.WriteAllText(vendorPath, vendor)
            File.SetUnixFileMode(vendorPath, enum<UnixFileMode> 0o640)
            let result = this.Invoke env "apply" strictConfiguration
            Assert.That(result["actual"].GetValue<string>(), Is.EqualTo "yes")
            Assert.That(result["inSync"].GetValue<bool>(), Is.True)
            let overridePath = Path.Combine(root, "etc/firewalld/firewalld.conf")
            let managed = "DefaultZone=public\nStrictForwardPorts=yes\n"
            Assert.That(File.ReadAllText overridePath, Is.EqualTo managed)
            Assert.That(int (File.GetUnixFileMode overridePath), Is.EqualTo 0o640)
            let read = this.Invoke env "read" strictConfiguration
            Assert.That(read["actual"].GetValue<string>(), Is.EqualTo "yes")
            Assert.That(read["inSync"].GetValue<bool>(), Is.True)
            this.Invoke env "delete" strictConfiguration |> ignore
            Assert.That(File.Exists overridePath, Is.False)
            Assert.That(File.ReadAllText vendorPath, Is.EqualTo vendor)
            Assert.That(File.Exists(Path.Combine(root, "var/lib/keroosha-iac/firewalld/settings-strict-forward-ports.json")), Is.False)
            Assert.That(calls |> Seq.filter (fun args -> args = [ "firewall-cmd"; "--reload" ]) |> Seq.length, Is.EqualTo 2))

    [<Test>]
    member this.``StrictForwardPorts refuses same-object replacement while the old generation remains active``() =
        this.WithHost(fun env root _ ->
            let oldOwner, newOwner = "old-settings-generation", "new-settings-generation"
            this.InvokeOwner env oldOwner "apply" strictConfiguration |> ignore
            let configPath = Path.Combine(root, "etc/firewalld/firewalld.conf")
            let before = File.ReadAllText configPath
            Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.InvokeOwner env newOwner "apply" strictConfiguration |> ignore) |> ignore
            Assert.That(File.ReadAllText configPath, Is.EqualTo before)
            let observed = this.InvokeOwner env oldOwner "read" strictConfiguration
            Assert.That(observed["actual"].GetValue<string>(), Is.EqualTo "yes")
            Assert.That(observed["inSync"].GetValue<bool>(), Is.True))

    [<Test>]
    member this.``DROP Docker policy refuses same-object replacement while the old guard remains active``() =
        this.WithHost(fun env root _ ->
            File.WriteAllText(Path.Combine(root, "etc/firewalld/zones/docker.xml"), "<zone target=\"ACCEPT\"/>")
            let config = (policy "blockdocker" { ingressZones [ "public" ]; egressZones [ "docker" ]; target FirewalldTarget.Drop; priority -10 }).Configuration
            this.InvokeOwner env "old-policy-generation" "apply" config |> ignore
            let policyPath = Path.Combine(root, "etc/firewalld/policies/blockdocker.xml")
            let before = File.ReadAllText policyPath
            Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.InvokeOwner env "new-policy-generation" "apply" config |> ignore) |> ignore
            Assert.That(File.ReadAllText policyPath, Is.EqualTo before)
            let observed = this.InvokeOwner env "old-policy-generation" "read" config
            Assert.That(observed["inSync"].GetValue<bool>(), Is.True))

    [<Test>]
    member this.``StrictForwardPorts delete restores only its inherited key and preserves later unrelated edits``() =
        this.WithHost(fun env root _ ->
            let configPath = Path.Combine(root, "etc/firewalld/firewalld.conf")
            File.WriteAllText(configPath, "DefaultZone=public\nStrictForwardPorts=no\n")
            this.Invoke env "apply" strictConfiguration |> ignore
            File.WriteAllText(configPath, "DefaultZone=trusted\nFirewallBackend=nftables\nStrictForwardPorts=yes\n")
            this.Invoke env "delete" strictConfiguration |> ignore
            Assert.That(File.ReadAllText configPath, Is.EqualTo "DefaultZone=trusted\nFirewallBackend=nftables\nStrictForwardPorts=no\n"))

    [<Test>]
    member this.``StrictForwardPorts retry after interrupted vendor-only Delete preserves foreign key``() =
        this.WithHost(fun env root calls ->
            let vendorPath = Path.Combine(root, "usr/lib/firewalld/firewalld.conf")
            File.WriteAllText(vendorPath, "DefaultZone=public\nStrictForwardPorts=no\n")
            this.Invoke env "apply" strictConfiguration |> ignore
            let configPath = Path.Combine(root, "etc/firewalld/firewalld.conf")
            File.WriteAllText(configPath, "DefaultZone=public\nStrictForwardPorts=yes\nForeignOption=keep\n")
            let mutable failedReloads = 0
            let interrupted =
                { env with
                    Run = fun executable arguments input ->
                        let result = env.Run executable arguments input
                        if executable = "firewall-cmd" && arguments = [ "--reload" ] && failedReloads < 2 then
                            failedReloads <- failedReloads + 1
                            { result with ExitCode = 1; Stderr = "reload interrupted" }
                        else result }
            Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.Invoke interrupted "delete" strictConfiguration |> ignore) |> ignore
            let journalPath = Path.Combine(root, "var/lib/keroosha-iac/firewalld/settings-strict-forward-ports.json")
            Assert.That(File.Exists journalPath, Is.True)
            NativeFirewalld.recoverPending env
            this.Invoke env "delete" strictConfiguration |> ignore
            Assert.That(File.ReadAllText configPath, Is.EqualTo "DefaultZone=public\nForeignOption=keep\n")
            let snapshot = this.Invoke env "read" strictConfiguration
            Assert.That(snapshot["actual"].GetValue<string>(), Is.EqualTo "no")
            Assert.That(File.Exists journalPath, Is.False))

    [<Test>]
    member this.``StrictForwardPorts refuses foreign setting changes without overwriting``() =
        this.WithHost(fun env root calls ->
            let configPath = Path.Combine(root, "etc/firewalld/firewalld.conf")
            let baseline = "DefaultZone=public\nStrictForwardPorts=no\n"
            File.WriteAllText(configPath, baseline)
            this.Invoke env "apply" strictConfiguration |> ignore
            let foreign = "DefaultZone=public\nStrictForwardPorts=no\n# external edit\n"
            File.WriteAllText(configPath, foreign)
            Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.Invoke env "apply" strictConfiguration |> ignore) |> ignore
            Assert.That(File.ReadAllText(configPath), Is.EqualTo foreign)
            Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.Invoke env "delete" strictConfiguration |> ignore) |> ignore
            Assert.That(File.ReadAllText(configPath), Is.EqualTo foreign))

    [<Test>]
    member this.``StrictForwardPorts failed first reload restores config and releases ownership``() =
        this.WithHost(fun env root calls ->
            let configPath = Path.Combine(root, "etc/firewalld/firewalld.conf")
            let baseline = "DefaultZone=public\nFirewallBackend=nftables\nStrictForwardPorts=no\n"
            File.WriteAllText(configPath, baseline)
            let mutable failed = false
            let failing =
                { env with
                    Run = fun executable arguments input ->
                        let result = env.Run executable arguments input
                        if executable = "firewall-cmd" && arguments = [ "--reload" ] && not failed then
                            failed <- true
                            { result with ExitCode = 1; Stderr = "reload unavailable" }
                        else result }
            Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.Invoke failing "apply" strictConfiguration |> ignore) |> ignore
            Assert.That(File.ReadAllText configPath, Is.EqualTo baseline)
            Assert.That(File.Exists(Path.Combine(root, "var/lib/keroosha-iac/firewalld/settings-strict-forward-ports.json")), Is.False)
            Assert.That(calls |> Seq.filter (fun args -> args = [ "firewall-cmd"; "--reload" ]) |> Seq.length, Is.EqualTo 2))

    [<Test>]
    member this.``Custom zone delete removes created XML and WireGuard binding is permanent only``() =
        this.WithHost(fun env root calls ->
            let config = (zone "vpn" { interfaces [ "wg-missing" ]; target FirewalldTarget.Drop }).Configuration
            this.Invoke env "apply" config |> ignore
            let file = Path.Combine(root, "etc/firewalld/zones/vpn.xml")
            Assert.That(File.ReadAllText file, Does.Contain "wg-missing")
            Assert.That(calls |> Seq.exists (fun args -> args |> List.exists (fun arg -> arg.Contains "--add-interface" || arg.Contains "--change-interface")), Is.False)
            this.Invoke env "delete" config |> ignore
            Assert.That(File.Exists file, Is.False))

    [<Test>]
    member this.``Missing unmanaged policy zone fails before any firewall mutation``() =
        this.WithHost(fun env root calls ->
            let config = (policy "blockdocker" { ingressZones [ "public" ]; egressZones [ "docker" ]; target FirewalldTarget.Drop; priority -10 }).Configuration
            Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.Invoke env "apply" config |> ignore) |> ignore
            Assert.That(Directory.Exists(Path.Combine(root, "var/lib/keroosha-iac")), Is.False)
            Assert.That(calls |> Seq.exists (fun args -> args = [ "firewall-cmd"; "--reload" ]), Is.False)
            File.WriteAllText(Path.Combine(root, "etc/firewalld/zones/docker.xml"), "<zone target=\"ACCEPT\"/>")
            this.Invoke env "apply" config |> ignore
            let policyXml = File.ReadAllText(Path.Combine(root, "etc/firewalld/policies/blockdocker.xml"))
            Assert.That(policyXml, Does.Contain "priority=\"-10\"")
            this.Invoke env "delete" config |> ignore
            Assert.That(File.Exists(Path.Combine(root, "etc/firewalld/zones/docker.xml")), Is.True))

    [<Test>]
    member this.``Unsafe SSH candidate leaves configuration and journal untouched``() =
        this.WithHost(fun env root calls ->
            let config = (zone "external" { interfaces [ "eth0" ]; target FirewalldTarget.Drop }).Configuration
            Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.Invoke env "apply" config |> ignore) |> ignore
            Assert.That(File.Exists(Path.Combine(root, "etc/firewalld/zones/external.xml")), Is.False)
            Assert.That(Directory.Exists(Path.Combine(root, "var/lib/keroosha-iac")), Is.False)
            Assert.That(calls |> Seq.exists (fun args -> args = [ "firewall-cmd"; "--check-config" ] || args = [ "firewall-cmd"; "--reload" ]), Is.False))

    [<TestCase("--check-config"); TestCase("--reload")>]
    member this.``Native failure rolls permanent state back and reloads original``(failingCommand: string) =
        this.WithHost(fun env root calls ->
            let mutable failed = false
            let failing =
                { env with
                    Run = fun executable arguments input ->
                        let result = env.Run executable arguments input
                        if executable = "firewall-cmd" && arguments = [ failingCommand ] && not failed then
                            failed <- true
                            { result with ExitCode = 1; Stderr = "INVALID_RULE: rejected fixture\n" + String.replicate 3000 "x" }
                        else result }
            let failure = Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.Invoke failing "apply" zoneConfiguration |> ignore)
            Assert.That(failure.Message, Does.Contain "INVALID_RULE: rejected fixture")
            Assert.That(failure.Message.Length, Is.LessThan 2400)
            Assert.That(failure.Message |> Seq.exists Char.IsControl, Is.False)
            Assert.That(File.Exists(Path.Combine(root, "etc/firewalld/zones/external.xml")), Is.False)
            let reloadCount = calls |> Seq.filter (fun args -> args = [ "firewall-cmd"; "--reload" ]) |> Seq.length
            Assert.That(reloadCount, Is.EqualTo(if failingCommand = "--reload" then 2 else 1))
            Assert.That(File.Exists(Path.Combine(root, "var/lib/keroosha-iac/firewalld/zone-external.json")), Is.False)
            // A retry retains the original no-override baseline and converges.
            let result = this.Invoke env "apply" zoneConfiguration
            Assert.That(result["inSync"].GetValue<bool>(), Is.True))

    [<Test>]
    member this.``Delete refuses unsafe default zone before restoring baseline``() =
        this.WithHost(fun env root calls ->
            this.Invoke env "apply" zoneConfiguration |> ignore
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/zones/public.xml"), "<zone target=\"DROP\"/>")
            // external's baseline is not bound; deletion would return SSH to public.
            let before = File.ReadAllText(Path.Combine(root, "etc/firewalld/zones/external.xml"))
            Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.Invoke env "delete" zoneConfiguration |> ignore) |> ignore
            Assert.That(File.ReadAllText(Path.Combine(root, "etc/firewalld/zones/external.xml")), Is.EqualTo before))

    [<Test>]
    member _.``Debian vendor allow-host-ipv6 and logging policies cannot block SSH``() =
        guard context (Map.ofList [ "public", xml ]) (Map.ofList [ "allow-host-ipv6", vendorPolicy ])
        for action in [ "accept"; "log"; "audit" ] do
            let policy = "<policy target=\"CONTINUE\"><ingress-zone name=\"ANY\"/><egress-zone name=\"HOST\"/><rule><" + action + "/></rule></policy>"
            guard context (Map.ofList [ "public", xml ]) (Map.ofList [ "policy", policy ])
        for action in [ "drop"; "reject"; "mark" ] do
            let policy = "<policy target=\"CONTINUE\"><ingress-zone name=\"ANY\"/><egress-zone name=\"HOST\"/><rule><port port=\"22\" protocol=\"tcp\"/><" + action + "/></rule></policy>"
            Assert.Throws<NativeFirewalld.BackendError>(fun () -> guard context (Map.ofList [ "public", xml ]) (Map.ofList [ "policy", policy ])) |> ignore

    [<Test>]
    member _.``Empty TCP service port never proves SSH reachability``() =
        let emptyPort _ = Some "<service><port port=\"\" protocol=\"tcp\"/></service>"
        Assert.Throws<NativeFirewalld.BackendError>(fun () ->
            NativeFirewalld.validateSshGuard context "public" (Map.ofList [ "public", xml ]) Map.empty emptyPort) |> ignore

    [<Test>]
    member this.``Runtime-only SSH binding is guarded before any permanent write``() =
        this.WithHost(fun env root calls ->
            let file = Path.Combine(root, "etc/firewalld/zones/runtime.xml")
            let before = "<zone><service name=\"ssh\"/></zone>"
            File.WriteAllText(file, before)
            let mutable extraBinding = true
            let runtime =
                { env with
                    Run = fun executable args input ->
                        let result = env.Run executable args input
                        match args with
                        | [ "--get-zone-of-interface=eth0" ] when extraBinding -> { result with ExitCode = 0; Stdout = "runtime" }
                        | [ "--zone=runtime"; "--list-all" ] when extraBinding -> { result with Stdout = result.Stdout.Replace("interfaces: \n", "interfaces: eth0\n") }
                        | [ "--zone=runtime"; "--list-interfaces" ] when extraBinding -> { result with Stdout = "eth0" }
                        | [ "--reload" ] -> extraBinding <- false; result
                        | _ -> result }
            let unsafe = (zone "runtime" { target FirewalldTarget.Drop }).Configuration
            Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.Invoke runtime "apply" unsafe |> ignore) |> ignore
            Assert.That(File.ReadAllText file, Is.EqualTo before)
            Assert.That(calls |> Seq.exists (fun args -> args = [ "firewall-cmd"; "--reload" ]), Is.False)
            let safe = (zone "runtime" { services [ "ssh" ]; ports [ 443, Tcp ] }).Configuration
            let result = this.Invoke runtime "apply" safe
            Assert.That(result["inSync"].GetValue<bool>(), Is.True))

    [<Test>]
    member this.``APT refuses unsafe first startup but accepts an explicitly preseeded custom SSH port``() =
        this.WithHost(fun env root calls ->
            File.WriteAllText(Path.Combine(root, "etc/os-release"), "ID=debian\n")
            Environment.SetEnvironmentVariable("SSH_CONNECTION", "192.0.2.1 49200 192.0.2.2 2222")
            let mutable installed = false
            let mutable installs = 0
            let success text : Dorothy.HostHelper.CommandResult = { ExitCode = 0; Stdout = text; Stderr = "" }
            let aptEnv =
                { env with
                    Run = fun executable args input ->
                        match executable, args with
                        | "dpkg", _ -> success "amd64"
                        | "dpkg-query", _ -> success (if installed then "firewalld\tall\tii \t2.3.1-1\tno\tno\n" else "")
                        | "apt-cache", _ -> success "Package: firewalld\nVersion: 2.3.1-1\n"
                        | "apt-get", args when List.contains "-s" args -> success "Inst firewalld (2.3.1-1 Debian:13 [all])\n"
                        | "apt-get", args when List.contains "-y" args ->
                            installed <- true
                            installs <- installs + 1
                            success ""
                        | "apt-get", _ -> success ""
                        | _ -> env.Run executable args input }
            use request = JsonDocument.Parse("""{"operation":"apply","ownerId":"firewall-package","previousNames":[],"desiredVersions":{"firewalld":null}}""")
            let failure = Assert.Throws<NativeFirewalld.BackendError>(fun () -> Dorothy.HostHelper.Apt.handle aptEnv request.RootElement |> ignore)
            Assert.That(failure.Message, Does.Contain "Pre-seed")
            Assert.That(installs, Is.Zero)
            let preseed = "<zone><port port=\"2222\" protocol=\"tcp\"/></zone>"
            let file = Path.Combine(root, "etc/firewalld/zones/public.xml")
            File.WriteAllText(file, preseed)
            Dorothy.HostHelper.Apt.handle aptEnv request.RootElement |> ignore
            Assert.That(installs, Is.EqualTo 1)
            Assert.That(File.ReadAllText file, Is.EqualTo preseed))

    [<Test>]
    member this.``Read of unowned configuration never reports ownership or rewrites it``() =
        this.WithHost(fun env root calls ->
            let file = Path.Combine(root, "etc/firewalld/zones/external.xml")
            let content = NativeFirewalld.render (Dorothy.HostHelper.FirewalldModel.parse zoneConfiguration)
            File.WriteAllText(file, content)
            let snapshot = this.Invoke env "read" zoneConfiguration
            Assert.That(snapshot["exists"].GetValue<bool>(), Is.True)
            Assert.That(snapshot["inSync"].GetValue<bool>(), Is.False)
            Assert.That(File.ReadAllText file, Is.EqualTo content)
            Assert.That(Directory.Exists(Path.Combine(root, "var/lib/keroosha-iac/firewalld")), Is.False))

    [<Test>]
    member this.``Delete restores the adopted override including its original binding``() =
        this.WithHost(fun env root calls ->
            let file = Path.Combine(root, "etc/firewalld/zones/external.xml")
            let baseline = "<zone target=\"DROP\">\n  <interface name=\"eth0\"/>\n  <port port=\"22\" protocol=\"tcp\"/>\n  <port port=\"9090\" protocol=\"tcp\"/>\n</zone>\n"
            File.WriteAllText(file, baseline)
            this.Invoke env "apply" zoneConfiguration |> ignore
            this.Invoke env "delete" zoneConfiguration |> ignore
            Assert.That(File.ReadAllText file, Is.EqualTo baseline))

    [<Test>]
    member this.``Undeclared rich baseline is not silently acquired or removed``() =
        this.WithHost(fun env root calls ->
            let file = Path.Combine(root, "etc/firewalld/zones/external.xml")
            let baseline = """<zone><service name="ssh"/><rule family="ipv6"><port port="10544" protocol="udp"/><drop/></rule></zone>"""
            File.WriteAllText(file, baseline)
            Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.Invoke env "apply" zoneConfiguration |> ignore) |> ignore
            this.Invoke env "delete" zoneConfiguration |> ignore
            Assert.That(File.ReadAllText file, Is.EqualTo baseline)
            Assert.That(calls, Does.Not.Contain [ "firewall-cmd"; "--reload" ])
            Assert.That(File.Exists(Path.Combine(root, "var/lib/keroosha-iac/firewalld/zone-external.json")), Is.False))

    [<Test>]
    member this.``Read distinguishes live drift from unchanged permanent bytes and leaves both alone``() =
        this.WithHost(fun env root calls ->
            this.Invoke env "apply" zoneConfiguration |> ignore
            let file = Path.Combine(root, "etc/firewalld/zones/external.xml")
            let desired = File.ReadAllText file
            File.WriteAllText(file, "<zone><interface name=\"eth0\"/><service name=\"ssh\"/><port port=\"9443\" protocol=\"tcp\"/></zone>")
            env.Run "firewall-cmd" [ "--reload" ] None |> ignore
            File.WriteAllText(file, desired)
            calls.Clear()
            let drift = this.Invoke env "read" zoneConfiguration
            Assert.That(drift["permanentInSync"].GetValue<bool>(), Is.True)
            Assert.That(drift["runtimeObserved"].GetValue<bool>(), Is.True)
            Assert.That(drift["runtimeInSync"].GetValue<bool>(), Is.False)
            Assert.That(drift["inSync"].GetValue<bool>(), Is.False)
            Assert.That(calls, Does.Not.Contain [ "firewall-cmd"; "--reload" ])
            Assert.That(File.ReadAllText file, Is.EqualTo desired)
            let repaired = this.Invoke env "apply" zoneConfiguration
            Assert.That(repaired["inSync"].GetValue<bool>(), Is.True))

    [<Test>]
    member this.``An external policy prevents deletion of its referenced managed zone``() =
        this.WithHost(fun env root calls ->
            let config = (zone "apps" { target FirewalldTarget.Drop }).Configuration
            this.Invoke env "apply" config |> ignore
            let zonePath = Path.Combine(root, "etc/firewalld/zones/apps.xml")
            let before = File.ReadAllBytes zonePath
            let policyPath = Path.Combine(root, "etc/firewalld/policies/external.xml")
            File.WriteAllText(policyPath, """<policy target="CONTINUE"><ingress-zone name="apps"/><egress-zone name="HOST"/></policy>""")
            calls.Clear()
            let refusal = Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.Invoke env "delete" config |> ignore)
            Assert.That(refusal.Message, Does.Contain "still referenced")
            Assert.That(File.ReadAllBytes(zonePath) = before, Is.True)
            Assert.That(calls, Does.Not.Contain [ "firewall-cmd"; "--reload" ]))

    [<Test>]
    member this.``A cycle through an external service fails before a referencing zone is staged``() =
        this.WithHost(fun env root calls ->
            let directory = Path.Combine(root, "usr/lib/firewalld/services")
            File.WriteAllText(Path.Combine(directory, "first.xml"), """<service><include service="second"/></service>""")
            File.WriteAllText(Path.Combine(directory, "second.xml"), """<service><include service="first"/></service>""")
            let config = (zone "apps" { services ["first"] }).Configuration
            let refusal = Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.Invoke env "apply" config |> ignore)
            Assert.That(refusal.Message, Does.Contain "Cyclic")
            Assert.That(File.Exists(Path.Combine(root, "etc/firewalld/zones/apps.xml")), Is.False)
            Assert.That(calls, Does.Not.Contain [ "firewall-cmd"; "--reload" ]))

    [<Test>]
    member this.``Foreign ownership cannot modify or delete a managed zone``() =
        this.WithHost(fun env root calls ->
            this.Invoke env "apply" zoneConfiguration |> ignore
            let before = File.ReadAllText(Path.Combine(root, "etc/firewalld/zones/external.xml"))
            for operation in [ "apply"; "delete"; "read" ] do
                Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.InvokeOwner env "other-owner" operation zoneConfiguration |> ignore) |> ignore
            Assert.That(File.ReadAllText(Path.Combine(root, "etc/firewalld/zones/external.xml")), Is.EqualTo before))

    [<Test>]
    member this.``Failed first Create releases ownership only after successful rollback``() =
        this.WithHost(fun env root calls ->
            let failing =
                { env with
                    Run = fun executable args input ->
                        let result = env.Run executable args input
                        if args = [ "--check-config" ] && File.Exists(Path.Combine(root, "etc/firewalld/zones/external.xml")) then
                            { result with ExitCode = 1; Stderr = "fixture rejection" }
                        else result }
            Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.Invoke failing "apply" zoneConfiguration |> ignore) |> ignore
            let result = this.InvokeOwner env "replacement-owner" "apply" zoneConfiguration
            Assert.That(result["inSync"].GetValue<bool>(), Is.True))

    [<Test>]
    member this.``Failed Update restores last managed XML clears pending and retains original baseline``() =
        this.WithHost(fun env root calls ->
            this.Invoke env "apply" zoneConfiguration |> ignore
            let file = Path.Combine(root, "etc/firewalld/zones/external.xml")
            let before = File.ReadAllText file
            let reloads = ResizeArray<string>()
            let failing =
                { env with
                    Run = fun executable args input ->
                        let result = env.Run executable args input
                        if args = [ "--reload" ] then
                            reloads.Add(File.ReadAllText file)
                            if reloads.Count = 1 then { result with ExitCode = 1; Stderr = "reload fixture" } else result
                        else result }
            let update = (zone "external" { services [ "ssh" ]; interfaces [ "eth0" ]; ports [ 443, Tcp ] }).Configuration
            Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.Invoke failing "apply" update |> ignore) |> ignore
            Assert.That(reloads.Count, Is.EqualTo 2)
            Assert.That(reloads[0], Does.Contain "443")
            Assert.That(reloads[1], Is.EqualTo before)
            use journal = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "var/lib/keroosha-iac/firewalld/zone-external.json")))
            Assert.That(journal.RootElement.GetProperty("pending").ValueKind, Is.EqualTo JsonValueKind.Null)
            Assert.That(journal.RootElement.GetProperty("baseline").ValueKind, Is.EqualTo JsonValueKind.Null)
            Assert.That(journal.RootElement.GetProperty("managed").GetString(), Is.EqualTo before))

    [<Test>]
    member this.``Interrupted rollback retains journal and recovers before retry``() =
        this.WithHost(fun env root calls ->
            let failReload =
                { env with
                    Run = fun executable args input ->
                        let result = env.Run executable args input
                        if args = [ "--reload" ] then { result with ExitCode = 1; Stderr = "reload unavailable" } else result }
            Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.Invoke failReload "apply" zoneConfiguration |> ignore) |> ignore
            let journalPath = Path.Combine(root, "var/lib/keroosha-iac/firewalld/zone-external.json")
            use pending = JsonDocument.Parse(File.ReadAllText journalPath)
            Assert.That(pending.RootElement.GetProperty("pending").ValueKind, Is.EqualTo JsonValueKind.Object)
            Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.InvokeOwner env "other-owner" "apply" zoneConfiguration |> ignore) |> ignore
            Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.Invoke env "apply" zoneConfiguration |> ignore) |> ignore
            NativeFirewalld.recoverPending env
            let result = this.Invoke env "apply" zoneConfiguration
            Assert.That(result["inSync"].GetValue<bool>(), Is.True)
            use recovered = JsonDocument.Parse(File.ReadAllText journalPath)
            Assert.That(recovered.RootElement.GetProperty("pending").ValueKind, Is.EqualTo JsonValueKind.Null)
            this.Invoke env "delete" zoneConfiguration |> ignore
            Assert.That(File.Exists(Path.Combine(root, "etc/firewalld/zones/external.xml")), Is.False))

    [<Test>]
    member _.``A trailing plus binds a prefix and cannot hide a DROP zone on the current interface``() =
        let candidate prefix =
            (zone "restricted" { interfaces [ prefix ]; target FirewalldTarget.Drop }).Configuration
            |> Dorothy.HostHelper.FirewalldModel.parse |> NativeFirewalld.render
        let zones prefix = Map.ofList [ "public", "<zone><service name=\"ssh\"/></zone>"; "restricted", candidate prefix ]
        guard context (zones "wg+") Map.empty
        for prefix in [ "eth+"; "+" ] do
            Assert.Throws<NativeFirewalld.BackendError>(fun () -> guard context (zones prefix) Map.empty) |> ignore

    [<TestCase(false); TestCase(true)>]
    member this.``Unbound runtime interface allows Apply Delete and pending recovery``(stderr: bool) =
        this.WithHost(fun env root calls ->
            let unbound =
                { env with
                    Run = fun executable args input ->
                        let result = env.Run executable args input
                        if args = [ "--get-zone-of-interface=eth0" ] && result.ExitCode = 2 then
                            { result with ExitCode = 2; Stdout = (if stderr then "" else "no zone\n"); Stderr = (if stderr then "no zone\n" else "") }
                        else result }
            let result = this.Invoke unbound "apply" zoneConfiguration
            Assert.That(result["inSync"].GetValue<bool>(), Is.True)
            this.Invoke unbound "delete" zoneConfiguration |> ignore
            let file = Path.Combine(root, "etc/firewalld/zones/external.xml")
            Assert.That(File.Exists file, Is.False)
            let interrupted =
                { unbound with
                    Run = fun executable args input ->
                        let result = unbound.Run executable args input
                        if args = [ "--reload" ] then { result with ExitCode = 1; Stderr = "interrupted reload" } else result }
            Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.Invoke interrupted "apply" zoneConfiguration |> ignore) |> ignore
            NativeFirewalld.recoverPending unbound
            let recovered = this.Invoke unbound "apply" zoneConfiguration
            Assert.That(recovered["inSync"].GetValue<bool>(), Is.True)
            use journal = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "var/lib/keroosha-iac/firewalld/zone-external.json")))
            Assert.That(journal.RootElement.GetProperty("pending").ValueKind, Is.EqualTo JsonValueKind.Null)
            this.Invoke unbound "delete" zoneConfiguration |> ignore
            Assert.That(File.Exists file, Is.False))

    [<TestCase(2, "access denied", "")>]
    [<TestCase(1, "no zone", "")>]
    [<TestCase(2, "no zone", "access denied")>]
    [<TestCase(0, "", "")>]
    member this.``Runtime interface query errors never become default-zone fallback``(code: int, stdout: string, stderr: string) =
        this.WithHost(fun env root calls ->
            let failing =
                { env with
                    Run = fun executable args input ->
                        let result = env.Run executable args input
                        if args = [ "--get-zone-of-interface=eth0" ] then { ExitCode = code; Stdout = stdout; Stderr = stderr }
                        else result }
            if code = 0 then
                Assert.Throws<ArgumentException>(fun () -> this.Invoke failing "apply" zoneConfiguration |> ignore) |> ignore
            else
                Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.Invoke failing "apply" zoneConfiguration |> ignore) |> ignore
            Assert.That(File.Exists(Path.Combine(root, "etc/firewalld/zones/external.xml")), Is.False)
            Assert.That(calls |> Seq.exists (fun args -> args = [ "firewall-cmd"; "--reload" ]), Is.False))

    [<TestCase("--state"); TestCase("--get-default-zone"); TestCase("--check-config"); TestCase("--reload")>]
    member this.``No-zone status is not accepted from other firewall commands``(command: string) =
        this.WithHost(fun env root calls ->
            let mutable failed = false
            let failing =
                { env with
                    Run = fun executable args input ->
                        let result = env.Run executable args input
                        if args = [ command ] && not failed then
                            failed <- true
                            { result with ExitCode = 2; Stdout = "no zone"; Stderr = "" }
                        else result }
            let error = Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.Invoke failing "apply" zoneConfiguration |> ignore)
            Assert.That(error.Message, Does.Contain command)
            Assert.That(File.Exists(Path.Combine(root, "etc/firewalld/zones/external.xml")), Is.False))
