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
    member _.``XML comparison ignores ordering but detects unowned rich filtering and missing fields``() =
        let reordered = "<zone version=\"1\" target=\"default\"><short>External</short><interface name=\"eth0\"/><service name=\"ssh\"/></zone>"
        Assert.That(NativeFirewalld.canonicalXml "zone" xml, Is.EqualTo(NativeFirewalld.canonicalXml "zone" reordered))
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
        Assert.That(provider.Diff(same, CancellationToken.None).Result.Changes.Value, Is.False)

    member private _.WithHost(action: Dorothy.HostHelper.HostEnvironment -> string -> ResizeArray<string list> -> unit) =
        let root = Path.Combine(Path.GetTempPath(), "dorothy-firewalld-" + Guid.NewGuid().ToString("N"))
        let previous = Environment.GetEnvironmentVariable "SSH_CONNECTION"
        try
            for directory in [ "etc/firewalld/zones"; "etc/firewalld/policies"; "usr/lib/firewalld/zones"; "usr/lib/firewalld/services"; "usr/lib/firewalld/policies"; "run/lock"; "var/lib" ] do
                Directory.CreateDirectory(Path.Combine(root, directory)) |> ignore
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/zones/public.xml"), "<zone><service name=\"ssh\"/></zone>")
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/zones/external.xml"), "<zone><service name=\"ssh\"/><masquerade/></zone>")
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/services/ssh.xml"), "<service><port port=\"22\" protocol=\"tcp\"/></service>")
            Environment.SetEnvironmentVariable("SSH_CONNECTION", "192.0.2.1 49200 192.0.2.2 22")
            let calls = ResizeArray<string list>()
            let run executable arguments _ : Dorothy.HostHelper.CommandResult =
                calls.Add(executable :: arguments)
                let output =
                    match executable, arguments with
                    | "stat", _ ->
                        let mode = File.GetUnixFileMode(List.last arguments) |> int |> fun value -> Convert.ToString(value, 8)
                        "0:" + mode
                    | "ip", _ -> "[{\"dev\":\"eth0\"}]"
                    | "firewall-cmd", [ "--get-default-zone" ] -> "public"
                    | "firewall-cmd", _ -> "success"
                    | _ -> failwith ("Unexpected fixture command: " + executable)
                { ExitCode = 0; Stdout = output; Stderr = "" }
            let environment: Dorothy.HostHelper.HostEnvironment = { Root = root; Run = run; UtcNow = fun () -> DateTimeOffset.UnixEpoch }
            action environment root calls
        finally
            Environment.SetEnvironmentVariable("SSH_CONNECTION", previous)
            if Directory.Exists root then Directory.Delete(root, true)

    member private _.Invoke environment operation configuration =
        let node = System.Text.Json.Nodes.JsonObject()
        node["operation"] <- System.Text.Json.Nodes.JsonValue.Create(operation: string)
        node["ownerId"] <- System.Text.Json.Nodes.JsonValue.Create "test-owner"
        node["configuration"] <- System.Text.Json.Nodes.JsonValue.Create(configuration: string)
        use document = JsonDocument.Parse(node.ToJsonString())
        NativeFirewalld.handle environment document.RootElement

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
                            { result with ExitCode = 1 }
                        else result }
            Assert.Throws<NativeFirewalld.BackendError>(fun () -> this.Invoke failing "apply" zoneConfiguration |> ignore) |> ignore
            Assert.That(File.Exists(Path.Combine(root, "etc/firewalld/zones/external.xml")), Is.False)
            Assert.That(calls |> Seq.exists (fun args -> args = [ "firewall-cmd"; "--reload" ]), Is.True)
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
