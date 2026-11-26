namespace Dorothy.Tests

open System
open System.IO
open Dorothy.HostHelper
open NUnit.Framework

[<TestFixture>]
type FirewalldRuntimeTests() =
    let element (name: string) (attributes: (string * string) list) (text: string option) (children: FirewalldModel.Element list) : FirewalldModel.Element =
        { Name = name
          Attributes = Map.ofList attributes
          Text = text
          Children = children }

    let commandResult (stdout: string) : CommandResult =
        { ExitCode = 0; Stdout = stdout; Stderr = "" }

    let makeEnvironment (run: string -> string list -> string option -> CommandResult) : HostEnvironment * string =
        let root = Path.Combine(Path.GetTempPath(), "dorothy-firewalld-runtime-" + Guid.NewGuid().ToString("N"))
        { Root = root
          Run = run
          UtcNow = fun () -> DateTimeOffset.UnixEpoch }, root

    let zoneOutput (services: string) (sources: string) (forwardPorts: string list) (richRules: string list) =
        "quiet\n"
        + "  target: default\n"
        + "  ingress-priority: 0\n"
        + "  egress-priority: 0\n"
        + "  icmp-block-inversion: no\n"
        + "  interfaces: \n"
        + "  sources: " + sources + "\n"
        + "  services: " + services + "\n"
        + "  ports: \n"
        + "  protocols: \n"
        + "  forward: no\n"
        + "  masquerade: no\n"
        + "  forward-ports:" + (if forwardPorts.IsEmpty then "\n" else "\n\t" + String.concat "\n\t" forwardPorts + "\n")
        + "  source-ports: \n"
        + "  icmp-blocks: \n"
        + "  rich rules:" + (if richRules.IsEmpty then "\n" else "\n\t" + String.concat "\n\t" richRules + "\n")

    let policyOutput (egress: string) (services: string) (ports: string) (protocols: string) (richRules: string list) =
        "blockdocker\n"
        + "  priority: -10\n"
        + "  target: DROP\n"
        + "  ingress-zones: public\n"
        + "  egress-zones: " + egress + "\n"
        + "  services: " + services + "\n"
        + "  ports: " + ports + "\n"
        + "  protocols: " + protocols + "\n"
        + "  masquerade: no\n"
        + "  forward-ports:\n"
        + "  source-ports: \n"
        + "  icmp-blocks: \n"
        + "  rich rules:" + (if richRules.IsEmpty then "\n" else "\n\t" + String.concat "\n\t" richRules + "\n")

    [<Test>]
    member _.``Renderer retains typed attributes nested fields and escaped text``() =
        let config =
            { FirewalldModel.empty "service" "custom-api" with
                Ports = [ "8443/tcp" ]
                Protocols = [ "gre" ]
                Attributes = Map.ofList [ "version", "2" ]
                Elements =
                    [ element "short" [] (Some "API & control") []
                      element "destination" [ "ipv4", "192.0.2.4" ] None [] ] }
        let rendered = FieldRuntime.render config
        Assert.That(
            FieldRuntime.canonicalXml "service" rendered,
            Is.EqualTo(FieldRuntime.canonicalXml "service" "<service version=\"2\"><destination ipv4=\"192.0.2.4\"/><port port=\"8443\" protocol=\"tcp\"/><protocol value=\"gre\"/><short>API &amp; control</short></service>"))
        let helper =
            { FirewalldModel.empty "helper" "ftp" with
                Attributes = Map.ofList [ "module", "nf_conntrack_ftp"; "family", "ipv4" ]
                Ports = [ "21/tcp" ] }
        let helperXml = FieldRuntime.render helper
        Assert.That(FieldRuntime.canonicalXml "helper" helperXml,
                    Is.EqualTo(FieldRuntime.canonicalXml "helper" """<helper module="nf_conntrack_ftp" family="ipv4"><port port="21" protocol="tcp"/></helper>"""))

    [<Test>]
    member _.``Canonical XML retains metadata and canonicalizes unordered rich rule sets``() =
        let first =
            "<zone version=\"1\"><short>Public</short><description>edge ingress</description>"
            + "<rule priority=\"10\"><source address=\"192.0.2.0/24\"/><drop/></rule>"
            + "<rule priority=\"10\"><source address=\"192.0.2.0/24\"/><drop/></rule>"
            + "<rule priority=\"-10\"><service name=\"ssh\"/><accept/></rule></zone>"
        let reordered =
            "<zone version=\"1\"><rule priority=\"-10\"><accept/><service name=\"ssh\"/></rule>"
            + "<description>edge ingress</description><short>Public</short>"
            + "<rule priority=\"10\"><drop/><source address=\"192.0.2.0/24\"/></rule></zone>"
        Assert.That(FieldRuntime.canonicalXml "zone" first, Is.EqualTo(FieldRuntime.canonicalXml "zone" reordered))
        let changedText = first.Replace("edge ingress", "public edge", StringComparison.Ordinal)
        Assert.That(FieldRuntime.canonicalXml "zone" first, Is.Not.EqualTo(FieldRuntime.canonicalXml "zone" changedText))

    [<Test>]
    member _.``Safe adoption requires nonlegacy metadata and filtering rules unchanged``() =
        let config =
            { FirewalldModel.empty "zone" "public" with
                Target = "DROP"
                Services = [ "ssh" ]
                Elements = [ element "description" [] (Some "preserved") [] ] }
        let baseline = "<zone target=\"DROP\"><service name=\"ssh\"/><description>preserved</description></zone>"
        Assert.That(FieldRuntime.safeAdoption config baseline, Is.True)
        Assert.That(FieldRuntime.safeAdoption config (baseline.Replace("preserved", "different", StringComparison.Ordinal)), Is.False)
        let opaqueService = baseline.Replace("<service name=\"ssh\"/>", "<service name=\"ssh\" future=\"on\"/>", StringComparison.Ordinal)
        Assert.That(FieldRuntime.safeAdoption config opaqueService, Is.False)
        let namespacedAttribute = baseline.Replace("<service name=\"ssh\"/>", "<service name=\"ssh\" xmlns:x=\"urn:opaque\" x:future=\"on\"/>", StringComparison.Ordinal)
        Assert.That(FieldRuntime.safeAdoption config namespacedAttribute, Is.False)
        let nestedPort = baseline.Replace("</zone>", "<port port=\"80\" protocol=\"tcp\"><future/></port></zone>", StringComparison.Ordinal)
        Assert.That(FieldRuntime.safeAdoption config nestedPort, Is.False)
        let richBaseline = baseline.Replace("</zone>", "<rule><source address=\"192.0.2.0/24\"/><drop/></rule></zone>", StringComparison.Ordinal)
        Assert.That(FieldRuntime.safeAdoption config richBaseline, Is.False)

    [<Test>]
    member _.``Read observes quiet zone selectors and runtime drift without claiming other objects``() =
        let config =
            { FirewalldModel.empty "zone" "quiet" with Services = [ "ssh" ] }
        let expectedXml = FieldRuntime.render config
        let quiet = zoneOutput "ssh" "" [] []
        let mutable drift = false
        let mutable unknown = false
        let run executable arguments _ =
            if executable <> "firewall-cmd" then failwith "Unexpected executable."
            match arguments with
            | [ "--zone=quiet"; "--list-all" ] ->
                let output = if drift then zoneOutput "" "" [] [] else quiet
                commandResult(if unknown then output + "  future-selector: opaque\n" else output)
            | [ "--permanent"; "--zone=quiet"; "--list-all" ] -> commandResult quiet
            | [ "--zone=quiet"; "--list-interfaces" ]
            | [ "--permanent"; "--zone=quiet"; "--list-interfaces" ]
            | [ "--zone=quiet"; "--list-rich-rules" ]
            | [ "--permanent"; "--zone=quiet"; "--list-rich-rules" ] -> commandResult ""
            | [ "--get-zones" ] -> commandResult "public quiet"
            | _ -> failwith ("Unexpected firewalld argv: " + String.concat " " arguments)
        let environment, root = makeEnvironment run
        try
            let zoneDirectory = Path.Combine(root, "etc/firewalld/zones")
            Directory.CreateDirectory zoneDirectory |> ignore
            File.WriteAllText(Path.Combine(zoneDirectory, "quiet.xml"), expectedXml)
            Assert.That(FirewalldRuntime.listRuntime environment "zone", Is.EqualTo(Some [ "public"; "quiet" ]))
            Assert.That(FirewalldRuntime.inSync environment config, Is.True)
            drift <- true
            let driftObservation = FirewalldRuntime.observe environment config
            Assert.That(driftObservation.Observed, Is.True)
            Assert.That(driftObservation.InSync, Is.False)
            Assert.That(FirewalldRuntime.inSync environment config, Is.False)
            drift <- false
            unknown <- true
            let runtime = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            Assert.That(Map.containsKey "future-selector" runtime.UnknownFields, Is.True)
            let unknownObservation = FirewalldRuntime.observe environment config
            Assert.That(unknownObservation.Observed, Is.False)
            Assert.That(FirewalldRuntime.inSync environment config, Is.False)
            unknown <- false
            let permanentPath = Path.Combine(zoneDirectory, "quiet.xml")
            File.WriteAllText(permanentPath, expectedXml.Replace("</zone>", "<description>unmanaged</description></zone>", StringComparison.Ordinal))
            let runtimeObservation = FirewalldRuntime.observe environment config
            Assert.That(runtimeObservation.Observed, Is.True)
            Assert.That(runtimeObservation.InSync, Is.True)
            Assert.That(FirewalldRuntime.inSync environment config, Is.True)
        finally
            if Directory.Exists root then Directory.Delete(root, true)

    [<Test>]
    member _.``Runtime projection preserves source ipsets forward ports rich rules and unknown fields``() =
        let rule = "rule family=\"ipv4\" source ipset=\"blocked\" drop"
        let output =
            zoneOutput "ssh" "192.0.2.0/24 02:00:00:00:00:01 ipset:trusted" [ "port=443:proto=tcp:toport=8443:toaddr=192.0.2.9"; "port=8080:proto=udp:toport=None:toaddr=2001:db8::3" ] [ rule ]
        let run executable arguments _ =
            if executable = "firewall-cmd" && arguments = [ "--zone=quiet"; "--list-all" ] then commandResult output
            else failwith "Unexpected fixture command."
        let environment, root = makeEnvironment run
        try
            Directory.CreateDirectory root |> ignore
            let snapshot = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            Assert.That(snapshot.SourcesRaw, Is.EquivalentTo [ "192.0.2.0/24"; "02:00:00:00:00:01"; "ipset:trusted" ])
            Assert.That(snapshot.Sources |> List.map (fun source -> source.Attributes), Is.EquivalentTo [ Map.ofList [ "address", "192.0.2.0/24" ]; Map.ofList [ "mac", "02:00:00:00:00:01" ]; Map.ofList [ "ipset", "trusted" ] ])
            Assert.That(snapshot.ForwardPorts.Head.Attributes, Is.EqualTo<Map<string,string>>(Map.ofList [ "port", "443"; "protocol", "tcp"; "to-port", "8443"; "to-addr", "192.0.2.9" ]))
            Assert.That(snapshot.ForwardPorts.Length, Is.EqualTo 2)
            Assert.That(snapshot.ForwardPorts[1].Attributes, Is.EqualTo<Map<string,string>>(Map.ofList [ "port", "8080"; "protocol", "udp"; "to-addr", "2001:db8::3" ]))
            Assert.That(snapshot.RichRules, Is.EquivalentTo [ rule ])
            Assert.That(snapshot.UnknownFields, Is.Empty)
        finally
            if Directory.Exists root then Directory.Delete(root, true)

    [<Test>]
    member _.``Policy runtime selectors are observed independently from permanent data``() =
        let config =
            { FirewalldModel.empty "policy" "blockdocker" with
                Target = "DROP"
                Priority = -10
                Ingress = [ "public" ]
                Egress = [ "docker" ] }
        let actual = FieldRuntime.render config
        let permanent = policyOutput "docker" "" "" "" []
        let mutable drift = false
        let run executable arguments _ =
            if executable <> "firewall-cmd" then failwith "Unexpected executable."
            match arguments with
            | [ "--policy=blockdocker"; "--list-all" ] -> commandResult (if drift then policyOutput "ANY" "" "" "" [] else permanent)
            | [ "--permanent"; "--policy=blockdocker"; "--list-all" ] -> commandResult permanent
            | [ "--policy=blockdocker"; "--list-rich-rules" ]
            | [ "--permanent"; "--policy=blockdocker"; "--list-rich-rules" ] -> commandResult ""
            | [ "--get-policies" ] -> commandResult "blockdocker"
            | _ -> failwith ("Unexpected firewalld argv: " + String.concat " " arguments)
        let environment, root = makeEnvironment run
        try
            let policyDirectory = Path.Combine(root, "etc/firewalld/policies")
            Directory.CreateDirectory policyDirectory |> ignore
            File.WriteAllText(Path.Combine(policyDirectory, "blockdocker.xml"), actual)
            Assert.That(FirewalldRuntime.listRuntime environment "policy", Is.EqualTo(Some [ "blockdocker" ]))
            Assert.That(FirewalldRuntime.inSync environment config, Is.True)
            drift <- true
            Assert.That(FirewalldRuntime.inSync environment config, Is.False)
        finally
            if Directory.Exists root then Directory.Delete(root, true)

    [<Test>]
    member _.``Runtime ipset projection exposes live entries and typed options``() =
        let run executable arguments _ =
            if executable = "firewall-cmd" && arguments = [ "--info-ipset=trusted" ] then
                commandResult "trusted\n  type: hash:net\n  options: family=inet hashsize=1024\n  entries: 192.0.2.0/24 198.51.100.0/24\n"
            else failwith "Unexpected fixture command."
        let environment, root = makeEnvironment run
        try
            Directory.CreateDirectory root |> ignore
            let snapshot = FirewalldRuntime.inspectRuntime environment "ipset" "trusted" |> Option.get
            Assert.That(snapshot.IpSetType, Is.EqualTo(Some "hash:net"))
            Assert.That(snapshot.IpSetOptions, Is.EqualTo<Map<string,string option>>(Map.ofList [ "family", Some "inet"; "hashsize", Some "1024" ]))
            Assert.That(snapshot.IpSetEntries, Is.EquivalentTo [ "192.0.2.0/24"; "198.51.100.0/24" ])
            Assert.That(snapshot.UnknownFields, Is.Empty)
        finally
            if Directory.Exists root then Directory.Delete(root, true)
