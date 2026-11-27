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
    member _.``Safe adoption preserves baseline features and allows explicit additions``() =
        let config =
            { FirewalldModel.empty "zone" "public" with
                Target = "DROP"
                Services = [ "ssh" ]
                Elements = [ element "description" [] (Some "preserved") [] ] }
        let baseline = "<zone target=\"DROP\"><service name=\"ssh\"/><description>preserved</description></zone>"
        Assert.That(FieldRuntime.safeAdoption config baseline, Is.True)
        let legacyBaseline =
            "<zone target=\"DROP\"><service name=\"ssh\"/><port port=\"9090\" protocol=\"tcp\"/><description>preserved</description></zone>"
        let explicitSuperset = { config with Ports = [ "9090/tcp"; "9443/tcp" ] }
        Assert.That(FieldRuntime.safeAdoption explicitSuperset legacyBaseline, Is.True)
        Assert.That(FieldRuntime.safeAdoption config legacyBaseline, Is.False)
        Assert.That(FieldRuntime.safeAdoption { explicitSuperset with Target = "default" } legacyBaseline, Is.False)
        Assert.That(FieldRuntime.safeAdoption { explicitSuperset with Target = "ACCEPT" } "<zone><service name=\"ssh\"/></zone>", Is.False)

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
    member _.``Live restrictive rich additions and authoritative NetworkManager interfaces do not drift``() =
        let config = { FirewalldModel.empty "zone" "quiet" with Services = [ "ssh" ] }
        let ban = "rule family=\"ipv4\" source address=\"192.0.2.7\" reject limit value=\"10/m\""
        let accept = "rule family=\"ipv4\" source address=\"192.0.2.8\" accept"
        let mutable richRules = [ ban ]
        let run executable arguments _ =
            match executable, arguments with
            | "firewall-cmd", [ "--zone=quiet"; "--list-all" ] ->
                commandResult(zoneOutput "ssh" "" [] richRules)
            | "firewall-cmd", [ "--zone=quiet"; "--list-interfaces" ] -> commandResult "eth0"
            | "nmcli", [ "-g"; "GENERAL.CON-UUID"; "device"; "show"; "eth0" ] -> commandResult "c9442404-b0ac-40fe-9bd0-ddbcb382196f"
            | "nmcli", [ "-g"; "connection.zone"; "connection"; "show"; "uuid"; "c9442404-b0ac-40fe-9bd0-ddbcb382196f" ] -> commandResult "quiet"
            | _ -> failwith ("Unexpected fixture command: " + executable + " " + String.concat " " arguments)
        let environment, root = makeEnvironment run
        try
            Directory.CreateDirectory root |> ignore
            let banObservation = FirewalldRuntime.observe environment config
            Assert.That(banObservation.Observed, Is.True)
            Assert.That(banObservation.InSync, Is.True)
            richRules <- [ accept ]
            let acceptObservation = FirewalldRuntime.observe environment config
            Assert.That(acceptObservation.Observed, Is.True)
            Assert.That(acceptObservation.InSync, Is.False)
            Assert.That(FirewalldRuntime.isRestrictiveRichRule ban, Is.True)
            Assert.That(
                FirewalldRuntime.isRestrictiveRichRule "rule family=\"ipv4\" source address=\"drop\" accept",
                Is.False)
        finally
            if Directory.Exists root then Directory.Delete(root, true)

    [<Test>]
    member _.``Overlapping port and source-port ranges normalize but adjacent ranges remain distinct``() =
        Assert.That(
            FirewalldRuntime.normalizeFieldValues "zone" "ports" [ "8005-8015/tcp 8000-8010/tcp" ],
            Is.EquivalentTo [ "8000-8015/tcp" ])
        Assert.That(
            FirewalldRuntime.normalizeFieldValues "policy" "source-ports" [ "2000-2010/udp"; "2005-2015/udp" ],
            Is.EquivalentTo [ "2000-2015/udp" ])
        Assert.That(
            FirewalldRuntime.normalizeFieldValues "zone" "ports" [ "8000-8010/tcp"; "8011-8015/tcp" ],
            Is.EquivalentTo [ "8000-8010/tcp"; "8011-8015/tcp" ])

    [<Test>]
    member _.``Rich selector ordering limits and default MSS value match firewalld native rendering``() =
        let source = element "source" [ "address", "192.0.2.0/24" ] None []
        let destination = element "destination" [ "address", "198.51.100.0/24" ] None []
        let mssClamp = element "tcp-mss-clamp" [] None []
        let rule = element "rule" [ "family", "ipv4" ] None [ destination; source; mssClamp ]
        let limitedSource = element "source" [ "address", "203.0.113.0/24" ] None []
        let logLimit = element "limit" [ "value", "10/minute"; "burst", "20" ] None []
        let log = element "log" [ "prefix", "limited" ] None [ logLimit ]
        let actionLimit = element "limit" [ "value", "5/second" ] None []
        let drop = element "drop" [] None [ actionLimit ]
        let limitedRule = element "rule" [ "family", "ipv4" ] None [ limitedSource; log; drop ]
        let config = { FirewalldModel.empty "zone" "quiet" with Elements = [ rule; limitedRule ] }
        let nativeRule =
            "rule family=\"ipv4\" source address=\"192.0.2.0/24\" destination address=\"198.51.100.0/24\" tcp-mss-clamp value=\"pmtu\""
        let nativeLimitedRule =
            "rule family=\"ipv4\" source address=\"203.0.113.0/24\" log prefix=\"limited\" limit value=\"10/m\" burst=20 drop limit value=\"5/s\""
        Assert.That(
            FirewalldRuntime.expectedRichRuleStrings config,
            Is.EqualTo(Some [ nativeRule; nativeLimitedRule ]))
        let run executable arguments _ =
            match executable, arguments with
            | "firewall-cmd", [ "--zone=quiet"; "--list-all" ] ->
                commandResult(zoneOutput "" "" [] [ nativeRule; nativeLimitedRule ])
            | "firewall-cmd", [ "--zone=quiet"; "--list-interfaces" ] -> commandResult ""
            | _ -> failwith ("Unexpected fixture command: " + executable + " " + String.concat " " arguments)
        let environment, root = makeEnvironment run
        try
            Directory.CreateDirectory root |> ignore
            let observation = FirewalldRuntime.observe environment config
            Assert.That(observation.Observed, Is.True)
            Assert.That(observation.InSync, Is.True)
            let projected =
                match FirewalldRuntime.snapshotFromXml "zone" "quiet" (Some(FieldRuntime.render config)) with
                | Ok(Some snapshot) -> snapshot
                | result -> failwith ("Unable to project effective XML: " + string result)
            let exactProjection = FirewalldRuntime.observeSnapshotExactly environment projected
            Assert.That(exactProjection.Observed, Is.True)
            Assert.That(exactProjection.InSync, Is.True)
        finally
            if Directory.Exists root then Directory.Delete(root, true)

    [<Test>]
    member _.``Service modules and ICMP family defaults use native spellings``() =
        let service =
            { FirewalldModel.empty "service" "ftp-control" with
                Elements = [ element "module" [ "name", "nf_conntrack_ftp" ] None [] ] }
        let disabledIcmp =
            { FirewalldModel.empty "icmptype" "no-family" with
                Elements = [ element "destination" [ "ipv4", "no"; "ipv6", "no" ] None [] ] }
        let defaultIcmp = FirewalldModel.empty "icmptype" "all-families"
        let run executable arguments _ =
            match executable, arguments with
            | "firewall-cmd", [ "--info-service=ftp-control" ] ->
                commandResult "ftp-control\n  ports:\n  protocols:\n  source-ports:\n  modules: ftp\n  destination:\n  includes:\n  helpers:\n"
            | "firewall-cmd", [ "--info-icmptype=no-family" ] ->
                commandResult "no-family\n  destination: ipv4 ipv6\n"
            | "firewall-cmd", [ "--info-icmptype=all-families" ] ->
                commandResult "all-families\n  destination: ipv4 ipv6\n"
            | _ -> failwith ("Unexpected fixture command: " + executable + " " + String.concat " " arguments)
        let environment, root = makeEnvironment run
        try
            Directory.CreateDirectory root |> ignore
            Assert.That(FirewalldRuntime.inSync environment service, Is.True)
            Assert.That(FirewalldRuntime.inSync environment disabledIcmp, Is.True)
            Assert.That(FirewalldRuntime.inSync environment defaultIcmp, Is.True)
        finally
            if Directory.Exists root then Directory.Delete(root, true)


    [<Test>]
    member _.``Reload preflight refuses foreign runtime differences across unrelated objects and ipsets``() =
        let mutable zoneRules = []
        let mutable policyRules = []
        let mutable policyPorts = "22/tcp"
        let mutable zoneServices = "ssh"
        let mutable zonePorts = "80/tcp"
        let mutable serviceDestination = ""
        let mutable includedServicePorts = ""
        let mutable ipsetEntries = "192.0.2.7"
        let mutable timeout = ""
        let mutable foreignDirect = ""
        let mutable timedMember = true
        let serviceOutput name ports destination includes =
            name + "\n  ports: " + ports + "\n  protocols:\n  source-ports:\n  modules:\n  destination: " + destination + "\n  includes: " + includes + "\n  helpers:\n"
        let zoneWithPorts services ports rules =
            (zoneOutput services "" [] rules).Replace("  ports: \n", "  ports: " + ports + "\n", StringComparison.Ordinal)
        let ipsetOutput entries =
            "blocked\n  type: hash:net\n  options: family=inet hashsize=1024" + timeout + "\n  entries: " + (if timeout = "" then entries else "") + "\n"
        let run executable arguments _ =
            match executable, arguments with
            | "nft", [ "-j"; "list"; "table"; "inet"; "firewalld" ] ->
                let entries = if timedMember then ",\"elem\":[{\"elem\":{\"val\":\"192.0.2.7\",\"expires\":15000}}]" else ""
                commandResult ("{\"nftables\":[{\"set\":{\"family\":\"inet\",\"table\":\"firewalld\",\"name\":\"blocked\"" + entries + "}}]}")
            | "firewall-cmd", [ "--direct"; "--get-all-rules" ] -> commandResult foreignDirect
            | "firewall-cmd", [ "--direct"; _ ]
            | "firewall-cmd", [ "--permanent"; "--direct"; _ ] -> commandResult ""
            | "firewall-cmd", [ "--get-zones" ]
            | "firewall-cmd", [ "--permanent"; "--get-zones" ] -> commandResult "public"
            | "firewall-cmd", [ "--get-policies" ]
            | "firewall-cmd", [ "--permanent"; "--get-policies" ] -> commandResult "edge"
            | "firewall-cmd", [ "--get-services" ]
            | "firewall-cmd", [ "--permanent"; "--get-services" ] -> commandResult "ssh ssh-aux"
            | "firewall-cmd", [ "--get-ipsets" ]
            | "firewall-cmd", [ "--permanent"; "--get-ipsets" ] -> commandResult "blocked"
            | "firewall-cmd", [ "--zone=public"; "--list-all" ] ->
                commandResult(zoneWithPorts zoneServices zonePorts zoneRules)
            | "firewall-cmd", [ "--permanent"; "--zone=public"; "--list-all" ] ->
                commandResult(zoneWithPorts "ssh" "80/tcp" [])
            | "firewall-cmd", [ "--zone=public"; "--list-interfaces" ]
            | "firewall-cmd", [ "--permanent"; "--zone=public"; "--list-interfaces" ] -> commandResult ""
            | "firewall-cmd", [ "--policy=edge"; "--list-all" ] ->
                commandResult(policyOutput "docker" "" policyPorts "" policyRules)
            | "firewall-cmd", [ "--permanent"; "--policy=edge"; "--list-all" ] ->
                commandResult(policyOutput "docker" "" "22/tcp" "" [])
            | "firewall-cmd", [ "--info-service=ssh" ] -> commandResult(serviceOutput "ssh" "" serviceDestination "ssh-aux")
            | "firewall-cmd", [ "--permanent"; "--info-service=ssh" ] -> commandResult(serviceOutput "ssh" "" "" "ssh-aux")
            | "firewall-cmd", [ "--info-service=ssh-aux" ] -> commandResult(serviceOutput "ssh-aux" includedServicePorts "" "")
            | "firewall-cmd", [ "--permanent"; "--info-service=ssh-aux" ] -> commandResult(serviceOutput "ssh-aux" "" "" "")
            | "firewall-cmd", [ "--info-ipset=blocked" ] -> commandResult(ipsetOutput ipsetEntries)
            | "firewall-cmd", [ "--permanent"; "--info-ipset=blocked" ] -> commandResult(ipsetOutput "192.0.2.7")
            | _ -> failwith ("Unexpected fixture command: " + executable + " " + String.concat " " arguments)
        let environment, root = makeEnvironment run
        let expectRefusal () =
            match FirewalldRuntime.validateReload environment with
            | Error _ -> ()
            | Ok () -> Assert.Fail("Reload preflight accepted an unpersisted runtime change.")
        let expectTargetedRefusal kind name field value =
            match FirewalldRuntime.validateReloadAllowingMissingSelector environment kind name field value with
            | Error _ -> ()
            | Ok () -> Assert.Fail("Targeted reload preflight accepted another host difference.")
        try
            Directory.CreateDirectory root |> ignore
            Assert.That(FirewalldRuntime.validateReload environment, Is.EqualTo(Ok () : Result<unit, string>))
            let newTarget () = FirewalldRuntime.validateReloadExcludingTargetObject environment "service" "not-yet-loaded"
            Assert.That(newTarget (), Is.EqualTo(Ok () : Result<unit, string>))
            let releasedPolicy disappears =
                let mutable inspected = false
                let runChanging exe args input =
                    match exe, args with
                    | "firewall-cmd", [ "--permanent"; "--policy=edge"; "--list-all" ] ->
                        inspected <- true
                        { commandResult "" with ExitCode = 1 }
                    | "firewall-cmd", [ "--permanent"; "--get-policies" ] when inspected && disappears -> commandResult ""
                    | _ -> run exe args input
                let changing = { environment with Run = runChanging }
                FirewalldRuntime.validateReloadExcludingTargetObject changing "policy" "edge"
            Assert.That(releasedPolicy true, Is.EqualTo(Ok () : Result<unit, string>))
            Assert.That(Result.isError (releasedPolicy false), Is.True)
            timeout <- " timeout=60"
            expectRefusal ()
            timedMember <- false
            Assert.That(FirewalldRuntime.validateReload environment, Is.EqualTo(Ok () : Result<unit, string>))
            timeout <- ""
            foreignDirect <- "ipv4 filter INPUT 0 independently-owned-rule"
            expectRefusal ()
            Assert.That(Result.isError (newTarget ()), Is.True)
            foreignDirect <- ""
            zoneServices <- ""
            zonePorts <- ""
            expectRefusal ()
            Assert.That(
                FirewalldRuntime.validateReloadAllowingMissingSelectors
                    environment "zone" "public" [ "services", "ssh"; "ports", "80/tcp" ],
                Is.EqualTo(Ok () : Result<unit, string>))
            policyPorts <- "8080/tcp"
            expectTargetedRefusal "zone" "public" "services" "ssh"
            policyPorts <- "22/tcp"
            zoneServices <- "ssh"
            zonePorts <- "80/tcp"
            policyPorts <- ""
            expectRefusal ()
            Assert.That(
                FirewalldRuntime.validateReloadAllowingMissingSelectors environment "policy" "edge" [ "ports", "22/tcp" ],
                Is.EqualTo(Ok () : Result<unit, string>))
            policyPorts <- "22/tcp"
            serviceDestination <- "ipv4:192.0.2.1"
            expectRefusal ()
            serviceDestination <- ""
            includedServicePorts <- "8443/tcp"
            expectRefusal ()
            includedServicePorts <- ""
            policyPorts <- "8080/tcp"
            expectRefusal ()
            policyPorts <- "22/tcp"
            policyRules <- [ "rule family=\"ipv4\" source address=\"192.0.2.9\" drop" ]
            expectRefusal ()
            policyRules <- []
            zoneRules <- [ "rule family=\"ipv4\" source address=\"192.0.2.8\" reject" ]
            Assert.That(FirewalldRuntime.validateReloadExcludingTargetObject environment "zone" "public", Is.EqualTo(Ok () : Result<unit, string>))
            let expectedAfter =
                { FirewalldModel.empty "zone" "public" with
                    Services = [ "ssh" ]
                    Ports = [ "80/tcp" ] }
            let exactTarget = FirewalldRuntime.observeExactly environment expectedAfter
            Assert.That(exactTarget.Observed, Is.True)
            Assert.That(exactTarget.InSync, Is.False)
            expectRefusal ()
            zoneRules <- []
            ipsetEntries <- "192.0.2.7 198.51.100.4"
            expectRefusal ()
        finally
            if Directory.Exists root then Directory.Delete(root, true)
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
            match executable, arguments with
            | "firewall-cmd", [ "--zone=quiet"; "--list-all" ] -> commandResult output
            | "firewall-cmd", [ "--zone=quiet"; "--list-interfaces" ] -> commandResult ""
            | _ -> failwith "Unexpected fixture command."
        let environment, root = makeEnvironment run
        try
            Directory.CreateDirectory root |> ignore
            let snapshot = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            Assert.That(snapshot.SourcesRaw, Is.EquivalentTo [ "192.0.2.0/24"; "02:00:00:00:00:01"; "ipset:trusted" ])
            Assert.That(snapshot.Sources |> List.map (fun source -> source.Attributes), Is.EquivalentTo [ Map.ofList [ "address", "192.0.2.0/24" ]; Map.ofList [ "address", "02:00:00:00:00:01" ]; Map.ofList [ "ipset", "trusted" ] ])
            Assert.That(snapshot.ForwardPorts.Head.Attributes, Is.EqualTo<Map<string,string>>(Map.ofList [ "port", "443"; "protocol", "tcp"; "to-port", "8443"; "to-addr", "192.0.2.9" ]))
            Assert.That(
                FirewalldRuntime.canonicalForwardPortValue snapshot.ForwardPorts.Head,
                Is.EqualTo(Some "port=443:proto=tcp:toport=8443:toaddr=192.0.2.9"))
            let expectedConfig =
                { FirewalldModel.empty "zone" "quiet" with
                    Elements =
                        [ element "forward-port"
                              [ "port", "443"; "protocol", "tcp"; "to-port", "8443"; "to-addr", "192.0.2.9" ]
                              None
                              [] ] }
            Assert.That(
                FirewalldRuntime.expectedForwardPortValues expectedConfig,
                Is.EqualTo(Some [ "port=443:proto=tcp:toport=8443:toaddr=192.0.2.9" ]))
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

    [<Test>]
    member _.``An empty active NM zone resolves to the running default only``() =
        let uuid = "7bf884ec-3192-4527-acbb-f3b29477b7c6"
        let run exe args _ =
            match exe, args with
            | "nmcli", [ "-g"; "GENERAL.CON-UUID"; "device"; "show"; "nm0" ] -> commandResult uuid
            | "nmcli", [ "-g"; "connection.zone"; "connection"; "show"; "uuid"; id ] when id = uuid -> commandResult ""
            | "firewall-cmd", [ "--get-default-zone" ] -> commandResult "public"
            | _ -> commandResult ""
        let env, _ = makeEnvironment run
        Assert.That(FirewalldRuntime.restoresRuntimeInterface env "nm0" "public", Is.True)
        Assert.That(FirewalldRuntime.restoresRuntimeInterface env "nm0" "trusted", Is.False)
        Assert.That(FirewalldRuntime.restoresRuntimeInterface env "unowned" "public", Is.False)
