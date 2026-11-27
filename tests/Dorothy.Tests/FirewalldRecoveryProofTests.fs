namespace Dorothy.Tests

open System
open System.Collections.Generic
open System.IO
open Dorothy.HostHelper
open NUnit.Framework

[<TestFixture>]
type FirewalldRecoveryProofTests() =
    let commandResult (stdout: string) : CommandResult =
        { ExitCode = 0; Stdout = stdout; Stderr = "" }

    let restoreWithoutReload environment configuration xml proof phase =
        FirewalldRecoveryProof.restoreRuntimeWithPreReload environment configuration xml proof phase
            (fun () -> Assert.Fail "A scoped inverse must not reload the daemon.")

    let configuration =
        { FirewalldModel.empty "zone" "quiet" with
            Services = [ "ssh" ]
            Ports = [ "443/tcp" ] }

    let withRuntime initialPorts initialServices (action: HostEnvironment -> ResizeArray<string list> -> (string list -> unit) -> unit) =
        let mutable ports = initialPorts
        let mutable services = initialServices
        let calls = ResizeArray<string list>()
        let zoneOutput (zonePorts: string list) (zoneServices: string list) =
            "quiet\n"
            + "  target: default\n"
            + "  ingress-priority: 0\n"
            + "  egress-priority: 0\n"
            + "  icmp-block-inversion: no\n"
            + "  interfaces: \n"
            + "  sources: \n"
            + "  services: " + String.concat " " zoneServices + "\n"
            + "  ports: " + String.concat " " zonePorts + "\n"
            + "  protocols: \n"
            + "  forward: no\n"
            + "  masquerade: no\n"
            + "  forward-ports:\n"
            + "  source-ports: \n"
            + "  icmp-blocks: \n"
            + "  rich rules:\n"
        let serviceInfo =
            "ssh\n"
            + "  ports: 22/tcp\n"
            + "  protocols: \n"
            + "  source-ports: \n"
            + "  modules: \n"
            + "  destination: \n"
            + "  includes: \n"
            + "  helpers: \n"
        let run executable arguments _ =
            calls.Add(executable :: arguments)
            match executable, arguments with
            | "firewall-cmd", [ "--zone=quiet"; "--list-all" ] -> commandResult (zoneOutput ports services)
            | "firewall-cmd", [ "--permanent"; "--zone=quiet"; "--list-all" ] -> commandResult (zoneOutput [ "443/tcp" ] [ "ssh" ])
            | "firewall-cmd", [ "--zone=quiet"; "--list-interfaces" ]
            | "firewall-cmd", [ "--zone=quiet"; "--list-rich-rules" ]
            | "firewall-cmd", [ "--permanent"; "--zone=quiet"; "--list-interfaces" ]
            | "firewall-cmd", [ "--permanent"; "--zone=quiet"; "--list-rich-rules" ] -> commandResult ""
            | "firewall-cmd", [ "--get-zones" ]
            | "firewall-cmd", [ "--permanent"; "--get-zones" ] -> commandResult "quiet"
            | "firewall-cmd", [ "--get-policies" ]
            | "firewall-cmd", [ "--permanent"; "--get-policies" ]
            | "firewall-cmd", [ "--get-ipsets" ]
            | "firewall-cmd", [ "--permanent"; "--get-ipsets" ] -> commandResult ""
            | "firewall-cmd", [ "--info-service=ssh" ]
            | "firewall-cmd", [ "--permanent"; "--info-service=ssh" ] -> commandResult serviceInfo
            | "firewall-cmd", [ "--zone=quiet"; "--add-service=ssh" ] ->
                services <- [ "ssh" ]
                commandResult "success"
            | "firewall-cmd", [ "--zone=quiet"; "--remove-service=ssh" ] ->
                services <- []
                commandResult "success"
            | "firewall-cmd", [ "--zone=quiet"; "--add-port=443/tcp" ] ->
                ports <- [ "443/tcp" ]
                commandResult "success"
            | "firewall-cmd", [ "--zone=quiet"; "--remove-port=443/tcp" ] ->
                ports <- []
                commandResult "success"
            | _ -> failwith ("Unexpected firewalld proof test command: " + String.concat " " (executable :: arguments))
        let environment =
            { Root = Path.Combine(Path.GetTempPath(), "dorothy-firewalld-recovery-proof")
              Run = run
              UtcNow = fun () -> DateTimeOffset.UnixEpoch }
        let replacePorts values = ports <- values
        action environment calls replacePorts

    let element name attributes children : FirewalldModel.Element =
        { Name = name
          Attributes = Map.ofList attributes
          Text = None
          Children = children }

    let selectorValues (configuration: FirewalldModel.Configuration) =
        let direct name key =
            configuration.Elements
            |> List.filter (fun item -> item.Name = name)
            |> List.choose (fun item -> Map.tryFind key item.Attributes)
        let ports name =
            configuration.Elements
            |> List.filter (fun item -> item.Name = name)
            |> List.choose (fun item ->
                match Map.tryFind "port" item.Attributes, Map.tryFind "protocol" item.Attributes with
                | Some port, Some protocol -> Some(FirewalldModel.port (port + "/" + protocol))
                | _ -> None)
        Map.ofList
            [ "services", configuration.Services @ direct "service" "name"
              "ports", configuration.Ports @ ports "port"
              "source-ports", ports "source-port"
              "protocols", configuration.Protocols @ direct "protocol" "value"
              "icmp-blocks", direct "icmp-block" "name"
              "rich rules", FirewalldRuntime.expectedRichRuleStrings configuration |> Option.defaultValue []
              "forward-ports", FirewalldRuntime.expectedForwardPortValues configuration |> Option.defaultValue [] ]

    let withSelectorRuntime
        (configuration: FirewalldModel.Configuration)
        (initial: Map<string, string list>)
        (action: HostEnvironment -> ResizeArray<string list> -> (unit -> Map<string, string list>) -> (Map<string, string list> -> unit) -> unit)
        =
        let permanent =
            let direct name key =
                configuration.Elements
                |> List.filter (fun item -> item.Name = name)
                |> List.choose (fun item -> Map.tryFind key item.Attributes)
            let directPorts name =
                configuration.Elements
                |> List.filter (fun item -> item.Name = name)
                |> List.choose (fun item ->
                    match Map.tryFind "port" item.Attributes, Map.tryFind "protocol" item.Attributes with
                    | Some port, Some protocol -> Some(FirewalldModel.port (port + "/" + protocol))
                    | _ -> None)
            Map.ofList
                [ "services", configuration.Services @ direct "service" "name"
                  "ports", configuration.Ports @ directPorts "port"
                  "source-ports", directPorts "source-port"
                  "protocols", configuration.Protocols @ direct "protocol" "value"
                  "icmp-blocks", direct "icmp-block" "name"
                  "rich rules", FirewalldRuntime.expectedRichRuleStrings configuration |> Option.defaultValue []
                  "forward-ports", FirewalldRuntime.expectedForwardPortValues configuration |> Option.defaultValue [] ]
        let mutable runtime = initial
        let calls = ResizeArray<string list>()
        let text (values: Map<string, string list>) field =
            Map.tryFind field values |> Option.defaultValue [] |> String.concat " "
        let block (values: Map<string, string list>) field =
            match Map.tryFind field values |> Option.defaultValue [] with
            | [] -> "\n"
            | entries -> "\n\t" + String.concat "\n\t" entries + "\n"
        let listAll values =
            "quiet\n"
            + "  target: " + configuration.Target + "\n"
            + "  ingress-priority: 0\n"
            + "  egress-priority: 0\n"
            + "  icmp-block-inversion: "
            + (if configuration.Elements |> List.exists (fun item -> item.Name = "icmp-block-inversion") then "yes" else "no")
            + "\n"
            + "  interfaces: \n"
            + "  sources: \n"
            + "  services: " + text values "services" + "\n"
            + "  ports: " + text values "ports" + "\n"
            + "  protocols: " + text values "protocols" + "\n"
            + "  forward: no\n"
            + "  masquerade: no\n"
            + "  forward-ports:" + block values "forward-ports"
            + "  source-ports: " + text values "source-ports" + "\n"
            + "  icmp-blocks: " + text values "icmp-blocks" + "\n"
            + "  rich rules:" + block values "rich rules"
        let options =
            [ "--add-service=", "services", true; "--remove-service=", "services", false
              "--add-port=", "ports", true; "--remove-port=", "ports", false
              "--add-source-port=", "source-ports", true; "--remove-source-port=", "source-ports", false
              "--add-protocol=", "protocols", true; "--remove-protocol=", "protocols", false
              "--add-icmp-block=", "icmp-blocks", true; "--remove-icmp-block=", "icmp-blocks", false
              "--add-rich-rule=", "rich rules", true; "--remove-rich-rule=", "rich rules", false
              "--add-forward-port=", "forward-ports", true; "--remove-forward-port=", "forward-ports", false ]
        let run executable arguments _ =
            calls.Add(executable :: arguments)
            let nativeResult () =
                match arguments with
                | [ "--get-zones" ]
                | [ "--permanent"; "--get-zones" ] -> Some "quiet"
                | [ "--zone=quiet"; "--list-all" ] -> Some(listAll runtime)
                | [ "--permanent"; "--zone=quiet"; "--list-all" ] -> Some(listAll permanent)
                | [ "--zone=quiet"; "--list-interfaces" ]
                | [ "--permanent"; "--zone=quiet"; "--list-interfaces" ] -> Some ""
                | [ "--zone=quiet"; "--list-rich-rules" ] -> Some(String.concat "\n" (Map.find "rich rules" runtime))
                | [ "--permanent"; "--zone=quiet"; "--list-rich-rules" ] -> Some(String.concat "\n" (Map.find "rich rules" permanent))
                | [ "--zone=quiet"; operation ] ->
                    options
                    |> List.tryPick (fun (prefix, field, add) ->
                        if operation.StartsWith(prefix, StringComparison.Ordinal) then
                            let value = operation.Substring(prefix.Length)
                            let current = Map.find field runtime
                            let updated = if add then value :: current |> List.distinct else current |> List.filter ((<>) value)
                            runtime <- Map.add field updated runtime
                            Some "success"
                        else None)
                | _ -> None
            let commandResult = if executable = "firewall-cmd" then nativeResult () else None
            match commandResult with
            | Some stdout -> { ExitCode = 0; Stdout = stdout; Stderr = "" }
            | None -> failwith ("Unexpected multi-selector proof command: " + String.concat " " (executable :: arguments))
        let environment =
            { Root = Path.Combine(Path.GetTempPath(), "dorothy-firewalld-multi-selector")
              Run = run
              UtcNow = fun () -> DateTimeOffset.UnixEpoch }
        action environment calls (fun () -> runtime) (fun value -> runtime <- value)


    [<Test>]
    member _.``Reload preimage must match exact effective disk XML and live selectors``() =
        withSelectorRuntime configuration (selectorValues configuration) (fun environment calls _ _ ->
            let originalRun = environment.Run
            let interfaceUuid = "c9442404-b0ac-40fe-9bd0-ddbcb382196f"
            let run executable arguments input =
                match executable, arguments with
                | "firewall-cmd", [ "--zone=quiet"; "--list-interfaces" ]
                | "firewall-cmd", [ "--permanent"; "--zone=quiet"; "--list-interfaces" ] -> commandResult "eth0"
                | "nmcli", [ "-g"; "GENERAL.CON-UUID"; "device"; "show"; "eth0" ] -> commandResult interfaceUuid
                | "nmcli", [ "-g"; "connection.zone"; "connection"; "show"; "uuid"; value ]
                    when value = interfaceUuid -> commandResult "quiet"
                | _ -> originalRun executable arguments input
            let environment = { environment with Run = run }
            let matchingXml = FieldRuntime.render configuration
            let proof = FirewalldRecoveryProof.reloadProof environment configuration (Some matchingXml) (Some matchingXml)
            Assert.That(proof["beforePresent"].GetValue<bool>(), Is.True)
            let driftedDisk = { configuration with Ports = [ "8443/tcp" ] }
            Assert.Throws<InvalidOperationException>(fun () ->
                FirewalldRecoveryProof.reloadProof
                    environment
                    configuration
                    (Some(FieldRuntime.render driftedDisk))
                    (Some matchingXml)
                |> ignore)
            |> ignore
            Assert.Throws<InvalidOperationException>(fun () ->
                restoreWithoutReload
                    environment
                    configuration
                    (Some(FieldRuntime.render driftedDisk))
                    (Some proof)
                    FirewalldLifecycle.ActiveDaemon
                |> ignore)
            |> ignore
            Assert.That(calls |> Seq.exists (fun args -> List.contains "--reload" args), Is.False))

    [<Test>]
    member _.``Reload rollback must pass the safety check before any reload``() =
        let preimage = { configuration with Ports = [] }
        withSelectorRuntime preimage (selectorValues preimage) (fun environment calls _ setCurrent ->
            let preimageXml = Some(FieldRuntime.render preimage)
            let postimageXml = Some(FieldRuntime.render configuration)
            let proof = FirewalldRecoveryProof.reloadProof environment preimage preimageXml postimageXml
            setCurrent (selectorValues configuration)
            let mutable checkedSafety = false
            let error =
                Assert.Throws<InvalidOperationException>(fun () ->
                    FirewalldRecoveryProof.restoreRuntimeWithPreReload
                        environment
                        preimage
                        preimageXml
                        (Some proof)
                        FirewalldLifecycle.ActiveDaemon
                        (fun () ->
                            checkedSafety <- true
                            raise (InvalidOperationException("blocked by reload safety preflight")))
                    |> ignore)
            Assert.That(error.Message, Is.EqualTo "blocked by reload safety preflight")
            Assert.That(checkedSafety, Is.True)
            Assert.That(calls |> Seq.exists (fun args -> List.contains "--reload" args), Is.False))

    [<Test>]
    member _.``Reload preimage accepts native coalescing of both destination and source intervals``() =
        let sourcePort range = element "source-port" [ "port", range; "protocol", "tcp" ] []
        let declared = { configuration with Ports = [ "8000-8010/tcp"; "8005-8015/tcp" ]; Elements = [ sourcePort "9000-9004"; sourcePort "9003-9008" ] }
        let coalesced = { configuration with Ports = [ "8000-8015/tcp" ]; Elements = [ sourcePort "9000-9008" ] }
        withSelectorRuntime coalesced (selectorValues coalesced) (fun environment calls _ _ ->
            let xml = Some(FieldRuntime.render declared)
            let proof = FirewalldRecoveryProof.reloadProof environment declared xml xml
            Assert.That(proof["beforePresent"].GetValue<bool>(), Is.True)
            let changed = Some(FieldRuntime.render { declared with Elements = [ sourcePort "9000-9007" ] })
            Assert.Throws<InvalidOperationException>(fun () ->
                FirewalldRecoveryProof.reloadProof environment declared changed xml |> ignore) |> ignore
            Assert.That(calls, Does.Not.Contain [ "firewall-cmd"; "--reload" ]))

    [<Test>]
    member _.``Dropped runtime port repair has an exact active and postboot inverse``() =
        withRuntime [] [ "ssh" ] (fun environment _ setPorts ->
            let snapshot = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            let proof = FirewalldRecoveryProof.runtimeRepairProof environment configuration snapshot
            Assert.That(proof["strategy"].GetValue<string>(), Is.EqualTo "runtime-delta")
            FirewalldRecoveryProof.activateRuntimeRepair environment configuration proof
            let repaired = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            Assert.That(repaired.Ports, Is.EquivalentTo [ "443/tcp" ])
            restoreWithoutReload environment configuration None (Some proof) FirewalldLifecycle.ActiveDaemon
            let rolledBack = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            Assert.That(rolledBack.Ports, Is.Empty)
            FirewalldRecoveryProof.activateRuntimeRepair environment configuration proof
            setPorts [ "443/tcp" ]
            restoreWithoutReload environment configuration None (Some proof) FirewalldLifecycle.BootBeforeFirewalld
            let daemonReady = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            Assert.That(daemonReady.Ports, Is.EquivalentTo [ "443/tcp" ])
            restoreWithoutReload environment configuration None (Some proof) FirewalldLifecycle.BootAfterFirewalld
            let postbootRollback = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            Assert.That(postbootRollback.Ports, Is.Empty))

    [<Test>]
    member _.``Runtime repair refuses multiple or foreign selector changes before mutation``() =
        withRuntime [] [ "ssh"; "http" ] (fun environment calls _ ->
            let snapshot = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            Assert.Throws<InvalidOperationException>(fun () ->
                FirewalldRecoveryProof.runtimeRepairProof environment configuration snapshot |> ignore)
            |> ignore
            Assert.That(calls |> Seq.exists (fun args -> args |> List.exists (fun value -> value.StartsWith("--add-", StringComparison.Ordinal))), Is.False))

    [<Test>]
    member _.``Dropped runtime service repair is restored with a scoped native inverse``() =
        withRuntime [ "443/tcp" ] [] (fun environment _ _ ->
            let snapshot = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            let proof = FirewalldRecoveryProof.runtimeRepairProof environment configuration snapshot
            let firstDelta = proof["deltas"].[0].AsObject()
            Assert.That(firstDelta["field"].GetValue<string>(), Is.EqualTo "services")
            Assert.That(firstDelta["value"].GetValue<string>(), Is.EqualTo "ssh")
            FirewalldRecoveryProof.activateRuntimeRepair environment configuration proof
            let repaired = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            Assert.That(repaired.Services, Is.EquivalentTo [ "ssh" ])
            restoreWithoutReload environment configuration None (Some proof) FirewalldLifecycle.ActiveDaemon
            let restored = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            Assert.That(restored.Services, Is.Empty))

    [<Test>]
    member _.``Multiple missing grant selectors replay in order and preserve a foreign timed ban``() =
        let config =
            { FirewalldModel.empty "zone" "quiet" with
                Services = [ "ssh"; "https" ]
                Ports = [ "443/tcp"; "8443/tcp" ]
                Protocols = [ "gre" ]
                Elements =
                    [ element "source-port" [ "port", "40000-40100"; "protocol", "udp" ] []
                      element "rule" [ "family", "ipv4" ]
                          [ element "port" [ "port", "9444"; "protocol", "tcp" ] []; element "accept" [] [] ] ] }
        let expected = selectorValues config
        let foreignBan = "rule family=\"ipv4\" source address=\"198.51.100.99\" drop"
        let initial =
            expected
            |> Map.map (fun field _ -> if field = "rich rules" then [ foreignBan ] else [])
        withSelectorRuntime config initial (fun environment calls current setCurrent ->
            let snapshot = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            let proof = FirewalldRecoveryProof.runtimeRepairProof environment config snapshot
            Assert.That(proof["deltas"].AsArray().Count, Is.GreaterThan 1)
            FirewalldRecoveryProof.activateRuntimeRepair environment config proof
            let repaired = current ()
            for field in [ "services"; "ports"; "source-ports"; "protocols"; "forward-ports" ] do
                Assert.That(repaired[field], Is.EquivalentTo expected[field], field)
            Assert.That(repaired["rich rules"], Does.Contain foreignBan)
            restoreWithoutReload environment config None (Some proof) FirewalldLifecycle.ActiveDaemon
            let rolledBack = current ()
            for field in Map.keys expected do
                if field = "rich rules" then
                    Assert.That(rolledBack[field], Is.EquivalentTo [ foreignBan ])
                else Assert.That(rolledBack[field], Is.Empty, field)
            FirewalldRecoveryProof.activateRuntimeRepair environment config proof
            let callCountBeforeBoot = calls.Count
            restoreWithoutReload environment config None (Some proof) FirewalldLifecycle.BootBeforeFirewalld
            Assert.That(calls.Count, Is.EqualTo callCountBeforeBoot)
            setCurrent expected
            restoreWithoutReload environment config None (Some proof) FirewalldLifecycle.BootAfterFirewalld
            let postboot = current ()
            for field in Map.keys expected do Assert.That(postboot[field], Is.Empty, field))

    [<Test>]
    member _.``A single forward-port steering delta has a native inverse``() =
        let config =
            { FirewalldModel.empty "zone" "quiet" with
                Elements =
                    [ element "forward-port"
                          [ "port", "8080"; "protocol", "tcp"; "to-port", "80"; "to-addr", "192.0.2.9" ] [] ] }
        let expected = selectorValues config
        let empty = expected |> Map.map (fun _ _ -> [])
        withSelectorRuntime config empty (fun environment calls current _ ->
            let snapshot = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            let proof = FirewalldRecoveryProof.runtimeRepairProof environment config snapshot
            Assert.That(proof["deltas"].AsArray().Count, Is.EqualTo 1)
            let delta = proof["deltas"].[0]
            Assert.That(delta["effect"].GetValue<string>(), Is.EqualTo "steer")
            FirewalldRecoveryProof.activateRuntimeRepair environment config proof
            let repaired = current ()
            Assert.That(repaired["forward-ports"], Is.EquivalentTo expected["forward-ports"])
            restoreWithoutReload environment config None (Some proof) FirewalldLifecycle.ActiveDaemon
            let restored = current ()
            Assert.That(restored["forward-ports"], Is.Empty)
            Assert.That(calls, Does.Contain [ "firewall-cmd"; "--zone=quiet"; "--add-forward-port=" + expected["forward-ports"].Head ])
            Assert.That(calls, Does.Contain [ "firewall-cmd"; "--zone=quiet"; "--remove-forward-port=" + expected["forward-ports"].Head ]))

    [<Test>]
    member _.``Multiple restrictive selectors compose but mixed effects are refused``() =
        let restrictive =
            { FirewalldModel.empty "zone" "quiet" with
                Elements =
                    [ element "icmp-block" [ "name", "echo-request" ] []
                      element "icmp-block" [ "name", "time-exceeded" ] []
                      element "rule" [ "family", "ipv4" ]
                          [ element "port" [ "port", "3389"; "protocol", "tcp" ] []; element "drop" [] [] ] ] }
        let expected = selectorValues restrictive
        let empty = expected |> Map.map (fun _ _ -> [])
        withSelectorRuntime restrictive empty (fun environment _ current _ ->
            let snapshot = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            let proof = FirewalldRecoveryProof.runtimeRepairProof environment restrictive snapshot
            Assert.That(proof["deltas"].AsArray().Count, Is.EqualTo 3)
            FirewalldRecoveryProof.activateRuntimeRepair environment restrictive proof
            let repaired = current ()
            for field in Map.keys expected do
                Assert.That(repaired[field], Is.EquivalentTo expected[field], field)
            restoreWithoutReload environment restrictive None (Some proof) FirewalldLifecycle.ActiveDaemon
            Assert.That(current (), Is.EqualTo(box empty)))

        let mixed =
            { FirewalldModel.empty "zone" "quiet" with
                Services = [ "ssh" ]
                Elements = [ element "icmp-block" [ "name", "echo-request" ] [] ] }
        let mixedExpected = selectorValues mixed
        let emptyMixed = mixedExpected |> Map.map (fun _ _ -> [])
        withSelectorRuntime mixed emptyMixed (fun environment calls _ _ ->
            let snapshot = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            Assert.Throws<InvalidOperationException>(fun () ->
                FirewalldRecoveryProof.runtimeRepairProof environment mixed snapshot |> ignore)
            |> ignore
            Assert.That(calls |> Seq.exists (fun args -> args |> List.exists (fun value -> value.StartsWith("--add-", StringComparison.Ordinal))), Is.False))

    [<Test>]
    member _.``ICMP block inversion classifies a missing block as a grant``() =
        let inverted =
            { FirewalldModel.empty "zone" "quiet" with
                Elements =
                    [ element "icmp-block-inversion" [] []
                      element "icmp-block" [ "name", "echo-request" ] [] ] }
        let expected = selectorValues inverted
        let empty = expected |> Map.map (fun _ _ -> [])
        withSelectorRuntime inverted empty (fun environment _ current _ ->
            let snapshot = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            let proof = FirewalldRecoveryProof.runtimeRepairProof environment inverted snapshot
            let delta = proof["deltas"].[0]
            Assert.That(delta["effect"].GetValue<string>(), Is.EqualTo "grant")
            FirewalldRecoveryProof.activateRuntimeRepair environment inverted proof
            let repaired = current ()
            Assert.That(repaired["icmp-blocks"], Is.EquivalentTo expected["icmp-blocks"])
            restoreWithoutReload environment inverted None (Some proof) FirewalldLifecycle.ActiveDaemon
            let restored = current ()
            Assert.That(restored["icmp-blocks"], Is.Empty))

    [<Test>]
    member _.``Native reject zone spelling survives disk and loaded rollback comparison``() =
        // 2.3.1 reports %%REJECT%% in both the vendor zone XML and --list-all.
        let blocked = { configuration with Target = "%%REJECT%%" }
        withSelectorRuntime blocked (selectorValues blocked) (fun environment _ _ _ ->
            let xml = Some(FieldRuntime.render blocked)
            let other = Some(FieldRuntime.render { blocked with Target = "ACCEPT" })
            let proof = FirewalldRecoveryProof.reloadProof environment blocked xml other
            Assert.That(proof["beforeFingerprint"].GetValue<string>(), Is.Not.EqualTo(proof["afterFingerprint"].GetValue<string>()))
            Assert.Throws<InvalidOperationException>(fun () ->
                FirewalldRecoveryProof.reloadProof environment blocked other xml |> ignore) |> ignore)

    [<Test>]
    member _.``Loaded projection accepts only UUID-authorized NetworkManager interfaces``() =
        let configuration = { FirewalldModel.empty "zone" "quiet" with Services = [ "ssh" ] }
        let project (configuration: FirewalldModel.Configuration) =
            match FirewalldRuntime.snapshotFromXml configuration.Kind configuration.Name (Some(FieldRuntime.render configuration)) with
            | Ok(Some snapshot) -> snapshot
            | _ -> failwith "Fixture XML did not project to a complete zone snapshot."
        let expected = project configuration
        let authorizedUuid = "c9442404-b0ac-40fe-9bd0-ddbcb382196f"
        let foreignUuid = "c9442404-b0ac-40fe-9bd0-ddbcb3821960"
        let mutable listedInterfaces = []
        let run executable arguments _ =
            match executable, arguments with
            | "firewall-cmd", [ "--zone=quiet"; "--list-interfaces" ] -> commandResult (String.concat " " listedInterfaces)
            | "firewall-cmd", [ "--permanent"; "--zone=quiet"; "--list-interfaces" ] -> commandResult (String.concat " " listedInterfaces)
            | "nmcli", [ "-g"; "GENERAL.CON-UUID"; "device"; "show"; "eth0" ] -> commandResult authorizedUuid
            | "nmcli", [ "-g"; "GENERAL.CON-UUID"; "device"; "show"; "eth1" ] -> commandResult foreignUuid
            | "nmcli", [ "-g"; "connection.zone"; "connection"; "show"; "uuid"; value ]
                when value = authorizedUuid -> commandResult "quiet"
            | "nmcli", [ "-g"; "connection.zone"; "connection"; "show"; "uuid"; value ]
                when value = foreignUuid -> commandResult "public"
            | _ -> failwith ("Unexpected NetworkManager projection command: " + executable + " " + String.concat " " arguments)
        let environment =
            { Root = Path.Combine(Path.GetTempPath(), "dorothy-firewalld-loaded-projection")
              Run = run
              UtcNow = fun () -> DateTimeOffset.UnixEpoch }
        let withInterfaces (snapshot: FirewalldRuntime.RuntimeSnapshot) (interfaces: string list) =
            { snapshot with
                Interfaces = interfaces
                NativeFields =
                    Map.add "interfaces"
                        (if interfaces.IsEmpty then [] else [ String.concat " " interfaces ])
                        snapshot.NativeFields }
        listedInterfaces <- [ "eth0" ]
        Assert.That(FirewalldRecoveryProof.matchesLoadedProjection environment expected (withInterfaces expected [ "eth0" ]), Is.True)
        listedInterfaces <- [ "eth1" ]
        Assert.That(FirewalldRecoveryProof.matchesLoadedProjection environment expected (withInterfaces expected [ "eth1" ]), Is.False)
        listedInterfaces <- []
        let diskRequiresInterface = project { configuration with Interfaces = [ "eth0" ] }
        Assert.That(FirewalldRecoveryProof.matchesLoadedProjection environment diskRequiresInterface expected, Is.False)
