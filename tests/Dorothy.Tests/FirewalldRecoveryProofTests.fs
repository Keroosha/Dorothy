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

    let restoreWithoutReload environment configuration xml proof phase progress =
        FirewalldRecoveryProof.restoreRuntimeWithProgress environment configuration xml proof phase
            (fun () -> Assert.Fail "A scoped inverse must not reload the daemon.") progress

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

    let withRuntimeProgress
        initialPorts
        initialServices
        (action: HostEnvironment -> ResizeArray<string list> -> (string list -> unit)
                -> (FirewalldLifecycle.NativeActivationProgress -> unit)
                -> (unit -> FirewalldLifecycle.NativeActivationProgress option)
                -> unit)
        =
        let mutable progress: FirewalldLifecycle.NativeActivationProgress option = None
        let report value = progress <- Some value
        withRuntime initialPorts initialServices (fun environment calls replacePorts ->
            action environment calls replacePorts report (fun () -> progress))

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
        let sources =
            configuration.Elements
            |> List.filter (fun item -> item.Name = "source")
            |> List.choose (fun item ->
                match Map.tryFind "address" item.Attributes, Map.tryFind "mac" item.Attributes, Map.tryFind "ipset" item.Attributes with
                | Some value, None, None -> Some value
                | None, Some value, None -> Some value
                | None, None, Some value -> Some("ipset:" + value)
                | _ -> None)
            |> FirewalldRuntime.normalizeFieldValues "zone" "sources"
        Map.ofList
            [ "services", configuration.Services @ direct "service" "name"
              "ports", configuration.Ports @ ports "port"
              "source-ports", ports "source-port"
              "protocols", configuration.Protocols @ direct "protocol" "value"
              "icmp-blocks", direct "icmp-block" "name"
              "rich rules", FirewalldRuntime.expectedRichRuleStrings configuration |> Option.defaultValue []
              "forward-ports", FirewalldRuntime.expectedForwardPortValues configuration |> Option.defaultValue []
              "sources", sources ]

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
            let sources =
                configuration.Elements
                |> List.filter (fun item -> item.Name = "source")
                |> List.choose (fun item ->
                    match Map.tryFind "address" item.Attributes, Map.tryFind "mac" item.Attributes, Map.tryFind "ipset" item.Attributes with
                    | Some value, None, None -> Some value
                    | None, Some value, None -> Some value
                    | None, None, Some value -> Some("ipset:" + value)
                    | _ -> None)
                |> FirewalldRuntime.normalizeFieldValues "zone" "sources"
            Map.ofList
                [ "services", configuration.Services @ direct "service" "name"
                  "ports", configuration.Ports @ directPorts "port"
                  "source-ports", directPorts "source-port"
                  "protocols", configuration.Protocols @ direct "protocol" "value"
                  "icmp-blocks", direct "icmp-block" "name"
                  "rich rules", FirewalldRuntime.expectedRichRuleStrings configuration |> Option.defaultValue []
                  "forward-ports", FirewalldRuntime.expectedForwardPortValues configuration |> Option.defaultValue []
                  "sources", sources ]
        let mutable runtime = initial
        let calls = ResizeArray<string list>()
        let text (values: Map<string, string list>) field =
            Map.tryFind field values |> Option.defaultValue [] |> String.concat " "
        let block (values: Map<string, string list>) field =
            match Map.tryFind field values |> Option.defaultValue [] with
            | [] -> "\n"
            | entries -> "\n\t" + String.concat "\n\t" entries + "\n"
        let listAll values =
            if configuration.Kind = "zone" then
                configuration.Name + "\n"
                + "  target: " + configuration.Target + "\n"
                + "  ingress-priority: 0\n"
                + "  egress-priority: 0\n"
                + "  icmp-block-inversion: "
                + (if configuration.Elements |> List.exists (fun item -> item.Name = "icmp-block-inversion") then "yes" else "no")
                + "\n"
                + "  interfaces: \n"
                + "  sources: " + text values "sources" + "\n"
                + "  services: " + text values "services" + "\n"
                + "  ports: " + text values "ports" + "\n"
                + "  protocols: " + text values "protocols" + "\n"
                + "  forward: no\n"
                + "  masquerade: no\n"
                + "  forward-ports:" + block values "forward-ports"
                + "  source-ports: " + text values "source-ports" + "\n"
                + "  icmp-blocks: " + text values "icmp-blocks" + "\n"
                + "  rich rules:" + block values "rich rules"
            else
                configuration.Name + "\n"
                + "  priority: " + string configuration.Priority + "\n"
                + "  target: " + configuration.Target + "\n"
                + "  ingress-zones: " + String.concat " " configuration.Ingress + "\n"
                + "  egress-zones: " + String.concat " " configuration.Egress + "\n"
                + "  services: " + text values "services" + "\n"
                + "  ports: " + text values "ports" + "\n"
                + "  protocols: " + text values "protocols" + "\n"
                + "  masquerade: no\n"
                + "  forward-ports:" + block values "forward-ports"
                + "  source-ports: " + text values "source-ports" + "\n"
                + "  icmp-blocks: " + text values "icmp-blocks" + "\n"
                + "  rich rules:" + block values "rich rules"
        let targetSelector =
            if configuration.Kind = "zone" then "--zone=" + configuration.Name
            else "--policy=" + configuration.Name
        let options =
            [ "--add-service=", "services", true; "--remove-service=", "services", false
              "--add-port=", "ports", true; "--remove-port=", "ports", false
              "--add-source-port=", "source-ports", true; "--remove-source-port=", "source-ports", false
              "--add-protocol=", "protocols", true; "--remove-protocol=", "protocols", false
              "--add-icmp-block=", "icmp-blocks", true; "--remove-icmp-block=", "icmp-blocks", false
              "--add-rich-rule=", "rich rules", true; "--remove-rich-rule=", "rich rules", false
              "--add-forward-port=", "forward-ports", true; "--remove-forward-port=", "forward-ports", false
              "--add-source=", "sources", true; "--remove-source=", "sources", false ]
        let run executable arguments _ =
            calls.Add(executable :: arguments)
            let nativeResult () =
                match arguments with
                | [ "--get-zones" ]
                | [ "--permanent"; "--get-zones" ] -> Some(if configuration.Kind = "zone" then configuration.Name else "")
                | [ "--get-policies" ]
                | [ "--permanent"; "--get-policies" ] -> Some(if configuration.Kind = "policy" then configuration.Name else "")
                | [ "--zone=quiet"; "--list-all" ] when configuration.Kind = "zone" -> Some(listAll runtime)
                | [ "--permanent"; "--zone=quiet"; "--list-all" ] when configuration.Kind = "zone" -> Some(listAll permanent)
                | [ selector; "--list-all" ] when selector = targetSelector -> Some(listAll runtime)
                | [ "--permanent"; selector; "--list-all" ] when selector = targetSelector -> Some(listAll permanent)
                | [ "--zone=quiet"; "--list-interfaces" ]
                | [ "--permanent"; "--zone=quiet"; "--list-interfaces" ] when configuration.Kind = "zone" -> Some ""
                | [ selector; "--list-rich-rules" ] when selector = targetSelector -> Some(String.concat "\n" (Map.find "rich rules" runtime))
                | [ "--permanent"; selector; "--list-rich-rules" ] when selector = targetSelector -> Some(String.concat "\n" (Map.find "rich rules" permanent))
                | [ selector; operation ] when selector = targetSelector ->
                    options
                    |> List.tryPick (fun (prefix, field, add) ->
                        if operation.StartsWith(prefix, StringComparison.Ordinal) then
                            let argument = operation.Substring(prefix.Length)
                            // Debian's listing fills omitted optional keys; the command
                            // doing the mutation does not accept those display sentinels.
                            let value =
                                if field <> "forward-ports" then argument
                                elif argument.Contains(":toaddr=None") || argument.Contains(":toport=None") then failwith "Invalid forward-port operand"
                                elif not (argument.Contains(":toaddr=")) then argument + ":toaddr=None"
                                elif not (argument.Contains(":toport=")) then argument.Replace(":toaddr=", ":toport=None:toaddr=")
                                else argument
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

    let withSelectorRuntimeProgress
        (configuration: FirewalldModel.Configuration)
        (initial: Map<string, string list>)
        (action: HostEnvironment -> ResizeArray<string list> -> (unit -> Map<string, string list>)
                -> (Map<string, string list> -> unit)
                -> (FirewalldLifecycle.NativeActivationProgress -> unit)
                -> (unit -> FirewalldLifecycle.NativeActivationProgress option)
                -> unit)
        =
        let mutable progress: FirewalldLifecycle.NativeActivationProgress option = None
        let report value = progress <- Some value
        withSelectorRuntime configuration initial (fun environment calls current setCurrent ->
            action environment calls current setCurrent report (fun () -> progress))

    let withIpSetRuntimeProgress
        (configuration: FirewalldModel.Configuration)
        (initialEntries: string list)
        (action: HostEnvironment -> ResizeArray<string list> -> (unit -> string list) -> (string list -> unit)
                -> (FirewalldLifecycle.NativeActivationProgress -> unit)
                -> (unit -> FirewalldLifecycle.NativeActivationProgress option)
                -> unit)
        =
        let mutable entries = initialEntries
        let mutable progress: FirewalldLifecycle.NativeActivationProgress option = None
        let calls = ResizeArray<string list>()
        let typeName = Map.find "type" configuration.Attributes
        let info (values: string list) =
            configuration.Name + "\n"
            + "  type: " + typeName + "\n"
            + "  options: family=inet\n"
            + "  entries:"
            + (if values.IsEmpty then "\n" else "\n\t" + String.concat "\n\t" values + "\n")
        let run executable arguments _ =
            calls.Add(executable :: arguments)
            match executable, arguments with
            | "firewall-cmd", [ "--get-ipsets" ]
            | "firewall-cmd", [ "--permanent"; "--get-ipsets" ] -> commandResult configuration.Name
            | "firewall-cmd", [ argument ]
                when argument.StartsWith("--info-ipset=", StringComparison.Ordinal)
                     && argument.Substring("--info-ipset=".Length) = configuration.Name -> commandResult (info entries)
            | "firewall-cmd", [ "--permanent"; argument ]
                when argument.StartsWith("--info-ipset=", StringComparison.Ordinal)
                     && argument.Substring("--info-ipset=".Length) = configuration.Name ->
                commandResult (info initialEntries)
            | "firewall-cmd", [ selector; operation ] when selector = "--ipset=" + configuration.Name ->
                let prefix, add =
                    if operation.StartsWith("--add-entry=", StringComparison.Ordinal) then "--add-entry=", true
                    elif operation.StartsWith("--remove-entry=", StringComparison.Ordinal) then "--remove-entry=", false
                    else "", false
                if prefix = "" then failwith ("Unexpected ipset selector operation: " + operation)
                else
                    let value = operation.Substring(prefix.Length)
                    entries <- if add then value :: entries |> List.distinct else entries |> List.filter ((<>) value)
                    commandResult "success"
            | _ -> failwith ("Unexpected ipset proof command: " + String.concat " " (executable :: arguments))
        let environment =
            { Root = Path.Combine(Path.GetTempPath(), "dorothy-firewalld-ipset-proof")
              Run = run
              UtcNow = fun () -> DateTimeOffset.UnixEpoch }
        let report value = progress <- Some value
        action environment calls (fun () -> entries) (fun value -> entries <- value) report (fun () -> progress)


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
                    None)
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
                    FirewalldRecoveryProof.restoreRuntimeWithProgress
                        environment
                        preimage
                        preimageXml
                        (Some proof)
                        FirewalldLifecycle.ActiveDaemon
                        (fun () ->
                            checkedSafety <- true
                            raise (InvalidOperationException("blocked by reload safety preflight")))
                        None
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
        withRuntimeProgress [] [ "ssh" ] (fun environment _ setPorts report getProgress ->
            let snapshot = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            let proof = FirewalldRecoveryProof.runtimeRepairProof environment configuration snapshot
            Assert.That(proof["strategy"].GetValue<string>(), Is.EqualTo "runtime-delta")
            FirewalldRecoveryProof.activateRuntimeRepairWithProgress environment configuration proof report
            let repaired = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            Assert.That(repaired.Ports, Is.EquivalentTo [ "443/tcp" ])
            restoreWithoutReload environment configuration None (Some proof) FirewalldLifecycle.ActiveDaemon (getProgress ())
            let rolledBack = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            Assert.That(rolledBack.Ports, Is.Empty)
            FirewalldRecoveryProof.activateRuntimeRepairWithProgress environment configuration proof report
            setPorts [ "443/tcp" ]
            restoreWithoutReload environment configuration None (Some proof) FirewalldLifecycle.BootBeforeFirewalld (getProgress ())
            let daemonReady = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            Assert.That(daemonReady.Ports, Is.EquivalentTo [ "443/tcp" ])
            restoreWithoutReload environment configuration None (Some proof) FirewalldLifecycle.BootAfterFirewalld (getProgress ())
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
        withRuntimeProgress [ "443/tcp" ] [] (fun environment _ _ report getProgress ->
            let snapshot = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            let proof = FirewalldRecoveryProof.runtimeRepairProof environment configuration snapshot
            let firstDelta = proof["deltas"].[0].AsObject()
            Assert.That(firstDelta["field"].GetValue<string>(), Is.EqualTo "services")
            Assert.That(firstDelta["value"].GetValue<string>(), Is.EqualTo "ssh")
            FirewalldRecoveryProof.activateRuntimeRepairWithProgress environment configuration proof report
            let repaired = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            Assert.That(repaired.Services, Is.EquivalentTo [ "ssh" ])
            restoreWithoutReload environment configuration None (Some proof) FirewalldLifecycle.ActiveDaemon (getProgress ())
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
        withSelectorRuntimeProgress config initial (fun environment calls current setCurrent report getProgress ->
            let snapshot = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            let proof = FirewalldRecoveryProof.runtimeRepairProof environment config snapshot
            Assert.That(proof["deltas"].AsArray().Count, Is.GreaterThan 1)
            FirewalldRecoveryProof.activateRuntimeRepairWithProgress environment config proof report
            let repaired = current ()
            for field in [ "services"; "ports"; "source-ports"; "protocols"; "forward-ports" ] do
                Assert.That(repaired[field], Is.EquivalentTo expected[field], field)
            Assert.That(repaired["rich rules"], Does.Contain foreignBan)
            restoreWithoutReload environment config None (Some proof) FirewalldLifecycle.ActiveDaemon (getProgress ())
            let rolledBack = current ()
            for field in Map.keys expected do
                if field = "rich rules" then
                    Assert.That(rolledBack[field], Is.EquivalentTo [ foreignBan ])
                else Assert.That(rolledBack[field], Is.Empty, field)
            FirewalldRecoveryProof.activateRuntimeRepairWithProgress environment config proof report
            let callCountBeforeBoot = calls.Count
            restoreWithoutReload environment config None (Some proof) FirewalldLifecycle.BootBeforeFirewalld (getProgress ())
            Assert.That(calls.Count, Is.EqualTo callCountBeforeBoot)
            setCurrent expected
            restoreWithoutReload environment config None (Some proof) FirewalldLifecycle.BootAfterFirewalld (getProgress ())
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
        withSelectorRuntimeProgress config empty (fun environment calls current _ report getProgress ->
            let snapshot = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            let proof = FirewalldRecoveryProof.runtimeRepairProof environment config snapshot
            Assert.That(proof["deltas"].AsArray().Count, Is.EqualTo 1)
            let delta = proof["deltas"].[0]
            Assert.That(delta["effect"].GetValue<string>(), Is.EqualTo "steer")
            FirewalldRecoveryProof.activateRuntimeRepairWithProgress environment config proof report
            let repaired = current ()
            Assert.That(repaired["forward-ports"], Is.EquivalentTo expected["forward-ports"])
            restoreWithoutReload environment config None (Some proof) FirewalldLifecycle.ActiveDaemon (getProgress ())
            let restored = current ()
            Assert.That(restored["forward-ports"], Is.Empty)
            Assert.That(calls, Does.Contain [ "firewall-cmd"; "--zone=quiet"; "--add-forward-port=" + expected["forward-ports"].Head ])
            Assert.That(calls, Does.Contain [ "firewall-cmd"; "--zone=quiet"; "--remove-forward-port=" + expected["forward-ports"].Head ]))

    [<Test>]
    member _.``Independent local redirects compose without claiming chained translations``() =
        let before = FirewalldModel.empty "zone" "quiet"
        let redirect port target = element "forward-port" [ "port", port; "protocol", "tcp"; "to-port", target ] []
        let pair = { before with Elements = [ redirect "8181" "8080"; redirect "8182" "8080" ] }
        let beforeXml = Some(FieldRuntime.render before)
        withSelectorRuntimeProgress before (selectorValues before) (fun env calls current _ report progress ->
            let plan c = FirewalldRecoveryProof.objectDeltaProof env c beforeXml (Some(FieldRuntime.render c))
            Assert.That((plan { pair with Elements = [ redirect "8181" "8080"; redirect "8182" "8181" ] }).IsNone, Is.True)
            let proof = plan pair |> Option.get
            FirewalldRecoveryProof.activateObjectDeltaWithProgress env pair beforeXml proof report
            Assert.That((current ())["forward-ports"], Is.EquivalentTo((selectorValues pair)["forward-ports"]))
            restoreWithoutReload env pair beforeXml (Some proof) FirewalldLifecycle.ActiveDaemon (progress ())
            Assert.That((current ())["forward-ports"], Is.Empty)
            Assert.That(calls, Does.Contain [ "firewall-cmd"; "--zone=quiet"; "--remove-forward-port=port=8181:proto=tcp:toport=8080" ]))

    [<Test>]
    member _.``Address-only IPv6 forward-port argv omits the display-only target port``() =
        Assert.That(FirewalldRuntime.forwardPortCommandValue "port=8443:proto=tcp:toport=None:toaddr=2001:db8::9",
                    Is.EqualTo(Some "port=8443:proto=tcp:toaddr=2001:db8::9"))

    [<Test>]
    member _.``Multiple restrictive selectors compose and mixed monotone deltas are ordered safely``() =
        let restrictive =
            { FirewalldModel.empty "zone" "quiet" with
                Elements =
                    [ element "icmp-block" [ "name", "echo-request" ] []
                      element "icmp-block" [ "name", "time-exceeded" ] []
                      element "rule" [ "family", "ipv4" ]
                          [ element "port" [ "port", "3389"; "protocol", "tcp" ] []; element "drop" [] [] ] ] }
        let expected = selectorValues restrictive
        let empty = expected |> Map.map (fun _ _ -> [])
        withSelectorRuntimeProgress restrictive empty (fun environment _ current _ report getProgress ->
            let snapshot = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            let proof = FirewalldRecoveryProof.runtimeRepairProof environment restrictive snapshot
            Assert.That(proof["deltas"].AsArray().Count, Is.EqualTo 3)
            FirewalldRecoveryProof.activateRuntimeRepairWithProgress environment restrictive proof report
            let repaired = current ()
            for field in Map.keys expected do
                Assert.That(repaired[field], Is.EquivalentTo expected[field], field)
            restoreWithoutReload environment restrictive None (Some proof) FirewalldLifecycle.ActiveDaemon (getProgress ())
            Assert.That(current (), Is.EqualTo(box empty)))

        let mixed =
            { FirewalldModel.empty "zone" "quiet" with
                Services = [ "ssh" ]
                Elements = [ element "icmp-block" [ "name", "echo-request" ] [] ] }
        let mixedExpected = selectorValues mixed
        let emptyMixed = mixedExpected |> Map.map (fun _ _ -> [])
        withSelectorRuntimeProgress mixed emptyMixed (fun environment _ current _ report getProgress ->
            let snapshot = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            let proof = FirewalldRecoveryProof.runtimeRepairProof environment mixed snapshot
            let deltas = proof["deltas"].AsArray()
            Assert.That(deltas.Count, Is.EqualTo 2)
            Assert.That(deltas[0].["field"].GetValue<string>(), Is.EqualTo "icmp-blocks")
            Assert.That(deltas[0].["effect"].GetValue<string>(), Is.EqualTo "restrict")
            Assert.That(deltas[1].["field"].GetValue<string>(), Is.EqualTo "services")
            Assert.That(deltas[1].["effect"].GetValue<string>(), Is.EqualTo "grant")
            FirewalldRecoveryProof.activateRuntimeRepairWithProgress environment mixed proof report
            let repaired = current ()
            for field in Map.keys mixedExpected do
                Assert.That(repaired[field], Is.EquivalentTo mixedExpected[field], field)
            restoreWithoutReload environment mixed None (Some proof) FirewalldLifecycle.ActiveDaemon (getProgress ())
            Assert.That(current (), Is.EqualTo(box emptyMixed)))

    [<Test>]
    member _.``ICMP block inversion classifies a missing block as a grant``() =
        let inverted =
            { FirewalldModel.empty "zone" "quiet" with
                Elements =
                    [ element "icmp-block-inversion" [] []
                      element "icmp-block" [ "name", "echo-request" ] [] ] }
        let expected = selectorValues inverted
        let empty = expected |> Map.map (fun _ _ -> [])
        withSelectorRuntimeProgress inverted empty (fun environment _ current _ report getProgress ->
            let snapshot = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            let proof = FirewalldRecoveryProof.runtimeRepairProof environment inverted snapshot
            let delta = proof["deltas"].[0]
            Assert.That(delta["effect"].GetValue<string>(), Is.EqualTo "grant")
            FirewalldRecoveryProof.activateRuntimeRepairWithProgress environment inverted proof report
            let repaired = current ()
            Assert.That(repaired["icmp-blocks"], Is.EquivalentTo expected["icmp-blocks"])
            restoreWithoutReload environment inverted None (Some proof) FirewalldLifecycle.ActiveDaemon (getProgress ())
            let restored = current ()
            Assert.That(restored["icmp-blocks"], Is.Empty))

    [<Test>]
    member _.``Scoped object inverse preserves a post-stage foreign timed restriction``() =
        let before =
            { FirewalldModel.empty "zone" "quiet" with
                Services = [ "ssh" ] }
        let after = { before with Ports = [ "8443/tcp" ] }
        let beforeXml = Some(FieldRuntime.render before)
        let afterXml = Some(FieldRuntime.render after)
        let expectedBefore = selectorValues before
        withSelectorRuntimeProgress before expectedBefore (fun environment calls current setCurrent report getProgress ->
            let proof = FirewalldRecoveryProof.objectDeltaProof environment after beforeXml afterXml |> Option.get
            Assert.That(proof["strategy"].GetValue<string>(), Is.EqualTo "object-delta")
            FirewalldRecoveryProof.activateObjectDeltaWithProgress environment after beforeXml proof report
            let foreignBan = "rule family=\"ipv4\" source address=\"198.51.100.99\" drop"
            setCurrent (Map.add "rich rules" [ foreignBan ] (current ()))
            restoreWithoutReload environment after beforeXml (Some proof) FirewalldLifecycle.ActiveDaemon (getProgress ())
            let restored = current ()
            Assert.That(restored["ports"], Is.Empty)
            Assert.That(restored["services"], Is.EquivalentTo [ "ssh" ])
            Assert.That(restored["rich rules"], Is.EquivalentTo [ foreignBan ])
            Assert.That(calls |> Seq.exists (fun args -> List.contains "--reload" args), Is.False)
            Assert.That(calls, Does.Contain [ "firewall-cmd"; "--zone=quiet"; "--add-port=8443/tcp" ])
            Assert.That(calls, Does.Contain [ "firewall-cmd"; "--zone=quiet"; "--remove-port=8443/tcp" ]))

    [<Test>]
    member _.``A single routing mark has a scoped inverse but cannot be batched with a grant``() =
        let before = { FirewalldModel.empty "zone" "quiet" with Services = [ "ssh" ] }
        let mark =
            element "rule" [ "family", "ipv4" ]
                [ element "port" [ "port", "8443"; "protocol", "tcp" ] []
                  element "mark" [ "set", "0x2" ] [] ]
        let after = { before with Elements = [ mark ] }
        let beforeXml = Some(FieldRuntime.render before)
        withSelectorRuntimeProgress before (selectorValues before) (fun environment _ current _ report getProgress ->
            let prove candidate =
                FirewalldRecoveryProof.objectDeltaProof environment candidate beforeXml (Some(FieldRuntime.render candidate))
            Assert.That((prove { after with Ports = [ "8444/tcp" ] }).IsNone, Is.True)
            let proof = prove after |> Option.get
            FirewalldRecoveryProof.activateObjectDeltaWithProgress environment after beforeXml proof report
            Assert.That((current ())["rich rules"], Is.EquivalentTo((selectorValues after)["rich rules"]))
            restoreWithoutReload environment after beforeXml (Some proof) FirewalldLifecycle.ActiveDaemon (getProgress ())
            Assert.That((current ())["rich rules"], Is.Empty))

    [<Test>]
    member _.``Scoped release records the restored baseline rather than departing inputs``() =
        let departing = { FirewalldModel.empty "zone" "quiet" with Services = [ "ssh" ]; Ports = [ "8443/tcp" ] }
        let baseline = { departing with Ports = [] }
        let beforeXml = Some(FieldRuntime.render departing)
        withSelectorRuntimeProgress departing (selectorValues departing) (fun environment _ current _ report getProgress ->
            let proof = FirewalldRecoveryProof.objectDeltaProof environment departing beforeXml (Some(FieldRuntime.render baseline)) |> Option.get
            FirewalldRecoveryProof.activateObjectDeltaWithProgress environment departing beforeXml proof report
            Assert.That((current ())["ports"], Is.Empty)
            restoreWithoutReload environment departing beforeXml (Some proof) FirewalldLifecycle.ActiveDaemon (getProgress ())
            Assert.That((current ())["ports"], Is.EquivalentTo [ "8443/tcp" ]))
    [<Test>]
    member _.``Overlapping preexisting rich DROP refuses an object proof before mutation``() =
        let before = FirewalldModel.empty "zone" "quiet"
        let drop =
            element "rule" [ "family", "ipv4" ]
                [ element "port" [ "port", "8443"; "protocol", "tcp" ] []; element "drop" [] [] ]
        let after = { before with Elements = [ drop ] }
        let beforeXml = Some(FieldRuntime.render before)
        let afterXml = Some(FieldRuntime.render after)
        let richDrop = FirewalldRuntime.expectedRichRuleStrings after |> Option.get |> List.exactlyOne
        let initial = Map.add "rich rules" [ richDrop ] (selectorValues before)
        withSelectorRuntime before initial (fun environment calls _ _ ->
            Assert.Throws<InvalidOperationException>(fun () ->
                FirewalldRecoveryProof.objectDeltaProof environment after beforeXml afterXml |> ignore)
            |> ignore
            Assert.That(
                calls |> Seq.exists (fun args -> args |> List.exists (fun value -> value.StartsWith("--add-", StringComparison.Ordinal))),
                Is.False))

    [<Test>]
    member _.``A rich DROP race after checkpoint zero is not treated as a completed add``() =
        let before = FirewalldModel.empty "zone" "quiet"
        let drop =
            element "rule" [ "family", "ipv4" ]
                [ element "port" [ "port", "8443"; "protocol", "tcp" ] []; element "drop" [] [] ]
        let after = { before with Elements = [ drop ] }
        let beforeXml = Some(FieldRuntime.render before)
        withSelectorRuntime before (selectorValues before) (fun environment calls current setCurrent ->
            let proof = FirewalldRecoveryProof.objectDeltaProof environment after beforeXml (Some(FieldRuntime.render after)) |> Option.get
            let richDrop = FirewalldRuntime.expectedRichRuleStrings after |> Option.get |> List.exactlyOne
            setCurrent (Map.add "rich rules" [ richDrop ] (current ()))
            Assert.Throws<InvalidOperationException>(fun () ->
                FirewalldRecoveryProof.activateObjectDeltaWithProgress environment after beforeXml proof ignore)
            |> ignore
            Assert.That(
                calls |> Seq.exists (fun args -> args |> List.exists (fun value -> value.StartsWith("--add-", StringComparison.Ordinal))),
                Is.False))

    [<Test>]
    member _.``Runtime repair refuses an identical rich DROP that races checkpoint zero``() =
        let drop =
            element "rule" [ "family", "ipv4" ]
                [ element "port" [ "port", "8443"; "protocol", "tcp" ] []; element "drop" [] [] ]
        let config = { FirewalldModel.empty "zone" "quiet" with Elements = [ drop ] }
        let expected = selectorValues config
        let empty = expected |> Map.map (fun _ _ -> [])
        withSelectorRuntime config empty (fun environment calls current setCurrent ->
            let snapshot = FirewalldRuntime.inspectRuntime environment "zone" "quiet" |> Option.get
            let proof = FirewalldRecoveryProof.runtimeRepairProof environment config snapshot
            let richDrop = expected["rich rules"] |> List.exactlyOne
            setCurrent (Map.add "rich rules" [ richDrop ] (current ()))
            Assert.Throws<InvalidOperationException>(fun () ->
                FirewalldRecoveryProof.activateRuntimeRepairWithProgress environment config proof ignore)
            |> ignore
            Assert.That(
                calls |> Seq.exists (fun args -> args |> List.exists (fun value -> value.StartsWith("--add-", StringComparison.Ordinal))),
                Is.False))

    [<Test>]
    member _.``Rich ICMP block and TCP MSS clamp actions have scoped inverses``() =
        let before = FirewalldModel.empty "zone" "quiet"
        let cases =
            [ element "rule" [ "family", "ipv4" ] [ element "icmp-block" [ "name", "echo-request" ] [] ], "restrict"
              element "rule" [ "family", "ipv4" ] [ element "tcp-mss-clamp" [ "value", "pmtu" ] [] ], "steer" ]
        for richRule, expectedEffect in cases do
            let after = { before with Elements = [ richRule ] }
            let beforeXml = Some(FieldRuntime.render before)
            let expected = selectorValues after
            withSelectorRuntimeProgress before (selectorValues before) (fun environment _ current _ report getProgress ->
                let proof =
                    FirewalldRecoveryProof.objectDeltaProof environment after beforeXml (Some(FieldRuntime.render after))
                    |> Option.get
                Assert.That(proof["deltas"].[0].["effect"].GetValue<string>(), Is.EqualTo expectedEffect)
                FirewalldRecoveryProof.activateObjectDeltaWithProgress environment after beforeXml proof report
                Assert.That((current ())["rich rules"], Is.EquivalentTo expected["rich rules"])
                restoreWithoutReload environment after beforeXml (Some proof) FirewalldLifecycle.ActiveDaemon (getProgress ())
                Assert.That((current ())["rich rules"], Is.Empty))

        let richIcmp =
            element "rule" [ "family", "ipv4" ] [ element "icmp-block" [ "name", "echo-request" ] [] ]
        let departing = { before with Elements = [ richIcmp ] }
        let beforeXml = Some(FieldRuntime.render departing)
        withSelectorRuntimeProgress departing (selectorValues departing) (fun environment _ current _ report getProgress ->
            let proof =
                FirewalldRecoveryProof.objectDeltaProof environment before beforeXml (Some(FieldRuntime.render before))
                |> Option.get
            Assert.That(proof["deltas"].[0].["effect"].GetValue<string>(), Is.EqualTo "grant")
            FirewalldRecoveryProof.activateObjectDeltaWithProgress environment before beforeXml proof report
            Assert.That((current ())["rich rules"], Is.Empty)
            restoreWithoutReload environment departing beforeXml (Some proof) FirewalldLifecycle.ActiveDaemon (getProgress ())
            Assert.That((current ())["rich rules"], Is.EquivalentTo((selectorValues departing)["rich rules"])))

    [<Test>]
    member _.``Mixed zone replacements apply restrictive steps before grants and invert safely``() =
        let before =
            { FirewalldModel.empty "zone" "quiet" with
                Services = [ "ssh" ]
                Ports = [ "8443/tcp" ] }
        let after =
            { FirewalldModel.empty "zone" "quiet" with
                Services = [ "https" ]
                Ports = [ "9443/tcp" ] }
        let beforeXml = Some(FieldRuntime.render before)
        let afterValues = selectorValues after
        withSelectorRuntimeProgress before (selectorValues before) (fun environment _ current _ report getProgress ->
            let proof =
                FirewalldRecoveryProof.objectDeltaProof environment after beforeXml (Some(FieldRuntime.render after))
                |> Option.get
            let deltas = proof["deltas"].AsArray()
            Assert.That(deltas.Count, Is.EqualTo 4)
            Assert.That(deltas[0].["effect"].GetValue<string>(), Is.EqualTo "restrict")
            Assert.That(deltas[1].["effect"].GetValue<string>(), Is.EqualTo "restrict")
            Assert.That(deltas[2].["effect"].GetValue<string>(), Is.EqualTo "grant")
            Assert.That(deltas[3].["effect"].GetValue<string>(), Is.EqualTo "grant")
            let midpointXml = FirewalldRecoveryProof.objectDeltaContractionXml after beforeXml proof |> Option.get
            let midpoint =
                FirewalldRuntime.snapshotFromXml "zone" "quiet" (Some midpointXml)
                |> Result.defaultWith failwith
                |> Option.get
            Assert.That(midpoint.Services, Is.Empty)
            Assert.That(midpoint.Ports, Is.Empty)
            FirewalldRecoveryProof.activateObjectDeltaWithProgress environment after beforeXml proof report
            Assert.That(current (), Is.EqualTo(box afterValues))
            restoreWithoutReload environment after beforeXml (Some proof) FirewalldLifecycle.ActiveDaemon (getProgress ())
            Assert.That(current (), Is.EqualTo(box(selectorValues before))))

    [<Test>]
    member _.``Mixed policy selector replacement uses the same non-expanding scoped order``() =
        let before =
            { FirewalldModel.empty "policy" "quiet-policy" with
                Ingress = [ "ANY" ]
                Egress = [ "HOST" ]
                Services = [ "ssh" ]
                Ports = [ "8443/tcp" ] }
        let after =
            { before with
                Services = [ "https" ]
                Ports = [ "9443/tcp" ] }
        let beforeXml = Some(FieldRuntime.render before)
        withSelectorRuntimeProgress before (selectorValues before) (fun environment _ current _ report getProgress ->
            let proof =
                FirewalldRecoveryProof.objectDeltaProof environment after beforeXml (Some(FieldRuntime.render after))
                |> Option.get
            let deltas = proof["deltas"].AsArray()
            Assert.That(deltas.Count, Is.EqualTo 4)
            Assert.That(deltas[0].["effect"].GetValue<string>(), Is.EqualTo "restrict")
            Assert.That(deltas[1].["effect"].GetValue<string>(), Is.EqualTo "restrict")
            Assert.That(deltas[2].["effect"].GetValue<string>(), Is.EqualTo "grant")
            Assert.That(deltas[3].["effect"].GetValue<string>(), Is.EqualTo "grant")
            FirewalldRecoveryProof.activateObjectDeltaWithProgress environment after beforeXml proof report
            Assert.That(current (), Is.EqualTo(box(selectorValues after)))
            restoreWithoutReload environment after beforeXml (Some proof) FirewalldLifecycle.ActiveDaemon (getProgress ())
            Assert.That(current (), Is.EqualTo(box(selectorValues before))))

    [<Test>]
    member _.``One zone source membership delta uses scoped native add and inverse``() =
        let before = FirewalldModel.empty "zone" "quiet"
        let source = element "source" [ "address", "192.0.2.8" ] []
        let after = { before with Elements = [ source ] }
        let beforeXml = Some(FieldRuntime.render before)
        withSelectorRuntimeProgress before (selectorValues before) (fun environment calls current _ report getProgress ->
            let proof =
                FirewalldRecoveryProof.objectDeltaProof environment after beforeXml (Some(FieldRuntime.render after))
                |> Option.get
            Assert.That(proof["deltas"].[0].["field"].GetValue<string>(), Is.EqualTo "sources")
            Assert.That(proof["deltas"].[0].["effect"].GetValue<string>(), Is.EqualTo "steer")
            FirewalldRecoveryProof.activateObjectDeltaWithProgress environment after beforeXml proof report
            Assert.That((current ())["sources"], Is.EquivalentTo [ "192.0.2.8" ])
            restoreWithoutReload environment after beforeXml (Some proof) FirewalldLifecycle.ActiveDaemon (getProgress ())
            Assert.That((current ())["sources"], Is.Empty)
            Assert.That(calls, Does.Contain [ "firewall-cmd"; "--zone=quiet"; "--add-source=192.0.2.8" ])
            Assert.That(calls, Does.Contain [ "firewall-cmd"; "--zone=quiet"; "--remove-source=192.0.2.8" ]))

    [<Test>]
    member _.``A native ALREADY response cannot authorize inverse removal``() =
        let before = FirewalldModel.empty "zone" "quiet"
        let drop =
            element "rule" [ "family", "ipv4" ]
                [ element "port" [ "port", "8443"; "protocol", "tcp" ] []; element "drop" [] [] ]
        let after = { before with Elements = [ drop ] }
        let beforeXml = Some(FieldRuntime.render before)
        withSelectorRuntimeProgress before (selectorValues before) (fun environment calls current setCurrent report getProgress ->
            let proof =
                FirewalldRecoveryProof.objectDeltaProof environment after beforeXml (Some(FieldRuntime.render after))
                |> Option.get
            let richDrop = (selectorValues after)["rich rules"] |> List.exactlyOne
            let originalRun = environment.Run
            let run executable arguments input =
                match executable, arguments with
                | "firewall-cmd", [ "--zone=quiet"; operation ]
                    when operation.StartsWith("--add-rich-rule=", StringComparison.Ordinal) ->
                    calls.Add(executable :: arguments)
                    setCurrent (Map.add "rich rules" [ richDrop ] (current ()))
                    { ExitCode = 11; Stdout = "ALREADY_ENABLED"; Stderr = "" }
                | _ -> originalRun executable arguments input
            let environment = { environment with Run = run }
            Assert.Throws<InvalidOperationException>(fun () ->
                FirewalldRecoveryProof.activateObjectDeltaWithProgress environment after beforeXml proof report)
            |> ignore
            Assert.Throws<InvalidOperationException>(fun () ->
                restoreWithoutReload environment after beforeXml (Some proof) FirewalldLifecycle.ActiveDaemon (getProgress ()))
            |> ignore
            Assert.That((current ())["rich rules"], Is.EquivalentTo [ richDrop ])
            Assert.That(
                calls |> Seq.exists (fun args -> args |> List.exists (fun value -> value.StartsWith("--remove-", StringComparison.Ordinal))),
                Is.False))

    [<Test>]
    member _.``A foreign zone interface does not block an attributable restrictive inverse``() =
        let before = FirewalldModel.empty "zone" "quiet"
        let after = { before with Ports = [ "8443/tcp" ] }
        let beforeXml = Some(FieldRuntime.render before)
        withSelectorRuntimeProgress before (selectorValues before) (fun environment calls current _ report getProgress ->
            let mutable foreignInterface = false
            let originalRun = environment.Run
            let run executable arguments input =
                match executable, arguments with
                | "firewall-cmd", [ "--zone=quiet"; "--list-interfaces" ] when foreignInterface -> commandResult "eth99"
                | _ -> originalRun executable arguments input
            let environment = { environment with Run = run }
            let proof =
                FirewalldRecoveryProof.objectDeltaProof environment after beforeXml (Some(FieldRuntime.render after))
                |> Option.get
            FirewalldRecoveryProof.activateObjectDeltaWithProgress environment after beforeXml proof report
            foreignInterface <- true
            restoreWithoutReload environment after beforeXml (Some proof) FirewalldLifecycle.ActiveDaemon (getProgress ())
            Assert.That((current ())["ports"], Is.Empty)
            Assert.That(calls |> Seq.exists (fun args -> args |> List.exists (fun value -> value.StartsWith("--remove-interface=", StringComparison.Ordinal))), Is.False)
            Assert.That(calls, Does.Contain [ "firewall-cmd"; "--zone=quiet"; "--remove-port=8443/tcp" ]))



    [<Test>]
    member _.``Scoped object inverse declines structural projection changes``() =
        let before = { FirewalldModel.empty "zone" "quiet" with Services = [ "ssh" ] }
        let after = { before with Target = "ACCEPT" }
        withSelectorRuntime before (selectorValues before) (fun environment _ _ _ ->
            let proof =
                FirewalldRecoveryProof.objectDeltaProof environment after
                    (Some(FieldRuntime.render before)) (Some(FieldRuntime.render after))
            Assert.That(proof.IsNone, Is.True))

    [<Test>]
    member _.``Only explicitly authorized disjoint IPv4 hash ipset batches get scoped proofs``() =
        let ipset typeName entries =
            let entry value = { element "entry" [] [] with Text = Some value }
            { FirewalldModel.empty "ipset" "peer-set" with
                Attributes = Map.ofList [ "type", typeName ]
                Elements =
                    element "option" [ "name", "family"; "value", "inet" ] []
                    :: (entries |> List.map entry) }
        let beforeEntries = [ "192.0.2.1" ]
        let before = ipset "hash:ip" beforeEntries
        let afterEntries = [ "192.0.2.1"; "192.0.2.2"; "192.0.2.3" ]
        let after = ipset "hash:ip" afterEntries
        let beforeXml = Some(FieldRuntime.render before)
        let afterXml = Some(FieldRuntime.render after)
        withIpSetRuntimeProgress before beforeEntries (fun environment calls current setCurrent report getProgress ->
            Assert.That(
                FirewalldRecoveryProof.objectDeltaProof environment after beforeXml afterXml |> Option.isNone,
                Is.True)
            let mutable authorizationCalls = 0
            let denied =
                FirewalldRecoveryProof.objectDeltaProofWithSetBatch environment after beforeXml afterXml (fun () ->
                    authorizationCalls <- authorizationCalls + 1
                    false)
            Assert.That(denied.IsNone, Is.True)
            Assert.That(authorizationCalls, Is.EqualTo 1)
            let proof =
                FirewalldRecoveryProof.objectDeltaProofWithSetBatch environment after beforeXml afterXml (fun () ->
                    authorizationCalls <- authorizationCalls + 1
                    true)
                |> Option.get
            Assert.That(authorizationCalls, Is.EqualTo 2)
            Assert.That(proof["steeringBatch"].GetValue<bool>(), Is.True)
            Assert.That(proof["deltas"].AsArray().Count, Is.EqualTo 2)
            FirewalldRecoveryProof.activateObjectDeltaWithProgress environment after beforeXml proof report
            Assert.That(current (), Is.EquivalentTo afterEntries)
            FirewalldRecoveryProof.restoreRuntimeWithProgress environment after beforeXml (Some proof)
                FirewalldLifecycle.ActiveDaemon
                (fun () -> Assert.Fail "A scoped inverse must not reload the daemon.")
                (getProgress ())
            Assert.That(current (), Is.EquivalentTo beforeEntries)
            Assert.That(calls, Does.Contain [ "firewall-cmd"; "--ipset=peer-set"; "--add-entry=192.0.2.2" ])
            Assert.That(calls, Does.Contain [ "firewall-cmd"; "--ipset=peer-set"; "--remove-entry=192.0.2.2" ])
            let mixed = ipset "hash:ip" [ "192.0.2.2" ]
            let beforeRejected = authorizationCalls
            let rejected =
                FirewalldRecoveryProof.objectDeltaProofWithSetBatch environment mixed beforeXml
                    (Some(FieldRuntime.render mixed))
                    (fun () -> authorizationCalls <- authorizationCalls + 1; true)
            Assert.That(rejected.IsNone, Is.True)
            Assert.That(authorizationCalls, Is.EqualTo beforeRejected))

        let networkBefore = ipset "hash:net" []
        let networkAfter = ipset "hash:net" [ "10.0.0.0/8"; "10.1.0.0/16" ]
        withIpSetRuntimeProgress networkBefore [] (fun environment _ _ _ _ _ ->
            let mutable authorized = false
            let proof =
                FirewalldRecoveryProof.objectDeltaProofWithSetBatch environment networkAfter
                    (Some(FieldRuntime.render networkBefore))
                    (Some(FieldRuntime.render networkAfter))
                    (fun () -> authorized <- true; true)
            Assert.That(proof.IsNone, Is.True)
            Assert.That(authorized, Is.False))

    [<Test>]
    member _.``Structural management narrowing is refused while quiet policies and expansions remain usable``() =
        let environment =
            { Root = Path.Combine(Path.GetTempPath(), "dorothy-firewalld-structural-gate")
              Run = fun _ _ _ -> failwith "Policy structural classification must not query the host."
              UtcNow = fun () -> DateTimeOffset.UnixEpoch }
        let hostPolicy =
            { FirewalldModel.empty "policy" "host-policy" with
                Ingress = [ "ANY" ]
                Egress = [ "HOST" ] }
        let blocked = { hostPolicy with Target = "DROP" }
        let expanded = { hostPolicy with Target = "ACCEPT" }
        let xml value = Some(FieldRuntime.render value)
        Assert.That(
            FirewalldRecoveryProof.objectTransitionMayNarrowManagement environment blocked (xml hostPolicy) (xml blocked),
            Is.True)
        Assert.That(
            FirewalldRecoveryProof.objectTransitionMayNarrowManagement environment expanded (xml hostPolicy) (xml expanded),
            Is.False)
        let quiet =
            { FirewalldModel.empty "policy" "quiet-policy" with
                Ingress = [ "public" ]
                Egress = [ "docker" ] }
        let quietDrop = { quiet with Target = "DROP" }
        Assert.That(
            FirewalldRecoveryProof.objectTransitionMayNarrowManagement environment quietDrop (xml quiet) (xml quietDrop),
            Is.False)

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
