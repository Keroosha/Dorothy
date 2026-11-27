namespace Dorothy.HostHelper

open System
open System.Text.RegularExpressions

module FirewalldDockerGate =
    let private fail message = raise (Firewalld.BackendError message)

    let private overlaps (left: Set<string>) (right: string list) =
        right |> List.exists (fun name -> name <> "HOST" && (name = "ANY" || left.Contains "ANY" || left.Contains name))

    let private hasPassFields (policy: FirewalldRuntime.RuntimeSnapshot) =
        not policy.Services.IsEmpty || not policy.Ports.IsEmpty || not policy.Protocols.IsEmpty || not policy.SourcePorts.IsEmpty
        || not policy.ForwardPorts.IsEmpty || policy.Masquerade

    /// `ANY` expands to concrete transit zones. For a matching ingress/egress pair,
    /// native policy priority orders dispatch; equal priority supplies no ordering proof.
    let verifyPolicies (policies: FirewalldRuntime.RuntimeSnapshot list) (fences: FirewalldGateModel.Fence list) =
        if fences.IsEmpty then fail "A Docker start gate requires a declared DROP policy."
        for fence in fences do
            let selected = policies |> List.tryFind (fun p -> p.Name = fence.Name) |> Option.defaultWith (fun () -> fail ("Missing live Docker fence: " + fence.Name))
            if selected.Kind <> "policy" || not selected.UnknownFields.IsEmpty || selected.Target <> "DROP" || hasPassFields selected || not selected.RichRules.IsEmpty
               || selected.Priority <> Some fence.Priority || Set.ofList selected.Ingress <> fence.Ingress || Set.ofList selected.Egress <> fence.Egress then
                fail ("Live Docker fence differs from the declared DROP: " + fence.Name)
            for policy in policies do
                if policy.Name <> fence.Name then
                    // An inactive (empty direction) policy does not match; an unparseable
                    // direction is not evidence of an empty one.
                    if policy.UnknownFields.ContainsKey "ingress-zones" || policy.UnknownFields.ContainsKey "egress-zones" then
                        fail ("Cannot determine scope of live firewalld policy: " + policy.Name)
                    if overlaps fence.Ingress policy.Ingress && (List.contains "docker" policy.Egress || List.contains "ANY" policy.Egress) then
                        match policy.Priority with
                        | None -> fail ("Cannot determine priority of overlapping policy: " + policy.Name)
                        | Some p when p <= fence.Priority ->
                            if not policy.UnknownFields.IsEmpty || hasPassFields policy || not (List.contains policy.Target [ "DROP"; "REJECT"; "CONTINUE" ])
                               || not (List.forall FirewalldRuntime.isRestrictiveRichRule policy.RichRules) then
                                fail ("Overlapping live policy may permit traffic before the Docker fence: " + policy.Name)
                        | _ -> ()

    let private systemdProperties (environment: HostEnvironment) (unitName: string) (properties: string list) =
        let arguments = [ "show"; "--no-pager"; "--property=" + String.concat "," properties; "--"; unitName ]
        let result =
            try environment.Run "/usr/bin/systemctl" arguments None
            with
            | :? TimeoutException -> fail ("Timed out while inspecting systemd unit: " + unitName)
            | _ -> fail ("Unable to inspect systemd unit: " + unitName)
        if result.ExitCode = 124 || result.ExitCode = 137 then
            fail ("Timed out while inspecting systemd unit: " + unitName)
        if result.ExitCode <> 0 then
            fail ("Unable to inspect systemd unit " + unitName + " (exit " + string result.ExitCode + ").")
        if result.Stderr <> "" then fail ("Systemd returned diagnostics while inspecting unit: " + unitName)
        if isNull result.Stdout then fail ("Systemd returned no state output for unit: " + unitName)
        let values = Collections.Generic.Dictionary<string, string>(StringComparer.Ordinal)
        let lines = result.Stdout.Split('\n')
        for index in 0 .. lines.Length - 1 do
            let sourceLine = lines[index]
            if sourceLine = "" && index = lines.Length - 1 then ()
            elif sourceLine = "" then fail ("Invalid systemd state response for unit: " + unitName)
            else
                let line =
                    if sourceLine.EndsWith("\r", StringComparison.Ordinal) then sourceLine.Substring(0, sourceLine.Length - 1)
                    else sourceLine
                let separator = line.IndexOf('=')
                if separator <= 0 then fail ("Invalid systemd state response for unit: " + unitName)
                let key, value = line.Substring(0, separator), line.Substring(separator + 1)
                if not (List.contains key properties) then fail ("Unexpected systemd state property for unit: " + unitName)
                if not (values.TryAdd(key, value)) then fail ("Duplicate systemd state property for unit: " + unitName)
        if properties |> List.exists (fun property -> not (values.ContainsKey property)) then
            fail ("Incomplete systemd state response for unit: " + unitName)
        values

    let private verifyNativeFirewalldRunning (environment: HostEnvironment) =
        let state = systemdProperties environment "firewalld.service" [ "LoadState"; "ActiveState"; "SubState" ]
        if state["LoadState"] <> "loaded" then fail "The native firewalld systemd unit is not loaded."
        if state["ActiveState"] <> "active" then fail ("Native firewalld is not running (ActiveState=" + state["ActiveState"] + ").")
        if state["SubState"] <> "running" then fail ("Native firewalld is not running (SubState=" + state["SubState"] + ").")
        let result =
            try environment.Run "firewall-cmd" [ "--state" ] None
            with
            | :? TimeoutException -> fail "Timed out while checking native firewalld state; the daemon may be suspended."
            | _ -> fail "Unable to check native firewalld state."
        if result.ExitCode = 124 || result.ExitCode = 137 then
            fail "Timed out while checking native firewalld state; the daemon may be suspended."
        if result.ExitCode <> 0 then
            fail ("Native firewalld is not running (--state exit " + string result.ExitCode + ").")
        if result.Stderr <> "" then fail "Native firewalld --state returned stderr diagnostics."
        if isNull result.Stdout || (result.Stdout <> "running" && result.Stdout <> "running\n") then
            fail "Native firewalld --state did not return exactly running."
    let private verifyPanicOff (environment: HostEnvironment) =
        let result =
            try environment.Run "firewall-cmd" [ "--query-panic" ] None
            with
            | :? TimeoutException -> fail "Timed out while querying native firewalld panic mode."
            | _ -> fail "Unable to query native firewalld panic mode."
        if result.ExitCode = 124 || result.ExitCode = 137 then
            fail "Timed out while querying native firewalld panic mode."
        let exactWord word = not (isNull result.Stdout) && (result.Stdout = word || result.Stdout = word + "\n")
        match result.ExitCode with
        | 0 when exactWord "yes" -> fail "Native firewalld panic mode is enabled; network traffic is suspended."
        | 0 when exactWord "no" -> fail "Native firewalld panic query returned conflicting status and reply."
        | 0 -> fail "Native firewalld panic query returned an ambiguous successful response."
        | 1 when exactWord "yes" -> fail "Native firewalld panic query returned conflicting status and reply."
        | 1 when not (exactWord "no") -> fail "Native firewalld panic query returned an ambiguous negative response."
        | 1 when result.Stderr <> "" -> fail "Native firewalld panic query returned stderr diagnostics."
        | 1 -> ()
        | code -> fail ("Native firewalld panic query failed (exit " + string code + ").")

    let private verifyRecoveryUnit (environment: HostEnvironment) (unitName: string) =
        let state = systemdProperties environment unitName [ "LoadState"; "ActiveState"; "Result"; "ExecMainStatus" ]
        if state["LoadState"] <> "loaded" then
            fail ("Dorothy firewalld recovery unit is not loaded: " + unitName)
        let status =
            match Int32.TryParse(state["ExecMainStatus"], Globalization.NumberStyles.None, Globalization.CultureInfo.InvariantCulture) with
            | true, value when value >= 0 -> value
            | _ -> fail ("Dorothy firewalld recovery unit has an uninspectable ExecMainStatus: " + unitName)
        let preboot = List.head FirewalldLifecycle.dockerBootDecisionUnits
        let containment = List.last FirewalldLifecycle.dockerBootDecisionUnits
        match state["ActiveState"], state["Result"], status with
        | "active", "success", 0 when unitName = preboot -> ()
        | "inactive", "success", 0 when unitName <> preboot -> ()
        | "inactive", "success", 0 -> fail "The ordered firewalld preboot decision is not latched."
        | "inactive", "exec-condition", declined when unitName = containment && (declined = 0 || declined = 1) -> ()
        | ("activating" | "deactivating" | "reloading" | "refreshing"), _, _ ->
            fail ("Dorothy firewalld recovery unit is still in progress: " + unitName)
        | "failed", _, _ ->
            fail ("Dorothy firewalld recovery unit is failed (Result=" + state["Result"] + ", ExecMainStatus=" + string status + "): " + unitName)
        | "active", _, _ ->
            fail ("Dorothy firewalld recovery unit is unexpectedly active or incomplete: " + unitName)
        | "inactive", _, _ ->
            fail ("Dorothy firewalld recovery unit did not complete successfully (Result=" + state["Result"] + ", ExecMainStatus=" + string status + "): " + unitName)
        | active, _, _ -> fail ("Dorothy firewalld recovery unit has an uninspectable ActiveState=" + active + ": " + unitName)

    /// Read-only admission proof: firewalld is running and not suspended, no
    /// Dorothy recovery intent is outstanding, and its local recovery jobs are
    /// not failed or in progress. This is an observation, not a packet-path test.
    let verifyReadiness (environment: HostEnvironment) =
        verifyNativeFirewalldRunning environment
        verifyPanicOff environment
        if not (FirewalldLifecycle.canClassifyPreStageRefusal environment) then
            fail "A pending, orphaned, or uninspectable Dorothy firewalld transaction prevents Docker admission."
        let units = FirewalldLifecycle.dockerBootDecisionUnits
        let preboot = List.head units
        let postboot = List.item 1 units
        let containment = List.last units
        verifyRecoveryUnit environment preboot
        verifyRecoveryUnit environment postboot
        verifyRecoveryUnit environment FirewalldLifecycle.dockerRollbackServiceName
        // The containment ExecCondition may decline only after all recovery and
        // rollback observations above succeeded and no transaction is reserved.
        verifyRecoveryUnit environment containment

    /// Full verification retains permanent/effective StrictForwardPorts and live
    /// policy-order checks, then repeats readiness before admission.
    let verify environment fences =
        verifyReadiness environment
        if not (Firewalld.strictForwardPortsConfigured environment) then fail "The permanent configuration must enable StrictForwardPorts."
        if not (Firewalld.strictForwardPortsLoaded environment) then fail "Cannot establish loaded StrictForwardPorts=yes."
        let names = FirewalldRuntime.listRuntime environment "policy" |> Option.defaultWith (fun () -> fail "Unable to enumerate live firewalld policies.")
        let policies = names |> List.map (fun name ->
            FirewalldRuntime.inspectRuntime environment "policy" name |> Option.defaultWith (fun () -> fail ("Unable to read live firewalld policy: " + name)))
        verifyPolicies policies fences
        verifyReadiness environment
    let internal startCommands (executable: string) (fences: FirewalldGateModel.Fence list) =
        // systemd receives typed argv and the installing helper's immutable path.
        if String.IsNullOrEmpty executable || not (Regex.IsMatch(executable, @"\A/var/cache/keroosha-iac/helper/linux-(?:x64|arm64)/[a-f0-9]{64}\z")) then
            fail "A Docker start gate requires a deployed content-addressed helper."
        match fences with
        | [] -> [ executable + " firewalld-docker-ready" ]
        | _ -> fences |> List.map (fun fence -> executable + " firewalld-docker-gate " + String.concat " " (FirewalldGateModel.arguments fence))

    let private orderAfterDecision () =
        "After=firewalld.service " + String.concat " " FirewalldLifecycle.dockerBootDecisionUnits

    let internal renderStartHook name commands =
        String.concat "\n" ([ "# Dorothy per-start Docker firewall check: " + name; "[Unit]"; orderAfterDecision (); ""; "[Service]" ]
                            @ List.map ((+) "ExecStartPre=") commands @ [ "" ])

    let internal renderUnit commands =
        let checks = commands |> List.map ((+) "ExecStart=")
        String.concat "\n" ([ "[Unit]"; "Description=Dorothy strict firewalld Docker start gate"; "Requires=firewalld.service"; orderAfterDecision (); "Before=docker.service"; "PartOf=docker.service"; ""; "[Service]"; "Type=oneshot" ]
                           @ checks @ [ "RemainAfterExit=yes"; ""; "[Install]"; "RequiredBy=docker.service"; "" ])
