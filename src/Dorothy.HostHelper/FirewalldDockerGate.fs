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

    let verify environment fences =
        if not (Firewalld.strictForwardPortsConfigured environment) then fail "The permanent configuration must enable StrictForwardPorts."
        if not (Firewalld.strictForwardPortsLoaded environment) then fail "Cannot establish loaded StrictForwardPorts=yes."
        let names = FirewalldRuntime.listRuntime environment "policy" |> Option.defaultWith (fun () -> fail "Unable to enumerate live firewalld policies.")
        let policies = names |> List.map (fun name ->
            FirewalldRuntime.inspectRuntime environment "policy" name |> Option.defaultWith (fun () -> fail ("Unable to read live firewalld policy: " + name)))
        verifyPolicies policies fences

    let renderUnit (executable: string) (fences: FirewalldGateModel.Fence list) =
        // No shell, writable dispatch link or daemon. systemd executes the verified,
        // immutable native helper which installed this unit; every argument is typed.
        if String.IsNullOrEmpty executable || not (Regex.IsMatch(executable, @"\A/var/cache/keroosha-iac/helper/linux-(?:x64|arm64)/[a-f0-9]{64}\z")) then
            fail "A Docker start gate requires a deployed content-addressed helper."
        let checks = fences |> List.map (fun f -> "ExecStart=" + executable + " firewalld-docker-gate " + String.concat " " (FirewalldGateModel.arguments f))
        String.concat "\n" ([ "[Unit]"; "Description=Dorothy strict firewalld Docker start gate"; "Requires=firewalld.service"; "After=firewalld.service"; "Before=docker.service"; "PartOf=docker.service"; ""; "[Service]"; "Type=oneshot" ]
                           @ checks @ [ "RemainAfterExit=yes"; ""; "[Install]"; "RequiredBy=docker.service"; "" ])
