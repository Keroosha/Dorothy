namespace Dorothy.Tests

open System
open System.IO
open System.Xml.Linq

/// Minimal native command surface for ownership/transaction tests. Disk edits do not update
/// the simulated daemon until activation. The Debian guest tests exercise the daemon itself.
module internal FirewalldCommandFixture =
    let recoveryUnitNames =
        [ "keroosha-iac-firewalld-rollback.service"
          "keroosha-iac-firewalld-boot-recovery.service"
          "keroosha-iac-firewalld-postboot-recovery.service"
          "keroosha-iac-firewalld-boot-containment.service"
          "keroosha-iac-firewalld-rollback.timer" ]
    let dependencyProperties =
        [ "Id"; "Names"; "LoadState"; "NeedDaemonReload"; "Wants"; "Requires"; "Requisite"
          "BindsTo"; "Upholds"; "OnFailure"; "OnSuccess"; "Conflicts"; "Triggers"
          "FragmentPath"; "DropInPaths" ]
    let dependencyQuery = String.concat "," dependencyProperties
    let dependencyQueryArguments =
        [ "show"; "--all"; "-p"; dependencyQuery; "--" ] @ recoveryUnitNames @ [ "firewalld.service" ]
    let private unitSearchPaths =
        [ "/etc/systemd/system.control"; "/etc/systemd/system"; "/run/systemd/system.attached"
          "/run/systemd/system"; "/usr/lib/systemd/system" ]
    let private mapPath root (logical: string) = Path.Combine(root, logical.TrimStart('/'))
    let unitFilesArguments root =
        let physical = mapPath root
        [ "-i"; "LC_ALL=C"; "PATH=/usr/sbin:/usr/bin:/sbin:/bin"
          "SYSTEMD_UNIT_PATH=" + (unitSearchPaths |> List.map physical |> String.concat ":")
          "/usr/bin/systemd-analyze"; "--system"; "--no-pager"; "unit-files"
          physical "/usr/lib/systemd/system/firewalld.service" ] @ recoveryUnitNames
    let systemdUnitFilesOutput root =
        let physical = mapPath root
        let firewall =
            "ids: firewalld.service → " + physical "/usr/lib/systemd/system/firewalld.service" + "\n"
        let ownedUnits =
            recoveryUnitNames
            |> List.choose (fun name ->
                let path = physical ("/etc/systemd/system/" + name)
                if File.Exists path then
                    Some("ids: " + name + " → " + path + "\naliases: " + name + " ← " + name + "\n")
                else None)
        firewall + String.concat "" ownedUnits
    let unitPathArguments =
        [ "--system"; "--json=short"; "get-property"; "org.freedesktop.systemd1"
          "/org/freedesktop/systemd1"; "org.freedesktop.systemd1.Manager"; "UnitPath" ]
    let unitPathResponse =
        """{"type":"as","data":["/etc/systemd/system.control","/etc/systemd/system","/run/systemd/system.attached","/run/systemd/system","/usr/lib/systemd/system"]}"""

    let systemdDependencyOutput (root: string) (dependencyOverrides: Map<string, Map<string, string>>) =
        let entryExists path =
            File.Exists path || Directory.Exists path || not (isNull (FileInfo(path).LinkTarget))
        let block name =
            let isFirewalld = name = "firewalld.service"
            let physical =
                if isFirewalld then Path.Combine(root, "usr/lib/systemd/system/firewalld.service")
                else Path.Combine(root, "etc/systemd/system", name)
            let loaded = isFirewalld || File.Exists physical
            let requires, wants, conflicts, triggers =
                if not loaded then "", "", "", ""
                else
                    match name with
                    | "keroosha-iac-firewalld-rollback.service" -> "system.slice", "", "", ""
                    | "keroosha-iac-firewalld-boot-recovery.service" -> "system.slice", "", "", ""
                    | "keroosha-iac-firewalld-postboot-recovery.service" -> "system.slice firewalld.service", "", "", ""
                    | "keroosha-iac-firewalld-boot-containment.service" ->
                        "system.slice", "firewalld.service keroosha-iac-firewalld-boot-recovery.service keroosha-iac-firewalld-postboot-recovery.service", "", ""
                    | "keroosha-iac-firewalld-rollback.timer" -> "sysinit.target", "", "shutdown.target", "keroosha-iac-firewalld-rollback.service"
                    | _ when isFirewalld ->
                        let legacy = Path.Combine(root, "etc/systemd/system/firewalld.service.requires/keroosha-iac-firewalld-boot-recovery.service")
                        let wanted = Path.Combine(root, "etc/systemd/system/firewalld.service.wants/keroosha-iac-firewalld-boot-recovery.service")
                        let ordinaryRequires = "system.slice sysinit.target dbus.socket"
                        (if entryExists legacy then ordinaryRequires + " keroosha-iac-firewalld-boot-recovery.service" else ordinaryRequires),
                        (if entryExists wanted then "network-pre.target keroosha-iac-firewalld-boot-recovery.service" else "network-pre.target"), "", ""
                    | _ -> "", "", "", ""
            let values =
                [ "Id", name
                  "Names", if isFirewalld then "firewalld.service dbus-org.fedoraproject.FirewallD1.service" else name
                  "LoadState", if loaded then "loaded" else "not-found"
                  "NeedDaemonReload", "no"
                  "Wants", wants
                  "Requires", requires
                  "Requisite", ""
                  "BindsTo", ""
                  "Upholds", ""
                  "OnFailure", ""
                  "OnSuccess", ""
                  "Conflicts", conflicts
                  "Triggers", triggers
                  "FragmentPath", if loaded then physical else ""
                  "DropInPaths", "" ]
                |> Map.ofList
            let overrides = dependencyOverrides |> Map.tryFind name |> Option.defaultValue Map.empty
            dependencyProperties
            |> List.map (fun property ->
                property + "=" + (overrides |> Map.tryFind property |> Option.defaultValue (Map.find property values)))
            |> String.concat "\n"
        recoveryUnitNames @ [ "firewalld.service" ]
        |> List.map block
        |> String.concat "\n\n"
    let commands (root: string) =
        let kernel = Directory.CreateDirectory(Path.Combine(root, "proc/sys/kernel/random"))
        File.WriteAllText(Path.Combine(kernel.FullName, "boot_id"), "12345678-1234-4234-8234-123456789012")
        let directories = [ "usr/lib/firewalld"; "etc/firewalld" ]
        let inventory category =
            directories |> List.fold (fun files directory ->
                let dir = Path.Combine(root, directory, category)
                if not (Directory.Exists dir) then files
                else Directory.GetFiles(dir, "*.xml") |> Array.fold (fun files path ->
                    Map.add (Path.GetFileNameWithoutExtension path) (XElement.Load path) files) files) Map.empty
        let load () =
            let settingsPath = Path.Combine(root, "etc/firewalld/firewalld.conf")
            let settings = if File.Exists settingsPath then File.ReadAllLines settingsPath else [||]
            [ "zone", "zones"; "policy", "policies"; "service", "services"
              "ipset", "ipsets"; "icmptype", "icmptypes"; "helper", "helpers" ]
            |> List.map (fun (kind, dir) -> kind, inventory dir)
            |> Map.ofList, settings
        let mutable loaded = lazy(load ())
        let attr name fallback (xml: XElement) =
            match xml.Attribute(XName.Get name) with null -> fallback | value -> value.Value
        let richRuleText (rule: XElement) =
            rule.DescendantsAndSelf()
            |> Seq.collect (fun node -> seq {
                yield node.Name.LocalName
                for attribute in node.Attributes() do yield sprintf "%s=\"%s\"" attribute.Name.LocalName attribute.Value })
            |> String.concat " "
        let richRules (xml: XElement) =
            xml.Elements(XName.Get "rule") |> Seq.map richRuleText |> Seq.toList
        let listing kind name (xml: XElement) =
            let children tag = xml.Elements(XName.Get tag)
            let names tag key = children tag |> Seq.map (attr key "") |> String.concat " "
            let ports tag = children tag |> Seq.map (fun p -> attr "port" "" p + "/" + attr "protocol" "" p) |> String.concat " "
            let flag tag = if Seq.isEmpty (children tag) then "no" else "yes"
            let fields = [
                if kind = "policy" then "priority", attr "priority" "-1" xml
                "target", attr "target" (if kind = "zone" then "default" else "CONTINUE") xml
                if kind = "zone" then
                    "ingress-priority", attr "ingress-priority" "0" xml
                    "egress-priority", attr "egress-priority" "0" xml
                    "icmp-block-inversion", flag "icmp-block-inversion"
                    "interfaces", names "interface" "name"
                    "sources", names "source" "address"
                else
                    "ingress-zones", names "ingress-zone" "name"
                    "egress-zones", names "egress-zone" "name"
                "services", names "service" "name"
                "ports", ports "port"
                "protocols", names "protocol" "value"
                if kind = "zone" then "forward", flag "forward"
                "masquerade", flag "masquerade"
                "forward-ports", ""
                "source-ports", ports "source-port"
                "icmp-blocks", names "icmp-block" "name"
                "rich rules", (richRules xml |> List.map ((+) "\n\t") |> String.concat "") ]
            String.concat "\n" (name :: (fields |> List.map (fun (key,value) -> "  " + key + ": " + value)))
        let definition kind name (xml: XElement) =
            let children tag = xml.Elements(XName.Get tag)
            let names tag key = children tag |> Seq.map (attr key "") |> String.concat " "
            let ports tag = children tag |> Seq.map (fun p -> attr "port" "" p + "/" + attr "protocol" "" p) |> String.concat " "
            let destinations = children "destination" |> Seq.collect _.Attributes()
            let fields =
                match kind with
                | "service" ->
                    [ "ports", ports "port"; "protocols", names "protocol" "value"; "source-ports", ports "source-port"
                      "modules", names "module" "name"; "destination", (destinations |> Seq.map (fun a -> a.Name.LocalName + ":" + a.Value) |> String.concat " ")
                      "includes", names "include" "service"; "helpers", names "helper" "name" ]
                | "helper" -> [ "family", attr "family" "" xml; "module", attr "module" "" xml; "ports", ports "port" ]
                | "icmptype" ->
                    let families = destinations |> Seq.choose (fun a -> if a.Value = "yes" then Some a.Name.LocalName else None) |> String.concat " "
                    [ "destination", (if families = "" then "ipv4 ipv6" else families) ]
                | "ipset" ->
                    [ "type", attr "type" "" xml
                      "options", (children "option" |> Seq.map (fun o -> attr "name" "" o + "=" + attr "value" "" o) |> String.concat " ")
                      "entries", (children "entry" |> Seq.map _.Value |> String.concat " ") ]
                | _ -> invalidOp "Not a definition."
            String.concat "\n" (name :: (fields |> List.map (fun (k, v) -> "  " + k + ": " + v)))
        let builtInIcmpTypes =
            set [ "neighbour-advertisement"; "neighbour-solicitation"; "router-advertisement"; "redirect" ]
        let mutateRuntimeSelector (selector: string) (operation: string) =
            let kind, name =
                if selector.StartsWith("--zone=", StringComparison.Ordinal) then "zone", selector.Substring(7)
                elif selector.StartsWith("--policy=", StringComparison.Ordinal) then "policy", selector.Substring(9)
                else "", ""
            let action, tag, attributes =
                if operation.StartsWith("--add-service=", StringComparison.Ordinal) then
                    Some true, "service", [ "name", operation.Substring("--add-service=".Length) ]
                elif operation.StartsWith("--remove-service=", StringComparison.Ordinal) then
                    Some false, "service", [ "name", operation.Substring("--remove-service=".Length) ]
                elif operation.StartsWith("--add-port=", StringComparison.Ordinal)
                     || operation.StartsWith("--remove-port=", StringComparison.Ordinal) then
                    let adding = operation.StartsWith("--add-port=", StringComparison.Ordinal)
                    let prefix = if adding then "--add-port=" else "--remove-port="
                    match operation.Substring(prefix.Length).Split('/') with
                    | [| port; protocol |] -> Some adding, "port", [ "port", port; "protocol", protocol ]
                    | _ -> None, "", []
                else None, "", []
            match action, (Map.tryFind kind (fst loaded.Value) |> Option.bind (Map.tryFind name)) with
            | Some add, Some current ->
                let objects, settings = loaded.Value
                let xml = XElement(current)
                let matches (element: XElement) =
                    element.Name = XName.Get tag
                    && (attributes |> List.forall (fun (key, value) -> attr key "" element = value))
                let existing = xml.Elements(XName.Get tag) |> Seq.filter matches |> Seq.toArray
                if add then
                    if existing.Length = 0 then
                        let element = XElement(XName.Get tag)
                        for (key, value) in attributes do element.SetAttributeValue(XName.Get key, value)
                        xml.Add element
                else
                    for element in existing do element.Remove()
                let updated = Map.add name xml objects[kind]
                loaded <- lazy(Map.add kind updated objects, settings)
                Some "success"
            | _ -> None
        let mutateRuntimeRichRule (selector: string) (operation: string) =
            let kind, name =
                if selector.StartsWith("--zone=", StringComparison.Ordinal) then "zone", selector.Substring(7)
                elif selector.StartsWith("--policy=", StringComparison.Ordinal) then "policy", selector.Substring(9)
                else "", ""
            let action, prefix =
                if operation.StartsWith("--add-rich-rule=", StringComparison.Ordinal) then Some true, "--add-rich-rule="
                elif operation.StartsWith("--remove-rich-rule=", StringComparison.Ordinal) then Some false, "--remove-rich-rule="
                else None, ""
            let value = operation.Substring(prefix.Length)
            let knownBan = "rule family=\"ipv4\" source address=\"198.51.100.99\" drop"
            let element =
                if value = knownBan then
                    Some(XElement(
                        XName.Get "rule",
                        XAttribute(XName.Get "family", "ipv4"),
                        XElement(XName.Get "source", XAttribute(XName.Get "address", "198.51.100.99")),
                        XElement(XName.Get "drop")))
                else None
            match action, element, Map.tryFind kind (fst loaded.Value) |> Option.bind (Map.tryFind name) with
            | Some add, Some rule, Some current ->
                let objects, settings = loaded.Value
                let xml = XElement(current)
                let existing = xml.Elements(XName.Get "rule") |> Seq.filter (fun item -> richRuleText item = value) |> Seq.toArray
                if add then
                    if existing.Length = 0 then xml.Add rule
                else
                    for item in existing do item.Remove()
                loaded <- lazy(Map.add kind (Map.add name xml objects[kind]) objects, settings)
                Some "success"
            | _ -> None


        fun executable (arguments: string list) ->
            let objects, settings = if List.contains "--permanent" arguments then load () else loaded.Value
            let zones, policies = objects["zone"], objects["policy"]
            let arguments = List.filter ((<>) "--permanent") arguments
            let setting key fallback =
                settings |> Array.tryPick (fun line ->
                    let fields = line.Split('=', 2, StringSplitOptions.TrimEntries)
                    if fields.Length = 2 && fields[0] = key then Some fields[1] else None)
                |> Option.defaultValue fallback
            match executable, arguments with
            | "/usr/bin/busctl", args when args = unitPathArguments -> Some unitPathResponse
            | "/usr/bin/env", args when args = unitFilesArguments root ->
                Some(systemdUnitFilesOutput root)
            | "/usr/bin/systemctl", args when args = dependencyQueryArguments ->
                Some(systemdDependencyOutput root Map.empty)
            | "firewall-cmd", [ "--direct"; ("--get-all-rules" | "--get-all-chains" | "--get-all-passthroughs") ] -> Some ""
            | "/usr/bin/busctl", args when List.tryLast args = Some "IPv6_rpfilter" ->
                Some(if List.contains (setting "IPv6_rpfilter" "strict") [ "no"; "false" ] then "b false" else "b true")
            | "firewall-cmd", [ "--reload" ]
            | ("systemctl" | "/usr/bin/systemctl"), [ "restart"; ("firewalld" | "firewalld.service") ] ->
                let snapshot = load ()
                loaded <- lazy snapshot
                Some ""
            | "firewall-cmd", [ "--get-zones" ] -> Some(String.concat " " zones.Keys)
            | "firewall-cmd", [ "--get-policies" ] -> Some(String.concat " " policies.Keys)
            | "firewall-cmd", [ opt ] when List.contains opt ["--get-services"; "--get-helpers"; "--get-icmptypes"; "--get-ipsets"] ->
                let kind = opt.Substring(6, opt.Length - 7)
                Some(String.concat " " objects[kind].Keys)
            | "firewall-cmd", [ opt ] when opt.StartsWith("--info-", StringComparison.Ordinal) ->
                let selector = opt.Substring(7).Split('=', 2)
                if selector.Length <> 2 then None
                else
                    match Map.tryFind selector[0] objects |> Option.bind (Map.tryFind selector[1]) with
                    | Some xml -> Some(definition selector[0] selector[1] xml)
                    | None when selector[0] = "icmptype" && builtInIcmpTypes.Contains selector[1] ->
                        Some(selector[1] + "\n  destination: ipv6")
                    | None -> None
            | "firewall-cmd", [ "--version" ] -> Some "2.3.1"
            | "firewall-cmd", [ "--get-default-zone" ] -> Some(setting "DefaultZone" "public")
            | "firewall-cmd", [ "--get-log-denied" ] -> Some(setting "LogDenied" "off")
            | "firewall-cmd", [ "--get-zone-of-interface=eth0" ] ->
                zones |> Map.tryPick (fun name zone ->
                    if zone.Elements(XName.Get "interface") |> Seq.exists (fun iface -> attr "name" "" iface = "eth0") then Some name else None)
                |> Option.defaultValue "no zone\n" |> Some
            | "firewall-cmd", [ selector; "--list-sources" ] when selector.StartsWith("--zone=") ->
                Some(zones[selector.Substring(7)].Elements(XName.Get "source") |> Seq.map (attr "address" "") |> String.concat " ")
            | "firewall-cmd", [ selector; "--list-interfaces" ] when selector.StartsWith("--zone=") ->
                Some(zones[selector.Substring(7)].Elements(XName.Get "interface") |> Seq.map (attr "name" "") |> String.concat " ")
            | "firewall-cmd", [ selector; "--list-rich-rules" ] when selector.StartsWith("--zone=") ->
                Some(String.concat "\n" (richRules zones[selector.Substring(7)]))
            | "firewall-cmd", [ selector; "--list-rich-rules" ] when selector.StartsWith("--policy=") ->
                Some(String.concat "\n" (richRules policies[selector.Substring(9)]))
            | "firewall-cmd", [ selector; "--list-all" ] when selector.StartsWith("--zone=") ->
                let name = selector.Substring(7)
                Map.tryFind name zones |> Option.map (listing "zone" name)
            | "firewall-cmd", [ selector; "--list-all" ] when selector.StartsWith("--policy=") ->
                let name = selector.Substring(9)
                Map.tryFind name policies |> Option.map (listing "policy" name)
            | "firewall-cmd", [ selector; operation ]
                when (operation.StartsWith("--add-rich-rule=", StringComparison.Ordinal)
                      || operation.StartsWith("--remove-rich-rule=", StringComparison.Ordinal))
                     && (selector.StartsWith("--zone=", StringComparison.Ordinal)
                         || selector.StartsWith("--policy=", StringComparison.Ordinal)) ->
                mutateRuntimeRichRule selector operation
            | "firewall-cmd", [ selector; operation ] when selector.StartsWith("--zone=", StringComparison.Ordinal) || selector.StartsWith("--policy=", StringComparison.Ordinal) ->
                mutateRuntimeSelector selector operation
            | "nft", [ "-j"; "list"; "table"; "inet"; "firewalld" ] ->
                let strict = [ "yes"; "true" ] |> List.contains ((setting "StrictForwardPorts" "no").ToLowerInvariant())
                let table = """{"table":{"family":"inet","name":"firewalld"}}"""
                let chain name = sprintf """{"chain":{"family":"inet","table":"firewalld","name":"%s"}}""" name
                let rule name expr = sprintf """{"rule":{"family":"inet","table":"firewalld","chain":"%s","expr":[%s]}}""" name expr
                let matchDnat = """{"match":{"op":"in","left":{"ct":{"key":"status"}},"right":"dnat"}}"""
                let records = [
                    yield table
                    let rpf = setting "IPv6_rpfilter" "strict"
                    if not (List.contains rpf [ "no"; "false" ]) then
                        let hook = if rpf.EndsWith("-forward") then "filter_FORWARD" else "filter_PREROUTING"
                        let flags = if rpf.StartsWith("loose") then "\"saddr\",\"mark\"" else "\"saddr\",\"mark\",\"iif\""
                        yield rule hook ("""{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv6"}},{"match":{"op":"==","left":{"fib":{"result":"oif","flags":[""" + flags + """]}},"right":false}},{"drop":null}""")
                    for baseName in [ "filter_INPUT"; "filter_FORWARD"; "filter_OUTPUT" ] do
                        yield chain baseName
                        if strict then
                            let dnat = baseName + "_dnat"
                            yield chain dnat
                            yield rule baseName (matchDnat + sprintf """,{"jump":{"target":"%s"}}""" dnat)
                            yield rule dnat """{"reject":{"type":"icmpx","expr":"admin-prohibited"}}"""
                        else yield rule baseName (matchDnat + """,{"accept":null}""") ]
                Some("{\"nftables\":[" + String.concat "," records + "]}")
            | _ -> None
