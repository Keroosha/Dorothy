namespace Dorothy.Tests

open System
open System.IO
open System.Xml.Linq

/// Minimal native command surface for ownership/transaction tests. Disk edits do not update
/// the simulated daemon until activation. The Debian guest tests exercise the daemon itself.
module internal FirewalldCommandFixture =
    let commands (root: string) =
        let directories = [ "usr/lib/firewalld"; "etc/firewalld" ]
        let inventory category =
            directories |> List.fold (fun files directory ->
                let dir = Path.Combine(root, directory, category)
                if not (Directory.Exists dir) then files
                else Directory.GetFiles(dir, "*.xml") |> Array.fold (fun files path ->
                    Map.add (Path.GetFileNameWithoutExtension path) (XElement.Load path) files) files) Map.empty
        let load () =
            let settings =
                directories |> List.choose (fun directory ->
                    let path = Path.Combine(root, directory, "firewalld.conf")
                    if File.Exists path then Some(File.ReadAllLines path) else None)
                |> List.tryLast |> Option.defaultValue [||]
            inventory "zones", inventory "policies", settings
        let mutable loaded = lazy(load ())
        let attr name fallback (xml: XElement) =
            match xml.Attribute(XName.Get name) with null -> fallback | value -> value.Value
        let richRules (xml: XElement) =
            xml.Elements(XName.Get "rule")
            |> Seq.map (fun rule ->
                rule.DescendantsAndSelf()
                |> Seq.collect (fun node -> seq {
                    yield node.Name.LocalName
                    for attribute in node.Attributes() do yield sprintf "%s=\"%s\"" attribute.Name.LocalName attribute.Value })
                |> String.concat " ")
            |> Seq.toList
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
        fun executable (arguments: string list) ->
            let zones, policies, settings = if List.contains "--permanent" arguments then load () else loaded.Value
            let arguments = List.filter ((<>) "--permanent") arguments
            let setting key fallback =
                settings |> Array.tryPick (fun line ->
                    let fields = line.Split('=', 2, StringSplitOptions.TrimEntries)
                    if fields.Length = 2 && fields[0] = key then Some fields[1] else None)
                |> Option.defaultValue fallback
            match executable, arguments with
            | "firewall-cmd", [ "--reload" ]
            | ("systemctl" | "/usr/bin/systemctl"), [ "restart"; ("firewalld" | "firewalld.service") ] ->
                let snapshot = load ()
                loaded <- lazy snapshot
                Some ""
            | "firewall-cmd", [ "--get-zones" ] -> Some(String.concat " " zones.Keys)
            | "firewall-cmd", [ "--get-policies" ] -> Some(String.concat " " policies.Keys)
            | "firewall-cmd", [ "--get-default-zone" ] -> Some(setting "DefaultZone" "public")
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
            | "nft", [ "-j"; "list"; "table"; "inet"; "firewalld" ] ->
                let strict = [ "yes"; "true" ] |> List.contains ((setting "StrictForwardPorts" "no").ToLowerInvariant())
                let table = """{"table":{"family":"inet","name":"firewalld"}}"""
                let chain name = sprintf """{"chain":{"family":"inet","table":"firewalld","name":"%s"}}""" name
                let rule name expr = sprintf """{"rule":{"family":"inet","table":"firewalld","chain":"%s","expr":[%s]}}""" name expr
                let matchDnat = """{"match":{"op":"in","left":{"ct":{"key":"status"}},"right":"dnat"}}"""
                let records = [
                    yield table
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
