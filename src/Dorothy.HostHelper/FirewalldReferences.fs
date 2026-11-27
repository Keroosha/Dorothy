namespace Dorothy.HostHelper

open System
open System.Collections.Generic
open System.Xml.Linq

/// Validates the next *individual* reload, including external consumers not in the Pulumi graph.
/// Inputs are the effective vendor + override inventory with the candidate already substituted.
module internal FirewalldReferences =
    let private attribute name (node: XElement) =
        match node.Attribute(XName.Get name) with null -> None | value -> Some value.Value

    let private references (root: XElement) = seq {
        for node in root.Descendants() do
            let reference =
                match node.Name.LocalName with
                | "service" -> attribute "name" node |> Option.map (fun n -> "service", n)
                | "include" -> attribute "service" node |> Option.map (fun n -> "service", n)
                | "helper" -> attribute "name" node |> Option.map (fun n -> "helper", n)
                | "module" ->
                    attribute "name" node
                    |> Option.map (fun moduleName -> "helper", FirewalldModel.helperNameForModule moduleName)
                | "icmp-block" | "icmp-type" -> attribute "name" node |> Option.map (fun n -> "icmptype", n)
                | "source" | "destination" -> attribute "ipset" node |> Option.map (fun n -> "ipset", n)
                | "ingress-zone" | "egress-zone" ->
                    attribute "name" node |> Option.bind (function "HOST" | "ANY" -> None | n -> Some("zone", n))
                | _ -> None
            match reference with Some identity -> yield identity | None -> () }

    let private overlap (a: string) (b: string) =
        let prefix (selector: string) = selector.TrimEnd('+')
        let aPrefix, bPrefix = prefix a, prefix b
        a = b
        || (a.EndsWith('+') && bPrefix.StartsWith(aPrefix, StringComparison.Ordinal))
        || (b.EndsWith('+') && aPrefix.StartsWith(bPrefix, StringComparison.Ordinal))

    let private validateBindings parse name (zone: XElement) (zones: Map<string,string>) =
        let interfaces (root: XElement) = root.Elements(XName.Get "interface") |> Seq.choose (attribute "name")
        let sources (root: XElement) =
            root.Elements(XName.Get "source") |> Seq.choose (fun source ->
                match attribute "ipset" source, attribute "address" source with
                | Some set, _ -> Some("ipset:" + set)
                | _, Some address -> Some("address:" + address.ToUpperInvariant())
                | _ -> None)
        let ownedInterfaces = interfaces zone |> Seq.toArray
        let ownedSources = sources zone |> Set.ofSeq
        if ownedInterfaces.Length <> 0 || not ownedSources.IsEmpty then
            for KeyValue(otherName, xml) in zones do
                if otherName <> name then
                    let other = parse "zone" xml
                    if interfaces other |> Seq.exists (fun iface -> ownedInterfaces |> Array.exists (overlap iface)) then
                        invalidOp ("An interface selector overlaps a binding in zone " + otherName + "; remove that binding first.")
                    if sources other |> Seq.exists ownedSources.Contains then
                        invalidOp ("A source is already bound to zone " + otherName + "; remove that binding first.")

    let usedByPacketFilter parse kind name (objects: Map<string, Map<string,string>>) =
        let seen = HashSet<string>(StringComparer.Ordinal)
        let rec depends (k, n) =
            if (k, n) = (kind, name) then true
            elif k = "service" && seen.Add n then
                match Map.tryFind n objects["service"] with
                | Some xml -> references (parse "service" xml) |> Seq.exists depends
                | None -> true // an uninspectable dependency is not evidence of disuse
            else false
        [ "zone"; "policy" ] |> List.exists (fun k ->
            objects[k] |> Map.exists (fun _ xml -> references (parse k xml) |> Seq.exists depends))

    let validate (parse: string -> string -> XElement) kind name defaultZone (objects: Map<string, Map<string,string>>) =
        let zones = objects["zone"]
        if not (Map.containsKey defaultZone zones) then invalidOp ("DefaultZone references a missing permanent zone: " + defaultZone)
        if kind <> "settings" then
            match Map.tryFind name objects[kind] with
            | None ->
                // Removing the override with no vendor fallback removes this definition. The
                // desired graph cannot tell us about a manually managed service, zone or policy.
                for consumerKind in [ "service"; "zone"; "policy" ] do
                    for KeyValue(consumer, xml) in objects[consumerKind] do
                        if references (parse consumerKind xml) |> Seq.contains (kind, name) then
                            invalidOp ("Cannot remove " + kind + " " + name + ": still referenced by " + consumerKind + " " + consumer + ".")
            | Some xml ->
                let root = parse kind xml
                if (kind = "zone" && objects["policy"].ContainsKey name) || (kind = "policy" && zones.ContainsKey name) then
                    invalidOp ("A zone and a policy cannot share the permanent name " + name + ".")
                let visited = HashSet<string>(StringComparer.Ordinal)
                let visiting = HashSet<string>(StringComparer.Ordinal)
                let rec check parentKind parentName target =
                    let targetKind, targetName = target
                    match Map.tryFind targetName objects[targetKind] with
                    | None -> invalidOp ("Missing firewalld " + targetKind + " prerequisite: " + targetName + " (referenced by " + parentKind + " " + parentName + ").")
                    | Some targetXml when targetKind = "service" && not (visited.Contains targetName) ->
                        if not (visiting.Add targetName) then invalidOp ("Cyclic firewalld service include: " + targetName)
                        references (parse targetKind targetXml) |> Seq.iter (check targetKind targetName)
                        visiting.Remove targetName |> ignore
                        visited.Add targetName |> ignore
                    | _ -> ()
                references root |> Seq.iter (check kind name)
                if kind = "zone" then validateBindings parse name root zones
