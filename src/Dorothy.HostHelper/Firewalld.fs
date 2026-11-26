namespace Dorothy.HostHelper

open System
open System.IO
open System.Net
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open System.Xml
open System.Xml.Linq

module Firewalld =
    type BackendError(message: string) =
        inherit Exception(message)

    let private fail message = raise (BackendError message)
    let private xn name = XName.Get name
    let private attr name (node: XElement) =
        match node.Attribute(xn name) with null -> None | value -> Some value.Value
    let private required name node = attr name node |> Option.defaultWith (fun () -> fail ("Missing firewalld XML attribute " + name + "."))

    let parseXml (kind: string) (text: string) =
        let settings = XmlReaderSettings()
        settings.DtdProcessing <- DtdProcessing.Prohibit
        settings.XmlResolver <- null
        use input = new StringReader(text)
        use reader = XmlReader.Create(input, settings)
        let document = XDocument.Load(reader)
        if isNull document.Root || document.Root.Name <> xn kind then fail "Unexpected firewalld XML root."
        document.Root

    let render = FieldRuntime.render
    let canonicalXml = FieldRuntime.canonicalXml

    type SshContext = { Peer: string; PeerPort: int; Local: string; Port: int; Interface: string }

    let parseSshContext (connection: string) (routeJson: string) =
        let fields = if isNull connection then [||] else connection.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
        let address (text: string) =
            match IPAddress.TryParse text with true, value -> value | _ -> fail "SSH_CONNECTION contains an invalid IP address."
        if fields.Length <> 4 then fail "SSH_CONNECTION is required to guard firewalld mutations."
        let peer, local = address fields[0], address fields[2]
        let number label (text: string) =
            match Int32.TryParse text with
            | true, value when value >= 1 && value <= 65535 -> value
            | _ -> fail ("SSH_CONNECTION has an invalid " + label + ".")
        let peerPort, port = number "peer port" fields[1], number "server port" fields[3]
        if peer.AddressFamily <> local.AddressFamily then fail "SSH_CONNECTION address families differ."
        use document = JsonDocument.Parse routeJson
        let routes = document.RootElement.EnumerateArray() |> Seq.toArray
        if routes.Length <> 1 then fail "Cannot identify a unique SSH route."
        let iface = routes[0].GetProperty("dev").GetString()
        FirewalldModel.token "SSH interface" 15 iface |> ignore
        { Peer = peer.ToString(); PeerPort = peerPort; Local = local.ToString(); Port = port; Interface = iface }

    type private MatchResult = Match | NoMatch | Unknown
    type private Packet =
        { Source: IPAddress; SourcePort: int
          Destination: IPAddress; DestinationPort: int }
    type private RuleResult = NotApplicable | RuleAllows | RuleBlocks | RuleUnknown

    let private asAddress (value: string) : IPAddress option =
        match IPAddress.TryParse value with true, parsed -> Some parsed | _ -> None

    let private cidrMatches (selector: string) (address: IPAddress) =
        let parts = selector.Split('/')
        if parts.Length > 2 then Unknown
        else
            match asAddress parts[0] with
            | None -> Unknown
            | Some network ->
                let networkBytes, addressBytes = network.GetAddressBytes(), address.GetAddressBytes()
                if networkBytes.Length <> addressBytes.Length then NoMatch
                else
                    let prefix =
                        if parts.Length = 1 then networkBytes.Length * 8
                        else
                            match Int32.TryParse parts[1] with
                            | true, value when value >= 0 && value <= networkBytes.Length * 8 -> value
                            | _ -> -1
                    if prefix < 0 then Unknown
                    else
                        let fullBytes, remainingBits = prefix / 8, prefix % 8
                        let fullEqual =
                            [ 0 .. fullBytes - 1 ]
                            |> List.forall (fun index -> networkBytes[index] = addressBytes[index])
                        let partialEqual =
                            if remainingBits = 0 then true
                            else
                                let mask = byte (0xff <<< (8 - remainingBits))
                                let networkPart = networkBytes[fullBytes] &&& mask
                                let addressPart = addressBytes[fullBytes] &&& mask
                                networkPart = addressPart
                        if fullEqual && partialEqual then Match else NoMatch

    let private invertMatch invert result =
        match invert, result with
        | false, result -> result
        | true, Match -> NoMatch
        | true, NoMatch -> Match
        | true, Unknown -> Unknown

    let private allMatches values =
        if List.contains NoMatch values then NoMatch
        elif List.contains Unknown values then Unknown
        else Match

    let private anyMatches values =
        if List.contains Match values then Match
        elif List.contains Unknown values then Unknown
        else NoMatch

    let private boolAttribute name (element: XElement) =
        match attr name element with
        | None -> Some false
        | Some value when String.Equals(value, "yes", StringComparison.OrdinalIgnoreCase)
                          || String.Equals(value, "true", StringComparison.OrdinalIgnoreCase) -> Some true
        | Some value when String.Equals(value, "no", StringComparison.OrdinalIgnoreCase)
                          || String.Equals(value, "false", StringComparison.OrdinalIgnoreCase) -> Some false
        | _ -> None
    let private attributesAreAllowed (allowed: Set<string>) (element: XElement) =
        element.Attributes() |> Seq.forall (fun value -> Set.contains value.Name.LocalName allowed)

    let private portRangeMatches (range: string) (value: int) =
        let pieces = range.Split('-')
        let parse (text: string) =
            match Int32.TryParse text with
            | true, number when number >= 1 && number <= 65535 -> Some number
            | _ -> None
        if pieces.Length < 1 || pieces.Length > 2 then Unknown
        else
            match parse pieces[0], parse pieces[pieces.Length - 1] with
            | Some first, Some last when last >= first -> if value >= first && value <= last then Match else NoMatch
            | _ -> Unknown
    let private tcpProtocol (value: string) =
        match value with
        | "tcp" | "6" -> Match
        | "udp" | "sctp" | "dccp" | "icmp" | "ipv6-icmp" | "1" | "58" -> NoMatch
        | _ ->
            match Int32.TryParse value with
            | true, number -> if number = 6 then Match else NoMatch
            | _ -> Unknown

    let private transportMatches (value: string) =
        match value with
        | "tcp" | "6" -> Match
        | "udp" | "sctp" | "dccp" -> NoMatch
        | _ -> Unknown

    let private ipSetMatches (ipsetXml: string -> string option) (name: string) (address: IPAddress) (port: int) =
        match ipsetXml name with
        | None -> Unknown
        | Some xml ->
            let root = parseXml "ipset" xml
            if not (attributesAreAllowed (set [ "type"; "version" ]) root) then Unknown
            else
                let setType = attr "type" root |> Option.defaultValue ""
                let optionNodes = root.Elements(xn "option") |> Seq.toList
                let optionsSupported =
                    optionNodes
                    |> List.forall (fun element ->
                        attributesAreAllowed (set [ "name"; "value" ]) element
                        && (attr "name" element |> Option.isSome)
                        && (attr "value" element |> Option.isSome)
                        && element.IsEmpty)
                let optionValues =
                    optionNodes
                    |> List.choose (fun element ->
                        match attr "name" element, attr "value" element with
                        | Some key, Some value -> Some(key, value)
                        | _ -> None)
                let duplicateOptions = optionValues |> List.countBy fst |> List.exists (fun (_, count) -> count > 1)
                let options = optionValues |> Map.ofList
                let allowedOptions = set [ "family"; "timeout"; "hashsize"; "maxelem"; "bucketsize"; "initval" ]
                let unknownOptions = options |> Map.exists (fun key _ -> not (Set.contains key allowedOptions))
                let familyResult =
                    match Map.tryFind "family" options, address.AddressFamily with
                    | None, _ | Some "inet", System.Net.Sockets.AddressFamily.InterNetwork | Some "ipv4", System.Net.Sockets.AddressFamily.InterNetwork -> Match
                    | Some "inet6", System.Net.Sockets.AddressFamily.InterNetworkV6 | Some "ipv6", System.Net.Sockets.AddressFamily.InterNetworkV6 -> Match
                    | Some "inet", _ | Some "ipv4", _ | Some "inet6", _ | Some "ipv6", _ -> NoMatch
                    | Some _, _ -> Unknown
                let timed =
                    match Map.tryFind "timeout" options with
                    | Some value -> match Int32.TryParse value with true, 0 -> false | true, _ -> true | _ -> true
                    | None -> false
                let addressKind, portKind =
                    match setType with
                    | "hash:ip" -> "ip", false
                    | "hash:net" -> "net", false
                    | "hash:ip,port" -> "ip", true
                    | "hash:net,port" -> "net", true
                    | _ -> "unknown", false
                if not optionsSupported || duplicateOptions || unknownOptions
                   || timed || addressKind = "unknown"
                   || (root.Elements() |> Seq.exists (fun element -> element.Name <> xn "option" && element.Name <> xn "entry" && element.Name <> xn "short" && element.Name <> xn "description")) then Unknown
                elif familyResult <> Match then familyResult
                else
                    let entryMatch (element: XElement) =
                        if not (element.IsEmpty || (not element.HasElements && element.Value.Trim() <> "")) then Unknown
                        elif not (element.Attributes() |> Seq.isEmpty) then Unknown
                        else
                            let entry = element.Value.Trim()
                            let parts = if portKind then entry.Split(',') else [| entry |]
                            if parts.Length <> (if portKind then 2 else 1) then Unknown
                            else
                                let addressResult =
                                    if addressKind = "ip" then
                                        match asAddress parts[0] with
                                        | Some entryAddress when entryAddress.AddressFamily <> address.AddressFamily -> NoMatch
                                        | Some entryAddress when entryAddress.Equals address -> Match
                                        | Some _ -> NoMatch
                                        | None -> Unknown
                                    else cidrMatches parts[0] address
                                if addressResult <> Match || not portKind then addressResult
                                else
                                    match parts[1].Split(':') with
                                    | [| protocol; range |] ->
                                        let protocolResult = tcpProtocol protocol
                                        if protocolResult <> Match then protocolResult
                                        else portRangeMatches range port
                                    | _ -> Unknown
                    root.Elements(xn "entry") |> Seq.map entryMatch |> Seq.toList |> anyMatches


    let private portElementMatches (element: XElement) actualPort =
        if not (attributesAreAllowed (set [ "protocol"; "port" ]) element) then Unknown
        else
            match attr "protocol" element, attr "port" element with
            | Some protocol, Some range ->
                match transportMatches protocol with
                | NoMatch -> NoMatch
                | Unknown -> Unknown
                | Match when range = "" -> Unknown
                | Match -> portRangeMatches range actualPort
            | _ -> Unknown
    let private addressSelectorMatches ipsetXml packetAddress packetPort (element: XElement) =
        if not (attributesAreAllowed (set [ "address"; "ipset"; "mac"; "invert" ]) element) then Unknown
        else
            let selectors =
                [ "address"; "ipset"; "mac" ]
                |> List.choose (fun name -> attr name element |> Option.map (fun value -> name, value))
            let result =
                match selectors with
                | [ "address", value ] -> cidrMatches value packetAddress
                | [ "ipset", value ] -> ipSetMatches ipsetXml value packetAddress packetPort
                | _ -> Unknown
            match boolAttribute "invert" element with
            | Some invert -> invertMatch invert result
            | None -> Unknown

    let private destinationSelectorMatches ipsetXml (packet: Packet) (element: XElement) =
        if not (attributesAreAllowed (set [ "address"; "ipset"; "invert" ]) element) then Unknown
        else
            let selectors =
                [ "address"; "ipset" ]
                |> List.choose (fun name -> attr name element |> Option.map (fun value -> name, value))
            let result =
                match selectors with
                | [ "address", value ] -> cidrMatches value packet.Destination
                | [ "ipset", value ] -> ipSetMatches ipsetXml value packet.Destination packet.DestinationPort
                | _ -> Unknown
            match boolAttribute "invert" element with
            | Some invert -> invertMatch invert result
            | None -> Unknown

    let rec private serviceMatches (serviceXml: string -> string option) ipsetXml packet (seen: Set<string>) name =
        if Set.contains name seen then fail "Cyclic firewalld service include."
        FirewalldModel.token "service" 128 name |> ignore
        let service = serviceXml name |> Option.defaultWith (fun () -> fail ("Required firewalld service is missing: " + name))
        let root = parseXml "service" service
        if not (attributesAreAllowed (set [ "version" ]) root) then Unknown
        else
            let destinationResult =
                match root.Elements(xn "destination") |> Seq.toList with
                | [] -> Match
                | [ destination ] ->
                    if not (attributesAreAllowed (set [ "ipv4"; "ipv6" ]) destination) then Unknown
                    else
                        let selectors =
                            [ "ipv4"; "ipv6" ]
                            |> List.choose (fun key -> attr key destination |> Option.map (fun value -> key, value))
                        match selectors with
                        | [] -> Unknown
                        | values ->
                            values
                            |> List.map (fun (family, value) ->
                                let expected =
                                    if family = "ipv4" then System.Net.Sockets.AddressFamily.InterNetwork
                                    else System.Net.Sockets.AddressFamily.InterNetworkV6
                                if packet.Destination.AddressFamily <> expected then NoMatch
                                else cidrMatches value packet.Destination)
                            |> anyMatches
                | _ -> Unknown
            if destinationResult = NoMatch then NoMatch
            elif destinationResult = Unknown then Unknown
            else
                let selectors =
                    root.Elements()
                    |> Seq.choose (fun element ->
                        match element.Name.LocalName with
                        | "port" -> Some(portElementMatches element packet.DestinationPort)
                        | "source-port" -> Some(portElementMatches element packet.SourcePort)
                        | "protocol" when attributesAreAllowed (set [ "value" ]) element ->
                            attr "value" element
                            |> Option.map (fun value -> match tcpProtocol value with Match -> Unknown | result -> result)
                            |> Option.orElse (Some Unknown)
                        | "protocol" -> Some Unknown
                        | "include" when attributesAreAllowed (set [ "service" ]) element ->
                            Some(serviceMatches serviceXml ipsetXml packet (Set.add name seen) (required "service" element))
                        | "module" | "helper" | "short" | "description" | "destination" -> None
                        | _ -> Some Unknown)
                    |> Seq.toList
                if selectors.IsEmpty then Unknown
                else
                    let result = anyMatches selectors
                    if result = Match
                       && (List.contains Unknown selectors
                           || (root.Elements() |> Seq.exists (fun element -> element.Name = xn "module" || element.Name = xn "helper"))) then Unknown
                    else result

    let private selectorMatches serviceXml ipsetXml packet (element: XElement) =
        match element.Name.LocalName with
        | "source" -> addressSelectorMatches ipsetXml packet.Source packet.SourcePort element
        | "destination" -> destinationSelectorMatches ipsetXml packet element
        | "port" | "source-port" ->
            if element.Name = xn "port" then portElementMatches element packet.DestinationPort
            else portElementMatches element packet.SourcePort
        | "protocol" when attributesAreAllowed (set [ "value" ]) element ->
            attr "value" element |> Option.map tcpProtocol |> Option.defaultValue Unknown
        | "protocol" -> Unknown
        | "service" when attributesAreAllowed (set [ "name" ]) element ->
            serviceMatches serviceXml ipsetXml packet Set.empty (required "name" element)
        | "service" -> Unknown
        | "icmp-type" | "icmp-block" when attributesAreAllowed (set [ "name" ]) element -> NoMatch
        | "icmp-type" | "icmp-block" -> Unknown
        | _ -> Unknown

    let private forwardPortMatches (packet: Packet) (element: XElement) =
        if not (attributesAreAllowed (set [ "port"; "protocol"; "to-port"; "to-addr" ]) element) then Unknown
        else
            let protocolResult = attr "protocol" element |> Option.map tcpProtocol |> Option.defaultValue Unknown
            let portResult = attr "port" element |> Option.map (fun value -> portRangeMatches value packet.DestinationPort) |> Option.defaultValue Unknown
            match allMatches [ protocolResult; portResult ] with
            | NoMatch -> NoMatch
            | Unknown -> Unknown
            | Match ->
                match attr "to-port" element, attr "to-addr" element with
                | Some value, _ when portRangeMatches value 1 = Unknown -> Unknown
                | _, Some value when asAddress value |> Option.isNone -> Unknown
                | _ -> Match

    let private familyMatches family (packet: Packet) =
        match family with
        | None -> Match
        | Some "ipv4" when packet.Source.AddressFamily = System.Net.Sockets.AddressFamily.InterNetwork -> Match
        | Some "ipv6" when packet.Source.AddressFamily = System.Net.Sockets.AddressFamily.InterNetworkV6 -> Match
        | Some "ipv4" | Some "ipv6" -> NoMatch
        | Some _ -> Unknown

    let private richRuleResult serviceXml ipsetXml packet isInbound (rule: XElement) =
        match familyMatches (attr "family" rule) packet with
        | NoMatch -> NotApplicable
        | Unknown -> RuleUnknown
        | Match when not (attributesAreAllowed (set [ "family"; "priority" ]) rule) -> RuleUnknown
        | Match ->
            let priorityResult =
                match attr "priority" rule with
                | None -> Match
                | Some value ->
                    match Int32.TryParse value with
                    | true, priority when priority >= -32768 && priority <= 32767 -> Match
                    | _ -> Unknown
            if priorityResult = Unknown then RuleUnknown
            else
                let children = rule.Elements() |> Seq.toList
                let selectorChildren =
                    children
                    |> List.filter (fun element ->
                        List.contains element.Name.LocalName [ "source"; "destination"; "service"; "port"; "source-port"; "protocol"; "icmp-type" ])
                let selectors = selectorChildren |> List.map (selectorMatches serviceXml ipsetXml packet) |> allMatches
                match selectors with
                | NoMatch -> NotApplicable
                | Unknown -> RuleUnknown
                | Match ->
                    let known =
                        set [ "source"; "destination"; "service"; "port"; "source-port"; "protocol"; "icmp-type"
                              "limit"; "log"; "nflog"; "audit"; "accept"; "drop"; "reject"; "mark"; "forward-port"; "masquerade" ]
                    let allowedAttributes = function
                        | "source" -> set [ "address"; "ipset"; "mac"; "invert" ]
                        | "destination" -> set [ "address"; "ipset"; "invert" ]
                        | "service" -> set [ "name" ]
                        | "port" | "source-port" -> set [ "port"; "protocol" ]
                        | "protocol" -> set [ "value" ]
                        | "icmp-type" -> set [ "name" ]
                        | "forward-port" -> set [ "port"; "protocol"; "to-port"; "to-addr" ]
                        | "limit" -> set [ "value"; "burst" ]
                        | "log" -> set [ "prefix"; "level" ]
                        | "nflog" -> set [ "group"; "prefix"; "queue-size" ]
                        | "reject" -> set [ "type" ]
                        | "mark" -> set [ "set" ]
                        | _ -> Set.empty
                    let limits =
                        children
                        |> List.collect (fun child ->
                            (if child.Name = xn "limit" then [ child ] else [])
                            @ (child.Descendants(xn "limit") |> Seq.toList))
                    let nestedUnknown =
                        children
                        |> List.exists (fun child ->
                            child.Descendants()
                            |> Seq.exists (fun nested -> nested.Name <> xn "limit"))
                    let limitsValid =
                        limits
                        |> List.forall (fun limit ->
                            attributesAreAllowed (set [ "value"; "burst" ]) limit
                            && not limit.HasElements
                            && String.IsNullOrWhiteSpace limit.Value)
                    let attributesValid =
                        children
                        |> List.forall (fun child -> attributesAreAllowed (allowedAttributes child.Name.LocalName) child)
                    if children |> List.exists (fun element -> not (known.Contains element.Name.LocalName))
                       || nestedUnknown || not limitsValid || not attributesValid then RuleUnknown
                    elif children |> List.exists (fun element -> element.Name = xn "masquerade") then RuleUnknown
                    else
                        let forwards =
                            if isInbound then children |> List.filter (fun element -> element.Name = xn "forward-port")
                            else []
                        match forwards |> List.map (forwardPortMatches packet) |> anyMatches with
                        | Match -> RuleBlocks
                        | Unknown -> RuleUnknown
                        | NoMatch when children |> List.exists (fun element -> element.Name = xn "drop" || element.Name = xn "reject") -> RuleBlocks
                        | NoMatch when children |> List.exists (fun element -> element.Name = xn "mark") -> RuleUnknown
                        | NoMatch when children |> List.exists (fun element -> element.Name = xn "accept") ->
                            if not limits.IsEmpty then RuleUnknown else RuleAllows
                        | _ -> NotApplicable

    let private interfaceMatches (configured: string) (actual: string) =
        if configured = "+" then true
        elif configured.EndsWith("+", StringComparison.Ordinal) then
            configured.Length > 1 && actual.StartsWith(configured.Substring(0, configured.Length - 1), StringComparison.Ordinal)
        elif configured.Contains '+' then fail "Cannot resolve a non-suffix-plus firewalld interface selector."
        else configured = actual

    let private zoneSourceMatches (ipsetXml: string -> string option) (address: IPAddress) (port: int) (zone: XElement) =
        zone.Elements(xn "source")
        |> Seq.map (fun source -> addressSelectorMatches ipsetXml address port source)
        |> Seq.toList

    let private zonesBoundToSource ipsetXml address port (zones: Map<string, XElement>) =
        zones
        |> Map.toList
        |> List.choose (fun (name, zone) ->
            let results = zoneSourceMatches ipsetXml address port zone
            if List.contains Unknown results then
                fail "Cannot prove whether a firewalld source-bound zone matches the SSH peer."
            if List.contains Match results then Some name else None)

    let private zonesBoundToInterface interfaceName (zones: Map<string, XElement>) =
        zones
        |> Map.toList
        |> List.choose (fun (name, zone) ->
            if zone.Elements(xn "interface")
               |> Seq.exists (fun element ->
                   if not (attributesAreAllowed (set [ "name" ]) element) then
                       fail "A firewalld interface binding has unknown attributes."
                   interfaceMatches (required "name" element) interfaceName) then Some name else None)

    let private resolveZone (label: string) (defaultZone: string) (explicit: string list) (sourceBound: string list) =
        if explicit.Length > 1 || sourceBound.Length > 1 then
            fail ("SSH " + label + " matches multiple firewalld zones.")
        match explicit, sourceBound with
        | [ first ], [ second ] when first <> second -> fail ("SSH " + label + " interface/source zone assignment is ambiguous.")
        | [ first ], _ -> first
        | _, [ first ] -> first
        | _ -> defaultZone

    let private directAllows serviceXml ipsetXml packet (root: XElement) =
        root.Elements()
        |> Seq.choose (fun element ->
            match element.Name.LocalName with
            | "service" | "port" | "source-port" | "protocol" -> Some(selectorMatches serviceXml ipsetXml packet element)
            | _ -> None)
        |> Seq.toList
        |> anyMatches

    let private zoneDecision isInbound serviceXml ipsetXml packet (zone: XElement) =
        if not (attributesAreAllowed (set [ "version"; "target"; "ingress-priority"; "egress-priority" ]) zone) then
            fail "A zone has an unknown attribute that may affect the SSH path."
        for priorityName in [ "ingress-priority"; "egress-priority" ] do
            match attr priorityName zone with
            | None -> ()
            | Some value ->
                match Int32.TryParse value with
                | true, 0 -> ()
                | _ -> fail "A non-default zone priority may alter the SSH path."
        let known =
            set [ "short"; "description"; "interface"; "source"; "service"; "port"; "source-port"; "protocol"
                  "rule"; "forward-port"; "icmp-block"; "icmp-block-inversion"; "masquerade"; "forward" ]
        if zone.Elements() |> Seq.exists (fun element -> not (known.Contains element.Name.LocalName)) then
            fail "An unknown zone element may affect the SSH management path."
        let rules = zone.Elements(xn "rule") |> Seq.map (richRuleResult serviceXml ipsetXml packet isInbound) |> Seq.toList
        if List.contains RuleBlocks rules then fail "A matching firewalld zone rule blocks or redirects the SSH connection."
        if List.contains RuleUnknown rules then fail "Cannot prove that a firewalld zone rule leaves the SSH connection unchanged."
        let forwards =
            if isInbound then
                zone.Elements(xn "forward-port") |> Seq.map (forwardPortMatches packet) |> Seq.toList
            else []
        if List.contains Match forwards then fail "A firewalld forward-port can redirect the SSH management connection."
        if List.contains Unknown forwards then fail "Cannot prove that a firewalld forward-port is disjoint from SSH."
        let ruleAllows = List.contains RuleAllows rules
        let allowedDirectly = directAllows serviceXml ipsetXml packet zone = Match
        let target = attr "target" zone |> Option.defaultValue "default"
        if not (List.contains target [ "default"; "ACCEPT"; "DROP"; "REJECT"; "%%REJECT%%" ]) then
            fail "A zone has an unknown target."
        target = "ACCEPT" || allowedDirectly || ruleAllows,
        zone.Elements(xn "masquerade") |> Seq.isEmpty |> not

    let private policyMatches (expected: string) (policy: XElement) (side: string) =
        policy.Elements(xn side)
        |> Seq.exists (fun element ->
            if not (attributesAreAllowed (set [ "name" ]) element) then
                fail "A policy zone selector has unknown attributes."
            let name = required "name" element
            name = expected || (expected <> "HOST" && name = "ANY"))

    let private policyDecision isInbound serviceXml ipsetXml packet sourceZone destinationZone policies =
        let priorityOf (policy: XElement) =
            match attr "priority" policy with
            | Some value ->
                match Int32.TryParse value with
                | true, priority when priority <> 0 && priority >= -32768 && priority <= 32767 -> priority
                | _ -> fail "A policy has an invalid priority."
            | None -> -1
        let relevant =
            policies
            |> Map.toList
            |> List.choose (fun (name, xml) ->
                let policy = parseXml "policy" xml
                if policyMatches sourceZone policy "ingress-zone" && policyMatches destinationZone policy "egress-zone" then Some(name, policy)
                else None)
            |> List.choose (fun (name, policy) ->
                let priority = priorityOf policy
                if isInbound && priority > 0 then None else Some(name, policy, priority))
        let mutable allows = false
        for _, policy, priority in relevant do
            if not (attributesAreAllowed (set [ "version"; "target"; "priority" ]) policy) then
                fail "A policy has an unknown attribute that may affect SSH."
            let known =
                set [ "short"; "description"; "ingress-zone"; "egress-zone"; "service"; "port"; "source-port"; "protocol"
                      "rule"; "forward-port"; "masquerade"; "icmp-block"; "icmp-block-inversion"; "priority" ]
            if policy.Elements() |> Seq.exists (fun element -> not (known.Contains element.Name.LocalName)) then
                fail "An unknown policy element may affect the SSH management path."
            let rules = policy.Elements(xn "rule") |> Seq.map (richRuleResult serviceXml ipsetXml packet isInbound) |> Seq.toList
            if List.contains RuleBlocks rules then fail "A matching host policy blocks or redirects the SSH connection."
            if List.contains RuleUnknown rules then fail "Cannot prove that a host policy leaves the SSH connection unchanged."
            let forwards =
                if isInbound then policy.Elements(xn "forward-port") |> Seq.map (forwardPortMatches packet) |> Seq.toList
                else []
            if List.contains Match forwards then fail "A host policy forward-port can redirect the SSH connection."
            if List.contains Unknown forwards then fail "Cannot prove that a host policy forward-port is disjoint from SSH."
            let direct = directAllows serviceXml ipsetXml packet policy = Match
            let ruleAllows = List.contains RuleAllows rules
            let target = attr "target" policy |> Option.defaultValue "CONTINUE"
            let policyAllows = target = "ACCEPT" || direct || ruleAllows
            if target = "DROP" || target = "REJECT" then
                if not direct && not ruleAllows then fail "A matching host policy denies the SSH connection."
            elif target <> "ACCEPT" && target <> "CONTINUE" then fail "A host policy has an unknown target."
            if policyAllows && (not isInbound || priority < 0) then allows <- true
            if not isInbound && (policy.Elements(xn "masquerade") |> Seq.isEmpty |> not) then
                fail "A host policy may masquerade the SSH reply."
        allows


    let private validateSshState context defaultZone zones policies ipsetXml serviceXml =
        let peer, local = IPAddress.Parse context.Peer, IPAddress.Parse context.Local
        let inbound =
            { Source = peer; SourcePort = context.PeerPort
              Destination = local; DestinationPort = context.Port }
        let outbound =
            { Source = local; SourcePort = context.Port
              Destination = peer; DestinationPort = context.PeerPort }
        let parsedZones = zones |> Map.map (fun _ xml -> parseXml "zone" xml)
        let sourceZones = zonesBoundToSource ipsetXml inbound.Source inbound.SourcePort parsedZones
        let ingressZone = resolveZone "ingress" defaultZone (zonesBoundToInterface context.Interface parsedZones) sourceZones
        let replySourceZones = zonesBoundToSource ipsetXml outbound.Destination outbound.DestinationPort parsedZones
        let egressZone = resolveZone "reply" defaultZone (zonesBoundToInterface context.Interface parsedZones) replySourceZones
        let ingress =
            parsedZones |> Map.tryFind ingressZone |> Option.defaultWith (fun () -> fail ("SSH ingress zone is missing: " + ingressZone))
        parsedZones |> Map.tryFind egressZone |> Option.defaultWith (fun () -> fail ("SSH reply zone is missing: " + egressZone)) |> ignore
        let inboundAllowed, _ = zoneDecision true serviceXml ipsetXml inbound ingress
        let inboundPolicyAllowed = policyDecision true serviceXml ipsetXml inbound ingressZone "HOST" policies
        if not inboundAllowed && not inboundPolicyAllowed then
            fail ("Final zone " + ingressZone + " and its host policies do not allow current SSH port " + string context.Port + "/tcp; refusing mutation.")
        policyDecision false serviceXml ipsetXml outbound "HOST" egressZone policies |> ignore
        ingressZone, egressZone

    let validateSshGuardWithDefinitions context defaultZone zones policies ipsets services =
        validateSshState context defaultZone zones policies (fun name -> Map.tryFind name ipsets) (fun name -> Map.tryFind name services)
        |> ignore

    /// Pure guard over final permanent definitions. Unrelated source bindings and host policies are ignored only when disjoint.
    let validateSshGuard context defaultZone zones policies serviceXml =
        validateSshState context defaultZone zones policies (fun _ -> None) serviceXml |> ignore

    let rec private runtimeElementToXml (element: FirewalldModel.Element) : XElement =
        let result = XElement(xn element.Name)
        for KeyValue(name, value) in element.Attributes do result.SetAttributeValue(xn name, value)
        element.Text |> Option.iter (fun value -> result.Add(XText value))
        for child in element.Children do result.Add(runtimeElementToXml child)
        result

    let private richRuleGroups =
        set [ "source"; "destination"; "service"; "port"; "source-port"; "protocol"; "icmp-type"
              "limit"; "log"; "nflog"; "audit"; "accept"; "drop"; "reject"; "mark"; "forward-port"; "masquerade" ]

    let private tokenizeRichRule (text: string) =
        let tokens = ResizeArray<string>()
        let current = StringBuilder()
        let mutable quoted = false
        let mutable escaped = false
        let flush () =
            if current.Length > 0 then
                tokens.Add(current.ToString())
                current.Clear() |> ignore
        for character in text do
            if escaped then
                current.Append character |> ignore
                escaped <- false
            elif character = '\\' && quoted then escaped <- true
            elif character = '"' then quoted <- not quoted
            elif Char.IsWhiteSpace character && not quoted then flush ()
            else current.Append character |> ignore
        if quoted || escaped then fail "Malformed runtime firewalld rich rule."
        flush ()
        List.ofSeq tokens

    let private runtimeRichRule (text: string) =
        let root = XElement(xn "rule")
        let mutable current: XElement option = None
        for token in tokenizeRichRule text do
            if token = "rule" then ()
            elif token = "NOT"
                 && (current |> Option.exists (fun element -> element.Name = xn "source" || element.Name = xn "destination")) then
                match current with
                | Some element when element.Attribute(xn "invert") = null
                                    && (element.Attributes() |> Seq.isEmpty) ->
                    element.SetAttributeValue(xn "invert", "true")
                | _ -> fail "Malformed runtime rich-rule inversion."
            elif richRuleGroups.Contains token then
                let child = XElement(xn token)
                root.Add child
                current <- Some child
            else
                let separator = token.IndexOf('=')
                if separator > 0 then
                    let name, value = token.Substring(0, separator), token.Substring(separator + 1)
                    match current with
                    | Some element ->
                        if element.Attribute(xn name) <> null then fail "Duplicate attribute in runtime firewalld rich rule."
                        element.SetAttributeValue(xn name, value)
                    | None when name = "family" || name = "priority" ->
                        if root.Attribute(xn name) <> null then fail "Duplicate runtime rich-rule selector."
                        root.SetAttributeValue(xn name, value)
                    | None -> root.Add(XElement(xn "unsupported"))
                else
                    root.Add(XElement(xn token))
                    current <- None
        root

    let private runtimePortElement name value =
        let validated = FirewalldModel.port value
        let parts = validated.Split('/')
        XElement(xn name, XAttribute(xn "port", parts[0]), XAttribute(xn "protocol", parts[1]))

    let private runtimeSnapshotXml (snapshot: FirewalldRuntime.RuntimeSnapshot) =
        let root = XElement(xn snapshot.Kind)
        if snapshot.Target <> "" then root.SetAttributeValue(xn "target", snapshot.Target)
        if snapshot.Kind = "policy" then
            snapshot.Priority |> Option.iter (fun value -> root.SetAttributeValue(xn "priority", string value))
        if snapshot.Kind = "zone" then
            snapshot.IngressPriority |> Option.iter (fun value -> root.SetAttributeValue(xn "ingress-priority", string value))
            snapshot.EgressPriority |> Option.iter (fun value -> root.SetAttributeValue(xn "egress-priority", string value))
        let add name key values =
            for value in values do root.Add(XElement(xn name, XAttribute(xn key, value)))
        match snapshot.Kind with
        | "zone" ->
            add "interface" "name" snapshot.Interfaces
            for source in snapshot.Sources do root.Add(runtimeElementToXml source)
        | "policy" ->
            add "ingress-zone" "name" snapshot.Ingress
            add "egress-zone" "name" snapshot.Egress
        | _ -> fail "Unexpected runtime firewalld object kind."
        add "service" "name" snapshot.Services
        add "protocol" "value" snapshot.Protocols
        for port in snapshot.Ports do root.Add(runtimePortElement "port" port)
        for port in snapshot.SourcePorts do root.Add(runtimePortElement "source-port" port)
        for forwardPort in snapshot.ForwardPorts do root.Add(runtimeElementToXml forwardPort)
        if snapshot.Masquerade then root.Add(XElement(xn "masquerade"))
        if snapshot.Forward then root.Add(XElement(xn "forward"))
        for name in snapshot.IcmpBlocks do root.Add(XElement(xn "icmp-block", XAttribute(xn "name", name)))
        if snapshot.IcmpBlockInversion then root.Add(XElement(xn "icmp-block-inversion"))
        for rule in snapshot.RichRules do root.Add(runtimeRichRule rule)
        root.ToString(SaveOptions.DisableFormatting)


    let private requireKnownRuntimeSelectors kind (snapshot: FirewalldRuntime.RuntimeSnapshot) =
        let required, known =
            if kind = "zone" then
                set [ "interfaces"; "sources" ],
                set [ "target"; "ingress-priority"; "egress-priority"; "icmp-block-inversion"; "interfaces"; "sources"
                      "services"; "ports"; "protocols"; "forward"; "masquerade"; "forward-ports"; "source-ports"
                      "icmp-blocks"; "rich rules"; "short"; "description" ]
            else
                set [ "ingress-zones"; "egress-zones" ],
                set [ "priority"; "target"; "ingress-zones"; "egress-zones"; "services"; "ports"; "protocols"
                      "masquerade"; "forward-ports"; "source-ports"; "icmp-blocks"; "rich rules"; "short"; "description" ]
        if required |> Seq.exists (fun name -> Map.containsKey name snapshot.UnknownFields) then
            fail ("Cannot resolve runtime firewalld " + kind + " bindings for the SSH connection.")
        if snapshot.UnknownFields |> Map.exists (fun name _ -> not (Set.contains name known)) then
            fail ("Runtime firewalld " + kind + " has an unknown field that may affect SSH.")

    let private runtimeSnapshots (environment: HostEnvironment) kind =
        let names =
            FirewalldRuntime.listRuntime environment kind
            |> Option.defaultWith (fun () -> fail ("Cannot enumerate runtime firewalld " + kind + " objects."))
        names
        |> List.map (fun name ->
            FirewalldModel.token ("runtime " + kind) (if kind = "zone" then 17 else 128) name |> ignore
            let snapshot =
                FirewalldRuntime.inspectRuntime environment kind name
                |> Option.defaultWith (fun () -> fail ("Cannot inspect runtime firewalld " + kind + ": " + name))
            if snapshot.Kind <> kind || snapshot.Name <> name then fail "Runtime firewalld inspection returned a different object."
            requireKnownRuntimeSelectors kind snapshot
            name, snapshot)
        |> Map.ofList

    let private runtimeIpSetXml (environment: HostEnvironment) name =
        match FirewalldRuntime.inspectRuntime environment "ipset" name with
        | Some snapshot when snapshot.Kind = "ipset" && snapshot.Name = name
                            && snapshot.IpSetType.IsSome && snapshot.UnknownFields.IsEmpty ->
            let root = XElement(xn "ipset", XAttribute(xn "type", snapshot.IpSetType.Value))
            for KeyValue(key, value) in snapshot.IpSetOptions do
                match value with
                | Some text -> root.Add(XElement(xn "option", XAttribute(xn "name", key), XAttribute(xn "value", text)))
                | None -> fail ("Runtime ipset option is unknown: " + key)
            for entry in snapshot.IpSetEntries do root.Add(XElement(xn "entry", entry))
            Some(root.ToString(SaveOptions.DisableFormatting))
        | _ -> None

    let private checkRuntimeFilters kind names (snapshots: Map<string, FirewalldRuntime.RuntimeSnapshot>) =
        for name in names do
            let snapshot = snapshots |> Map.tryFind name |> Option.defaultWith (fun () -> fail ("Runtime firewalld " + kind + " is missing: " + name))
            let relevant =
                if kind = "zone" then
                    set [ "target"; "ingress-priority"; "egress-priority"; "services"; "ports"; "protocols"; "source-ports"; "forward-ports"; "rich rules"
                          "masquerade"; "forward"; "destination"; "destinations" ]
                else
                    set [ "target"; "priority"; "services"; "ports"; "protocols"; "source-ports"; "forward-ports"; "rich rules"; "masquerade" ]
            if relevant |> Seq.exists (fun field -> Map.containsKey field snapshot.UnknownFields) then
                fail ("Cannot prove that runtime firewalld " + kind + " " + name + " leaves SSH unchanged.")
            if snapshot.UnknownFields |> Map.exists (fun field values -> not (Set.contains field relevant) && not values.IsEmpty) then
                fail ("Runtime firewalld " + kind + " " + name + " has an unknown SSH-relevant field.")

    let private validateRuntimeBinding
        (environment: HostEnvironment)
        context
        runtimeDefaultZone
        finalDefaultZone
        runtimeZone
        runtimeInterfaceBound
        zones
        policies
        ipsets
        services
        =
        validateSshState context finalDefaultZone zones policies (fun name -> Map.tryFind name ipsets) (fun name -> Map.tryFind name services)
        |> ignore
        if runtimeInterfaceBound then
            if not (Map.containsKey runtimeZone zones) then
                fail "SSH runtime zone is absent from final permanent configuration; reconcile the runtime binding before applying."
            let runtimeBound =
                zones |> Map.map (fun name xml ->
                    let root = parseXml "zone" xml
                    root.Elements(xn "interface")
                    |> Seq.filter (fun element -> interfaceMatches (required "name" element) context.Interface)
                    |> Seq.toArray |> Array.iter (fun element -> element.Remove())
                    if name = runtimeZone then
                        root.Add(XElement(xn "interface", XAttribute(xn "name", context.Interface)))
                    root.ToString(SaveOptions.DisableFormatting))
            validateSshState context finalDefaultZone runtimeBound policies (fun name -> Map.tryFind name ipsets) (fun name -> Map.tryFind name services)
            |> ignore

        let zoneSnapshots = runtimeSnapshots environment "zone"
        let policySnapshots = runtimeSnapshots environment "policy"
        let runtimeZones = zoneSnapshots |> Map.map (fun _ snapshot -> runtimeSnapshotXml snapshot)
        let runtimePolicies = policySnapshots |> Map.map (fun _ snapshot -> runtimeSnapshotXml snapshot)
        let runtimeServices = fun name -> Map.tryFind name services
        let runtimeIngressZone, egressZone =
            validateSshState context runtimeDefaultZone runtimeZones runtimePolicies (runtimeIpSetXml environment) runtimeServices
        let runtimeParsedZones = runtimeZones |> Map.map (fun _ xml -> parseXml "zone" xml)
        let interfaceZones = zonesBoundToInterface context.Interface runtimeParsedZones
        match runtimeInterfaceBound, interfaceZones with
        | false, [] -> ()
        | true, [ name ] when name = runtimeZone -> ()
        | false, _ -> fail "Runtime interface selectors disagree with firewall-cmd's unbound observation."
        | true, _ -> fail "Runtime interface selectors disagree with firewall-cmd's zone observation."
        let selectedZones = [ runtimeIngressZone; egressZone ] |> List.distinct
        checkRuntimeFilters "zone" selectedZones zoneSnapshots
        let relevantPolicies =
            policySnapshots
            |> Map.toList
            |> List.choose (fun (name, snapshot) ->
                let policy = parseXml "policy" (runtimeSnapshotXml snapshot)
                if (policyMatches runtimeIngressZone policy "ingress-zone" && policyMatches "HOST" policy "egress-zone")
                   || (policyMatches "HOST" policy "ingress-zone" && policyMatches egressZone policy "egress-zone") then Some name
                else None)
        checkRuntimeFilters "policy" relevantPolicies policySnapshots

    let private diagnostic (text: string) =
        if isNull text then ""
        else
            text.Substring(0, min 2048 text.Length)
            |> String.map (fun c -> if Char.IsControl c then ' ' else c)

    let private mode644 = UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.GroupRead ||| UnixFileMode.OtherRead
    let private mode600 = UnixFileMode.UserRead ||| UnixFileMode.UserWrite
    let private mode700 = mode600 ||| UnixFileMode.UserExecute
    let private strictUtf8 = UTF8Encoding(false, true)
    let private journalDirectory = "/var/lib/keroosha-iac/firewalld"
    let private lockPath = "/run/lock/keroosha-firewalld-backend.lock"
    let private path environment logical = HostEnvironment.path environment logical
    let private category = function
        | "zone" -> "zones"
        | "policy" -> "policies"
        | "service" -> "services"
        | "ipset" -> "ipsets"
        | "icmptype" -> "icmptypes"
        | "helper" -> "helpers"
        | kind -> fail ("Unsupported firewalld definition kind: " + kind)
    let private objectPath prefix kind name = prefix + "/" + category kind + "/" + name + ".xml"

    let private checkedCommandResult executable arguments (result: CommandResult) =
        if result.ExitCode <> 0 then
            let detail = if String.IsNullOrWhiteSpace result.Stderr then result.Stdout else result.Stderr
            let commandLine = String.concat " " arguments
            fail ("firewalld command failed: " + executable + " " + commandLine + " (exit " + string result.ExitCode + "): " + diagnostic detail)
        result.Stdout.Trim()

    let private command (environment: HostEnvironment) executable arguments =
        environment.Run executable arguments None |> checkedCommandResult executable arguments

    let private runtimeZoneOfInterface (environment: HostEnvironment) (defaultZone: string) (iface: string) =
        let arguments = [ "--get-zone-of-interface=" + iface ]
        let result = environment.Run "firewall-cmd" arguments None
        let stdout, stderr = result.Stdout.Trim(), result.Stderr.Trim()
        let unbound =
            result.ExitCode = 2
            && ((stdout = "no zone" && (stderr = "" || stderr = "no zone"))
                || (stderr = "no zone" && stdout = ""))
        if unbound then defaultZone, false
        else
            let name = checkedCommandResult "firewall-cmd" arguments result
            FirewalldModel.token "runtime zone" 17 name, true

    let private firewall environment arguments = command environment "firewall-cmd" arguments

    let private regularPath environment logical =
        let physical = path environment logical
        let rec parents (item: string) =
            if item <> Path.GetPathRoot item then
                if File.GetAttributes(item).HasFlag FileAttributes.ReparsePoint then fail "Symlinks are not accepted for firewalld state paths."
                parents (Path.GetDirectoryName item)
        if File.Exists physical || Directory.Exists physical then parents physical
        else parents (Path.GetDirectoryName physical)
        physical

    let private readFile environment logical =
        let physical = path environment logical
        if File.Exists physical then
            regularPath environment logical |> ignore
            if File.GetAttributes(physical).HasFlag FileAttributes.Directory then fail "Expected a regular firewalld configuration file."
            let bytes = File.ReadAllBytes physical
            if bytes.Length >= 3 && bytes[0] = 0xEFuy && bytes[1] = 0xBBuy && bytes[2] = 0xBFuy then
                fail "Firewalld configuration files must use UTF-8 without a byte-order mark."
            try Some(strictUtf8.GetString bytes)
            with :? DecoderFallbackException -> fail "Firewalld configuration files must contain valid UTF-8."
        else
            if Directory.Exists physical then fail "Expected a regular firewalld configuration file."
            if not (isNull (FileInfo(physical).LinkTarget)) then fail "Dangling firewalld state symlink."
            None
    let private objectFileMode environment logical =
        let physical = regularPath environment logical
        if File.Exists physical then
            let owner = command environment "stat" [ "-c"; "%u:%g"; "--"; physical ]
            if owner <> "0:0" then fail "Firewalld object overrides must be owned by root:root."
            int (File.GetUnixFileMode physical)
        else 0o644

    let private effective environment kind name =
        match readFile environment (objectPath "/etc/firewalld" kind name) with
        | Some xml -> Some xml
        | None -> readFile environment (objectPath "/usr/lib/firewalld" kind name)

    let private inventory environment kind =
        [ "/usr/lib/firewalld"; "/etc/firewalld" ]
        |> List.fold (fun result prefix ->
            let directory = path environment (prefix + "/" + category kind)
            if not (Directory.Exists directory) then result
            else
                regularPath environment (prefix + "/" + category kind) |> ignore
                Directory.EnumerateFiles(directory, "*.xml")
                |> Seq.fold (fun state file ->
                    let name = Path.GetFileNameWithoutExtension file
                    FirewalldModel.token kind (if kind = "zone" then 17 else 128) name |> ignore
                    let logical = objectPath prefix kind name
                    match readFile environment logical with Some xml -> Map.add name xml state | None -> state) result) Map.empty
    let ensureNoSplitZones (environment: HostEnvironment) =
        for prefix in [ "/usr/lib/firewalld"; "/etc/firewalld" ] do
            let logical = prefix + "/zones"
            let directory = path environment logical
            if Directory.Exists directory then
                regularPath environment logical |> ignore
                for child in Directory.EnumerateDirectories directory do
                    let childLogical = logical + "/" + Path.GetFileName child
                    regularPath environment childLogical |> ignore
                    if Directory.EnumerateFileSystemEntries child |> Seq.isEmpty |> not then
                        fail "A populated split firewalld zone definition prevents proving the effective SSH policy; flatten it into the declared zone before mutation."

    let private rootOnly environment logical expectedMode =
        let physical = regularPath environment logical
        let info = command environment "stat" [ "-c"; "%u:%a"; "--"; physical ]
        if info <> "0:" + expectedMode then fail ("Firewalld journal must be root-owned with mode " + expectedMode + ".")

    let private journalPath (c: FirewalldModel.Configuration) = journalDirectory + "/" + c.Kind + "-" + c.Name + ".json"

    let private getString (node: JsonObject) (key: string) =
        match node[key] with
        | null -> fail ("Missing firewalld journal field " + key + ".")
        | value -> value.GetValue<string>()

    let private optionalString (node: JsonObject) (key: string) =
        if not (node.ContainsKey key) then fail ("Missing firewalld journal field " + key + ".")
        match node[key] with null -> None | value -> Some(value.GetValue<string>())

    let private loadJournal environment (c: FirewalldModel.Configuration) owner =
        let directory = path environment journalDirectory
        if not (Directory.Exists directory) then None
        else
            rootOnly environment journalDirectory "700"
            match readFile environment (journalPath c) with
            | None -> None
            | Some text ->
                rootOnly environment (journalPath c) "600"
                let journal = JsonNode.Parse(text).AsObject()
                let keys = journal |> Seq.map (fun pair -> pair.Key) |> Set.ofSeq
                let required = set [ "version"; "ownerId"; "baseline"; "managed"; "pending" ]
                let allowed = Set.union required (set [ "baselineMode"; "managedMode"; "deleteOnConfirm" ])
                if not (Set.isSubset required keys) || not (Set.isSubset keys allowed)
                   || journal["version"].GetValue<int>() <> 1
                   || getString journal "ownerId" <> owner then
                    fail "Firewalld object is owned by another resource or its journal is invalid."
                optionalString journal "baseline" |> ignore
                optionalString journal "managed" |> ignore
                Some journal

    let private saveJournal environment c (journal: JsonObject) =
        let parent = path environment "/var/lib/keroosha-iac"
        if not (Directory.Exists parent) then Directory.CreateDirectory(parent, mode700) |> ignore
        regularPath environment "/var/lib/keroosha-iac" |> ignore
        // Reject an attacker-writable parent before creating the private journal directory.
        let ownership = command environment "stat" [ "-c"; "%u:%a"; "--"; parent ]
        let parts = ownership.Split(':')
        if parts.Length <> 2 || parts[0] <> "0" || (Convert.ToInt32(parts[1], 8) &&& 0o022) <> 0 then
            fail "Firewalld journal parent must be root-owned and not group/world writable."
        let directory = path environment journalDirectory
        if not (Directory.Exists directory) then Directory.CreateDirectory(directory, mode700) |> ignore
        rootOnly environment journalDirectory "700"
        HostFiles.atomicWrite (path environment (journalPath c)) (Encoding.UTF8.GetBytes(journal.ToJsonString())) mode600

    let private setOptional (node: JsonObject) (key: string) (value: string option) =
        node[key] <- match value with None -> null | Some text -> JsonValue.Create text :> JsonNode

    let private newJournal owner baseline =
        let journal = JsonObject()
        journal["version"] <- JsonValue.Create 1
        journal["ownerId"] <- JsonValue.Create(owner: string)
        setOptional journal "baseline" baseline
        setOptional journal "managed" baseline
        journal["pending"] <- null
        journal

    let private writeOverride environment (c: FirewalldModel.Configuration) contents mode =
        let logical = objectPath "/etc/firewalld" c.Kind c.Name
        let parent = Path.GetDirectoryName(path environment logical)
        if not (Directory.Exists parent) then
            regularPath environment "/etc/firewalld" |> ignore
            Directory.CreateDirectory parent |> ignore
        let physical = regularPath environment logical
        match contents with
        | Some text -> HostFiles.atomicWrite physical (strictUtf8.GetBytes(text: string)) (enum<UnixFileMode> mode)
        | None ->
            if File.Exists physical then
                File.Delete physical
                HostFiles.syncDirectory (Path.GetDirectoryName physical)
    type private GuardInventory =
        { Zones: Map<string, string>
          Policies: Map<string, string>
          Services: Map<string, string>
          IpSets: Map<string, string>
          IcmpTypes: Map<string, string>
          Helpers: Map<string, string>
          DefaultZone: string }

    let private definitionFolder kind =
        match kind with
        | "zone" -> "zones"
        | "policy" -> "policies"
        | "service" -> "services"
        | "ipset" -> "ipsets"
        | "icmptype" -> "icmptypes"
        | "helper" -> "helpers"
        | _ -> fail ("Unsupported firewalld definition kind: " + kind)

    let private definitionPath prefix kind name =
        prefix + "/" + definitionFolder kind + "/" + name + ".xml"

    let private validateDefinitionName kind (name: string) =
        let maxLength, allowed, disallowDots =
            match kind with
            | "zone" -> 17, set [ '_'; '-'; '.' ], true
            | "policy" -> 18, set [ '_'; '-'; '.' ], true
            | "service" | "icmptype" -> 128, set [ '_'; '-' ], false
            | "ipset" -> 32, set [ '_'; '-'; ':'; '.' ], false
            | "helper" -> 128, set [ '-'; '.' ], false
            | _ -> fail ("Unsupported firewalld definition kind: " + kind)
        if String.IsNullOrEmpty name || name.Length > maxLength
           || not (Char.IsAsciiLetterOrDigit name[0])
           || not (name |> Seq.forall (fun character -> Char.IsAsciiLetterOrDigit character || Set.contains character allowed))
           || (disallowDots && name.Contains '.') then
            fail ("Invalid firewalld " + kind + " name.")
        name

    let private readDefinition environment prefix kind name =
        validateDefinitionName kind name |> ignore
        readFile environment (definitionPath prefix kind name)

    let private definitionInventory environment kind =
        if kind = "zone" then ensureNoSplitZones environment
        [ "/usr/lib/firewalld"; "/etc/firewalld" ]
        |> List.fold (fun result prefix ->
            let logicalDirectory = prefix + "/" + definitionFolder kind
            let directory = path environment logicalDirectory
            if not (Directory.Exists directory) then result
            else
                regularPath environment logicalDirectory |> ignore
                Directory.EnumerateFiles(directory, "*.xml")
                |> Seq.fold (fun state file ->
                    let name = Path.GetFileNameWithoutExtension file
                    validateDefinitionName kind name |> ignore
                    match readDefinition environment prefix kind name with
                    | Some xml -> Map.add name xml state
                    | None -> state) result)
            Map.empty

    let private configuredDefaultZone etcContents vendorContents =
        let parse (text: string option) =
            match text with
            | None -> None
            | Some contents ->
                let values =
                    contents.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
                    |> Array.choose (fun source ->
                        let line = source.Trim()
                        if line = "" || line.StartsWith("#", StringComparison.Ordinal) || line.StartsWith(";", StringComparison.Ordinal) then None
                        else
                            let separator = line.IndexOf('=')
                            if separator < 0 then
                                if line = "DefaultZone" then fail "Invalid DefaultZone setting in firewalld.conf."
                                None
                            elif line.Substring(0, separator).Trim() = "DefaultZone" then
                                Some(line.Substring(separator + 1).Trim())
                            else None)
                match values with
                | [||] -> None
                | [| value |] -> Some(FirewalldModel.token "default zone" 17 value)
                | _ -> fail "Duplicate DefaultZone settings in firewalld.conf."
        parse etcContents |> Option.orElse (parse vendorContents) |> Option.defaultValue "public"

    let private updateDefinition environment kind name proposed values =
        match proposed with
        | Some xml -> Map.add name xml values
        | None ->
            match readDefinition environment "/usr/lib/firewalld" kind name with
            | Some vendor -> Map.add name vendor values
            | None -> Map.remove name values

    let private finalInventory environment (c: FirewalldModel.Configuration) proposed =
        let zones = definitionInventory environment "zone"
        let policies = definitionInventory environment "policy"
        let services = definitionInventory environment "service"
        let ipsets = definitionInventory environment "ipset"
        let icmpTypes = definitionInventory environment "icmptype"
        let helpers = definitionInventory environment "helper"
        let zones = if c.Kind = "zone" then updateDefinition environment c.Kind c.Name proposed zones else zones
        let policies = if c.Kind = "policy" then updateDefinition environment c.Kind c.Name proposed policies else policies
        let services = if c.Kind = "service" then updateDefinition environment c.Kind c.Name proposed services else services
        let ipsets = if c.Kind = "ipset" then updateDefinition environment c.Kind c.Name proposed ipsets else ipsets
        let icmpTypes = if c.Kind = "icmptype" then updateDefinition environment c.Kind c.Name proposed icmpTypes else icmpTypes
        let helpers = if c.Kind = "helper" then updateDefinition environment c.Kind c.Name proposed helpers else helpers
        let etcConfig = readFile environment "/etc/firewalld/firewalld.conf"
        let vendorConfig = readFile environment "/usr/lib/firewalld/firewalld.conf"
        let settingsKey = if c.Kind = "settings" then FirewalldModel.settingKey c else ""
        let candidateConfig =
            if c.Kind = "settings" && settingsKey = "DefaultZone" then proposed
            else etcConfig
        { Zones = zones; Policies = policies; Services = services; IpSets = ipsets
          IcmpTypes = icmpTypes; Helpers = helpers
          DefaultZone = configuredDefaultZone candidateConfig vendorConfig }

    let guardMutation (environment: HostEnvironment) (c: FirewalldModel.Configuration) (proposed: string option) =
        let connection = Environment.GetEnvironmentVariable "SSH_CONNECTION"
        let fields = if isNull connection then [||] else connection.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
        if fields.Length <> 4 then fail "SSH_CONNECTION is required before any firewalld mutation."
        for index in [ 0; 2 ] do
            match IPAddress.TryParse fields[index] with true, _ -> () | _ -> fail "Invalid SSH_CONNECTION address."
        let route = command environment "ip" [ "-j"; "route"; "get"; fields[0]; "from"; fields[2] ]
        let context = parseSshContext connection route
        let runtimeDefaultZone = firewall environment [ "--get-default-zone" ] |> FirewalldModel.token "runtime default zone" 17
        let inventory = finalInventory environment c proposed
        let definitions =
            Map.ofList [ "zone", inventory.Zones; "policy", inventory.Policies; "service", inventory.Services
                         "ipset", inventory.IpSets; "helper", inventory.Helpers; "icmptype", inventory.IcmpTypes ]
        try FirewalldReferences.validate parseXml c.Kind c.Name inventory.DefaultZone definitions
        with :? InvalidOperationException as error -> fail error.Message
        let runtimeZone, runtimeInterfaceBound = runtimeZoneOfInterface environment runtimeDefaultZone context.Interface
        validateRuntimeBinding environment context runtimeDefaultZone inventory.DefaultZone runtimeZone runtimeInterfaceBound inventory.Zones inventory.Policies inventory.IpSets inventory.Services

    /// APT may start firewalld from its maintainer script, before any zone resource runs.
    /// Validate that first-start permanent configuration without writing an unowned zone.
    let validatePackageInstall (environment: HostEnvironment) =
        let connection = Environment.GetEnvironmentVariable "SSH_CONNECTION"
        let fields = if isNull connection then [||] else connection.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
        if fields.Length <> 4 then fail "Installing firewalld requires SSH_CONNECTION to guard package-triggered startup."
        for index in [ 0; 2 ] do
            match IPAddress.TryParse fields[index] with true, _ -> () | _ -> fail "Invalid SSH_CONNECTION address."
        let route = command environment "ip" [ "-j"; "route"; "get"; fields[0]; "from"; fields[2] ]
        let context = parseSshContext connection route
        let inventory =
            { Zones = definitionInventory environment "zone"
              Policies = definitionInventory environment "policy"
              Services = definitionInventory environment "service"
              IpSets = definitionInventory environment "ipset"
              IcmpTypes = definitionInventory environment "icmptype"
              Helpers = definitionInventory environment "helper"
              DefaultZone =
                configuredDefaultZone
                    (readFile environment "/etc/firewalld/firewalld.conf")
                    (readFile environment "/usr/lib/firewalld/firewalld.conf") }
        // Debian 13's package default permits SSH on 22, not the provider's configured port.
        let stockSsh = "<service><port port=\"22\" protocol=\"tcp\"/></service>"
        let services =
            if Map.containsKey "ssh" inventory.Services then inventory.Services
            else Map.add "ssh" stockSsh inventory.Services
        let zones =
            if Map.containsKey "public" inventory.Zones then inventory.Zones
            else Map.add "public" "<zone><port port=\"22\" protocol=\"tcp\"/></zone>" inventory.Zones
        try validateSshGuardWithDefinitions context inventory.DefaultZone zones inventory.Policies inventory.IpSets services
        with :? BackendError as error ->
            fail ("Refusing firewalld package startup before zone resources: " + error.Message
                  + " Pre-seed the permanent default/interface zone to permit the actual SSH server port before installing firewalld.")


    let private snapshot environment (c: FirewalldModel.Configuration) journal =
        let actual = effective environment c.Kind c.Name
        let overrideFile = readFile environment (objectPath "/etc/firewalld" c.Kind c.Name)
        let objectPending =
            journal
            |> Option.exists (fun (value: JsonObject) -> not (isNull value["pending"]))
        let pending = objectPending || (FirewalldLifecycle.pending environment |> Option.isSome)
        let managed =
            match journal with
            | Some value ->
                match value["pending"] with
                | :? JsonObject as transaction when transaction.ContainsKey "managedAfter" ->
                    optionalString transaction "managedAfter"
                | _ -> optionalString value "managed"
            | None -> None
        let owned = managed = overrideFile && journal.IsSome
        let matches =
            actual |> Option.exists (fun xml -> canonicalXml c.Kind xml = canonicalXml c.Kind (render c))
        let splitZonesSafe =
            try
                ensureNoSplitZones environment
                true
            with :? BackendError -> false
        let permanentInSync = owned && matches && splitZonesSafe
        let observation = FirewalldRuntime.observe environment c
        let runtimeObserved = observation.Observed
        let runtimeInSync = observation.InSync
        let result = JsonObject()
        result["exists"] <- JsonValue.Create actual.IsSome
        result["actual"] <- JsonValue.Create(defaultArg actual "")
        result["permanentInSync"] <- JsonValue.Create permanentInSync
        result["runtimeObserved"] <- JsonValue.Create runtimeObserved
        result["runtimeInSync"] <- JsonValue.Create runtimeInSync
        result["inSync"] <- JsonValue.Create(permanentInSync && runtimeObserved && runtimeInSync && not pending)
        result :> JsonNode

    let private activateRecovered (environment: HostEnvironment) (c: FirewalldModel.Configuration) =
        let arguments = [ "is-active"; "firewalld.service" ]
        let state = environment.Run "/usr/bin/systemctl" arguments None
        match state.ExitCode, state.Stdout.Trim() with
        | 0, "active" when c.Kind = "settings" ->
            command environment "/usr/bin/systemctl" [ "restart"; "firewalld.service" ] |> ignore
        | 0, "active" ->
            firewall environment [ "--check-config" ] |> ignore
            firewall environment [ "--reload" ] |> ignore
        | _ -> command environment "/usr/bin/systemctl" [ "restart"; "firewalld.service" ] |> ignore

    let private recover environment (c: FirewalldModel.Configuration) (journal: JsonObject) =
        let logical = objectPath "/etc/firewalld" c.Kind c.Name
        let write contents mode = writeOverride environment c contents mode
        let validate proposed = guardMutation environment c proposed
        try
            FirewalldLifecycle.recover environment c journal logical write validate (fun () -> activateRecovered environment c)
        with :? InvalidOperationException as error ->
            fail error.Message

    let private transact environment (c: FirewalldModel.Configuration) (journal: JsonObject) releaseOnRollback desired afterMode =
        if releaseOnRollback then
            match effective environment c.Kind c.Name with
            | Some baseline when not (FieldRuntime.safeAdoption c baseline) ->
                fail "Existing firewalld definition contains unrepresented baseline fields; refusing to replace it."
            | _ -> ()
        let logical = objectPath "/etc/firewalld" c.Kind c.Name
        let before = readFile environment logical
        let beforeMode = objectFileMode environment logical
        if releaseOnRollback && before.IsSome && not (List.contains beforeMode [ 0o600; 0o640; 0o644 ]) then
            fail "An adopted firewalld object override must be root-owned and non-executable mode 0600, 0640, or 0644."
        let managedBefore = optionalString journal "managed"
        let write contents mode = writeOverride environment c contents mode
        let validate proposed = guardMutation environment c proposed
        let activate () =
            firewall environment [ "--check-config" ] |> ignore
            if before <> desired then
                firewall environment [ "--reload" ] |> ignore
            else
                let observation = FirewalldRuntime.observe environment c
                if not observation.Observed || not observation.InSync then
                    firewall environment [ "--reload" ] |> ignore
        try
            FirewalldLifecycle.transact
                environment c journal releaseOnRollback logical before beforeMode desired afterMode
                managedBefore desired write validate activate
        with :? InvalidOperationException as error ->
            fail error.Message

    let private strictConfigPath = "/etc/firewalld/firewalld.conf"
    let private vendorStrictConfigPath = "/usr/lib/firewalld/firewalld.conf"
    let private settingsUtf8 = UTF8Encoding(false, true)

    type private SettingEntry =
        { Start: int
          ContentEnd: int
          End: int
          Value: string }

    type private SettingsOrigin =
        { EtcExisted: bool
          VendorContents: string option
          VendorMode: int }

    type private SettingsBaseline =
        { Exists: bool
          Contents: string option
          Value: string option
          Mode: int
          Origin: SettingsOrigin }

    let private readSettingsFile environment logical =
        let physical = path environment logical
        if File.Exists physical then
            regularPath environment logical |> ignore
            let contents =
                try settingsUtf8.GetString(File.ReadAllBytes physical)
                with :? DecoderFallbackException -> fail "firewalld.conf is not valid UTF-8."
            if contents.StartsWith("\uFEFF", StringComparison.Ordinal) then
                fail "firewalld.conf must not contain a UTF-8 byte-order mark."
            Some contents
        else
            if Directory.Exists physical then fail "Expected a regular firewalld configuration file."
            if not (isNull (FileInfo(physical).LinkTarget)) then fail "Dangling firewalld state symlink."
            None

    let private settingEntries (text: string) (key: string) =
        let result = ResizeArray<SettingEntry>()
        let mutable start = 0
        while start < text.Length do
            let mutable contentEnd = start
            while contentEnd < text.Length && text[contentEnd] <> '\r' && text[contentEnd] <> '\n' do
                contentEnd <- contentEnd + 1
            let finish =
                if contentEnd = text.Length then contentEnd
                elif text[contentEnd] = '\r' && contentEnd + 1 < text.Length && text[contentEnd + 1] = '\n' then contentEnd + 2
                else contentEnd + 1
            let line = text.Substring(start, contentEnd - start).Trim()
            if line <> "" && not (line.StartsWith("#", StringComparison.Ordinal)) && not (line.StartsWith(";", StringComparison.Ordinal)) then
                let separator = line.IndexOf('=')
                let lineKey = if separator < 0 then line else line.Substring(0, separator).Trim()
                if lineKey = key then
                    if separator < 0 || line.IndexOf('=', separator + 1) >= 0 then
                        fail ("Invalid " + key + " setting in firewalld.conf.")
                    let value = line.Substring(separator + 1).Trim()
                    if value = "" then fail ("Invalid " + key + " value in firewalld.conf.")
                    result.Add { Start = start; ContentEnd = contentEnd; End = finish; Value = value }
            start <- finish
        if result.Count > 1 then fail ("Duplicate " + key + " settings in firewalld.conf.")
        result |> Seq.toList

    let private settingValue (text: string) (key: string) =
        match settingEntries text key with
        | [] -> None
        | [ entry ] -> Some entry.Value
        | _ -> fail ("Duplicate " + key + " settings in firewalld.conf.")

    let private newlineOf (text: string) =
        let lf = text.IndexOf('\n')
        if lf >= 0 then
            if lf > 0 && text[lf - 1] = '\r' then "\r\n" else "\n"
        elif text.Contains('\r') then "\r"
        else "\n"

    let private setSettingValue (text: string) (key: string) (value: string option) =
        match settingEntries text key with
        | [ entry ] ->
            match value with
            | Some item ->
                text.Substring(0, entry.Start) + key + "=" + item + text.Substring(entry.ContentEnd)
            | None ->
                text.Remove(entry.Start, entry.End - entry.Start)
        | [] ->
            match value with
            | None -> text
            | Some item ->
                let newline = newlineOf text
                let separator =
                    if text = "" || text.EndsWith("\n", StringComparison.Ordinal) || text.EndsWith("\r", StringComparison.Ordinal) then ""
                    else newline
                text + separator + key + "=" + item + newline
        | _ -> fail ("Duplicate " + key + " settings in firewalld.conf.")

    let private settingsFileModeAt environment logical contents =
        match contents with
        | None -> 0o600
        | Some _ ->
            let physical = regularPath environment logical
            let owner = command environment "stat" [ "-c"; "%u:%g"; "--"; physical ]
            if owner <> "0:0" then fail "firewalld.conf must be owned by root:root."
            let mode = File.GetUnixFileMode physical |> int
            if mode < 0 || mode > 0o7777 then fail "firewalld.conf has a mode that cannot be preserved."
            mode

    let private settingsFileMode environment contents =
        settingsFileModeAt environment strictConfigPath contents

    let private writeSettingsFile environment (contents: string option) (mode: int) =
        if mode < 0 || mode > 0o7777 then fail "firewalld.conf has a mode that cannot be preserved."
        let physical = path environment strictConfigPath
        match contents with
        | Some value ->
            let parent = Path.GetDirectoryName physical
            if not (Directory.Exists parent) then
                regularPath environment "/etc/firewalld" |> ignore
                Directory.CreateDirectory parent |> ignore
            let physical = regularPath environment strictConfigPath
            if Directory.Exists physical || not (isNull (FileInfo(physical).LinkTarget)) then
                fail "firewalld.conf is not a regular file."
            HostFiles.atomicWrite physical (settingsUtf8.GetBytes value) (enum<UnixFileMode> mode)
        | None ->
            if Directory.Exists physical then fail "firewalld.conf is not a regular file."
            if not (isNull (FileInfo(physical).LinkTarget)) then fail "Dangling firewalld state symlink."
            if File.Exists physical then
                regularPath environment strictConfigPath |> ignore
                File.Delete physical
                HostFiles.syncDirectory (Path.GetDirectoryName physical)
    let private writeStrictConfig environment contents mode = writeSettingsFile environment contents mode

    let private settingDefaults =
        Map.ofList
            [ "DefaultZone", "public"
              "CleanupOnExit", "yes"
              "CleanupModulesOnExit", "no"
              "IPv6_rpfilter", "strict"
              "IndividualCalls", "no"
              "LogDenied", "off"
              "FirewallBackend", "nftables"
              "FlushAllOnReload", "yes"
              "ReloadPolicy", "INPUT:DROP,FORWARD:DROP,OUTPUT:DROP"
              "RFC3964_IPv4", "yes"
              "AllowZoneDrifting", "no"
              "NftablesFlowtable", "off"
              "NftablesCounters", "no"
              "NftablesTableOwner", "yes"
              "StrictForwardPorts", "no"
              "Lockdown", "no" ]
    let private booleanSettingKeys =
        set
            [ "CleanupOnExit"; "CleanupModulesOnExit"; "IndividualCalls"; "FlushAllOnReload"
              "RFC3964_IPv4"; "AllowZoneDrifting"; "NftablesCounters"; "NftablesTableOwner"
              "StrictForwardPorts"; "Lockdown" ]
    let private reloadPolicyActions = set [ "ACCEPT"; "REJECT"; "DROP" ]
    let private reloadPolicyDefaults = Map.ofList [ "INPUT", "DROP"; "FORWARD", "DROP"; "OUTPUT", "DROP" ]
    let private deprecatedSettings = set [ "MinimalMark"; "AutomaticHelpers"; "AllowZoneDrifting"; "Lockdown" ]
    let private nftablesSettings = set [ "NftablesFlowtable"; "NftablesTableOwner"; "NftablesCounters" ]
    let private observableSettings =
        set
            [ "DefaultZone"; "LogDenied"; "FirewallBackend"; "StrictForwardPorts"
              "NftablesFlowtable"; "NftablesTableOwner"; "NftablesCounters" ]
    let private dnatChains = [ "INPUT"; "FORWARD"; "OUTPUT" ]

    let private settingDefault key = Map.tryFind key settingDefaults

    let private effectiveSettingValue key etcContents vendorContents =
        let fileValue =
            match etcContents with
            | Some contents -> settingValue contents key
            | None -> vendorContents |> Option.bind (fun contents -> settingValue contents key)
        fileValue |> Option.orElseWith (fun () -> settingDefault key)

    let private normalizedBoolean (value: string) =
        match value.ToLowerInvariant() with
        | "yes" | "true" -> Some "yes"
        | "no" | "false" -> Some "no"
        | _ -> None

    let private normalizedReloadPolicy (value: string) =
        let actions = reloadPolicyActions
        let defaults = reloadPolicyDefaults
        let value = value.Trim()
        if actions.Contains(value.ToUpperInvariant()) then
            let action = value.ToUpperInvariant()
            Some([ "INPUT"; "FORWARD"; "OUTPUT" ] |> List.map (fun key -> key + ":" + action) |> String.concat ",")
        else
            let mutable parsed = defaults
            let mutable valid = true
            for part in value.Replace(';', ',').Split(',') do
                let part = part.Trim()
                if part <> "" then
                    let colon = part.IndexOf(':')
                    let equals = part.IndexOf('=')
                    let separator = if colon >= 0 then colon else equals
                    if separator <= 0 || part.IndexOfAny([| ':'; '=' |], separator + 1) >= 0 then
                        valid <- false
                    else
                        let key = part.Substring(0, separator).Trim().ToUpperInvariant()
                        let action = part.Substring(separator + 1).Trim().ToUpperInvariant()
                        if not (Map.containsKey key defaults) || not (actions.Contains action) then
                            valid <- false
                        else
                            parsed <- Map.add key action parsed
            if valid then
                Some([ "INPUT"; "FORWARD"; "OUTPUT" ] |> List.map (fun key -> key + ":" + Map.find key parsed) |> String.concat ",")
            else None

    let private settingValuesEqual key left right =
        match left, right with
        | None, None -> true
        | Some first, Some second ->
            let equal a b = String.Equals(a, b, StringComparison.Ordinal)
            if booleanSettingKeys.Contains key then normalizedBoolean first = normalizedBoolean second
            elif key = "IPv6_rpfilter" then
                let normalize (value: string) =
                    match value.ToLowerInvariant() with
                    | "yes" | "true" -> "strict"
                    | "no" | "false" -> "no"
                    | other -> other
                equal (normalize first) (normalize second)
            elif key = "LogDenied" || key = "FirewallBackend" then
                equal (first.ToLowerInvariant()) (second.ToLowerInvariant())
            elif key = "ReloadPolicy" then normalizedReloadPolicy first = normalizedReloadPolicy second
            elif key = "NftablesFlowtable" then
                let normalize (value: string) =
                    value.Split([| ' '; '\t'; '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
                    |> String.concat " "
                equal (normalize first) (normalize second)
            else equal first second
        | _ -> false

    let private encodeSettingsBaseline key (contents: string option) (mode: int) (origin: SettingsOrigin) =
        let baseline = JsonObject()
        baseline["version"] <- JsonValue.Create 3
        baseline["key"] <- JsonValue.Create(key: string)
        baseline["etcExists"] <- JsonValue.Create(contents.IsSome)
        setOptional baseline "etcContents" contents
        setOptional baseline "etcValue" (contents |> Option.bind (fun text -> settingValue text key))
        baseline["etcMode"] <- JsonValue.Create mode
        baseline["originEtcExists"] <- JsonValue.Create origin.EtcExisted
        setOptional baseline "originVendorContents" origin.VendorContents
        baseline["originVendorMode"] <- JsonValue.Create origin.VendorMode
        baseline.ToJsonString()

    let private parseSettingsBaseline key (text: string) =
        let baseline =
            try JsonNode.Parse(text).AsObject()
            with _ -> fail "Invalid firewalld settings ownership baseline."
        let keys = baseline |> Seq.map (fun pair -> pair.Key) |> Set.ofSeq
        let currentVersion = set [ "version"; "key"; "etcExists"; "etcContents"; "etcValue"; "etcMode"; "originEtcExists"; "originVendorContents"; "originVendorMode" ]
        let previousVersion = set [ "version"; "key"; "etcExists"; "etcContents"; "etcValue"; "etcMode" ]
        let legacyCompact = set [ "etcExists"; "etcStrictValue"; "etcMode" ]
        let legacyContents = set [ "etcExists"; "etcContents"; "vendorContents"; "etcMode" ]
        let result =
            if keys = currentVersion then
                if baseline["version"].GetValue<int>() <> 3 || getString baseline "key" <> key then
                    fail "Firewalld settings ownership baseline does not match its key."
                let exists = baseline["etcExists"].GetValue<bool>()
                let contents = optionalString baseline "etcContents"
                let value = optionalString baseline "etcValue"
                let vendorMode = baseline["originVendorMode"].GetValue<int>()
                if exists <> contents.IsSome
                   || (contents |> Option.bind (fun item -> settingValue item key)) <> value
                   || vendorMode < 0 || vendorMode > 0o7777 then
                    fail "Invalid firewalld settings ownership baseline."
                { Exists = exists
                  Contents = contents
                  Value = value
                  Mode = baseline["etcMode"].GetValue<int>()
                  Origin =
                    { EtcExisted = baseline["originEtcExists"].GetValue<bool>()
                      VendorContents = optionalString baseline "originVendorContents"
                      VendorMode = vendorMode } }
            elif keys = previousVersion then
                if baseline["version"].GetValue<int>() <> 2 || getString baseline "key" <> key then
                    fail "Firewalld settings ownership baseline does not match its key."
                let exists = baseline["etcExists"].GetValue<bool>()
                let contents = optionalString baseline "etcContents"
                let value = optionalString baseline "etcValue"
                if exists <> contents.IsSome
                   || (contents |> Option.bind (fun item -> settingValue item key)) <> value then
                    fail "Invalid firewalld settings ownership baseline."
                { Exists = exists
                  Contents = contents
                  Value = value
                  Mode = baseline["etcMode"].GetValue<int>()
                  Origin = { EtcExisted = exists; VendorContents = None; VendorMode = 0o600 } }
            elif key = "StrictForwardPorts" && keys = legacyCompact then
                let exists = baseline["etcExists"].GetValue<bool>()
                { Exists = exists
                  Contents = None
                  Value = optionalString baseline "etcStrictValue"
                  Mode = baseline["etcMode"].GetValue<int>()
                  Origin = { EtcExisted = exists; VendorContents = None; VendorMode = 0o600 } }
            elif key = "StrictForwardPorts" && keys = legacyContents then
                let exists = baseline["etcExists"].GetValue<bool>()
                let contents = optionalString baseline "etcContents"
                { Exists = exists
                  Contents = contents
                  Value = contents |> Option.bind (fun value -> settingValue value key)
                  Mode = baseline["etcMode"].GetValue<int>()
                  Origin =
                    { EtcExisted = exists
                      VendorContents = optionalString baseline "vendorContents"
                      VendorMode = 0o600 } }
            else fail "Invalid firewalld settings ownership baseline."
        if result.Mode < 0 || result.Mode > 0o7777
           || result.Origin.VendorMode < 0 || result.Origin.VendorMode > 0o7777 then
            fail "Invalid firewalld settings baseline mode."
        result

    let private settingsJournalFiles (environment: HostEnvironment) (c: FirewalldModel.Configuration) =
        let directory = path environment journalDirectory
        if not (Directory.Exists directory) then []
        else
            rootOnly environment journalDirectory "700"
            let currentName = Path.GetFileName(path environment (journalPath c))
            Directory.EnumerateFiles(directory, "settings-*.json")
            |> Seq.map Path.GetFileName
            |> Seq.filter (fun name -> name <> currentName)
            |> Seq.sort
            |> Seq.toList

    let private settingsOriginFromJournal
        (environment: HostEnvironment)
        (fileName: string)
        (fallbackVendorContents: string option)
        (fallbackVendorMode: int)
        =
        let logical = journalDirectory + "/" + fileName
        rootOnly environment logical "600"
        let journalText =
            readFile environment logical
            |> Option.defaultWith (fun () -> fail "A firewalld settings journal disappeared during ownership inspection.")
        let journal = JsonNode.Parse(journalText).AsObject()
        let baselineText = optionalString journal "baseline" |> Option.defaultWith (fun () -> fail "Missing firewalld settings ownership baseline.")
        let baseline = JsonNode.Parse(baselineText).AsObject()
        let hasOriginMetadata = baseline.ContainsKey "originEtcExists"
        let etcExisted =
            if hasOriginMetadata then baseline["originEtcExists"].GetValue<bool>()
            else baseline["etcExists"].GetValue<bool>()
        let vendorContents =
            if baseline.ContainsKey "originVendorContents" then optionalString baseline "originVendorContents"
            elif baseline.ContainsKey "vendorContents" then optionalString baseline "vendorContents"
            else fallbackVendorContents
        let vendorMode =
            if baseline.ContainsKey "originVendorMode" then baseline["originVendorMode"].GetValue<int>()
            else fallbackVendorMode
        if vendorMode < 0 || vendorMode > 0o7777 then fail "Invalid firewalld settings vendor baseline mode."
        { EtcExisted = etcExisted; VendorContents = vendorContents; VendorMode = vendorMode }, hasOriginMetadata

    let private settingsOriginForNewOwner
        (environment: HostEnvironment)
        (c: FirewalldModel.Configuration)
        (etcContents: string option)
        (vendorContents: string option)
        (vendorMode: int)
        =
        match settingsJournalFiles environment c with
        | [] -> { EtcExisted = etcContents.IsSome; VendorContents = vendorContents; VendorMode = vendorMode }
        | files ->
            let origins =
                files
                |> List.map (fun file -> settingsOriginFromJournal environment file vendorContents vendorMode)
            let existedValues = origins |> List.map (fun (origin, _) -> origin.EtcExisted) |> List.distinct
            if existedValues.Length <> 1 then fail "Firewalld settings journals disagree about the original override."
            let persisted = origins |> List.choose (fun (origin, hasMetadata) -> if hasMetadata then Some origin else None)
            let origin =
                match persisted with
                | first :: remaining ->
                    if remaining |> List.exists ((<>) first) then fail "Firewalld settings journals disagree about the vendor baseline."
                    first
                | [] ->
                    origins
                    |> List.tryFind (fun (value, _) -> value.VendorContents.IsSome)
                    |> Option.map fst
                    |> Option.defaultValue (fst (List.head origins))
            origin

    let private managedSettingValue key (contents: string option) =
        contents |> Option.bind (fun text -> settingValue text key)

    let private deprecatedSetting key = Set.contains key deprecatedSettings

    let private guardCurrentConfiguration (environment: HostEnvironment) =
        let connection = Environment.GetEnvironmentVariable "SSH_CONNECTION"
        let fields = if isNull connection then [||] else connection.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
        if fields.Length <> 4 then fail "SSH_CONNECTION is required before any firewalld mutation."
        for index in [ 0; 2 ] do
            match IPAddress.TryParse fields[index] with true, _ -> () | _ -> fail "Invalid SSH_CONNECTION address."
        let route = command environment "ip" [ "-j"; "route"; "get"; fields[0]; "from"; fields[2] ]
        let context = parseSshContext connection route
        let runtimeDefaultZone = firewall environment [ "--get-default-zone" ] |> FirewalldModel.token "runtime default zone" 17
        let zones, policies = definitionInventory environment "zone", definitionInventory environment "policy"
        let services, ipsets = definitionInventory environment "service", definitionInventory environment "ipset"
        let runtimeZone, runtimeInterfaceBound = runtimeZoneOfInterface environment runtimeDefaultZone context.Interface
        let defaultZone =
            configuredDefaultZone
                (readFile environment "/etc/firewalld/firewalld.conf")
                (readFile environment "/usr/lib/firewalld/firewalld.conf")
        validateRuntimeBinding environment context runtimeDefaultZone defaultZone runtimeZone runtimeInterfaceBound zones policies ipsets services

    type private NftRuntimeState =
        { Chains: Set<string>
          Rules: JsonElement list
          TableOwner: bool option
          Flowtable: string option }

    type private RuntimeFirewall =
        { Backend: string
          Nft: NftRuntimeState option
          Iptables: string option
          Iptables6: string option
          Ipv6Enabled: bool option }

    let private jsonProperty (name: string) (element: JsonElement) =
        if element.ValueKind <> JsonValueKind.Object then None
        else
            let mutable value = Unchecked.defaultof<JsonElement>
            if element.TryGetProperty(name, &value) then Some value else None

    let private jsonString name element =
        jsonProperty name element
        |> Option.bind (fun value ->
            if value.ValueKind = JsonValueKind.String then Some(value.GetString())
            else None)

    let private nftRuntimeState (environment: HostEnvironment) =
        try
            let result = environment.Run "nft" [ "-j"; "list"; "table"; "inet"; "firewalld" ] None
            if result.ExitCode <> 0 then None
            else
                use document = JsonDocument.Parse result.Stdout
                let mutable tablePresent = false
                let mutable tableOwner = None
                let mutable flowtable = None
                let mutable flowtableSeen = false
                let chains = ResizeArray<string>()
                let rules = ResizeArray<JsonElement>()
                for item in document.RootElement.GetProperty("nftables").EnumerateArray() do
                    match jsonProperty "table" item with
                    | Some table when jsonString "family" table = Some "inet" && jsonString "name" table = Some "firewalld" ->
                        tablePresent <- true
                        tableOwner <-
                            match jsonProperty "flags" table with
                            | Some flags when flags.ValueKind = JsonValueKind.Array ->
                                Some(flags.EnumerateArray() |> Seq.exists (fun flag -> flag.ValueKind = JsonValueKind.String && flag.GetString() = "owner"))
                            | Some _ -> None
                            | None -> Some false
                    | _ -> ()
                    match jsonProperty "chain" item with
                    | Some chain when jsonString "family" chain = Some "inet" && jsonString "table" chain = Some "firewalld" ->
                        jsonString "name" chain |> Option.iter chains.Add
                    | _ -> ()
                    match jsonProperty "flowtable" item with
                    | Some value when jsonString "family" value = Some "inet" && jsonString "table" value = Some "firewalld" ->
                        if jsonString "name" value = Some "fastpath" then
                            flowtableSeen <- true
                            flowtable <-
                                match jsonProperty "dev" value with
                                | Some devices when devices.ValueKind = JsonValueKind.Array
                                                     && (devices.EnumerateArray() |> Seq.forall (fun device -> device.ValueKind = JsonValueKind.String)) ->
                                    Some(devices.EnumerateArray() |> Seq.map _.GetString() |> String.concat " ")
                                | _ -> None
                    | _ -> ()
                    match jsonProperty "rule" item with
                    | Some rule when jsonString "family" rule = Some "inet" && jsonString "table" rule = Some "firewalld" ->
                        rules.Add(rule.Clone())
                    | _ -> ()
                if tablePresent then
                    Some
                        { Chains = Set.ofSeq chains
                          Rules = List.ofSeq rules
                          TableOwner = tableOwner
                          Flowtable = if flowtableSeen then flowtable else Some "off" }
                else None
        with _ -> None


    let private filterRulesFromSave (environment: HostEnvironment) executable =
        try
            let result = environment.Run executable [ "-t"; "filter" ] None
            if result.ExitCode <> 0 then None
            else
                let lines = result.Stdout.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
                if lines |> Array.contains "*filter" then Some result.Stdout else None
        with _ -> None

    let private iptablesFilter environment = filterRulesFromSave environment "iptables-save"
    let private ip6tablesFilter environment = filterRulesFromSave environment "ip6tables-save"

    let private dbusBoolean (environment: HostEnvironment) property =
        try
            match
                command environment "/usr/bin/busctl"
                    [ "--system"; "get-property"; "org.fedoraproject.FirewallD1"; "/org/fedoraproject/FirewallD1"
                      "org.fedoraproject.FirewallD1"; property ]
            with
            | "b true" -> Some true
            | "b false" -> Some false
            | _ -> None
        with _ -> None

    let private iptablesHasChain (rules: string) chain =
        rules.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
        |> Array.exists (fun line -> line.StartsWith(":" + chain + " ", StringComparison.Ordinal))

    let private iptablesBaseChains (rules: string) =
        [ "INPUT_POLICIES"; "FORWARD_POLICIES"; "OUTPUT_POLICIES" ]
        |> List.forall (iptablesHasChain rules)

    let private runtimeFirewall (environment: HostEnvironment) =
        let nft = nftRuntimeState environment
        let iptables = iptablesFilter environment |> Option.filter iptablesBaseChains
        match nft, iptables with
        | Some _, Some _ -> None
        | Some state, None ->
            Some
                { Backend = "nftables"
                  Nft = Some state
                  Iptables = None
                  Iptables6 = None
                  Ipv6Enabled = None }
        | None, Some rules ->
            match dbusBoolean environment "IPv4", dbusBoolean environment "IPv6" with
            | Some true, Some ipv6Enabled ->
                let iptables6 =
                    if ipv6Enabled then ip6tablesFilter environment |> Option.filter iptablesBaseChains
                    else None
                if ipv6Enabled && iptables6.IsNone then None
                else
                    Some
                        { Backend = "iptables"
                          Nft = None
                          Iptables = Some rules
                          Iptables6 = iptables6
                          Ipv6Enabled = Some ipv6Enabled }
            | _ -> None
        | None, None -> None

    let private nftRuleChain rule = jsonString "chain" rule

    let private nftExpressions rule =
        match jsonProperty "expr" rule with
        | Some expressions when expressions.ValueKind = JsonValueKind.Array ->
            Some(expressions.EnumerateArray() |> Seq.toList)
        | _ -> None

    let private nftStatusDnatMatch expression =
        jsonProperty "match" expression
        |> Option.exists (fun matched ->
            jsonString "op" matched = Some "in"
            && jsonString "right" matched = Some "dnat"
            && (jsonProperty "left" matched
                |> Option.bind (jsonProperty "ct")
                |> Option.bind (jsonString "key")) = Some "status")

    let private nftHasDnatMatch rule =
        nftExpressions rule |> Option.exists (List.exists nftStatusDnatMatch)

    let private validNftPort (value: JsonElement) =
        let number (item: JsonElement) =
            let mutable parsed = 0
            item.ValueKind = JsonValueKind.Number
            && item.TryGetInt32(&parsed)
            && parsed >= 1
            && parsed <= 65535
        match value.ValueKind with
        | JsonValueKind.Number -> number value
        | JsonValueKind.Object ->
            match jsonProperty "range" value with
            | Some range when range.ValueKind = JsonValueKind.Array ->
                let values = range.EnumerateArray() |> Seq.toArray
                values.Length = 2
                && number values[0]
                && number values[1]
                && values[0].GetInt32() <= values[1].GetInt32()
            | _ -> false
        | _ -> false

    let private nftOriginalPortMatch expression =
        jsonProperty "match" expression
        |> Option.exists (fun matched ->
            jsonString "op" matched = Some "=="
            && (jsonProperty "left" matched
                |> Option.bind (jsonProperty "ct")
                |> Option.exists (fun conntrack ->
                    jsonString "key" conntrack = Some "proto-dst"
                    && jsonString "dir" conntrack = Some "original"))
            && (jsonProperty "right" matched |> Option.exists validNftPort))

    let private nftAcceptExpression expression = jsonProperty "accept" expression |> Option.isSome
    let private nftCounterExpression expression = jsonProperty "counter" expression |> Option.isSome
    let private nftJumpExpression target expression =
        jsonProperty "jump" expression
        |> Option.exists (fun jump -> jsonString "target" jump = Some target)

    let private nftDnatJumpRule target rule =
        match nftExpressions rule with
        | Some [ matchExpression; jumpExpression ] ->
            nftStatusDnatMatch matchExpression && nftJumpExpression target jumpExpression
        | Some [ matchExpression; counterExpression; jumpExpression ] ->
            nftStatusDnatMatch matchExpression
            && nftCounterExpression counterExpression
            && nftJumpExpression target jumpExpression
        | _ -> false

    let private nftGenericDnatAccept rule =
        match nftExpressions rule with
        | Some [ matchExpression; acceptExpression ] ->
            nftStatusDnatMatch matchExpression && nftAcceptExpression acceptExpression
        | Some [ matchExpression; counterExpression; acceptExpression ] ->
            nftStatusDnatMatch matchExpression
            && nftCounterExpression counterExpression
            && nftAcceptExpression acceptExpression
        | _ -> false

    let private nftDnatPortAccept rule =
        match nftExpressions rule with
        | Some [ matchExpression; acceptExpression ] ->
            nftOriginalPortMatch matchExpression && nftAcceptExpression acceptExpression
        | Some [ matchExpression; counterExpression; acceptExpression ] ->
            nftOriginalPortMatch matchExpression
            && nftCounterExpression counterExpression
            && nftAcceptExpression acceptExpression
        | _ -> false

    let private nftStrictReject rule =
        let reject expression =
            jsonProperty "reject" expression
            |> Option.exists (fun value ->
                jsonString "type" value = Some "icmpx"
                && jsonString "expr" value = Some "admin-prohibited")
        match nftExpressions rule with
        | Some [ rejectExpression ] -> reject rejectExpression
        | Some [ counterExpression; rejectExpression ] ->
            nftCounterExpression counterExpression && reject rejectExpression
        | _ -> false

    let private nftStrictValue (state: NftRuntimeState) =
        let rulesInChain chain =
            state.Rules |> List.filter (fun rule -> nftRuleChain rule = Some chain)
        let dnatRules chain =
            rulesInChain ("filter_" + chain)
            |> List.filter nftHasDnatMatch
        let strictRules =
            dnatChains
            |> List.forall (fun chain ->
                let dnatChain = "filter_" + chain + "_dnat"
                let allowedAndReject = rulesInChain dnatChain
                state.Chains.Contains dnatChain
                && (match List.rev allowedAndReject with
                    | reject :: allowed -> nftStrictReject reject && List.forall nftDnatPortAccept allowed
                    | [] -> false)
                && (match dnatRules chain with
                    | [ rule ] -> nftDnatJumpRule dnatChain rule
                    | _ -> false))
        if strictRules then Some "yes"
        else
            let genericRules =
                dnatChains
                |> List.forall (fun chain ->
                    not (state.Chains.Contains("filter_" + chain + "_dnat"))
                    && (match dnatRules chain with
                        | [ rule ] -> nftGenericDnatAccept rule
                        | _ -> false))
            if genericRules then Some "no" else None

    let private iptablesPort (text: string) =
        let number (part: string) =
            match Int32.TryParse part with
            | true, value when value >= 1 && value <= 65535 -> Some value
            | _ -> None
        match text.Split(':') with
        | [| one |] -> number one |> Option.isSome
        | [| first; last |] ->
            match number first, number last with
            | Some firstValue, Some lastValue -> firstValue <= lastValue
            | _ -> false
        | _ -> false

    let private iptablesStrictValue (rules: string) =
        let lines = rules.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
        let chainRules chain =
            let prefix = "-A " + chain + " "
            lines |> Array.filter (fun line -> line.StartsWith(prefix, StringComparison.Ordinal))
        let dnatRules chain =
            chainRules chain |> Array.filter (fun line -> line.Contains("DNAT", StringComparison.Ordinal))
        let dnatPortAccept (line: string) =
            if not (line.Contains("--ctstate DNAT", StringComparison.Ordinal)
                    && line.Contains("--ctdir ORIGINAL", StringComparison.Ordinal)
                    && line.Contains("-j ACCEPT", StringComparison.Ordinal)) then false
            else
                let fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                match fields |> Array.tryFindIndex ((=) "--ctorigdstport") with
                | Some index when index + 1 < fields.Length -> iptablesPort fields[index + 1]
                | _ -> false
        let strictRules =
            dnatChains
            |> List.forall (fun chain ->
                let dnatChain = chain + "_dnat"
                let chainLines = chainRules dnatChain
                let baseDnat = dnatRules chain
                iptablesHasChain rules dnatChain
                && chainLines.Length > 0
                && chainLines[chainLines.Length - 1].StartsWith("-A " + dnatChain + " -j REJECT", StringComparison.Ordinal)
                && (chainLines |> Array.take (chainLines.Length - 1) |> Array.forall dnatPortAccept)
                && baseDnat.Length = 1
                && baseDnat[0].Contains("--ctstate DNAT", StringComparison.Ordinal)
                && baseDnat[0].Contains("-j " + dnatChain, StringComparison.Ordinal))
        if strictRules then Some "yes"
        else
            let genericRules =
                dnatChains
                |> List.forall (fun chain ->
                    let dnatChain = chain + "_dnat"
                    let baseDnat = dnatRules chain
                    not (iptablesHasChain rules dnatChain)
                    && baseDnat.Length = 1
                    && baseDnat[0].Contains("--ctstate RELATED,ESTABLISHED,DNAT", StringComparison.Ordinal)
                    && baseDnat[0].Contains("-j ACCEPT", StringComparison.Ordinal))
            if genericRules then Some "no" else None


    let private nftHasCounter rule =
        jsonProperty "expr" rule
        |> Option.exists (fun expressions ->
            expressions.EnumerateArray()
            |> Seq.exists (fun expression -> jsonProperty "counter" expression |> Option.isSome))

    let private nftCountersValue (state: NftRuntimeState) =
        let counts = state.Rules |> List.map nftHasCounter
        if counts.IsEmpty then None
        elif counts |> List.forall id then Some "yes"
        elif counts |> List.forall not then Some "no"
        else None

    let private runtimeSettingValue (environment: HostEnvironment) key =
        let tryCommand executable arguments =
            try Some(command environment executable arguments)
            with _ -> None
        match key with
        | "DefaultZone" -> tryCommand "firewall-cmd" [ "--get-default-zone" ]
        | "LogDenied" -> tryCommand "firewall-cmd" [ "--get-log-denied" ]
        | "FirewallBackend" ->
            runtimeFirewall environment |> Option.map _.Backend
        | "StrictForwardPorts" ->
            runtimeFirewall environment
            |> Option.bind (fun runtime ->
                match runtime.Backend, runtime.Nft, runtime.Iptables, runtime.Ipv6Enabled, runtime.Iptables6 with
                | "nftables", Some state, _, _, _ -> nftStrictValue state
                | "iptables", _, Some rules, Some false, _ -> iptablesStrictValue rules
                | "iptables", _, Some ipv4Rules, Some true, Some ipv6Rules ->
                    match iptablesStrictValue ipv4Rules, iptablesStrictValue ipv6Rules with
                    | Some ipv4, Some ipv6 when ipv4 = ipv6 -> Some ipv4
                    | _ -> None
                | _ -> None)
        | "NftablesFlowtable" ->
            runtimeFirewall environment
            |> Option.bind (fun runtime -> runtime.Nft |> Option.bind (fun state -> state.Flowtable))
        | "NftablesTableOwner" ->
            runtimeFirewall environment
            |> Option.bind (fun runtime ->
                runtime.Nft
                |> Option.bind (fun state ->
                    state.TableOwner |> Option.map (fun enabled -> if enabled then "yes" else "no")))
        | "NftablesCounters" ->
            runtimeFirewall environment
            |> Option.bind (fun runtime -> runtime.Nft |> Option.bind nftCountersValue)
        | _ -> None

    let private settingRuntimeObservable key = Set.contains key observableSettings

    let private daemonActive (environment: HostEnvironment) =
        try
            firewall environment [ "--state" ] |> ignore
            true
        with _ -> false

    let private validateSettingsCandidate (environment: HostEnvironment) (c: FirewalldModel.Configuration) key proposed =
        proposed |> Option.iter (fun contents -> settingValue contents key |> ignore)
        if nftablesSettings.Contains key then
            let vendorContents = readSettingsFile environment vendorStrictConfigPath
            match effectiveSettingValue "FirewallBackend" proposed vendorContents with
            | Some backend when String.Equals(backend, "iptables", StringComparison.OrdinalIgnoreCase) ->
                fail (key + " cannot be confirmed with FirewallBackend=iptables.")
            | _ -> ()
        guardMutation environment c proposed

    let private activateSettings (environment: HostEnvironment) key =
        firewall environment [ "--check-config" ] |> ignore
        if key = "FirewallBackend" then
            command environment "/usr/bin/systemctl" [ "restart"; "firewalld" ] |> ignore
        else
            firewall environment [ "--reload" ] |> ignore
        firewall environment [ "--state" ] |> ignore
        if settingRuntimeObservable key then
            let etcContents = readSettingsFile environment strictConfigPath
            let vendorContents = readSettingsFile environment vendorStrictConfigPath
            let expected = effectiveSettingValue key etcContents vendorContents
            match expected, runtimeSettingValue environment key with
            | Some expectedValue, Some actualValue when settingValuesEqual key (Some expectedValue) (Some actualValue) -> ()
            | Some _, Some _ -> fail ("firewalld did not load the requested " + key + " effect.")
            | _ -> fail ("Unable to observe the loaded " + key + " effect after activation.")
    let private validateSettingsConfirmation (environment: HostEnvironment) key (journal: JsonObject) =
        let pending =
            match journal["pending"] with
            | :? JsonObject as value -> value
            | _ -> fail "No firewalld settings transaction awaits confirmation."
        let after = optionalString pending "after"
        let current = readSettingsFile environment strictConfigPath
        if current <> after then fail "firewalld.conf changed before settings confirmation."
        if not (daemonActive environment) then fail "firewalld is not active at settings confirmation."
        let vendorContents = readSettingsFile environment vendorStrictConfigPath
        let expected = effectiveSettingValue key current vendorContents
        if settingRuntimeObservable key then
            match expected, runtimeSettingValue environment key with
            | Some expectedValue, Some actualValue when settingValuesEqual key (Some expectedValue) (Some actualValue) -> ()
            | Some _, Some _ -> fail ("Loaded " + key + " effect changed before fresh-connection confirmation.")
            | _ -> fail ("Unable to observe the loaded " + key + " effect at confirmation.")


    let private settingsSnapshot (environment: HostEnvironment) (owner: string) (c: FirewalldModel.Configuration) key desired =
        let etcContents = readSettingsFile environment strictConfigPath
        let vendorContents = readSettingsFile environment vendorStrictConfigPath
        let effective = etcContents |> Option.orElse vendorContents
        let permanentValue = effectiveSettingValue key etcContents vendorContents
        let runtimeValue = runtimeSettingValue environment key
        let journal = loadJournal environment c owner
        let pendingNode =
            journal
            |> Option.bind (fun value ->
                match value["pending"] with
                | :? JsonObject as pending -> Some pending
                | _ -> None)
        let pending = pendingNode.IsSome
        let managedContents =
            match pendingNode with
            | Some value when value.ContainsKey "managedAfter" -> optionalString value "managedAfter"
            | _ -> journal |> Option.bind (fun value -> optionalString value "managed")
        let managedValue = managedSettingValue key managedContents
        let managedMatches =
            journal.IsSome
            && settingValuesEqual key (etcContents |> Option.bind (fun text -> settingValue text key)) managedValue
        let active = daemonActive environment
        let permanentInSync = managedMatches && settingValuesEqual key permanentValue (Some desired)
        let runtimeInSync = runtimeValue |> Option.exists (fun actual -> settingValuesEqual key (Some actual) (Some desired))
        let runtimeObserved = runtimeValue.IsSome
        let activationReceipt = managedMatches && active
        let inSync =
            not pending
            && permanentInSync
            && active
            && (if settingRuntimeObservable key then runtimeInSync else activationReceipt)
        let result = JsonObject()
        result["exists"] <- JsonValue.Create effective.IsSome
        result["actual"] <- JsonValue.Create(runtimeValue |> Option.orElse permanentValue |> Option.defaultValue "")
        result["inSync"] <- JsonValue.Create inSync
        result["permanentActual"] <- match permanentValue with None -> null | Some value -> JsonValue.Create value :> JsonNode
        result["runtimeActual"] <- match runtimeValue with None -> null | Some value -> JsonValue.Create value :> JsonNode
        result["permanentInSync"] <- JsonValue.Create permanentInSync
        result["runtimeObserved"] <- JsonValue.Create runtimeObserved
        result["runtimeInSync"] <- JsonValue.Create runtimeInSync
        result["activationReceipt"] <- JsonValue.Create activationReceipt
        let runtimeLimit =
            if runtimeObserved then
                match key with
                | "DefaultZone" | "LogDenied" -> "firewall-cmd runtime value observed; packet behavior not probed"
                | "StrictForwardPorts" -> "firewalld-owned DNAT rules observed; packet behavior not probed"
                | "FirewallBackend" -> "active firewall backend table/chains observed"
                | "NftablesFlowtable" -> "inet firewalld flowtable metadata observed; packet behavior not probed"
                | "NftablesTableOwner" -> "inet firewalld table ownership flag observed"
                | "NftablesCounters" -> "inet firewalld rule counter metadata observed; packet behavior not probed"
                | _ -> "native runtime effect observed"
            elif deprecatedSetting key then "deprecated or ignored by firewalld 2.3.1"
            elif settingRuntimeObservable key then "native runtime getter unavailable; not confirmed"
            else "successful activation receipt only; packet behavior is not observed"
        result["runtimeLimit"] <- JsonValue.Create runtimeLimit
        result :> JsonNode



    let private strictSettings
        (environment: HostEnvironment)
        (operation: string)
        (owner: string)
        (transactionNonce: string option)
        (c: FirewalldModel.Configuration)
        =
        let key = FirewalldModel.settingKey c
        let desired =
            if c.Name = "strict-forward-ports" then
                c.StrictForwardPorts
                |> Option.map (fun value -> if value then "yes" else "no")
                |> Option.defaultWith (fun () -> fail "StrictForwardPorts setting value is required.")
            else
                c.SettingValue |> Option.defaultWith (fun () -> fail (key + " setting value is required."))
        let write = writeSettingsFile environment
        let validate = validateSettingsCandidate environment c key
        let activate = fun () -> activateSettings environment key
        let lockFile = path environment lockPath
        if operation = "read" then
            use _lock =
                if File.Exists lockFile then HostFiles.lockFile lockFile
                else { new IDisposable with member _.Dispose() = () }
            settingsSnapshot environment owner c key desired
        elif operation = "confirm" then
            use _lock = HostFiles.lockFile lockFile
            let journal = loadJournal environment c owner |> Option.defaultWith (fun () -> fail "No owned firewalld settings transaction awaits confirmation.")
            let nonce = transactionNonce |> Option.defaultWith (fun () -> fail "Firewalld confirmation requires transactionNonce.")
            validateSettingsConfirmation environment key journal
            FirewalldLifecycle.confirm environment c journal nonce
            JsonObject() :> JsonNode
        elif operation = "apply" || operation = "delete" then
            use _lock = HostFiles.lockFile lockFile
            let existingJournal = loadJournal environment c owner
            if operation = "delete" && existingJournal.IsNone then
                let unchanged = JsonObject()
                unchanged["unchanged"] <- JsonValue.Create true
                unchanged :> JsonNode
            else
                firewall environment [ "--state" ] |> ignore
                existingJournal
                |> Option.iter (fun journal -> FirewalldLifecycle.recover environment c journal strictConfigPath write validate activate)
                let recoveredJournal =
                    if existingJournal.IsSome then loadJournal environment c owner
                    else None
                let current = readSettingsFile environment strictConfigPath
                let currentMode = settingsFileMode environment current
                let vendorContents = readSettingsFile environment vendorStrictConfigPath
                let vendorMode = settingsFileModeAt environment vendorStrictConfigPath vendorContents
                let isNewOwner = recoveredJournal.IsNone
                let journal =
                    recoveredJournal
                    |> Option.defaultWith (fun () ->
                        let origin = settingsOriginForNewOwner environment c current vendorContents vendorMode
                        newJournal owner (Some(encodeSettingsBaseline key current currentMode origin)))
                if operation = "delete" && existingJournal.IsSome && isNewOwner then
                    let unchanged = JsonObject()
                    unchanged["unchanged"] <- JsonValue.Create true
                    unchanged :> JsonNode
                else
                    let currentValue = current |> Option.bind (fun text -> settingValue text key)
                    let managedContents = optionalString journal "managed"
                    let managedValue = managedSettingValue key managedContents
                    if not isNewOwner && not (settingValuesEqual key currentValue managedValue) then
                        fail ("Owned " + key + " setting changed independently; refusing to overwrite firewalld.conf.")
                    let baselineText = optionalString journal "baseline" |> Option.defaultWith (fun () -> fail "Missing firewalld settings ownership baseline.")
                    let baseline = parseSettingsBaseline key baselineText
                    if operation = "apply" then
                        let effectiveNow = effectiveSettingValue key current vendorContents
                        let candidate =
                            if settingValuesEqual key effectiveNow (Some desired) then current
                            else
                                let source = current |> Option.defaultValue (defaultArg vendorContents "")
                                Some(setSettingValue source key (Some desired))
                        let fileChanged = candidate <> current
                        let runtimeMatches =
                            runtimeSettingValue environment key
                            |> Option.exists (fun actual -> settingValuesEqual key (Some actual) (Some desired))
                        let needsActivation = fileChanged || (settingRuntimeObservable key && not runtimeMatches)
                        let needsTransaction = needsActivation || isNewOwner
                        if needsTransaction then
                            let afterMode =
                                match candidate, current, vendorContents with
                                | Some _, Some _, _ -> currentMode
                                | Some _, None, Some _ -> vendorMode
                                | Some _, None, None -> 0o600
                                | None, _, _ -> currentMode
                            let activation = if needsActivation then activate else fun () -> ()
                            let nonce =
                                FirewalldLifecycle.transact
                                    environment c journal isNewOwner strictConfigPath
                                    current currentMode candidate afterMode managedContents candidate
                                    write validate activation
                            let result = settingsSnapshot environment owner c key desired |> fun value -> value.AsObject()
                            result["transactionNonce"] <- JsonValue.Create nonce
                            result :> JsonNode
                        else
                            settingsSnapshot environment owner c key desired
                    else
                        let otherOwnersRemain = not (settingsJournalFiles environment c).IsEmpty
                        let transactDelete after afterMode managedAfter =
                            journal["deleteOnConfirm"] <- JsonValue.Create true
                            let changed = after <> current || (after.IsSome && afterMode <> currentMode)
                            let activation = if changed then activate else fun () -> ()
                            let nonce =
                                FirewalldLifecycle.transact
                                    environment c journal false strictConfigPath
                                    current currentMode after afterMode managedContents managedAfter
                                    write validate activation
                            let result = JsonObject()
                            result["transactionNonce"] <- JsonValue.Create nonce
                            result :> JsonNode
                        let restoredBeforeCleanup =
                            if baseline.Value = managedValue then current
                            else
                                let restoredText = setSettingValue (defaultArg current "") key baseline.Value
                                if baseline.Exists then Some restoredText
                                elif restoredText = "" then None
                                else Some restoredText
                        let removeOverride =
                            not baseline.Origin.EtcExisted
                            && not otherOwnersRemain
                            && (current = managedContents
                                || restoredBeforeCleanup = baseline.Origin.VendorContents
                                || restoredBeforeCleanup = vendorContents)
                        let restored = if removeOverride then None else restoredBeforeCleanup
                        let restoredMode =
                            match restored, current with
                            | Some _, Some _ -> currentMode
                            | Some _, None when baseline.Exists -> baseline.Mode
                            | Some _, None when vendorContents.IsSome -> vendorMode
                            | Some _, None -> 0o600
                            | None, _ -> currentMode
                        transactDelete restored restoredMode restored
        else fail "Unsupported firewalld operation."
    let private recoverPendingCore (environment: HostEnvironment) (bootRecovery: bool) =
        try
            FirewalldLifecycle.recoverPending environment (fun transaction journal ->
                let c = transaction.Configuration
                let journal =
                    match journal with
                    | Some value -> value
                    | None when transaction.ReleaseOnRollback || (transaction.Status = "confirmed" && transaction.DeleteOnConfirm) ->
                        let value = JsonObject()
                        value["ownerId"] <- JsonValue.Create(transaction.OwnerId)
                        value
                    | None -> fail "Firewalld recovery owner journal is missing."
                let logical = if c.Kind = "settings" then strictConfigPath else objectPath "/etc/firewalld" c.Kind c.Name
                let write contents mode =
                    if c.Kind = "settings" then writeStrictConfig environment contents mode
                    else writeOverride environment c contents mode
                let validate proposed = guardMutation environment c proposed
                let activate () =
                    if not bootRecovery then activateRecovered environment c
                FirewalldLifecycle.recoverPendingTransaction environment c journal logical write activate)
        with :? InvalidOperationException as error ->
            fail error.Message

    let recoverPending (environment: HostEnvironment) = recoverPendingCore environment false

    let recoverPendingBoot (environment: HostEnvironment) = recoverPendingCore environment true
    let handle (environment: HostEnvironment) (request: JsonElement) : JsonNode =
        let operation = request.GetProperty("operation").GetString()
        let keys = request.EnumerateObject() |> Seq.map (fun property -> property.Name) |> Set.ofSeq
        let requestFields = set [ "operation"; "ownerId"; "configuration" ]
        let expectedFields = if operation = "confirm" then Set.add "transactionNonce" requestFields else requestFields
        if keys <> expectedFields then fail "Invalid firewalld request fields."
        let mutable nonceElement = Unchecked.defaultof<JsonElement>
        let transactionNonce =
            if request.TryGetProperty("transactionNonce", &nonceElement) then
                if nonceElement.ValueKind <> JsonValueKind.String then fail "Invalid firewalld transaction nonce."
                let nonce = nonceElement.GetString()
                if String.IsNullOrWhiteSpace nonce then fail "Invalid firewalld transaction nonce."
                Some nonce
            else None
        let owner = request.GetProperty("ownerId").GetString()
        if String.IsNullOrWhiteSpace owner || owner |> Seq.exists Char.IsControl then fail "Invalid firewalld owner identity."
        let c =
            try FirewalldModel.parse (request.GetProperty("configuration").GetString())
            with _ -> fail "Invalid firewalld configuration."
        if c.Kind = "settings" then
            try
                let result = strictSettings environment operation owner transactionNonce c
                if operation = "read" then
                    let snapshot = result.AsObject()
                    if FirewalldLifecycle.pending environment |> Option.isSome then
                        snapshot["inSync"] <- JsonValue.Create false
                    try
                        ensureNoSplitZones environment
                        result
                    with :? BackendError ->
                        snapshot["inSync"] <- JsonValue.Create false
                        snapshot["permanentInSync"] <- JsonValue.Create false
                        snapshot["runtimeObserved"] <- JsonValue.Create false
                        snapshot["runtimeInSync"] <- JsonValue.Create false
                        snapshot["runtimeLimit"] <- JsonValue.Create("unknown: populated split zone definition")
                        result
                else result
            with :? InvalidOperationException as error -> fail error.Message
        else
            let lockFile = path environment lockPath
            if operation = "read" then
                use _lock =
                    if File.Exists lockFile then HostFiles.lockFile lockFile
                    else { new IDisposable with member _.Dispose() = () }
                snapshot environment c (loadJournal environment c owner)
            elif operation = "confirm" then
                use _lock = HostFiles.lockFile lockFile
                let journal = loadJournal environment c owner |> Option.defaultWith (fun () -> fail "No owned firewalld object awaits confirmation.")
                let deleting =
                    match journal["deleteOnConfirm"] with
                    | null -> false
                    | value -> value.GetValue<bool>()
                if deleting then firewall environment [ "--state" ] |> ignore
                else
                    let observed = snapshot environment c (Some journal)
                    if not (observed["permanentInSync"].GetValue<bool>())
                       || not (observed["runtimeObserved"].GetValue<bool>())
                       || not (observed["runtimeInSync"].GetValue<bool>()) then
                        fail "Firewalld object did not converge before fresh-connection confirmation."
                try
                    FirewalldLifecycle.confirm environment c journal (transactionNonce |> Option.get)
                with :? InvalidOperationException as error ->
                    fail error.Message
                JsonObject() :> JsonNode
            elif operation = "apply" || operation = "delete" then
                use _lock = HostFiles.lockFile lockFile
                let existingJournal = loadJournal environment c owner
                if operation = "delete" && existingJournal.IsNone then
                    let result = JsonObject()
                    result["unchanged"] <- JsonValue.Create true
                    result :> JsonNode
                else
                    firewall environment [ "--state" ] |> ignore
                    let logical = objectPath "/etc/firewalld" c.Kind c.Name
                    let initialJournal =
                        existingJournal
                        |> Option.defaultWith (fun () -> newJournal owner (readFile environment logical))
                    recover environment c initialJournal
                    let currentJournal = loadJournal environment c owner
                    if operation = "delete" && currentJournal.IsNone then
                        let result = JsonObject()
                        result["unchanged"] <- JsonValue.Create true
                        result :> JsonNode
                    else
                        let journal =
                            currentJournal
                            |> Option.defaultWith (fun () -> newJournal owner (readFile environment logical))
                        if operation = "apply" then
                            let desiredMode = objectFileMode environment logical
                            let nonce = transact environment c journal currentJournal.IsNone (Some(render c)) desiredMode
                            let result = snapshot environment c (Some journal)
                            if not (result["permanentInSync"].GetValue<bool>())
                               || not (result["runtimeObserved"].GetValue<bool>())
                               || not (result["runtimeInSync"].GetValue<bool>()) then
                                fail "Firewalld object did not converge after activation."
                            result["transactionNonce"] <- JsonValue.Create nonce
                            result
                        else
                            let current = readFile environment logical
                            if current <> optionalString journal "managed" then fail "Owned firewalld file changed independently; refusing Delete."
                            let currentMode = objectFileMode environment logical
                            if current.IsSome && journal.ContainsKey "managedMode" && journal["managedMode"].GetValue<int>() <> currentMode then
                                fail "Owned firewalld file mode changed independently; refusing Delete."
                            let baseline = optionalString journal "baseline"
                            let baselineMode =
                                if journal.ContainsKey "baselineMode" && not (isNull journal["baselineMode"]) then
                                    journal["baselineMode"].GetValue<int>()
                                elif baseline.IsNone then int mode644
                                else fail "Legacy firewalld journal lacks the original override mode; refusing Delete."
                            journal["deleteOnConfirm"] <- JsonValue.Create true
                            let nonce = transact environment c journal false baseline baselineMode
                            let result = JsonObject()
                            result["transactionNonce"] <- JsonValue.Create nonce
                            result :> JsonNode
            else fail "Unsupported firewalld operation."
