namespace Dorothy.HostHelper

open System
open System.Globalization
open System.IO
open System.Net
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open System.Security.Cryptography
open System.Xml
open System.Xml.Linq

module Firewalld =
    type BackendError(message: string) =
        inherit Exception(message)
    type PreStageRefusal(operation: string, ownerId: string, reason: string) =
        inherit BackendError(reason)
        member _.Operation = operation
        member _.OwnerId = ownerId
        member _.Reason = reason

    type private JournalOwnerConflict() =
        inherit BackendError("Firewalld object is owned by another resource or its journal is invalid.")

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
        { Source: IPAddress; SourcePort: int option
          Destination: IPAddress; DestinationPort: int option }
    type private RuleResult = NotApplicable | RuleAllows | RuleBlocks | RuleUnknown
    type private SshNetworkContext =
        { IngressInterfaces: string list option
          Layer2Interfaces: Set<string> option }
    type private ZoneCandidate = { Name: string; NdpMayBeNeeded: bool }
    type private NdpPolicyDecision = NdpUndecided | NdpAllowed | NdpBlocked
    let private unknownSshNetwork = { IngressInterfaces = None; Layer2Interfaces = None }
    type private SshGuardSnapshots =
        { CandidateZones: Map<string, string>
          CandidatePolicies: Map<string, string>
          RuntimeZones: Map<string, string>
          RuntimePolicies: Map<string, string> }

    let private observeSshNetwork (environment: HostEnvironment) (context: SshContext) =
        try
            let result = environment.Run "ip" [ "-j"; "link"; "show" ] None
            if result.ExitCode <> 0 then unknownSshNetwork
            else
                use document = JsonDocument.Parse result.Stdout
                if document.RootElement.ValueKind <> JsonValueKind.Array then unknownSshNetwork
                else
                    let mutable complete = true
                    let peerIsLoopback = IPAddress.IsLoopback(IPAddress.Parse context.Peer)
                    let offHostEgress = not peerIsLoopback && context.Interface <> "lo"
                    let interfaces, layer2 =
                        document.RootElement.EnumerateArray()
                        |> Seq.fold (fun (interfaces, layer2) link ->
                            let interfaceName = link.GetProperty("ifname").GetString()
                            FirewalldModel.token "SSH interface" 15 interfaceName |> ignore
                            let mutable linkType = Unchecked.defaultof<JsonElement>
                            let hasLinkType =
                                link.TryGetProperty("link_type", &linkType)
                                && linkType.ValueKind = JsonValueKind.String
                            let mutable operstate = Unchecked.defaultof<JsonElement>
                            let isDown =
                                link.TryGetProperty("operstate", &operstate)
                                && operstate.ValueKind = JsonValueKind.String
                                && operstate.GetString() = "DOWN"
                            let mutable flags = Unchecked.defaultof<JsonElement>
                            let hasLoopbackFlag =
                                link.TryGetProperty("flags", &flags)
                                && flags.ValueKind = JsonValueKind.Array
                                && (flags.EnumerateArray() |> Seq.exists (fun flag -> flag.GetString() = "LOOPBACK"))
                            let isLoopback =
                                interfaceName = "lo" || hasLoopbackFlag
                                || (hasLinkType && linkType.GetString() = "loopback")
                            if isDown || (offHostEgress && isLoopback) then interfaces, layer2
                            else
                                if not hasLinkType then complete <- false
                                if hasLinkType && linkType.GetString() = "ether" then
                                    Set.add interfaceName interfaces, Set.add interfaceName layer2
                                else Set.add interfaceName interfaces, layer2)
                            (Set.empty, Set.empty)
                    let routeInterfacePresent = Set.contains context.Interface interfaces
                    { IngressInterfaces = Some(Set.toList interfaces)
                      Layer2Interfaces = if complete && routeInterfacePresent then Some layer2 else None }
        with _ -> unknownSshNetwork

    let private isLayer2Interface network interfaceName =
        match network.Layer2Interfaces with
        | Some interfaces -> Set.contains interfaceName interfaces
        | None -> true

    let private asAddress (value: string) : IPAddress option =
        match IPAddress.TryParse value with true, parsed -> Some parsed | _ -> None

    let private contiguousMaskPrefix (mask: IPAddress) =
        let mutable prefix = 0
        let mutable sawZero = false
        let mutable valid = true
        for octet in mask.GetAddressBytes() do
            for bit in 0 .. 7 do
                let setBit = (octet &&& byte (1 <<< (7 - bit))) <> 0uy
                if setBit then
                    if sawZero then valid <- false
                    prefix <- prefix + 1
                else sawZero <- true
        if valid then Some prefix else None

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
                            | _ when network.AddressFamily = System.Net.Sockets.AddressFamily.InterNetwork && parts[1].Contains('.') ->
                                match asAddress parts[1] with
                                | Some mask when mask.AddressFamily = System.Net.Sockets.AddressFamily.InterNetwork ->
                                    contiguousMaskPrefix mask |> Option.defaultValue -1
                                | _ -> -1
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

    let private portRangeMatches (range: string) (value: int option) =
        let pieces = range.Split('-')
        let parse (text: string) =
            match Int32.TryParse text with
            | true, number when number >= 1 && number <= 65535 -> Some number
            | _ -> None
        if pieces.Length < 1 || pieces.Length > 2 then Unknown
        else
            match parse pieces[0], parse pieces[pieces.Length - 1], value with
            | Some first, Some last, Some actual when last >= first -> if actual >= first && actual <= last then Match else NoMatch
            | Some first, Some last, None when last >= first -> Unknown
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

    let private ipSetMatches (ipsetXml: string -> string option) (name: string) (address: IPAddress) (port: int option) =
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
        FirewalldModel.nativeReference "service" "service" name |> ignore
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
            let ownSelectors =
                root.Elements()
                |> Seq.choose (fun element ->
                    match element.Name.LocalName with
                    | "port" when attributesAreAllowed (set [ "protocol"; "port" ]) element && attr "port" element = Some "" ->
                        Some(attr "protocol" element |> Option.map tcpProtocol |> Option.defaultValue Unknown)
                    | "port" -> Some(portElementMatches element packet.DestinationPort)
                    | "source-port" -> Some(portElementMatches element packet.SourcePort)
                    | "protocol" when attributesAreAllowed (set [ "value" ]) element ->
                        attr "value" element |> Option.map tcpProtocol |> Option.defaultValue Unknown |> Some
                    | "protocol" -> Some Unknown
                    | "include" | "module" | "helper" | "short" | "description" | "destination" -> None
                    | _ -> Some Unknown)
                |> Seq.toList
            let ownResult =
                match destinationResult with
                | NoMatch -> NoMatch
                | Unknown -> Unknown
                | Match when ownSelectors.IsEmpty -> NoMatch
                | Match ->
                    let result = anyMatches ownSelectors
                    if result = Match && List.contains Unknown ownSelectors then Unknown else result
            let includedResults =
                root.Elements(xn "include")
                |> Seq.map (fun element ->
                    if not (attributesAreAllowed (set [ "service" ]) element) then Unknown
                    else serviceMatches serviceXml ipsetXml packet (Set.add name seen) (required "service" element))
                |> Seq.toList
            let result = anyMatches (ownResult :: includedResults)
            if result = Match
               && (List.contains Unknown ownSelectors
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
                | Some value, _ when portRangeMatches value (Some 1) = Unknown -> Unknown
                | _, Some value ->
                    match asAddress value with
                    | None -> Unknown
                    | Some address when address.AddressFamily <> packet.Destination.AddressFamily -> NoMatch
                    | Some _ -> Match
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
                | Unknown ->
                    if children |> List.exists (fun element ->
                        List.contains element.Name.LocalName [ "drop"; "reject"; "forward-port" ]) then RuleUnknown
                    else NotApplicable
                | Match ->
                    let known =
                        set [ "source"; "destination"; "service"; "port"; "source-port"; "protocol"; "icmp-type"; "icmp-block"
                              "tcp-mss-clamp"; "limit"; "log"; "nflog"; "audit"; "accept"; "drop"; "reject"; "mark"; "forward-port"; "masquerade" ]
                    let allowedAttributes = function
                        | "source" -> set [ "address"; "ipset"; "mac"; "invert" ]
                        | "destination" -> set [ "address"; "ipset"; "invert" ]
                        | "service" -> set [ "name" ]
                        | "port" | "source-port" -> set [ "port"; "protocol" ]
                        | "protocol" -> set [ "value" ]
                        | "icmp-type" | "icmp-block" -> set [ "name" ]
                        | "forward-port" -> set [ "port"; "protocol"; "to-port"; "to-addr" ]
                        | "tcp-mss-clamp" -> set [ "value" ]
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
                    else
                        let forwards =
                            if isInbound then children |> List.filter (fun element -> element.Name = xn "forward-port")
                            else []
                        match forwards |> List.map (forwardPortMatches packet) |> anyMatches with
                        | Match -> RuleBlocks
                        | Unknown -> RuleUnknown
                        | NoMatch when children |> List.exists (fun element -> element.Name = xn "drop" || element.Name = xn "reject") -> RuleBlocks
                        | NoMatch when children |> List.exists (fun element -> element.Name = xn "accept") ->
                            if not limits.IsEmpty then NotApplicable else RuleAllows
                        | _ -> NotApplicable

    let private richRulePreRoutingResult serviceXml ipsetXml packet (rule: XElement) =
        let children = rule.Elements() |> Seq.toList
        let hasPreRoutingAction =
            children |> List.exists (fun element -> element.Name = xn "forward-port" || element.Name = xn "mark")
        if not hasPreRoutingAction then NotApplicable
        else
            match familyMatches (attr "family" rule) packet with
            | NoMatch -> NotApplicable
            | Unknown -> RuleUnknown
            | Match when not (attributesAreAllowed (set [ "family"; "priority" ]) rule) -> RuleUnknown
            | Match ->
                let priorityValid =
                    match attr "priority" rule with
                    | None -> true
                    | Some value ->
                        match Int32.TryParse value with
                        | true, priority -> priority >= -32768 && priority <= 32767
                        | _ -> false
                if not priorityValid then RuleUnknown
                else
                    let selectors =
                        children
                        |> List.filter (fun element ->
                            List.contains element.Name.LocalName [ "source"; "destination"; "service"; "port"; "source-port"; "protocol"; "icmp-type" ])
                        |> List.map (selectorMatches serviceXml ipsetXml packet)
                        |> allMatches
                    match selectors with
                    | NoMatch -> NotApplicable
                    | Unknown -> RuleUnknown
                    | Match ->
                        if children |> List.exists (fun element ->
                            (element.Name = xn "mark" && not (attributesAreAllowed (set [ "set" ]) element))
                            || (element.Name = xn "forward-port" && not (attributesAreAllowed (set [ "port"; "protocol"; "to-port"; "to-addr" ]) element))) then
                            RuleUnknown
                        else
                            let forwards =
                                children |> List.filter (fun element -> element.Name = xn "forward-port")
                            match forwards |> List.map (forwardPortMatches packet) |> anyMatches with
                            | Match -> RuleBlocks
                            | Unknown -> RuleUnknown
                            | NoMatch when children |> List.exists (fun element -> element.Name = xn "mark") -> RuleUnknown
                            | _ -> NotApplicable
    let private interfaceMatches (configured: string) (actual: string) =
        if configured = "+" then true
        elif configured.EndsWith("+", StringComparison.Ordinal) then
            configured.Length > 1 && actual.StartsWith(configured.Substring(0, configured.Length - 1), StringComparison.Ordinal)
        elif configured.Contains '+' then fail "Cannot resolve a non-suffix-plus firewalld interface selector."
        else configured = actual

    let private zoneSourceMatches (ipsetXml: string -> string option) (address: IPAddress) (zone: XElement) =
        zone.Elements(xn "source")
        |> Seq.map (fun source -> addressSelectorMatches ipsetXml address None source)
        |> Seq.toList
        |> anyMatches

    let private zonesBoundToInterface interfaceName (zones: Map<string, XElement>) =
        zones
        |> Map.toList
        |> List.choose (fun (name, zone) ->
            if zone.Elements(xn "interface")
               |> Seq.exists (fun element ->
                   if not (attributesAreAllowed (set [ "name" ]) element) then
                       fail "A firewalld interface binding has unknown attributes."
                   interfaceMatches (required "name" element) interfaceName) then Some name else None)

    let private zonePriority priorityName (zone: XElement) =
        match attr priorityName zone with
        | None -> 0
        | Some value ->
            match Int32.TryParse value with
            | true, priority when priority >= -32768 && priority <= 32767 -> priority
            | _ -> fail "A firewalld zone has an invalid classification priority."

    let private selectZoneCandidates priorityName names (zones: Map<string, XElement>) ndpMayBeNeeded =
        let matching =
            names
            |> List.distinct
            |> List.choose (fun name -> Map.tryFind name zones |> Option.map (fun zone -> name, zone))
        match matching with
        | [] -> []
        | _ ->
            let selectedPriority = matching |> List.map (fun (_, zone) -> zonePriority priorityName zone) |> List.min
            matching
            |> List.choose (fun (name, zone) ->
                if zonePriority priorityName zone = selectedPriority then Some { Name = name; NdpMayBeNeeded = ndpMayBeNeeded }
                else None)

    let private mergeZoneCandidates candidates =
        candidates
        |> List.fold (fun merged candidate ->
            match Map.tryFind candidate.Name merged with
            | Some previous ->
                Map.add candidate.Name { previous with NdpMayBeNeeded = previous.NdpMayBeNeeded || candidate.NdpMayBeNeeded } merged
            | None -> Map.add candidate.Name candidate merged) Map.empty
        |> Map.toList
        |> List.map snd

    let private interfaceCandidatePaths network defaultZone priorityName (zones: Map<string, XElement>) =
        let candidatesFor iface =
            let ndpPossible = isLayer2Interface network iface
            let bound = zonesBoundToInterface iface zones
            match selectZoneCandidates priorityName bound zones ndpPossible with
            | [] -> [ { Name = defaultZone; NdpMayBeNeeded = ndpPossible } ]
            | selected -> selected
        match network.IngressInterfaces with
        | Some interfaces ->
            let paths = interfaces |> List.distinct |> List.map candidatesFor
            if paths.IsEmpty then [ [ { Name = defaultZone; NdpMayBeNeeded = true } ] ] else paths
        | None ->
            let configured =
                zones
                |> Map.toList
                |> List.collect (fun (_, zone) ->
                    zone.Elements(xn "interface")
                    |> Seq.map (required "name")
                    |> Seq.toList)
            let representatives =
                configured
                |> List.collect (fun selector ->
                    if selector = "+" then [ "x" ]
                    elif selector.EndsWith("+", StringComparison.Ordinal) then
                        let prefix = selector.Substring(0, selector.Length - 1)
                        [ prefix + "x"; prefix + "0" ] |> List.filter (fun value -> value.Length <= 15)
                    else [ selector ])
                |> List.distinct
            let paths = representatives |> List.map candidatesFor
            if List.contains "+" configured then paths
            else paths @ [ [ { Name = defaultZone; NdpMayBeNeeded = true } ] ]

    let private classifyZoneCandidates priorityName (zones: Map<string, XElement>) sourceStatuses interfaceCandidates =
        let definite = sourceStatuses |> List.choose (fun (name, result) -> if result = Match then Some name else None)
        let uncertain = sourceStatuses |> List.choose (fun (name, result) -> if result = Unknown then Some name else None)
        let sourceNdpMayBeNeeded = interfaceCandidates |> List.exists (fun candidate -> candidate.NdpMayBeNeeded)
        let known =
            (definite |> List.map (fun name -> name, 0, sourceNdpMayBeNeeded))
            @ (interfaceCandidates |> List.map (fun candidate -> candidate.Name, 1, candidate.NdpMayBeNeeded))
        let score (name, rank, _) = zonePriority priorityName zones[name], rank
        match known with
        | [] -> []
        | _ ->
            let best = known |> List.map score |> List.min
            let winners =
                known
                |> List.choose (fun (name, rank, ndp) ->
                    if score (name, rank, ndp) = best then Some { Name = name; NdpMayBeNeeded = ndp }
                    else None)
            let possibleSourceWinners =
                uncertain
                |> List.choose (fun name ->
                    let candidateScore = zonePriority priorityName zones[name], 0
                    if candidateScore <= best then Some { Name = name; NdpMayBeNeeded = sourceNdpMayBeNeeded }
                    else None)
            (winners @ possibleSourceWinners) |> mergeZoneCandidates

    let private zoneSourceStatuses ipsetXml address (zones: Map<string, XElement>) =
        zones
        |> Map.toList
        |> List.map (fun (name, zone) -> name, zoneSourceMatches ipsetXml address zone)

    let private ingressZoneCandidates network defaultZone ipsetXml peer (zones: Map<string, XElement>) =
        let sourceStatuses = zoneSourceStatuses ipsetXml peer zones
        interfaceCandidatePaths network defaultZone "ingress-priority" zones
        |> List.collect (classifyZoneCandidates "ingress-priority" zones sourceStatuses)
        |> mergeZoneCandidates

    let private egressZoneCandidates network defaultZone ipsetXml peer interfaceName (zones: Map<string, XElement>) =
        let sourceStatuses = zoneSourceStatuses ipsetXml peer zones
        interfaceCandidatePaths { network with IngressInterfaces = Some [ interfaceName ] } defaultZone "egress-priority" zones
        |> List.collect (classifyZoneCandidates "egress-priority" zones sourceStatuses)
        |> mergeZoneCandidates

    let private directAllows serviceXml ipsetXml packet (root: XElement) =
        root.Elements()
        |> Seq.choose (fun element ->
            match element.Name.LocalName with
            | "service" | "port" | "source-port" | "protocol" -> Some(selectorMatches serviceXml ipsetXml packet element)
            | _ -> None)
        |> Seq.toList
        |> anyMatches

    let private neighborSolicitationNames = set [ "neighbor-solicitation"; "neighbour-solicitation"; "nd-neighbor-solicit"; "nd-neighbor-solicitation" ]
    let private neighborAdvertisementNames = set [ "neighbor-advertisement"; "neighbour-advertisement"; "nd-neighbor-advert"; "nd-neighbor-advertisement" ]
    let private isNeighborDiscoveryType name =
        Set.contains name neighborSolicitationNames || Set.contains name neighborAdvertisementNames

    let private richRuleBlocksNeighborDiscovery packet ndpMayBeNeeded (rule: XElement) =
        if not ndpMayBeNeeded
           || packet.Source.AddressFamily <> System.Net.Sockets.AddressFamily.InterNetworkV6 then false
        else
            let children = rule.Elements() |> Seq.toList
            let namedIcmp =
                children
                |> List.choose (fun child ->
                    if child.Name = xn "icmp-type" || child.Name = xn "icmp-block" then attr "name" child
                    else None)
            let blocks =
                children
                |> List.exists (fun child ->
                    List.contains child.Name.LocalName [ "icmp-block"; "drop"; "reject"; "mark"; "forward-port" ])
            if not blocks || not (List.exists isNeighborDiscoveryType namedIcmp) then false
            else
                match familyMatches (attr "family" rule) packet with
                | NoMatch -> false
                | _ -> true

    let private zoneBlocksNeighborDiscovery packet ndpMayBeNeeded (zone: XElement) =
        if not ndpMayBeNeeded
           || packet.Source.AddressFamily <> System.Net.Sockets.AddressFamily.InterNetworkV6 then false
        else
            let blocks =
                zone.Elements(xn "icmp-block")
                |> Seq.map (fun element ->
                    if not (attributesAreAllowed (set [ "name" ]) element) then
                        fail "A zone ICMP block has unknown attributes."
                    required "name" element)
                |> Set.ofSeq
            let inversion =
                match zone.Elements(xn "icmp-block-inversion") |> Seq.toList with
                | [] -> false
                | [ element ] ->
                    if not (attributesAreAllowed Set.empty element) then fail "ICMP block inversion has unknown attributes."
                    true
                | _ -> fail "A zone has duplicate ICMP block inversion elements."
            let explicitlyBlocked = blocks |> Set.exists isNeighborDiscoveryType
            let inversionBlocksNdp =
                inversion
                && not
                    (Set.exists (fun name -> Set.contains name blocks) neighborSolicitationNames
                     && Set.exists (fun name -> Set.contains name blocks) neighborAdvertisementNames)
            explicitlyBlocked || inversionBlocksNdp

    let private zoneDecision isInbound ndpMayBeNeeded serviceXml ipsetXml packet (zone: XElement) =
        if not (attributesAreAllowed (set [ "version"; "target"; "ingress-priority"; "egress-priority" ]) zone) then
            fail "A zone has an unknown attribute that may affect the SSH path."
        zonePriority "ingress-priority" zone |> ignore
        zonePriority "egress-priority" zone |> ignore
        let known =
            set [ "short"; "description"; "interface"; "source"; "service"; "port"; "source-port"; "protocol"
                  "rule"; "forward-port"; "icmp-block"; "icmp-block-inversion"; "masquerade"; "forward" ]
        if zone.Elements() |> Seq.exists (fun element -> not (known.Contains element.Name.LocalName)) then
            fail "An unknown zone element may affect the SSH management path."
        if zoneBlocksNeighborDiscovery packet ndpMayBeNeeded zone
           || (zone.Elements(xn "rule") |> Seq.exists (richRuleBlocksNeighborDiscovery packet ndpMayBeNeeded)) then
            fail "A firewalld zone may block IPv6 neighbor discovery needed by the SSH path."
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
        let explicitAllowed = allowedDirectly || ruleAllows
        target = "ACCEPT" || explicitAllowed,
        zone.Elements(xn "masquerade") |> Seq.isEmpty |> not,
        explicitAllowed

    let private policyMatches (expected: string) (policy: XElement) (side: string) =
        policy.Elements(xn side)
        |> Seq.exists (fun element ->
            if not (attributesAreAllowed (set [ "name" ]) element) then
                fail "A policy zone selector has unknown attributes."
            let name = required "name" element
            name = expected || (expected <> "HOST" && name = "ANY"))

    let private policyBlocksNeighborDiscovery packet ndpMayBeNeeded (policy: XElement) =
        if not ndpMayBeNeeded
           || packet.Source.AddressFamily <> System.Net.Sockets.AddressFamily.InterNetworkV6 then false
        else
            let directBlocks =
                policy.Elements(xn "icmp-block")
                |> Seq.map (fun element ->
                    if not (attributesAreAllowed (set [ "name" ]) element) then
                        fail "A policy ICMP block has unknown attributes."
                    required "name" element)
                |> Seq.exists isNeighborDiscoveryType
            directBlocks
            || (policy.Elements(xn "rule") |> Seq.exists (richRuleBlocksNeighborDiscovery packet ndpMayBeNeeded))

    let private policyPriority (policy: XElement) =
        match attr "priority" policy with
        | Some value ->
            match Int32.TryParse value with
            | true, priority when priority <> 0 && priority >= -32768 && priority <= 32767 -> priority
            | _ -> fail "A policy has an invalid priority."
        | None -> -1

    let private policyDecision zoneExplicitlyAllows serviceXml ipsetXml packet sourceZone policies =
        let relevant =
            policies
            |> Map.toList
            |> List.choose (fun (name, xml) ->
                let policy = parseXml "policy" xml
                if policyMatches sourceZone policy "ingress-zone" && policyMatches "HOST" policy "egress-zone" then
                    Some(name, policy, policyPriority policy)
                else None)
            |> List.sortBy (fun (_, _, priority) -> priority)
        let mutable allows = false
        for _, policy, priority in relevant do
            let alreadyAcceptedByZone = zoneExplicitlyAllows && priority > 0
            if not alreadyAcceptedByZone then
                if not (attributesAreAllowed (set [ "version"; "target"; "priority" ]) policy) then
                    fail "A policy has an unknown attribute that may affect SSH."
                let known =
                    set [ "short"; "description"; "ingress-zone"; "egress-zone"; "service"; "port"; "source-port"; "protocol"
                          "rule"; "forward-port"; "masquerade"; "icmp-block"; "icmp-block-inversion"; "priority" ]
                if policy.Elements() |> Seq.exists (fun element -> not (known.Contains element.Name.LocalName)) then
                    fail "An unknown policy element may affect the SSH management path."
                let rules = policy.Elements(xn "rule") |> Seq.map (richRuleResult serviceXml ipsetXml packet true) |> Seq.toList
                if List.contains RuleBlocks rules then fail "A matching host policy blocks or redirects the SSH connection."
                if List.contains RuleUnknown rules then fail "Cannot prove that a host policy leaves the SSH connection unchanged."
                let forwards = policy.Elements(xn "forward-port") |> Seq.map (forwardPortMatches packet) |> Seq.toList
                if List.contains Match forwards then fail "A host policy forward-port can redirect the SSH connection."
                if List.contains Unknown forwards then fail "Cannot prove that a host policy forward-port is disjoint from SSH."
                let direct = directAllows serviceXml ipsetXml packet policy = Match
                let ruleAllows = List.contains RuleAllows rules
                let target = attr "target" policy |> Option.defaultValue "CONTINUE"
                let policyAllows = target = "ACCEPT" || direct || ruleAllows
                if target = "DROP" || target = "REJECT" then
                    if not direct && not ruleAllows then fail "A matching host policy denies the SSH connection."
                elif target <> "ACCEPT" && target <> "CONTINUE" then fail "A host policy has an unknown target."
                if policyAllows then allows <- true
        allows

    let private richRuleAllowsNeighborDiscovery packet ndpMayBeNeeded (rule: XElement) =
        if not ndpMayBeNeeded
           || packet.Source.AddressFamily <> System.Net.Sockets.AddressFamily.InterNetworkV6 then false
        else
            let children = rule.Elements() |> Seq.toList
            let namedIcmp =
                children
                |> List.exists (fun child ->
                    (child.Name = xn "icmp-type" || child.Name = xn "icmp-block")
                    && (attr "name" child |> Option.exists isNeighborDiscoveryType))
            let onlyIcmpSelector =
                children
                |> List.forall (fun child -> child.Name = xn "icmp-type" || child.Name = xn "accept")
            let limited = children |> List.exists (fun child -> child.Descendants(xn "limit") |> Seq.isEmpty |> not)
            let accepts = children |> List.exists (fun child -> child.Name = xn "accept")
            namedIcmp && onlyIcmpSelector && accepts && not limited
            && familyMatches (attr "family" rule) packet = Match

    let private policyNdpDecision packet ndpMayBeNeeded ingressZone egressZone policies =
        if not ndpMayBeNeeded || packet.Source.AddressFamily <> System.Net.Sockets.AddressFamily.InterNetworkV6 then
            NdpUndecided
        else
            let relevant =
                policies
                |> Map.toList
                |> List.choose (fun (_, xml) ->
                    let policy = parseXml "policy" xml
                    if policyMatches ingressZone policy "ingress-zone" && policyMatches egressZone policy "egress-zone" then
                        Some(policy, policyPriority policy)
                    else None)
                |> List.sortBy snd
            let mutable decision = NdpUndecided
            for policy, _ in relevant do
                if decision = NdpUndecided then
                    if not (attributesAreAllowed (set [ "version"; "target"; "priority" ]) policy) then
                        fail "A policy has an unknown attribute that may affect IPv6 neighbor discovery."
                    if policyBlocksNeighborDiscovery packet ndpMayBeNeeded policy then
                        decision <- NdpBlocked
                    else
                        let target = attr "target" policy |> Option.defaultValue "CONTINUE"
                        let allows =
                            target = "ACCEPT"
                            || (policy.Elements(xn "rule")
                                |> Seq.exists (richRuleAllowsNeighborDiscovery packet ndpMayBeNeeded))
                        if allows then decision <- NdpAllowed
                        elif target = "DROP" || target = "REJECT" then decision <- NdpBlocked
                        elif target <> "CONTINUE" then
                            fail "A host policy has an unknown IPv6 neighbor-discovery target."
            decision


    let private policyHasPreroutingEgress packet ipsetXml (zones: Map<string, XElement>) (policy: XElement) =
        let ingressIsAny = policyMatches "ANY" policy "ingress-zone"
        policy.Elements(xn "egress-zone")
        |> Seq.exists (fun element ->
            if not (attributesAreAllowed (set [ "name" ]) element) then
                fail "A policy egress selector has unknown attributes."
            let name = required "name" element
            if name = "ANY" then true
            elif name = "HOST" then ingressIsAny
            else
                let zone =
                    zones |> Map.tryFind name |> Option.defaultWith (fun () -> fail ("Policy egress zone is missing: " + name))
                if zone.Elements(xn "interface") |> Seq.isEmpty |> not then false
                elif zone.Elements(xn "source") |> Seq.isEmpty then true
                else zoneSourceMatches ipsetXml packet.Destination zone <> NoMatch)

    let private policyPreRoutingDecision serviceXml ipsetXml packet sourceZone zones policies =
        let relevant =
            policies
            |> Map.toList
            |> List.choose (fun (name, xml) ->
                let policy = parseXml "policy" xml
                if policyMatches sourceZone policy "ingress-zone"
                   && policyHasPreroutingEgress packet ipsetXml zones policy then
                    Some(name, policy, policyPriority policy)
                else None)
            |> List.sortBy (fun (_, _, priority) -> priority)
        for _, policy, _ in relevant do
            if not (attributesAreAllowed (set [ "version"; "target"; "priority" ]) policy) then
                fail "A policy has an unknown attribute that may affect SSH."
            let known =
                set [ "short"; "description"; "ingress-zone"; "egress-zone"; "service"; "port"; "source-port"; "protocol"
                      "rule"; "forward-port"; "masquerade"; "icmp-block"; "icmp-block-inversion"; "priority" ]
            if policy.Elements() |> Seq.exists (fun element -> not (known.Contains element.Name.LocalName)) then
                fail "An unknown policy element may affect the SSH management path."
            let forwards = policy.Elements(xn "forward-port") |> Seq.map (forwardPortMatches packet) |> Seq.toList
            if List.contains Match forwards then fail "A policy forward-port can redirect management SSH in PREROUTING."
            if List.contains Unknown forwards then fail "Cannot prove that a PREROUTING policy forward-port is disjoint from management SSH."
            let rules = policy.Elements(xn "rule") |> Seq.map (richRulePreRoutingResult serviceXml ipsetXml packet) |> Seq.toList
            if List.contains RuleBlocks rules then fail "A matching policy DNAT can redirect the SSH connection."
            if List.contains RuleUnknown rules then fail "Cannot prove that a policy PREROUTING mark or DNAT leaves SSH unchanged."
    let private validateSshState network context defaultZone zones policies ipsetXml serviceXml =
        let peer, local = IPAddress.Parse context.Peer, IPAddress.Parse context.Local
        let inbound =
            { Source = peer; SourcePort = None
              Destination = local; DestinationPort = Some context.Port }
        let outbound =
            { Source = local; SourcePort = Some context.Port
              Destination = peer; DestinationPort = None }
        let parsedZones = zones |> Map.map (fun _ xml -> parseXml "zone" xml)
        let ingressCandidates = ingressZoneCandidates network defaultZone ipsetXml inbound.Source parsedZones
        let egressCandidates = egressZoneCandidates network defaultZone ipsetXml outbound.Destination context.Interface parsedZones
        for candidate in ingressCandidates do
            let ingress =
                parsedZones |> Map.tryFind candidate.Name |> Option.defaultWith (fun () -> fail ("SSH ingress zone is missing: " + candidate.Name))
            let ndpPolicy = policyNdpDecision inbound candidate.NdpMayBeNeeded candidate.Name "HOST" policies
            if ndpPolicy = NdpBlocked then
                fail "A host policy may block IPv6 neighbor discovery needed by the SSH path."
            let ndpMayBeNeeded = candidate.NdpMayBeNeeded && ndpPolicy <> NdpAllowed
            let inboundAllowed, _, zoneExplicitlyAllows =
                zoneDecision true ndpMayBeNeeded serviceXml ipsetXml inbound ingress
            let inboundPolicyAllowed =
                policyDecision zoneExplicitlyAllows serviceXml ipsetXml inbound candidate.Name policies
            policyPreRoutingDecision serviceXml ipsetXml inbound candidate.Name parsedZones policies
            if not inboundAllowed && not inboundPolicyAllowed then
                fail ("SSH on port " + string context.Port + "/tcp is not authorized on possible ingress zone "
                      + candidate.Name + " by its zone or HOST policies. A reply route does not prove inbound classification; refusing mutation.")
        for candidate in egressCandidates do
            let egress =
                parsedZones |> Map.tryFind candidate.Name |> Option.defaultWith (fun () -> fail ("SSH reply zone is missing: " + candidate.Name))
            let ndpPolicy = policyNdpDecision outbound candidate.NdpMayBeNeeded "HOST" candidate.Name policies
            if ndpPolicy = NdpBlocked then
                fail "A host egress policy may block IPv6 neighbor discovery needed by the SSH path."
            if zoneBlocksNeighborDiscovery outbound (candidate.NdpMayBeNeeded && ndpPolicy <> NdpAllowed) egress then
                fail "A firewalld reply zone may block IPv6 neighbor discovery needed by the SSH path."
        ingressCandidates, egressCandidates

    let validateSshGuardWithDefinitions context defaultZone zones policies ipsets services =
        validateSshState unknownSshNetwork context defaultZone zones policies (fun name -> Map.tryFind name ipsets) (fun name -> Map.tryFind name services)
        |> ignore

    /// Pure guard over final permanent definitions. Unrelated source bindings and host policies are ignored only when disjoint.
    let validateSshGuard context defaultZone zones policies serviceXml =
        validateSshState unknownSshNetwork context defaultZone zones policies (fun _ -> None) serviceXml |> ignore


    let rec private runtimeElementToXml (element: FirewalldModel.Element) : XElement =
        let result = XElement(xn element.Name)
        for KeyValue(name, value) in element.Attributes do result.SetAttributeValue(xn name, value)
        element.Text |> Option.iter (fun value -> result.Add(XText value))
        for child in element.Children do result.Add(runtimeElementToXml child)
        result

    let private richRuleGroups =
        set [ "source"; "destination"; "service"; "port"; "source-port"; "protocol"; "icmp-type"; "icmp-block"; "tcp-mss-clamp"
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
            FirewalldModel.nativeReference kind ("runtime " + kind) name |> ignore
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

    let private tryIpSetShape xml =
        try
            let root = parseXml "ipset" xml
            let setType = attr "type" root |> Option.defaultValue ""
            let optionNodes = root.Elements(xn "option") |> Seq.toList
            let options =
                optionNodes
                |> List.choose (fun option ->
                    match attr "name" option, attr "value" option with
                    | Some name, Some value when attributesAreAllowed (set [ "name"; "value" ]) option && option.IsEmpty ->
                        Some(name, value)
                    | _ -> None)
            let entries =
                root.Elements(xn "entry")
                |> Seq.map (fun entry -> entry.Value.Trim())
                |> Seq.toList
            if setType = "" || options.Length <> optionNodes.Length
               || (options |> List.countBy fst |> List.exists (fun (_, count) -> count > 1)) then None
            else Some(setType, Set.ofList options, entries)
        with _ -> None

    let private mergeRuntimeIpSetEntries candidate runtime =
        match candidate, runtime with
        | None, None -> None
        | Some permanent, None -> Some permanent
        | None, Some live -> Some live
        | Some permanent, Some live ->
            match tryIpSetShape permanent, tryIpSetShape live with
            | Some(permanentType, permanentOptions, _), Some(liveType, liveOptions, liveEntries)
                when permanentType = liveType && permanentOptions = liveOptions ->
                let root = parseXml "ipset" permanent
                let permanentEntries =
                    root.Elements(xn "entry")
                    |> Seq.map (fun entry -> entry.Value.Trim())
                    |> Set.ofSeq
                for entry in liveEntries do
                    if not (Set.contains entry permanentEntries) then root.Add(XElement(xn "entry", entry))
                Some(root.ToString(SaveOptions.DisableFormatting))
            | _ -> None

    let private runtimeServiceXml (environment: HostEnvironment) name =
        match FirewalldRuntime.inspectRuntime environment "service" name with
        | Some snapshot when snapshot.UnknownFields.IsEmpty ->
            try
                let values key =
                    snapshot.NativeFields[key] |> Seq.collect (fun text -> text.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries))
                let root = XElement(xn "service")
                for field, tag in [ "ports", "port"; "source-ports", "source-port" ] do
                    for value in values field do
                        let port = FirewalldModel.port value
                        let separator = port.IndexOf('/')
                        root.Add(XElement(xn tag, XAttribute(xn "port", port.Substring(0, separator)), XAttribute(xn "protocol", port.Substring(separator + 1))))
                for field, tag, key in [ "protocols", "protocol", "value"; "includes", "include", "service"
                                         "modules", "module", "name"; "helpers", "helper", "name" ] do
                    for value in values field do root.Add(XElement(xn tag, XAttribute(xn key, value)))
                let destination = XElement(xn "destination")
                for value in values "destination" do
                    let separator = value.IndexOf(':')
                    if separator < 1 then fail "Malformed runtime service destination."
                    let family = value.Substring(0, separator)
                    if (family <> "ipv4" && family <> "ipv6") || not (isNull (destination.Attribute(xn family))) then
                        fail "Unknown or duplicate runtime service destination."
                    destination.SetAttributeValue(xn family, value.Substring(separator + 1))
                if destination.HasAttributes then root.Add destination
                Some(root.ToString(SaveOptions.DisableFormatting))
            with _ -> None
        | _ -> None

    let private referencedIpSets zones policies =
        let collect kind objects =
            objects
            |> Map.toList
            |> List.collect (fun (_, xml) ->
                (parseXml kind xml).DescendantsAndSelf()
                |> Seq.choose (attr "ipset")
                |> Seq.toList)
            |> Set.ofList
        Set.union (collect "zone" zones) (collect "policy" policies)

    let private runtimeIpSetNames (environment: HostEnvironment) =
        let result = environment.Run "firewall-cmd" [ "--get-ipsets" ] None
        if result.ExitCode <> 0 then fail "Cannot enumerate runtime firewalld ipsets for the retained-entry guard."
        result.Stdout.Split([| ' '; '\t'; '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
        |> Array.map (FirewalldModel.nativeReference "ipset" "runtime ipset")
        |> Set.ofArray

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
        network
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
        validateSshState network context finalDefaultZone zones policies (fun name -> Map.tryFind name ipsets) (fun name -> Map.tryFind name services)
        |> ignore
        let runtimeBound =
            if not runtimeInterfaceBound then None
            else
                if not (Map.containsKey runtimeZone zones) then
                    fail "SSH runtime zone is absent from final permanent configuration; reconcile the runtime binding before applying."
                let bound =
                    zones |> Map.map (fun name xml ->
                        let root = parseXml "zone" xml
                        root.Elements(xn "interface")
                        |> Seq.filter (fun element -> interfaceMatches (required "name" element) context.Interface)
                        |> Seq.toArray |> Array.iter (fun element -> element.Remove())
                        if name = runtimeZone then
                            root.Add(XElement(xn "interface", XAttribute(xn "name", context.Interface)))
                        root.ToString(SaveOptions.DisableFormatting))
                validateSshState network context finalDefaultZone bound policies (fun name -> Map.tryFind name ipsets) (fun name -> Map.tryFind name services)
                |> ignore
                Some bound
        // 2.3.1 decides retention using the PRE-reload in-memory value.
        // A file edit is not evidence of that value. Prove both the clean
        // candidate (above) and the candidate combined with surviving members.
        let referenced = referencedIpSets zones policies
        if not referenced.IsEmpty then
            let runtimeNames = runtimeIpSetNames environment
            let retainedResolver name =
                let candidate = Map.tryFind name ipsets
                if Set.contains name runtimeNames then
                    match runtimeIpSetXml environment name with
                    | Some live -> mergeRuntimeIpSetEntries candidate (Some live)
                    | None -> None
                else candidate
            validateSshState network context finalDefaultZone zones policies retainedResolver (fun name -> Map.tryFind name services)
            |> ignore
            runtimeBound
            |> Option.iter (fun bound ->
                validateSshState network context finalDefaultZone bound policies retainedResolver (fun name -> Map.tryFind name services)
                |> ignore)

        let zoneSnapshots = runtimeSnapshots environment "zone"
        let policySnapshots = runtimeSnapshots environment "policy"
        let runtimeZones = zoneSnapshots |> Map.map (fun _ snapshot -> runtimeSnapshotXml snapshot)
        let runtimePolicies = policySnapshots |> Map.map (fun _ snapshot -> runtimeSnapshotXml snapshot)
        let runtimeIngressCandidates, runtimeEgressCandidates =
            validateSshState network context runtimeDefaultZone runtimeZones runtimePolicies (runtimeIpSetXml environment) (runtimeServiceXml environment)
        let runtimeParsedZones = runtimeZones |> Map.map (fun _ xml -> parseXml "zone" xml)
        let interfaceZones = zonesBoundToInterface context.Interface runtimeParsedZones
        let selectedInterfaceZones =
            selectZoneCandidates "egress-priority" interfaceZones runtimeParsedZones (isLayer2Interface network context.Interface)
            |> List.map (fun candidate -> candidate.Name)
        match runtimeInterfaceBound, selectedInterfaceZones with
        | false, [] -> ()
        | true, [ name ] when name = runtimeZone -> ()
        | false, _ -> fail "Runtime interface selectors disagree with firewall-cmd's unbound observation."
        | true, _ -> fail "Runtime interface selectors disagree with firewall-cmd's zone observation."
        let selectedZones =
            (runtimeIngressCandidates @ runtimeEgressCandidates)
            |> List.map (fun candidate -> candidate.Name)
            |> List.distinct
        checkRuntimeFilters "zone" selectedZones zoneSnapshots
        let ingressNames = runtimeIngressCandidates |> List.map (fun candidate -> candidate.Name)
        let egressNames = runtimeEgressCandidates |> List.map (fun candidate -> candidate.Name)
        let relevantPolicies =
            policySnapshots
            |> Map.toList
            |> List.choose (fun (name, snapshot) ->
                let policy = parseXml "policy" (runtimeSnapshotXml snapshot)
                let inboundHost =
                    ingressNames
                    |> List.exists (fun ingress ->
                        policyMatches ingress policy "ingress-zone" && policyMatches "HOST" policy "egress-zone")
                let inboundAny =
                    ingressNames
                    |> List.exists (fun ingress ->
                        policyMatches ingress policy "ingress-zone" && policyMatches "ANY" policy "egress-zone")
                let outbound =
                    egressNames
                    |> List.exists (fun egress ->
                        policyMatches "HOST" policy "ingress-zone" && policyMatches egress policy "egress-zone")
                if inboundHost || inboundAny || outbound then Some name else None)
        checkRuntimeFilters "policy" relevantPolicies policySnapshots
        { CandidateZones = zones
          CandidatePolicies = policies
          RuntimeZones = runtimeZones
          RuntimePolicies = runtimePolicies }

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
            FirewalldModel.nativeReference "zone" "runtime zone" name, true

    let private firewall environment arguments = command environment "firewall-cmd" arguments

    let private regularPath environment logical =
        try FirewalldLifecycle.regularPath environment logical
        with :? InvalidOperationException as error -> fail error.Message

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
                let settingsFields = set [ "settingsScopeVersion"; "settingsActivation" ]
                let allowed =
                    Set.union required
                        (set [ "baselineMode"; "managedMode"; "deleteOnConfirm" ] |> Set.union settingsFields)
                if not (Set.isSubset required keys) || not (Set.isSubset keys allowed)
                   || journal["version"].GetValue<int>() <> 1 then
                    fail "Firewalld object is owned by another resource or its journal is invalid."
                let storedOwner = getString journal "ownerId"
                if String.IsNullOrWhiteSpace storedOwner || storedOwner |> Seq.exists Char.IsControl then
                    fail "Firewalld object is owned by another resource or its journal is invalid."
                if c.Kind = "settings" then
                    if journal.ContainsKey "settingsScopeVersion"
                       && journal["settingsScopeVersion"].GetValue<int>() <> 1 then
                        fail "Unsupported firewalld settings journal scope version."
                    if journal.ContainsKey "settingsActivation" then
                        match journal["settingsActivation"] with
                        | :? JsonObject as proof ->
                            let proofKeys = proof |> Seq.map (fun pair -> pair.Key) |> Set.ofSeq
                            let legacyKeys = set [ "version"; "key"; "value"; "source" ]
                            let currentKeys = set [ "version"; "key"; "value"; "source"; "generation" ]
                            if (proofKeys <> legacyKeys && proofKeys <> currentKeys)
                               || proof["version"].GetValue<int>() <> 1 then
                                fail "Invalid firewalld settings activation receipt."
                        | _ -> fail "Invalid firewalld settings activation receipt."
                elif settingsFields |> Seq.exists journal.ContainsKey then
                    fail "Settings ownership metadata is attached to a non-settings firewalld journal."
                optionalString journal "baseline" |> ignore
                optionalString journal "managed" |> ignore
                if storedOwner <> owner then raise (JournalOwnerConflict())
                Some journal

    let private loadMutationJournal environment (c: FirewalldModel.Configuration) owner operation =
        if operation <> "apply" then loadJournal environment c owner
        else
            let canRefuse = FirewalldLifecycle.canClassifyPreStageRefusal environment
            try loadJournal environment c owner
            with :? JournalOwnerConflict when canRefuse ->
                raise (
                    PreStageRefusal(
                        operation,
                        owner,
                        "A different resource generation already owns this firewalld object; no changes were made."
                    )
                )
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

    let private definitionInventory environment kind =
        if kind = "zone" then ensureNoSplitZones environment
        [ "/usr/lib/firewalld"; "/etc/firewalld" ]
        |> List.fold (fun result prefix ->
            let logicalDirectory = prefix + "/" + category kind
            let directory = path environment logicalDirectory
            if not (Directory.Exists directory) then result
            else
                regularPath environment logicalDirectory |> ignore
                Directory.EnumerateFiles(directory, "*.xml")
                |> Seq.fold (fun state file ->
                    let name = Path.GetFileNameWithoutExtension file
                    FirewalldModel.nativeReference kind "inventory object" name |> ignore
                    match readFile environment (objectPath prefix kind name) with
                    | Some xml -> Map.add name xml state
                    | None -> state) result)
            Map.empty

    let private configuredDefaultZone etcContents =
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
                | [| value |] -> Some(FirewalldModel.nativeReference "zone" "default zone" value)
                | _ -> fail "Duplicate DefaultZone settings in firewalld.conf."
        parse etcContents |> Option.defaultValue "public"

    let private updateDefinition environment kind name proposed values =
        match proposed with
        | Some xml -> Map.add name xml values
        | None ->
            match readFile environment (objectPath "/usr/lib/firewalld" kind name) with
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
        let settingsKey = if c.Kind = "settings" then FirewalldModel.settingKey c else ""
        let candidateConfig =
            if c.Kind = "settings" && settingsKey = "DefaultZone" then proposed
            else etcConfig
        { Zones = zones; Policies = policies; Services = services; IpSets = ipsets
          IcmpTypes = icmpTypes; Helpers = helpers
          DefaultZone = configuredDefaultZone candidateConfig }

    let guardMutation (environment: HostEnvironment) (c: FirewalldModel.Configuration) (proposed: string option) =
        let connection = Environment.GetEnvironmentVariable "SSH_CONNECTION"
        let fields = if isNull connection then [||] else connection.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
        if fields.Length <> 4 then fail "SSH_CONNECTION is required before any firewalld mutation."
        for index in [ 0; 2 ] do
            match IPAddress.TryParse fields[index] with true, _ -> () | _ -> fail "Invalid SSH_CONNECTION address."
        let route = command environment "ip" [ "-j"; "route"; "get"; fields[0]; "from"; fields[2] ]
        let context = parseSshContext connection route
        let network = observeSshNetwork environment context
        let runtimeDefaultZone = firewall environment [ "--get-default-zone" ] |> FirewalldModel.nativeReference "zone" "runtime default zone"
        let inventory = finalInventory environment c proposed
        let definitions =
            Map.ofList [ "zone", inventory.Zones; "policy", inventory.Policies; "service", inventory.Services
                         "ipset", inventory.IpSets; "helper", inventory.Helpers; "icmptype", inventory.IcmpTypes ]
        try FirewalldReferences.validate parseXml c.Kind c.Name inventory.DefaultZone definitions
        with :? InvalidOperationException as error -> fail error.Message
        let runtimeZone, runtimeInterfaceBound = runtimeZoneOfInterface environment runtimeDefaultZone context.Interface
        let snapshots =
            validateRuntimeBinding
                environment network
                context runtimeDefaultZone inventory.DefaultZone runtimeZone runtimeInterfaceBound
                inventory.Zones inventory.Policies inventory.IpSets inventory.Services
        if c.Kind = "zone" || c.Kind = "policy" then
            match FirewalldBindingTransfer.validate c (effective environment c.Kind c.Name)
                      snapshots.CandidateZones snapshots.CandidatePolicies inventory.DefaultZone runtimeDefaultZone
                      snapshots.RuntimeZones snapshots.RuntimePolicies with
            | Ok () -> ()
            | Error reason -> fail reason

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
        let etcConfig = readFile environment "/etc/firewalld/firewalld.conf"
        let inventory =
            { Zones = definitionInventory environment "zone"
              Policies = definitionInventory environment "policy"
              Services = definitionInventory environment "service"
              IpSets = definitionInventory environment "ipset"
              IcmpTypes = definitionInventory environment "icmptype"
              Helpers = definitionInventory environment "helper"
              DefaultZone = configuredDefaultZone etcConfig }
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


    let private pendingFor environment (c: FirewalldModel.Configuration) =
        FirewalldLifecycle.pending environment
        |> Option.exists (fun tx -> tx.Configuration.Kind = c.Kind && tx.Configuration.Name = c.Name)

    let private snapshot environment (c: FirewalldModel.Configuration) journal =
        let actual = effective environment c.Kind c.Name
        let logical = objectPath "/etc/firewalld" c.Kind c.Name
        let overrideFile = readFile environment logical
        let objectPending =
            journal
            |> Option.exists (fun (value: JsonObject) -> not (isNull value["pending"]))
        let pending = objectPending || pendingFor environment c
        let managed =
            match journal with
            | Some value ->
                match value["pending"] with
                | :? JsonObject as transaction when transaction.ContainsKey "managedAfter" ->
                    optionalString transaction "managedAfter"
                | _ -> optionalString value "managed"
            | None -> None
        let managedMode =
            journal
            |> Option.bind (fun value ->
                match value["pending"] with
                | :? JsonObject as transaction when transaction.ContainsKey "managedAfter" && transaction.ContainsKey "afterMode" ->
                    Some(transaction["afterMode"].GetValue<int>())
                | _ when value.ContainsKey "managedMode" && not (isNull value["managedMode"]) ->
                    Some(value["managedMode"].GetValue<int>())
                | _ when (c.Kind = "zone" || c.Kind = "policy") && FirewalldLifecycle.preMetadataJournal value -> Some 0o644
                | _ -> None)
        let metadataMatches =
            match managedMode, overrideFile with
            | Some expectedMode, None -> expectedMode = 0o644
            | Some expectedMode, Some _ ->
                try
                    let physical = regularPath environment logical
                    let owner = environment.Run "stat" [ "-c"; "%u:%g"; "--"; physical ] None
                    owner.ExitCode = 0
                    && owner.Stdout.Trim() = "0:0"
                    && int (File.GetUnixFileMode physical) = expectedMode
                with _ -> false
            | None, _ -> false
        let ownershipConflict =
            journal.IsSome && (managed <> overrideFile || not metadataMatches)
        let owned = journal.IsSome && managed = overrideFile && metadataMatches
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
        result["ownershipConflict"] <- JsonValue.Create ownershipConflict
        result["permanentInSync"] <- JsonValue.Create permanentInSync
        result["runtimeObserved"] <- JsonValue.Create runtimeObserved
        result["runtimeInSync"] <- JsonValue.Create runtimeInSync
        result["inSync"] <- JsonValue.Create(permanentInSync && runtimeObserved && runtimeInSync && not pending)
        result :> JsonNode

    let private objectReadState (scope: JsonObject option) (contents: string option) =
        if scope.IsSome then fail "Firewalld object transaction cannot use a scoped file state."
        contents

    let private objectWriteState
        (environment: HostEnvironment)
        (c: FirewalldModel.Configuration)
        (logical: string)
        (scope: JsonObject option)
        (expectedCurrent: string option)
        (target: string option)
        (mode: int)
        =
        if scope.IsSome then fail "Firewalld object transaction cannot use a scoped file state."
        let current = readFile environment logical
        if current <> expectedCurrent then
            fail "Firewalld object configuration changed before its transaction write."
        writeOverride environment c target mode

    let private requireReloadProof (environment: HostEnvironment) =
        match FirewalldRuntime.validateReload environment with
        | Ok () -> ()
        | Error reason -> fail ("Cannot prove a daemon-wide firewalld activation and rollback safe: " + reason)

    let private requireRestoredObjectRuntime
        (environment: HostEnvironment)
        (c: FirewalldModel.Configuration)
        =
        match FirewalldRuntime.validateReload environment with
        | Error reason -> fail ("Firewalld runtime did not restore its permanent baseline: " + reason)
        | Ok () ->
            let disk = FirewalldRuntime.snapshotFromXml c.Kind c.Name (effective environment c.Kind c.Name)
            match disk, FirewalldRuntime.queryPermanent environment c.Kind c.Name, FirewalldRuntime.queryRuntime environment c.Kind c.Name with
            | Ok None, Ok None, Ok None -> ()
            | Ok(Some expected), Ok(Some permanent), Ok(Some live)
                when FirewalldRecoveryProof.matchesLoadedProjection environment expected permanent
                  && FirewalldRecoveryProof.matchesLoadedProjection environment expected live -> ()
            | Error reason, _, _ -> fail ("Unable to prove restored firewalld XML: " + reason)
            | _, Error reason, _ -> fail ("Unable to prove restored permanent firewalld object: " + reason)
            | _, _, Error reason -> fail ("Unable to prove restored runtime firewalld object: " + reason)
            | _ -> fail "The deleted firewalld object is not absent or loaded at its restored baseline."

    let private restoreObjectRuntime
        (environment: HostEnvironment)
        (c: FirewalldModel.Configuration)
        (preReload: unit -> unit)
        (transaction: FirewalldLifecycle.PendingTransaction)
        (phase: FirewalldLifecycle.RecoveryPhase)
        =
        let effectiveCurrent = effective environment c.Kind c.Name
        FirewalldRecoveryProof.restoreRuntimeWithPreReload environment c effectiveCurrent transaction.RollbackProof phase preReload

    let private recover environment (c: FirewalldModel.Configuration) (journal: JsonObject) (preReload: unit -> unit) =
        let logical = objectPath "/etc/firewalld" c.Kind c.Name
        let readState scope contents = objectReadState scope contents
        let writeState scope expectedCurrent target mode =
            objectWriteState environment c logical scope expectedCurrent target mode
        try
            FirewalldLifecycle.recover environment c journal logical readState writeState (restoreObjectRuntime environment c preReload)
        with :? InvalidOperationException as error ->
            fail error.Message

    let private transact environment (c: FirewalldModel.Configuration) (journal: JsonObject) releaseOnRollback deleteOnConfirm desired afterMode (preflightSettings: unit -> unit) =
        if releaseOnRollback then
            match effective environment c.Kind c.Name with
            | Some baseline when not (FieldRuntime.safeAdoption c baseline) ->
                let reason = "Existing firewalld definition contains unrepresented baseline fields; refusing to replace it."
                if FirewalldLifecycle.canClassifyPreStageRefusal environment then
                    raise (PreStageRefusal("apply", getString journal "ownerId", reason))
                else fail reason
            | _ -> ()
        let logical = objectPath "/etc/firewalld" c.Kind c.Name
        let before = readFile environment logical
        let beforeMode = objectFileMode environment logical
        if releaseOnRollback && before.IsSome && not (List.contains beforeMode [ 0o600; 0o640; 0o644 ]) then
            fail "An adopted firewalld object override must be root-owned and non-executable mode 0600, 0640, or 0644."
        let managedBefore = optionalString journal "managed"
        let readState scope contents = objectReadState scope contents
        let writeState scope expectedCurrent target mode =
            objectWriteState environment c logical scope expectedCurrent target mode
        let validate (scope: JsonObject option) proposed =
            if scope.IsSome then fail "Firewalld object transaction cannot use a scoped file state."
            guardMutation environment c proposed
        // Lifecycle validates the candidate immediately before arming. Guard a
        // different disk rollback preimage as well, before any mutation.
        if before <> desired then validate None before
        let prove build =
            try build ()
            with :? InvalidOperationException as error -> fail error.Message
        let runtimeMatches () =
            let observation = FirewalldRuntime.observe environment c
            observation.Observed && observation.InSync
        let rollbackProof, activate =
            if before <> desired then
                preflightSettings()
                requireReloadProof environment
                let effectiveBefore = effective environment c.Kind c.Name
                let effectiveAfter =
                    desired |> Option.orElseWith (fun () -> readFile environment (objectPath "/usr/lib/firewalld" c.Kind c.Name))
                prove (fun () -> FirewalldRecoveryProof.reloadProof environment c effectiveBefore effectiveAfter),
                (fun () ->
                    preflightSettings()
                    firewall environment [ "--check-config" ] |> ignore
                    firewall environment [ "--reload" ] |> ignore)
            elif runtimeMatches () then
                FirewalldRecoveryProof.unchangedProof c,
                (fun () -> firewall environment [ "--check-config" ] |> ignore)
            else
                let live =
                    FirewalldRuntime.inspectRuntime environment c.Kind c.Name
                    |> Option.defaultWith (fun () -> fail "Unable to observe the loaded firewalld object before proving a runtime repair.")
                let proof = prove (fun () -> FirewalldRecoveryProof.runtimeRepairProof environment c live)
                proof,
                (fun () ->
                    firewall environment [ "--check-config" ] |> ignore
                    FirewalldRecoveryProof.activateRuntimeRepair environment c proof)
        try
            FirewalldLifecycle.transact
                environment c journal releaseOnRollback deleteOnConfirm logical None before beforeMode desired afterMode
                managedBefore desired (Some rollbackProof) readState writeState validate activate (restoreObjectRuntime environment c preflightSettings)
        with :? InvalidOperationException as error ->
            fail error.Message

    let private strictConfigPath = "/etc/firewalld/firewalld.conf"
    let private settingsUtf8 = UTF8Encoding(false, true)

    type private SettingEntry =
        { Start: int
          ContentEnd: int
          End: int
          Value: string
          Line: string }

    type private SettingsOrigin =
        { EtcExisted: bool
          LegacyVendorSeedHash: string option }

    type private SettingsBaseline =
        { Exists: bool
          Value: string option
          Line: string option
          Mode: int
          Origin: SettingsOrigin }

    type private SettingsKeyState =
        { Value: string option
          Line: string option }

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
                    result.Add { Start = start; ContentEnd = contentEnd; End = finish; Value = value; Line = text.Substring(start, contentEnd - start) }
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

    let private settingLine (text: string) (key: string) =
        match settingEntries text key with
        | [] -> None
        | [ entry ] -> Some entry.Line
        | _ -> fail ("Duplicate " + key + " settings in firewalld.conf.")

    let private setSettingLine (text: string) (key: string) (line: string option) =
        match settingEntries text key with
        | [ entry ] ->
            match line with
            | Some replacement -> text.Substring(0, entry.Start) + replacement + text.Substring(entry.ContentEnd)
            | None -> text.Remove(entry.Start, entry.End - entry.Start)
        | [] ->
            match line with
            | None -> text
            | Some replacement ->
                let newline = newlineOf text
                let separator =
                    if text = "" || text.EndsWith("\n", StringComparison.Ordinal) || text.EndsWith("\r", StringComparison.Ordinal) then ""
                    else newline
                text + separator + replacement + newline
        | _ -> fail ("Duplicate " + key + " settings in firewalld.conf.")

    let private setSettingValue (text: string) (key: string) (value: string option) =
        setSettingLine text key (value |> Option.map (fun item -> key + "=" + item))
    let private settingsContentHash (contents: string) =
        SHA256.HashData(settingsUtf8.GetBytes contents) |> Convert.ToHexString
    let private settingsKeyState key (contents: string option) =
        match contents with
        | None -> { Value = None; Line = None }
        | Some text ->
            { Value = settingValue text key
              Line = settingLine text key }

    let private encodeSettingsKeyState (state: SettingsKeyState) =
        let node = JsonObject()
        node["version"] <- JsonValue.Create 1
        setOptional node "value" state.Value
        setOptional node "line" state.Line
        node.ToJsonString()

    let private parseSettingsKeyState key (text: string) =
        let state =
            try JsonNode.Parse(text).AsObject()
            with _ -> fail "Invalid key-scoped firewalld settings state."
        let keys = state |> Seq.map (fun pair -> pair.Key) |> Set.ofSeq
        if keys <> set [ "version"; "value"; "line" ] || state["version"].GetValue<int>() <> 1 then
            fail "Invalid key-scoped firewalld settings state."
        let value, line = optionalString state "value", optionalString state "line"
        match line, value with
        | None, None -> { Value = None; Line = None }
        | Some raw, Some expected when settingValue raw key = Some expected && settingLine raw key = Some raw ->
            { Value = value; Line = line }
        | _ -> fail "Key-scoped firewalld settings state does not match its key line."

    let private settingsKeyStateToken key contents =
        settingsKeyState key contents |> encodeSettingsKeyState


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

    let private effectiveSettingValue key etcContents =
        let fileValue = etcContents |> Option.bind (fun contents -> settingValue contents key)
        fileValue |> Option.orElseWith (fun () -> settingDefault key)

    let private systemdProperty (environment: HostEnvironment) property =
        try
            Some(command environment "/usr/bin/systemctl" [ "show"; "--timestamp=unix"; "--property=" + property; "--value"; "firewalld.service" ])
        with _ -> None

    let private systemdTimestamp (value: string) =
        if not (value.StartsWith('@')) then None
        else
            match Int64.TryParse(value.AsSpan(1), NumberStyles.None, CultureInfo.InvariantCulture) with
            | true, seconds when seconds > 0L -> Some seconds
            | _ -> None


    let private firewalldDaemonIdentity (environment: HostEnvironment) =
        // Readiness follows configuration parsing. Only a file that predates
        // process creation can be attributed to that startup.
        match systemdProperty environment "InvocationID", systemdProperty environment "ExecMainStartTimestamp" with
        | Some invocation, Some entered when not (String.IsNullOrWhiteSpace invocation || invocation = "n/a") ->
            systemdTimestamp entered |> Option.map (fun start -> invocation, start)
        | _ -> None

    let private trustedPathPredates (environment: HostEnvironment) logical (started: int64) =
        try
            let physical = regularPath environment logical
            if not (File.Exists physical || Directory.Exists physical) then false
            else
                let owner = command environment "stat" [ "-c"; "%u:%g"; "--"; physical ]
                let mode = command environment "stat" [ "-c"; "%a"; "--"; physical ] |> fun value -> Convert.ToInt32(value, 8)
                let changed = command environment "stat" [ "-c"; "%Z"; "--"; physical ] |> Int64.Parse
                owner = "0:0"
                && (mode &&& 0o022) = 0
                && changed < started
        with _ -> false

    let private settingsStartupLoadedValue
        (environment: HostEnvironment)
        key
        (etcContents: string option)
        =
        match firewalldDaemonIdentity environment with
        | None -> None
        | Some(generation, started) ->
            let etcPath = if etcContents.IsSome then strictConfigPath else "/etc/firewalld"
            if not (trustedPathPredates environment etcPath started) then None
            else
                let explicitValue = etcContents |> Option.bind (fun contents -> settingValue contents key)
                let value =
                    match explicitValue with
                    | Some item -> Some item
                    | None ->
                        let version =
                            try command environment "firewall-cmd" [ "--version" ]
                            with _ -> ""
                        if version.StartsWith("2.3.1", StringComparison.Ordinal) then settingDefault key
                        else None
                let stableGeneration =
                    firewalldDaemonIdentity environment
                    |> Option.exists (fun (currentGeneration, _) -> currentGeneration = generation)
                if stableGeneration then value |> Option.map (fun item -> item, generation)
                else None

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

    let private encodeSettingsBaseline key (exists: bool) (state: SettingsKeyState) (mode: int) (origin: SettingsOrigin) =
        let baseline = JsonObject()
        baseline["version"] <- JsonValue.Create 4
        baseline["key"] <- JsonValue.Create(key: string)
        baseline["etcExists"] <- JsonValue.Create exists
        setOptional baseline "etcValue" state.Value
        setOptional baseline "etcLine" state.Line
        baseline["etcMode"] <- JsonValue.Create mode
        baseline["originEtcExists"] <- JsonValue.Create origin.EtcExisted
        origin.LegacyVendorSeedHash |> Option.iter (fun hash -> setOptional baseline "legacyVendorSeedHash" (Some hash))
        baseline.ToJsonString()

    let private parseSettingsBaseline key (text: string) =
        let baseline =
            try JsonNode.Parse(text).AsObject()
            with _ -> fail "Invalid firewalld settings ownership baseline."
        let keys = baseline |> Seq.map (fun pair -> pair.Key) |> Set.ofSeq
        let keyScoped = set [ "version"; "key"; "etcExists"; "etcValue"; "etcLine"; "etcMode"; "originEtcExists" ]
        let keyScopedWithLegacy = Set.add "legacyVendorSeedHash" keyScoped
        let version3 = set [ "version"; "key"; "etcExists"; "etcContents"; "etcValue"; "etcMode"; "originEtcExists"; "originVendorContents"; "originVendorMode" ]
        let version2 = set [ "version"; "key"; "etcExists"; "etcContents"; "etcValue"; "etcMode" ]
        let legacyCompact = set [ "etcExists"; "etcStrictValue"; "etcMode" ]
        let legacyContents = set [ "etcExists"; "etcContents"; "vendorContents"; "etcMode" ]
        let validateLine value line =
            match line, value with
            | None, None -> ()
            | Some raw, Some expected when settingValue raw key = Some expected && settingLine raw key = Some raw -> ()
            | _ -> fail "Invalid firewalld settings baseline key line."
        let legacySeed vendor =
            vendor
            |> Option.map (fun contents -> settingsContentHash (setSettingLine contents key None))
        let result =
            if keys = keyScoped || keys = keyScopedWithLegacy then
                if baseline["version"].GetValue<int>() <> 4 || getString baseline "key" <> key then
                    fail "Firewalld settings ownership baseline does not match its key."
                let exists = baseline["etcExists"].GetValue<bool>()
                let value, line = optionalString baseline "etcValue", optionalString baseline "etcLine"
                validateLine value line
                if not exists && value.IsSome then fail "Invalid absent-file firewalld settings baseline."
                let legacyVendorSeedHash =
                    if keys = keyScopedWithLegacy then optionalString baseline "legacyVendorSeedHash"
                    else None
                { Exists = exists
                  Value = value
                  Line = line
                  Mode = baseline["etcMode"].GetValue<int>()
                  Origin =
                    { EtcExisted = baseline["originEtcExists"].GetValue<bool>()
                      LegacyVendorSeedHash = legacyVendorSeedHash } }
            elif keys = version3 then
                if baseline["version"].GetValue<int>() <> 3 || getString baseline "key" <> key then
                    fail "Firewalld settings ownership baseline does not match its key."
                let exists = baseline["etcExists"].GetValue<bool>()
                let contents = optionalString baseline "etcContents"
                let value = optionalString baseline "etcValue"
                let line = contents |> Option.bind (fun item -> settingLine item key)
                if exists <> contents.IsSome || (contents |> Option.bind (fun item -> settingValue item key)) <> value then
                    fail "Invalid firewalld settings ownership baseline."
                validateLine value line
                let originEtcExists = baseline["originEtcExists"].GetValue<bool>()
                let legacyVendorSeedHash =
                    if originEtcExists then None else legacySeed (optionalString baseline "originVendorContents")
                { Exists = exists
                  Value = value
                  Line = line
                  Mode = baseline["etcMode"].GetValue<int>()
                  Origin = { EtcExisted = originEtcExists; LegacyVendorSeedHash = legacyVendorSeedHash } }
            elif keys = version2 then
                if baseline["version"].GetValue<int>() <> 2 || getString baseline "key" <> key then
                    fail "Firewalld settings ownership baseline does not match its key."
                let exists = baseline["etcExists"].GetValue<bool>()
                let contents = optionalString baseline "etcContents"
                let value = optionalString baseline "etcValue"
                let line = contents |> Option.bind (fun item -> settingLine item key)
                if exists <> contents.IsSome || (contents |> Option.bind (fun item -> settingValue item key)) <> value then
                    fail "Invalid firewalld settings ownership baseline."
                validateLine value line
                { Exists = exists
                  Value = value
                  Line = line
                  Mode = baseline["etcMode"].GetValue<int>()
                  Origin = { EtcExisted = exists; LegacyVendorSeedHash = None } }
            elif key = "StrictForwardPorts" && keys = legacyCompact then
                let exists = baseline["etcExists"].GetValue<bool>()
                let value = optionalString baseline "etcStrictValue"
                let line = value |> Option.map (fun item -> key + "=" + item)
                { Exists = exists
                  Value = value
                  Line = line
                  Mode = baseline["etcMode"].GetValue<int>()
                  Origin = { EtcExisted = exists; LegacyVendorSeedHash = None } }
            elif key = "StrictForwardPorts" && keys = legacyContents then
                let exists = baseline["etcExists"].GetValue<bool>()
                let contents = optionalString baseline "etcContents"
                let value = contents |> Option.bind (fun item -> settingValue item key)
                let line = contents |> Option.bind (fun item -> settingLine item key)
                let legacyVendorSeedHash =
                    if exists then None else legacySeed (optionalString baseline "vendorContents")
                { Exists = exists
                  Value = value
                  Line = line
                  Mode = baseline["etcMode"].GetValue<int>()
                  Origin = { EtcExisted = exists; LegacyVendorSeedHash = legacyVendorSeedHash } }
            else fail "Invalid firewalld settings ownership baseline."
        if result.Mode < 0 || result.Mode > 0o7777 then
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

    let private settingsOriginFromJournal (environment: HostEnvironment) (fileName: string) =
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
        let legacyVendorContents =
            if baseline.ContainsKey "originVendorContents" then optionalString baseline "originVendorContents"
            elif baseline.ContainsKey "vendorContents" then optionalString baseline "vendorContents"
            else None
        let legacyKey =
            if baseline.ContainsKey "key" then getString baseline "key"
            elif fileName = "settings-strict-forward-ports.json" then "StrictForwardPorts"
            else ""
        let legacyVendorSeedHash =
            if baseline.ContainsKey "legacyVendorSeedHash" then optionalString baseline "legacyVendorSeedHash"
            elif etcExisted || String.IsNullOrEmpty legacyKey then None
            else
                legacyVendorContents
                |> Option.map (fun contents -> settingsContentHash (setSettingLine contents legacyKey None))
        { EtcExisted = etcExisted
          LegacyVendorSeedHash = legacyVendorSeedHash }, hasOriginMetadata

    let private settingsOriginForNewOwner
        (environment: HostEnvironment)
        (c: FirewalldModel.Configuration)
        (etcContents: string option)
        =
        match settingsJournalFiles environment c with
        | [] -> { EtcExisted = etcContents.IsSome; LegacyVendorSeedHash = None }
        | files ->
            let origins = files |> List.map (settingsOriginFromJournal environment)
            let existedValues = origins |> List.map (fun (origin, _) -> origin.EtcExisted) |> List.distinct
            if existedValues.Length <> 1 then fail "Firewalld settings journals disagree about the original override."
            let persisted = origins |> List.choose (fun (origin, hasMetadata) -> if hasMetadata then Some origin else None)
            match persisted with
            | first :: remaining ->
                if remaining |> List.exists ((<>) first) then fail "Firewalld settings journals disagree about the original override provenance."
                first
            | [] -> fst (List.head origins)

    let private managedSettingState key keyScoped (contents: string option) =
        contents
        |> Option.map (fun text ->
            if keyScoped then parseSettingsKeyState key text
            else settingsKeyState key (Some text))
        |> Option.defaultValue { Value = None; Line = None }

    let private deprecatedSetting key = Set.contains key deprecatedSettings


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

    let private iptablesFields (line: string) =
        line.Split(' ', StringSplitOptions.RemoveEmptyEntries)

    let private iptablesStateSet (fields: string array) =
        let selector =
            [| "--ctstate"; "--state" |]
            |> Array.choose (fun flag -> fields |> Array.tryFindIndex ((=) flag) |> Option.map (fun index -> flag, index))
        match selector with
        | [| (flag, index) |] when index + 1 < fields.Length ->
            let moduleName =
                fields
                |> Array.pairwise
                |> Array.tryFind (fun (name, value) -> name = "-m" && (value = "conntrack" || value = "state"))
                |> Option.map snd
            let moduleMatches =
                match flag, moduleName with
                | "--ctstate", Some "conntrack" -> true
                | "--state", Some "state" -> true
                | _ -> false
            if moduleMatches then Some(fields[index + 1].Split(',') |> Set.ofArray) else None
        | _ -> None

    let private iptablesTarget (fields: string array) =
        match
            [| "-j"; "--jump" |]
            |> Array.choose (fun flag -> fields |> Array.tryFindIndex ((=) flag) |> Option.map id)
        with
        | [| index |] when index + 1 < fields.Length -> Some fields[index + 1]
        | _ -> None

    let private iptablesRuleFields chain (rules: string) =
        let prefix = "-A " + chain + " "
        rules.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
        |> Array.filter (fun line -> line.StartsWith(prefix, StringComparison.Ordinal))
        |> Array.map iptablesFields

    let private iptablesDnatMatch (fields: string array) =
        iptablesStateSet fields |> Option.exists (Set.contains "DNAT")

    let private iptablesAcceptMayMatchDnat (fields: string array) =
        iptablesTarget fields = Some "ACCEPT"
        && (iptablesStateSet fields |> Option.forall (Set.contains "DNAT"))

    let private iptablesPortAccept (fields: string array) =
        match iptablesStateSet fields, iptablesTarget fields with
        | Some states, Some "ACCEPT" when states = Set.singleton "DNAT" ->
            fields
            |> Array.tryFindIndex ((=) "--ctdir")
            |> Option.exists (fun index ->
                index + 1 < fields.Length
                && fields[index + 1] = "ORIGINAL"
                && (fields
                    |> Array.tryFindIndex ((=) "--ctorigdstport")
                    |> Option.exists (fun portIndex -> portIndex + 1 < fields.Length && iptablesPort fields[portIndex + 1])))
        | _ -> false

    let private iptablesTerminalReject (fields: string array) =
        fields.Length >= 4
        && fields[0] = "-A"
        && (fields[2] = "-j" || fields[2] = "--jump")
        && fields[3] = "REJECT"

    let private iptablesGenericDnatAccept (fields: string array) =
        let genericStates = Set.ofList [ "RELATED"; "ESTABLISHED"; "DNAT" ]
        iptablesStateSet fields = Some genericStates && iptablesTarget fields = Some "ACCEPT"

    let private iptablesHasEarlierAcceptBypass (rules: string) chain index =
        iptablesRuleFields chain rules
        |> Array.take index
        |> Array.exists iptablesAcceptMayMatchDnat

    let private iptablesStrictValue (rules: string) =
        let chainRules chain = iptablesRuleFields chain rules
        let dnatRules chain = chainRules chain |> Array.filter iptablesDnatMatch
        let strictRules =
            dnatChains
            |> List.forall (fun chain ->
                let dnatChain = chain + "_dnat"
                let chainLines = chainRules dnatChain
                let baseDnat = dnatRules chain
                let jumpIndex =
                    chainRules chain
                    |> Array.tryFindIndex (fun fields ->
                        iptablesStateSet fields = Some(Set.singleton "DNAT")
                        && iptablesTarget fields = Some dnatChain)
                iptablesHasChain rules dnatChain
                && chainLines.Length > 0
                && iptablesTerminalReject chainLines[chainLines.Length - 1]
                && (chainLines |> Array.take (chainLines.Length - 1) |> Array.forall iptablesPortAccept)
                && baseDnat.Length = 1
                && jumpIndex.IsSome
                && not (iptablesHasEarlierAcceptBypass rules chain (Option.get jumpIndex)))
        if strictRules then Some "yes"
        else
            let genericRules =
                dnatChains
                |> List.forall (fun chain ->
                    let dnatChain = chain + "_dnat"
                    let chainLines = chainRules chain
                    let baseDnat = dnatRules chain
                    let acceptIndex = chainLines |> Array.tryFindIndex iptablesGenericDnatAccept
                    not (iptablesHasChain rules dnatChain)
                    && baseDnat.Length = 1
                    && acceptIndex.IsSome
                    && not (iptablesHasEarlierAcceptBypass rules chain (Option.get acceptIndex)))
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

    let private strictValueFromRuntime runtime =
        match runtime.Backend, runtime.Nft, runtime.Iptables, runtime.Ipv6Enabled, runtime.Iptables6 with
        | "nftables", Some state, _, _, _ -> nftStrictValue state
        | "iptables", _, Some rules, Some false, _ -> iptablesStrictValue rules
        | "iptables", _, Some ipv4Rules, Some true, Some ipv6Rules ->
            match iptablesStrictValue ipv4Rules, iptablesStrictValue ipv6Rules with
            | Some ipv4, Some ipv6 when ipv4 = ipv6 -> Some ipv4
            | _ -> None
        | _ -> None

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
            runtimeFirewall environment |> Option.bind strictValueFromRuntime
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
    let strictForwardPortsLoaded (environment: HostEnvironment) =
        runtimeSettingValue environment "StrictForwardPorts" = Some "yes"
    let strictForwardPortsConfigured (environment: HostEnvironment) =
        try
            effectiveSettingValue "StrictForwardPorts" (readSettingsFile environment strictConfigPath)
            |> Option.exists (fun value -> normalizedBoolean value = Some "yes")
        with _ -> false

    let private requireLoadedSecuritySettings (environment: HostEnvironment) (skipKey: string option) =
        let etcContents = readSettingsFile environment strictConfigPath
        let compare key loaded =
            if skipKey <> Some key then
                match effectiveSettingValue key etcContents, loaded with
                | Some expected, Some actual when settingValuesEqual key (Some expected) (Some actual) -> ()
                | Some _, Some _ -> fail ("Loaded " + key + " differs from its effective system configuration; refusing daemon-wide activation.")
                | None, _ -> fail ("Unable to establish effective " + key + " before daemon-wide activation.")
                | _, None -> fail ("Unable to verify loaded " + key + " before daemon-wide activation.")
        compare "DefaultZone" (runtimeSettingValue environment "DefaultZone")
        let runtime =
            runtimeFirewall environment
            |> Option.defaultWith (fun () -> fail "Unable to establish one complete loaded firewall backend snapshot before daemon-wide activation.")
        compare "FirewallBackend" (Some runtime.Backend)
        compare "StrictForwardPorts" (strictValueFromRuntime runtime)



    let private settingRuntimeObservable key = Set.contains key observableSettings

    let private daemonActive (environment: HostEnvironment) =
        try
            firewall environment [ "--state" ] |> ignore
            true
        with _ -> false

    let private validateSettingsCandidate (environment: HostEnvironment) (c: FirewalldModel.Configuration) key proposed =
        proposed |> Option.iter (fun contents -> settingValue contents key |> ignore)
        if nftablesSettings.Contains key then
            match effectiveSettingValue "FirewallBackend" proposed with
            | Some backend when String.Equals(backend, "iptables", StringComparison.OrdinalIgnoreCase) ->
                fail (key + " cannot be confirmed with FirewallBackend=iptables.")
            | _ -> ()
        guardMutation environment c proposed

    let private activateSettings (environment: HostEnvironment) key =
        requireLoadedSecuritySettings environment (Some key)
        firewall environment [ "--check-config" ] |> ignore
        if key = "FirewallBackend" then
            command environment "/usr/bin/systemctl" [ "restart"; "firewalld" ] |> ignore
        else
            firewall environment [ "--reload" ] |> ignore
        firewall environment [ "--state" ] |> ignore
        if settingRuntimeObservable key then
            let etcContents = readSettingsFile environment strictConfigPath
            let expected = effectiveSettingValue key etcContents
            match expected, runtimeSettingValue environment key with
            | Some expectedValue, Some actualValue when settingValuesEqual key (Some expectedValue) (Some actualValue) -> ()
            | Some _, Some _ -> fail ("firewalld did not load the requested " + key + " effect.")
            | _ -> fail ("Unable to observe the loaded " + key + " effect after activation.")

    let private settingsScope key (removeEmptyFile: bool) legacyVendorSeedHash =
        let scope = JsonObject()
        scope["version"] <- JsonValue.Create 1
        scope["kind"] <- JsonValue.Create "setting"
        scope["key"] <- JsonValue.Create(key: string)
        scope["removeEmptyFile"] <- JsonValue.Create removeEmptyFile
        legacyVendorSeedHash
        |> Option.iter (fun hash -> scope["legacySeedHash"] <- JsonValue.Create(hash: string))
        Some scope

    let private settingsScopeDetails (scope: JsonObject option) =
        let value = scope |> Option.defaultWith (fun () -> fail "Firewalld settings transaction has no key scope.")
        let keys = value |> Seq.map (fun pair -> pair.Key) |> Set.ofSeq
        let required = set [ "version"; "kind"; "key"; "removeEmptyFile" ]
        if (keys <> required && keys <> Set.add "legacySeedHash" required)
           || value["version"].GetValue<int>() <> 1
           || getString value "kind" <> "setting" then
            fail "Invalid key-scoped firewalld settings transaction."
        let key = getString value "key"
        let removeEmptyFile = value["removeEmptyFile"].GetValue<bool>()
        let legacyVendorSeedHash =
            if value.ContainsKey "legacySeedHash" then optionalString value "legacySeedHash"
            else None
        key, removeEmptyFile, legacyVendorSeedHash

    let private readSettingsState (_environment: HostEnvironment) scope contents =
        let key, _, _ = settingsScopeDetails scope
        let state = settingsKeyState key contents
        if state.Value.IsNone then None else Some(encodeSettingsKeyState state)

    let private validateSettingsState
        (environment: HostEnvironment)
        (c: FirewalldModel.Configuration)
        scope
        candidate
        =
        let key, removeEmptyFile, legacyVendorSeedHash = settingsScopeDetails scope
        if c.Kind <> "settings" || FirewalldModel.settingKey c <> key then
            fail "Firewalld settings transaction scope does not match its resource."
        let state =
            candidate
            |> Option.map (parseSettingsKeyState key)
            |> Option.defaultValue { Value = None; Line = None }
        let current = readSettingsFile environment strictConfigPath
        let merged = setSettingLine (defaultArg current "") key state.Line
        let legacySeedMatches =
            legacyVendorSeedHash
            |> Option.exists (fun hash -> settingsContentHash merged = hash)
        let proposed =
            if current.IsNone && state.Value.IsNone then None
            elif removeEmptyFile && state.Value.IsNone && (merged = "" || legacySeedMatches) then None
            else Some merged
        // The same permanent selectors can classify SSH differently under the
        // old and new DefaultZone. Both must be safe before arming recovery.
        if key = "DefaultZone" && effectiveSettingValue key current <> effectiveSettingValue key proposed then
            validateSettingsCandidate environment c key current
        validateSettingsCandidate environment c key proposed

    let private writeSettingsState
        (environment: HostEnvironment)
        (c: FirewalldModel.Configuration)
        scope
        expected
        target
        mode
        =
        let key, removeEmptyFile, legacyVendorSeedHash = settingsScopeDetails scope
        if c.Kind <> "settings" || FirewalldModel.settingKey c <> key then
            fail "Firewalld settings transaction scope does not match its resource."
        let current = readSettingsFile environment strictConfigPath
        settingsFileMode environment current |> ignore
        if readSettingsState environment scope current <> expected then
            fail "The owned firewalld setting changed during key-scoped write; refusing to overwrite it."
        let state =
            target
            |> Option.map (parseSettingsKeyState key)
            |> Option.defaultValue { Value = None; Line = None }
        let merged = setSettingLine (defaultArg current "") key state.Line
        let legacySeedMatches =
            legacyVendorSeedHash
            |> Option.exists (fun hash -> settingsContentHash merged = hash)
        let proposed =
            if current.IsNone && state.Value.IsNone then None
            elif removeEmptyFile && state.Value.IsNone && (merged = "" || legacySeedMatches) then None
            else Some merged
        writeSettingsFile environment proposed mode
    let private settingsRollbackProof key loadedValue source =
        let proof = JsonObject()
        proof["version"] <- JsonValue.Create 1
        proof["key"] <- JsonValue.Create(key: string)
        proof["loadedValue"] <- JsonValue.Create(loadedValue: string)
        proof["source"] <- JsonValue.Create(source: string)
        proof

    let private settingsActivationValue (environment: HostEnvironment) key (journal: JsonObject option) =
        let currentGeneration = firewalldDaemonIdentity environment |> Option.map fst
        journal
        |> Option.bind (fun value ->
            match value["settingsActivation"], currentGeneration with
            | :? JsonObject as proof, Some generation
                when proof.ContainsKey "generation"
                     && proof["version"].GetValue<int>() = 1
                     && getString proof "key" = key
                     && getString proof "generation" = generation ->
                if firewalldDaemonIdentity environment |> Option.exists (fun (current, _) -> current = generation) then
                    optionalString proof "value"
                else None
            | _ -> None)

    let private recordSettingsActivation
        (environment: HostEnvironment)
        c key value source
        (journal: JsonObject)
        =
        match firewalldDaemonIdentity environment |> Option.map fst with
        | Some generation ->
            let receipt = JsonObject()
            receipt["version"] <- JsonValue.Create 1
            receipt["key"] <- JsonValue.Create(key: string)
            receipt["value"] <- JsonValue.Create(value: string)
            receipt["source"] <- JsonValue.Create(source: string)
            receipt["generation"] <- JsonValue.Create(generation: string)
            journal["settingsActivation"] <- receipt
            saveJournal environment c journal
        | None when settingRuntimeObservable key -> ()
        | None -> fail "Cannot record activation without a verifiable firewalld daemon generation."

    let private settingsLoadedEvidence environment key journal etcContents =
        match settingsActivationValue environment key journal with
        | Some value -> Some(value, "completed-activation-receipt")
        | None ->
            settingsStartupLoadedValue environment key etcContents
            |> Option.map (fun (value, _) -> value, "verified-daemon-start")


    let private restoreSettingsRuntime
        (environment: HostEnvironment)
        (transaction: FirewalldLifecycle.PendingTransaction)
        (phase: FirewalldLifecycle.RecoveryPhase)
        =
        if transaction.ActivationStarted && phase <> FirewalldLifecycle.BootBeforeFirewalld then
            let proof =
                transaction.RollbackProof
                |> Option.defaultWith (fun () -> fail "Settings recovery has no durable loaded-state proof.")
            let keys = proof |> Seq.map (fun pair -> pair.Key) |> Set.ofSeq
            if keys <> set [ "version"; "key"; "loadedValue"; "source" ] || proof["version"].GetValue<int>() <> 1 then
                fail "Invalid key-scoped firewalld settings rollback proof."
            let key = getString proof "key"
            let loadedValue = getString proof "loadedValue"
            if transaction.Configuration.Kind <> "settings" || key <> FirewalldModel.settingKey transaction.Configuration then
                fail "Firewalld settings rollback proof does not match its resource."
            let current = readSettingsFile environment strictConfigPath
            let permanent = effectiveSettingValue key current
            if not (settingValuesEqual key permanent (Some loadedValue)) then
                fail ("Cannot restore loaded " + key + " without replacing its proven permanent preimage.")
            match phase with
            | FirewalldLifecycle.ActiveDaemon ->
                requireReloadProof environment
                activateSettings environment key
            | FirewalldLifecycle.BootAfterFirewalld ->
                if not (daemonActive environment) then fail "firewalld is not active at post-boot settings recovery."
                let loaded =
                    if settingRuntimeObservable key then runtimeSettingValue environment key
                    else settingsStartupLoadedValue environment key current |> Option.map fst
                match loaded with
                | Some actual when settingValuesEqual key (Some actual) (Some loadedValue) -> ()
                | Some _ -> fail ("The post-boot loaded " + key + " effect does not match the rollback proof.")
                | None -> fail ("Unable to verify the post-boot loaded " + key + " effect.")
            | FirewalldLifecycle.BootBeforeFirewalld -> ()

    let private restoreSettingsRuntimeWithJournal
        (environment: HostEnvironment)
        (transaction: FirewalldLifecycle.PendingTransaction)
        (phase: FirewalldLifecycle.RecoveryPhase)
        (journal: JsonObject option)
        =
        restoreSettingsRuntime environment transaction phase
        if phase <> FirewalldLifecycle.BootBeforeFirewalld && transaction.ActivationStarted then
            let proof = transaction.RollbackProof |> Option.get
            let key = getString proof "key"
            let loadedValue = getString proof "loadedValue"
            match journal with
            | Some value -> recordSettingsActivation environment transaction.Configuration key loadedValue "rollback-activation" value
            | None when transaction.ReleaseOnRollback -> ()
            | None -> fail "Firewalld settings owner journal disappeared during rollback."

    let private validateSettingsConfirmation (environment: HostEnvironment) key (journal: JsonObject) =
        let pending =
            match journal["pending"] with
            | :? JsonObject as value -> value
            | _ -> fail "No firewalld settings transaction awaits confirmation."
        let scope =
            match pending["scope"] with
            | :? JsonObject as value -> Some value
            | _ -> fail "Firewalld settings confirmation has no key scope."
        let scopedKey, _, _ = settingsScopeDetails scope
        if scopedKey <> key then fail "Firewalld settings confirmation scope does not match its key."
        let after = optionalString pending "after"
        let current = readSettingsFile environment strictConfigPath
        if readSettingsState environment scope current <> after then
            fail "The owned firewalld setting changed before confirmation."
        if not (daemonActive environment) then fail "firewalld is not active at settings confirmation."
        let expected = effectiveSettingValue key current
        if settingRuntimeObservable key then
            match expected, runtimeSettingValue environment key with
            | Some expectedValue, Some actualValue when settingValuesEqual key (Some expectedValue) (Some actualValue) -> ()
            | Some _, Some _ -> fail ("Loaded " + key + " effect changed before fresh-connection confirmation.")
            | _ -> fail ("Unable to observe the loaded " + key + " effect at confirmation.")
        elif not (settingsActivationValue environment key (Some journal) |> Option.exists (fun value -> settingValuesEqual key (Some value) expected)) then
            fail ("No completed activation receipt proves the loaded " + key + " effect at confirmation.")

    let private settingsSnapshot (environment: HostEnvironment) (owner: string) (c: FirewalldModel.Configuration) key desired =
        let etcContents = readSettingsFile environment strictConfigPath
        let effective = etcContents
        let permanentValue = effectiveSettingValue key etcContents
        let runtimeValue = runtimeSettingValue environment key
        let currentState = settingsKeyState key etcContents
        let currentMode = settingsFileMode environment etcContents
        let journal = loadJournal environment c owner
        let pendingNode =
            journal
            |> Option.bind (fun value ->
                match value["pending"] with
                | :? JsonObject as pending -> Some pending
                | _ -> None)
        let pending = pendingNode.IsSome || pendingFor environment c
        let keyScoped =
            (journal
             |> Option.exists (fun value ->
                 value.ContainsKey "settingsScopeVersion"
                 && value["settingsScopeVersion"].GetValue<int>() = 1))
            || (pendingNode
                |> Option.exists (fun value -> value["scope"] :? JsonObject))
        let managedContents =
            match pendingNode with
            | Some value when value.ContainsKey "managedAfter" -> optionalString value "managedAfter"
            | _ -> journal |> Option.bind (fun value -> optionalString value "managed")
        let managedState = managedSettingState key keyScoped managedContents
        let managedMatches =
            journal.IsSome && settingValuesEqual key currentState.Value managedState.Value
        let expectedMode =
            match pendingNode with
            | Some value when value.ContainsKey "afterMode" -> Some(value["afterMode"].GetValue<int>())
            | _ ->
                journal
                |> Option.bind (fun value ->
                    if value.ContainsKey "managedMode" && not (isNull value["managedMode"]) then
                        Some(value["managedMode"].GetValue<int>())
                    elif key = "StrictForwardPorts" && FirewalldLifecycle.preMetadataJournal value then
                        optionalString value "baseline" |> Option.map (fun text -> (parseSettingsBaseline key text).Mode)
                    else None)
        let modeMatches =
            if journal.IsNone then false
            elif managedState.Value.IsNone then true
            else
                match expectedMode, etcContents with
                | Some _, None -> false
                | Some expected, Some _ -> expected = currentMode
                | _ -> false
        let active = daemonActive environment
        let permanentInSync =
            managedMatches && modeMatches && settingValuesEqual key permanentValue (Some desired)
        let runtimeInSync = runtimeValue |> Option.exists (fun actual -> settingValuesEqual key (Some actual) (Some desired))
        let runtimeObserved = runtimeValue.IsSome
        let loadedEvidence = settingsLoadedEvidence environment key journal etcContents
        let activationReceipt =
            managedMatches
            && modeMatches
            && (loadedEvidence |> Option.exists (fun (actual, _) -> settingValuesEqual key (Some actual) (Some desired)))
        let inSync =
            not pending
            && permanentInSync
            && active
            && (if settingRuntimeObservable key then runtimeInSync else activationReceipt)
        let result = JsonObject()
        result["exists"] <- JsonValue.Create effective.IsSome
        result["actual"] <- JsonValue.Create(defaultArg permanentValue "")
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
            else
                match loadedEvidence with
                | Some(_, "verified-daemon-start") -> "trusted pre-start system configuration/default and current daemon generation; packet behavior not probed"
                | Some _ -> "activation receipt verified for current firewalld generation; packet behavior not probed"
                | None -> "no loaded-value getter or verified activation proof; packet behavior unknown"
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
        let readState = readSettingsState environment
        let writeState = writeSettingsState environment c
        let validateState = validateSettingsState environment c
        let mutable activeJournal: JsonObject option = None
        let restoreRuntime transaction recoveryPhase =
            restoreSettingsRuntimeWithJournal environment transaction recoveryPhase activeJournal
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
            FirewalldLifecycle.confirm environment c journal nonce readState
            JsonObject() :> JsonNode
        elif operation = "apply" || operation = "delete" then
            use _lock = HostFiles.lockFile lockFile
            let existingJournal = loadMutationJournal environment c owner operation
            if operation = "delete" && existingJournal.IsNone then
                let unchanged = JsonObject()
                unchanged["unchanged"] <- JsonValue.Create true
                unchanged :> JsonNode
            else
                firewall environment [ "--state" ] |> ignore
                activeJournal <- existingJournal
                existingJournal
                |> Option.iter (fun journal ->
                    FirewalldLifecycle.recover environment c journal strictConfigPath readState writeState restoreRuntime)
                let recoveredJournal =
                    if existingJournal.IsSome then loadJournal environment c owner
                    else None
                activeJournal <- recoveredJournal
                if operation = "delete" && recoveredJournal.IsNone then
                    let unchanged = JsonObject()
                    unchanged["unchanged"] <- JsonValue.Create true
                    unchanged :> JsonNode
                else
                    let current = readSettingsFile environment strictConfigPath
                    let currentMode = settingsFileMode environment current
                    let isNewOwner = recoveredJournal.IsNone
                    let journal =
                        match recoveredJournal with
                        | Some value -> value
                        | None ->
                            let baselineState = settingsKeyState key current
                            let origin = settingsOriginForNewOwner environment c current
                            let baselineText =
                                encodeSettingsBaseline key current.IsSome baselineState currentMode origin
                            let value = newJournal owner (Some baselineText)
                            value["settingsScopeVersion"] <- JsonValue.Create 1
                            setOptional value "managed" (Some(encodeSettingsKeyState baselineState))
                            value
                    activeJournal <- Some journal
                    let baselineText =
                        optionalString journal "baseline"
                        |> Option.defaultWith (fun () -> fail "Missing firewalld settings ownership baseline.")
                    let baseline = parseSettingsBaseline key baselineText
                    let keyScoped =
                        journal.ContainsKey "settingsScopeVersion"
                        && journal["settingsScopeVersion"].GetValue<int>() = 1
                    let storedManaged = optionalString journal "managed"
                    let managedState = managedSettingState key keyScoped storedManaged
                    let baselineNode = JsonNode.Parse(baselineText).AsObject()
                    let baselineVersion =
                        if baselineNode.ContainsKey "version" then baselineNode["version"].GetValue<int>()
                        else 0
                    let mutable journalChanged = false
                    if not keyScoped || baselineVersion <> 4 then
                        let compact =
                            encodeSettingsBaseline key baseline.Exists
                                { Value = baseline.Value; Line = baseline.Line }
                                baseline.Mode baseline.Origin
                        setOptional journal "baseline" (Some compact)
                        setOptional journal "managed" (Some(encodeSettingsKeyState managedState))
                        journal["settingsScopeVersion"] <- JsonValue.Create 1
                        if journal.ContainsKey "deleteOnConfirm" then journal.Remove "deleteOnConfirm" |> ignore
                        journalChanged <- true
                    if current.IsSome && managedState.Value.IsNone then
                        if not (journal.ContainsKey "managedMode")
                           || isNull journal["managedMode"]
                           || journal["managedMode"].GetValue<int>() <> currentMode then
                            journal["managedMode"] <- JsonValue.Create currentMode
                            journalChanged <- true
                    elif current.IsSome then
                        if journal.ContainsKey "managedMode" && not (isNull journal["managedMode"]) then
                            if journal["managedMode"].GetValue<int>() <> currentMode then
                                fail "Owned firewalld.conf mode changed independently; refusing to mutate it."
                        elif baseline.Mode = currentMode then
                            journal["managedMode"] <- JsonValue.Create currentMode
                            journalChanged <- true
                        else
                            fail "Firewalld settings ownership mode is unknown; refusing to mutate firewalld.conf."
                    let managedContents = optionalString journal "managed"
                    let managedState = managedSettingState key true managedContents
                    let currentState = settingsKeyState key current
                    let managedMatches = settingValuesEqual key currentState.Value managedState.Value
                    let effectiveNow = effectiveSettingValue key current
                    let runtimeValue = runtimeSettingValue environment key
                    let priorEvidence = settingsLoadedEvidence environment key (Some journal) current
                    let priorReceipt = priorEvidence |> Option.map fst
                    let otherOwnersRemain = not (settingsJournalFiles environment c).IsEmpty
                    let removeEmptyFile = not baseline.Origin.EtcExisted && not otherOwnersRemain
                    let scope = settingsScope key removeEmptyFile baseline.Origin.LegacyVendorSeedHash
                    if operation = "apply" then
                        let candidate =
                            if settingValuesEqual key effectiveNow (Some desired) then current
                            else Some(setSettingValue (defaultArg current "") key (Some desired))
                        let candidateState = settingsKeyState key candidate
                        let currentProjected = readState scope current
                        let candidateProjected = readState scope candidate
                        let effectiveAfter = effectiveSettingValue key candidate
                        let runtimeMatches =
                            runtimeValue
                            |> Option.exists (fun actual -> settingValuesEqual key (Some actual) (Some desired))
                        let receiptMatches =
                            priorReceipt
                            |> Option.exists (fun actual -> settingValuesEqual key (Some actual) (Some desired))
                        let needsTransaction =
                            isNewOwner
                            || journalChanged
                            || currentProjected <> candidateProjected
                            || not managedMatches
                            || (settingRuntimeObservable key && not runtimeMatches)
                            || (not (settingRuntimeObservable key) && not receiptMatches)
                        if not needsTransaction then
                            let unchanged = JsonObject()
                            unchanged["unchanged"] <- JsonValue.Create true
                            unchanged :> JsonNode
                        else
                            let loadedValue, proofSource =
                                if settingRuntimeObservable key then
                                    match runtimeValue, effectiveNow with
                                    | Some actual, Some permanent when settingValuesEqual key (Some actual) (Some permanent) ->
                                        actual, "observed-runtime"
                                    | Some _, Some _ ->
                                        fail ("Cannot safely mutate " + key + " while its loaded value differs from the permanent preimage.")
                                    | None, _ ->
                                        fail ("Cannot observe the previous loaded " + key + " value for a safe transaction.")
                                    | _, None ->
                                        fail ("Cannot establish the previous effective " + key + " value for a safe transaction.")
                                else
                                    match priorEvidence with
                                    | Some(value, source) when settingValuesEqual key (Some value) effectiveNow -> value, source
                                    | _ ->
                                        fail ("Cannot safely change unobservable " + key + " without a current-generation activation receipt or trusted pre-start configuration.")
                            let attribution =
                                if settingValuesEqual key currentState.Value managedState.Value then "managed"
                                elif settingValuesEqual key currentState.Value baseline.Value then "baseline"
                                else "owned-key-drift"
                            let rollbackProof =
                                settingsRollbackProof key loadedValue (proofSource + ":" + attribution)
                            let afterMode =
                                match candidate, current with
                                | Some _, Some _ -> currentMode
                                | Some _, None when journal.ContainsKey "managedMode" && not (isNull journal["managedMode"]) ->
                                    journal["managedMode"].GetValue<int>()
                                | Some _, None -> 0o600
                                | None, _ -> currentMode
                            requireReloadProof environment
                            requireLoadedSecuritySettings environment None
                            let nonce =
                                FirewalldLifecycle.transact
                                    environment c journal isNewOwner false strictConfigPath scope
                                    currentProjected currentMode candidateProjected afterMode
                                    managedContents (Some(encodeSettingsKeyState candidateState))
                                    (Some rollbackProof) readState writeState validateState
                                    (fun () -> activateSettings environment key) restoreRuntime
                            let activatedValue =
                                effectiveAfter
                                |> Option.defaultWith (fun () -> fail ("Unable to establish activated " + key + " value."))
                            recordSettingsActivation environment c key activatedValue "completed-activation" journal
                            let result = settingsSnapshot environment owner c key desired |> fun value -> value.AsObject()
                            result["transactionNonce"] <- JsonValue.Create nonce
                            result :> JsonNode
                    else
                        let restoredText = setSettingLine (defaultArg current "") key baseline.Line
                        let restored =
                            if current.IsNone && baseline.Line.IsNone then None
                            elif removeEmptyFile && restoredText = "" then None
                            else Some restoredText
                        let restoredState = settingsKeyState key restored
                        let beforeProjected = readState scope current
                        let afterProjected = readState scope restored
                        let effectiveAfter = effectiveSettingValue key restored
                        let loadedValue, proofSource =
                            if settingRuntimeObservable key then
                                match runtimeValue, effectiveNow with
                                | Some actual, Some permanent when settingValuesEqual key (Some actual) (Some permanent) ->
                                    actual, "observed-runtime"
                                | Some _, Some _ ->
                                    fail ("Cannot safely delete " + key + " while its loaded value differs from the permanent preimage.")
                                | None, _ ->
                                    fail ("Cannot observe the previous loaded " + key + " value for safe Delete.")
                                | _, None ->
                                    fail ("Cannot establish the previous effective " + key + " value for safe Delete.")
                            else
                                match priorEvidence with
                                | Some(value, source) when settingValuesEqual key (Some value) effectiveNow -> value, source
                                | _ ->
                                    fail ("Cannot safely Delete unobservable " + key + " without a current-generation activation receipt or trusted pre-start configuration.")
                        let attribution =
                            if settingValuesEqual key currentState.Value managedState.Value then "managed"
                            elif settingValuesEqual key currentState.Value baseline.Value then "baseline"
                            else "owned-key-drift"
                        let rollbackProof =
                            settingsRollbackProof key loadedValue (proofSource + ":" + attribution)
                        let afterMode =
                            match restored, current with
                            | Some _, Some _ -> currentMode
                            | Some _, None when baseline.Exists -> baseline.Mode
                            | Some _, None -> 0o600
                            | None, _ -> currentMode
                        requireReloadProof environment
                        requireLoadedSecuritySettings environment None
                        let nonce =
                            FirewalldLifecycle.transact
                                environment c journal false true strictConfigPath scope
                                beforeProjected currentMode afterProjected afterMode
                                managedContents (Some(encodeSettingsKeyState restoredState))
                                (Some rollbackProof) readState writeState validateState
                                (fun () -> activateSettings environment key) restoreRuntime
                        let activatedValue =
                            effectiveAfter
                            |> Option.defaultWith (fun () -> fail ("Unable to establish restored " + key + " value."))
                        recordSettingsActivation environment c key activatedValue "completed-activation" journal
                        let result = JsonObject()
                        result["transactionNonce"] <- JsonValue.Create nonce
                        result :> JsonNode
        else fail "Unsupported firewalld operation."
    let private recoverPendingCore (environment: HostEnvironment) (phase: FirewalldLifecycle.RecoveryPhase) =
        try
            let recover (transaction: FirewalldLifecycle.PendingTransaction) ownerJournal =
                let c = transaction.Configuration
                let journal =
                    match ownerJournal with
                    | Some value -> value
                    | None when transaction.ReleaseOnRollback || (transaction.Status = "confirmed" && transaction.DeleteOnConfirm) ->
                        let value = JsonObject()
                        value["ownerId"] <- JsonValue.Create(transaction.OwnerId)
                        value
                    | None -> fail "Firewalld recovery owner journal is missing."
                let logical = if c.Kind = "settings" then strictConfigPath else objectPath "/etc/firewalld" c.Kind c.Name
                let readState scope contents =
                    if c.Kind = "settings" then readSettingsState environment scope contents
                    else objectReadState scope contents
                let writeState scope expectedCurrent target mode =
                    if c.Kind = "settings" then writeSettingsState environment c scope expectedCurrent target mode
                    else objectWriteState environment c logical scope expectedCurrent target mode
                let restoreRuntime transaction recoveryPhase =
                    if c.Kind = "settings" then restoreSettingsRuntimeWithJournal environment transaction recoveryPhase ownerJournal
                    else restoreObjectRuntime environment c (fun () -> requireLoadedSecuritySettings environment None) transaction recoveryPhase
                FirewalldLifecycle.recoverPendingTransaction
                    environment c journal logical phase readState writeState restoreRuntime
            match phase with
            | FirewalldLifecycle.ActiveDaemon -> FirewalldLifecycle.recoverPending environment recover
            | FirewalldLifecycle.BootBeforeFirewalld -> FirewalldLifecycle.recoverPendingBoot environment recover
            | FirewalldLifecycle.BootAfterFirewalld -> FirewalldLifecycle.recoverPendingPostBoot environment recover
        with :? InvalidOperationException as error ->
            fail error.Message

    let recoverPending (environment: HostEnvironment) =
        recoverPendingCore environment FirewalldLifecycle.ActiveDaemon

    let recoverPendingBoot (environment: HostEnvironment) =
        recoverPendingCore environment FirewalldLifecycle.BootBeforeFirewalld

    let recoverPendingPostBoot (environment: HostEnvironment) =
        recoverPendingCore environment FirewalldLifecycle.BootAfterFirewalld
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
                let nonce = transactionNonce |> Option.defaultWith (fun () -> fail "Firewalld confirmation requires transactionNonce.")
                let transaction =
                    FirewalldLifecycle.pending environment
                    |> Option.defaultWith (fun () -> fail "No global firewalld transaction awaits confirmation.")
                if transaction.OwnerId <> owner || transaction.Nonce <> nonce
                   || FirewalldModel.toJson transaction.Configuration <> FirewalldModel.toJson c then
                    fail "Firewalld confirmation does not match the authenticated pending transaction."
                let deleting = transaction.DeleteOnConfirm
                if deleting then
                    firewall environment [ "--state" ] |> ignore
                    requireRestoredObjectRuntime environment c
                else
                    let observed = snapshot environment c (Some journal)
                    if not (observed["permanentInSync"].GetValue<bool>())
                       || not (observed["runtimeObserved"].GetValue<bool>())
                       || not (observed["runtimeInSync"].GetValue<bool>()) then
                        fail "Firewalld object did not converge before fresh-connection confirmation."
                let readState scope contents = objectReadState scope contents
                try
                    FirewalldLifecycle.confirm environment c journal nonce readState
                with :? InvalidOperationException as error ->
                    fail error.Message
                JsonObject() :> JsonNode
            elif operation = "apply" || operation = "delete" then
                use _lock = HostFiles.lockFile lockFile
                let existingJournal = loadMutationJournal environment c owner operation
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
                    let preflightSettings () = requireLoadedSecuritySettings environment None
                    recover environment c initialJournal preflightSettings
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
                            let nonce = transact environment c journal currentJournal.IsNone false (Some(render c)) desiredMode preflightSettings
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
                            let nonce = transact environment c journal false true baseline baselineMode preflightSettings
                            let result = JsonObject()
                            result["transactionNonce"] <- JsonValue.Create nonce
                            result :> JsonNode
            else fail "Unsupported firewalld operation."
