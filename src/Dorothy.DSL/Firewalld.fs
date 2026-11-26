namespace Dorothy.DSL

open System
open System.Collections.Generic

[<RequireQualifiedAccess>]
type FirewalldTarget = Default | Accept | Drop | Reject | Continue

[<RequireQualifiedAccess>]
type FirewalldTransport = Tcp | Udp | Sctp | Dccp

[<RequireQualifiedAccess>]
type FirewalldFamily = IPv4 | IPv6

[<RequireQualifiedAccess>]
type FirewalldLimitUnit = Second | Minute | Hour | Day

/// One typed native service port or inclusive port range.
type FirewalldPort = private { First: int; Last: int; Transport: FirewalldTransport }

/// One independently scoped original transport and NAT destination.
type FirewalldForwardPort =
    private
        { OriginalPort: FirewalldPort
          DestinationAddress: string option
          DestinationPort: FirewalldPort option }

/// A typed source or destination selector used by zones and rich rules.
type FirewalldSelector =
    private
        { Role: string
          Attribute: string
          Value: string
          Inverted: bool }

type FirewalldPart =
    internal
    | Target of FirewalldTarget
    | Interfaces of string list
    | Services of string list
    | Ports of string list
    | TypedPorts of FirewalldPort list
    | Protocols of string list
    | Masquerade of bool
    | Forward of bool
    | Ingress of string list
    | Egress of string list
    | Priority of int
    | ZoneIngressPriority of int
    | ZoneEgressPriority of int
    | Sources of FirewalldSelector list
    | RichRules of FirewalldModel.Element list
    | ForwardPort of FirewalldForwardPort
    | IcmpBlocks of string list
    | IcmpBlockInversion
    | Short of string
    | Description of string
    | Version of string
    | SourcePorts of FirewalldPort list
    | Includes of string list
    | Helpers of string list
    | Modules of string list
    | ServiceDestination of string option * string option
    | IPSetType of string
    | IPSetOptions of (string * string) list
    | IPSetEntries of string list
    | IcmpDestinations of FirewalldFamily list
    | HelperModule of string
    | HelperFamily of FirewalldFamily
    | HelperPorts of FirewalldPort list

type FirewalldRichRulePart =
    internal
    | RichFamily of FirewalldFamily
    | RichPriority of int
    | RichDestination of FirewalldSelector
    | RichService of string
    | RichPort of FirewalldPort
    | RichSourcePort of FirewalldPort
    | RichProtocol of string
    | RichIcmpType of string
    | RichIcmpBlock of string
    | RichMasquerade
    | RichForwardPort of FirewalldForwardPort
    | RichLog of string option * string option
    | RichNfLog of string option * string option * int option
    | RichAudit
    | RichLimit of int * FirewalldLimitUnit * int option
    | RichTcpMssClamp of int option
    | RichAccept
    | RichReject of string option
    | RichDrop
    | RichMark of string

/// A complete firewalld object, not an additive fragment.
type FirewalldObjectSpec internal (configuration: FirewalldModel.Configuration) =
    member _.Name = configuration.Name
    member _.Kind = configuration.Kind
    member _.Configuration = FirewalldModel.toJson configuration
    member internal _.Value = configuration

/// A fully validated firewalld object graph. Objects are ordered before their declared references.
type FirewalldSpec internal (objects: FirewalldObjectSpec list, strictForwardPorts: bool option) =
    member _.Objects = objects
    member _.StrictForwardPorts = strictForwardPorts

module private FirewalldFormatting =
    let transportName = function
        | FirewalldTransport.Tcp -> "tcp"
        | FirewalldTransport.Udp -> "udp"
        | FirewalldTransport.Sctp -> "sctp"
        | FirewalldTransport.Dccp -> "dccp"

    let familyName = function
        | FirewalldFamily.IPv4 -> "ipv4"
        | FirewalldFamily.IPv6 -> "ipv6"

    let port first last transport =
        if first < 1 || first > 65535 || last < first || last > 65535 then
            invalidArg "port" "Firewalld ports must be between 1 and 65535 and ranges must be ordered."
        { First = first; Last = last; Transport = transport }

    let portValue (value: FirewalldPort) =
        let range =
            if value.First = value.Last then string value.First
            else string value.First + "-" + string value.Last
        range + "/" + transportName value.Transport

    let nativeRange (value: FirewalldPort) =
        if value.First = value.Last then string value.First
        else string value.First + "-" + string value.Last

    let node name attributes text children : FirewalldModel.Element =
        { Name = name
          Attributes = Map.ofList attributes
          Text = text
          Children = children }

    let selectorElement (selector: FirewalldSelector) =
        if selector.Role <> "source" then
            invalidArg "sources" "Only source selectors can be attached to a zone."
        if selector.Inverted then
            invalidArg "sources" "Zone source bindings cannot be inverted."
        let attribute = if selector.Attribute = "mac" then "address" else selector.Attribute
        node selector.Role [ attribute, selector.Value ] None []

    let portElement name (value: FirewalldPort) =
        node name [ "port", nativeRange value; "protocol", transportName value.Transport ] None []

    let forwardPortAttributes (value: FirewalldForwardPort) =
        [ "port", nativeRange value.OriginalPort
          "protocol", transportName value.OriginalPort.Transport ]
        @ (value.DestinationAddress |> Option.map (fun address -> [ "to-addr", address ]) |> Option.defaultValue [])
        @ (value.DestinationPort |> Option.map (fun port -> [ "to-port", nativeRange port ]) |> Option.defaultValue [])

    let forwardPortElement (value: FirewalldForwardPort) =
        node "forward-port" (forwardPortAttributes value) None []
[<Sealed>]
type FirewalldObjectBuilder internal (kind: string, name: string) =
    member _.Yield(value: FirewalldForwardPort) = [ ForwardPort value ]
    member _.Yield(part: FirewalldPart) = [ part ]
    member _.YieldFrom(parts: seq<FirewalldPart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: FirewalldPart list, right: FirewalldPart list) = left @ right
    member _.Delay(body: unit -> FirewalldPart list) = body()
    member _.For(values: seq<'T>, body: 'T -> FirewalldPart list) = values |> Seq.collect body |> Seq.toList
    member _.Run(parts: FirewalldPart list) =
        let mutable configuration = FirewalldModel.empty kind name
        let seen = HashSet<string>(StringComparer.Ordinal)
        let once key =
            if not (seen.Add key) then invalidArg "firewalld" (key + " may only be declared once.")
        let addElements elements =
            configuration <- { configuration with Elements = configuration.Elements @ elements }
        let addAttribute key value =
            configuration <- { configuration with Attributes = Map.add key value configuration.Attributes }
        for part in parts do
            match part with
            | Target value ->
                once "target"
                configuration <-
                    { configuration with
                        Target =
                            match value with
                            | FirewalldTarget.Default -> "default"
                            | FirewalldTarget.Accept -> "ACCEPT"
                            | FirewalldTarget.Drop -> "DROP"
                            | FirewalldTarget.Reject -> if kind = "zone" then "%%REJECT%%" else "REJECT"
                            | FirewalldTarget.Continue -> "CONTINUE" }
            | Interfaces value -> once "interfaces"; configuration <- { configuration with Interfaces = value }
            | Services value -> once "services"; configuration <- { configuration with Services = value }
            | Ports value -> once "ports"; configuration <- { configuration with Ports = value }
            | TypedPorts value ->
                once "ports"
                configuration <- { configuration with Ports = value |> List.map FirewalldFormatting.portValue }
            | Protocols value -> once "protocols"; configuration <- { configuration with Protocols = value }
            | Masquerade value -> once "masquerade"; configuration <- { configuration with Masquerade = value }
            | Forward value -> once "forward"; configuration <- { configuration with Forward = value }
            | Ingress value -> once "ingress"; configuration <- { configuration with Ingress = value }
            | Egress value -> once "egress"; configuration <- { configuration with Egress = value }
            | Priority value -> once "priority"; configuration <- { configuration with Priority = value }
            | ZoneIngressPriority value ->
                once "ingressPriority"
                addAttribute "ingress-priority" (string value)
            | ZoneEgressPriority value ->
                once "egressPriority"
                addAttribute "egress-priority" (string value)
            | Sources values ->
                once "sources"
                addElements (values |> List.map FirewalldFormatting.selectorElement)
            | RichRules values ->
                once "richRules"
                if values |> List.exists (fun element -> isNull (box element) || element.Name <> "rule") then
                    invalidArg "richRules" "Each richRules value must be a complete rich rule element."
                addElements values
            | Short value ->
                once "short"
                addElements [ FirewalldFormatting.node "short" [] (Some value) [] ]
            | Description value ->
                once "description"
                addElements [ FirewalldFormatting.node "description" [] (Some value) [] ]
            | Version value -> once "version"; addAttribute "version" value
            | SourcePorts values ->
                once "sourcePorts"
                addElements (values |> List.map (FirewalldFormatting.portElement "source-port"))
            | Includes values ->
                once "includes"
                addElements (values |> List.map (fun service -> FirewalldFormatting.node "include" [ "service", service ] None []))
            | Helpers values ->
                once "helpers"
                addElements (values |> List.map (fun helper -> FirewalldFormatting.node "helper" [ "name", helper ] None []))
            | Modules values ->
                once "modules"
                addElements (values |> List.map (fun moduleName -> FirewalldFormatting.node "module" [ "name", moduleName ] None []))
            | ServiceDestination(ipv4, ipv6) ->
                once "destination"
                let attributes =
                    (ipv4 |> Option.map (fun value -> [ "ipv4", value ]) |> Option.defaultValue [])
                    @ (ipv6 |> Option.map (fun value -> [ "ipv6", value ]) |> Option.defaultValue [])
                addElements [ FirewalldFormatting.node "destination" attributes None [] ]
            | ForwardPort value ->
                seen.Add "forwardPorts" |> ignore
                addElements [ FirewalldFormatting.forwardPortElement value ]
            | IcmpBlocks values ->
                once "icmpBlocks"
                addElements (values |> List.map (fun name -> FirewalldFormatting.node "icmp-block" [ "name", name ] None []))
            | IcmpBlockInversion ->
                once "icmpBlockInversion"
                addElements [ FirewalldFormatting.node "icmp-block-inversion" [] None [] ]
            | IPSetType value -> once "type"; addAttribute "type" value
            | IPSetOptions values ->
                seen.Add "IPSetOptions" |> ignore
                addElements (values |> List.map (fun (optionName, optionValue) ->
                    FirewalldFormatting.node "option" [ "name", optionName; "value", optionValue ] None []))
            | IPSetEntries values ->
                once "entries"
                addElements (values |> List.map (fun value -> FirewalldFormatting.node "entry" [] (Some value) []))
            | IcmpDestinations values ->
                once "destinations"
                let families = values |> List.distinct
                addElements
                    [ FirewalldFormatting.node
                          "destination"
                          [ "ipv4", if List.contains FirewalldFamily.IPv4 families then "yes" else "no"
                            "ipv6", if List.contains FirewalldFamily.IPv6 families then "yes" else "no" ]
                          None
                          [] ]
            | HelperModule value -> once "module"; addAttribute "module" value
            | HelperFamily value -> once "family"; addAttribute "family" (FirewalldFormatting.familyName value)
            | HelperPorts values ->
                once "ports"
                configuration <- { configuration with Ports = values |> List.map FirewalldFormatting.portValue }
        let allowed =
            match kind with
            | "zone" ->
                set [ "target"; "interfaces"; "services"; "ports"; "protocols"; "masquerade"; "forward"
                      "sources"; "sourcePorts"; "ingressPriority"; "egressPriority"; "richRules"; "forwardPorts"; "icmpBlocks"; "icmpBlockInversion"
                      "short"; "description"; "version" ]
            | "policy" ->
                set [ "target"; "ingress"; "egress"; "priority"; "masquerade"; "services"; "ports"
                      "protocols"; "sourcePorts"; "richRules"; "forwardPorts"; "icmpBlocks"; "short"; "description"; "version" ]
            | "service" ->
                set [ "short"; "description"; "version"; "ports"; "protocols"; "sourcePorts"; "includes"
                      "helpers"; "modules"; "destination" ]
            | "ipset" -> set [ "short"; "description"; "version"; "type"; "IPSetOptions"; "entries" ]
            | "icmptype" -> set [ "short"; "description"; "version"; "destinations" ]
            | "helper" -> set [ "short"; "description"; "version"; "module"; "family"; "ports" ]
            | _ -> Set.empty
        if not (Set.contains kind (set [ "zone"; "policy"; "service"; "ipset"; "icmptype"; "helper" ])) then
            invalidArg "kind" "Unsupported firewalld object kind."
        if seen |> Seq.exists (fun key -> not (allowed.Contains key)) then
            invalidArg "firewalld" ("Unsupported field for " + kind + ".")
        FirewalldObjectSpec(FirewalldModel.validate configuration)

type FirewalldRichRuleBuilder internal () =
    member _.Yield(part: FirewalldRichRulePart) = [ part ]
    member _.Yield(selector: FirewalldSelector) = [ RichDestination selector ]
    member _.Yield(forwardPort: FirewalldForwardPort) = [ RichForwardPort forwardPort ]
    member _.YieldFrom(parts: seq<FirewalldRichRulePart>) = Seq.toList parts
    member _.YieldFrom(selectors: seq<FirewalldSelector>) = selectors |> Seq.map RichDestination |> Seq.toList
    member _.Zero() = []
    member _.Combine(left: FirewalldRichRulePart list, right: FirewalldRichRulePart list) = left @ right
    member _.Delay(body: unit -> FirewalldRichRulePart list) = body()
    member _.For(values: seq<'T>, body: 'T -> FirewalldRichRulePart list) = values |> Seq.collect body |> Seq.toList
    member _.Run(parts: FirewalldRichRulePart list) =
        let mutable family: FirewalldFamily option = None
        let mutable priority: int option = None
        let children = ResizeArray<FirewalldModel.Element option>()
        let mutable source: FirewalldSelector option = None
        let mutable sourceIndex: int option = None
        let mutable destination: FirewalldSelector option = None
        let mutable destinationIndex: int option = None
        let mutable actionSeen = false
        let mutable limitIndex: int option = None
        let once fieldName existing =
            if Option.isSome existing then invalidArg "richRule" (fieldName + " may only be declared once.")
        let addChild node =
            children.Add(Some node)
            limitIndex <- None
        let addLimitableChild node =
            children.Add(Some node)
            limitIndex <- Some(children.Count - 1)
        let setSelector role selector =
            if selector.Role <> role then invalidArg "richRule" "A selector was used in the wrong position."
            if role = "source" then
                once "source" source
                source <- Some selector
                sourceIndex <- Some children.Count
            else
                once "destination" destination
                destination <- Some selector
                destinationIndex <- Some children.Count
            children.Add None
            limitIndex <- None
        let setAction node supportsLimit =
            if actionSeen then invalidArg "richRule" "A rich rule may declare only one terminal action."
            actionSeen <- true
            if supportsLimit then addLimitableChild node else addChild node
        let limitNode rate unit burst =
            let suffix =
                match unit with
                | FirewalldLimitUnit.Second -> "s"
                | FirewalldLimitUnit.Minute -> "m"
                | FirewalldLimitUnit.Hour -> "h"
                | FirewalldLimitUnit.Day -> "d"
            let attributes =
                [ "value", string rate + "/" + suffix ]
                @ (burst |> Option.map (fun value -> [ "burst", string value ]) |> Option.defaultValue [])
            FirewalldFormatting.node "limit" attributes None []
        for part in parts do
            match part with
            | RichFamily value -> once "family" family; family <- Some value
            | RichPriority value -> once "priority" priority; priority <- Some value
            | RichDestination selector -> setSelector selector.Role selector
            | RichService value -> addChild (FirewalldFormatting.node "service" [ "name", value ] None [])
            | RichPort value -> addChild (FirewalldFormatting.portElement "port" value)
            | RichSourcePort value -> addChild (FirewalldFormatting.portElement "source-port" value)
            | RichProtocol value -> addChild (FirewalldFormatting.node "protocol" [ "value", value ] None [])
            | RichIcmpType value -> addChild (FirewalldFormatting.node "icmp-type" [ "name", value ] None [])
            | RichIcmpBlock value -> addChild (FirewalldFormatting.node "icmp-block" [ "name", value ] None [])
            | RichMasquerade ->
                setAction (FirewalldFormatting.node "masquerade" [] None []) false
            | RichForwardPort value ->
                setAction (FirewalldFormatting.forwardPortElement value) false
            | RichLog(level, prefix) ->
                let attributes =
                    (level |> Option.map (fun value -> [ "level", value ]) |> Option.defaultValue [])
                    @ (prefix |> Option.map (fun value -> [ "prefix", value ]) |> Option.defaultValue [])
                addLimitableChild (FirewalldFormatting.node "log" attributes None [])
            | RichNfLog(group, prefix, queueSize) ->
                let attributes =
                    (group |> Option.map (fun value -> [ "group", value ]) |> Option.defaultValue [])
                    @ (prefix |> Option.map (fun value -> [ "prefix", value ]) |> Option.defaultValue [])
                    @ (queueSize |> Option.map (fun value -> [ "queue-size", string value ]) |> Option.defaultValue [])
                addLimitableChild (FirewalldFormatting.node "nflog" attributes None [])
            | RichAudit -> addLimitableChild (FirewalldFormatting.node "audit" [] None [])
            | RichTcpMssClamp value ->
                let attributes = value |> Option.map (fun size -> [ "value", string size ]) |> Option.defaultValue []
                addChild (FirewalldFormatting.node "tcp-mss-clamp" attributes None [])
            | RichLimit(rate, unit, burst) ->
                match limitIndex with
                | Some index ->
                    match children[index] with
                    | Some parent when parent.Children.IsEmpty ->
                        children[index] <- Some { parent with Children = [ limitNode rate unit burst ] }
                        limitIndex <- None
                    | _ -> invalidArg "richRule" "Limit must follow a log, audit, or terminal action and may only be declared once."
                | None -> invalidArg "richRule" "Limit must follow a log, audit, or terminal action."
            | RichAccept -> setAction (FirewalldFormatting.node "accept" [] None []) true
            | RichReject rejectType ->
                let attributes = rejectType |> Option.map (fun value -> [ "type", value ]) |> Option.defaultValue []
                setAction (FirewalldFormatting.node "reject" attributes None []) true
            | RichDrop -> setAction (FirewalldFormatting.node "drop" [] None []) true
            | RichMark value -> setAction (FirewalldFormatting.node "mark" [ "set", value ] None []) true
        let selectorNode role (selector: FirewalldSelector) =
            let attributes =
                [ selector.Attribute, selector.Value ]
                @ (if selector.Inverted then [ "invert", "true" ] else [])
            FirewalldFormatting.node role attributes None []
        let completedChildren =
            children
            |> Seq.mapi (fun index child ->
                match child with
                | Some value -> value
                | None when sourceIndex = Some index -> selectorNode "source" source.Value
                | None when destinationIndex = Some index -> selectorNode "destination" destination.Value
                | None -> invalidOp "A rich-rule selector placeholder was not completed.")
            |> Seq.toList
        let childRank name =
            match name with
            | "source" | "destination" -> 0
            | "service" | "port" | "protocol" | "tcp-mss-clamp" | "icmp-block" | "icmp-type" | "masquerade" | "forward-port" | "source-port" -> 1
            | "log" | "nflog" -> 2
            | "audit" -> 3
            | "accept" | "reject" | "drop" | "mark" -> 4
            | _ -> invalidArg "richRule" ("Unsupported rich-rule child '" + name + "'.")
        let mutable previousRank = -1
        for child in completedChildren do
            let rank = childRank child.Name
            if rank < previousRank then invalidArg "richRule" "Rich-rule selectors, elements, logging, audit, and actions must stay in native order."
            previousRank <- rank
        let attributes =
            (family |> Option.map (fun value -> [ "family", FirewalldFormatting.familyName value ]) |> Option.defaultValue [])
            @ (priority |> Option.map (fun value -> [ "priority", string value ]) |> Option.defaultValue [])
        FirewalldFormatting.node "rule" attributes None completedChildren

[<RequireQualifiedAccess>]
type FirewalldDeclaration =
    | Object of FirewalldObjectSpec
    | StrictForwardPorts of bool

module internal FirewalldGraph =
    let private interfacePrefix (value: string) =
        if value.EndsWith("+", StringComparison.Ordinal) then value.Substring(0, value.Length - 1) else value

    let interfaceSelectorsOverlap (left: string) (right: string) =
        let leftWildcard = left.EndsWith("+", StringComparison.Ordinal)
        let rightWildcard = right.EndsWith("+", StringComparison.Ordinal)
        match leftWildcard, rightWildcard with
        | false, false -> String.Equals(left, right, StringComparison.Ordinal)
        | true, false -> right.StartsWith(interfacePrefix left, StringComparison.Ordinal)
        | false, true -> left.StartsWith(interfacePrefix right, StringComparison.Ordinal)
        | true, true ->
            let leftPrefix = interfacePrefix left
            let rightPrefix = interfacePrefix right
            leftPrefix.StartsWith(rightPrefix, StringComparison.Ordinal)
            || rightPrefix.StartsWith(leftPrefix, StringComparison.Ordinal)

    let private sourceBindingKey (element: FirewalldModel.Element) =
        element.Attributes |> Map.toList |> List.sortBy fst

    let private objectRank = function
        | "zone" -> 0
        | "settings" -> 1
        | "service" | "ipset" | "icmptype" | "helper" -> 2
        | "policy" -> 3
        | _ -> 4

    let orderObjects (objects: FirewalldObjectSpec list) =
        let byIdentity = objects |> List.map (fun item -> (item.Kind, item.Name), item) |> Map.ofList
        let state = Dictionary<string * string, int>()
        let ordered = ResizeArray<FirewalldObjectSpec>()
        let rec visit (item: FirewalldObjectSpec) =
            let identity = item.Kind, item.Name
            match state.TryGetValue identity with
            | true, 2 -> ()
            | true, 1 -> invalidArg "firewalld" (sprintf "Firewalld dependency cycle includes %s '%s'." item.Kind item.Name)
            | _ ->
                state[identity] <- 1
                for kind, name in FirewalldModel.references item.Value |> List.distinct do
                    match Map.tryFind (kind, name) byIdentity with
                    | Some dependency -> visit dependency
                    | None -> () // External definitions are referenced but never owned here.
                state[identity] <- 2
                ordered.Add item
        objects
        |> List.mapi (fun index item -> index, item)
        |> List.sortBy (fun (index, item) -> objectRank item.Kind, index)
        |> List.iter (snd >> visit)
        ordered |> Seq.toList

    /// Native policy constraints that can be determined from this declaration.
    /// Do not assume a backend or an interface list for externally supplied zones.
    let validatePolicyTopology (objects: FirewalldObjectSpec list) =
        let boundZones = objects |> List.choose (fun p -> if p.Kind = "zone" && not p.Value.Interfaces.IsEmpty then Some p.Name else None) |> Set.ofList
        let iptables = objects |> List.exists (fun p -> p.Kind = "settings" && p.Name = "FirewallBackend" && p.Value.SettingValue = Some "iptables")
        for obj in objects do
            if obj.Kind = "policy" then
                let policy = obj.Value
                let contains name = policy.Elements |> List.exists (fun e -> e.Name = name || (e.Name = "rule" && (e.Children |> List.exists (fun child -> child.Name = name))))
                if iptables && (policy.Masquerade || contains "masquerade") && (policy.Ingress |> List.exists boundZones.Contains) then
                    invalidArg "masquerade" "The iptables backend cannot masquerade a policy with interface-bound ingress zones."
                if (contains "forward-port" || contains "mark") && (policy.Egress |> List.exists boundZones.Contains) then
                    invalidArg "egressZones" "A policy forward-port or mark cannot use an interface-bound egress zone."

    let validateUniqueBindings (objects: FirewalldObjectSpec list) =
        let zonePolicyNames = HashSet<string>(StringComparer.Ordinal)
        let interfaceBindings = ResizeArray<string * string>()
        let sourceBindings = HashSet<(string * string) list>()
        for item in objects do
            if item.Kind = "zone" || item.Kind = "policy" then
                if not (zonePolicyNames.Add item.Name) then
                    invalidArg "firewalld" "A zone and policy cannot share a name, and each name may have only one owner."
            for interfaceName in item.Value.Interfaces do
                let overlapsOtherZone =
                    interfaceBindings
                    |> Seq.exists (fun (owner, existing) ->
                        owner <> item.Name && interfaceSelectorsOverlap interfaceName existing)
                if overlapsOtherZone then
                    invalidArg "firewalld" "Overlapping interface selectors cannot be assigned to multiple declared zones."
                interfaceBindings.Add((item.Name, interfaceName))
            if item.Kind = "zone" then
                for element in item.Value.Elements do
                    if element.Name = "source" then
                        let key = sourceBindingKey element
                        if not (sourceBindings.Add key) then
                            invalidArg "firewalld" "A source binding can belong to only one declared zone."

    // Firewalld ANY covers zone-originated traffic but excludes HOST.
    let private overlaps (left: string list) (right: string list) =
        let leftAny = List.contains "ANY" left
        let rightAny = List.contains "ANY" right
        match leftAny, rightAny with
        | true, true -> true
        | true, false -> right |> List.exists (fun value -> value <> "HOST")
        | false, true -> left |> List.exists (fun value -> value <> "HOST")
        | false, false -> left |> List.exists (fun value -> List.contains value right)

    let private hasUnsafePassElement (configuration: FirewalldModel.Configuration) =
        let rec hasUnsafeAction (element: FirewalldModel.Element) =
            List.contains element.Name [ "accept"; "continue"; "forward-port"; "masquerade"; "mark" ]
            || (element.Children |> List.exists hasUnsafeAction)
        configuration.Elements
        |> List.exists (fun element ->
            (element.Name <> "rule" && List.contains element.Name [ "service"; "port"; "protocol"; "source-port" ])
            || hasUnsafeAction element)

    // CONTINUE falls through; only ACCEPT or explicit pass elements can bypass the policy.
    let private mayPass (configuration: FirewalldModel.Configuration) =
        configuration.Target = "ACCEPT"
        || not configuration.Services.IsEmpty
        || not configuration.Ports.IsEmpty
        || not configuration.Protocols.IsEmpty
        || configuration.Masquerade
        || hasUnsafePassElement configuration

    let isEffectiveDockerGuard
        (policies: FirewalldModel.Configuration list)
        (candidate: FirewalldModel.Configuration)
        =
        // A strict-Docker fence stays rule-free so boot can verify the live policy without parsing rich syntax.
        let isBlockingCandidate =
            candidate.Kind = "policy"
            && candidate.Target = "DROP"
            && candidate.Priority < 0
            && List.contains "docker" candidate.Egress
            && not candidate.Ingress.IsEmpty && not (List.contains "HOST" candidate.Ingress)
            && candidate.Services.IsEmpty
            && candidate.Ports.IsEmpty
            && candidate.Protocols.IsEmpty
            && not candidate.Masquerade
            && not (candidate.Elements |> List.exists (fun element -> element.Name = "rule"))
            && not (hasUnsafePassElement candidate)
        let bypassesCandidate =
            policies
            |> List.exists (fun earlier ->
                earlier.Kind = "policy"
                && not (String.Equals(earlier.Name, candidate.Name, StringComparison.Ordinal))
                && earlier.Priority <= candidate.Priority
                && (List.contains "docker" earlier.Egress || List.contains "ANY" earlier.Egress)
                && overlaps earlier.Ingress candidate.Ingress
                && mayPass earlier)
        isBlockingCandidate && not bypassesCandidate

module internal FirewalldGuardUnit =
    let name (hostName: string) = hostName + "-docker-firewall-guard.service"

    let specification (unitName: string) (policies: FirewalldObjectSpec list) =
        let spec = System.Text.Json.Nodes.JsonObject()
        spec["name"] <- System.Text.Json.Nodes.JsonValue.Create unitName
        spec["managed"] <- System.Text.Json.Nodes.JsonValue.Create true
        spec["configuration"] <- System.Text.Json.Nodes.JsonValue.Create ""
        spec["dockerFence"] <- policies |> List.map (fun p -> FirewalldGateModel.ofPolicy p.Value) |> FirewalldGateModel.encode
        spec.ToJsonString()

type FirewalldBuilder internal () =
    member _.Yield(value: FirewalldObjectSpec) = [ FirewalldDeclaration.Object value ]
    member _.Yield(value: FirewalldDeclaration) = [ value ]
    member _.YieldFrom(values: seq<FirewalldObjectSpec>) = values |> Seq.map FirewalldDeclaration.Object |> Seq.toList
    member _.YieldFrom(values: seq<FirewalldDeclaration>) = Seq.toList values
    member _.Zero() = []
    member _.Combine(left: FirewalldDeclaration list, right: FirewalldDeclaration list) = left @ right
    member _.Delay(body: unit -> FirewalldDeclaration list) = body()
    member _.For(values: seq<'T>, body: 'T -> FirewalldDeclaration list) = values |> Seq.collect body |> Seq.toList
    member _.Run(declarations: FirewalldDeclaration list) =
        let values = declarations |> List.choose (function FirewalldDeclaration.Object value -> Some value | _ -> None)
        let settings = declarations |> List.choose (function FirewalldDeclaration.StrictForwardPorts value -> Some value | _ -> None)
        if settings.Length > 1 then invalidArg "firewalld" "strictForwardPorts may be declared only once."
        let names = HashSet<string * string>()
        let identities =
            values
            |> List.map (fun value ->
                let name = value.Name
                let kind =
                    if value.Kind = "zone" || value.Kind = "policy" then "zone-policy"
                    else value.Kind
                kind, name)
        for identity in identities do
            if not (names.Add identity) then invalidArg "firewalld" "Duplicate firewalld object or daemon setting."
        if values |> List.exists (fun value ->
            value.Kind = "settings"
            && FirewalldModel.settingKey value.Value = "StrictForwardPorts") then
            invalidArg "firewalld" "StrictForwardPorts has a legacy resource identity and cannot have a second settings owner."
        FirewalldGraph.validateUniqueBindings values
        FirewalldGraph.validatePolicyTopology values
        FirewalldSpec(FirewalldGraph.orderObjects values, List.tryHead settings)

/// Open this module for the firewalld vocabulary; names do not shadow other host DSLs globally.
module Firewalld =
    let firewalld = FirewalldBuilder()
    let richRule = FirewalldRichRuleBuilder()
    let strictForwardPorts enabled = FirewalldDeclaration.StrictForwardPorts enabled
    let zone name = FirewalldObjectBuilder("zone", name)
    let policy name = FirewalldObjectBuilder("policy", name)
    let ipset name = FirewalldObjectBuilder("ipset", name)
    let icmpType name = FirewalldObjectBuilder("icmptype", name)
    let helper name = FirewalldObjectBuilder("helper", name)
    let setting key value =
        { FirewalldModel.empty "settings" key with SettingValue = Some value }
        |> FirewalldModel.validate
        |> FirewalldObjectSpec
    let target value = Target value
    let interfaces values = Interfaces values
    let services values = Services values
    /// Legacy port syntax retained for existing callers.
    let ports (values: (int * UfwProtocol) list) =
        values
        |> List.collect (fun (number, protocol) ->
            let protocols =
                match protocol with
                | UfwProtocol.Tcp -> [ "tcp" ]
                | UfwProtocol.Udp -> [ "udp" ]
                | UfwProtocol.TcpAndUdp -> [ "tcp"; "udp" ]
            protocols |> List.map (fun protocolName -> sprintf "%d/%s" number protocolName))
        |> Ports
    /// Legacy string ranges retained for existing callers.
    let portRanges values = Ports values
    let tcpPort number = FirewalldFormatting.port number number FirewalldTransport.Tcp
    let udpPort number = FirewalldFormatting.port number number FirewalldTransport.Udp
    let sctpPort number = FirewalldFormatting.port number number FirewalldTransport.Sctp
    let dccpPort number = FirewalldFormatting.port number number FirewalldTransport.Dccp
    let portRange first last transport = FirewalldFormatting.port first last transport
    let tcpPortRange first last = portRange first last FirewalldTransport.Tcp
    let udpPortRange first last = portRange first last FirewalldTransport.Udp
    let sctpPortRange first last = portRange first last FirewalldTransport.Sctp
    let dccpPortRange first last = portRange first last FirewalldTransport.Dccp
    let transportPorts values = TypedPorts values
    let servicePorts values = TypedPorts values
    let sourcePorts values = SourcePorts values
    let protocols values = Protocols values
    let masquerade value = Masquerade value
    let forward value = Forward value
    let ingressZones values = Ingress values
    let egressZones values = Egress values
    let priority value = Priority value
    let sourceAddress value = { Role = "source"; Attribute = "address"; Value = value; Inverted = false }
    let sourceMac value = { Role = "source"; Attribute = "mac"; Value = value; Inverted = false }
    let sourceIPSet value = { Role = "source"; Attribute = "ipset"; Value = value; Inverted = false }
    let destinationAddress value = { Role = "destination"; Attribute = "address"; Value = value; Inverted = false }
    let destinationIPSet value = { Role = "destination"; Attribute = "ipset"; Value = value; Inverted = false }
    let invertSource selector =
        if selector.Role <> "source" then invalidArg "selector" "invertSource requires a source selector."
        { selector with Inverted = true }
    let invertDestination selector =
        if selector.Role <> "destination" then invalidArg "selector" "invertDestination requires a destination selector."
        { selector with Inverted = true }
    let sources values = Sources values
    let icmpBlocks values = IcmpBlocks values
    let icmpBlockInversion = IcmpBlockInversion
    let richRules values = RichRules values
    let short value = Short value
    let version value = Version value
    let includes values = Includes values
    let helpers values = Helpers values
    let modules values = Modules values
    let serviceDestination ipv4 ipv6 = ServiceDestination(ipv4, ipv6)
    let ipsetType value = IPSetType value
    let ipsetOptions values = IPSetOptions values
    let entries values = IPSetEntries values
    let icmpDestinations values = IcmpDestinations values
    let helperModule value = HelperModule value
    let helperFamily value = HelperFamily value
    let helperPorts values = HelperPorts values
    let family value = RichFamily value
    let richPriority value = RichPriority value
    let richService value = RichService value
    let richPort value = RichPort value
    let richSourcePort value = RichSourcePort value
    let richProtocol value = RichProtocol value
    let richIcmpType value = RichIcmpType value
    let richIcmpBlock value = RichIcmpBlock value
    let richMasquerade = RichMasquerade
    let forwardPort original destinationAddress destinationPort =
        match destinationPort with
        | Some value when value.Transport <> original.Transport ->
            invalidArg "destinationPort" "DNAT destination port transport must match the original transport."
        | _ -> ()
        if Option.isNone destinationAddress && Option.isNone destinationPort then
            invalidArg "forwardPort" "A forward-port requires a destination address or port."
        { OriginalPort = original
          DestinationAddress = destinationAddress
          DestinationPort = destinationPort }
    module Defined =
        let service name = FirewalldObjectBuilder("service", name)
        let description value = Description value

    module Zone =
        let ingressPriority value = ZoneIngressPriority value
        let egressPriority value = ZoneEgressPriority value

    module RichRule =
        let log level prefix = RichLog(level, prefix)
        let nflog group prefix queueSize = RichNfLog(group, prefix, queueSize)
        let audit = RichAudit
        let limit rate unit = RichLimit(rate, unit, None)
        let limitBurst rate unit burst = RichLimit(rate, unit, Some burst)
        let accept = RichAccept
        let reject = RichReject None
        let rejectWith rejectType = RichReject(Some rejectType)
        let drop = RichDrop
        let mark value = RichMark value
        let tcpMssClamp = RichTcpMssClamp None
        let tcpMssClampValue value = RichTcpMssClamp(Some value)
