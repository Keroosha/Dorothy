namespace Dorothy.HostHelper

open System
open System.Net
open System.Collections.Generic

module FirewalldRuntime =
    type RuntimeSnapshot =
        { Kind: string
          Name: string
          Target: string
          Priority: int option
          IngressPriority: int option
          EgressPriority: int option
          Ingress: string list
          Egress: string list
          Interfaces: string list
          SourcesRaw: string list
          Sources: FirewalldModel.Element list
          Services: string list
          Ports: string list
          Protocols: string list
          SourcePorts: string list
          ForwardPorts: FirewalldModel.Element list
          Masquerade: bool
          Forward: bool
          IcmpBlocks: string list
          IcmpBlockInversion: bool
          RichRules: string list
          IpSetType: string option
          IpSetOptions: Map<string, string option>
          IpSetEntries: string list
          NativeFields: Map<string, string list>
          UnknownFields: Map<string, string list> }

    type RuntimeObservation =
        { Observed: bool
          InSync: bool }
    let private categories =
        Map.ofList
            [ "zone", 17
              "policy", 18
              "service", 128
              "ipset", 32
              "icmptype", 128
              "helper", 128 ]

    let private run (environment: HostEnvironment) arguments =
        try
            let result = environment.Run "firewall-cmd" arguments None
            if result.ExitCode = 0 then Some result.Stdout else None
        with _ -> None

    let private words (values: string list) =
        values
        |> List.collect (fun (value: string) ->
            value.Split([| ' '; '\t'; '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
            |> Array.toList)

    /// Enumerates runtime-loaded objects, including those without active bindings.
    let listRuntime (environment: HostEnvironment) (kind: string) : string list option =
        let arguments =
            match kind with
            | "zone" -> Some [ "--get-zones" ]
            | "policy" -> Some [ "--get-policies" ]
            | _ -> None
        arguments
        |> Option.bind (fun args -> run environment args)
        |> Option.map (fun output -> words [ output ] |> List.distinct |> List.sort)


    let private parseFields (text: string) : Map<string, string list> =
        let fields = Dictionary<string, ResizeArray<string>>(StringComparer.Ordinal)
        let mutable current = None
        let mutable sawHeader = false
        let addUnparsed value =
            let values =
                match fields.TryGetValue "<unparsed>" with
                | true, existing -> existing
                | _ ->
                    let created = ResizeArray<string>()
                    fields["<unparsed>"] <- created
                    created
            values.Add value
            current <- Some "<unparsed>"
        for sourceLine in text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n') do
            if String.IsNullOrWhiteSpace sourceLine then ()
            elif not sawHeader then
                sawHeader <- true
                current <- None
            elif sourceLine.StartsWith("\t", StringComparison.Ordinal) then
                match current with
                | Some key -> fields[key].Add(sourceLine.Trim())
                | None -> addUnparsed (sourceLine.Trim())
            else
                let line = sourceLine.TrimStart()
                let separator = line.IndexOf(':')
                if separator > 0 then
                    let key = line.Substring(0, separator).Trim()
                    let value = line.Substring(separator + 1).Trim()
                    if fields.ContainsKey key then
                        let duplicateKey = "<duplicate:" + key + ">"
                        let duplicateValues =
                            match fields.TryGetValue duplicateKey with
                            | true, existing -> existing
                            | _ ->
                                let created = ResizeArray<string>()
                                fields[duplicateKey] <- created
                                created
                        if value.Length > 0 then duplicateValues.Add value
                        if value.Length > 0 then fields[key].Add value
                    else
                        let values = ResizeArray<string>()
                        if value.Length > 0 then values.Add value
                        fields[key] <- values
                    current <- Some key
                else
                    addUnparsed line
        fields
        |> Seq.map (fun pair -> pair.Key, List.ofSeq pair.Value)
        |> Map.ofSeq

    let private knownZoneFields =
        set [ "target"; "ingress-priority"; "egress-priority"; "icmp-block-inversion"; "interfaces"; "sources"; "services"; "ports"; "protocols"; "forward"; "masquerade"; "forward-ports"; "source-ports"; "icmp-blocks"; "rich rules" ]

    let private knownPolicyFields =
        set [ "priority"; "target"; "ingress-zones"; "egress-zones"; "services"; "ports"; "protocols"; "masquerade"; "forward-ports"; "source-ports"; "icmp-blocks"; "rich rules" ]

    let private boolField (fields: Map<string, string list>) key =
        match Map.tryFind key fields with
        | Some [ "yes" ] -> Some true
        | Some [ "no" ] -> Some false
        | _ -> None

    let private scalar (fields: Map<string, string list>) key =
        match Map.tryFind key fields with
        | Some [ value ] -> Some value
        | _ -> None

    let private integer (fields: Map<string, string list>) key =
        scalar fields key
        |> Option.bind (fun (value: string) -> match Int32.TryParse value with true, number -> Some number | _ -> None)

    let private element (name: string) (attributes: (string * string) list) : FirewalldModel.Element =
        { Name = name; Attributes = Map.ofList attributes; Text = None; Children = [] }

    let private hexByte (value: string) =
        value.Length = 2 && value |> Seq.forall Uri.IsHexDigit

    let private isMacAddress (value: string) =
        let parts = value.Split(':')
        parts.Length = 6 && (parts |> Array.forall hexByte)

    let private sourceElement (source: string) =
        if source.StartsWith("ipset:", StringComparison.Ordinal) && source.Length > 6 then
            Some(element "source" [ "ipset", source.Substring(6) ])
        elif isMacAddress source then
            Some(element "source" [ "mac", source ])
        else
            let address = source.Split('/')[0]
            match IPAddress.TryParse address with
            | true, _ -> Some(element "source" [ "address", source ])
            | _ -> None

    let private parseForwardPortFields (value: string) =
        let keys = [| "port"; "proto"; "toport"; "toaddr" |]
        let values = Array.zeroCreate<string> keys.Length
        let mutable cursor = 0
        let mutable valid = true
        for index in 0 .. keys.Length - 1 do
            if valid then
                let prefix = (if index = 0 then "" else ":") + keys[index] + "="
                if cursor + prefix.Length > value.Length
                   || value.IndexOf(prefix, cursor, StringComparison.Ordinal) <> cursor then
                    valid <- false
                else
                    let valueStart = cursor + prefix.Length
                    if index = keys.Length - 1 then
                        values[index] <- value.Substring(valueStart)
                        cursor <- value.Length
                    else
                        let marker = ":" + keys[index + 1] + "="
                        let next = value.IndexOf(marker, valueStart, StringComparison.Ordinal)
                        if next < 0 then valid <- false
                        else
                            values[index] <- value.Substring(valueStart, next - valueStart)
                            cursor <- next
        if valid && cursor = value.Length then
            Some(Map.ofArray (Array.zip keys values))
        else None

    let private forwardPortElement (value: string) =
        match parseForwardPortFields value with
        | None -> None
        | Some fields ->
            let port, protocol = Map.find "port" fields, Map.find "proto" fields
            let toPort, toAddress = Map.find "toport" fields, Map.find "toaddr" fields
            let validPort value =
                try FirewalldModel.port (value + "/" + protocol) |> ignore; true
                with _ -> false
            let hasAddress = toAddress <> "" && toAddress <> "None"
            let validAddress = not hasAddress || (match IPAddress.TryParse toAddress with true, _ -> true | _ -> false)
            if port = "" || not (validPort port) || (toPort <> "" && toPort <> "None" && not (validPort toPort))
               || not validAddress || ((toPort = "" || toPort = "None") && not hasAddress) then None
            else
                let attributes =
                    [ yield "port", port
                      yield "protocol", protocol
                      if toPort <> "" && toPort <> "None" then yield "to-port", toPort
                      if toAddress <> "" && toAddress <> "None" then yield "to-addr", toAddress ]
                Some(element "forward-port" attributes)

    let private emptySnapshot (kind: string) (name: string) (unknown: Map<string, string list>) : RuntimeSnapshot =
        { Kind = kind
          Name = name
          Target = ""
          Priority = None
          IngressPriority = None
          EgressPriority = None
          Ingress = []
          Egress = []
          Interfaces = []
          SourcesRaw = []
          Sources = []
          Services = []
          Ports = []
          Protocols = []
          SourcePorts = []
          ForwardPorts = []
          Masquerade = false
          Forward = false
          IcmpBlocks = []
          IcmpBlockInversion = false
          RichRules = []
          IpSetType = None
          IpSetOptions = Map.empty
          IpSetEntries = []
          NativeFields = Map.empty
          UnknownFields = unknown }

    let private unknownFields known (fields: Map<string, string list>) =
        fields |> Map.filter (fun key _ -> not (Set.contains key known))

    let private ipSetOptions (values: string list) =
        let parsed =
            words values
            |> List.choose (fun value ->
                let separator = value.IndexOf('=')
                if separator <= 0 then Some(value, None)
                else Some(value.Substring(0, separator), Some(value.Substring(separator + 1))) )
        let map = Map.ofList parsed
        let malformed = parsed |> List.countBy fst |> List.exists (fun (_, count) -> count > 1)
        map, malformed

    let private validateRuntimeName kind maxLength (name: string) =
        match kind with
        | "zone" | "policy" ->
            FirewalldModel.token "name" maxLength name |> ignore
            if name.Contains('.') then invalidArg "name" "Zone and policy names cannot contain dots."
        | "ipset" ->
            if String.IsNullOrEmpty name
               || name.Length > maxLength
               || not (Char.IsAsciiLetterOrDigit name[0])
               || not (name |> Seq.forall (fun character ->
                    Char.IsAsciiLetterOrDigit character
                    || character = '_' || character = '-' || character = ':' || character = '.')) then
                invalidArg "name" "Invalid ipset name."
        | _ -> invalidArg "kind" "Unsupported runtime object kind."

    /// Read a named runtime object directly. Unlike --get-active-zones, per-object
    /// list-all works for quiet zones and inactive policies. Unknown native fields,
    /// source selectors and rich-rule strings remain explicit for safety callers.
    let inspectRuntime (environment: HostEnvironment) (kind: string) (name: string) : RuntimeSnapshot option =
        try
            match Map.tryFind kind categories with
            | Some maxLength when kind = "ipset" ->
                validateRuntimeName kind maxLength name
                match run environment [ "--info-ipset=" + name ] with
                | None -> None
                | Some output ->
                    let fields = parseFields output
                    let known = set [ "type"; "options"; "entries" ]
                    let mutable unknown = unknownFields known fields
                    for key in known do
                        if not (Map.containsKey key fields) then unknown <- Map.add key [] unknown
                    let typeValue = scalar fields "type"
                    if typeValue.IsNone then unknown <- Map.add "type" (Map.tryFind "type" fields |> Option.defaultValue []) unknown
                    let options, malformedOptions = ipSetOptions (Map.tryFind "options" fields |> Option.defaultValue [])
                    if malformedOptions then unknown <- Map.add "options" (Map.tryFind "options" fields |> Option.defaultValue []) unknown
                    Some
                        { emptySnapshot kind name unknown with
                            IpSetType = typeValue
                            IpSetOptions = options
                            IpSetEntries = Map.tryFind "entries" fields |> Option.defaultValue [] |> words
                            NativeFields = fields }
            | Some maxLength when kind = "zone" || kind = "policy" ->
                validateRuntimeName kind maxLength name
                let selector = if kind = "zone" then "--zone=" + name else "--policy=" + name
                match run environment [ selector; "--list-all" ] with
                | None -> None
                | Some output ->
                    let fields = parseFields output
                    let known = if kind = "zone" then knownZoneFields else knownPolicyFields
                    let rules = Map.tryFind "rich rules" fields |> Option.defaultValue []
                    let sourceValues = if kind = "zone" then Map.tryFind "sources" fields |> Option.defaultValue [] |> words else []
                    let parsedSources = sourceValues |> List.choose sourceElement
                    let sourceUnknown = sourceValues |> List.filter (sourceElement >> Option.isNone)
                    let forwardPortValues = Map.tryFind "forward-ports" fields |> Option.defaultValue []
                    let parsedForwardPorts = forwardPortValues |> List.choose forwardPortElement
                    let forwardPortUnknown = forwardPortValues |> List.filter (forwardPortElement >> Option.isNone)
                    let mutable unknown = unknownFields known fields
                    if not sourceUnknown.IsEmpty then unknown <- Map.add "source-selectors" sourceUnknown unknown
                    if not forwardPortUnknown.IsEmpty then unknown <- Map.add "forward-ports" forwardPortUnknown unknown
                    for key in known do
                        if not (Map.containsKey key fields) then unknown <- Map.add key [] unknown
                    let target = scalar fields "target" |> Option.defaultValue ""
                    let priority = integer fields "priority"
                    let ingressPriority = integer fields "ingress-priority"
                    let egressPriority = integer fields "egress-priority"
                    let icmpInversion = boolField fields "icmp-block-inversion"
                    let forward = boolField fields "forward"
                    let masquerade = boolField fields "masquerade"
                    let scalarUnknown =
                        [ "target", scalar fields "target" |> Option.isNone
                          "priority", (kind = "policy" && priority.IsNone)
                          "ingress-priority", (kind = "zone" && ingressPriority.IsNone)
                          "egress-priority", (kind = "zone" && egressPriority.IsNone)
                          "icmp-block-inversion", (kind = "zone" && icmpInversion.IsNone)
                          "forward", (kind = "zone" && forward.IsNone)
                          "masquerade", masquerade.IsNone ]
                    for key, missing in scalarUnknown do
                        if missing && not (Map.containsKey key unknown) then
                            unknown <- Map.add key (Map.tryFind key fields |> Option.defaultValue []) unknown
                    Some
                        { emptySnapshot kind name unknown with
                            NativeFields = fields
                            Target = target
                            Priority = priority
                            IngressPriority = ingressPriority
                            EgressPriority = egressPriority
                            Ingress = Map.tryFind "ingress-zones" fields |> Option.defaultValue [] |> words
                            Egress = Map.tryFind "egress-zones" fields |> Option.defaultValue [] |> words
                            Interfaces = Map.tryFind "interfaces" fields |> Option.defaultValue [] |> words
                            SourcesRaw = sourceValues
                            Sources = parsedSources
                            Services = Map.tryFind "services" fields |> Option.defaultValue [] |> words
                            Ports = Map.tryFind "ports" fields |> Option.defaultValue [] |> words
                            Protocols = Map.tryFind "protocols" fields |> Option.defaultValue [] |> words
                            SourcePorts = Map.tryFind "source-ports" fields |> Option.defaultValue [] |> words
                            ForwardPorts = parsedForwardPorts
                            Masquerade = defaultArg masquerade false
                            Forward = defaultArg forward false
                            IcmpBlocks = Map.tryFind "icmp-blocks" fields |> Option.defaultValue [] |> words
                            IcmpBlockInversion = defaultArg icmpInversion false
                            RichRules = rules |> List.filter (String.IsNullOrWhiteSpace >> not) }
            | _ -> None
        with _ -> None

    let private listValues (text: string) =
        text.Split([| ' '; '\t'; '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
        |> Array.distinct
        |> Array.sort
        |> Array.toList


    let private listFields =
        set [ "services"; "ports"; "protocols"; "sources"; "ingress-zones"; "egress-zones"; "source-ports"; "icmp-blocks"; "forward-ports"; "modules"; "destination"; "includes"; "helpers"; "options"; "entries" ]

    let private normalizeFields kind (fields: Map<string, string list>) =
        let ignored = set [ "interfaces"; "sources"; "forward-ports"; "rich rules" ]
        fields
        |> Map.filter (fun key _ -> not (Set.contains key ignored))
        |> Map.map (fun key values ->
            if key = "target" then values |> List.map (fun value -> if value = "%%REJECT%%" then "REJECT" else value)
            elif Set.contains key listFields then words values |> List.distinct |> List.sort
            else values)

    let private field key values =
        key, (if List.isEmpty values then [] else [ String.concat " " values ])

    let private directElements (c: FirewalldModel.Configuration) name =
        c.Elements |> List.filter (fun element -> element.Name = name)

    let private elementAttribute key (element: FirewalldModel.Element) =
        Map.tryFind key element.Attributes

    let private requiredElementAttribute key element =
        elementAttribute key element
        |> Option.defaultWith (fun () -> invalidOp ("Missing native element attribute " + key))

    let private elementValues name key (c: FirewalldModel.Configuration) =
        directElements c name |> List.map (requiredElementAttribute key)

    let private sourceValue (source: FirewalldModel.Element) =
        match Map.tryFind "address" source.Attributes, Map.tryFind "mac" source.Attributes, Map.tryFind "ipset" source.Attributes with
        | Some value, None, None -> value
        | None, Some value, None -> value
        | None, None, Some value -> "ipset:" + value
        | _ -> invalidOp "Unsupported source selector shape."

    let private normalizeSource (value: string) =
        if value.StartsWith("ipset:", StringComparison.Ordinal) then value
        elif isMacAddress value then value.ToUpperInvariant()
        else
            let parts = value.Split('/')
            match IPAddress.TryParse parts[0] with
            | true, address ->
                address.ToString()
                + (if parts.Length = 1 then "" else "/" + String.Join("/", parts |> Array.skip 1))
            | _ -> value

    let private isTrue (value: string) =
        match value.ToLowerInvariant() with
        | "yes" | "true" -> true
        | _ -> false

    let private quote (value: string) =
        if value.Contains('"') || value.Contains('\n') || value.Contains('\r') then
            invalidOp "Rich-rule value cannot be represented by the native display grammar."
        "\"" + value + "\""

    let private canonicalInteger (value: string) =
        match Int32.TryParse(value, Globalization.NumberStyles.Integer, Globalization.CultureInfo.InvariantCulture) with
        | true, number -> number.ToString(Globalization.CultureInfo.InvariantCulture)
        | _ -> invalidOp "Invalid rich-rule integer."

    let private canonicalUnsigned (value: string) =
        let parsed =
            if value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
                match UInt64.TryParse(value.Substring(2), Globalization.NumberStyles.AllowHexSpecifier, Globalization.CultureInfo.InvariantCulture) with
                | true, number -> Some number
                | _ -> None
            else
                match UInt64.TryParse(value, Globalization.NumberStyles.None, Globalization.CultureInfo.InvariantCulture) with
                | true, number -> Some number
                | _ -> None
        parsed
        |> Option.map (fun number -> number.ToString(Globalization.CultureInfo.InvariantCulture))
        |> Option.defaultWith (fun () -> invalidOp "Invalid rich-rule number.")

    let private richAttribute key (node: FirewalldModel.Element) =
        Map.tryFind key node.Attributes

    let private requiredRichAttribute key (node: FirewalldModel.Element) =
        richAttribute key node
        |> Option.defaultWith (fun () -> invalidOp ("Missing rich-rule attribute " + key))

    let private quotedRichAttribute key value = key + "=" + quote value

    let private richLimit (node: FirewalldModel.Element) =
        match node.Children with
        | [] -> ""
        | [ limit ] ->
            let parts = (requiredRichAttribute "value" limit).Split('/')
            if parts.Length <> 2 then invalidOp "Invalid rich-rule limit."
            let duration =
                match parts[1].Trim() with
                | "s" | "second" -> "s"
                | "m" | "minute" -> "m"
                | "h" | "hour" -> "h"
                | "d" | "day" -> "d"
                | _ -> invalidOp "Unsupported rich-rule limit duration."
            let burst =
                richAttribute "burst" limit
                |> Option.map canonicalInteger
                |> Option.filter ((<>) "0")
                |> Option.map (fun value -> " burst=" + value)
                |> Option.defaultValue ""
            " limit value=" + quote (canonicalInteger parts[0] + "/" + duration) + burst
        | _ -> invalidOp "Multiple rich-rule limits are unsupported."

    let private renderRichSelector (node: FirewalldModel.Element) =
        let selector =
            [ "address"; "mac"; "ipset" ]
            |> List.tryPick (fun key -> richAttribute key node |> Option.map (quotedRichAttribute key))
            |> Option.defaultWith (fun () -> invalidOp "Missing rich-rule selector.")
        let inverted = richAttribute "invert" node |> Option.exists isTrue
        node.Name + (if inverted then " NOT " else " ") + selector

    let private renderRichElement (node: FirewalldModel.Element) =
        match node.Name with
        | "service" -> "service " + quotedRichAttribute "name" (requiredRichAttribute "name" node)
        | "port" | "source-port" ->
            node.Name + " "
            + quotedRichAttribute "port" (requiredRichAttribute "port" node) + " "
            + quotedRichAttribute "protocol" (requiredRichAttribute "protocol" node)
        | "protocol" -> "protocol " + quotedRichAttribute "value" (requiredRichAttribute "value" node)
        | "icmp-block" | "icmp-type" ->
            node.Name + " " + quotedRichAttribute "name" (requiredRichAttribute "name" node)
        | "masquerade" -> "masquerade"
        | "tcp-mss-clamp" ->
            match richAttribute "value" node with
            | Some value when value <> "None" && value <> "" -> "tcp-mss-clamp " + quotedRichAttribute "value" value
            | _ -> "tcp-mss-clamp"
        | "forward-port" ->
            "forward-port "
            + quotedRichAttribute "port" (requiredRichAttribute "port" node) + " "
            + quotedRichAttribute "protocol" (requiredRichAttribute "protocol" node)
            + (richAttribute "to-port" node |> Option.map (quotedRichAttribute "to-port") |> Option.map (fun value -> " " + value) |> Option.defaultValue "")
            + (richAttribute "to-addr" node |> Option.map (quotedRichAttribute "to-addr") |> Option.map (fun value -> " " + value) |> Option.defaultValue "")
        | _ -> invalidOp "Unsupported rich-rule element."

    let private renderRichLog (node: FirewalldModel.Element) =
        let keys = if node.Name = "log" then [ "prefix"; "level" ] else [ "group"; "prefix"; "queue-size" ]
        let attributes =
            keys
            |> List.choose (fun key ->
                richAttribute key node
                |> Option.bind (fun original ->
                    let value = if key = "group" || key = "queue-size" then canonicalUnsigned original else original
                    if (key = "prefix" && value = "")
                       || ((key = "group" || key = "queue-size") && value = "0") then None
                    else Some(quotedRichAttribute key value)))
        node.Name
        + (if attributes.IsEmpty then "" else " " + String.concat " " attributes)
        + richLimit node

    let private renderRichAction (node: FirewalldModel.Element) =
        let attributes =
            match node.Name with
            | "reject" -> richAttribute "type" node |> Option.map (quotedRichAttribute "type") |> Option.toList
            | "mark" -> richAttribute "set" node |> Option.map (fun value -> "set=" + value) |> Option.toList
            | _ -> []
        node.Name
        + (if attributes.IsEmpty then "" else " " + String.concat " " attributes)
        + richLimit node

    let private renderRichRule (rule: FirewalldModel.Element) =
        try
            let parts = ResizeArray<string>()
            parts.Add "rule"
            richAttribute "priority" rule
            |> Option.map canonicalInteger
            |> Option.filter ((<>) "0")
            |> Option.iter (fun value -> parts.Add(quotedRichAttribute "priority" value))
            richAttribute "family" rule |> Option.iter (fun value -> parts.Add(quotedRichAttribute "family" value))
            rule.Children
            |> List.filter (fun node -> node.Name = "source" || node.Name = "destination")
            |> List.iter (fun node -> parts.Add(renderRichSelector node))
            let elementNames =
                [ "service"; "port"; "protocol"; "tcp-mss-clamp"; "icmp-block"; "icmp-type"; "masquerade"; "forward-port"; "source-port" ]
            rule.Children
            |> List.filter (fun node -> List.contains node.Name elementNames)
            |> List.iter (fun node -> parts.Add(renderRichElement node))
            rule.Children
            |> List.filter (fun node -> node.Name = "log" || node.Name = "nflog")
            |> List.iter (fun node -> parts.Add(renderRichLog node))
            rule.Children
            |> List.filter (fun node -> node.Name = "audit")
            |> List.iter (fun node -> parts.Add("audit" + richLimit node))
            rule.Children
            |> List.filter (fun node -> List.contains node.Name [ "accept"; "reject"; "drop"; "mark" ])
            |> List.iter (fun node -> parts.Add(renderRichAction node))
            Some(String.concat " " parts)
        with _ -> None

    let private infoArguments kind name =
        match kind with
        | "service" -> "--info-service=" + name
        | "ipset" -> "--info-ipset=" + name
        | "icmptype" -> "--info-icmptype=" + name
        | "helper" -> "--info-helper=" + name
        | _ -> ""

    let private commonFieldSet kind =
        match kind with
        | "service" -> set [ "ports"; "protocols"; "source-ports"; "modules"; "destination"; "includes"; "helpers" ]
        | "ipset" -> set [ "type"; "options"; "entries" ]
        | "icmptype" -> set [ "destination" ]
        | "helper" -> set [ "family"; "module"; "ports" ]
        | _ -> Set.empty

    let private expectedZonePolicyFields (c: FirewalldModel.Configuration) =
        let combine name key legacy =
            legacy @ (directElements c name |> List.choose (elementAttribute key))
        let ports =
            c.Ports
            @ (directElements c "port"
               |> List.map (fun node ->
                   requiredElementAttribute "port" node + "/" + requiredElementAttribute "protocol" node))
        let protocols = combine "protocol" "value" c.Protocols
        let services = combine "service" "name" c.Services
        let ingress = combine "ingress-zone" "name" c.Ingress
        let egress = combine "egress-zone" "name" c.Egress
        let target = Map.tryFind "target" c.Attributes |> Option.defaultValue c.Target
        let target = if target = "%%REJECT%%" then "REJECT" else target
        let rootPriority name fallback =
            Map.tryFind name c.Attributes |> Option.map canonicalInteger |> Option.defaultValue fallback
        let sourcePorts =
            directElements c "source-port"
            |> List.map (fun node ->
                requiredElementAttribute "port" node + "/" + requiredElementAttribute "protocol" node)
        let forwardPorts = directElements c "forward-port"
        let richRules =
            directElements c "rule"
            |> List.map renderRichRule
            |> List.fold (fun state item ->
                match state, item with
                | Some rules, Some value -> Some(value :: rules)
                | _ -> None) (Some [])
            |> Option.map Set.ofList
        let fields =
            if c.Kind = "zone" then
                Map.ofList
                    [ "target", [ target ]
                      "ingress-priority", [ rootPriority "ingress-priority" "0" ]
                      "egress-priority", [ rootPriority "egress-priority" "0" ]
                      "icmp-block-inversion", [ if (directElements c "icmp-block-inversion").IsEmpty then "no" else "yes" ]
                      field "interfaces" (combine "interface" "name" c.Interfaces)
                      field "sources" (directElements c "source" |> List.map sourceValue)
                      field "services" services
                      field "ports" ports
                      field "protocols" protocols
                      "forward", [ if c.Forward || not (directElements c "forward").IsEmpty then "yes" else "no" ]
                      "masquerade", [ if c.Masquerade || not (directElements c "masquerade").IsEmpty then "yes" else "no" ]
                      field "forward-ports" []
                      field "source-ports" sourcePorts
                      field "icmp-blocks" (elementValues "icmp-block" "name" c)
                      field "rich rules" [] ]
            else
                let priority = rootPriority "priority" (c.Priority.ToString(Globalization.CultureInfo.InvariantCulture))
                Map.ofList
                    [ "priority", [ priority ]
                      "target", [ target ]
                      field "ingress-zones" ingress
                      field "egress-zones" egress
                      field "services" services
                      field "ports" ports
                      field "protocols" protocols
                      "masquerade", [ if c.Masquerade || not (directElements c "masquerade").IsEmpty then "yes" else "no" ]
                      field "forward-ports" []
                      field "source-ports" sourcePorts
                      field "icmp-blocks" (elementValues "icmp-block" "name" c)
                      field "rich rules" [] ]
        let interfaces = combine "interface" "name" c.Interfaces
        let sources =
            directElements c "source"
            |> List.map sourceValue
            |> List.map normalizeSource
            |> Set.ofList
        fields, interfaces, sources, Set.ofList forwardPorts, richRules

    let private expectedDefinitionFields (c: FirewalldModel.Configuration) =
        let elementValues name key =
            directElements c name |> List.choose (elementAttribute key)
        let portFields =
            c.Ports
            @ (directElements c "port"
               |> List.choose (fun node ->
                   let port = requiredElementAttribute "port" node
                   if port = "" then None else Some(port + "/" + requiredElementAttribute "protocol" node)))
        let protocolFields =
            c.Protocols
            @ elementValues "protocol" "value"
            @ (directElements c "port"
               |> List.choose (fun node ->
                   if requiredElementAttribute "port" node = "" then Some(requiredElementAttribute "protocol" node) else None))
        match c.Kind with
        | "service" ->
            let destinations =
                directElements c "destination"
                |> List.collect (fun node ->
                    node.Attributes
                    |> Map.toList
                    |> List.map (fun (family, address) -> family + ":" + address))
            Map.ofList
                [ field "ports" portFields
                  field "protocols" protocolFields
                  field "source-ports" (directElements c "source-port" |> List.map (fun node ->
                      requiredElementAttribute "port" node + "/" + requiredElementAttribute "protocol" node))
                  field "modules" (elementValues "module" "name")
                  field "destination" destinations
                  field "includes" (elementValues "include" "service")
                  field "helpers" (elementValues "helper" "name") ]
        | "helper" ->
            let family = Map.tryFind "family" c.Attributes |> Option.filter (fun value -> value <> "") |> Option.toList
            Map.ofList
                [ field "family" family
                  "module", [ Map.find "module" c.Attributes ]
                  field "ports" portFields ]
        | "ipset" ->
            let options =
                directElements c "option"
                |> List.map (fun node ->
                    requiredElementAttribute "name" node + "="
                    + (Map.tryFind "value" node.Attributes |> Option.defaultValue ""))
            Map.ofList
                [ "type", [ Map.find "type" c.Attributes ]
                  field "options" options
                  field "entries" (directElements c "entry" |> List.map (fun node -> node.Text |> Option.defaultValue "")) ]
        | "icmptype" ->
            let destinations =
                directElements c "destination"
                |> List.collect (fun node ->
                    node.Attributes
                    |> Map.toList
                    |> List.choose (fun (family, value) -> if isTrue value then Some family else None))
            let destinations = if (directElements c "destination").IsEmpty then [ "ipv4"; "ipv6" ] else destinations
            Map.ofList [ field "destination" destinations ]
        | _ -> Map.empty

    let private fieldsHaveExpectedKeys (expected: Map<string, string list>) (actual: Map<string, string list>) =
        (actual |> Map.keys |> Set.ofSeq) = (expected |> Map.keys |> Set.ofSeq)

    let private available (matches: bool) : RuntimeObservation =
        { Observed = true; InSync = matches }

    let private unavailable : RuntimeObservation =
        { Observed = false; InSync = false }

    let private observeZonePolicy (environment: HostEnvironment) (c: FirewalldModel.Configuration) =
        match inspectRuntime environment c.Kind c.Name with
        | None -> unavailable
        | Some runtime when not runtime.UnknownFields.IsEmpty -> unavailable
        | Some runtime ->
            let expectedFields, expectedInterfaces, expectedSources, expectedForwardPorts, expectedRichRules =
                expectedZonePolicyFields c
            match expectedRichRules with
            | None -> unavailable
            | Some expectedRules ->
                let selector = if c.Kind = "zone" then "--zone=" + c.Name else "--policy=" + c.Name
                let interfaces =
                    if c.Kind = "zone" then run environment [ selector; "--list-interfaces" ] |> Option.map listValues
                    else Some []
                match interfaces with
                | None -> unavailable
                | Some currentInterfaces ->
                    let knownFields = if c.Kind = "zone" then knownZoneFields else knownPolicyFields
                    let keysMatch = (runtime.NativeFields |> Map.keys |> Set.ofSeq) = knownFields
                    let fieldsMatch = normalizeFields c.Kind runtime.NativeFields = normalizeFields c.Kind expectedFields
                    let interfacesMatch = c.Kind <> "zone" || Set.ofList currentInterfaces = Set.ofList expectedInterfaces
                    let sourcesMatch = Set.ofList (runtime.SourcesRaw |> List.map normalizeSource) = expectedSources
                    let forwardPortsMatch = Set.ofList runtime.ForwardPorts = expectedForwardPorts
                    let richRulesMatch = Set.ofList runtime.RichRules = expectedRules
                    if not keysMatch then unavailable
                    else available (fieldsMatch && interfacesMatch && sourcesMatch && forwardPortsMatch && richRulesMatch)

    let private observeDefinition (environment: HostEnvironment) (c: FirewalldModel.Configuration) =
        let expected = expectedDefinitionFields c
        let expectedKeys = commonFieldSet c.Kind
        if c.Kind = "ipset" then
            match inspectRuntime environment "ipset" c.Name with
            | None -> unavailable
            | Some runtime when not runtime.UnknownFields.IsEmpty || runtime.IpSetType.IsNone -> unavailable
            | Some runtime ->
                let actual = runtime.NativeFields
                let complete =
                    fieldsHaveExpectedKeys expected actual
                    && (actual |> Map.keys |> Set.ofSeq) = expectedKeys
                if not complete then unavailable
                else available (normalizeFields c.Kind actual = normalizeFields c.Kind expected)
        else
            let selector = infoArguments c.Kind c.Name
            match run environment [ selector ] with
            | None -> unavailable
            | Some output ->
                let actual = parseFields output
                let complete =
                    fieldsHaveExpectedKeys expected actual
                    && (actual |> Map.keys |> Set.ofSeq) = expectedKeys
                if not complete then unavailable
                else available (normalizeFields c.Kind actual = normalizeFields c.Kind expected)

    /// Runtime selector state is observed independently of permanent-file drift using
    /// firewalld 2.3.1's named-object `--list-all` and `--info-*` getters. These APIs do
    /// not observe direct/passthrough rules, arbitrary nftables state, or packet behavior.
    /// `Observed=false` means a getter failed or exposed an unsupported shape; consumers
    /// must not interpret that as an in-sync runtime observation.
    let observe (environment: HostEnvironment) (configuration: FirewalldModel.Configuration) : RuntimeObservation =
        try
            let c = FirewalldModel.validate configuration
            match c.Kind with
            | "zone" | "policy" -> observeZonePolicy environment c
            | "service" | "ipset" | "icmptype" | "helper" -> observeDefinition environment c
            | _ -> unavailable
        with _ -> unavailable

    let inSync (environment: HostEnvironment) (configuration: FirewalldModel.Configuration) : bool =
        let result = observe environment configuration
        result.Observed && result.InSync

