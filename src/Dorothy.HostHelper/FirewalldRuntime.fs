namespace Dorothy.HostHelper

open System
open System.Net
open System.Collections.Generic
open System.Text.Json

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
    type private RichToken =
        { Value: string
          IsAttribute: bool
          IsQuoted: bool }

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
            | "service" -> Some [ "--get-services" ]
            | "ipset" -> Some [ "--get-ipsets" ]
            | "icmptype" -> Some [ "--get-icmptypes" ]
            | "helper" -> Some [ "--get-helpers" ]
            | _ -> None

        arguments
        |> Option.bind (fun args -> run environment args)
        |> Option.map (fun output -> words [ output ] |> List.distinct |> List.sort)

    let private listZoneInterfaces (environment: HostEnvironment) (permanent: bool) (zone: string) =
        let mode = if permanent then [ "--permanent" ] else []
        run environment (mode @ [ "--zone=" + zone; "--list-interfaces" ])
        |> Option.map (fun output -> words [ output ] |> List.distinct |> List.sort)

    let listRuntimeInterfaces (environment: HostEnvironment) (zone: string) =
        listZoneInterfaces environment false zone

    let listPermanentInterfaces (environment: HostEnvironment) (zone: string) =
        listZoneInterfaces environment true zone



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
            Some(element "source" [ "address", source.ToUpperInvariant() ])
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

    /// Renders a typed forward-port element in firewalld's list-all value format.
    let canonicalForwardPortValue (forwardPort: FirewalldModel.Element) : string option =
        try
            if forwardPort.Name <> "forward-port" then None
            else
                let required key =
                    Map.tryFind key forwardPort.Attributes
                    |> Option.defaultWith (fun () -> invalidOp ("Missing forward-port attribute " + key))
                let port = required "port"
                let protocol = required "protocol"
                let canonicalPort value = (FirewalldModel.port (value + "/" + protocol)).Split('/')[0]
                let targetPort =
                    Map.tryFind "to-port" forwardPort.Attributes
                    |> Option.map canonicalPort
                    |> Option.defaultValue "None"
                let targetAddress = Map.tryFind "to-addr" forwardPort.Attributes |> Option.defaultValue "None"
                let value =
                    "port=" + canonicalPort port + ":proto=" + protocol
                    + ":toport=" + targetPort + ":toaddr=" + targetAddress
                forwardPortElement value |> Option.map (fun _ -> value)
        with _ -> None

    /// list-all prints missing optional fields as "None"; that is not a valid
    /// address or port in an add/remove command. Retain the listing format for
    /// fingerprints, and construct argv only from a decoded typed selector.
    let forwardPortCommandValue displayValue =
        forwardPortElement displayValue |> Option.map (fun e ->
            let optional name flag = Map.tryFind name e.Attributes |> Option.map (fun v -> ":" + flag + "=" + v) |> Option.defaultValue ""
            "port=" + e.Attributes["port"] + ":proto=" + e.Attributes["protocol"]
            + optional "to-port" "toport" + optional "to-addr" "toaddr")

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

    let private validateRuntimeName kind name = FirewalldModel.nativeReference kind "name" name |> ignore

    /// Maps a definition kind to the firewalld information option.
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
    /// Reads a named runtime or permanent object. Zone and policy list-all getters
    /// cover quiet objects; unsupported native fields remain explicit to callers.
    let private inspectRuntimeWith (environment: HostEnvironment) (permanent: bool) (kind: string) (name: string) : RuntimeSnapshot option =

        let mode = if permanent then [ "--permanent" ] else []

        try
            match kind with
            | "ipset" ->
                validateRuntimeName kind name
                match run environment (mode @ [ "--info-ipset=" + name ]) with

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
            | "zone" | "policy" ->
                validateRuntimeName kind name
                let selector = if kind = "zone" then "--zone=" + name else "--policy=" + name
                match run environment (mode @ [ selector; "--list-all" ]) with
                | None -> None
                | Some output ->
                    let interfaceValues =
                        if kind = "zone" then listZoneInterfaces environment permanent name
                        else Some []
                    match interfaceValues with
                    | None -> None
                    | Some interfaces ->
                        let fields = parseFields output
                        let fields =
                            if kind = "zone" then
                                let interfaceField =
                                    if interfaces.IsEmpty then [] else [ String.concat " " interfaces ]
                                Map.add "interfaces" interfaceField fields
                            else fields
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
                                Interfaces = interfaces
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
            | "service" | "icmptype" | "helper" ->
                validateRuntimeName kind name
                match run environment (mode @ [ infoArguments kind name ]) with
                | None -> None
                | Some output ->
                    let fields = parseFields output
                    let known = commonFieldSet kind
                    let mutable unknown = unknownFields known fields
                    for key in known do
                        if not (Map.containsKey key fields) then unknown <- Map.add key [] unknown
                    Some { emptySnapshot kind name unknown with NativeFields = fields }
            | _ -> None
        with _ -> None
    let inspectRuntime (environment: HostEnvironment) (kind: string) (name: string) : RuntimeSnapshot option =
        inspectRuntimeWith environment false kind name
    let inspectPermanent (environment: HostEnvironment) (kind: string) (name: string) : RuntimeSnapshot option =
        inspectRuntimeWith environment true kind name
    let queryRuntime (environment: HostEnvironment) (kind: string) (name: string) : Result<RuntimeSnapshot option, string> =
        match listRuntime environment kind with
        | None -> Error("Unable to enumerate runtime firewalld " + kind + " objects.")
        | Some names when not (List.contains name names) -> Ok None
        | Some _ ->
            match inspectRuntime environment kind name with
            | Some snapshot -> Ok(Some snapshot)
            | None -> Error("Unable to inspect runtime firewalld " + kind + " " + name + ".")


    let private listValues (text: string) =
        text.Split([| ' '; '\t'; '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
        |> Array.distinct
        |> Array.sort
        |> Array.toList


    let private listFields =
        set [ "services"; "ports"; "protocols"; "sources"; "ingress-zones"; "egress-zones"; "source-ports"; "icmp-blocks"; "forward-ports"; "modules"; "destination"; "includes"; "helpers"; "options"; "entries" ]

    let private portTuple (value: string) =
        try
            let normalized = FirewalldModel.port value
            let parts = normalized.Split('/')
            let range = parts[0].Split('-')
            let first = Int32.Parse(range[0], Globalization.CultureInfo.InvariantCulture)
            let last = Int32.Parse(range[range.Length - 1], Globalization.CultureInfo.InvariantCulture)
            Some(parts[1], first, last)
        with _ -> None

    let private normalizePortValues (values: string list) =
        let parsed = values |> List.choose portTuple
        let invalid = values |> List.filter (portTuple >> Option.isNone)
        let merged =
            parsed
            |> List.groupBy (fun (protocol, _, _) -> protocol)
            |> List.collect (fun (protocol, ranges) ->
                let ordered = ranges |> List.map (fun (_, first, last) -> first, last) |> List.sort
                let ranges =
                    ordered
                    |> List.fold (fun state (first, last) ->
                        match state with
                        | (previousFirst, previousLast) :: rest when first <= previousLast ->
                            (previousFirst, max previousLast last) :: rest
                        | _ -> (first, last) :: state) []
                    |> List.rev
                ranges
                |> List.map (fun (first, last) ->
                    (if first = last then string first else string first + "-" + string last) + "/" + protocol))
        (merged @ invalid) |> List.distinct |> List.sort

    let private portValuesOverlap (left: string list) (right: string list) =
        let parse values =
            let parsed = values |> List.map portTuple
            if parsed |> List.exists Option.isNone then None
            else Some(parsed |> List.choose id)
        match parse left, parse right with
        | Some leftRanges, Some rightRanges ->
            Some(
                leftRanges
                |> List.exists (fun (leftProtocol, leftFirst, leftLast) ->
                    rightRanges
                    |> List.exists (fun (rightProtocol, rightFirst, rightLast) ->
                        leftProtocol = rightProtocol && leftFirst <= rightLast && rightFirst <= leftLast)))
        | _ -> None

    /// Canonicalizes native list-valued fields for comparison and bounded repair proofs.
    let normalizeFieldValues (kind: string) (fieldName: string) (values: string list) : string list =
        if fieldName = "sources" then
            words values |> List.map (fun value -> if isMacAddress value then value.ToUpperInvariant() else value) |> List.distinct |> List.sort
        elif fieldName = "ports" || fieldName = "source-ports" then
            normalizePortValues (words values)
        elif kind = "service" && fieldName = "modules" then
            words values
            |> List.map FirewalldModel.helperNameForModule
            |> List.distinct
            |> List.sort
        elif kind = "icmptype" && fieldName = "destination" then
            words values
            |> List.choose (fun value ->
                let separator = value.IndexOf('=')
                if separator < 0 then Some value
                elif value.Substring(separator + 1) = "yes" then Some(value.Substring(0, separator))
                else None)
            |> List.distinct
            |> List.sort
        else
            words values |> List.distinct |> List.sort

    let private exactSetDifference live disk removed =
        Set.difference disk live = removed
        && Set.difference live disk = Set.empty

    let private normalizeFields kind (fields: Map<string, string list>) =
        let ignored = set [ "interfaces"; "sources"; "forward-ports"; "rich rules" ]
        fields
        |> Map.filter (fun key _ -> not (Set.contains key ignored))
        |> Map.map (fun key values ->
            if key = "target" then values |> List.map (fun value -> if value = "%%REJECT%%" then "REJECT" else value)
            elif Set.contains key listFields then normalizeFieldValues kind key values
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


    let private normalizeCompleteFields kind (fields: Map<string, string list>) =
        fields
        |> Map.map (fun key values ->
            if key = "target" then values |> List.map (fun value -> if value = "%%REJECT%%" then "REJECT" else value)
            elif key = "sources" then words values |> List.map normalizeSource |> List.distinct |> List.sort
            elif key = "interfaces" then normalizeFieldValues kind key values
            elif key = "forward-ports" || key = "rich rules" then
                values |> List.filter (String.IsNullOrWhiteSpace >> not) |> List.distinct |> List.sort
            elif Set.contains key listFields then normalizeFieldValues kind key values
            else values)
    let private isTrue (value: string) =
        match value.ToLowerInvariant() with
        | "yes" | "true" -> true
        | _ -> false

    let private quote (value: string) =
        if value.Contains('"') || value.Contains('\n') || value.Contains('\r') then
            invalidOp "Rich-rule value cannot be represented by the native display grammar."
        "\"" + value + "\""
    let private richTokens (text: string) =
        let tokens = ResizeArray<RichToken>()
        let mutable index = 0
        let mutable valid = true
        let isWhitespace character = Char.IsWhiteSpace character
        let quotedValue () =
            if index >= text.Length || text[index] <> '"' then None
            else
                index <- index + 1
                let start = index
                let mutable closed = false
                while index < text.Length && not closed do
                    if text[index] = '\\' && index + 1 < text.Length then index <- index + 2
                    elif text[index] = '"' then closed <- true
                    else index <- index + 1
                if not closed then None
                else
                    let value = text.Substring(start, index - start)
                    index <- index + 1
                    Some value
        while index < text.Length && valid do
            while index < text.Length && isWhitespace text[index] do index <- index + 1
            if index < text.Length then
                if text[index] = '"' then
                    match quotedValue () with
                    | Some value -> tokens.Add { Value = value; IsAttribute = false; IsQuoted = true }
                    | None -> valid <- false
                else
                    let start = index
                    while index < text.Length && not (isWhitespace text[index]) && text[index] <> '=' do
                        index <- index + 1
                    if start = index then valid <- false
                    else
                        let key = text.Substring(start, index - start)
                        if index < text.Length && text[index] = '=' then
                            index <- index + 1
                            let value =
                                if index < text.Length && text[index] = '"' then quotedValue ()
                                else
                                    let valueStart = index
                                    while index < text.Length && not (isWhitespace text[index]) do index <- index + 1
                                    Some(text.Substring(valueStart, index - valueStart))
                            match value with
                            | Some value -> tokens.Add { Value = key + "=" + value; IsAttribute = true; IsQuoted = false }
                            | None -> valid <- false
                        else
                            tokens.Add { Value = key; IsAttribute = false; IsQuoted = false }
        if valid then Some(List.ofSeq tokens) else None
    let private missingSelectorsMatch kind fieldName (values: string list) (runtime: RuntimeSnapshot) (permanent: RuntimeSnapshot) =
        if values.IsEmpty || (values |> List.distinct).Length <> values.Length then false
        else
            let rawValues snapshot =
                Map.tryFind fieldName snapshot.NativeFields |> Option.defaultValue [] |> words
            match fieldName with
            | "services" | "protocols" | "icmp-blocks" ->
                let canonicalValues =
                    values
                    |> List.forall (fun value -> normalizeFieldValues kind fieldName [ value ] = [ value ])
                canonicalValues
                && exactSetDifference
                    (Set.ofList (normalizeFieldValues kind fieldName (rawValues runtime)))
                    (Set.ofList (normalizeFieldValues kind fieldName (rawValues permanent)))
                    (Set.ofList values)
            | "ports" | "source-ports" ->
                let canonicalValues =
                    values
                    |> List.forall (fun value ->
                        portTuple value |> Option.isSome
                        && normalizeFieldValues kind fieldName [ value ] = [ value ])
                match portValuesOverlap (rawValues runtime) values with
                | Some false when canonicalValues ->
                    let expected = normalizeFieldValues kind fieldName (rawValues permanent)
                    normalizeFieldValues kind fieldName (rawValues runtime @ values) = expected
                | _ -> false
            | "rich rules" ->
                values |> List.forall (richTokens >> Option.isSome)
                && exactSetDifference
                    (Set.ofList runtime.RichRules)
                    (Set.ofList permanent.RichRules)
                    (Set.ofList values)
            | "forward-ports" ->
                let parseCanonical value =
                    forwardPortElement value
                    |> Option.bind (fun element ->
                        canonicalForwardPortValue element
                        |> Option.filter ((=) value)
                        |> Option.map (fun _ -> element))
                let requested = values |> List.map parseCanonical
                if requested |> List.exists Option.isNone then false
                else
                    exactSetDifference
                        (Set.ofList runtime.ForwardPorts)
                        (Set.ofList permanent.ForwardPorts)
                        (requested |> List.choose id |> Set.ofList)
            | _ -> false

    let private richRuleAction (rule: string) =
        richTokens rule
        |> Option.bind (fun tokens ->
            let actions =
                tokens
                |> List.filter (fun token ->
                    not token.IsAttribute
                    && not token.IsQuoted
                    && List.contains token.Value [ "accept"; "reject"; "drop"; "mark" ])
                |> List.map (fun token -> token.Value)
            match actions with
            | [ action ] -> Some action
            | _ -> None)

    let isRestrictiveRichRule (rule: string) : bool =
        match richRuleAction rule with
        | Some("drop" | "reject") -> true
        | _ -> false

    let private richRuleReferences (rule: string) =
        richTokens rule
        |> Option.map (fun tokens ->
            let services = ResizeArray<string>()
            let icmpTypes = ResizeArray<string>()
            let ipsets = ResizeArray<string>()
            let values = List.toArray tokens
            for index in 0 .. values.Length - 1 do
                let token = values[index]
                if token.IsAttribute && token.Value.StartsWith("ipset=", StringComparison.Ordinal) then
                    ipsets.Add(token.Value.Substring("ipset=".Length))
                elif not token.IsAttribute && not token.IsQuoted && index + 1 < values.Length then
                    let next = values[index + 1]
                    if next.IsAttribute && next.Value.StartsWith("name=", StringComparison.Ordinal) then
                        let name = next.Value.Substring("name=".Length)
                        if token.Value = "service" then services.Add name
                        elif token.Value = "icmp-block" || token.Value = "icmp-type" then icmpTypes.Add name
            Set.ofSeq services, Set.ofSeq icmpTypes, Set.ofSeq ipsets)


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
            | _ -> "tcp-mss-clamp value=\"pmtu\""
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
            |> List.sortBy (fun node -> if node.Name = "source" then 0 else 1)
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

    /// Renders one rich-rule element in firewalld's native display syntax.
    let canonicalRichRule (rule: FirewalldModel.Element) : string option =
        renderRichRule rule



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

    /// Returns the native rich-rule strings expected from a valid zone or policy configuration.
    let expectedRichRuleStrings (configuration: FirewalldModel.Configuration) : string list option =
        try
            let c = FirewalldModel.validate configuration
            if c.Kind <> "zone" && c.Kind <> "policy" then None
            else
                let _, _, _, _, rules = expectedZonePolicyFields c
                rules |> Option.map Set.toList
        with _ -> None

    /// Returns the canonical native forward-port elements expected for a zone or policy.
    let expectedForwardPortElements (configuration: FirewalldModel.Configuration) : FirewalldModel.Element list option =
        try
            let c = FirewalldModel.validate configuration
            if c.Kind <> "zone" && c.Kind <> "policy" then None
            else
                let _, _, _, forwardPorts, _ = expectedZonePolicyFields c
                Some(Set.toList forwardPorts)
        with _ -> None

    /// Returns the expected forward-port values in firewalld's list-all format.
    let expectedForwardPortValues (configuration: FirewalldModel.Configuration) : string list option =
        expectedForwardPortElements configuration
        |> Option.bind (fun elements ->
            let values = elements |> List.map canonicalForwardPortValue
            if values |> List.exists Option.isNone then None
            else Some(values |> List.choose id))

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
            // An empty native destination list is displayed and enforced as both
            // families, whether absent in XML or specified as two disabled flags.
            let destinations = if destinations.IsEmpty then [ "ipv4"; "ipv6" ] else destinations
            Map.ofList [ field "destination" destinations ]
        | _ -> Map.empty

    let private snapshotFromConfiguration (c: FirewalldModel.Configuration) : Result<RuntimeSnapshot, string> =
        try
            let c = FirewalldModel.validate c
            let scalar (fields: Map<string, string list>) key =
                Map.tryFind key fields |> Option.bind List.tryHead
            let values (fields: Map<string, string list>) key =
                Map.tryFind key fields |> Option.defaultValue []
            let integer fields key =
                scalar fields key
                |> Option.bind (fun value ->
                    match Int32.TryParse(value, Globalization.NumberStyles.Integer, Globalization.CultureInfo.InvariantCulture) with
                    | true, number -> Some number
                    | _ -> None)
            let boolean fields key = scalar fields key = Some "yes"
            match c.Kind with
            | "zone" | "policy" ->
                let fields, interfaces, _, forwardPorts, richRules = expectedZonePolicyFields c
                match richRules with
                | None -> Error "A rich rule cannot be represented in the native firewalld display syntax."
                | Some rules ->
                    let forwardPortValues = forwardPorts |> Set.toList |> List.map canonicalForwardPortValue
                    if forwardPortValues |> List.exists Option.isNone then
                        Error "A forward port cannot be represented in the native firewalld display syntax."
                    else
                        let fields =
                            fields
                            |> Map.add "forward-ports" (forwardPortValues |> List.choose id)
                            |> Map.add "rich rules" (Set.toList rules)
                        Ok
                            { emptySnapshot c.Kind c.Name Map.empty with
                                NativeFields = fields
                                Target = scalar fields "target" |> Option.defaultValue ""
                                Priority = integer fields "priority"
                                IngressPriority = integer fields "ingress-priority"
                                EgressPriority = integer fields "egress-priority"
                                Ingress = values fields "ingress-zones" |> words
                                Egress = values fields "egress-zones" |> words
                                Interfaces = interfaces
                                SourcesRaw = values fields "sources" |> words
                                Sources = values fields "sources" |> words |> List.map (fun source ->
                                    sourceElement source |> Option.defaultWith (fun () -> invalidOp "Cannot project the declared zone source."))
                                Services = values fields "services" |> words
                                Ports = values fields "ports" |> words
                                Protocols = values fields "protocols" |> words
                                SourcePorts = values fields "source-ports" |> words
                                ForwardPorts = Set.toList forwardPorts
                                Masquerade = boolean fields "masquerade"
                                Forward = boolean fields "forward"
                                IcmpBlocks = values fields "icmp-blocks" |> words
                                IcmpBlockInversion = boolean fields "icmp-block-inversion"
                                RichRules = Set.toList rules }
            | "service" | "ipset" | "icmptype" | "helper" ->
                let fields = expectedDefinitionFields c
                let ipSetType = scalar fields "type"
                let options, malformedOptions = ipSetOptions (values fields "options")
                if malformedOptions then Error "The projected ipset options are ambiguous."
                else
                    Ok
                        { emptySnapshot c.Kind c.Name Map.empty with
                            NativeFields = fields
                            IpSetType = ipSetType
                            IpSetOptions = options
                            IpSetEntries = values fields "entries" |> words }
            | _ -> Error "The configuration kind is not a firewalld XML object."
        with error -> Error error.Message

    /// Projects effective XML into a complete expected runtime selector snapshot.
    /// Unsupported or ambiguous native XML fails closed; `None` represents absence.
    let snapshotFromXml (kind: string) (name: string) (effectiveXml: string option) : Result<RuntimeSnapshot option, string> =
        match effectiveXml with
        | None -> Ok None
        | Some xml ->
            match FieldRuntime.parseConfiguration kind name xml with
            | Error reason -> Error reason
            | Ok configuration -> snapshotFromConfiguration configuration |> Result.map Some

    let private fieldsHaveExpectedKeys (expected: Map<string, string list>) (actual: Map<string, string list>) =
        (actual |> Map.keys |> Set.ofSeq) = (expected |> Map.keys |> Set.ofSeq)

    let private available (matches: bool) : RuntimeObservation =
        { Observed = true; InSync = matches }

    let private unavailable : RuntimeObservation =
        { Observed = false; InSync = false }

    let networkManagerAssignsZone (environment: HostEnvironment) (interfaceName: string) (zone: string) : bool =
        try
            match environment.Run "nmcli" [ "-g"; "GENERAL.CON-UUID"; "device"; "show"; interfaceName ] None with
            | { ExitCode = 0; Stdout = connection } when fst (Guid.TryParseExact(connection.Trim(), "D")) ->
                match environment.Run "nmcli" [ "-g"; "connection.zone"; "connection"; "show"; "uuid"; connection.Trim() ] None with
                | { ExitCode = 0; Stdout = configuredZone } ->
                    let explicitZone = configuredZone.Trim()
                    if explicitZone = "" then
                        run environment [ "--get-default-zone" ] |> Option.exists (fun activeDefault -> activeDefault.Trim() = zone)
                    else explicitZone = zone
                | _ -> false
            | _ -> false
        with _ -> false

    // A kernel bridge and `docker network inspect` identify the link, not the
    // producer of a runtime zone assignment. Authenticate the running daemon's
    // firewalld callback and its IPv4 bridge integration, not stale iptables rules.
    let private dockerRestoresFirewall (environment: HostEnvironment) =
        let command exe args =
            let result = environment.Run exe args None
            if result.ExitCode <> 0 then invalidOp "Docker firewalld integration cannot be verified."
            result.Stdout.Trim()
        let pid = command "/usr/bin/systemctl" [ "show"; "--property=MainPID"; "--value"; "docker.service" ] |> Int32.Parse
        if pid <= 0 then false
        else
            let args = IO.File.ReadAllText(HostEnvironment.path environment ("/proc/" + string pid + "/cmdline")).Split('\000', StringSplitOptions.RemoveEmptyEntries)
            let explicit = args |> Array.tryPick (fun a -> if a.StartsWith("--iptables=", StringComparison.Ordinal) then Some(a.Substring(11)) else None)
            let config =
                args |> Array.tryFindIndex (fun a -> a = "--config-file" || a.StartsWith("--config-file=", StringComparison.Ordinal))
                |> Option.map (fun i -> if args[i] = "--config-file" then args[i+1] else args[i].Substring(14))
                |> Option.defaultValue "/etc/docker/daemon.json"
            if not (IO.Path.IsPathFullyQualified config) || (explicit.IsSome && explicit <> Some "true") then false
            else
                let file = HostEnvironment.path environment config
                let enabled =
                    if explicit = Some "true" then true
                    else
                        let start = command "/usr/bin/systemctl" [ "show"; "--timestamp=unix"; "--property=ExecMainStartTimestamp"; "--value"; "docker.service" ]
                        let rec closest path =
                            if IO.File.Exists path || IO.Directory.Exists path then path
                            else closest (IO.Path.GetDirectoryName path)
                        let stamp = command "stat" [ "-c"; "%u:%g:%Z"; "--"; closest file ]
                        let fields = stamp.Split(':')
                        fields.Length = 3 && fields[0] = "0" && fields[1] = "0" && start.StartsWith('@')
                        && command "readlink" [ "-m"; "--"; file ] = file
                        && Int64.Parse(fields[2]) < Int64.Parse(start.Substring(1))
                        && (not (IO.File.Exists file) ||
                            (use doc = JsonDocument.Parse(IO.File.ReadAllBytes file)
                             match doc.RootElement.TryGetProperty "iptables" with
                             | true, v -> v.ValueKind = JsonValueKind.True
                             | false, _ -> true))
                enabled &&
                (use connections = JsonDocument.Parse(command "busctl" [ "--system"; "--json=short"; "--unique"; "list" ])
                 use matches = JsonDocument.Parse(command "busctl" [ "--system"; "--json=short"; "call"; "org.freedesktop.DBus"; "/org/freedesktop/DBus"; "org.freedesktop.DBus.Debug.Stats"; "GetAllMatchRules" ])
                 let rules = matches.RootElement.GetProperty("data")[0]
                 let expected = set [ "type='signal'"; "path='/org/fedoraproject/FirewallD1'"; "interface='org.fedoraproject.FirewallD1'"; "sender='org.fedoraproject.FirewallD1'"; "member='Reloaded'" ]
                 let restarted = set [ "type='signal'"; "path='/org/freedesktop/DBus'"; "interface='org.freedesktop.DBus'"; "sender='org.freedesktop.DBus'"; "member='NameOwnerChanged'"; "arg0='org.fedoraproject.FirewallD1'" ]
                 connections.RootElement.EnumerateArray() |> Seq.exists (fun entry ->
                     match entry.TryGetProperty "pid", entry.TryGetProperty "process", entry.TryGetProperty "unit", entry.TryGetProperty "user" with
                     | (true, p), (true, exe), (true, unit), (true, user)
                         when p.ValueKind = JsonValueKind.Number && p.GetInt32() = pid && exe.GetString() = "dockerd" && unit.GetString() = "docker.service" && user.GetString() = "root" ->
                         match rules.TryGetProperty(entry.GetProperty("name").GetString()) with
                         | true, values ->
                             let subscriptions = values.EnumerateArray() |> Seq.map (fun v -> Set.ofArray (v.GetString().Split(','))) |> Set.ofSeq
                             Set.contains expected subscriptions && Set.contains restarted subscriptions
                         | _ -> false
                     | _ -> false))

    let private dockerOwnsBridge (environment: HostEnvironment) (interfaceName: string) =
        try
            let query arguments = environment.Run "docker" ("--host=unix:///run/docker.sock" :: arguments) None
            let link = environment.Run "ip" [ "-j"; "-d"; "link"; "show"; "dev"; interfaceName ] None
            if link.ExitCode <> 0 then false
            else
                use links = JsonDocument.Parse(link.Stdout)
                let bridge =
                    links.RootElement.EnumerateArray()
                    |> Seq.exists (fun entry ->
                        entry.GetProperty("ifname").GetString() = interfaceName
                        && entry.GetProperty("linkinfo").GetProperty("info_kind").GetString() = "bridge")
                if not bridge || not (dockerRestoresFirewall environment) then false
                else
                    let inventory = query [ "network"; "ls"; "--filter"; "driver=bridge"; "--quiet"; "--no-trunc" ]
                    let ids = words [ inventory.Stdout ]
                    if inventory.ExitCode <> 0 || ids.IsEmpty || ids.Length > 1024
                       || not (ids |> List.forall (fun id -> id.Length = 64 && id |> Seq.forall Uri.IsHexDigit)) then false
                    else
                        let result = query ([ "network"; "inspect"; "--format"; "{{json .}}" ] @ ids)
                        result.ExitCode = 0
                        && (result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                            |> Array.exists (fun line ->
                                use net = JsonDocument.Parse(line)
                                let n = net.RootElement
                                let id = n.GetProperty("Id").GetString()
                                let options = n.GetProperty("Options")
                                let bridgeName =
                                    match options.ValueKind with
                                    | JsonValueKind.Object ->
                                        match options.TryGetProperty "com.docker.network.bridge.name" with
                                        | true, value -> value.GetString()
                                        | _ -> "br-" + id.Substring(0, 12)
                                    | JsonValueKind.Null -> "br-" + id.Substring(0, 12)
                                    | _ -> ""
                                let hasIPv4 = n.GetProperty("IPAM").GetProperty("Config").EnumerateArray() |> Seq.exists (fun config ->
                                    match config.TryGetProperty "Subnet" with
                                    | true, subnet -> match IPAddress.TryParse(subnet.GetString().Split('/')[0]) with true, addr -> addr.AddressFamily = Sockets.AddressFamily.InterNetwork | _ -> false
                                    | _ -> false)
                                hasIPv4 && List.contains id ids && n.GetProperty("Driver").GetString() = "bridge"
                                && n.GetProperty("Scope").GetString() = "local" && bridgeName = interfaceName))
        with _ -> false

    let restoresRuntimeInterface environment interfaceName zone =
        networkManagerAssignsZone environment interfaceName zone
        || (zone = "docker" && dockerOwnsBridge environment interfaceName)

    let withVerifiedDockerBindings (environment: HostEnvironment) activate =
        let required =
            match listRuntime environment "zone" with
            | None -> invalidOp "Cannot enumerate runtime zones before activation."
            | Some zones when List.contains "docker" zones ->
                let interfaces permanent =
                    let values = if permanent then listPermanentInterfaces environment "docker" else listRuntimeInterfaces environment "docker"
                    values |> Option.defaultWith (fun () -> invalidOp "Cannot verify Docker zone interfaces.") |> Set.ofList
                let extra = Set.difference (interfaces false) (interfaces true)
                for iface in extra do
                    if not (restoresRuntimeInterface environment iface "docker") then
                        invalidOp "Cannot verify the producer that restores the runtime Docker zone binding."
                extra
            | _ -> Set.empty
        activate ()
        if not required.IsEmpty then
            // dockerd handles the daemon's Reloaded/NameOwnerChanged asynchronously.
            let timer = Diagnostics.Stopwatch.StartNew()
            let rec check () =
                match listRuntimeInterfaces environment "docker" with
                | Some names when Set.isSubset required (Set.ofList names) -> ()
                | _ when timer.Elapsed.TotalSeconds < 5.0 -> Threading.Thread.Sleep 100; check ()
                | _ -> invalidOp "The prior runtime Docker zone membership was not restored after activation."
            check ()

    let private observeZonePolicy (allowCoexistingAdditions: bool) (environment: HostEnvironment) (c: FirewalldModel.Configuration) =
        match inspectRuntime environment c.Kind c.Name with
        | None -> unavailable
        | Some runtime when not runtime.UnknownFields.IsEmpty -> unavailable
        | Some runtime ->
            let expectedFields, expectedInterfaces, expectedSources, expectedForwardPorts, expectedRichRules =
                expectedZonePolicyFields c
            match expectedRichRules with
            | None -> unavailable
            | Some expectedRules ->
                let interfaces = if c.Kind = "zone" then Some runtime.Interfaces else Some []
                match interfaces with
                | None -> unavailable
                | Some currentInterfaces ->
                    let knownFields = if c.Kind = "zone" then knownZoneFields else knownPolicyFields
                    let keysMatch = (runtime.NativeFields |> Map.keys |> Set.ofSeq) = knownFields
                    let fieldsMatch = normalizeFields c.Kind runtime.NativeFields = normalizeFields c.Kind expectedFields
                    let interfacesMatch =
                        if c.Kind <> "zone" then true
                        else
                            let expected = Set.ofList expectedInterfaces
                            let actual = Set.ofList currentInterfaces
                            if allowCoexistingAdditions then
                                Set.isSubset expected actual
                                && (Set.difference actual expected
                                    |> Set.forall (fun interfaceName -> restoresRuntimeInterface environment interfaceName c.Name))
                            else actual = expected
                    let sourcesMatch = Set.ofList (runtime.SourcesRaw |> List.map normalizeSource) = expectedSources
                    let forwardPortsMatch = Set.ofList runtime.ForwardPorts = expectedForwardPorts
                    let actualRules = Set.ofList runtime.RichRules
                    let richRulesMatch =
                        if allowCoexistingAdditions then
                            let foreignRules = Set.difference actualRules expectedRules
                            Set.isSubset expectedRules actualRules
                            && (foreignRules |> Set.forall isRestrictiveRichRule)
                        else actualRules = expectedRules
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

    let private observeWithCoexistingAdditions (allowCoexistingAdditions: bool) (environment: HostEnvironment) (configuration: FirewalldModel.Configuration) : RuntimeObservation =
        try
            let c = FirewalldModel.validate configuration
            match c.Kind with
            | "zone" | "policy" -> observeZonePolicy allowCoexistingAdditions environment c
            | "service" | "ipset" | "icmptype" | "helper" -> observeDefinition environment c
            | _ -> unavailable
        with _ -> unavailable

    /// Runtime selector state uses firewalld's named-object getters. This does not
    /// observe direct/passthrough rules, arbitrary nftables state, or packet behavior.
    let observe (environment: HostEnvironment) (configuration: FirewalldModel.Configuration) : RuntimeObservation =
        observeWithCoexistingAdditions true environment configuration

    /// Requires exact runtime selector equality, without safe rich-rule or
    /// NetworkManager-interface supersets.
    let observeExactly (environment: HostEnvironment) (configuration: FirewalldModel.Configuration) : RuntimeObservation =
        observeWithCoexistingAdditions false environment configuration

    /// Compares the live target against a pure XML projection without accepting
    /// independently-owned rule or interface supersets.
    let observeSnapshotExactly (environment: HostEnvironment) (expected: RuntimeSnapshot) : RuntimeObservation =
        match inspectRuntime environment expected.Kind expected.Name with
        | None -> unavailable
        | Some actual when not actual.UnknownFields.IsEmpty || not expected.UnknownFields.IsEmpty -> unavailable
        | Some actual ->
            let fieldsMatch =
                normalizeCompleteFields expected.Kind actual.NativeFields = normalizeCompleteFields expected.Kind expected.NativeFields
            let interfacesMatch =
                expected.Kind <> "zone"
                || Set.ofList actual.Interfaces = Set.ofList expected.Interfaces
            let sourcesMatch =
                let normalized sources = sources |> Seq.map normalizeSource |> Set.ofSeq
                normalized actual.SourcesRaw = normalized expected.SourcesRaw
            let forwardPortsMatch = Set.ofList actual.ForwardPorts = Set.ofList expected.ForwardPorts
            let richRulesMatch = Set.ofList actual.RichRules = Set.ofList expected.RichRules
            let ipsetMatch =
                expected.Kind <> "ipset"
                || (actual.IpSetType = expected.IpSetType
                    && actual.IpSetOptions = expected.IpSetOptions
                    && Set.ofList actual.IpSetEntries = Set.ofList expected.IpSetEntries)
            available (fieldsMatch && interfacesMatch && sourcesMatch && forwardPortsMatch && richRulesMatch && ipsetMatch)

    let inSync (environment: HostEnvironment) (configuration: FirewalldModel.Configuration) : bool =
        let result = observe environment configuration
        result.Observed && result.InSync


    let private listObjectNames (environment: HostEnvironment) (permanent: bool) (kind: string) =
        let arguments =
            match kind with
            | "zone" -> Some [ "--get-zones" ]
            | "policy" -> Some [ "--get-policies" ]
            | "service" -> Some [ "--get-services" ]
            | "ipset" -> Some [ "--get-ipsets" ]
            | "icmptype" -> Some [ "--get-icmptypes" ]
            | "helper" -> Some [ "--get-helpers" ]
            | _ -> None
        arguments
        |> Option.bind (fun args ->
            let mode = if permanent then [ "--permanent" ] else []
            run environment (mode @ args))
        |> Option.map (fun output -> words [ output ] |> List.distinct |> List.sort)
    let queryPermanent (environment: HostEnvironment) (kind: string) (name: string) : Result<RuntimeSnapshot option, string> =
        match listObjectNames environment true kind with
        | None -> Error("Unable to enumerate permanent firewalld " + kind + " objects.")
        | Some names when not (List.contains name names) -> Ok None
        | Some _ ->
            match inspectPermanent environment kind name with
            | Some snapshot -> Ok(Some snapshot)
            | None -> Error("Unable to inspect permanent firewalld " + kind + " " + name + ".")

    let private normalizedObjectFields kind (snapshot: RuntimeSnapshot) =
        let fields = normalizeCompleteFields kind snapshot.NativeFields
        if kind = "zone" then Map.remove "interfaces" fields else fields


    let private referencesFromZonePolicy (snapshot: RuntimeSnapshot) =
        let fieldValues name =
            Map.tryFind name snapshot.NativeFields |> Option.defaultValue [] |> words |> Set.ofList
        let services = fieldValues "services"
        let icmpTypes = fieldValues "icmp-blocks"
        let ipsets =
            snapshot.SourcesRaw
            |> List.choose (fun source ->
                if source.StartsWith("ipset:", StringComparison.Ordinal) then Some(source.Substring("ipset:".Length))
                else None)
            |> Set.ofList
        let mutable valid = true
        let mutable richServices = Set.empty
        let mutable richIcmpTypes = Set.empty
        let mutable richIpsets = Set.empty
        for rule in snapshot.RichRules do
            match richRuleReferences rule with
            | Some(ruleServices, ruleIcmpTypes, ruleIpsets) ->
                richServices <- Set.union richServices ruleServices
                richIcmpTypes <- Set.union richIcmpTypes ruleIcmpTypes
                richIpsets <- Set.union richIpsets ruleIpsets
            | None -> valid <- false
        (valid,
         Set.union services richServices,
         Set.union icmpTypes richIcmpTypes,
         Set.union ipsets richIpsets)

    /// Refuses a daemon-wide activation unless every loaded selector and active
    /// referenced definition matches permanent data, except active NetworkManager
    /// interface bindings which firewalld restores from NetworkManager on reload.
    /// This is a read-only preflight; it never copies runtime state into permanent data.
    let private kernelSetIsEmpty (environment: HostEnvironment) name =
        try
            let table = environment.Run "nft" [ "-j"; "list"; "table"; "inet"; "firewalld" ] None
            if table.ExitCode <> 0 then false
            else
                use document = JsonDocument.Parse(table.Stdout)
                let mutable matched, empty = 0, true
                for row in document.RootElement.GetProperty("nftables").EnumerateArray() do
                    for kind in [ "set"; "element" ] do
                        match row.TryGetProperty kind with
                        | true, obj when obj.GetProperty("family").GetString() = "inet" &&
                                         obj.GetProperty("table").GetString() = "firewalld" && obj.GetProperty("name").GetString() = name ->
                            if kind = "set" then matched <- matched + 1
                            match obj.TryGetProperty "elem" with
                            | true, entries when entries.ValueKind = JsonValueKind.Array && entries.GetArrayLength() = 0 -> ()
                            | false, _ when kind = "set" -> ()
                            | _ -> empty <- false
                        | _ -> ()
                matched = 1 && empty
        with _ -> false

    let private validateReloadCore
        (environment: HostEnvironment)
        (allowance: (string * string * (string * string) list) option)
        (excludedTarget: (string * string) option)
        : Result<unit, string> =
        try
            let mutable failure: string option = None
            let refuse reason =
                if failure.IsNone then failure <- Some reason
            let mutable allowanceObserved = allowance.IsNone
            let names kind permanent =
                match listObjectNames environment permanent kind with
                | Some values -> values
                | None ->
                    refuse ("Unable to enumerate " + (if permanent then "permanent " else "runtime ") + "firewalld " + kind + " objects.")
                    []
            // These three legacy getters are read-only. Never import, execute
            // or write direct/passthrough rules. A reload can discard them too.
            let mutable hasDirect = false
            for getter in [ "--get-all-rules"; "--get-all-chains"; "--get-all-passthroughs" ] do
                match run environment [ "--direct"; getter ], run environment [ "--permanent"; "--direct"; getter ] with
                | Some live, Some disk when live.TrimEnd() = disk.TrimEnd() ->
                    if not (String.IsNullOrWhiteSpace live) then hasDirect <- true
                | _ -> refuse "Unattributed direct runtime state prevents a daemon-wide firewalld activation."
            let runtimeZones = names "zone" false
            let permanentZones = names "zone" true
            let runtimePolicies = names "policy" false
            let permanentPolicies = names "policy" true
            let runtimeIpSets = names "ipset" false
            let permanentIpSets = names "ipset" true
            let excludedRuntimeNames, excludedPermanentNames =
                match excludedTarget with
                | Some("zone", _) -> runtimeZones, permanentZones
                | Some("policy", _) -> runtimePolicies, permanentPolicies
                | Some("ipset", _) -> runtimeIpSets, permanentIpSets
                | Some(kind, _) -> names kind false, names kind true
                | None -> [], []
            let namesMatch kind left right =
                let leftNames, rightNames = Set.ofList left, Set.ofList right
                match excludedTarget with
                | Some(targetKind, targetName) when targetKind = kind ->
                    Set.remove targetName leftNames = Set.remove targetName rightNames
                | _ -> leftNames = rightNames
            if not (namesMatch "zone" runtimeZones permanentZones) then refuse "Runtime and permanent firewalld zone inventories differ."
            if not (namesMatch "policy" runtimePolicies permanentPolicies) then refuse "Runtime and permanent firewalld policy inventories differ."
            if not (namesMatch "ipset" runtimeIpSets permanentIpSets) then refuse "Runtime and permanent firewalld ipset inventories differ."
            let mutable services = Set.empty<string>
            let mutable icmpTypes = Set.empty<string>
            let mutable activeIpSets = Set.empty<string>
            let recordReferences snapshot =
                let valid, objectServices, objectIcmpTypes, objectIpSets = referencesFromZonePolicy snapshot
                if not valid then false
                else
                    services <- Set.union services objectServices
                    icmpTypes <- Set.union icmpTypes objectIcmpTypes
                    activeIpSets <- Set.union activeIpSets objectIpSets
                    true
            let compareZonePolicy kind name =
                match inspectRuntimeWith environment false kind name, inspectRuntimeWith environment true kind name with
                | Some runtime, Some permanent
                    when runtime.UnknownFields.IsEmpty && permanent.UnknownFields.IsEmpty ->
                    let isExcluded = excludedTarget = Some(kind, name)
                    let fieldsMatch =
                        if isExcluded then true
                        else
                            match allowance |> Option.filter (fun (allowedKind, allowedName, _) -> allowedKind = kind && allowedName = name) with
                            | None -> normalizedObjectFields kind runtime = normalizedObjectFields kind permanent
                            | Some(_, _, selectors) ->
                                let fields = selectors |> List.map fst |> List.distinct
                                let stripAllowed current =
                                    fields |> List.fold (fun value fieldName -> Map.remove fieldName value) current
                                let runtimeFields = normalizedObjectFields kind runtime
                                let permanentFields = normalizedObjectFields kind permanent
                                let otherFieldsMatch = stripAllowed runtimeFields = stripAllowed permanentFields
                                let groups = selectors |> List.groupBy fst
                                let selectorsMatch =
                                    groups
                                    |> List.forall (fun (fieldName, pairs) ->
                                        missingSelectorsMatch kind fieldName (pairs |> List.map snd) runtime permanent)
                                let mutable referencesValid = true
                                if selectorsMatch then
                                    for fieldName, pairs in groups do
                                        let values = pairs |> List.map snd
                                        match fieldName with
                                        | "services" -> services <- Set.union services (Set.ofList values)
                                        | "icmp-blocks" -> icmpTypes <- Set.union icmpTypes (Set.ofList values)
                                        | "rich rules" ->
                                            for rule in values do
                                                match richRuleReferences rule with
                                                | Some(ruleServices, ruleIcmpTypes, ruleIpsets) ->
                                                    services <- Set.union services ruleServices
                                                    icmpTypes <- Set.union icmpTypes ruleIcmpTypes
                                                    activeIpSets <- Set.union activeIpSets ruleIpsets
                                                | None -> referencesValid <- false
                                        | _ -> ()
                                if otherFieldsMatch && selectorsMatch && referencesValid then
                                    allowanceObserved <- true
                                otherFieldsMatch && selectorsMatch && referencesValid
                    let interfacesMatch =
                        if isExcluded || kind <> "zone" then true
                        else
                            let live = Set.ofList runtime.Interfaces
                            let disk = Set.ofList permanent.Interfaces
                            Set.isSubset disk live
                            && (Set.difference live disk |> Set.forall (fun iface -> restoresRuntimeInterface environment iface name))
                    if not fieldsMatch || not interfacesMatch then
                        refuse ("Reload would change unpersisted live selectors in firewalld " + kind + " " + name + ".")
                    if not isExcluded && not (recordReferences runtime) then
                        refuse ("Cannot classify rich-rule references in firewalld " + kind + " " + name + ".")
                | _ -> refuse ("Cannot completely inspect runtime and permanent firewalld " + kind + " " + name + ".")

            for name in runtimeZones do
                if failure.IsNone && excludedTarget <> Some("zone", name) then compareZonePolicy "zone" name
            for name in runtimePolicies do
                if failure.IsNone && excludedTarget <> Some("policy", name) then compareZonePolicy "policy" name
            match excludedTarget with
            | Some(kind, name) when kind = "zone" || kind = "policy" ->
                let runtimeNames, permanentNames =
                    if kind = "zone" then runtimeZones, permanentZones
                    else runtimePolicies, permanentPolicies
                let collect present permanent =
                    if not present then true
                    else
                        match inspectRuntimeWith environment permanent kind name with
                        | Some snapshot when snapshot.UnknownFields.IsEmpty -> recordReferences snapshot
                        // During a structural Delete the daemon's permanent file watcher
                        // can remove exactly the target between enumeration and lookup.
                        // Prove its absence with a fresh successful permanent inventory;
                        // never treat a lookup error or an unreadable live target as absent.
                        | None when permanent ->
                            listObjectNames environment true kind
                            |> Option.exists (List.contains name >> not)
                        | _ -> false
                if not (collect (List.contains name runtimeNames) false
                        && collect (List.contains name permanentNames) true) then
                    refuse "Cannot inspect selector references on the excluded target."
            | _ -> ()


            let inspectExcludedDefinition kind name : Result<RuntimeSnapshot option * RuntimeSnapshot option, string> =
                let livePresent = List.contains name excludedRuntimeNames
                let diskPresent = List.contains name excludedPermanentNames
                let inspect permanent present =
                    if not present then Ok None
                    else
                        match inspectRuntimeWith environment permanent kind name with
                        | Some snapshot when snapshot.UnknownFields.IsEmpty -> Ok(Some snapshot)
                        | _ -> Error("Cannot inspect excluded firewalld " + kind + " " + name + ".")
                if not livePresent && not diskPresent then
                    Error("Excluded firewalld " + kind + " " + name + " is absent from both inventories.")
                else
                    match inspect false livePresent, inspect true diskPresent with
                    | Ok runtime, Ok permanent -> Ok(runtime, permanent)
                    | Error reason, _
                    | _, Error reason -> Error reason

            let mutable pendingServices = services
            let mutable checkedServices = Set.empty<string>
            let mutable pendingHelpers = Set.empty<string>
            let addServiceDependencies (snapshot: RuntimeSnapshot) =
                let includes = Map.tryFind "includes" snapshot.NativeFields |> Option.defaultValue [] |> words |> Set.ofList
                let helpers = Map.tryFind "helpers" snapshot.NativeFields |> Option.defaultValue [] |> words |> Set.ofList
                let modules =
                    Map.tryFind "modules" snapshot.NativeFields
                    |> Option.defaultValue []
                    |> normalizeFieldValues "service" "modules"
                    |> Set.ofList
                pendingServices <- Set.union pendingServices includes
                pendingHelpers <- Set.union pendingHelpers (Set.union helpers modules)
            while not pendingServices.IsEmpty && failure.IsNone do
                let name = Set.minElement pendingServices
                pendingServices <- Set.remove name pendingServices
                if not (Set.contains name checkedServices) then
                    checkedServices <- Set.add name checkedServices
                    if excludedTarget = Some("service", name) then
                        match inspectExcludedDefinition "service" name with
                        | Error reason -> refuse reason
                        | Ok(runtime, permanent) ->
                            if permanent.IsNone && Set.contains name services then
                                refuse "Reload would leave an active firewalld service reference unresolved."
                            [ runtime; permanent ]
                            |> List.choose id
                            |> List.iter addServiceDependencies
                    else
                        match inspectRuntimeWith environment false "service" name, inspectRuntimeWith environment true "service" name with
                        | Some runtime, Some permanent
                            when runtime.UnknownFields.IsEmpty && permanent.UnknownFields.IsEmpty
                                 && normalizedObjectFields "service" runtime = normalizedObjectFields "service" permanent ->
                            addServiceDependencies runtime
                        | _ -> refuse ("Reload would change or cannot inspect active firewalld service " + name + ".")

            let mutable checkedHelpers = Set.empty<string>
            while not pendingHelpers.IsEmpty && failure.IsNone do
                let name = Set.minElement pendingHelpers
                pendingHelpers <- Set.remove name pendingHelpers
                if not (Set.contains name checkedHelpers) then
                    checkedHelpers <- Set.add name checkedHelpers
                    if excludedTarget = Some("helper", name) then
                        match inspectExcludedDefinition "helper" name with
                        | Ok(_, permanent) when permanent.IsNone ->
                            refuse "Reload would leave an active firewalld helper reference unresolved."
                        | Ok _ -> ()
                        | Error reason -> refuse reason
                    else
                        match inspectRuntimeWith environment false "helper" name, inspectRuntimeWith environment true "helper" name with
                        | Some runtime, Some permanent
                            when runtime.UnknownFields.IsEmpty && permanent.UnknownFields.IsEmpty
                                 && normalizedObjectFields "helper" runtime = normalizedObjectFields "helper" permanent -> ()
                        | _ -> refuse ("Reload would change or cannot inspect active firewalld helper " + name + ".")

            for name in icmpTypes do
                if failure.IsNone then
                    if excludedTarget = Some("icmptype", name) then
                        match inspectExcludedDefinition "icmptype" name with
                        | Ok(_, permanent) when permanent.IsNone ->
                            refuse "Reload would leave an active firewalld ICMP reference unresolved."
                        | Ok _ -> ()
                        | Error reason -> refuse reason
                    else
                        match inspectRuntimeWith environment false "icmptype" name, inspectRuntimeWith environment true "icmptype" name with
                        | Some runtime, Some permanent
                            when runtime.UnknownFields.IsEmpty && permanent.UnknownFields.IsEmpty
                                 && normalizedObjectFields "icmptype" runtime = normalizedObjectFields "icmptype" permanent -> ()
                        | _ -> refuse ("Reload would change or cannot inspect active firewalld ICMP type " + name + ".")

            let knownIpSets = Set.ofList runtimeIpSets
            let referencedIpSets =
                match excludedTarget with
                | Some("ipset", name) -> Set.remove name activeIpSets
                | _ -> activeIpSets
            if not (Set.isSubset referencedIpSets knownIpSets) then
                refuse "An active firewalld selector references an uninspectable ipset."
            for name in runtimeIpSets do
                if failure.IsNone then
                    match inspectRuntimeWith environment false "ipset" name, inspectRuntimeWith environment true "ipset" name with
                    | Some runtime, _ when
                        (match Map.tryFind "timeout" runtime.IpSetOptions with
                         | None | Some(Some "0") -> false
                         | _ -> true) && (hasDirect || not (kernelSetIsEmpty environment name)) ->
                        refuse ("The expiring kernel members of ipset " + name + " are not observable through firewalld; refusing a flushing activation.")
                    | Some _, _ when excludedTarget = Some("ipset", name) -> ()
                    | Some runtime, Some permanent
                        when runtime.UnknownFields.IsEmpty
                             && permanent.UnknownFields.IsEmpty
                             && runtime.IpSetType = permanent.IpSetType
                             && runtime.IpSetOptions = permanent.IpSetOptions
                             && Set.ofList runtime.IpSetEntries = Set.ofList permanent.IpSetEntries -> ()
                    | _ -> refuse ("Reload would change or cannot inspect live firewalld ipset " + name + ".")

            match excludedTarget with
            | Some("ipset", name)
                when Set.contains name activeIpSets && not (List.contains name permanentIpSets) ->
                refuse "Reload would leave an active firewalld ipset selector unresolved."
            | _ -> ()

            if not allowanceObserved then
                refuse "The requested missing selector was not the only proven live decrease."
            match failure with
            | Some reason -> Error reason
            | None -> Ok ()
        with error -> Error("Unable to prove firewalld reload safety: " + error.Message)

    /// Requires strict host-wide runtime/permanent equivalence before daemon activation.
    let validateReload (environment: HostEnvironment) : Result<unit, string> =
        validateReloadCore environment None None

    /// Allows only the exact listed permanent-to-runtime selector decreases on one
    /// zone or policy; all unrelated host state remains subject to strict proof.
    let validateReloadAllowingMissingSelectors
        (environment: HostEnvironment)
        (kind: string)
        (name: string)
        (selectors: (string * string) list)
        : Result<unit, string> =
        let supportedFields =
            [ "services"; "ports"; "source-ports"; "protocols"; "icmp-blocks"; "rich rules"; "forward-ports" ]
        let valid =
            List.contains kind [ "zone"; "policy" ]
            && not (String.IsNullOrWhiteSpace name)
            && not selectors.IsEmpty
            && selectors.Length <= 4096
            && (selectors |> List.forall (fun (field, value) ->
                List.contains field supportedFields && not (String.IsNullOrWhiteSpace value)))
            && (selectors |> List.distinct).Length = selectors.Length
        if not valid then
            Error "The reload exception must identify a bounded, unique set of zone or policy selectors."
        else
            validateReloadCore environment (Some(kind, name, selectors)) None

    /// Single-entry convenience form of the bounded selector allowlist.
    let validateReloadAllowingMissingSelector
        (environment: HostEnvironment)
        (kind: string)
        (name: string)
        (field: string)
        (value: string)
        : Result<unit, string> =
        validateReloadAllowingMissingSelectors environment kind name [ field, value ]

    /// Compare all other objects. A new unreferenced object can be absent from
    /// both daemon inventories until reload; callers verify its actual loaded
    /// preimage and its staged/restored disk projection separately.
    let validateReloadExcludingTargetObject
        (environment: HostEnvironment)
        (kind: string)
        (name: string)
        : Result<unit, string> =
        if not (List.contains kind [ "zone"; "policy"; "service"; "ipset"; "icmptype"; "helper" ])
           || String.IsNullOrWhiteSpace name then
            Error "The reload exclusion must identify one firewalld object."
        else
            validateReloadCore environment None (Some(kind, name))
