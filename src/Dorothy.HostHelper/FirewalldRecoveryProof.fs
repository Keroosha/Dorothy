namespace Dorothy.HostHelper

open System
open System.Net
open System.Security.Cryptography
open System.Text
open System.Text.Json.Nodes
open System.Text.RegularExpressions

module FirewalldRecoveryProof =
    type private RepairEffect =
        | Grants
        | Restricts
        | Observes
        | Steers

    type private RuntimeDelta =
        { Field: string
          Value: string
          Effect: RepairEffect }

    type private ObjectDelta =
        { Field: string
          Value: string
          Add: bool
          Effect: RepairEffect }

    type private RuntimeRepair =
        { Deltas: RuntimeDelta list
          StateFingerprints: string list
          Version: int
          DeclaredInterfaces: string list
          DeclaredNativeInterfaces: string list }
    type private ObjectRepair =
        { Before: FirewalldRuntime.RuntimeSnapshot
          After: FirewalldRuntime.RuntimeSnapshot
          Deltas: ObjectDelta list
          StateFingerprints: string list }

    let private fail message = raise (InvalidOperationException(message))

    let private expectedNativeFields kind =
        match kind with
        | "zone" ->
            set [ "target"; "ingress-priority"; "egress-priority"; "icmp-block-inversion"; "interfaces"; "sources"
                  "services"; "ports"; "protocols"; "forward"; "masquerade"; "forward-ports"; "source-ports"
                  "icmp-blocks"; "rich rules" ]
        | "policy" ->
            set [ "priority"; "target"; "ingress-zones"; "egress-zones"; "services"; "ports"; "protocols"
                  "masquerade"; "forward-ports"; "source-ports"; "icmp-blocks"; "rich rules" ]
        | "service" -> set [ "ports"; "protocols"; "source-ports"; "modules"; "destination"; "includes"; "helpers" ]
        | "ipset" -> set [ "type"; "options"; "entries" ]
        | "icmptype" -> set [ "destination" ]
        | "helper" -> set [ "family"; "module"; "ports" ]
        | _ -> Set.empty

    let snapshotComplete (snapshot: FirewalldRuntime.RuntimeSnapshot) =
        let expected = expectedNativeFields snapshot.Kind
        let actual = snapshot.NativeFields |> Map.keys |> Set.ofSeq
        let metadata = set [ "short"; "description" ]
        not expected.IsEmpty
        && Set.isSubset expected actual
        && Set.isEmpty (Set.difference actual (Set.union expected metadata))
        && (snapshot.UnknownFields |> Map.forall (fun key _ -> Set.contains key metadata))

    let private ensureCompleteSnapshot (configuration: FirewalldModel.Configuration) (snapshot: FirewalldRuntime.RuntimeSnapshot) =
        if configuration.Kind <> snapshot.Kind || configuration.Name <> snapshot.Name then
            fail "Runtime rollback proof inspected a different firewalld object."
        if not (snapshotComplete snapshot) then
            fail "Runtime firewalld object does not expose a complete native selector snapshot."

    let private sorted (values: string list) =
        values |> List.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right))

    let rec private elementJson (element: FirewalldModel.Element) =
        let node = JsonObject()
        node["name"] <- JsonValue.Create element.Name
        let attributes = JsonObject()
        element.Attributes
        |> Map.toList
        |> List.sortBy fst
        |> List.iter (fun (name, value) -> attributes[name] <- JsonValue.Create value)
        node["attributes"] <- attributes
        node["text"] <-
            match element.Text with
            | None -> null
            | Some value -> JsonValue.Create value :> JsonNode
        let children = JsonArray()
        for child in element.Children do children.Add(elementJson child)
        node["children"] <- children
        node

    let fingerprint (snapshot: FirewalldRuntime.RuntimeSnapshot) =
        let node = JsonObject()
        node["kind"] <- JsonValue.Create snapshot.Kind
        node["name"] <- JsonValue.Create snapshot.Name
        node["target"] <- JsonValue.Create snapshot.Target
        let addOptionalInt (key: string) (value: int option) =
            node[key] <-
                match value with
                | None -> null
                | Some number -> JsonValue.Create number :> JsonNode
        let addStrings (key: string) (values: string list) =
            let array = JsonArray()
            for value in sorted values do array.Add(JsonValue.Create value)
            node[key] <- array
        let addElements (key: string) values =
            let serialized =
                values
                |> List.map (elementJson >> fun item -> item.ToJsonString())
                |> List.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right))
            let array = JsonArray()
            for value in serialized do array.Add(JsonValue.Create value)
            node[key] <- array
        let addNativeFields () =
            let fields = JsonObject()
            snapshot.NativeFields
            |> Map.toList
            |> List.filter (fun (key, _) -> key <> "short" && key <> "description")
            |> List.sortBy fst
            |> List.iter (fun (key, values) ->
                let array = JsonArray()
                for value in FirewalldRuntime.normalizeFieldValues snapshot.Kind key values do
                    array.Add(JsonValue.Create value)
                fields[key] <- array)
            node["nativeFields"] <- fields

        addOptionalInt "priority" snapshot.Priority
        addOptionalInt "ingressPriority" snapshot.IngressPriority
        addOptionalInt "egressPriority" snapshot.EgressPriority
        addStrings "ingress" snapshot.Ingress
        addStrings "egress" snapshot.Egress
        addStrings "interfaces" snapshot.Interfaces
        addStrings "sourcesRaw" (FirewalldRuntime.normalizeFieldValues snapshot.Kind "sources" snapshot.SourcesRaw)
        addElements "sources" snapshot.Sources
        addStrings "services" (FirewalldRuntime.normalizeFieldValues snapshot.Kind "services" snapshot.Services)
        addStrings "ports" (FirewalldRuntime.normalizeFieldValues snapshot.Kind "ports" snapshot.Ports)
        addStrings "protocols" snapshot.Protocols
        addStrings "sourcePorts" (FirewalldRuntime.normalizeFieldValues snapshot.Kind "source-ports" snapshot.SourcePorts)
        addElements "forwardPorts" snapshot.ForwardPorts
        node["masquerade"] <- JsonValue.Create snapshot.Masquerade
        node["forward"] <- JsonValue.Create snapshot.Forward
        addStrings "icmpBlocks" snapshot.IcmpBlocks
        node["icmpBlockInversion"] <- JsonValue.Create snapshot.IcmpBlockInversion
        addStrings "richRules" snapshot.RichRules
        node["ipSetType"] <-
            match snapshot.IpSetType with
            | None -> null
            | Some value -> JsonValue.Create value :> JsonNode
        let options = JsonObject()
        snapshot.IpSetOptions
        |> Map.toList
        |> List.sortBy fst
        |> List.iter (fun (key, value) ->
            options[key] <-
                match value with
                | None -> null
                | Some text -> JsonValue.Create text :> JsonNode)
        node["ipSetOptions"] <- options
        addStrings "ipSetEntries" snapshot.IpSetEntries
        addNativeFields ()
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(node.ToJsonString()))).ToLowerInvariant()

    let snapshotsEqual (left: FirewalldRuntime.RuntimeSnapshot) (right: FirewalldRuntime.RuntimeSnapshot) =
        left.Kind = right.Kind
        && left.Name = right.Name
        && snapshotComplete left
        && snapshotComplete right
        && fingerprint left = fingerprint right

    let private interfaceEvidence (snapshot: FirewalldRuntime.RuntimeSnapshot) =
        if snapshot.Kind <> "zone" then Some([], [])
        else
            match Map.tryFind "interfaces" snapshot.NativeFields with
            | None -> None
            | Some nativeValues ->
                let typed =
                    FirewalldRuntime.normalizeFieldValues "zone" "interfaces" snapshot.Interfaces
                    |> sorted
                let native =
                    FirewalldRuntime.normalizeFieldValues "zone" "interfaces" nativeValues
                    |> sorted
                if typed = native then Some(typed, native) else None

    let private projectLiveInterfaces
        (environment: HostEnvironment)
        (declaredInterfaces: string list)
        (actualLive: FirewalldRuntime.RuntimeSnapshot)
        =
        if actualLive.Kind <> "zone" then Some actualLive
        else
            match interfaceEvidence actualLive with
            | None -> None
            | Some(liveInterfaces, _) when Set.isSubset (Set.ofList declaredInterfaces) (Set.ofList liveInterfaces) ->
                let declared = Set.ofList declaredInterfaces
                let extra = Set.difference (Set.ofList liveInterfaces) declared
                let restoredByOwner =
                    extra
                    |> Set.forall (fun interfaceName ->
                        FirewalldRuntime.restoresRuntimeInterface environment interfaceName actualLive.Name)
                if not restoredByOwner then None
                else
                    let nativeValue =
                        if declaredInterfaces.IsEmpty then []
                        else [ String.concat " " declaredInterfaces ]
                    Some
                        { actualLive with
                            Interfaces = declaredInterfaces
                            NativeFields = Map.add "interfaces" nativeValue actualLive.NativeFields }
            | Some _ -> None

    /// Compares a live snapshot to the effective disk projection after proving
    /// that only firewalld interfaces assigned by NetworkManager are added.
    let matchesLoadedProjection
        (environment: HostEnvironment)
        (expectedDiskSnapshot: FirewalldRuntime.RuntimeSnapshot)
        (actualLive: FirewalldRuntime.RuntimeSnapshot)
        : bool =
        if expectedDiskSnapshot.Kind <> actualLive.Kind
           || expectedDiskSnapshot.Name <> actualLive.Name
           || not (snapshotComplete expectedDiskSnapshot)
           || not (snapshotComplete actualLive) then false
        else
            match interfaceEvidence expectedDiskSnapshot with
            | None -> false
            | Some(declaredInterfaces, _) ->
                projectLiveInterfaces environment declaredInterfaces actualLive
                |> Option.exists (snapshotsEqual expectedDiskSnapshot)


    let private elementAttribute key (element: FirewalldModel.Element) =
        Map.tryFind key element.Attributes

    let private directValues (configuration: FirewalldModel.Configuration) name key =
        configuration.Elements
        |> List.filter (fun element -> element.Name = name)
        |> List.choose (elementAttribute key)
    let private declaredInterfaceEvidence (configuration: FirewalldModel.Configuration) =
        if configuration.Kind <> "zone" then [], []
        else
            let declared =
                configuration.Interfaces @ directValues configuration "interface" "name"
                |> FirewalldRuntime.normalizeFieldValues "zone" "interfaces"
                |> sorted
            declared, declared

    let private directPorts (configuration: FirewalldModel.Configuration) name =
        configuration.Elements
        |> List.filter (fun element -> element.Name = name)
        |> List.choose (fun element ->
            match elementAttribute "port" element, elementAttribute "protocol" element with
            | Some port, Some protocol -> Some(FirewalldModel.port (port + "/" + protocol))
            | _ -> None)

    let private expectedSelectorValues (configuration: FirewalldModel.Configuration) =
        let normalize field values = FirewalldRuntime.normalizeFieldValues configuration.Kind field values
        let richRules =
            FirewalldRuntime.expectedRichRuleStrings configuration
            |> Option.defaultWith (fun () -> fail "Declared rich rules cannot be represented in firewalld's native grammar.")
        let forwardPorts =
            FirewalldRuntime.expectedForwardPortValues configuration
            |> Option.defaultWith (fun () -> fail "Declared forward-ports cannot be represented in firewalld's native grammar.")
        Map.ofList
            [ "services", normalize "services" (configuration.Services @ directValues configuration "service" "name")
              "ports", normalize "ports" (configuration.Ports @ directPorts configuration "port")
              "source-ports", normalize "source-ports" (directPorts configuration "source-port")
              "protocols", normalize "protocols" (configuration.Protocols @ directValues configuration "protocol" "value")
              "icmp-blocks", normalize "icmp-blocks" (directValues configuration "icmp-block" "name")
              "rich rules", richRules |> List.distinct |> sorted
              "forward-ports", forwardPorts |> List.distinct |> sorted ]

    let private actualSelectorValues (snapshot: FirewalldRuntime.RuntimeSnapshot) =
        let normalize field values = FirewalldRuntime.normalizeFieldValues snapshot.Kind field values
        let forwardPorts =
            snapshot.ForwardPorts
            |> List.map (fun element ->
                FirewalldRuntime.canonicalForwardPortValue element
                |> Option.defaultWith (fun () -> fail "A runtime forward-port cannot be represented for rollback."))
        Map.ofList
            [ "services", normalize "services" snapshot.Services
              "ports", normalize "ports" snapshot.Ports
              "source-ports", normalize "source-ports" snapshot.SourcePorts
              "protocols", normalize "protocols" snapshot.Protocols
              "icmp-blocks", normalize "icmp-blocks" snapshot.IcmpBlocks
              "rich rules", snapshot.RichRules |> List.distinct |> sorted
              "entries", normalize "entries" snapshot.IpSetEntries
              "forward-ports", forwardPorts |> List.distinct |> sorted ]

    let private expectedForwardPortElement (configuration: FirewalldModel.Configuration) value =
        configuration.Elements
        |> List.tryFind (fun element ->
            element.Name = "forward-port"
            && FirewalldRuntime.canonicalForwardPortValue element = Some value)
        |> Option.defaultWith (fun () -> fail "A runtime forward-port is not in the declared object.")

    let private setRuntimeField
        (configuration: FirewalldModel.Configuration)
        (snapshot: FirewalldRuntime.RuntimeSnapshot)
        field values
        =
        let values =
            if field = "rich rules" || field = "forward-ports" then values |> List.distinct |> sorted
            else FirewalldRuntime.normalizeFieldValues configuration.Kind field values
        let encoded =
            if values.IsEmpty then []
            elif field = "rich rules" || field = "forward-ports" then values
            else [ String.concat " " values ]
        let snapshot = { snapshot with NativeFields = Map.add field encoded snapshot.NativeFields }
        match field with
        | "services" -> { snapshot with Services = values }
        | "ports" -> { snapshot with Ports = values }
        | "source-ports" -> { snapshot with SourcePorts = values }
        | "protocols" -> { snapshot with Protocols = values }
        | "icmp-blocks" -> { snapshot with IcmpBlocks = values }
        | "rich rules" -> { snapshot with RichRules = values }
        | "forward-ports" ->
            { snapshot with ForwardPorts = values |> List.map (expectedForwardPortElement configuration) }
        | _ -> fail "Unsupported selector in firewalld runtime rollback proof."

    let private applyDelta
        (configuration: FirewalldModel.Configuration)
        (snapshot: FirewalldRuntime.RuntimeSnapshot)
        (delta: RuntimeDelta)
        add
        =
        let current = actualSelectorValues snapshot |> Map.find delta.Field
        let next =
            if add then delta.Value :: current
            else current |> List.filter ((<>) delta.Value)
        setRuntimeField configuration snapshot delta.Field next

    let private ownedFingerprintRaw
        (configuration: FirewalldModel.Configuration)
        (snapshot: FirewalldRuntime.RuntimeSnapshot)
        =
        let expectedRich = expectedSelectorValues configuration |> Map.find "rich rules" |> Set.ofList
        let ownedRich =
            snapshot.RichRules
            |> List.filter (fun rule -> Set.contains rule expectedRich)
            |> sorted
        fingerprint { snapshot with RichRules = ownedRich; NativeFields = Map.empty }

    let private ownedFingerprint
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (declaredInterfaces: string list)
        (snapshot: FirewalldRuntime.RuntimeSnapshot)
        =
        let snapshot =
            if configuration.Kind = "zone" then
                projectLiveInterfaces environment declaredInterfaces snapshot
                |> Option.defaultWith (fun () -> fail "Runtime interfaces are missing declared bindings or contain non-NetworkManager extras.")
            else snapshot
        let expectedRich = expectedSelectorValues configuration |> Map.find "rich rules" |> Set.ofList
        let ownedRich =
            snapshot.RichRules
            |> List.filter (fun rule -> Set.contains rule expectedRich)
            |> sorted
        let nativeFields =
            if configuration.Kind = "zone" then
                let interfaces = if declaredInterfaces.IsEmpty then [] else [ String.concat " " declaredInterfaces ]
                Map.ofList [ "interfaces", interfaces ]
            else Map.empty
        fingerprint { snapshot with RichRules = ownedRich; NativeFields = nativeFields }

    let private ownedFingerprintForRepair
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (repair: RuntimeRepair)
        (snapshot: FirewalldRuntime.RuntimeSnapshot)
        =
        if repair.Version = 1 then ownedFingerprintRaw configuration snapshot
        else ownedFingerprint environment configuration repair.DeclaredInterfaces snapshot

    let private adjustedConfiguration
        (configuration: FirewalldModel.Configuration)
        (snapshot: FirewalldRuntime.RuntimeSnapshot)
        =
        let actual = actualSelectorValues snapshot
        let actualSet field = Map.find field actual |> Set.ofList
        let expectedRich = expectedSelectorValues configuration |> Map.find "rich rules" |> Set.ofList
        let actualOwnedRich = Set.intersect expectedRich (actualSet "rich rules")
        let elements =
            configuration.Elements
            |> List.filter (fun element ->
                match element.Name with
                | "service" | "port" | "protocol" -> false
                | "source-port" ->
                    match elementAttribute "port" element, elementAttribute "protocol" element with
                    | Some port, Some protocol ->
                        Set.contains (FirewalldModel.port (port + "/" + protocol)) (actualSet "source-ports")
                    | _ -> false
                | "icmp-block" ->
                    elementAttribute "name" element
                    |> Option.exists (fun value -> Set.contains value (actualSet "icmp-blocks"))
                | "forward-port" ->
                    FirewalldRuntime.canonicalForwardPortValue element
                    |> Option.exists (fun value -> Set.contains value (actualSet "forward-ports"))
                | "rule" ->
                    FirewalldRuntime.canonicalRichRule element
                    |> Option.exists (fun value -> Set.contains value actualOwnedRich)
                | _ -> true)
        { configuration with
            Services = snapshot.Services
            Ports = snapshot.Ports
            Protocols = snapshot.Protocols
            Elements = elements }

    let private observeAdjusted
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (snapshot: FirewalldRuntime.RuntimeSnapshot)
        =
        let observed = FirewalldRuntime.observe environment (adjustedConfiguration configuration snapshot)
        if not observed.Observed || not observed.InSync then
            fail "Non-repaired runtime selectors do not independently match the declared object."

    let private richRuleEffect (configuration: FirewalldModel.Configuration) value =
        let rule =
            configuration.Elements
            |> List.tryFind (fun element ->
                element.Name = "rule"
                && FirewalldRuntime.canonicalRichRule element = Some value)
            |> Option.defaultWith (fun () -> fail "A runtime rich-rule selector is not in the declared object.")
        let actions =
            rule.Children
            |> List.filter (fun child ->
                List.contains child.Name
                    [ "accept"; "drop"; "reject"; "mark"; "forward-port"; "masquerade"; "icmp-block"; "tcp-mss-clamp" ])
        match actions with
        | [ action ] when action.Name = "drop" || action.Name = "reject" || action.Name = "icmp-block" -> Restricts
        | [ action ] when action.Name = "accept" -> Grants
        | [ action ] when action.Name = "forward-port" || action.Name = "masquerade"
                          || action.Name = "mark" || action.Name = "tcp-mss-clamp" -> Steers
        | [] when rule.Children |> List.exists (fun child -> child.Name = "log" || child.Name = "nflog") ->
            // LOG/NFLOG alone produces a record, not a packet verdict.
            Observes
        | _ -> fail "A rich rule has no single reversible monotone action; refusing runtime-only repair."

    let private deltaEffect (configuration: FirewalldModel.Configuration) field value =
        match field with
        | "icmp-blocks" ->
            let inverted =
                configuration.Kind = "zone"
                && (configuration.Elements |> List.exists (fun element -> element.Name = "icmp-block-inversion"))
            if inverted then Grants else Restricts
        | "rich rules" -> richRuleEffect configuration value
        | "forward-ports" -> Steers
        | "services" | "ports" | "source-ports" | "protocols" -> Grants
        | _ -> fail "The runtime selector has no proven native inverse."

    let private fieldOrder =
        Map.ofList
            [ "services", 0; "ports", 1; "source-ports", 2; "protocols", 3
              "forward-ports", 4; "icmp-blocks", 5; "rich rules", 6; "sources", 7; "entries", 8 ]

    let private effectOrder = function Restricts -> 0 | Steers | Observes -> 1 | Grants -> 2

    let private sortDeltas (deltas: RuntimeDelta list) =
        deltas
        |> List.sortWith (fun left right ->
            let effectCompare = compare (effectOrder left.Effect) (effectOrder right.Effect)
            if effectCompare <> 0 then effectCompare
            else
                let fieldCompare = compare (Map.find left.Field fieldOrder) (Map.find right.Field fieldOrder)
                if fieldCompare <> 0 then fieldCompare
                else StringComparer.Ordinal.Compare(left.Value, right.Value))

    let private planRuntimeRepair
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (snapshot: FirewalldRuntime.RuntimeSnapshot)
        =
        ensureCompleteSnapshot configuration snapshot
        let declaredInterfaces, declaredNativeInterfaces = declaredInterfaceEvidence configuration
        let snapshot =
            if configuration.Kind = "zone" then
                projectLiveInterfaces environment declaredInterfaces snapshot
                |> Option.defaultWith (fun () -> fail "Live zone interfaces are missing declared bindings or include non-NetworkManager additions.")
            else snapshot
        let expected = expectedSelectorValues configuration
        let actual = actualSelectorValues snapshot
        let deltas =
            expected
            |> Map.toList
            |> List.collect (fun (field, expectedValues) ->
                let expectedSet = Set.ofList expectedValues
                let actualSet = Map.find field actual |> Set.ofList
                let missing = Set.difference expectedSet actualSet
                let extra = Set.difference actualSet expectedSet
                if field <> "rich rules" && not extra.IsEmpty then
                    fail ("Unowned runtime " + field + " selectors prevent safe repair; refusing to erase them.")
                missing
                |> Set.toList
                |> List.map (fun value ->
                    { Field = field
                      Value = value
                      Effect = deltaEffect configuration field value }))
            |> sortDeltas
        if deltas.IsEmpty then
            fail "Runtime drift has no supported missing native selector; refusing mutation without an inverse."
        if deltas.Length > 4096 then fail "Runtime repair exceeds the bounded native selector proof."
        let effects = deltas |> List.map (fun delta -> delta.Effect) |> Set.ofList
        if Set.contains Steers effects && (effects.Count > 1 || deltas.Length > 1) then
            fail "Runtime repair mixes steering with other selectors or has multiple steering deltas without a proved safe order."
        observeAdjusted environment configuration snapshot
        let currentSnapshot =
            FirewalldRuntime.inspectRuntime environment configuration.Kind configuration.Name
            |> Option.defaultWith (fun () -> fail "Unable to re-observe the loaded firewalld object before staging its runtime repair.")
            |> fun current ->
                if configuration.Kind = "zone" then
                    projectLiveInterfaces environment declaredInterfaces current
                    |> Option.defaultWith (fun () -> fail "Live zone interfaces changed outside the declared/NM-backed projection.")
                else current
        ensureCompleteSnapshot configuration currentSnapshot
        if fingerprint currentSnapshot <> fingerprint snapshot then
            fail "Runtime firewalld selectors changed while preparing the rollback proof."
        let permanentSnapshot =
            FirewalldRuntime.inspectPermanent environment configuration.Kind configuration.Name
            |> Option.defaultWith (fun () -> fail "Unable to observe the permanent firewalld object required for boot rollback proof.")
            |> fun permanent ->
                if configuration.Kind = "zone" then
                    projectLiveInterfaces environment declaredInterfaces permanent
                    |> Option.defaultWith (fun () -> fail "Permanent zone interfaces differ outside the declared/NM-backed projection.")
                else permanent
        ensureCompleteSnapshot configuration permanentSnapshot
        let permanentBefore =
            deltas |> List.fold (fun state delta -> applyDelta configuration state delta false) permanentSnapshot
        if ownedFingerprint environment configuration declaredInterfaces permanentBefore
           <> ownedFingerprint environment configuration declaredInterfaces snapshot then
            fail "Live owned selectors differ from their permanent preimage outside the reversible native deltas."
        let mutable state = snapshot
        let fingerprints = ResizeArray<string>()
        fingerprints.Add(ownedFingerprint environment configuration declaredInterfaces state)
        for delta in deltas do
            state <- applyDelta configuration state delta true
            fingerprints.Add(ownedFingerprint environment configuration declaredInterfaces state)
        { Deltas = deltas
          StateFingerprints = List.ofSeq fingerprints
          Version = 2
          DeclaredInterfaces = declaredInterfaces
          DeclaredNativeInterfaces = declaredNativeInterfaces }

    let private proofBase (configuration: FirewalldModel.Configuration) (strategy: string) =
        let node = JsonObject()
        node["version"] <- JsonValue.Create 1
        node["scope"] <- JsonValue.Create "object"
        node["kind"] <- JsonValue.Create configuration.Kind
        node["name"] <- JsonValue.Create configuration.Name
        node["strategy"] <- JsonValue.Create strategy
        node

    let private interfaceArray (values: string list) =
        let array = JsonArray()
        for value in values do array.Add(JsonValue.Create value)
        array

    let private writeInterfaceEvidence (node: JsonObject) (prefix: string) (snapshot: FirewalldRuntime.RuntimeSnapshot option) =
        let typed, native =
            match snapshot with
            | None -> [], []
            | Some value ->
                interfaceEvidence value
                |> Option.defaultWith (fun () -> fail "The declared interface projection is inconsistent.")
        node[prefix + "Interfaces"] <- interfaceArray typed
        node[prefix + "NativeInterfaces"] <- interfaceArray native

    let private readInterfaceArray (node: JsonObject) (key: string) =
        let values =
            match node[key] with
            | :? JsonArray as array ->
                array
                |> Seq.map (fun value ->
                    if isNull value then fail ("Invalid interface evidence " + key + ".")
                    value.GetValue<string>())
                |> List.ofSeq
            | _ -> fail ("Missing interface evidence " + key + ".")
        if values.Length > 4096
           || (values |> List.exists String.IsNullOrWhiteSpace)
           || values <> sorted values
           || (values |> List.distinct).Length <> values.Length then
            fail ("Invalid or noncanonical interface evidence " + key + ".")
        values

    let private readInterfaceEvidence (node: JsonObject) (prefix: string) =
        let typed = readInterfaceArray node (prefix + "Interfaces")
        let native = readInterfaceArray node (prefix + "NativeInterfaces")
        if typed <> native then fail ("Typed and native interface evidence differ for " + prefix + ".")
        typed, native


    let reloadProof
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (effectiveBefore: string option)
        (effectiveAfter: string option)
        =
        let node = proofBase configuration "reload-before"
        node["version"] <- JsonValue.Create 2
        let diskBefore =
            match FirewalldRuntime.snapshotFromXml configuration.Kind configuration.Name effectiveBefore with
            | Error reason -> fail ("Cannot project the effective on-disk firewalld preimage: " + reason)
            | Ok None -> None
            | Ok(Some snapshot) when snapshotComplete snapshot -> Some snapshot
            | Ok(Some _) -> fail "The effective on-disk firewalld preimage has unknown native selectors."
        writeInterfaceEvidence node "before" diskBefore
        match FirewalldRuntime.queryPermanent environment configuration.Kind configuration.Name,
              FirewalldRuntime.queryRuntime environment configuration.Kind configuration.Name with
        | Error reason, _ -> fail ("Cannot prove the permanent firewalld preimage before reload: " + reason)
        | _, Error reason -> fail ("Cannot prove the loaded firewalld preimage before reload: " + reason)
        | Ok None, Ok None when diskBefore.IsNone ->
            node["beforePresent"] <- JsonValue.Create false
            node["beforeFingerprint"] <- null
        | Ok(Some permanent), Ok(Some live) ->
            let disk =
                diskBefore
                |> Option.defaultWith (fun () -> fail "The loaded firewalld preimage exists but its effective on-disk definition is absent.")
            if not (matchesLoadedProjection environment disk permanent
                    && matchesLoadedProjection environment disk live) then
                fail "Permanent or loaded selectors differ from the effective disk projection outside NetworkManager-restored interfaces; refusing daemon-wide recovery by reload."
            node["beforePresent"] <- JsonValue.Create true
            node["beforeFingerprint"] <- JsonValue.Create(fingerprint disk)
        | _ ->
            fail "The loaded firewalld target presence differs from the effective on-disk preimage; refusing daemon-wide recovery by reload."
        match FirewalldRuntime.snapshotFromXml configuration.Kind configuration.Name effectiveAfter with
        | Error reason -> fail ("Cannot project the post-transaction firewalld target: " + reason)
        | Ok None ->
            writeInterfaceEvidence node "after" None
            node["afterPresent"] <- JsonValue.Create false
            node["afterFingerprint"] <- null
        | Ok(Some after) when snapshotComplete after ->
            writeInterfaceEvidence node "after" (Some after)
            node["afterPresent"] <- JsonValue.Create true
            node["afterFingerprint"] <- JsonValue.Create(fingerprint after)
        | Ok(Some _) -> fail "The post-transaction firewalld target has unknown native selectors."
        node

    let unchangedProof (configuration: FirewalldModel.Configuration) =
        proofBase configuration "unchanged"

    let private effectName = function Grants -> "grant" | Restricts -> "restrict" | Steers -> "steer" | Observes -> "observe"

    let private objectSelectorFields kind =
        if kind = "ipset" then [ "entries" ]
        elif kind = "zone" then
            [ "services"; "ports"; "source-ports"; "protocols"; "icmp-blocks"; "rich rules"; "forward-ports"; "sources" ]
        else [ "services"; "ports"; "source-ports"; "protocols"; "icmp-blocks"; "rich rules"; "forward-ports" ]

    let private objectSelectorValues (snapshot: FirewalldRuntime.RuntimeSnapshot) =
        let values = actualSelectorValues snapshot
        if snapshot.Kind = "zone" then
            Map.add "sources" (FirewalldRuntime.normalizeFieldValues "zone" "sources" snapshot.SourcesRaw) values
        else values

    let private withoutObjectSelectors (snapshot: FirewalldRuntime.RuntimeSnapshot) =
        let nativeFields =
            objectSelectorFields snapshot.Kind
            |> List.fold (fun fields field -> Map.add field [] fields) snapshot.NativeFields
        { snapshot with
            Services = []
            Ports = []
            SourcePorts = []
            Protocols = []
            Sources = []
            SourcesRaw = []
            ForwardPorts = []
            IcmpBlocks = []
            RichRules = []
            IpSetEntries = []
            NativeFields = nativeFields }

    let private nonSelectorFingerprint snapshot = fingerprint (withoutObjectSelectors snapshot)

    let private parseObjectConfiguration kind name xml =
        FieldRuntime.parseConfiguration kind name xml
        |> Result.defaultWith (fun reason -> fail ("Cannot parse the firewalld object projection: " + reason))

    let private inverseEffect = function
        | Grants -> Restricts
        | Restricts -> Grants
        | Steers -> Steers
        | Observes -> Observes

    let private objectDeltaEffect (beforeConfiguration: FirewalldModel.Configuration) (afterConfiguration: FirewalldModel.Configuration) field value add =
        if field = "entries" || field = "sources" then Steers
        elif add then deltaEffect afterConfiguration field value
        else deltaEffect beforeConfiguration field value |> inverseEffect

    let private sortObjectDeltas deltas =
        deltas
        |> List.sortWith (fun left right ->
            let effectCompare = compare (effectOrder left.Effect) (effectOrder right.Effect)
            if effectCompare <> 0 then effectCompare
            else
                let fieldCompare = compare (Map.find left.Field fieldOrder) (Map.find right.Field fieldOrder)
                if fieldCompare <> 0 then fieldCompare
                else StringComparer.Ordinal.Compare(left.Value, right.Value))

    let private deriveObjectDeltas before after beforeConfiguration afterConfiguration =
        let beforeSelectors = objectSelectorValues before
        let afterSelectors = objectSelectorValues after
        objectSelectorFields before.Kind
        |> List.collect (fun field ->
            let oldValues = Set.ofList (Map.find field beforeSelectors)
            let newValues = Set.ofList (Map.find field afterSelectors)
            (Set.difference newValues oldValues
             |> Set.toList
             |> List.map (fun value ->
                 { Field = field; Value = value; Add = true
                   Effect = objectDeltaEffect beforeConfiguration afterConfiguration field value true }))
            @ (Set.difference oldValues newValues
               |> Set.toList
               |> List.map (fun value ->
                   { Field = field; Value = value; Add = false
                     Effect = objectDeltaEffect beforeConfiguration afterConfiguration field value false })))
        |> sortObjectDeltas


    let private applyObjectDeltaSet (values: Map<string, Set<string>>) (delta: ObjectDelta) =
        let current = Map.find delta.Field values
        Map.add delta.Field (if delta.Add then Set.add delta.Value current else Set.remove delta.Value current) values

    let private objectStateFingerprint (deltas: ObjectDelta list) (values: Map<string, Set<string>>) =
        let state = JsonArray()
        for delta in deltas do
            let item = JsonObject()
            item["field"] <- JsonValue.Create delta.Field
            item["value"] <- JsonValue.Create delta.Value
            item["present"] <- JsonValue.Create(Set.contains delta.Value (Map.find delta.Field values))
            state.Add item
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(state.ToJsonString()))).ToLowerInvariant()

    let private objectStateFingerprints before deltas =
        let mutable values = objectSelectorValues before |> Map.map (fun _ items -> Set.ofList items)
        let states = ResizeArray<string>()
        states.Add(objectStateFingerprint deltas values)
        for delta in deltas do
            values <- applyObjectDeltaSet values delta
            states.Add(objectStateFingerprint deltas values)
        List.ofSeq states

    let private objectRuntimeNonSelectorsMatch
        (environment: HostEnvironment)
        (expected: FirewalldRuntime.RuntimeSnapshot)
        (actual: FirewalldRuntime.RuntimeSnapshot)
        =
        if expected.Kind <> actual.Kind || expected.Name <> actual.Name || not (snapshotComplete expected && snapshotComplete actual) then false
        else
            projectLiveInterfaces environment expected.Interfaces actual
            |> Option.exists (fun projected ->
                nonSelectorFingerprint projected = nonSelectorFingerprint expected)

    let private objectRuntimeMatchesPreimage
        (environment: HostEnvironment)
        (expected: FirewalldRuntime.RuntimeSnapshot)
        (actual: FirewalldRuntime.RuntimeSnapshot)
        =
        if not (objectRuntimeNonSelectorsMatch environment expected actual) then false
        else
            let expectedSelectors = objectSelectorValues expected
            let actualSelectors = objectSelectorValues actual
            let exactSelectors =
                objectSelectorFields expected.Kind
                |> List.filter ((<>) "rich rules")
                |> List.forall (fun field ->
                    Set.ofList (Map.find field expectedSelectors) = Set.ofList (Map.find field actualSelectors))
            let expectedRules = Set.ofList (Map.find "rich rules" expectedSelectors)
            let actualRules = Set.ofList (Map.find "rich rules" actualSelectors)
            let extras = Set.difference actualRules expectedRules
            exactSelectors
            && Set.isSubset expectedRules actualRules
            && (extras |> Set.forall FirewalldRuntime.isRestrictiveRichRule)
    let private objectRuntimeRollbackStructureMatches
        (environment: HostEnvironment)
        (expected: FirewalldRuntime.RuntimeSnapshot)
        (actual: FirewalldRuntime.RuntimeSnapshot)
        (inverseOnlyNarrows: bool)
        =
        if not inverseOnlyNarrows || expected.Kind <> "zone" then
            objectRuntimeNonSelectorsMatch environment expected actual
        elif expected.Kind <> actual.Kind || expected.Name <> actual.Name
             || not (snapshotComplete expected && snapshotComplete actual) then false
        else
            match interfaceEvidence expected, interfaceEvidence actual with
            | Some(expectedInterfaces, _), Some(actualInterfaces, _) ->
                if not (Set.isSubset (Set.ofList expectedInterfaces) (Set.ofList actualInterfaces)) then false
                else
                    let nativeInterfaces =
                        if expectedInterfaces.IsEmpty then [] else [ String.concat " " expectedInterfaces ]
                    let projected =
                        { actual with
                            Interfaces = expectedInterfaces
                            NativeFields = Map.add "interfaces" nativeInterfaces actual.NativeFields }
                    nonSelectorFingerprint projected = nonSelectorFingerprint expected
            | _ -> false

    let private objectRuntimeMatchesPreimageForRollback
        (environment: HostEnvironment)
        (repair: ObjectRepair)
        (actual: FirewalldRuntime.RuntimeSnapshot)
        =
        let inverseOnlyNarrows =
            repair.Deltas
            |> List.forall (fun delta -> inverseEffect delta.Effect = Restricts)
        if not (objectRuntimeRollbackStructureMatches environment repair.Before actual inverseOnlyNarrows) then false
        else
            let expectedSelectors = objectSelectorValues repair.Before
            let actualSelectors = objectSelectorValues actual
            let exactSelectors =
                objectSelectorFields repair.Before.Kind
                |> List.filter ((<>) "rich rules")
                |> List.forall (fun field ->
                    Set.ofList (Map.find field expectedSelectors) = Set.ofList (Map.find field actualSelectors))
            let expectedRules = Set.ofList (Map.find "rich rules" expectedSelectors)
            let actualRules = Set.ofList (Map.find "rich rules" actualSelectors)
            let extras = Set.difference actualRules expectedRules
            exactSelectors
            && Set.isSubset expectedRules actualRules
            && (extras |> Set.forall FirewalldRuntime.isRestrictiveRichRule)


    let private objectRuntimeMatchesCheckpointZero
        (environment: HostEnvironment)
        (expected: FirewalldRuntime.RuntimeSnapshot)
        (deltas: ObjectDelta list)
        (actual: FirewalldRuntime.RuntimeSnapshot)
        =
        if not (objectRuntimeMatchesPreimage environment expected actual) then false
        else
            let expectedSelectors = objectSelectorValues expected
            let actualSelectors = objectSelectorValues actual
            deltas
            |> List.forall (fun delta ->
                List.contains delta.Value (Map.find delta.Field expectedSelectors) = List.contains delta.Value (Map.find delta.Field actualSelectors))

    let matchesLoadedProjectionPreservingRestrictions
        (environment: HostEnvironment)
        (expected: FirewalldRuntime.RuntimeSnapshot)
        (actual: FirewalldRuntime.RuntimeSnapshot)
        =
        if expected.Kind = "zone" || expected.Kind = "policy" then objectRuntimeMatchesPreimage environment expected actual
        else matchesLoadedProjection environment expected actual
    let private ordinaryIpv4SetMember typeName (value: string) =
        let parts = value.Split('/')
        match IPAddress.TryParse parts[0] with
        | true, address when address.AddressFamily = System.Net.Sockets.AddressFamily.InterNetwork
                             && address.ToString() = parts[0] ->
            let bytes = address.GetAddressBytes()
            let prefix =
                if typeName = "hash:ip" && parts.Length = 1 then Some 32
                elif typeName = "hash:net" && parts.Length = 1 then Some 32
                elif typeName = "hash:net" && parts.Length = 2 then
                    match Int32.TryParse(parts[1], Globalization.NumberStyles.None, Globalization.CultureInfo.InvariantCulture) with
                    | true, bits when bits >= 1 && bits <= 32 && string bits = parts[1] -> Some bits
                    | _ -> None
                else None
            match prefix with
            | None -> None
            | Some bits ->
                let first = Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(ReadOnlySpan<byte>(bytes))
                let host = if bits = 32 then 0u else UInt32.MaxValue >>> bits
                if first &&& host = 0u then Some(first, first ||| host) else None
        | _ -> None

    let private safeStaticIpSetEntryBatch
        (before: FirewalldRuntime.RuntimeSnapshot)
        (after: FirewalldRuntime.RuntimeSnapshot)
        (deltas: ObjectDelta list)
        =
        let family (snapshot: FirewalldRuntime.RuntimeSnapshot) =
            match Map.tryFind "family" snapshot.IpSetOptions with
            | None | Some None -> "inet"
            | Some(Some value) -> value
        let expiring (snapshot: FirewalldRuntime.RuntimeSnapshot) =
            match Map.tryFind "timeout" snapshot.IpSetOptions with None | Some(Some "0") -> false | _ -> true
        if before.Kind <> "ipset" || after.Kind <> "ipset"
           || before.IpSetType <> after.IpSetType
           || not (List.contains before.IpSetType [ Some "hash:ip"; Some "hash:net" ])
           || family before <> "inet" || family after <> "inet"
           || expiring before || expiring after
           || deltas.Length < 2
           || (deltas |> List.exists (fun delta -> delta.Field <> "entries"))
           || not ((deltas |> List.forall (fun delta -> delta.Add))
                   || (deltas |> List.forall (fun delta -> not delta.Add))) then false
        else
            let beforeEntries = Set.ofList before.IpSetEntries
            let afterEntries = Set.ofList after.IpSetEntries
            let nested =
                if deltas.Head.Add then Set.isSubset beforeEntries afterEntries
                else Set.isSubset afterEntries beforeEntries
            let memberValues = Set.union beforeEntries afterEntries |> Set.toList
            let members =
                memberValues
                |> List.map (ordinaryIpv4SetMember (Option.get before.IpSetType))
            if not nested || (members |> List.exists Option.isNone) then false
            else
                let intervals = members |> List.choose id |> List.sortBy fst
                intervals |> List.pairwise |> List.forall (fun ((_, previousEnd), (nextStart, _)) -> previousEnd < nextStart)


    let private independentLocalRedirects (before: FirewalldRuntime.RuntimeSnapshot) (after: FirewalldRuntime.RuntimeSnapshot) (deltas: ObjectDelta list) =
        let eligible = deltas.Length > 1 && deltas.Length <= 4096 && (before.Kind = "zone" || before.Kind = "policy")
                       && List.forall (fun d -> d.Field = "forward-ports" && d.Add = deltas.Head.Add) deltas
                       && before.RichRules.IsEmpty && after.RichRules.IsEmpty && not before.Masquerade && not after.Masquerade
        if not eligible then false
        else
            // Every packet must see either the former or the final redirect.
            // Do not batch overlapping inputs, remote address changes, or a
            // translation whose destination is an input to another redirect.
            let superset = if deltas.Head.Add then after.ForwardPorts else before.ForwardPorts
            let range (text: string) =
                let bounds = text.Split('-')
                Int32.Parse(bounds[0]), Int32.Parse(bounds[bounds.Length-1])
            let redirects = superset |> List.choose (fun e ->
                match Map.tryFind "to-port" e.Attributes, Map.tryFind "to-addr" e.Attributes with
                | Some target, None -> Some(e.Attributes["protocol"], range e.Attributes["port"], range target)
                | _ -> None)
            List.length redirects = List.length superset &&
            (redirects |> List.groupBy (fun (proto, _, _) -> proto) |> List.forall (fun (_, group) ->
                let inputs = group |> List.map (fun (_, input, _) -> input) |> List.sort |> List.toArray
                let outputs = group |> List.map (fun (_, _, output) -> output) |> List.sort
                let mutable i = 0
                (inputs |> Seq.pairwise |> Seq.forall (fun ((_, last), (next, _)) -> last < next))
                && (outputs |> List.forall (fun (first, last) ->
                    while i < inputs.Length && snd inputs[i] < first do i <- i+1
                    i = inputs.Length || fst inputs[i] > last))))

    let private objectDeltaProofCore
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (effectiveBefore: string option)
        (effectiveAfter: string option)
        (authorizeSetBatch: unit -> bool)
        =
        if not (List.contains configuration.Kind [ "zone"; "policy"; "ipset" ]) then None
        else
            match FirewalldRuntime.snapshotFromXml configuration.Kind configuration.Name effectiveBefore,
                  FirewalldRuntime.snapshotFromXml configuration.Kind configuration.Name effectiveAfter with
            | Error reason, _ -> fail ("Cannot project the effective firewalld preimage: " + reason)
            | _, Error reason -> fail ("Cannot project the candidate firewalld object: " + reason)
            | Ok(Some before), Ok(Some after) when snapshotComplete before && snapshotComplete after ->
                let expiring (s: FirewalldRuntime.RuntimeSnapshot) =
                    match Map.tryFind "timeout" s.IpSetOptions with None | Some(Some "0") -> false | _ -> true
                if expiring before || expiring after || nonSelectorFingerprint before <> nonSelectorFingerprint after then None
                else
                    let beforeConfiguration =
                        effectiveBefore
                        |> Option.defaultWith (fun () -> fail "A scoped object inverse requires an existing before object.")
                        |> parseObjectConfiguration configuration.Kind configuration.Name
                    let afterConfiguration =
                        effectiveAfter
                        |> Option.defaultWith (fun () -> fail "A scoped object inverse requires an existing after object.")
                        |> parseObjectConfiguration configuration.Kind configuration.Name
                    let deltas = deriveObjectDeltas before after beforeConfiguration afterConfiguration
                    let effects = deltas |> List.map (fun delta -> delta.Effect) |> Set.ofList
                    let setBatchCandidate = safeStaticIpSetEntryBatch before after deltas
                    let redirectBatch = independentLocalRedirects before after deltas
                    let unsafeSteeringMix =
                        Set.contains Steers effects
                        && (effects.Count > 1 || (deltas.Length > 1 && not (setBatchCandidate || redirectBatch)))
                    if unsafeSteeringMix || deltas.Length > 4096 then None
                    else
                        match FirewalldRuntime.queryPermanent environment configuration.Kind configuration.Name,
                              FirewalldRuntime.inspectRuntime environment configuration.Kind configuration.Name with
                        | Ok(Some permanent), Some live
                            when matchesLoadedProjection environment before permanent
                                 && objectRuntimeMatchesCheckpointZero environment before deltas live ->
                            let steeringBatch = redirectBatch || (setBatchCandidate && authorizeSetBatch ())
                            if setBatchCandidate && not steeringBatch then None
                            else
                                let node = proofBase configuration "object-delta"
                                node["version"] <- JsonValue.Create(if redirectBatch then 6 else 5)
                                node["steeringBatch"] <- JsonValue.Create steeringBatch
                                node["afterConfiguration"] <- JsonValue.Create(FirewalldModel.toJson afterConfiguration)
                                node["beforePresent"] <- JsonValue.Create true
                                node["beforeFingerprint"] <- JsonValue.Create(fingerprint before)
                                node["afterPresent"] <- JsonValue.Create true
                                node["afterFingerprint"] <- JsonValue.Create(fingerprint after)
                                writeInterfaceEvidence node "before" (Some before)
                                writeInterfaceEvidence node "after" (Some after)
                                let deltaNodes = JsonArray()
                                for delta in deltas do
                                    let item = JsonObject()
                                    item["field"] <- JsonValue.Create delta.Field
                                    item["value"] <- JsonValue.Create delta.Value
                                    item["add"] <- JsonValue.Create delta.Add
                                    item["effect"] <- JsonValue.Create(effectName delta.Effect)
                                    deltaNodes.Add item
                                let states = JsonArray()
                                for state in objectStateFingerprints before deltas do states.Add(JsonValue.Create state)
                                node["deltas"] <- deltaNodes
                                node["stateFingerprints"] <- states
                                Some node
                        | _ ->
                            fail "Cannot prove the live firewalld target is the recorded preimage; a scoped object transaction would overwrite independent runtime state."
            | Ok _, Ok _ -> None

    let objectDeltaProof
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (effectiveBefore: string option)
        (effectiveAfter: string option)
        =
        objectDeltaProofCore environment configuration effectiveBefore effectiveAfter (fun () -> false)

    let objectDeltaProofWithSetBatch
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (effectiveBefore: string option)
        (effectiveAfter: string option)
        (authorizeSetBatch: unit -> bool)
        =
        objectDeltaProofCore environment configuration effectiveBefore effectiveAfter authorizeSetBatch
    let private parseListenerPort (endpoint: string) =
        let separator = endpoint.LastIndexOf(':')
        if separator < 0 || separator = endpoint.Length - 1 then None
        else
            match Int32.TryParse(endpoint.Substring(separator + 1)) with
            | true, port when port > 0 && port <= 65535 -> Some port
            | _ -> None

    let private listeningProcessOwners (value: string) =
        let prefix = "users:(("
        if not (value.StartsWith(prefix, StringComparison.Ordinal) && value.EndsWith("))", StringComparison.Ordinal)) then None
        else
            let body = value.Substring(prefix.Length, value.Length - prefix.Length - 2)
            let entries = Regex.Split(body, @"\),\(")
            let parseEntry (entry: string) =
                match entry.Split(',') with
                | [| quotedName; pid; fd |]
                    when quotedName.Length >= 2 && quotedName[0] = '"' && quotedName[quotedName.Length - 1] = '"'
                         && pid.StartsWith("pid=", StringComparison.Ordinal)
                         && fd.StartsWith("fd=", StringComparison.Ordinal) ->
                    let mutable processId = 0
                    let mutable descriptor = 0
                    if Int32.TryParse(pid.Substring(4), &processId) && processId > 0
                       && Int32.TryParse(fd.Substring(3), &descriptor) && descriptor >= 0 then
                        Some(quotedName.Substring(1, quotedName.Length - 2), processId)
                    else None
                | _ -> None
            let owners = entries |> Array.map parseEntry
            if owners.Length = 0 || (owners |> Array.exists Option.isNone) then None
            else owners |> Array.choose id |> Array.toList |> Some

    let private listeningTcpSockets (environment: HostEnvironment) includeProcessInfo =
        try
            let arguments = if includeProcessInfo then [ "-H"; "-ltnp" ] else [ "-H"; "-ltn" ]
            let result = environment.Run "ss" arguments None
            if result.ExitCode <> 0 || not (String.IsNullOrWhiteSpace result.Stderr) then None
            else
                let sockets = ResizeArray<int * (string * int) list option>()
                let mutable complete = true
                for line in result.Stdout.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries) do
                    let fields = line.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
                    if fields.Length < 5 || fields[0] <> "LISTEN" then
                        complete <- false
                    else
                        match parseListenerPort fields[3] with
                        | None -> complete <- false
                        | Some port ->
                            let owners =
                                if not includeProcessInfo then Some []
                                elif fields.Length < 6 then None
                                else listeningProcessOwners(String.concat " " fields[5..])
                            sockets.Add((port, owners))
                if complete then Some(List.ofSeq sockets) else None
        with _ -> None

    let private listenerExecutable (environment: HostEnvironment) (processId: int) =
        try
            let path = "/proc/" + processId.ToString(System.Globalization.CultureInfo.InvariantCulture) + "/exe"
            let result = environment.Run "/usr/bin/readlink" [ "-f"; path ] None
            if result.ExitCode = 0 && String.IsNullOrWhiteSpace result.Stderr
               && not (String.IsNullOrWhiteSpace result.Stdout) then Some(result.Stdout.Trim())
            else None
        with _ -> None

    let private isNativeSshExecutable (path: string) =
        List.contains path
            [ "/usr/sbin/sshd"; "/usr/sbin/dropbear"; "/usr/bin/dropbear"
              "/usr/sbin/dropbearmulti"; "/usr/bin/dropbearmulti" ]

    let private sshConnectionPort () =
        match Environment.GetEnvironmentVariable "SSH_CONNECTION" with
        | null -> None
        | text ->
            match text.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries) with
            | [| _; _; _; value |] ->
                match Int32.TryParse value with
                | true, port when port > 0 && port <= 65535 -> Some port
                | _ -> None
            | _ -> None

    /// Returns ports attributable to Debian's native OpenSSH or Dropbear, plus
    /// systemd-owned and unidentifiable listeners conservatively. Executables are
    /// authenticated through /proc/PID/exe; comm alone never rules a listener out.
    /// Arbitrary SSH embedded or proxied by another executable is outside this boundary.
    let managementServerPorts (environment: HostEnvironment) =
        let connectionPort = sshConnectionPort ()
        match listeningTcpSockets environment true with
        | None -> None
        | Some sockets ->
            let ports = Collections.Generic.HashSet<int>()
            let executableCache = Collections.Generic.Dictionary<int, string option>()
            let mayBeSsh (name, processId) =
                if processId = 1 || name = "systemd" then true
                else
                    let executable =
                        match executableCache.TryGetValue processId with
                        | true, path -> path
                        | _ ->
                            let path = listenerExecutable environment processId
                            executableCache[processId] <- path
                            path
                    match executable with
                    | None -> true
                    | Some path -> isNativeSshExecutable path
            for port, owners in sockets do
                let possibleManagement =
                    match owners with
                    | None -> true
                    | Some processes -> processes |> List.exists mayBeSsh
                if possibleManagement then ports.Add port |> ignore
            match connectionPort with
            | Some port when not (sockets |> List.exists (fst >> (=) port)) -> None
            | Some port ->
                ports.Add port |> ignore
                Some(Set.ofSeq ports)
            | None -> Some(Set.ofSeq ports)

    /// DefaultZone equivalence compares admission at every listening TCP port,
    /// independent of owner. An incomplete inventory falls back to all-port equivalence.
    let listeningTcpPorts (environment: HostEnvironment) =
        match listeningTcpSockets environment false with
        | None -> None
        | Some sockets ->
            let ports = sockets |> List.map fst |> Set.ofList
            match sshConnectionPort () with
            | Some port when not (Set.contains port ports) -> None
            | _ when ports.IsEmpty -> None
            | _ -> Some ports


    let private relevantPorts managementPorts ports =
        match managementPorts with
        | None -> Set.ofList ports
        | Some servers ->
            let containsServerPort (value: string) =
                match value.Split('/') with
                | [| range; "tcp" |] ->
                    match range.Split('-') with
                    | [| first |] ->
                        match Int32.TryParse first with
                        | true, port -> Set.contains port servers
                        | _ -> false
                    | [| first; last |] ->
                        match Int32.TryParse first, Int32.TryParse last with
                        | (true, low), (true, high) when low > 0 && high >= low && high <= 65535 ->
                            servers |> Set.exists (fun port -> low <= port && port <= high)
                        | _ -> false
                    | _ -> false
                | _ -> false
            ports |> List.filter containsServerPort |> Set.ofList

    let private admissionSignature managementPorts (s: FirewalldRuntime.RuntimeSnapshot) =
        s.Target, Set.ofList s.Services, relevantPorts managementPorts s.Ports, Set.ofList s.Protocols,
        Set.ofList s.SourcePorts, Set.ofList s.ForwardPorts, Set.ofList s.RichRules,
        Set.ofList s.IcmpBlocks, s.IcmpBlockInversion

    let private steersPackets (s: FirewalldRuntime.RuntimeSnapshot) =
        s.Masquerade || not s.ForwardPorts.IsEmpty ||
        (s.RichRules |> List.exists (fun rule -> rule.Split(' ') |> Array.exists (function "mark" | "forward-port" | "masquerade" -> true | _ -> false)))

    let private noDispatchDifference environment affected =
        FirewalldRuntime.listRuntime environment "policy" |> Option.get |> List.forall (fun p ->
            [ FirewalldRuntime.inspectRuntime environment "policy" p |> Option.get
              FirewalldRuntime.inspectPermanent environment "policy" p |> Option.get ]
            |> List.forall (fun policy ->
                let endpoints = policy.Ingress @ policy.Egress
                snapshotComplete policy &&
                (not (List.exists (fun z -> Set.contains z affected) endpoints) ||
                 (not (List.contains "HOST" endpoints) && not (steersPackets policy)))))

    // Service getters retain native fields; unlike zone/policy list-all, they do
    // not populate the zone-specific Ports/Protocols/SourcePorts projections.
    let private nativeWords field (s: FirewalldRuntime.RuntimeSnapshot) =
        Map.tryFind field s.NativeFields |> Option.defaultValue []
        |> List.collect (fun line -> line.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries) |> Array.toList)

    let private grantsAt servers protocols ports =
        if List.contains "tcp" protocols then servers
        else servers |> Set.filter (fun port -> not (Set.isEmpty (relevantPorts (Some(Set.singleton port)) ports)))

    let private defaultAdmission environment managementPorts (cache: Collections.Generic.Dictionary<string, Set<int> option>) (zone: FirewalldRuntime.RuntimeSnapshot) =
        let simple (s: FirewalldRuntime.RuntimeSnapshot) =
            snapshotComplete s && (nativeWords "source-ports" s).IsEmpty &&
            List.forall (fun field ->
                Map.tryFind field s.NativeFields |> Option.forall (List.forall String.IsNullOrWhiteSpace))
                [ "includes"; "destination"; "modules"; "helpers" ]
            && List.forall (fun p -> List.contains p ["tcp"; "udp"; "sctp"; "dccp"]) (nativeWords "protocols" s)
            && List.forall (fun (p: string) -> System.Text.RegularExpressions.Regex.IsMatch(p, @"^\d+(-\d+)?/(tcp|udp|sctp|dccp)$")) (nativeWords "ports" s)
        match managementPorts with
        | None ->
            admissionSignature None zone, Set.empty, zone.IngressPriority, zone.EgressPriority, zone.Masquerade, zone.Forward
        | Some servers ->
            let grants s = grantsAt servers (nativeWords "protocols" s) (nativeWords "ports" s)
            let mutable granted = grantsAt servers zone.Protocols zone.Ports
            let residual = zone.Services |> List.filter (fun name ->
                let effect =
                    match cache.TryGetValue name with
                    | true, result -> result
                    | _ ->
                        let result =
                            match FirewalldRuntime.inspectPermanent environment "service" name, FirewalldRuntime.inspectRuntime environment "service" name with
                            | Some a, Some b when simple a && simple b && grants a = grants b -> Some(grants a)
                            | _ -> None
                        cache[name] <- result
                        result
                match effect with
                | None -> true
                | Some permits -> granted <- Set.union granted permits; false)
            admissionSignature managementPorts { zone with Services = residual; Ports = []; Protocols = zone.Protocols |> List.filter ((<>) "tcp") },
            granted, zone.IngressPriority, zone.EgressPriority, zone.Masquerade, zone.Forward

    let equivalentDefaultZones environment original candidate =
        if original = candidate then true
        else
            try
                let managementPorts = listeningTcpPorts environment
                let snapshots = [ for name in [ original; candidate ] do
                                      yield FirewalldRuntime.inspectRuntime environment "zone" name |> Option.get
                                      yield FirewalldRuntime.inspectPermanent environment "zone" name |> Option.get ]
                let cache = Collections.Generic.Dictionary<string, Set<int> option>(StringComparer.Ordinal)
                List.forall snapshotComplete snapshots
                && (let baseline = defaultAdmission environment managementPorts cache snapshots.Head
                    snapshots.Tail |> List.forall (fun zone -> defaultAdmission environment managementPorts cache zone = baseline))
                && noDispatchDifference environment (set [ original; candidate ])
            with _ -> false

    let private equivalentZoneAdmission environment name (before: FirewalldRuntime.RuntimeSnapshot option) (after: FirewalldRuntime.RuntimeSnapshot option) (candidate: FirewalldModel.Configuration) =
        let managementPorts = managementServerPorts environment
        let signature = admissionSignature managementPorts
        let candidates = [before; after] |> List.choose id
        let sameShape first snapshots = snapshots |> List.forall (fun x -> signature x = signature first)
        match candidates with
        | [] -> true
        | first :: _ when not (sameShape first candidates) -> false
        | first :: _ ->
            let selection (s: FirewalldRuntime.RuntimeSnapshot) = Set.ofList s.Interfaces, Set.ofList s.SourcesRaw, s.IngressPriority, s.EgressPriority
            if Option.map selection before = Option.map selection after then true
            else
                let zones = FirewalldRuntime.listRuntime environment "zone" |> Option.get
                let sourceChange = (before |> Option.map _.SourcesRaw) <> (after |> Option.map _.SourcesRaw)
                // Adding a literal IPv4 source cannot affect IPv6 NDP. If its new
                // zone unconditionally grants every attributed management TCP
                // listener, a stricter default target for *other* ports is harmless.
                let safeNewSource =
                    match before, after, managementPorts with
                    | None, Some z, Some servers when not servers.IsEmpty && z.Interfaces.IsEmpty && not z.SourcesRaw.IsEmpty ->
                        let exclusivelyIPv4 = z.SourcesRaw |> List.forall (fun source ->
                            match Net.IPAddress.TryParse(source.Split('/')[0]) with true, ip -> ip.AddressFamily = Net.Sockets.AddressFamily.InterNetwork | _ -> false)
                        let serviceListenerPorts service =
                            match FirewalldRuntime.inspectPermanent environment "service" service,
                                  FirewalldRuntime.inspectRuntime environment "service" service with
                            | Some permanent, Some runtime
                                when snapshotComplete permanent
                                     && snapshotComplete runtime
                                     && (Map.tryFind "destination" permanent.NativeFields |> Option.forall (List.forall String.IsNullOrWhiteSpace))
                                     && (Map.tryFind "destination" runtime.NativeFields |> Option.forall (List.forall String.IsNullOrWhiteSpace)) ->
                                let permits s = grantsAt servers (nativeWords "protocols" s) (nativeWords "ports" s)
                                Some(Set.intersect (permits permanent) (permits runtime))
                            | _ -> None
                        let disjointPort (el: FirewalldModel.Element) =
                            match Map.tryFind "protocol" el.Attributes, Map.tryFind "port" el.Attributes with
                            | Some ("udp" | "sctp" | "dccp"), _ -> true
                            | Some "tcp", Some range -> Set.isEmpty (relevantPorts managementPorts [ range + "/tcp" ])
                            | _ -> false
                        let cannotIntercept (el: FirewalldModel.Element) =
                            match el.Name with
                            | "forward-port" -> disjointPort el
                            | "masquerade" -> false
                            | "rule" ->
                                Map.tryFind "family" el.Attributes = Some "ipv6" ||
                                (el.Children |> List.exists (fun child ->
                                    List.contains child.Name [ "icmp-type"; "icmp-block" ] ||
                                    (List.contains child.Name [ "port"; "forward-port" ] && disjointPort child)))
                            | _ -> true
                        let directGrant =
                            if List.contains "tcp" z.Protocols then servers
                            else servers |> Set.filter (fun port ->
                                not (Set.isEmpty (relevantPorts (Some(Set.singleton port)) z.Ports)))
                        let allGranted =
                            z.Services
                            |> List.fold (fun granted service ->
                                serviceListenerPorts service
                                |> Option.map (Set.union granted)
                                |> Option.defaultValue granted)
                                directGrant
                            |> fun granted -> Set.isSubset servers granted
                        exclusivelyIPv4 && not z.Masquerade && List.forall cannotIntercept candidate.Elements
                        && allGranted
                    | _ -> false
                let dz = environment.Run "firewall-cmd" ["--get-default-zone"] None
                if dz.ExitCode <> 0 || not (List.contains (dz.Stdout.Trim()) zones) then false
                else
                    let changed = candidates |> List.collect _.Interfaces
                    let overlaps (a: string) (b: string) =
                        a = b || (a.EndsWith('+') && b.StartsWith(a.TrimEnd('+'), StringComparison.Ordinal))
                        || (b.EndsWith('+') && a.StartsWith(b.TrimEnd('+'), StringComparison.Ordinal))
                    let mutable affected = Set.singleton name
                    let zonesAgree =
                        zones |> List.forall (fun z ->
                            if z = name then true
                            else
                                let views = [ FirewalldRuntime.inspectRuntime environment "zone" z |> Option.get
                                              FirewalldRuntime.inspectPermanent environment "zone" z |> Option.get ]
                                if views |> List.exists (fun view ->
                                    z = dz.Stdout.Trim() || not view.SourcesRaw.IsEmpty
                                    || (sourceChange && not view.Interfaces.IsEmpty)
                                    || view.Interfaces |> List.exists (fun iface -> changed |> List.exists (overlaps iface))) then
                                    affected <- Set.add z affected
                                    views |> List.forall snapshotComplete &&
                                    (sameShape first views || (safeNewSource && views |> List.forall (steersPackets >> not)))
                                else true)
                    zonesAgree && noDispatchDifference environment affected

    let objectTransitionMayNarrowManagement
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (effectiveBefore: string option)
        (effectiveAfter: string option)
        =
        if configuration.Kind <> "zone" && configuration.Kind <> "policy" then false
        else
            try
                let project xml =
                    match FirewalldRuntime.snapshotFromXml configuration.Kind configuration.Name xml with
                    | Ok(Some snapshot) when snapshotComplete snapshot -> Some snapshot
                    | Ok None -> None
                    | _ -> fail "The native object projection is incomplete."
                let before = project effectiveBefore
                let after = project effectiveAfter
                let empty =
                    let configuration = FirewalldModel.empty configuration.Kind configuration.Name
                    match FirewalldRuntime.snapshotFromXml configuration.Kind configuration.Name (Some(FieldRuntime.render configuration)) with
                    | Ok(Some snapshot) when snapshotComplete snapshot -> snapshot
                    | _ -> fail "Cannot construct an empty firewalld object projection."
                let beforeSnapshot = Option.defaultValue empty before
                let afterSnapshot = Option.defaultValue empty after
                let beforeConfiguration =
                    effectiveBefore
                    |> Option.map (parseObjectConfiguration configuration.Kind configuration.Name)
                    |> Option.defaultValue (FirewalldModel.empty configuration.Kind configuration.Name)
                let afterConfiguration =
                    effectiveAfter
                    |> Option.map (parseObjectConfiguration configuration.Kind configuration.Name)
                    |> Option.defaultValue (FirewalldModel.empty configuration.Kind configuration.Name)
                let managementPorts = managementServerPorts environment
                let steeringCanMatch (c: FirewalldModel.Configuration) =
                    let mayMatch (e: FirewalldModel.Element) =
                        match Map.tryFind "protocol" e.Attributes, Map.tryFind "port" e.Attributes with
                        | Some ("udp" | "sctp" | "dccp"), _ -> false
                        | Some "tcp", Some range when not (List.contains "HOST" c.Ingress) ->
                            not (Set.isEmpty (relevantPorts managementPorts [ range + "/tcp" ]))
                        | _ -> true
                    c.Masquerade || (c.Elements |> List.exists (fun e ->
                        match e.Name with
                        | "forward-port" -> mayMatch e
                        | "masquerade" -> true
                        | "rule" when e.Children |> List.exists (fun child -> List.contains child.Name [ "forward-port"; "mark"; "masquerade" ]) ->
                            e.Children |> List.tryFind (fun child -> child.Name = "port" || child.Name = "forward-port")
                            |> Option.forall mayMatch
                        | _ -> false))
                let steeringRisk = steeringCanMatch beforeConfiguration || steeringCanMatch afterConfiguration
                let managementZone =
                    if configuration.Kind <> "zone" then false
                    else
                        let defaultZone =
                            match environment.Run "firewall-cmd" [ "--get-default-zone" ] None with
                            | { ExitCode = 0; Stdout = value } when not (String.IsNullOrWhiteSpace value) -> Some(value.Trim())
                            | _ -> None
                        let declaredInterfaces = beforeSnapshot.Interfaces @ afterSnapshot.Interfaces
                        let runtimeInterfaces =
                            match FirewalldRuntime.listRuntime environment "zone" with
                            | Some names when List.contains configuration.Name names ->
                                FirewalldRuntime.listRuntimeInterfaces environment configuration.Name
                                |> Option.defaultValue declaredInterfaces
                            | Some _ -> []
                            | None -> declaredInterfaces
                        let activeInterfaces =
                            try
                                match environment.Run "ip" [ "-j"; "link"; "show" ] None with
                                | { ExitCode = 0; Stdout = output } ->
                                    use document = System.Text.Json.JsonDocument.Parse output
                                    if document.RootElement.ValueKind <> System.Text.Json.JsonValueKind.Array then None
                                    else
                                        document.RootElement.EnumerateArray()
                                        |> Seq.choose (fun link ->
                                            let mutable name = Unchecked.defaultof<System.Text.Json.JsonElement>
                                            if link.TryGetProperty("ifname", &name)
                                               && name.ValueKind = System.Text.Json.JsonValueKind.String then
                                                Some(name.GetString())
                                            else None)
                                        |> Set.ofSeq
                                        |> Some
                                | _ -> None
                            with _ -> None
                        let boundToActiveInterface =
                            let bindings = declaredInterfaces @ runtimeInterfaces
                            match activeInterfaces with
                            | Some names -> bindings |> List.exists (fun selector ->
                                if selector.EndsWith('+') then names |> Set.exists (fun name -> name.StartsWith(selector.TrimEnd('+'), StringComparison.Ordinal))
                                else Set.contains selector names)
                            | None -> not bindings.IsEmpty
                        defaultZone.IsNone
                        || defaultZone = Some configuration.Name
                        || boundToActiveInterface
                        || not beforeSnapshot.SourcesRaw.IsEmpty
                        || not afterSnapshot.SourcesRaw.IsEmpty
                let managementPolicy =
                    if configuration.Kind <> "policy" then false
                    else
                        [ beforeSnapshot; afterSnapshot ]
                        |> List.exists (fun snapshot ->
                            List.contains "HOST" snapshot.Ingress
                            || List.contains "HOST" snapshot.Egress || steeringRisk)
                if not (managementZone || managementPolicy) then false
                else
                    let targetRank (target: string) =
                        match target.ToUpperInvariant() with
                        | "ACCEPT" -> 2
                        | "DROP" | "REJECT" | "%%REJECT%%" -> 0
                        | "DEFAULT" | "CONTINUE" -> 1
                        | _ -> -1
                    let beforeTarget, afterTarget = targetRank beforeSnapshot.Target, targetRank afterSnapshot.Target
                    let targetNarrowed =
                        afterTarget < beforeTarget
                        || (beforeSnapshot.Target <> afterSnapshot.Target && (beforeTarget < 0 || afterTarget < 0))
                    let beforeRules = Set.ofList beforeSnapshot.RichRules
                    let afterRules = Set.ofList afterSnapshot.RichRules
                    let addedRules = Set.difference afterRules beforeRules
                    let removedRules = Set.difference beforeRules afterRules
                    let ruleNarrowed =
                        (addedRules |> Set.exists FirewalldRuntime.isRestrictiveRichRule)
                        || (removedRules |> Set.exists (FirewalldRuntime.isRestrictiveRichRule >> not))
                    let selectorDeltas =
                        deriveObjectDeltas beforeSnapshot afterSnapshot beforeConfiguration afterConfiguration
                    let selectorNarrowed =
                        selectorDeltas |> List.exists (fun delta -> delta.Effect = Restricts || delta.Effect = Steers)
                    // Every actual management listener can be reached by the peer
                    // regardless of its source address; unknown inventories require
                    // conservative consideration of every TCP port.
                    let hasManagementGrant (snapshot: FirewalldRuntime.RuntimeSnapshot) =
                        match managementPorts with
                        | Some servers when servers.IsEmpty -> false
                        | _ ->
                            targetRank snapshot.Target = 2
                            || List.contains "ssh" snapshot.Services
                            || List.contains "tcp" snapshot.Protocols
                            || not (Set.isEmpty (relevantPorts managementPorts snapshot.Ports))
                    let hasBlockingSemantics (snapshot: FirewalldRuntime.RuntimeSnapshot) =
                        targetRank snapshot.Target = 0
                        || (snapshot.RichRules |> List.exists FirewalldRuntime.isRestrictiveRichRule)
                        || (not snapshot.IcmpBlockInversion && not snapshot.IcmpBlocks.IsEmpty)
                    let bindingsRemoved oldValues newValues =
                        not (Set.difference (Set.ofList oldValues) (Set.ofList newValues)).IsEmpty
                    let structuralNarrowed =
                        if configuration.Kind = "zone" then
                            let oldInterfaces, newInterfaces = beforeSnapshot.Interfaces, afterSnapshot.Interfaces
                            let oldSources, newSources = beforeSnapshot.SourcesRaw, afterSnapshot.SourcesRaw
                            let bindingChanged =
                                Set.ofList oldInterfaces <> Set.ofList newInterfaces
                                || Set.ofList oldSources <> Set.ofList newSources
                            let bindingRemoved =
                                bindingsRemoved oldInterfaces newInterfaces
                                || bindingsRemoved oldSources newSources
                            let priorityChanged =
                                beforeSnapshot.IngressPriority <> afterSnapshot.IngressPriority
                                || beforeSnapshot.EgressPriority <> afterSnapshot.EgressPriority
                            let forwardingChanged =
                                beforeSnapshot.Forward <> afterSnapshot.Forward
                                || beforeSnapshot.Masquerade <> afterSnapshot.Masquerade
                            let inversionChanged =
                                beforeSnapshot.IcmpBlockInversion <> afterSnapshot.IcmpBlockInversion
                                && (not beforeSnapshot.IcmpBlocks.IsEmpty || not afterSnapshot.IcmpBlocks.IsEmpty)
                            (bindingRemoved && hasManagementGrant beforeSnapshot)
                            || (bindingChanged
                                && (hasBlockingSemantics afterSnapshot || not (hasManagementGrant afterSnapshot)))
                            || (priorityChanged && (hasManagementGrant beforeSnapshot || hasManagementGrant afterSnapshot
                                                    || hasBlockingSemantics beforeSnapshot || hasBlockingSemantics afterSnapshot))
                            || forwardingChanged
                            || inversionChanged
                        else
                            let endpointsRemoved =
                                bindingsRemoved beforeSnapshot.Ingress afterSnapshot.Ingress
                                || bindingsRemoved beforeSnapshot.Egress afterSnapshot.Egress
                            let endpointsChanged =
                                Set.ofList beforeSnapshot.Ingress <> Set.ofList afterSnapshot.Ingress
                                || Set.ofList beforeSnapshot.Egress <> Set.ofList afterSnapshot.Egress
                            let priorityChanged = beforeSnapshot.Priority <> afterSnapshot.Priority
                            let endpointRisk =
                                endpointsChanged
                                && (steersPackets beforeSnapshot || steersPackets afterSnapshot || hasBlockingSemantics afterSnapshot
                                    || (endpointsRemoved && hasManagementGrant beforeSnapshot))
                            let priorityRisk =
                                priorityChanged
                                && (steersPackets beforeSnapshot || steersPackets afterSnapshot || hasBlockingSemantics beforeSnapshot || hasBlockingSemantics afterSnapshot
                                    || hasManagementGrant beforeSnapshot || hasManagementGrant afterSnapshot)
                            endpointRisk || priorityRisk || beforeSnapshot.Masquerade <> afterSnapshot.Masquerade
                    let risk = targetNarrowed || ruleNarrowed || selectorNarrowed || structuralNarrowed
                    risk && not (configuration.Kind = "zone" && equivalentZoneAdmission environment configuration.Name before after afterConfiguration)
            with _ -> true

    let runtimeRepairProof
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (snapshot: FirewalldRuntime.RuntimeSnapshot)
        =
        let repair = planRuntimeRepair environment configuration snapshot
        let node = proofBase configuration "runtime-delta"
        node["version"] <- JsonValue.Create 2
        let deltas = JsonArray()
        for delta in repair.Deltas do
            let item = JsonObject()
            item["field"] <- JsonValue.Create delta.Field
            item["value"] <- JsonValue.Create delta.Value
            item["effect"] <- JsonValue.Create(effectName delta.Effect)
            deltas.Add item
        let states = JsonArray()
        for fingerprint in repair.StateFingerprints do states.Add(JsonValue.Create fingerprint)
        node["deltas"] <- deltas
        node["stateFingerprints"] <- states
        node["declaredInterfaces"] <- interfaceArray repair.DeclaredInterfaces
        node["declaredNativeInterfaces"] <- interfaceArray repair.DeclaredNativeInterfaces
        node

    let private readProof (configuration: FirewalldModel.Configuration) (proof: JsonObject option) =
        let node = proof |> Option.defaultWith (fun () -> fail "Firewalld transaction has no native rollback proof.")
        let getString (key: string) =
            match node[key] with
            | null -> fail ("Missing firewalld rollback proof field " + key + ".")
            | value -> value.GetValue<string>()
        if isNull node["version"] then fail "Missing firewalld rollback proof version."
        let version = node["version"].GetValue<int>()
        if not (List.contains version [ 1; 2; 3; 4; 5; 6 ])
           || getString "scope" <> "object"
           || getString "kind" <> configuration.Kind
           || getString "name" <> configuration.Name then
            fail "Firewalld transaction rollback proof belongs to a different object or version."
        let strategy = getString "strategy"
        let expectedKeys =
            if strategy = "runtime-delta" && version = 1 then
                set [ "version"; "scope"; "kind"; "name"; "strategy"; "deltas"; "stateFingerprints" ]
            elif strategy = "runtime-delta" && version = 2 then
                set [ "version"; "scope"; "kind"; "name"; "strategy"; "deltas"; "stateFingerprints"
                      "declaredInterfaces"; "declaredNativeInterfaces" ]
            elif strategy = "reload-before" && version = 1 then
                set [ "version"; "scope"; "kind"; "name"; "strategy"; "beforePresent"; "beforeFingerprint"; "afterPresent"; "afterFingerprint" ]
            elif strategy = "reload-before" && version = 2 then
                set [ "version"; "scope"; "kind"; "name"; "strategy"; "beforePresent"; "beforeFingerprint"; "afterPresent"; "afterFingerprint"
                      "beforeInterfaces"; "beforeNativeInterfaces"; "afterInterfaces"; "afterNativeInterfaces" ]
            elif strategy = "object-delta" && version >= 3 then
                let fields = set [ "version"; "scope"; "kind"; "name"; "strategy"; "beforePresent"; "beforeFingerprint"; "afterPresent"; "afterFingerprint"
                                   "beforeInterfaces"; "beforeNativeInterfaces"; "afterInterfaces"; "afterNativeInterfaces"; "deltas"; "stateFingerprints" ]
                let fields = if version >= 4 then Set.add "afterConfiguration" fields else fields
                if version >= 5 then Set.add "steeringBatch" fields else fields
            elif strategy = "unchanged" && version = 1 then
                set [ "version"; "scope"; "kind"; "name"; "strategy" ]
            else Set.empty
        let actualKeys = node |> Seq.map (fun pair -> pair.Key) |> Set.ofSeq
        if expectedKeys.IsEmpty || actualKeys <> expectedKeys then
            fail "Invalid firewalld native rollback proof fields."
        if strategy = "object-delta" && version >= 5 then
            node["steeringBatch"].GetValue<bool>() |> ignore
        let validateProjection label =
            let presentKey, fingerprintKey = label + "Present", label + "Fingerprint"
            if isNull node[presentKey] then fail ("Missing firewalld " + label + " selector-presence proof.")
            let present = node[presentKey].GetValue<bool>()
            if present then
                match node[fingerprintKey] with
                | null -> fail ("Missing firewalld " + label + " selector fingerprint.")
                | value ->
                    let digest = value.GetValue<string>()
                    if not (Regex.IsMatch(digest, "^[0-9a-f]{64}$", RegexOptions.CultureInvariant)) then
                        fail ("Invalid firewalld " + label + " selector fingerprint.")
            elif not (isNull node[fingerprintKey]) then
                fail ("Absent firewalld " + label + " target cannot have a selector fingerprint.")
        let validateInterfaceProjection label present =
            let typed, native = readInterfaceEvidence node label
            if typed <> native
               || (configuration.Kind <> "zone" && not typed.IsEmpty)
               || (not present && not typed.IsEmpty) then
                fail ("Invalid declared interface evidence for " + label + ".")
        if strategy = "reload-before" || strategy = "object-delta" then
            validateProjection "before"
            validateProjection "after"
            if version >= 2 then
                validateInterfaceProjection "before" (node["beforePresent"].GetValue<bool>())
                validateInterfaceProjection "after" (node["afterPresent"].GetValue<bool>())
        if strategy = "object-delta" then
            if configuration.Kind <> "zone" && configuration.Kind <> "policy" && not ((version = 4 || version = 5) && configuration.Kind = "ipset") then
                fail "Scoped object rollback is not supported for this object kind."
            if not (node["beforePresent"].GetValue<bool>() && node["afterPresent"].GetValue<bool>()) then
                fail "Scoped object rollback requires an existing before and after object."
            let deltas =
                match node["deltas"] with
                | :? JsonArray as values -> values
                | _ -> fail "Missing firewalld object selector delta list."
            let states =
                match node["stateFingerprints"] with
                | :? JsonArray as values -> values
                | _ -> fail "Missing firewalld object selector checkpoints."
            if deltas.Count > 4096 || states.Count <> deltas.Count + 1 then
                fail "Invalid number of firewalld object selector checkpoints."
            for item in deltas do
                match item with
                | :? JsonObject as value ->
                    let keys = value |> Seq.map (fun pair -> pair.Key) |> Set.ofSeq
                    if keys <> set [ "field"; "value"; "add"; "effect" ] then
                        fail "Invalid firewalld object selector delta fields."
                | _ -> fail "Invalid firewalld object selector delta record."
            for item in states do
                if isNull item then fail "Missing firewalld object selector checkpoint."
                let value = item.GetValue<string>()
                if not (Regex.IsMatch(value, "^[0-9a-f]{64}$", RegexOptions.CultureInvariant)) then
                    fail "Invalid firewalld object selector checkpoint fingerprint."
        if strategy = "runtime-delta" && version >= 2 then
            let typed, native = readInterfaceEvidence node "declared"
            let expectedTyped, expectedNative = declaredInterfaceEvidence configuration
            if typed <> expectedTyped || native <> expectedNative then
                fail "Runtime-delta declared interface evidence differs from the saved configuration."
        if strategy = "runtime-delta" then
            let deltas =
                match node["deltas"] with
                | :? JsonArray as values -> values
                | _ -> fail "Missing firewalld runtime delta list."
            let states =
                match node["stateFingerprints"] with
                | :? JsonArray as values -> values
                | _ -> fail "Missing firewalld runtime delta state checkpoints."
            if deltas.Count = 0 || deltas.Count > 4096 || states.Count <> deltas.Count + 1 then
                fail "Invalid number of firewalld runtime delta checkpoints."
            for item in deltas do
                match item with
                | :? JsonObject as value ->
                    let keys = value |> Seq.map (fun pair -> pair.Key) |> Set.ofSeq
                    if keys <> set [ "field"; "value"; "effect" ] then
                        fail "Invalid firewalld runtime delta fields."
                | _ -> fail "Invalid firewalld runtime delta record."
            for item in states do
                if isNull item then fail "Missing firewalld runtime delta state fingerprint."
                let value = item.GetValue<string>()
                if not (Regex.IsMatch(value, "^[0-9a-f]{64}$", RegexOptions.CultureInvariant)) then
                    fail "Invalid firewalld runtime delta state fingerprint."
        strategy, node

    let private decodeRuntimeRepair
        (configuration: FirewalldModel.Configuration)
        (node: JsonObject)
        =
        let expected = expectedSelectorValues configuration
        let deltaNodes = node["deltas"].AsArray()
        let deltas =
            deltaNodes
            |> Seq.map (fun item ->
                let value = item.AsObject()
                let field = value["field"].GetValue<string>()
                let selectorValue = value["value"].GetValue<string>()
                let expectedValues =
                    Map.tryFind field expected
                    |> Option.defaultWith (fun () -> fail "Unsupported field in firewalld runtime delta proof.")
                if not (List.contains selectorValue expectedValues) then
                    fail "Firewalld runtime delta is not a selector in the declared object."
                let effect = deltaEffect configuration field selectorValue
                if value["effect"].GetValue<string>() <> effectName effect then
                    fail "Firewalld runtime delta effect does not match its declared selector."
                { Field = field; Value = selectorValue; Effect = effect })
            |> List.ofSeq
        let effects = deltas |> List.map (fun delta -> delta.Effect) |> Set.ofList
        let steeringConflict = Set.contains Steers effects && (effects.Count > 1 || deltas.Length > 1)
        if (deltas |> List.map (fun delta -> delta.Field, delta.Value) |> Set.ofList).Count <> deltas.Length
           || sortDeltas deltas <> deltas
           || steeringConflict then
            fail "Firewalld runtime delta list is duplicated, unordered, or has an unproved steering order."
        let version = node["version"].GetValue<int>()
        let declaredInterfaces, declaredNativeInterfaces =
            if version >= 2 then readInterfaceEvidence node "declared"
            else [], []
        { Deltas = deltas
          StateFingerprints = node["stateFingerprints"].AsArray() |> Seq.map (fun item -> item.GetValue<string>()) |> List.ofSeq
          Version = version
          DeclaredInterfaces = declaredInterfaces
          DeclaredNativeInterfaces = declaredNativeInterfaces }
    let private decodeObjectRepair
        (configuration: FirewalldModel.Configuration)
        (effectiveBefore: string option)
        (node: JsonObject)
        =
        let before =
            match FirewalldRuntime.snapshotFromXml configuration.Kind configuration.Name effectiveBefore with
            | Error reason -> fail ("Cannot project the recorded firewalld object preimage: " + reason)
            | Ok(Some snapshot) when snapshotComplete snapshot -> snapshot
            | _ -> fail "The recorded firewalld object preimage is absent or incomplete."
        let afterConfiguration =
            if node["version"].GetValue<int>() >= 4 then FirewalldModel.parse (node["afterConfiguration"].GetValue<string>())
            else configuration
        if afterConfiguration.Kind <> configuration.Kind || afterConfiguration.Name <> configuration.Name then
            fail "Scoped object postimage identity differs from its journal."
        let afterXml = Some(FieldRuntime.render afterConfiguration)
        let after =
            match FirewalldRuntime.snapshotFromXml configuration.Kind configuration.Name afterXml with
            | Error reason -> fail ("Cannot project the recorded firewalld object candidate: " + reason)
            | Ok(Some snapshot) when snapshotComplete snapshot -> snapshot
            | _ -> fail "The recorded firewalld object candidate is absent or incomplete."
        if fingerprint before <> node["beforeFingerprint"].GetValue<string>()
           || fingerprint after <> node["afterFingerprint"].GetValue<string>()
           || nonSelectorFingerprint before <> nonSelectorFingerprint after then
            fail "The scoped firewalld object projection differs from its durable before/after proof."
        let beforeConfiguration =
            effectiveBefore
            |> Option.defaultWith (fun () -> fail "A scoped object inverse requires an existing before object.")
            |> parseObjectConfiguration configuration.Kind configuration.Name
        let deltas =
            node["deltas"].AsArray()
            |> Seq.map (fun item ->
                let value = item.AsObject()
                let field = value["field"].GetValue<string>()
                let selectorValue = value["value"].GetValue<string>()
                let add = value["add"].GetValue<bool>()
                if not (List.contains field (objectSelectorFields configuration.Kind))
                   || String.IsNullOrWhiteSpace selectorValue then
                    fail "Unsupported selector in firewalld object delta proof."
                let effect = objectDeltaEffect beforeConfiguration afterConfiguration field selectorValue add
                if value["effect"].GetValue<string>() <> effectName effect then
                    fail "Firewalld object delta effect differs from its native selector."
                { Field = field; Value = selectorValue; Add = add; Effect = effect })
            |> List.ofSeq
        let expectedDeltas = deriveObjectDeltas before after beforeConfiguration afterConfiguration
        let effects = deltas |> List.map (fun delta -> delta.Effect) |> Set.ofList
        let steeringBatch =
            node["version"].GetValue<int>() >= 5
            && node["steeringBatch"].GetValue<bool>()
        let redirectFormat = node["version"].GetValue<int>() = 6
        if redirectFormat && not (steeringBatch && independentLocalRedirects before after deltas) then
            fail "The recorded redirections are not independent local destination ports."
        if steeringBatch && not redirectFormat && not (safeStaticIpSetEntryBatch before after deltas) then
            fail "The recorded ipset batch no longer has disjoint static IPv4 membership semantics."
        let unsafeSteeringMix =
            Set.contains Steers effects && (effects.Count > 1 || (deltas.Length > 1 && not steeringBatch))
        if deltas <> expectedDeltas || sortObjectDeltas deltas <> deltas || unsafeSteeringMix then
            fail "Firewalld object delta list is incomplete, duplicated, unordered, or has an unproved steering order."
        let states = node["stateFingerprints"].AsArray() |> Seq.map (fun item -> item.GetValue<string>()) |> List.ofSeq
        if states <> objectStateFingerprints before deltas then
            fail "Firewalld object selector checkpoints do not match their recorded inverse."
        { Before = before
          After = after
          Deltas = deltas
          StateFingerprints = states }

    let private updateConfigurationMembership (values: string list) value add =
        if add then
            if List.contains value values then values else value :: values
        else values |> List.filter ((<>) value)

    let private updateConfigurationElements
        (configuration: FirewalldModel.Configuration)
        (matches: FirewalldModel.Element -> bool)
        (add: bool)
        (selected: FirewalldModel.Element option)
        =
        if add then
            if configuration.Elements |> List.exists matches then configuration
            else
                let item = selected |> Option.defaultWith (fun () -> fail "The staged selector has no typed intermediate representation.")
                { configuration with Elements = item :: configuration.Elements }
        else
            { configuration with Elements = configuration.Elements |> List.filter (matches >> not) }

    let private directPortSelector name (item: FirewalldModel.Element) =
        if item.Name <> name then None
        else
            match elementAttribute "port" item, elementAttribute "protocol" item with
            | Some port, Some protocol -> Some(FirewalldModel.port (port + "/" + protocol))
            | _ -> None

    let private applyContractionDelta
        (before: FirewalldModel.Configuration)
        (after: FirewalldModel.Configuration)
        (delta: ObjectDelta)
        =
        let matchesElement name attr =
            fun (item: FirewalldModel.Element) ->
                item.Name = name && elementAttribute attr item = Some delta.Value
        match delta.Field with
        | "services" ->
            let matches = matchesElement "service" "name"
            let updated = updateConfigurationElements before matches delta.Add None
            { updated with Services = updateConfigurationMembership before.Services delta.Value delta.Add }
        | "ports" ->
            let matches item = directPortSelector "port" item = Some delta.Value
            let updated = updateConfigurationElements before matches delta.Add None
            { updated with Ports = updateConfigurationMembership before.Ports delta.Value delta.Add }
        | "protocols" ->
            let matches = matchesElement "protocol" "value"
            let updated = updateConfigurationElements before matches delta.Add None
            { updated with Protocols = updateConfigurationMembership before.Protocols delta.Value delta.Add }
        | "source-ports" ->
            let matches item = directPortSelector "source-port" item = Some delta.Value
            let selected =
                after.Elements
                |> List.tryFind (fun item -> directPortSelector "source-port" item = Some delta.Value)
            updateConfigurationElements before matches delta.Add selected
        | "icmp-blocks" ->
            let matches = matchesElement "icmp-block" "name"
            let selected = after.Elements |> List.tryFind matches
            updateConfigurationElements before matches delta.Add selected
        | "rich rules" ->
            let matches (item: FirewalldModel.Element) = item.Name = "rule" && FirewalldRuntime.canonicalRichRule item = Some delta.Value
            let selected = after.Elements |> List.tryFind matches
            updateConfigurationElements before matches delta.Add selected
        | _ -> fail "A mixed selector contraction contains a non-contractive native operation."

    let objectDeltaContractionXml
        (configuration: FirewalldModel.Configuration)
        (effectiveBefore: string option)
        (proof: JsonObject)
        : string option =
        let strategy, node = readProof configuration (Some proof)
        if strategy <> "object-delta" then fail "Expected a scoped firewalld object proof."
        let repair = decodeObjectRepair configuration effectiveBefore node
        let effects = repair.Deltas |> List.map (fun delta -> delta.Effect) |> Set.ofList
        if effects.Count <= 1 then None
        elif Set.contains Steers effects then
            fail "A mixed firewalld steering transition has no authenticated contraction intermediate."
        else
            let beforeConfiguration =
                effectiveBefore
                |> Option.defaultWith (fun () -> fail "A scoped contraction requires an existing before object.")
                |> parseObjectConfiguration configuration.Kind configuration.Name
            let afterConfiguration =
                if node["version"].GetValue<int>() >= 4 then
                    FirewalldModel.parse (node["afterConfiguration"].GetValue<string>())
                else configuration
            let intermediate =
                repair.Deltas
                |> List.filter (fun delta -> delta.Effect = Restricts)
                |> List.fold (fun current delta -> applyContractionDelta current afterConfiguration delta) beforeConfiguration
            Some(FieldRuntime.render intermediate)


    let private checkedCommand (environment: HostEnvironment) arguments =
        let result = environment.Run "firewall-cmd" arguments None
        if result.ExitCode <> 0 then
            let detail = if String.IsNullOrWhiteSpace result.Stderr then result.Stdout else result.Stderr
            fail ("Firewalld runtime rollback command failed: " + String.concat " " arguments + ": " + detail)

    let private inspect (environment: HostEnvironment) (configuration: FirewalldModel.Configuration) =
        FirewalldRuntime.inspectRuntime environment configuration.Kind configuration.Name
        |> Option.defaultWith (fun () -> fail "Unable to observe the loaded firewalld object for rollback.")

    let private targetProjectionMatches
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (proof: JsonObject)
        (label: string)
        =
        let presentKey, fingerprintKey = label + "Present", label + "Fingerprint"
        let expectedPresent = proof[presentKey].GetValue<bool>()
        let version = proof["version"].GetValue<int>()
        match FirewalldRuntime.queryRuntime environment configuration.Kind configuration.Name with
        | Error reason -> fail ("Unable to observe the firewalld " + label + " target: " + reason)
        | Ok None -> not expectedPresent
        | Ok(Some snapshot) ->
            if not expectedPresent || not (snapshotComplete snapshot) then false
            else
                let projected =
                    if version = 1 then Some snapshot
                    else
                        let declared, _ = readInterfaceEvidence proof label
                        projectLiveInterfaces environment declared snapshot
                projected
                |> Option.exists (fun value -> fingerprint value = proof[fingerprintKey].GetValue<string>())

    let private verifyEffectiveProjection
        (configuration: FirewalldModel.Configuration)
        (effectiveXml: string option)
        (proof: JsonObject)
        (label: string)
        =
        let expectedPresent = proof[label + "Present"].GetValue<bool>()
        let version = proof["version"].GetValue<int>()
        let verifySnapshot (snapshot: FirewalldRuntime.RuntimeSnapshot) =
            if not (snapshotComplete snapshot) then
                fail ("Effective on-disk firewalld " + label + " target has incomplete selectors.")
            if version >= 2 then
                let expectedTyped, expectedNative = readInterfaceEvidence proof label
                match interfaceEvidence snapshot with
                | Some(typed, native) when typed = expectedTyped && native = expectedNative -> ()
                | _ -> fail ("Effective on-disk firewalld " + label + " interface evidence differs from its rollback proof.")
            if fingerprint snapshot <> proof[label + "Fingerprint"].GetValue<string>() then
                fail ("Effective on-disk firewalld target differs from the recorded " + label + " preimage.")
        match FirewalldRuntime.snapshotFromXml configuration.Kind configuration.Name effectiveXml with
        | Error reason -> fail ("Cannot project the effective on-disk firewalld " + label + " target: " + reason)
        | Ok None when not expectedPresent ->
            if version >= 2 then
                let typed, native = readInterfaceEvidence proof label
                if not typed.IsEmpty || not native.IsEmpty then
                    fail ("Absent firewalld " + label + " target has interface evidence.")
        | Ok(Some snapshot) when expectedPresent -> verifySnapshot snapshot
        | _ -> fail ("Effective on-disk firewalld target differs from the recorded " + label + " preimage.")
    let private verifyTargetProjection environment configuration proof label =
        if not (targetProjectionMatches environment configuration proof label) then
            fail ("Loaded firewalld target differs from the recorded " + label + " projection.")

    let private validateSourceSelector name (value: string) =
        let key, selector = if value.StartsWith("ipset:", StringComparison.Ordinal) then "ipset", value.Substring(6) else "address", value
        let sourceElement: FirewalldModel.Element =
            { Name = "source"; Attributes = Map.ofList [ key, selector ]; Text = None; Children = [] }
        let candidate =
            { FirewalldModel.empty "zone" name with
                Elements = [ sourceElement ] }
        FirewalldModel.validate candidate |> ignore
        if FirewalldRuntime.normalizeFieldValues "zone" "sources" [ value ] <> [ value ] then
            fail "A zone source selector is not in its canonical native form."
    let private selectorArguments (configuration: FirewalldModel.Configuration) (delta: RuntimeDelta) action =
        let selector =
            match configuration.Kind with
            | "zone" -> "--zone=" + configuration.Name
            | "policy" -> "--policy=" + configuration.Name
            | "ipset" when delta.Field = "entries" -> "--ipset=" + configuration.Name
            | _ -> fail "No native selector inverse exists for this object kind."
        let optionName =
            match delta.Field with
            | "services" ->
                FirewalldModel.nativeReference "service" "runtime service" delta.Value |> ignore
                "service"
            | "ports" ->
                FirewalldModel.port delta.Value |> ignore
                "port"
            | "source-ports" ->
                FirewalldModel.port delta.Value |> ignore
                "source-port"
            | "protocols" ->
                FirewalldModel.token "runtime protocol" 128 delta.Value |> ignore
                "protocol"
            | "icmp-blocks" ->
                FirewalldModel.nativeReference "icmptype" "runtime ICMP type" delta.Value |> ignore
                "icmp-block"
            | "rich rules" -> "rich-rule"
            | "forward-ports" -> "forward-port"
            | "sources" when configuration.Kind = "zone" ->
                validateSourceSelector configuration.Name delta.Value
                "source"
            | "entries" when configuration.Kind = "ipset" -> "entry"
            | _ -> fail "Unsupported selector in firewalld rollback proof."
        let argument =
            if delta.Field = "forward-ports" then
                FirewalldRuntime.forwardPortCommandValue delta.Value |> Option.defaultWith (fun () -> fail "Invalid scoped forward-port command.")
            else delta.Value
        [ selector; "--" + action + "-" + optionName + "=" + argument ]

    let activateReload (environment: HostEnvironment) (configuration: FirewalldModel.Configuration) (proof: JsonObject) =
        let strategy, node = readProof configuration (Some proof)
        if strategy <> "reload-before" then fail "Expected a validated daemon reload proof."
        if not (targetProjectionMatches environment configuration node "before") then
            fail "Loaded firewalld target changed after staging; refusing a daemon-wide reload that would erase foreign runtime state."
        match FirewalldRuntime.validateReloadExcludingTargetObject environment configuration.Kind configuration.Name with
        | Ok () -> ()
        | Error reason -> fail ("Refusing daemon-wide firewalld activation because non-target runtime state changed after staging: " + reason)
        checkedCommand environment [ "--check-config" ]
        FirewalldRuntime.withVerifiedDockerBindings environment (fun () ->
            checkedCommand environment [ "--reload" ])
        verifyTargetProjection environment configuration node "after"
        match FirewalldRuntime.validateReload environment with
        | Ok () -> ()
        | Error reason -> fail ("The activated firewalld runtime differs from its staged native projection: " + reason)

    let private activationProgress (completedSteps: int) (inFlightStep: int option) : FirewalldLifecycle.NativeActivationProgress =
        { CompletedSteps = completedSteps
          InFlightStep = inFlightStep }

    let private activationCommand (environment: HostEnvironment) arguments =
        let result = environment.Run "firewall-cmd" arguments None
        if result.ExitCode <> 0 then
            let detail = if String.IsNullOrWhiteSpace result.Stderr then result.Stdout else result.Stderr
            fail ("Firewalld native activation command failed: " + String.concat " " arguments + ": " + detail)
        if not (String.IsNullOrWhiteSpace result.Stderr) then
            fail ("Firewalld native activation command emitted stderr; refusing to attribute the selector change: " + String.concat " " arguments)
        if result.Stdout.Trim() <> "success" then
            fail ("Firewalld native activation command did not confirm a selector change: " + String.concat " " arguments)
    let private attributableStepCount
        (progress: FirewalldLifecycle.NativeActivationProgress option)
        (currentIndex: int)
        (maximumSteps: int)
        =
        match progress with
        | None when currentIndex = 0 -> 0
        | None -> fail "A later firewalld selector checkpoint has no durable native command attribution."
        | Some value when value.CompletedSteps < 0 || value.CompletedSteps > maximumSteps ->
            fail "Invalid durable firewalld native activation progress."
        | Some value ->
            match value.InFlightStep with
            | Some index when index < 0 || index >= maximumSteps || index <> value.CompletedSteps ->
                fail "Invalid in-flight firewalld native activation progress."
            | Some index when currentIndex > index ->
                fail "The live firewalld selector may include a command without a confirmed native success."
            | _ when currentIndex = value.CompletedSteps -> currentIndex
            | _ -> fail "The live firewalld selector differs from the last durably attributed native checkpoint."

    let private remainingUndo (tracking: FirewalldLifecycle.UndoJournal option) current maximum initial =
        match tracking with
        | Some { Previous = Some receipt } ->
            if receipt.InFlightStep.IsSome then
                fail "The previous firewalld inverse command has no confirmed outcome; refusing to issue it again."
            if receipt.RemainingSteps <> current || receipt.RemainingSteps > maximum then
                fail "The live firewalld checkpoint differs from the durable inverse cursor; independent changes are not ours."
            receipt.RemainingSteps
        | Some _ -> initial ()
        | None when current = 0 -> 0
        | None -> fail "Legacy firewalld progress cannot identify a previous inverse; refusing a native write."

    let private undoStep (tracking: FirewalldLifecycle.UndoJournal option) index commandAndVerify =
        let journal = tracking |> Option.defaultWith (fun () -> fail "A durable inverse journal is required.")
        journal.Persist { RemainingSteps = index + 1; InFlightStep = Some index }
        commandAndVerify ()
        journal.Persist { RemainingSteps = index; InFlightStep = None }

    let private objectRepairStateIndex (repair: ObjectRepair) (snapshot: FirewalldRuntime.RuntimeSnapshot) =
        let values = objectSelectorValues snapshot |> Map.map (fun _ items -> Set.ofList items)
        let fingerprint = objectStateFingerprint repair.Deltas values
        repair.StateFingerprints |> List.tryFindIndex ((=) fingerprint)

    let validateObjectDeltaCheckpoint
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (effectiveBefore: string option)
        (proof: JsonObject)
        =
        let strategy, node = readProof configuration (Some proof)
        if strategy <> "object-delta" then fail "Expected a scoped firewalld object proof."
        verifyEffectiveProjection configuration effectiveBefore node "before"
        let repair = decodeObjectRepair configuration effectiveBefore node
        let current = inspect environment configuration
        ensureCompleteSnapshot configuration current
        if objectRepairStateIndex repair current <> Some 0
           || not (objectRuntimeMatchesCheckpointZero environment repair.Before repair.Deltas current) then
            fail "The live firewalld object no longer matches authenticated scoped checkpoint zero."

    let validateRuntimeRepairCheckpoint
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (proof: JsonObject)
        =
        let strategy, node = readProof configuration (Some proof)
        if strategy <> "runtime-delta" then fail "Expected a reversible runtime repair proof."
        let repair = decodeRuntimeRepair configuration node
        let current = inspect environment configuration
        ensureCompleteSnapshot configuration current
        let stateIndex snapshot =
            let hash = ownedFingerprintForRepair environment configuration repair snapshot
            repair.StateFingerprints |> List.tryFindIndex ((=) hash)
        if stateIndex current <> Some 0 then
            fail "The live firewalld object no longer matches authenticated runtime checkpoint zero."
        observeAdjusted environment configuration current
    let activateObjectDeltaWithProgress
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (effectiveBefore: string option)
        (proof: JsonObject)
        (report: FirewalldLifecycle.NativeActivationProgress -> unit)
        =
        let strategy, node = readProof configuration (Some proof)
        if strategy <> "object-delta" then fail "Expected a scoped firewalld object proof."
        validateObjectDeltaCheckpoint environment configuration effectiveBefore proof
        let repair = decodeObjectRepair configuration effectiveBefore node
        let mutable current = inspect environment configuration
        ensureCompleteSnapshot configuration current
        if not (objectRuntimeNonSelectorsMatch environment repair.Before current) then
            fail "The firewalld object's structural runtime state changed after staging."
        let currentIndex =
            objectRepairStateIndex repair current
            |> Option.defaultWith (fun () -> fail "Runtime selectors are outside every scoped object checkpoint.")
        if currentIndex <> 0 then
            fail "Scoped object activation requires authenticated checkpoint zero before its first native command."
        for index in 0 .. repair.Deltas.Length - 1 do
            if objectRepairStateIndex repair current <> Some index
               || not (objectRuntimeNonSelectorsMatch environment repair.Before current) then
                fail "Runtime selectors or structure changed before the next scoped object step."
            let delta = repair.Deltas[index]
            let runtimeDelta = { Field = delta.Field; Value = delta.Value; Effect = delta.Effect }
            report (activationProgress index (Some index))
            activationCommand environment (selectorArguments configuration runtimeDelta (if delta.Add then "add" else "remove"))
            current <- inspect environment configuration
            ensureCompleteSnapshot configuration current
            if objectRepairStateIndex repair current <> Some(index + 1)
               || not (objectRuntimeNonSelectorsMatch environment repair.Before current) then
                fail "firewalld did not apply the recorded scoped object selector step."
            report (activationProgress (index + 1) None)
        if not (objectRuntimeMatchesPreimage environment repair.After current) then
            fail "The activated firewalld object differs from its after projection outside preserved restrictive rich rules."


    let activateRuntimeRepairWithProgress
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (proof: JsonObject)
        (report: FirewalldLifecycle.NativeActivationProgress -> unit)
        =
        let strategy, node = readProof configuration (Some proof)
        if strategy <> "runtime-delta" then fail "Expected a reversible runtime repair proof."
        validateRuntimeRepairCheckpoint environment configuration proof
        let repair = decodeRuntimeRepair configuration node
        let stateIndex snapshot =
            let hash = ownedFingerprintForRepair environment configuration repair snapshot
            repair.StateFingerprints |> List.tryFindIndex ((=) hash)
        let snapshot = inspect environment configuration
        ensureCompleteSnapshot configuration snapshot
        let currentIndex =
            stateIndex snapshot
            |> Option.defaultWith (fun () -> fail "Runtime selectors are outside every persisted repair checkpoint.")
        if currentIndex <> 0 then
            fail "Runtime repair activation requires authenticated checkpoint zero before its first native command."
        observeAdjusted environment configuration snapshot
        let mutable current = snapshot
        for index in 0 .. repair.Deltas.Length - 1 do
            if ownedFingerprintForRepair environment configuration repair current <> repair.StateFingerprints[index] then
                fail "Runtime selector membership changed before the next repair step."
            report (activationProgress index (Some index))
            activationCommand environment (selectorArguments configuration repair.Deltas[index] "add")
            current <- inspect environment configuration
            ensureCompleteSnapshot configuration current
            if ownedFingerprintForRepair environment configuration repair current <> repair.StateFingerprints[index + 1] then
                fail "firewalld did not apply the recorded runtime selector step."
            report (activationProgress (index + 1) None)
            observeAdjusted environment configuration current
        let observation = FirewalldRuntime.observe environment configuration
        if not observation.Observed || not observation.InSync then
            fail "The repaired firewalld object did not converge to its declared selectors."


    let restoreRuntimeWithProgress
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (effectiveCurrent: string option)
        (proof: JsonObject option)
        (phase: FirewalldLifecycle.RecoveryPhase)
        (preReload: unit -> unit)
        (progress: FirewalldLifecycle.NativeActivationProgress option)
        (tracking: FirewalldLifecycle.UndoJournal option)
        =
        let strategy, node = readProof configuration proof
        if strategy = "reload-before" || strategy = "object-delta" then
            verifyEffectiveProjection configuration effectiveCurrent node "before"
        let loadedBeforeMatches =
            if phase = FirewalldLifecycle.BootBeforeFirewalld || strategy <> "reload-before" then false
            else
                match FirewalldRuntime.snapshotFromXml configuration.Kind configuration.Name effectiveCurrent with
                | Error reason -> fail ("Cannot project the restored firewalld preimage: " + reason)
                | Ok None ->
                    match FirewalldRuntime.queryRuntime environment configuration.Kind configuration.Name with
                    | Ok None -> true
                    | Error reason -> fail ("Unable to observe the restored firewalld target: " + reason)
                    | Ok(Some _) -> false
                | Ok(Some expected) ->
                    match FirewalldRuntime.queryRuntime environment configuration.Kind configuration.Name with
                    | Ok(Some live) ->
                        matchesLoadedProjectionPreservingRestrictions environment expected live
                    | Error reason -> fail ("Unable to observe the restored firewalld target: " + reason)
                    | Ok None -> false
        match phase with
        | FirewalldLifecycle.BootBeforeFirewalld -> ()
        | FirewalldLifecycle.ActiveDaemon | FirewalldLifecycle.BootAfterFirewalld ->
            match strategy with
            | "unchanged" -> ()
            | ("object-delta" | "runtime-delta") when
                    tracking |> Option.bind _.Previous |> Option.exists (fun p -> p.RemainingSteps = 0 && p.InFlightStep.IsNone) ->
                // Authority is exhausted even if a foreign writer subsequently
                // introduced an identical selector.
                ()
            | ("object-delta" | "runtime-delta") when phase = FirewalldLifecycle.ActiveDaemon &&
                    (tracking |> Option.bind _.Previous).IsNone &&
                    progress |> Option.exists (fun p -> p.CompletedSteps = 0 && p.InFlightStep.IsNone) ->
                // No native command was ever begun. The restored file is ours;
                // any new live membership belongs entirely to another writer.
                ()
            | "reload-before" ->
                if phase = FirewalldLifecycle.ActiveDaemon then
                    if loadedBeforeMatches then ()
                    elif targetProjectionMatches environment configuration node "after" then
                        preReload ()
                        match FirewalldRuntime.validateReloadExcludingTargetObject environment configuration.Kind configuration.Name with
                        | Ok () -> ()
                        | Error reason ->
                            fail ("Refusing rollback reload because non-target live state changed while confirmation was pending: " + reason)
                        let check = environment.Run "firewall-cmd" [ "--check-config" ] None
                        if check.ExitCode <> 0 then fail "The restored firewalld preimage failed native configuration validation."
                        FirewalldRuntime.withVerifiedDockerBindings environment (fun () ->
                            checkedCommand environment [ "--reload" ])
                        verifyTargetProjection environment configuration node "before"
                        match FirewalldRuntime.validateReload environment with
                        | Ok () -> ()
                        | Error reason -> fail ("The restored firewalld runtime did not match its known-working preimage: " + reason)
                    else
                        fail "Loaded target is neither the saved preimage nor the staged post-state; refusing rollback reload."
                elif not loadedBeforeMatches then
                    fail "Post-boot firewalld did not load the restored target preimage."
            | "object-delta" ->
                let repair = decodeObjectRepair configuration effectiveCurrent node
                let mutable current = inspect environment configuration
                ensureCompleteSnapshot configuration current
                let currentIndex =
                    objectRepairStateIndex repair current
                    |> Option.defaultWith (fun () -> fail "Runtime selectors are outside the recorded scoped object checkpoints.")
                let inverseOnlyNarrows =
                    repair.Deltas
                    |> List.forall (fun delta -> inverseEffect delta.Effect = Restricts)
                let allowForeignInterfaces =
                    phase = FirewalldLifecycle.ActiveDaemon && currentIndex > 0 && inverseOnlyNarrows
                if not (objectRuntimeRollbackStructureMatches environment repair.Before current allowForeignInterfaces) then
                    fail "The live firewalld object structure differs from its recorded preimage; refusing a scoped inverse."
                if phase = FirewalldLifecycle.BootAfterFirewalld && currentIndex <> 0 then
                    fail "Post-boot firewalld did not load the restored scoped object preimage."
                let inverseCount =
                    if phase <> FirewalldLifecycle.ActiveDaemon then 0
                    else remainingUndo tracking currentIndex repair.Deltas.Length (fun () ->
                        if currentIndex = 0 then 0 else attributableStepCount progress currentIndex repair.Deltas.Length)
                if inverseCount > 0 then
                    for index in inverseCount - 1 .. -1 .. 0 do
                        if objectRepairStateIndex repair current <> Some(index + 1)
                           || not (objectRuntimeRollbackStructureMatches environment repair.Before current allowForeignInterfaces) then
                            fail "Runtime selectors changed before their durably attributed scoped inverse."
                        let delta = repair.Deltas[index]
                        let runtimeDelta = { Field = delta.Field; Value = delta.Value; Effect = delta.Effect }
                        undoStep tracking index (fun () ->
                            activationCommand environment (selectorArguments configuration runtimeDelta (if delta.Add then "remove" else "add"))
                            current <- inspect environment configuration
                            ensureCompleteSnapshot configuration current
                            if objectRepairStateIndex repair current <> Some index
                               || not (objectRuntimeRollbackStructureMatches environment repair.Before current allowForeignInterfaces) then
                                fail "firewalld did not restore the recorded scoped object checkpoint.")
                let returnedToPreimage =
                    if allowForeignInterfaces then objectRuntimeMatchesPreimageForRollback environment repair current
                    else objectRuntimeMatchesPreimage environment repair.Before current
                if not returnedToPreimage || objectRepairStateIndex repair current <> Some 0 then
                    fail "The scoped firewalld object did not return to its recorded runtime preimage."
            | "runtime-delta" ->
                let repair = decodeRuntimeRepair configuration node
                let states = repair.StateFingerprints
                let lastIndex = repair.Deltas.Length
                let mutable current = inspect environment configuration
                ensureCompleteSnapshot configuration current
                let currentIndex =
                    ownedFingerprintForRepair environment configuration repair current
                    |> fun hash ->
                        states
                        |> List.tryFindIndex ((=) hash)
                        |> Option.defaultWith (fun () -> fail "Runtime owned selectors are outside the recorded repair checkpoints.")
                if phase = FirewalldLifecycle.BootAfterFirewalld && (tracking |> Option.bind _.Previous).IsNone && currentIndex <> lastIndex then
                    fail "Post-boot firewalld did not load the staged permanent candidate; refusing an unproved inverse."
                observeAdjusted environment configuration current
                let inverseCount =
                    remainingUndo tracking currentIndex lastIndex (fun () ->
                        if phase = FirewalldLifecycle.BootAfterFirewalld then currentIndex
                        elif currentIndex > 0 then attributableStepCount progress currentIndex lastIndex
                        else 0)
                if inverseCount > 0 then
                    for index = inverseCount - 1 downto 0 do
                        if ownedFingerprintForRepair environment configuration repair current <> states[index + 1] then
                            fail "Runtime selector membership changed before its durably attributed inverse."
                        undoStep tracking index (fun () ->
                            activationCommand environment (selectorArguments configuration repair.Deltas[index] "remove")
                            current <- inspect environment configuration
                            ensureCompleteSnapshot configuration current
                            if ownedFingerprintForRepair environment configuration repair current <> states[index] then
                                fail "firewalld did not restore the recorded selector checkpoint."
                            observeAdjusted environment configuration current)
            | _ -> fail "Invalid firewalld recovery strategy."
