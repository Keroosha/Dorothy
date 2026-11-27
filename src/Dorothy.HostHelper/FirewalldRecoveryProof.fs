namespace Dorothy.HostHelper

open System
open System.Security.Cryptography
open System.Text
open System.Text.Json.Nodes
open System.Text.RegularExpressions

module FirewalldRecoveryProof =
    type private RepairEffect =
        | Grants
        | Restricts
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
        let verdicts =
            rule.Children
            |> List.filter (fun child ->
                List.contains child.Name [ "accept"; "drop"; "reject"; "mark"; "forward-port"; "masquerade" ])
        match verdicts with
        | [ verdict ] when verdict.Name = "drop" || verdict.Name = "reject" -> Restricts
        | [ verdict ] when verdict.Name = "accept" -> Grants
        | [ verdict ] when verdict.Name = "forward-port" || verdict.Name = "masquerade" -> Steers
        | _ -> fail "A rich rule has no single reversible monotone verdict; refusing runtime-only repair."

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
              "forward-ports", 4; "icmp-blocks", 5; "rich rules", 6; "entries", 7 ]

    let private sortDeltas (deltas: RuntimeDelta list) =
        deltas
        |> List.sortWith (fun left right ->
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
        if effects.Count <> 1 then
            fail "Runtime repair mixes grants and restrictions; refusing an unsafe intermediate policy."
        if effects = set [ Steers ] && deltas.Length > 1 then
            fail "Multiple NAT/forward-port steering deltas have no proved safe intermediate order; repair them separately."
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

    let private effectName = function Grants -> "grant" | Restricts -> "restrict" | Steers -> "steer"
    let private objectSelectorFields kind =
        if kind = "ipset" then [ "entries" ]
        else [ "services"; "ports"; "source-ports"; "protocols"; "icmp-blocks"; "rich rules"; "forward-ports" ]

    let private withoutObjectSelectors (snapshot: FirewalldRuntime.RuntimeSnapshot) =
        let nativeFields =
            objectSelectorFields snapshot.Kind
            |> List.fold (fun fields field -> Map.add field [] fields) snapshot.NativeFields
        { snapshot with
            Services = []
            Ports = []
            SourcePorts = []
            Protocols = []
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

    let private objectDeltaEffect (beforeConfiguration: FirewalldModel.Configuration) (afterConfiguration: FirewalldModel.Configuration) field value add =
        if field = "entries" then Steers // source membership can choose either a grant or a denial
        elif add then deltaEffect afterConfiguration field value
        else deltaEffect beforeConfiguration field value |> inverseEffect

    let private sortObjectDeltas deltas =
        deltas
        |> List.sortWith (fun left right ->
            let fieldCompare = compare (Map.find left.Field fieldOrder) (Map.find right.Field fieldOrder)
            if fieldCompare <> 0 then fieldCompare
            else StringComparer.Ordinal.Compare(left.Value, right.Value))
    let private deriveObjectDeltas before after beforeConfiguration afterConfiguration =
        let beforeSelectors = actualSelectorValues before
        let afterSelectors = actualSelectorValues after
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
        let mutable values = actualSelectorValues before |> Map.map (fun _ items -> Set.ofList items)
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
            let expectedSelectors = actualSelectorValues expected
            let actualSelectors = actualSelectorValues actual
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

    let matchesLoadedProjectionPreservingRestrictions
        (environment: HostEnvironment)
        (expected: FirewalldRuntime.RuntimeSnapshot)
        (actual: FirewalldRuntime.RuntimeSnapshot)
        =
        if expected.Kind = "zone" || expected.Kind = "policy" then objectRuntimeMatchesPreimage environment expected actual
        else matchesLoadedProjection environment expected actual

    let objectDeltaProof
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (effectiveBefore: string option)
        (effectiveAfter: string option)
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
                    if effects.Count > 1
                       || (effects = set [ Steers ] && deltas.Length > 1)
                       || deltas.Length > 4096 then None
                    else
                        match FirewalldRuntime.queryPermanent environment configuration.Kind configuration.Name,
                              FirewalldRuntime.inspectRuntime environment configuration.Kind configuration.Name with
                        | Ok(Some permanent), Some live
                            when matchesLoadedProjection environment before permanent
                                 && objectRuntimeMatchesPreimage environment before live ->
                            let node = proofBase configuration "object-delta"
                            node["version"] <- JsonValue.Create 4
                            // On Delete the effective postimage can be an adopted or
                            // vendor definition, not the departing provider inputs.
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
    // Releasing an interface is not an SSH tightening if every zone it can
    // reach has identical host admission and no policy dispatch distinguishes
    // those zones. Forward/masquerade are transit settings; binding-transfer
    // validation independently checks whether a workload becomes exposed.
    let private equivalentZoneAdmission environment name (before: FirewalldRuntime.RuntimeSnapshot option) (after: FirewalldRuntime.RuntimeSnapshot option) =
        let managementPort =
            match Environment.GetEnvironmentVariable "SSH_CONNECTION" with
            | null -> None
            | text ->
                match text.Split(' ', StringSplitOptions.RemoveEmptyEntries) with
                | [| _; _; _; p |] -> match Int32.TryParse p with true, n when n > 0 && n <= 65535 -> Some n | _ -> None
                | _ -> None
        let relevantPorts ports =
            match managementPort with
            | None -> Set.ofList ports
            | Some port ->
                ports |> List.filter (fun (value: string) ->
                    match value.Split('/') with
                    | [| range; "tcp" |] ->
                        let ends = range.Split('-')
                        Int32.Parse(ends[0]) <= port && Int32.Parse(ends[ends.Length - 1]) >= port
                    | _ -> false) |> Set.ofList
        let signature (s: FirewalldRuntime.RuntimeSnapshot) =
            s.Target, Set.ofList s.Services, relevantPorts s.Ports, Set.ofList s.Protocols,
            Set.ofList s.SourcePorts, Set.ofList s.ForwardPorts, Set.ofList s.RichRules,
            Set.ofList s.IcmpBlocks, s.IcmpBlockInversion
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
                let policies = FirewalldRuntime.listRuntime environment "policy" |> Option.get
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
                                    || view.Interfaces |> List.exists (fun iface -> changed |> List.exists (overlaps iface))) then
                                    affected <- Set.add z affected
                                    views |> List.forall snapshotComplete && sameShape first views
                                else true)
                    zonesAgree && (policies |> List.forall (fun p ->
                        [ FirewalldRuntime.inspectRuntime environment "policy" p |> Option.get
                          FirewalldRuntime.inspectPermanent environment "policy" p |> Option.get ]
                        |> List.forall (fun policy ->
                            snapshotComplete policy && not (List.exists affected.Contains (policy.Ingress @ policy.Egress)))))

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
                            | Some names -> bindings |> List.exists (fun name -> Set.contains name names)
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
                            || List.contains "HOST" snapshot.Egress)
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
                    let managementPort =
                        let connection = Environment.GetEnvironmentVariable "SSH_CONNECTION"
                        let fields =
                            if isNull connection then [||]
                            else connection.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
                        if fields.Length = 4 then
                            match Int32.TryParse fields[3] with
                            | true, port when port >= 1 && port <= 65535 -> Some port
                            | _ -> None
                        else None
                    let hasManagementGrant (snapshot: FirewalldRuntime.RuntimeSnapshot) =
                        let ports =
                            match managementPort with
                            | None -> false
                            | Some port ->
                                snapshot.Ports
                                |> List.exists (fun value ->
                                    match value.Split('/') with
                                    | [| range; "tcp" |] ->
                                        let bounds = range.Split('-')
                                        match bounds with
                                        | [| one |] ->
                                            match Int32.TryParse one with
                                            | true, candidate -> candidate = port
                                            | _ -> false
                                        | [| first; last |] ->
                                            match Int32.TryParse first, Int32.TryParse last with
                                            | (true, low), (true, high) -> low <= port && port <= high
                                            | _ -> false
                                        | _ -> false
                                    | _ -> false)
                        targetRank snapshot.Target = 2
                        || List.contains "ssh" snapshot.Services
                        || ports
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
                                && (hasBlockingSemantics afterSnapshot
                                    || (endpointsRemoved && hasManagementGrant beforeSnapshot))
                            let priorityRisk =
                                priorityChanged
                                && (hasBlockingSemantics beforeSnapshot || hasBlockingSemantics afterSnapshot
                                    || hasManagementGrant beforeSnapshot || hasManagementGrant afterSnapshot)
                            endpointRisk || priorityRisk || beforeSnapshot.Masquerade <> afterSnapshot.Masquerade
                    let risk = targetNarrowed || ruleNarrowed || selectorNarrowed || structuralNarrowed
                    risk && not (configuration.Kind = "zone" && equivalentZoneAdmission environment configuration.Name before after)
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
        if not (List.contains version [ 1; 2; 3; 4 ])
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
            elif strategy = "object-delta" && (version = 3 || version = 4) then
                let fields = set [ "version"; "scope"; "kind"; "name"; "strategy"; "beforePresent"; "beforeFingerprint"; "afterPresent"; "afterFingerprint"
                                   "beforeInterfaces"; "beforeNativeInterfaces"; "afterInterfaces"; "afterNativeInterfaces"; "deltas"; "stateFingerprints" ]
                if version = 4 then Set.add "afterConfiguration" fields else fields
            elif strategy = "unchanged" && version = 1 then
                set [ "version"; "scope"; "kind"; "name"; "strategy" ]
            else Set.empty
        let actualKeys = node |> Seq.map (fun pair -> pair.Key) |> Set.ofSeq
        if expectedKeys.IsEmpty || actualKeys <> expectedKeys then
            fail "Invalid firewalld native rollback proof fields."
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
            if configuration.Kind <> "zone" && configuration.Kind <> "policy" && not (version = 4 && configuration.Kind = "ipset") then
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
        if strategy = "runtime-delta" && version = 2 then
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
        if (deltas |> List.map (fun delta -> delta.Field, delta.Value) |> Set.ofList).Count <> deltas.Length
           || sortDeltas deltas <> deltas
           || effects.Count <> 1 then
            fail "Firewalld runtime delta list is duplicated, unordered, or non-monotone."
        if effects = set [ Steers ] && deltas.Length > 1 then
            fail "Multiple NAT/forward-port steering deltas have no proved safe intermediate order."
        let version = node["version"].GetValue<int>()
        let declaredInterfaces, declaredNativeInterfaces =
            if version = 2 then readInterfaceEvidence node "declared"
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
            if node["version"].GetValue<int>() = 4 then FirewalldModel.parse (node["afterConfiguration"].GetValue<string>())
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
        if deltas <> expectedDeltas
           || sortObjectDeltas deltas <> deltas
           || effects.Count > 1
           || (effects = set [ Steers ] && deltas.Length > 1) then
            fail "Firewalld object delta list is incomplete, duplicated, unordered, or non-monotone."
        let states = node["stateFingerprints"].AsArray() |> Seq.map (fun item -> item.GetValue<string>()) |> List.ofSeq
        if states <> objectStateFingerprints before deltas then
            fail "Firewalld object selector checkpoints do not match their recorded inverse."
        { Before = before
          After = after
          Deltas = deltas
          StateFingerprints = states }


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
            | "entries" when configuration.Kind = "ipset" -> "entry"
            | _ -> fail "Unsupported selector in firewalld rollback proof."
        [ selector; "--" + action + "-" + optionName + "=" + delta.Value ]
    let activateReload (environment: HostEnvironment) (configuration: FirewalldModel.Configuration) (proof: JsonObject) =
        let strategy, node = readProof configuration (Some proof)
        if strategy <> "reload-before" then fail "Expected a validated daemon reload proof."
        if not (targetProjectionMatches environment configuration node "before") then
            fail "Loaded firewalld target changed after staging; refusing a daemon-wide reload that would erase foreign runtime state."
        match FirewalldRuntime.validateReloadExcludingTargetObject environment configuration.Kind configuration.Name with
        | Ok () -> ()
        | Error reason -> fail ("Refusing daemon-wide firewalld activation because non-target runtime state changed after staging: " + reason)
        checkedCommand environment [ "--check-config" ]
        checkedCommand environment [ "--reload" ]
        verifyTargetProjection environment configuration node "after"
        match FirewalldRuntime.validateReload environment with
        | Ok () -> ()
        | Error reason -> fail ("The activated firewalld runtime differs from its staged native projection: " + reason)

    let private objectRepairStateIndex (repair: ObjectRepair) (snapshot: FirewalldRuntime.RuntimeSnapshot) =
        let values = actualSelectorValues snapshot |> Map.map (fun _ items -> Set.ofList items)
        let fingerprint = objectStateFingerprint repair.Deltas values
        repair.StateFingerprints |> List.tryFindIndex ((=) fingerprint)

    let activateObjectDelta
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (effectiveBefore: string option)
        (proof: JsonObject)
        =
        let strategy, node = readProof configuration (Some proof)
        if strategy <> "object-delta" then fail "Expected a scoped firewalld object proof."
        verifyEffectiveProjection configuration effectiveBefore node "before"
        let repair = decodeObjectRepair configuration effectiveBefore node
        let mutable current = inspect environment configuration
        ensureCompleteSnapshot configuration current
        if not (objectRuntimeNonSelectorsMatch environment repair.Before current) then
            fail "The firewalld object's structural runtime state changed after staging."
        let currentIndex =
            objectRepairStateIndex repair current
            |> Option.defaultWith (fun () -> fail "Runtime selectors are outside every scoped object checkpoint.")
        if currentIndex < repair.Deltas.Length then
            for index in currentIndex .. repair.Deltas.Length - 1 do
                if objectRepairStateIndex repair current <> Some index
                   || not (objectRuntimeNonSelectorsMatch environment repair.Before current) then
                    fail "Runtime selectors or structure changed before the next scoped object step."
                let delta = repair.Deltas[index]
                let runtimeDelta = { Field = delta.Field; Value = delta.Value; Effect = delta.Effect }
                checkedCommand environment (selectorArguments configuration runtimeDelta (if delta.Add then "add" else "remove"))
                current <- inspect environment configuration
                ensureCompleteSnapshot configuration current
                if objectRepairStateIndex repair current <> Some(index + 1)
                   || not (objectRuntimeNonSelectorsMatch environment repair.Before current) then
                    fail "firewalld did not apply the recorded scoped object selector step."
        if not (objectRuntimeMatchesPreimage environment repair.After current) then
            fail "The activated firewalld object differs from its after projection outside preserved restrictive rich rules."


    let activateRuntimeRepair (environment: HostEnvironment) (configuration: FirewalldModel.Configuration) (proof: JsonObject) =
        let strategy, node = readProof configuration (Some proof)
        if strategy <> "runtime-delta" then fail "Expected a reversible runtime repair proof."
        let repair = decodeRuntimeRepair configuration node
        let stateIndex snapshot =
            let hash = ownedFingerprintForRepair environment configuration repair snapshot
            repair.StateFingerprints |> List.tryFindIndex ((=) hash)
        let snapshot = inspect environment configuration
        ensureCompleteSnapshot configuration snapshot
        let currentIndex =
            stateIndex snapshot
            |> Option.defaultWith (fun () -> fail "Runtime selectors are outside every persisted repair checkpoint.")
        if currentIndex < repair.Deltas.Length then
            observeAdjusted environment configuration snapshot
            let mutable current = snapshot
            for index in currentIndex .. repair.Deltas.Length - 1 do
                if ownedFingerprintForRepair environment configuration repair current <> repair.StateFingerprints[index] then
                    fail "Runtime selector membership changed before the next repair step."
                checkedCommand environment (selectorArguments configuration repair.Deltas[index] "add")
                current <- inspect environment configuration
                ensureCompleteSnapshot configuration current
                if ownedFingerprintForRepair environment configuration repair current <> repair.StateFingerprints[index + 1] then
                    fail "firewalld did not apply the recorded runtime selector step."
                observeAdjusted environment configuration current
        let observation = FirewalldRuntime.observe environment configuration
        if not observation.Observed || not observation.InSync then
            fail "The repaired firewalld object did not converge to its declared selectors."

    let restoreRuntimeWithPreReload
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (effectiveCurrent: string option)
        (proof: JsonObject option)
        (phase: FirewalldLifecycle.RecoveryPhase)
        (preReload: unit -> unit)
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
                        checkedCommand environment [ "--reload" ]
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
                if not (objectRuntimeNonSelectorsMatch environment repair.Before current) then
                    fail "The live firewalld object structure differs from its recorded preimage; refusing a scoped inverse."
                let currentIndex =
                    objectRepairStateIndex repair current
                    |> Option.defaultWith (fun () -> fail "Runtime selectors are outside the recorded scoped object checkpoints.")
                if phase = FirewalldLifecycle.BootAfterFirewalld && currentIndex <> 0 then
                    fail "Post-boot firewalld did not load the restored scoped object preimage."
                if phase = FirewalldLifecycle.ActiveDaemon && currentIndex > 0 then
                    for index in currentIndex - 1 .. -1 .. 0 do
                        if objectRepairStateIndex repair current <> Some(index + 1)
                           || not (objectRuntimeNonSelectorsMatch environment repair.Before current) then
                            fail "Runtime selectors changed before their recorded scoped inverse."
                        let delta = repair.Deltas[index]
                        let runtimeDelta = { Field = delta.Field; Value = delta.Value; Effect = delta.Effect }
                        checkedCommand environment
                            (selectorArguments configuration runtimeDelta (if delta.Add then "remove" else "add"))
                        current <- inspect environment configuration
                        ensureCompleteSnapshot configuration current
                        if objectRepairStateIndex repair current <> Some index
                           || not (objectRuntimeNonSelectorsMatch environment repair.Before current) then
                            fail "firewalld did not restore the recorded scoped object checkpoint."
                if not (objectRuntimeNonSelectorsMatch environment repair.Before current)
                   || objectRepairStateIndex repair current <> Some 0 then
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
                if phase = FirewalldLifecycle.BootAfterFirewalld && currentIndex <> lastIndex then
                    fail "Post-boot firewalld did not load the staged permanent candidate; refusing an unproved inverse."
                observeAdjusted environment configuration current
                if currentIndex > 0 then
                    for index = currentIndex - 1 downto 0 do
                        if ownedFingerprintForRepair environment configuration repair current <> states[index + 1] then
                            fail "Runtime selector membership changed before its recorded inverse."
                        checkedCommand environment (selectorArguments configuration repair.Deltas[index] "remove")
                        current <- inspect environment configuration
                        ensureCompleteSnapshot configuration current
                        if ownedFingerprintForRepair environment configuration repair current <> states[index] then
                            fail "firewalld did not restore the recorded selector checkpoint."
                        observeAdjusted environment configuration current
            | _ -> fail "Invalid firewalld recovery strategy."
