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

    type private RuntimeRepair =
        { Deltas: RuntimeDelta list
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
        addStrings "sourcePorts" snapshot.SourcePorts
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

    let private elementAttribute key (element: FirewalldModel.Element) =
        Map.tryFind key element.Attributes

    let private directValues (configuration: FirewalldModel.Configuration) name key =
        configuration.Elements
        |> List.filter (fun element -> element.Name = name)
        |> List.choose (elementAttribute key)

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

    let private ownedFingerprint
        (configuration: FirewalldModel.Configuration)
        (snapshot: FirewalldRuntime.RuntimeSnapshot)
        =
        let expectedRich = expectedSelectorValues configuration |> Map.find "rich rules" |> Set.ofList
        let ownedRich =
            snapshot.RichRules
            |> List.filter (fun rule -> Set.contains rule expectedRich)
            |> sorted
        // Complete-snapshot checks validate NativeFields; step hashes use the canonical
        // typed projection rather than duplicate CLI formatting for those same values.
        fingerprint { snapshot with RichRules = ownedRich; NativeFields = Map.empty }

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
              "forward-ports", 4; "icmp-blocks", 5; "rich rules", 6 ]

    let private sortDeltas deltas =
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
        ensureCompleteSnapshot configuration currentSnapshot
        if fingerprint currentSnapshot <> fingerprint snapshot then
            fail "Runtime firewalld selectors changed while preparing the rollback proof."
        let permanentSnapshot =
            FirewalldRuntime.inspectPermanent environment configuration.Kind configuration.Name
            |> Option.defaultWith (fun () -> fail "Unable to observe the permanent firewalld object required for boot rollback proof.")
        ensureCompleteSnapshot configuration permanentSnapshot
        let permanentBefore =
            deltas |> List.fold (fun state delta -> applyDelta configuration state delta false) permanentSnapshot
        if ownedFingerprint configuration permanentBefore <> ownedFingerprint configuration snapshot then
            fail "Live owned selectors differ from their permanent preimage outside the reversible native deltas."
        let mutable state = snapshot
        let fingerprints = ResizeArray<string>()
        fingerprints.Add(ownedFingerprint configuration state)
        for delta in deltas do
            state <- applyDelta configuration state delta true
            fingerprints.Add(ownedFingerprint configuration state)
        { Deltas = deltas
          StateFingerprints = List.ofSeq fingerprints }

    let private proofBase (configuration: FirewalldModel.Configuration) (strategy: string) =
        let node = JsonObject()
        node["version"] <- JsonValue.Create 1
        node["scope"] <- JsonValue.Create "object"
        node["kind"] <- JsonValue.Create configuration.Kind
        node["name"] <- JsonValue.Create configuration.Name
        node["strategy"] <- JsonValue.Create strategy
        node

    let reloadProof
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (effectiveBefore: string option)
        (effectiveAfter: string option)
        =
        let node = proofBase configuration "reload-before"
        let diskBefore =
            match FirewalldRuntime.snapshotFromXml configuration.Kind configuration.Name effectiveBefore with
            | Error reason -> fail ("Cannot project the effective on-disk firewalld preimage: " + reason)
            | Ok None -> None
            | Ok(Some snapshot) when snapshotComplete snapshot -> Some snapshot
            | Ok(Some _) -> fail "The effective on-disk firewalld preimage has unknown native selectors."
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
            if not (snapshotsEqual disk permanent && snapshotsEqual disk live) then
                fail "The loaded firewalld selectors or permanent selectors differ from the exact effective on-disk preimage; refusing daemon-wide recovery by reload."
            node["beforePresent"] <- JsonValue.Create true
            node["beforeFingerprint"] <- JsonValue.Create(fingerprint live)
        | _ ->
            fail "The loaded firewalld target presence differs from the effective on-disk preimage; refusing daemon-wide recovery by reload."
        match FirewalldRuntime.snapshotFromXml configuration.Kind configuration.Name effectiveAfter with
        | Error reason -> fail ("Cannot project the post-transaction firewalld target: " + reason)
        | Ok None ->
            node["afterPresent"] <- JsonValue.Create false
            node["afterFingerprint"] <- null
        | Ok(Some after) when snapshotComplete after ->
            node["afterPresent"] <- JsonValue.Create true
            node["afterFingerprint"] <- JsonValue.Create(fingerprint after)
        | Ok(Some _) -> fail "The post-transaction firewalld target has unknown native selectors."
        node

    let unchangedProof (configuration: FirewalldModel.Configuration) =
        proofBase configuration "unchanged"

    let private effectName = function Grants -> "grant" | Restricts -> "restrict" | Steers -> "steer"

    let runtimeRepairProof
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (snapshot: FirewalldRuntime.RuntimeSnapshot)
        =
        let repair = planRuntimeRepair environment configuration snapshot
        let node = proofBase configuration "runtime-delta"
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
        node

    let private readProof (configuration: FirewalldModel.Configuration) (proof: JsonObject option) =
        let node = proof |> Option.defaultWith (fun () -> fail "Firewalld transaction has no native rollback proof.")
        let getString (key: string) =
            match node[key] with
            | null -> fail ("Missing firewalld rollback proof field " + key + ".")
            | value -> value.GetValue<string>()
        if isNull node["version"]
           || node["version"].GetValue<int>() <> 1
           || getString "scope" <> "object"
           || getString "kind" <> configuration.Kind
           || getString "name" <> configuration.Name then
            fail "Firewalld transaction rollback proof belongs to a different object or version."
        let strategy = getString "strategy"
        let expectedKeys =
            if strategy = "runtime-delta" then
                set [ "version"; "scope"; "kind"; "name"; "strategy"; "deltas"; "stateFingerprints" ]
            elif strategy = "reload-before" then
                set [ "version"; "scope"; "kind"; "name"; "strategy"; "beforePresent"; "beforeFingerprint"; "afterPresent"; "afterFingerprint" ]
            elif strategy = "unchanged" then
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
        if strategy = "reload-before" then
            validateProjection "before"
            validateProjection "after"
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
        let stateFingerprints = node["stateFingerprints"].AsArray() |> Seq.map (fun item -> item.GetValue<string>()) |> List.ofSeq
        { Deltas = deltas; StateFingerprints = stateFingerprints }

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
        match FirewalldRuntime.queryRuntime environment configuration.Kind configuration.Name with
        | Error reason -> fail ("Unable to observe the firewalld " + label + " target: " + reason)
        | Ok None -> not expectedPresent
        | Ok(Some snapshot) ->
            expectedPresent
            && snapshotComplete snapshot
            && fingerprint snapshot = proof[fingerprintKey].GetValue<string>()

    let private verifyEffectiveProjection
        (configuration: FirewalldModel.Configuration)
        (effectiveXml: string option)
        (proof: JsonObject)
        (label: string)
        =
        let expectedPresent = proof[label + "Present"].GetValue<bool>()
        match FirewalldRuntime.snapshotFromXml configuration.Kind configuration.Name effectiveXml with
        | Error reason -> fail ("Unable to project the effective on-disk firewalld " + label + " target: " + reason)
        | Ok None when not expectedPresent -> ()
        | Ok(Some snapshot)
            when expectedPresent
                 && snapshotComplete snapshot
                 && fingerprint snapshot = proof[label + "Fingerprint"].GetValue<string>() -> ()
        | _ -> fail ("Effective on-disk firewalld target differs from the recorded " + label + " preimage.")
    let private verifyTargetProjection environment configuration proof label =
        if not (targetProjectionMatches environment configuration proof label) then
            fail ("Loaded firewalld target differs from the recorded " + label + " projection.")

    let private selectorArguments (configuration: FirewalldModel.Configuration) (delta: RuntimeDelta) action =
        let selector = if configuration.Kind = "zone" then "--zone=" + configuration.Name else "--policy=" + configuration.Name
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
            | _ -> fail "Unsupported selector in firewalld rollback proof."
        [ selector; "--" + action + "-" + optionName + "=" + delta.Value ]

    let activateRuntimeRepair (environment: HostEnvironment) (configuration: FirewalldModel.Configuration) (proof: JsonObject) =
        let strategy, node = readProof configuration (Some proof)
        if strategy <> "runtime-delta" then fail "Expected a reversible runtime repair proof."
        let repair = decodeRuntimeRepair configuration node
        let stateIndex snapshot =
            let hash = ownedFingerprint configuration snapshot
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
                if ownedFingerprint configuration current <> repair.StateFingerprints[index] then
                    fail "Runtime selector membership changed before the next repair step."
                checkedCommand environment (selectorArguments configuration repair.Deltas[index] "add")
                current <- inspect environment configuration
                ensureCompleteSnapshot configuration current
                if ownedFingerprint configuration current <> repair.StateFingerprints[index + 1] then
                    fail "firewalld did not apply the recorded runtime selector step."
                observeAdjusted environment configuration current
        let observation = FirewalldRuntime.observe environment configuration
        if not observation.Observed || not observation.InSync then
            fail "The repaired firewalld object did not converge to its declared selectors."

    let restoreRuntime
        (environment: HostEnvironment)
        (configuration: FirewalldModel.Configuration)
        (effectiveCurrent: string option)
        (proof: JsonObject option)
        (phase: FirewalldLifecycle.RecoveryPhase)
        =
        let strategy, node = readProof configuration proof
        if strategy = "reload-before" then verifyEffectiveProjection configuration effectiveCurrent node "before"
        match phase with
        | FirewalldLifecycle.BootBeforeFirewalld -> ()
        | FirewalldLifecycle.ActiveDaemon | FirewalldLifecycle.BootAfterFirewalld ->
            match strategy with
            | "unchanged" -> ()
            | "reload-before" ->
                if phase = FirewalldLifecycle.ActiveDaemon then
                    if targetProjectionMatches environment configuration node "before" then ()
                    elif targetProjectionMatches environment configuration node "after" then
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
                else
                    verifyTargetProjection environment configuration node "before"
                    match FirewalldRuntime.validateReload environment with
                    | Ok () -> ()
                    | Error reason -> fail ("Post-boot runtime did not match the restored firewalld preimage: " + reason)
            | "runtime-delta" ->
                let repair = decodeRuntimeRepair configuration node
                let states = repair.StateFingerprints
                let lastIndex = repair.Deltas.Length
                let mutable current = inspect environment configuration
                ensureCompleteSnapshot configuration current
                let currentIndex =
                    ownedFingerprint configuration current
                    |> fun hash ->
                        states
                        |> List.tryFindIndex ((=) hash)
                        |> Option.defaultWith (fun () -> fail "Runtime owned selectors are outside the recorded repair checkpoints.")
                if phase = FirewalldLifecycle.BootAfterFirewalld && currentIndex <> lastIndex then
                    fail "Post-boot firewalld did not load the staged permanent candidate; refusing an unproved inverse."
                observeAdjusted environment configuration current
                if currentIndex > 0 then
                    for index = currentIndex - 1 downto 0 do
                        if ownedFingerprint configuration current <> states[index + 1] then
                            fail "Runtime selector membership changed before its recorded inverse."
                        checkedCommand environment (selectorArguments configuration repair.Deltas[index] "remove")
                        current <- inspect environment configuration
                        ensureCompleteSnapshot configuration current
                        if ownedFingerprint configuration current <> states[index] then
                            fail "firewalld did not restore the recorded selector checkpoint."
                        observeAdjusted environment configuration current
            | _ -> fail "Invalid firewalld recovery strategy."
