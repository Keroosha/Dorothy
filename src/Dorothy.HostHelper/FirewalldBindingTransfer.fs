namespace Dorothy.HostHelper

open System
open System.Globalization
open System.IO
open System.Net
open System.Net.Sockets
open System.Xml
open System.Xml.Linq

/// Checks native firewalld zones and policies only; it does not model arbitrary direct or external nftables rules.
/// Before an open fallback handoff, require confirmed priority -32768 ANY->HOST and ANY->ANY source/destination
/// drops, adding HOST->ANY destination drops only when host-egress policy restrictions can change.
module internal FirewalldBindingTransfer =
    let private xn name = XName.Get name
    let private attribute name (node: XElement) =
        match node.Attribute(xn name) with null -> None | value -> Some value.Value

    type private Network =
        { Address: IPAddress
          Prefix: int }

    type private SourceSelector =
        | Network of Network
        | IpSet of string
        | Mac of string
        | Unsupported of string

    type private SelectorSide =
        | SourceSide
        | DestinationSide

    type private RichDrop =
        { Selector: SourceSelector
          Side: SelectorSide
          Family: string option
          Priority: int }

    type private PolicyInfo =
        { Name: string
          Priority: int
          Ingress: string list
          Egress: string list
          Stage: (string * string * RichDrop list) option
          HostOutputRestrictive: bool }

    let private addressBits (address: IPAddress) =
        if address.AddressFamily = AddressFamily.InterNetwork then 32 else 128

    let private normalizeNetwork (address: IPAddress) prefix =
        let bytes = address.GetAddressBytes()
        for bit in prefix .. (bytes.Length * 8 - 1) do
            let index = bit / 8
            let bitMask = 1 <<< (7 - bit % 8)
            bytes[index] <- byte (int bytes[index] &&& (0xff ^^^ bitMask))
        { Address = IPAddress(bytes); Prefix = prefix }

    let private ipv4PrefixFromMask (mask: IPAddress) =
        if mask.AddressFamily <> AddressFamily.InterNetwork then None
        else
            let mutable prefix = 0
            let mutable zeroSeen = false
            let mutable contiguous = true
            for octet in mask.GetAddressBytes() do
                for bit in [ 7; 6; 5; 4; 3; 2; 1; 0 ] do
                    if (int octet &&& (1 <<< bit)) <> 0 then
                        if zeroSeen then contiguous <- false
                        prefix <- prefix + 1
                    else
                        zeroSeen <- true
            if contiguous then Some prefix else None

    let private parseNetwork (text: string) =
        if String.IsNullOrWhiteSpace text || text.Contains('%') then None
        else
            let parts = text.Split('/')
            if parts.Length > 2 then None
            else
                match IPAddress.TryParse parts[0] with
                | true, address ->
                    let bits = addressBits address
                    let prefix =
                        if parts.Length = 1 then Some bits
                        else
                            match Int32.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture) with
                            | true, value when value >= 0 && value <= bits -> Some value
                            | _ when address.AddressFamily = AddressFamily.InterNetwork && parts[1].Contains('.') ->
                                match IPAddress.TryParse parts[1] with
                                | true, mask -> ipv4PrefixFromMask mask
                                | _ -> None
                            | _ -> None
                    prefix |> Option.map (normalizeNetwork address)
                | _ -> None

    let private networkContains (outer: Network) (inner: Network) =
        if outer.Address.AddressFamily <> inner.Address.AddressFamily || outer.Prefix > inner.Prefix then false
        else
            let outerBytes, innerBytes = outer.Address.GetAddressBytes(), inner.Address.GetAddressBytes()
            let wholeBytes, remainingBits = outer.Prefix / 8, outer.Prefix % 8
            let wholeEqual =
                let mutable equal = true
                let mutable index = 0
                while equal && index < wholeBytes do
                    equal <- outerBytes[index] = innerBytes[index]
                    index <- index + 1
                equal
            let partialEqual =
                if remainingBits = 0 then true
                else
                    let mask = (0xff <<< (8 - remainingBits)) &&& 0xff
                    (int outerBytes[wholeBytes] &&& mask) = (int innerBytes[wholeBytes] &&& mask)
            wholeEqual && partialEqual

    let private networkOverlaps left right = networkContains left right || networkContains right left

    let private rightChild (network: Network) =
        let bytes = network.Address.GetAddressBytes()
        let bit = network.Prefix
        let index = bit / 8
        let mask = 1 <<< (7 - bit % 8)
        bytes[index] <- byte (int bytes[index] ||| mask)
        { Address = IPAddress(bytes); Prefix = bit + 1 }

    let private networksCover (covering: Network list) target =
        let rec covered (candidate: Network) =
            if covering |> List.exists (fun network -> networkContains network candidate) then true
            elif not (covering |> List.exists (fun network -> networkContains candidate network)) then false
            elif candidate.Prefix = addressBits candidate.Address then false
            else
                let left = { candidate with Prefix = candidate.Prefix + 1 }
                covered left && covered (rightChild candidate)
        covered target

    let private isMacAddress (value: string) =
        let parts = value.Split(':')
        parts.Length = 6 && (parts |> Array.forall (fun part -> part.Length = 2 && (part |> Seq.forall Uri.IsHexDigit)))
    let private canonicalMac (value: string) =
        value.ToLowerInvariant()

    let private selectorFromAttributes (attributes: Map<string, string>) =
        match Map.tryFind "address" attributes, Map.tryFind "ipset" attributes, Map.tryFind "mac" attributes with
        | Some address, None, None ->
            match parseNetwork address with
            | Some network -> Network network
            | None when isMacAddress address -> Mac(canonicalMac address)
            | None -> Unsupported("address=" + address)
        | None, Some name, None when not (String.IsNullOrWhiteSpace name) -> IpSet name
        | None, None, Some mac when isMacAddress mac -> Mac(canonicalMac mac)
        | _ -> Unsupported "unrecognized source selector"

    let private selectorFromElement (source: XElement) =
        source.Attributes()
        |> Seq.map (fun item -> item.Name.LocalName, item.Value)
        |> Map.ofSeq
        |> selectorFromAttributes


    let private sameNetwork left right = networkContains left right && networkContains right left

    let private sameSelector left right =
        match left, right with
        | Network first, Network second -> sameNetwork first second
        | IpSet first, IpSet second -> String.Equals(first, second, StringComparison.Ordinal)
        | Mac first, Mac second -> String.Equals(first, second, StringComparison.OrdinalIgnoreCase)
        | Unsupported first, Unsupported second -> String.Equals(first, second, StringComparison.Ordinal)
        | _ -> false

    let private selectorCovers covering target =
        match covering, target with
        | Network first, Network second -> networkContains first second
        | IpSet first, IpSet second -> String.Equals(first, second, StringComparison.Ordinal)
        | Mac first, Mac second -> String.Equals(first, second, StringComparison.OrdinalIgnoreCase)
        | Unsupported first, Unsupported second -> String.Equals(first, second, StringComparison.Ordinal)
        | _ -> false

    let private selectorFullyCoveredBy covering target =
        match target with
        | Network network ->
            covering
            |> List.choose (function Network candidate -> Some candidate | _ -> None)
            |> fun networks -> networksCover networks network
        | _ -> covering |> List.exists (fun candidate -> selectorCovers candidate target)

    let private selectorMayOverlap left right =
        match left, right with
        | Network first, Network second -> networkOverlaps first second
        | Mac first, Mac second -> String.Equals(first, second, StringComparison.OrdinalIgnoreCase)
        | _ -> true

    let private displaySelector = function
        | Network network -> network.Address.ToString() + "/" + string network.Prefix
        | IpSet name -> "ipset " + name
        | Mac value -> "MAC " + value
        | Unsupported text -> text

    let private parseRoot kind (text: string) =
        try
            let settings = XmlReaderSettings()
            settings.DtdProcessing <- DtdProcessing.Prohibit
            settings.XmlResolver <- null
            use input = new StringReader(text)
            use reader = XmlReader.Create(input, settings)
            let document = XDocument.Load reader
            let root = document.Root
            if isNull root then Error "missing XML root"
            elif root.Name <> xn kind then Error "unexpected XML root"
            else Ok root
        with _ -> Error "invalid XML"

    let private sourceSelectorsFromXml (text: string) =
        parseRoot "zone" text
        |> Result.map (fun root -> root.Elements(xn "source") |> Seq.map selectorFromElement |> Seq.toList)

    let private distinctSelectors selectors =
        let mutable result = []
        for selector in selectors do
            if not (result |> List.exists (sameSelector selector)) then result <- selector :: result
        List.rev result

    let private removedSelectors name (beforeZone: string option) (runtimeZones: Map<string, string>) (afterZones: Map<string, string>) =
        let previousZones =
            [ beforeZone; Map.tryFind name runtimeZones ]
            |> List.choose id
        let previousSelectors =
            previousZones
            |> List.fold (fun state xml ->
                match state, sourceSelectorsFromXml xml with
                | Error reason, _ | _, Error reason -> Error reason
                | Ok accumulated, Ok selectors -> Ok(accumulated @ selectors)) (Ok [])
        let nextSelectors =
            Map.tryFind name afterZones
            |> Option.map sourceSelectorsFromXml
            |> Option.defaultValue (Ok [])
        match previousSelectors, nextSelectors with
        | Error reason, _ | _, Error reason -> Error("Cannot inspect source bindings in zone " + name + ": " + reason + ".")
        | Ok oldSelectors, Ok newSelectors ->
            oldSelectors
            |> List.filter (fun old -> not (selectorFullyCoveredBy newSelectors old))
            |> distinctSelectors
            |> Ok
    let private richFamilyValid side selector family =
        match side, selector, family with
        | _, Network _, None -> true
        | _, Network network, Some "ipv4" -> network.Address.AddressFamily = AddressFamily.InterNetwork
        | _, Network network, Some "ipv6" -> network.Address.AddressFamily = AddressFamily.InterNetworkV6
        | SourceSide, (IpSet _ | Mac _), None
        | DestinationSide, IpSet _, None -> true
        | _ -> false

    let private richDropFromXml (rule: XElement) =
        let allowedRuleAttributes = set [ "family"; "priority" ]
        let ruleAttributes = rule.Attributes() |> Seq.map (fun item -> item.Name.LocalName) |> Set.ofSeq
        let priority =
            match attribute "priority" rule with
            | None -> Some 0
            | Some value ->
                match Int32.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture) with
                | true, number when number >= -32768 && number <= 32767 -> Some number
                | _ -> None
        let family = attribute "family" rule
        let validFamily = family |> Option.forall (fun value -> value = "ipv4" || value = "ipv6")
        let children = rule.Elements() |> Seq.toArray
        let selectorNode =
            if children.Length = 2 && children[1].Name = xn "drop" then
                match children[0].Name with
                | name when name = xn "source" -> Some(children[0], SourceSide)
                | name when name = xn "destination" -> Some(children[0], DestinationSide)
                | _ -> None
            else None
        match priority, selectorNode with
        | Some number, Some(source, side)
            when ruleAttributes.IsSubsetOf allowedRuleAttributes
                 && validFamily
                 && String.IsNullOrWhiteSpace rule.Value
                 && not children[1].HasAttributes
                 && String.IsNullOrWhiteSpace children[1].Value
                 && (children[1].Elements() |> Seq.isEmpty) ->
            let sourceAttributes = source.Attributes() |> Seq.map (fun item -> item.Name.LocalName) |> Set.ofSeq
            let selector = selectorFromElement source
            let selectorAttributeMatches =
                match side, selector with
                | _, Network _ -> sourceAttributes = set [ "address" ]
                | _, IpSet _ -> sourceAttributes = set [ "ipset" ]
                | SourceSide, Mac _ -> sourceAttributes = set [ "mac" ]
                | _ -> false
            if selectorAttributeMatches
               && String.IsNullOrWhiteSpace source.Value
               && (source.Elements() |> Seq.isEmpty)
               && richFamilyValid side selector family then
                Some { Selector = selector; Side = side; Family = family; Priority = number }
            else None
        | _ -> None

    let private expectedStageSides ingress egress =
        match ingress, egress with
        | "ANY", "HOST" -> Some [ SourceSide ]
        | "ANY", "ANY" -> Some [ SourceSide; DestinationSide ]
        | "HOST", "ANY" -> Some [ DestinationSide ]
        | _ -> None

    let private stagePolicyFromXml name (text: string) =
        match parseRoot "policy" text with
        | Error _ -> None
        | Ok root ->
            let rootAttributes = root.Attributes() |> Seq.map (fun item -> item.Name.LocalName) |> Set.ofSeq
            let children = root.Elements() |> Seq.toArray
            let ingressNodes = children |> Array.filter (fun node -> node.Name = xn "ingress-zone")
            let egressNodes = children |> Array.filter (fun node -> node.Name = xn "egress-zone")
            let rules = children |> Array.filter (fun node -> node.Name = xn "rule")
            let descriptions = children |> Array.filter (fun node -> node.Name = xn "short" || node.Name = xn "description")
            let priority =
                match attribute "priority" root with
                | Some value ->
                    match Int32.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture) with
                    | true, number -> Some number
                    | _ -> None
                | None -> Some -1
            let target = attribute "target" root |> Option.defaultValue "CONTINUE"
            let stageChildren = [ xn "ingress-zone"; xn "egress-zone"; xn "rule"; xn "short"; xn "description" ]
            let shortCount = descriptions |> Array.filter (fun node -> node.Name = xn "short") |> Array.length
            let descriptionCount = descriptions |> Array.filter (fun node -> node.Name = xn "description") |> Array.length
            let onlyStageChildren =
                (children |> Array.forall (fun node -> List.contains node.Name stageChildren))
                && shortCount <= 1
                && descriptionCount <= 1
            let noRootText =
                root.Nodes()
                |> Seq.forall (function :? XText as textNode -> String.IsNullOrWhiteSpace textNode.Value | _ -> true)
            let descriptionsAreTextOnly =
                descriptions |> Array.forall (fun node -> not node.HasAttributes && (node.Elements() |> Seq.isEmpty))
            match priority, ingressNodes, egressNodes with
            | Some value, [| ingress |], [| egress |]
                when value = -32768
                     && rootAttributes.IsSubsetOf(set [ "priority"; "target"; "version" ])
                     && target = "CONTINUE"
                     && noRootText
                     && onlyStageChildren
                     && descriptionsAreTextOnly
                     && children.Length = 2 + rules.Length + descriptions.Length
                     && (ingress.Attributes() |> Seq.map (fun item -> item.Name.LocalName) |> Set.ofSeq) = set [ "name" ]
                     && (egress.Attributes() |> Seq.map (fun item -> item.Name.LocalName) |> Set.ofSeq) = set [ "name" ]
                     && String.IsNullOrWhiteSpace ingress.Value
                     && String.IsNullOrWhiteSpace egress.Value
                     && (ingress.Elements() |> Seq.isEmpty)
                     && (egress.Elements() |> Seq.isEmpty) ->
                let ingressName = attribute "name" ingress |> Option.defaultValue ""
                let egressName = attribute "name" egress |> Option.defaultValue ""
                match expectedStageSides ingressName egressName with
                | None -> None
                | Some expectedSides when rules.Length = expectedSides.Length ->
                    let richDrops = rules |> Array.choose (fun rule -> if rule.Name = xn "rule" then richDropFromXml rule else None)
                    let actualSides = richDrops |> Array.map (fun rule -> rule.Side) |> Set.ofArray
                    if richDrops.Length = rules.Length && actualSides = Set.ofList expectedSides then
                        let ruleList = Array.toList richDrops
                        Some
                            { Name = name
                              Priority = -32768
                              Ingress = [ ingressName ]
                              Egress = [ egressName ]
                              Stage = Some(ingressName, egressName, ruleList)
                              HostOutputRestrictive = ingressName = "HOST" }
                    else None
                | Some _ -> None
            | _ -> None

    let private isOutputRestrictive (root: XElement) =
        let ingress = root.Elements(xn "ingress-zone") |> Seq.choose (attribute "name") |> Seq.toList
        let egress = root.Elements(xn "egress-zone") |> Seq.choose (attribute "name") |> Seq.toList
        let disabled = root.Elements(xn "disable") |> Seq.isEmpty |> not
        let affectsHostOutput =
            not disabled
            && List.contains "HOST" ingress
            && (egress |> List.exists ((<>) "HOST"))
        if not affectsHostOutput then false
        else
            let target = attribute "target" root |> Option.defaultValue "CONTINUE"
            let rootAttributes = root.Attributes() |> Seq.map (fun item -> item.Name.LocalName) |> Set.ofSeq
            let knownRootAttributes = set [ "version"; "target"; "priority" ]
            let knownChildren =
                set [ "disable"; "ingress-zone"; "egress-zone"; "short"; "description"; "service"; "port"
                      "protocol"; "icmp-block"; "masquerade"; "forward-port"; "source-port"; "rule" ]
            let unknownChildren = root.Elements() |> Seq.exists (fun node -> not (Set.contains node.Name.LocalName knownChildren))
            let ruleCanRestrict (rule: XElement) =
                let children = rule.DescendantsAndSelf() |> Seq.map (fun node -> node.Name.LocalName) |> Set.ofSeq
                let knownRuleParts =
                    set [ "rule"; "source"; "destination"; "service"; "port"; "protocol"; "icmp-block"; "icmp-type"
                          "masquerade"; "forward-port"; "source-port"; "log"; "nflog"; "audit"; "accept"; "reject"
                          "drop"; "mark"; "limit" ]
                not (children.IsSubsetOf knownRuleParts)
                || children.Contains "drop" || children.Contains "reject" || children.Contains "mark"
                || children.Contains "icmp-block" || children.Contains "icmp-type" || children.Contains "forward-port"
                || children.Contains "masquerade"
            let unknownRuleAttributes =
                root.Elements(xn "rule")
                |> Seq.exists (fun rule ->
                    let attributes = rule.Attributes() |> Seq.map (fun item -> item.Name.LocalName) |> Set.ofSeq
                    not (attributes.IsSubsetOf(set [ "family"; "priority" ])))
            target = "DROP" || target = "REJECT" || (target <> "CONTINUE" && target <> "ACCEPT")
            || not (rootAttributes.IsSubsetOf knownRootAttributes)
            || unknownChildren || unknownRuleAttributes
            || not (root.Elements(xn "icmp-block") |> Seq.isEmpty)
            || not (root.Elements(xn "masquerade") |> Seq.isEmpty)
            || not (root.Elements(xn "forward-port") |> Seq.isEmpty)
            || not (root.Elements(xn "icmp-block-inversion") |> Seq.isEmpty)
            || (root.Elements(xn "rule") |> Seq.exists ruleCanRestrict)

    let private policyInfoFromXml name (text: string) =
        match parseRoot "policy" text with
        | Error reason -> Error("Cannot inspect firewalld policy " + name + ": " + reason + ".")
        | Ok root ->
            let priority =
                match attribute "priority" root with
                | None -> Some -1
                | Some value ->
                    match Int32.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture) with
                    | true, number when number >= -32768 && number <= 32767 && number <> 0 -> Some number
                    | _ -> None
            let disabled = root.Elements(xn "disable") |> Seq.isEmpty |> not
            let ingress = if disabled then [] else root.Elements(xn "ingress-zone") |> Seq.choose (attribute "name") |> Seq.toList
            let egress = if disabled then [] else root.Elements(xn "egress-zone") |> Seq.choose (attribute "name") |> Seq.toList
            match priority with
            | Some number ->
                Ok
                    { Name = name
                      Priority = number
                      Ingress = ingress
                      Egress = egress
                      Stage = stagePolicyFromXml name text |> Option.bind (fun stage -> stage.Stage)
                      HostOutputRestrictive = isOutputRestrictive root }
            | _ -> Error("Cannot prove the priority of firewalld policy " + name + ".")

    let private ruleSideProvesDisjoint side (moving: SourceSelector) (rule: XElement) =
        let familyDisjoint =
            match moving, attribute "family" rule with
            | Network network, Some "ipv4" -> network.Address.AddressFamily <> AddressFamily.InterNetwork
            | Network network, Some "ipv6" -> network.Address.AddressFamily <> AddressFamily.InterNetworkV6
            | _, Some family when family <> "ipv4" && family <> "ipv6" -> false
            | _ -> false
        if familyDisjoint then true
        else
            let selectorName = if side = SourceSide then "source" else "destination"
            match rule.Elements(xn selectorName) |> Seq.toArray with
            | [| selectorNode |] ->
                let attributes = selectorNode.Attributes() |> Seq.map (fun item -> item.Name.LocalName, item.Value) |> Map.ofSeq
                let selectorAttributes = attributes |> Map.filter (fun name _ -> name = "address" || name = "ipset" || name = "mac")
                let knownAttributes = set [ "address"; "ipset"; "mac"; "invert" ]
                let attributesKnown = attributes |> Map.forall (fun name _ -> Set.contains name knownAttributes)
                let invert =
                    match Map.tryFind "invert" attributes with
                    | None -> Some false
                    | Some value when value.Equals("true", StringComparison.OrdinalIgnoreCase) || value.Equals("yes", StringComparison.OrdinalIgnoreCase) -> Some true
                    | Some value when value.Equals("false", StringComparison.OrdinalIgnoreCase) || value.Equals("no", StringComparison.OrdinalIgnoreCase) -> Some false
                    | _ -> None
                if not attributesKnown
                   || selectorAttributes.Count <> 1
                   || not (selectorNode.Elements() |> Seq.isEmpty)
                   || not (String.IsNullOrWhiteSpace selectorNode.Value) then false
                else
                    let ruleSelector = selectorFromAttributes selectorAttributes
                    match ruleSelector, invert with
                    | Unsupported _, _ -> false
                    | _, None -> false
                    | ruleSelector, Some true -> selectorCovers ruleSelector moving
                    | ruleSelector, Some false -> not (selectorMayOverlap ruleSelector moving)
            | _ -> false

    let private richRuleHasPreRoutingChange side moving (rule: XElement) =
        let changes =
            rule.DescendantsAndSelf()
            |> Seq.exists (fun node -> Set.contains node.Name.LocalName (set [ "forward-port"; "masquerade"; "mark" ]))
        changes && not (ruleSideProvesDisjoint side moving rule)

    let private zoneHasPreRoutingChange (moving: SourceSelector) (text: string) =
        match parseRoot "zone" text with
        | Error _ -> true
        | Ok root ->
            not (root.Elements(xn "forward-port") |> Seq.isEmpty)
            || not (root.Elements(xn "masquerade") |> Seq.isEmpty)
            || (root.Elements(xn "rule") |> Seq.exists (richRuleHasPreRoutingChange SourceSide moving))

    let private policyHasPreRoutingChange side (moving: SourceSelector) (text: string) =
        match parseRoot "policy" text with
        | Error _ -> true
        | Ok root ->
            not (root.Elements(xn "forward-port") |> Seq.isEmpty)
            || not (root.Elements(xn "masquerade") |> Seq.isEmpty)
            || (root.Elements(xn "rule") |> Seq.exists (richRuleHasPreRoutingChange side moving))

    let private sameRichDrop (left: RichDrop) (right: RichDrop) =
        left.Priority = right.Priority
        && left.Side = right.Side
        && left.Family = right.Family
        && sameSelector left.Selector right.Selector

    let private sameRichDrops (left: RichDrop list) (right: RichDrop list) =
        left.Length = right.Length
        && (left |> List.forall (fun expected -> right |> List.exists (sameRichDrop expected)))

    let private stageMatchesRuntime (expected: string * string * RichDrop list) (runtime: PolicyInfo) =
        let expectedIngress, expectedEgress, expectedRules = expected
        runtime.Priority = -32768
        && runtime.Ingress = [ expectedIngress ]
        && runtime.Egress = [ expectedEgress ]
        && (runtime.Stage
            |> Option.exists (fun (actualIngress, actualEgress, actualRules) ->
                actualIngress = expectedIngress
                && actualEgress = expectedEgress
                && sameRichDrops actualRules expectedRules))

    let private candidateStagesFor selector ingress egress (candidatePolicies: (string * PolicyInfo) list) (runtimePolicies: Map<string, PolicyInfo>) =
        candidatePolicies
        |> List.choose (fun (name, info) ->
            match info.Stage, Map.tryFind name runtimePolicies with
            | Some ((stageIngress, stageEgress, rules) as stage), Some runtime
                when stageIngress = ingress
                     && stageEgress = egress
                     && (rules |> List.forall (fun rule ->
                         selectorCovers rule.Selector selector && richFamilyValid rule.Side rule.Selector rule.Family))
                     && stageMatchesRuntime stage runtime -> Some name
            | _ -> None)
        |> Set.ofList

    let private policyCanIngress (fallbackZones: Set<string>) (policy: PolicyInfo) =
        not policy.Egress.IsEmpty
        && (policy.Ingress |> List.exists (fun zone -> zone = "ANY" || Set.contains zone fallbackZones))

    let private policyMayAffectHost (policy: PolicyInfo) =
        policy.Egress |> List.contains "HOST"

    let private policyMayAffectTransit (policy: PolicyInfo) =
        policy.Egress |> List.exists ((<>) "HOST")

    let private candidatePolicyTiesAreSafe egress (safeStages: Set<string>) fallbackZones (policies: (string * PolicyInfo) list) =
        policies
        |> List.forall (fun (name, policy) ->
            if policy.Priority <> -32768 || not (policyCanIngress fallbackZones policy) then true
            else
                let mayAffect = if egress = "HOST" then policyMayAffectHost policy else policyMayAffectTransit policy
                not mayAffect || Set.contains name safeStages)

    let private runtimePolicyTiesAreSafe egress (safeStages: Set<string>) fallbackZones (policies: (string * PolicyInfo) list) =
        policies
        |> List.forall (fun (name, policy) ->
            if policy.Priority <> -32768 || not (policyCanIngress fallbackZones policy) then true
            else
                let mayAffect = if egress = "HOST" then policyMayAffectHost policy else policyMayAffectTransit policy
                not mayAffect || Set.contains name safeStages)

    let private policyMayOutputTo egressZones (policy: PolicyInfo) =
        List.contains "HOST" policy.Ingress
        && not policy.Egress.IsEmpty
        && (policy.Egress |> List.exists (fun zone -> zone = "ANY" || Set.contains zone egressZones))

    let private policyOutputClassificationDepends egressZones (policy: PolicyInfo) =
        List.contains "HOST" policy.Ingress
        && not policy.Egress.IsEmpty
        && not (List.contains "ANY" policy.Egress)
        && (policy.Egress |> List.exists (fun zone -> Set.contains zone egressZones))

    let private outputPolicyTiesAreSafe (safeStages: Set<string>) egressZones (policies: (string * PolicyInfo) list) =
        policies
        |> List.forall (fun (name, policy) ->
            if policy.Priority <> -32768 || not (policyMayOutputTo egressZones policy) then true
            else Set.contains name safeStages)

    let private hasUnsafePreRoutingChange sourceZone removed fallbackZones candidateZones runtimeZones candidatePolicies runtimePolicies candidatePolicyXml runtimePolicyXml =
        let zoneUnsafe zones =
            fallbackZones
            |> Set.exists (fun name ->
                name <> sourceZone
                && (Map.tryFind name zones
                    |> Option.exists (fun xml ->
                        removed |> List.exists (fun selector -> zoneHasPreRoutingChange selector xml))))
        let policyUnsafe side canMatch policies definitions =
            policies
            |> List.exists (fun (name, policy) ->
                if not (canMatch policy) then false
                else
                    match Map.tryFind name definitions with
                    | Some xml -> removed |> List.exists (fun selector -> policyHasPreRoutingChange side selector xml)
                    | None -> true)
        let inputPolicyCanStart policy =
            policyCanIngress fallbackZones policy
            && not (policy.Priority < 0 && (List.contains "ANY" policy.Ingress || List.contains sourceZone policy.Ingress))
        let egressPolicyCanStart policy =
            let ingressCanApply = policyCanIngress fallbackZones policy
            let specificFallbackEgress =
                policy.Egress
                |> List.exists (fun zone -> zone <> sourceZone && Set.contains zone fallbackZones)
            let lateAnyEgress = List.contains "ANY" policy.Egress && policy.Priority > 0 && ingressCanApply
            ingressCanApply && (specificFallbackEgress || lateAnyEgress)
        let outputPolicyCanStart policy = policyOutputClassificationDepends fallbackZones policy
        let inputPolicyUnsafe policies definitions = policyUnsafe SourceSide inputPolicyCanStart policies definitions
        let egressPolicyUnsafe policies definitions = policyUnsafe DestinationSide egressPolicyCanStart policies definitions
        let outputPolicyUnsafe policies definitions = policyUnsafe DestinationSide outputPolicyCanStart policies definitions
        zoneUnsafe candidateZones
        || zoneUnsafe runtimeZones
        || inputPolicyUnsafe candidatePolicies candidatePolicyXml
        || inputPolicyUnsafe runtimePolicies runtimePolicyXml
        || egressPolicyUnsafe candidatePolicies candidatePolicyXml
        || egressPolicyUnsafe runtimePolicies runtimePolicyXml
        || outputPolicyUnsafe candidatePolicies candidatePolicyXml
        || outputPolicyUnsafe runtimePolicies runtimePolicyXml

    let private candidateZoneInterfaces (text: string) =
        parseRoot "zone" text
        |> Result.map (fun root -> root.Elements(xn "interface") |> Seq.isEmpty |> not)

    let private possibleFallbackZones removingZone defaultZones removed (candidateZones: Map<string, string>) (runtimeZones: Map<string, string>) =
        let mutable names = Set.ofList defaultZones
        let mutable error = None
        let addZones (zones: Map<string, string>) isRuntime =
            for KeyValue(name, xml) in zones do
                if error.IsNone then
                    match candidateZoneInterfaces xml, sourceSelectorsFromXml xml with
                    | Error reason, _ | _, Error reason ->
                        error <- Some("Cannot inspect fallback zone " + name + ": " + reason + ".")
                    | Ok hasInterface, Ok selectors ->
                        let mayMatch =
                            selectors
                            |> List.exists (fun selector ->
                                removed
                                |> List.exists (fun old ->
                                    // The old binding disappears with this reload; other runtime source matches may remain.
                                    (not isRuntime || name <> removingZone || not (sameSelector old selector))
                                    && selectorMayOverlap selector old))
                        if hasInterface || mayMatch then names <- Set.add name names
        addZones candidateZones false
        addZones runtimeZones true
        match error with Some reason -> Error reason | None -> Ok names

    let private zoneIsBlanketDropXml (text: string) =
        match parseRoot "zone" text with
        | Error _ -> false
        | Ok root ->
            let attributes = root.Attributes() |> Seq.map (fun item -> item.Name.LocalName) |> Set.ofSeq
            let target = attribute "target" root |> Option.defaultValue "default"
            let allowedChildren = set [ "interface"; "source"; "short"; "description"; "icmp-block" ]
            let safeChild = root.Elements() |> Seq.forall (fun child -> Set.contains child.Name.LocalName allowedChildren)
            let inversion = root.Elements(xn "icmp-block-inversion") |> Seq.isEmpty |> not
            attributes.IsSubsetOf(set [ "target"; "version"; "ingress-priority"; "egress-priority" ])
            && (target = "DROP" || target = "%%REJECT%%")
            && safeChild && not inversion

    let private policyMayIngressFallback fallbackZones (policy: PolicyInfo) = policyCanIngress fallbackZones policy

    let private fallbackIsRestrictive fallbackZones (candidateZones: Map<string, string>) runtimeZones candidatePolicies runtimePolicies =
        let zonesAreDenied =
            fallbackZones
            |> Set.forall (fun name ->
                match Map.tryFind name candidateZones, Map.tryFind name runtimeZones with
                | Some permanent, Some runtime -> zoneIsBlanketDropXml permanent && zoneIsBlanketDropXml runtime
                | _ -> false)
        let noPermanentPolicy = candidatePolicies |> List.forall (fun (_, policy) -> not (policyMayIngressFallback fallbackZones policy))
        let noRuntimePolicy = runtimePolicies |> List.forall (fun (_, policy) -> not (policyMayIngressFallback fallbackZones policy))
        zonesAreDenied && noPermanentPolicy && noRuntimePolicy

    let private zoneIsUnrestricted (text: string) =
        match parseRoot "zone" text with
        | Error _ -> false
        | Ok root ->
            let attributes = root.Attributes() |> Seq.map (fun item -> item.Name.LocalName) |> Set.ofSeq
            let target = attribute "target" root |> Option.defaultValue "default"
            let allowedChildren = set [ "interface"; "source"; "short"; "description" ]
            attributes.IsSubsetOf(set [ "target"; "version"; "ingress-priority"; "egress-priority" ])
            && target = "ACCEPT"
            && (root.Elements() |> Seq.forall (fun child -> Set.contains child.Name.LocalName allowedChildren))

    let private noPolicyFromZone zoneName (policies: (string * PolicyInfo) list) =
        policies
        |> List.forall (fun (_, policy) ->
            policy.Egress.IsEmpty
            || not (policy.Ingress |> List.exists (fun ingress -> ingress = "ANY" || ingress = zoneName)))

    let private hostOutputFenceRequired oldZone fallbackZones policies =
        let egressZones = Set.add oldZone fallbackZones
        policies
        |> List.exists (fun (_, policy) -> policy.HostOutputRestrictive && policyOutputClassificationDepends egressZones policy)
    let private validateZoneSourceBinding
        (configuration: FirewalldModel.Configuration)
        (beforeZone: string option)
        (afterZones: Map<string, string>)
        (candidatePolicyXml: Map<string, string>)
        (candidateDefaultZone: string)
        (runtimeDefaultZone: string)
        (runtimeZones: Map<string, string>)
        (runtimePolicyXml: Map<string, string>)
        =
        if configuration.Kind <> "zone" then Ok ()
        else
            match removedSelectors configuration.Name beforeZone runtimeZones afterZones with
            | Error reason -> Error reason
            | Ok [] -> Ok ()
            | Ok removed ->
                let readPolicies (sources: Map<string, string>) =
                    sources
                    |> Map.toList
                    |> List.map (fun (name, xml) -> policyInfoFromXml name xml)
                let candidatePolicyInfos = readPolicies candidatePolicyXml
                let runtimePolicyInfos = readPolicies runtimePolicyXml
                let invalidPolicy =
                    candidatePolicyInfos @ runtimePolicyInfos
                    |> List.tryPick (function Error reason -> Some reason | _ -> None)
                match invalidPolicy with
                | Some reason -> Error reason
                | None ->
                    let candidatePolicies = candidatePolicyInfos |> List.choose (function Ok info -> Some(info.Name, info) | _ -> None)
                    let runtimePolicies = runtimePolicyInfos |> List.choose (function Ok info -> Some(info.Name, info) | _ -> None)
                    let runtimePolicyMap = Map.ofList runtimePolicies
                    match possibleFallbackZones configuration.Name [ candidateDefaultZone; runtimeDefaultZone ] removed afterZones runtimeZones with
                    | Error reason -> Error reason
                    | Ok fallbackZones ->
                        let sameDefaultZone =
                            candidateDefaultZone = configuration.Name
                            && runtimeDefaultZone = configuration.Name
                            && fallbackZones = Set.singleton configuration.Name
                        if sameDefaultZone then Ok ()
                        elif hasUnsafePreRoutingChange configuration.Name removed fallbackZones afterZones runtimeZones candidatePolicies runtimePolicies candidatePolicyXml runtimePolicyXml then
                            Error(
                                "Refusing to remove firewalld source binding: a fallback zone or policy can activate a matching forward-port, masquerade, or mark before normal filter dispatch. Detach or quarantine that native translation in a separately confirmed phase; filter DROP policies cannot undo it.")
                        else
                            let outputFenceRequired =
                                hostOutputFenceRequired configuration.Name fallbackZones (candidatePolicies @ runtimePolicies)
                            let sourceZoneUnrestricted =
                                not outputFenceRequired
                                && (beforeZone
                                    |> Option.exists (fun xml -> zoneIsUnrestricted xml
                                                                && noPolicyFromZone configuration.Name candidatePolicies
                                                                && noPolicyFromZone configuration.Name runtimePolicies))
                            let fallbackIsSafe =
                                not outputFenceRequired
                                && fallbackIsRestrictive fallbackZones afterZones runtimeZones candidatePolicies runtimePolicies
                            if sourceZoneUnrestricted || fallbackIsSafe then Ok ()
                            else
                                let mutable allStaged = true
                                let outputEgressZones = Set.add configuration.Name fallbackZones
                                for selector in removed do
                                    let hostStages = candidateStagesFor selector "ANY" "HOST" candidatePolicies runtimePolicyMap
                                    let transitStages = candidateStagesFor selector "ANY" "ANY" candidatePolicies runtimePolicyMap
                                    let hostSafe =
                                        not hostStages.IsEmpty
                                        && candidatePolicyTiesAreSafe "HOST" hostStages fallbackZones candidatePolicies
                                        && runtimePolicyTiesAreSafe "HOST" hostStages fallbackZones runtimePolicies
                                    let transitSafe =
                                        not transitStages.IsEmpty
                                        && candidatePolicyTiesAreSafe "ANY" transitStages fallbackZones candidatePolicies
                                        && runtimePolicyTiesAreSafe "ANY" transitStages fallbackZones runtimePolicies
                                    let outputSafe =
                                        if not outputFenceRequired then true
                                        else
                                            let outputStages = candidateStagesFor selector "HOST" "ANY" candidatePolicies runtimePolicyMap
                                            not outputStages.IsEmpty
                                            && outputPolicyTiesAreSafe outputStages outputEgressZones candidatePolicies
                                            && outputPolicyTiesAreSafe outputStages outputEgressZones runtimePolicies
                                    if not hostSafe || not transitSafe || not outputSafe then allStaged <- false
                                if allStaged then Ok ()
                                else
                                    let selectors = removed |> List.map displaySelector |> String.concat ", "
                                    let outputGuidance =
                                        if outputFenceRequired then " and a destination-only priority -32768 DROP policy for HOST to ANY"
                                        else ""
                                    Error(
                                        "Refusing to remove firewalld source binding " + selectors
                                        + ": the confirmed fallback is not proven restrictive. First apply and confirm a priority -32768 source-only DROP policy for ANY to HOST, a priority -32768 ANY to ANY policy with both source and destination DROP rules"
                                        + outputGuidance
                                        + ", then remove the old binding, bind the destination zone, and delete the staging policies; conflicting minimum-priority policies must be resolved first.")
    let private collectZoneSourceSelectors (zones: Map<string, string>) =
        zones
        |> Map.toList
        |> List.fold (fun state (_, xml) ->
            match state, sourceSelectorsFromXml xml with
            | Error reason, _ | _, Error reason -> Error reason
            | Ok selectors, Ok current -> Ok(selectors @ current)) (Ok [])
        |> Result.map distinctSelectors

    let private validateStagePolicyChange
        (configuration: FirewalldModel.Configuration)
        (beforePolicy: string option)
        (afterZones: Map<string, string>)
        (candidatePolicyXml: Map<string, string>)
        (candidateDefaultZone: string)
        (runtimeDefaultZone: string)
        (runtimeZones: Map<string, string>)
        (runtimePolicyXml: Map<string, string>)
        =
        match beforePolicy with
        | None -> Ok ()
        | Some before ->
            match policyInfoFromXml configuration.Name before with
            | Error reason -> Error reason
            | Ok oldPolicy ->
                match oldPolicy.Stage with
                | None -> Ok ()
                | Some(oldIngress, oldEgress, oldRules) ->
                    let runtimeAfterXml =
                        Map.remove configuration.Name runtimePolicyXml
                        |> fun current -> Map.fold (fun state name xml -> Map.add name xml state) current candidatePolicyXml
                    let readPolicies (sources: Map<string, string>) =
                        sources
                        |> Map.toList
                        |> List.map (fun (name, xml) -> policyInfoFromXml name xml)
                    let candidateInfoResults = readPolicies candidatePolicyXml
                    let runtimeInfoResults = readPolicies runtimeAfterXml
                    let invalidPolicy =
                        candidateInfoResults @ runtimeInfoResults
                        |> List.tryPick (function Error reason -> Some reason | _ -> None)
                    match invalidPolicy with
                    | Some reason -> Error reason
                    | None ->
                        let candidatePolicies = candidateInfoResults |> List.choose (function Ok info -> Some(info.Name, info) | _ -> None)
                        let runtimePolicies = runtimeInfoResults |> List.choose (function Ok info -> Some(info.Name, info) | _ -> None)
                        let runtimePolicyMap = Map.ofList runtimePolicies
                        let removedRules =
                            oldRules
                            |> List.filter (fun rule ->
                                candidateStagesFor rule.Selector oldIngress oldEgress candidatePolicies runtimePolicyMap
                                |> Set.isEmpty)
                        if removedRules.IsEmpty then Ok ()
                        else
                            match collectZoneSourceSelectors afterZones, collectZoneSourceSelectors runtimeZones with
                            | Error reason, _ | _, Error reason -> Error("Cannot verify source-binding ownership during staging-policy removal: " + reason + ".")
                            | Ok permanentBindings, Ok liveBindings ->
                                let mutable safeToRemove = true
                                for rule in removedRules do
                                    let boundPermanently = selectorFullyCoveredBy permanentBindings rule.Selector
                                    let boundAtRuntime = selectorFullyCoveredBy liveBindings rule.Selector
                                    if not (boundPermanently && boundAtRuntime) then
                                        if oldIngress = "HOST" then safeToRemove <- false
                                        else
                                            match possibleFallbackZones "" [ candidateDefaultZone; runtimeDefaultZone ] [ rule.Selector ] afterZones runtimeZones with
                                            | Ok fallbackZones when fallbackIsRestrictive fallbackZones afterZones runtimeZones candidatePolicies runtimePolicies -> ()
                                            | _ -> safeToRemove <- false
                                if safeToRemove then Ok ()
                                else
                                    let selectors = removedRules |> List.map (fun rule -> displaySelector rule.Selector) |> List.distinct |> String.concat ", "
                                    Error(
                                        "Refusing to remove or weaken firewalld transfer fence " + configuration.Name + " for " + selectors
                                        + ": the selector is not bound in both permanent and runtime state, and its fallback is not proven restrictive. Keep the fence until the destination binding is active, or quarantine the selector in a confirmed restrictive fallback before releasing it.")

    let validate
        (configuration: FirewalldModel.Configuration)
        (beforeObject: string option)
        (afterZones: Map<string, string>)
        (candidatePolicyXml: Map<string, string>)
        (candidateDefaultZone: string)
        (runtimeDefaultZone: string)
        (runtimeZones: Map<string, string>)
        (runtimePolicyXml: Map<string, string>)
        =
        match configuration.Kind with
        | "zone" ->
            validateZoneSourceBinding configuration beforeObject afterZones candidatePolicyXml candidateDefaultZone runtimeDefaultZone runtimeZones runtimePolicyXml
        | "policy" ->
            validateStagePolicyChange configuration beforeObject afterZones candidatePolicyXml candidateDefaultZone runtimeDefaultZone runtimeZones runtimePolicyXml
        | _ -> Ok ()
