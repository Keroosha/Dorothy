namespace Dorothy.HostHelper

open System
open System.IO
open System.Text.Json
open System.Text.Json.Nodes
open System.Xml
open System.Xml.Linq

module FieldRuntime =
    let private xn name = XName.Get name

    let private parseRoot kind (text: string) =
        let settings = XmlReaderSettings()
        settings.DtdProcessing <- DtdProcessing.Prohibit
        settings.XmlResolver <- null
        settings.IgnoreWhitespace <- false
        use input = new StringReader(text)
        use reader = XmlReader.Create(input, settings)
        let document = XDocument.Load(reader, LoadOptions.PreserveWhitespace)
        if isNull document.Root || document.Root.Name <> xn kind then
            raise (XmlException("Unexpected firewalld XML root."))
        document.Root

    let private xmlAttributes (node: XElement) =
        node.Attributes()
        |> Seq.map (fun attribute ->
            if attribute.Name.Namespace <> XNamespace.None then
                invalidOp "Namespaced firewalld XML attributes cannot be projected."
            attribute.Name.LocalName, attribute.Value)
        |> Map.ofSeq

    let rec private xmlElement (node: XElement) : FirewalldModel.Element =
        if node.Name.Namespace <> XNamespace.None then
            invalidOp "Namespaced firewalld XML elements cannot be projected."
        let texts =
            node.Nodes()
            |> Seq.choose (function
                | :? XText as text -> Some text.Value
                | _ -> None)
            |> Seq.toArray
        let text =
            if texts.Length = 0
               || (node.HasElements && (texts |> Array.forall String.IsNullOrWhiteSpace)) then None
            else Some(String.concat "" texts)
        { Name = node.Name.LocalName
          Attributes = xmlAttributes node
          Text = text
          Children = node.Elements() |> Seq.map xmlElement |> Seq.toList }

    /// Parses an effective native XML object into the validated wire model without
    /// normalizing away any root attributes or child elements.
    let parseConfiguration (kind: string) (name: string) (text: string) : Result<FirewalldModel.Configuration, string> =
        try
            if kind = "settings" then invalidArg "kind" "Global settings are not XML objects."
            let root = parseRoot kind text
            let rootTexts =
                root.Nodes()
                |> Seq.choose (function
                    | :? XText as value -> Some value.Value
                    | _ -> None)
                |> Seq.toArray
            if rootTexts |> Array.exists (String.IsNullOrWhiteSpace >> not) then
                invalidArg "text" "Firewalld object roots cannot contain text."
            let attributes = xmlAttributes root
            let empty = FirewalldModel.empty kind name
            let target =
                if kind = "zone" || kind = "policy" then
                    Map.tryFind "target" attributes |> Option.defaultValue empty.Target
                else empty.Target
            let priority =
                if kind = "policy" then
                    Map.tryFind "priority" attributes
                    |> Option.map (fun value -> Int32.Parse(value, Globalization.CultureInfo.InvariantCulture))
                    |> Option.defaultValue empty.Priority
                else empty.Priority
            let attributes =
                if kind = "zone" || kind = "policy" then Map.remove "target" attributes
                else attributes
            let attributes = if kind = "policy" then Map.remove "priority" attributes else attributes
            let configuration =
                { empty with
                    Target = target
                    Priority = priority
                    Attributes = attributes
                    Elements = root.Elements() |> Seq.map xmlElement |> Seq.toList }
            FirewalldModel.validate configuration |> ignore
            Ok configuration
        with error -> Error error.Message

    let rec private modelElement (element: FirewalldModel.Element) =
        let result = XElement(xn element.Name)
        for KeyValue(name, value) in element.Attributes do
            result.SetAttributeValue(xn name, value)
        element.Text |> Option.iter (fun value -> result.Add(XText value))
        for child in element.Children do
            result.Add(modelElement child :> obj)
        result

    let private legacyElement name attributes =
        let result = XElement(xn name)
        for key, value in attributes do
            result.SetAttributeValue(xn key, value)
        result

    /// Render declared fields and structured native XML as one permanent object.
    let render (configuration: FirewalldModel.Configuration) =
        let c = FirewalldModel.validate configuration
        if c.Kind = "settings" then
            invalidArg "configuration" "Global firewalld settings are not XML objects."

        let root = XElement(xn c.Kind)
        for KeyValue(name, value) in c.Attributes do
            root.SetAttributeValue(xn name, value)

        let hasAttribute name = Map.containsKey name c.Attributes
        if c.Kind = "zone" then
            if not (hasAttribute "target") && c.Target <> "default" then root.SetAttributeValue(xn "target", c.Target)
        elif c.Kind = "policy" then
            if not (hasAttribute "target") then root.SetAttributeValue(xn "target", c.Target)
            if not (hasAttribute "priority") then root.SetAttributeValue(xn "priority", string c.Priority)

        let add name key values =
            for value in values do
                root.Add(legacyElement name [ key, value ])

        match c.Kind with
        | "zone" ->
            add "interface" "name" c.Interfaces
            add "service" "name" c.Services
            for port in c.Ports do
                let parts = port.Split('/')
                root.Add(legacyElement "port" [ "port", parts[0]; "protocol", parts[1] ])
            add "protocol" "value" c.Protocols
            if c.Masquerade then root.Add(XElement(xn "masquerade"))
            if c.Forward then root.Add(XElement(xn "forward"))
        | "policy" ->
            add "ingress-zone" "name" c.Ingress
            add "egress-zone" "name" c.Egress
            add "service" "name" c.Services
            for port in c.Ports do
                let parts = port.Split('/')
                root.Add(legacyElement "port" [ "port", parts[0]; "protocol", parts[1] ])
            add "protocol" "value" c.Protocols
            if c.Masquerade then root.Add(XElement(xn "masquerade"))
        | "service" ->
            for port in c.Ports do
                let parts = port.Split('/')
                root.Add(legacyElement "port" [ "port", parts[0]; "protocol", parts[1] ])
            add "protocol" "value" c.Protocols
        | "helper" ->
            for port in c.Ports do
                let parts = port.Split('/')
                root.Add(legacyElement "port" [ "port", parts[0]; "protocol", parts[1] ])
        | _ -> ()

        for element in c.Elements do
            root.Add(modelElement element)

        root.ToString(SaveOptions.DisableFormatting) + "\n"

    let private directText isRoot (node: XElement) =
        let texts =
            node.Nodes()
            |> Seq.choose (function
                | :? XText as text -> Some text.Value
                | _ -> None)
            |> Seq.toArray
        if texts.Length = 0 then None
        elif (isRoot || node.HasElements) && (texts |> Array.forall String.IsNullOrWhiteSpace) then None
        else Some(String.concat "" texts)
 

    let private canonicalNode (root: XElement) =
        let rec canonical (node: XElement) : JsonArray =
            let result = JsonArray()
            result.Add(JsonValue.Create(node.Name.ToString()))

            let attributes =
                node.Attributes()
                |> Seq.filter (fun attribute ->
                    not (node = root && attribute.Name = xn "target" && attribute.Value = "default"))
                |> Seq.map (fun attribute -> attribute.Name.ToString(), attribute.Value)
                |> Seq.sort
            let attributeArray = JsonArray()
            for name, value in attributes do
                let pair = JsonArray()
                pair.Add(JsonValue.Create name)
                pair.Add(JsonValue.Create value)
                attributeArray.Add pair
            result.Add attributeArray

            let textArray = JsonArray()
            directText (node = root) node |> Option.iter (fun value -> textArray.Add(JsonValue.Create value))
            result.Add textArray

            // firewalld 2.3.1 stores rich rules as a set. Priority is part of each
            // rule; order between equal-priority rules is undefined. Sorting full
            // canonical children retains each action/selector without inventing
            // semantics from XML or HashSet iteration order.
            let childEntries =
                node.Elements()
                |> Seq.map (fun child -> child.Name.ToString(), canonical child)
                |> Seq.toList
            let childEntries =
                if node = root && (root.Name = xn "zone" || root.Name = xn "policy") then
                    let rules =
                        childEntries
                        |> List.filter (fun (name, _) -> name = "rule")
                        |> List.distinctBy (fun (_, rule) -> rule.ToJsonString())
                    childEntries |> List.filter (fun (name, _) -> name <> "rule") |> fun other -> other @ rules
                else childEntries
            let children =
                childEntries
                |> List.sortBy (fun (_, child) -> child.ToJsonString())
            let childArray = JsonArray()
            for _, child in children do childArray.Add child
            result.Add childArray
            result
        canonical root

    /// Canonical comparison ignores XML formatting and unordered native element order,
    /// but retains every declared attribute and text value. The zone/policy rule
    /// sequence is normalized as firewalld's native priority/rule set, not XML order.
    let canonicalXml kind text =
        (parseRoot kind text |> canonicalNode).ToJsonString()

    let private jsonArray (node: JsonNode) =
        match node with
        | :? JsonArray as values -> values
        | _ -> invalidOp "Canonical XML has an invalid array."

    let private jsonString (node: JsonNode) =
        match node with
        | :? JsonValue as value -> value.GetValue<string>()
        | _ -> invalidOp "Canonical XML has an invalid string."

    let private canonicalFeaturesPreserved (baseline: JsonArray) (desired: JsonArray) =
        let attributes (root: JsonArray) =
            jsonArray root[1]
            |> Seq.map (fun pair ->
                let pair = jsonArray pair
                jsonString pair[0], jsonString pair[1])
            |> Map.ofSeq
        let baselineAttributes = attributes baseline
        let desiredAttributes = attributes desired
        let attributesPreserved =
            baselineAttributes
            |> Map.forall (fun name value -> Map.tryFind name desiredAttributes = Some value)
        let baselineText = jsonArray baseline[2]
        let desiredText = jsonArray desired[2]
        let textPreserved =
            baselineText.Count = 0
            || baselineText.ToJsonString() = desiredText.ToJsonString()
        let childSet (root: JsonArray) =
            jsonArray root[3]
            |> Seq.map (fun child -> child.ToJsonString())
            |> Set.ofSeq
        attributesPreserved
        && textPreserved
        && Set.isSubset (childSet baseline) (childSet desired)

    /// First adoption may add declared features, but it must carry every native
    /// feature already present in the baseline forward without changing it.
    let safeAdoption (configuration: FirewalldModel.Configuration) (baselineXml: string) : bool =
        try
            let c = FirewalldModel.validate configuration
            if c.Kind = "settings" || isNull baselineXml then false
            else
                let baseline = parseRoot c.Kind baselineXml
                let desired = parseRoot c.Kind (render c)
                let effectiveAttr key fallback (root: XElement) =
                    match root.Attribute(xn key) with null -> fallback | attribute -> attribute.Value
                // Omitting target/priority still has native packet semantics. An
                // implicit default is not permission to replace it during acquisition.
                let defaults =
                    match c.Kind with
                    | "zone" -> [ "target", "default"; "ingress-priority", "0"; "egress-priority", "0" ]
                    | "policy" -> [ "target", "CONTINUE"; "priority", "-1" ]
                    | _ -> []
                (defaults |> List.forall (fun (key, fallback) -> effectiveAttr key fallback baseline = effectiveAttr key fallback desired))
                && canonicalFeaturesPreserved (canonicalNode baseline) (canonicalNode desired)
        with _ -> false
