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

    let private directText (node: XElement) =
        let texts =
            node.Nodes()
            |> Seq.choose (function
                | :? XText as text -> Some text.Value
                | _ -> None)
            |> Seq.toArray
        if texts.Length = 0 then None
        elif node.HasElements && (texts |> Array.forall String.IsNullOrWhiteSpace) then None
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
            directText node |> Option.iter (fun value -> textArray.Add(JsonValue.Create value))
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
        (canonical root).ToJsonString()

    /// Canonical comparison ignores XML formatting and unordered native element order,
    /// but retains every declared attribute and text value. The zone/policy rule
    /// sequence is normalized as firewalld's native priority/rule set, not XML order.
    let canonicalXml kind text =
        parseRoot kind text |> canonicalNode

    let private legacyChildAttributes kind (name: XName) =
        match kind, name with
        | "zone", name when name = xn "interface" -> Some [ "name" ]
        | "zone", name when name = xn "service" -> Some [ "name" ]
        | "zone", name when name = xn "port" -> Some [ "port"; "protocol" ]
        | "zone", name when name = xn "protocol" -> Some [ "value" ]
        | "zone", name when name = xn "masquerade" -> Some []
        | "zone", name when name = xn "forward" -> Some []
        | "policy", name when name = xn "ingress-zone" -> Some [ "name" ]
        | "policy", name when name = xn "egress-zone" -> Some [ "name" ]
        | "policy", name when name = xn "masquerade" -> Some []
        | _ -> None

    let private completeLegacyChild kind (node: XElement) =
        match legacyChildAttributes kind node.Name with
        | None -> false
        | Some expectedAttributes ->
            let actualAttributes = node.Attributes() |> Seq.map (fun attribute -> attribute.Name.ToString()) |> Seq.sort |> Seq.toList
            let expectedAttributes = expectedAttributes |> List.map (fun name -> (xn name).ToString()) |> List.sort
            let noContent =
                not node.HasElements
                && (node.Nodes()
                    |> Seq.forall (function
                        | :? XText as text -> String.IsNullOrWhiteSpace text.Value
                        | _ -> false))
            actualAttributes = expectedAttributes && noContent

    let private preserveNonLegacy (kind: string) (root: XElement) =
        for child in root.Elements() |> Seq.toArray do
            if completeLegacyChild kind child then child.Remove()
        for attribute in root.Attributes() |> Seq.toArray do
            if ((kind = "zone" || kind = "policy") && attribute.Name = xn "target")
               || (kind = "policy" && attribute.Name = xn "priority") then
                attribute.Remove()
        root

    /// Existing definitions may be replaced only if every feature outside the
    /// legacy replacement contract is explicitly carried through unchanged.
    let safeAdoption (configuration: FirewalldModel.Configuration) (baselineXml: string) : bool =
        try
            let c = FirewalldModel.validate configuration
            if c.Kind = "settings" || isNull baselineXml then false
            else
                let baseline = parseRoot c.Kind baselineXml
                let desired = parseRoot c.Kind (render c)
                let baselineFeatures = canonicalNode (preserveNonLegacy c.Kind baseline)
                let desiredFeatures = canonicalNode (preserveNonLegacy c.Kind desired)
                baselineFeatures = desiredFeatures
        with _ -> false
