namespace Dorothy.HostHelper

open System
open System.IO
open System.Net
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open System.Xml
open System.Xml.Linq

module Firewalld =
    type BackendError(message: string) =
        inherit Exception(message)

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

    let render (c: FirewalldModel.Configuration) =
        let c = FirewalldModel.validate c
        let root = XElement(xn c.Kind)
        if c.Target <> "default" then root.SetAttributeValue(xn "target", c.Target)
        if c.Kind = "policy" then root.SetAttributeValue(xn "priority", string c.Priority)
        let add name key values =
            for value in values do
                let element = XElement(xn name)
                element.SetAttributeValue(xn key, (value: string))
                root.Add element
        add "interface" "name" c.Interfaces
        add "service" "name" c.Services
        for port in c.Ports do
            let parts = port.Split('/')
            let element = XElement(xn "port")
            element.SetAttributeValue(xn "port", parts[0])
            element.SetAttributeValue(xn "protocol", parts[1])
            root.Add element
        add "protocol" "value" c.Protocols
        add "ingress-zone" "name" c.Ingress
        add "egress-zone" "name" c.Egress
        if c.Masquerade then root.Add(XElement(xn "masquerade"))
        if c.Forward then root.Add(XElement(xn "forward"))
        root.ToString(SaveOptions.DisableFormatting) + "\n"

    // Element and attribute order is not semantic; unknown elements remain in the comparison.
    // Descriptive text is not a packet filtering setting.
    let canonicalXml kind text =
        let root = parseXml kind text
        let rec canonical (node: XElement) : string =
            let attributes =
                node.Attributes()
                |> Seq.filter (fun a -> not (node = root && (a.Name.LocalName = "version" || (a.Name.LocalName = "target" && a.Value = "default"))))
                |> Seq.map (fun a -> a.Name.ToString(), a.Value)
                |> Seq.sort |> Seq.toList
            let children =
                node.Elements()
                |> Seq.filter (fun e -> e.Name <> xn "short" && e.Name <> xn "description")
                |> Seq.map canonical |> Seq.sort |> Seq.toList
            let output = JsonArray()
            output.Add(JsonValue.Create(node.Name.ToString()))
            for key, value in attributes do
                output.Add(JsonValue.Create(key + "=" + value))
            for child in children do output.Add(JsonValue.Create child)
            output.ToJsonString()
        canonical root

    type SshContext = { Peer: string; Local: string; Port: int; Interface: string }

    let parseSshContext (connection: string) (routeJson: string) =
        let fields = if isNull connection then [||] else connection.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
        let address (text: string) =
            match IPAddress.TryParse text with true, value -> value | _ -> fail "SSH_CONNECTION contains an invalid IP address."
        if fields.Length <> 4 then fail "SSH_CONNECTION is required to guard firewalld mutations."
        let peer, local = address fields[0], address fields[2]
        let port =
            match Int32.TryParse fields[3] with
            | true, value when value >= 1 && value <= 65535 -> value
            | _ -> fail "SSH_CONNECTION has an invalid server port."
        if peer.AddressFamily <> local.AddressFamily then fail "SSH_CONNECTION address families differ."
        use document = JsonDocument.Parse routeJson
        let routes = document.RootElement.EnumerateArray() |> Seq.toArray
        if routes.Length <> 1 then fail "Cannot identify a unique SSH route."
        let iface = routes[0].GetProperty("dev").GetString()
        FirewalldModel.token "SSH interface" 15 iface |> ignore
        { Peer = peer.ToString(); Local = local.ToString(); Port = port; Interface = iface }

    let private portAllows port (element: XElement) =
        match attr "protocol" element, attr "port" element with
        | Some "tcp", Some value ->
            if value = "" then false
            else
                let canonical = FirewalldModel.port (value + "/tcp")
                let range = (canonical.Split('/')[0]).Split('-') |> Array.map int
                port >= range[0] && port <= range[range.Length - 1]
        | _ -> false

    let private richRuleMayBlockSsh (rule: XElement) =
        let elements = rule.Descendants() |> Seq.map (fun e -> e.Name.LocalName) |> Set.ofSeq
        let actions = set [ "accept"; "log"; "audit" ]
        let understood = Set.union actions (set [ "source"; "destination"; "service"; "port"; "source-port"; "protocol"; "icmp-type"; "limit" ])
        // Accept/log/audit cannot deny traffic, regardless of selectors or rate limits.
        // Unknown actions (including mark and forwarding) must not be treated as harmless.
        if not (Set.isEmpty (Set.intersect elements actions)) && Set.isSubset elements understood then false
        elif elements.Contains "icmp-type" && Set.isSubset elements (set [ "icmp-type"; "source"; "destination"; "drop"; "reject"; "limit" ]) then false
        else true

    /// Pure guard over the final permanent inventory. Ambiguous source/rich rules fail closed.
    let validateSshGuard
        (context: SshContext)
        (defaultZone: string)
        (zones: Map<string, string>)
        (policies: Map<string, string>)
        (serviceXml: string -> string option)
        =
        let parsed = zones |> Map.map (fun _ xml -> parseXml "zone" xml)
        for KeyValue(_, zone) in parsed do
            if zone.Elements(xn "source") |> Seq.isEmpty |> not then
                fail "SSH guard cannot prove safety with source-bound zones; remove source bindings before managing firewalld."
        let bindings =
            parsed |> Map.toList |> List.choose (fun (name, zone) ->
                if zone.Elements(xn "interface") |> Seq.exists (fun e -> required "name" e = context.Interface) then Some name else None)
        let zoneName =
            match bindings with
            | [] -> defaultZone
            | [ name ] -> name
            | _ -> fail "SSH interface is bound to multiple permanent zones."
        let zone = parsed |> Map.tryFind zoneName |> Option.defaultWith (fun () -> fail "SSH interface's final zone is missing.")
        if zone.Elements(xn "rule") |> Seq.isEmpty |> not
           || zone.Elements(xn "forward-port") |> Seq.isEmpty |> not then
            fail "SSH guard cannot prove safety with rich rules or forwarding ports in the SSH zone."
        let rec serviceAllows seen name =
            if Set.contains name seen then fail "Cyclic firewalld service include."
            FirewalldModel.token "service" 128 name |> ignore
            let xml = serviceXml name |> Option.defaultWith (fun () -> fail ("Required firewalld service is missing: " + name))
            let service = parseXml "service" xml
            if not (service.Elements(xn "destination") |> Seq.isEmpty) then false
            else
                (service.Elements(xn "port") |> Seq.exists (portAllows context.Port))
                || (service.Elements(xn "protocol") |> Seq.exists (fun e -> required "value" e = "tcp" || required "value" e = "6"))
                || (service.Elements(xn "include") |> Seq.exists (fun e -> serviceAllows (Set.add name seen) (required "service" e)))
        let allowed =
            attr "target" zone = Some "ACCEPT"
            || (zone.Elements(xn "port") |> Seq.exists (portAllows context.Port))
            || (zone.Elements(xn "protocol") |> Seq.exists (fun e -> List.contains (required "value" e) [ "tcp"; "6" ]))
            || (zone.Elements(xn "service") |> Seq.exists (fun e -> serviceAllows Set.empty (required "name" e)))
        if not allowed then fail ("Final zone " + zoneName + " does not allow current SSH port " + string context.Port + "/tcp; refusing mutation.")
        for KeyValue(_, xml) in policies do
            let policy = parseXml "policy" xml
            let matches side names = policy.Elements(xn side) |> Seq.exists (fun e -> List.contains (required "name" e) names)
            // Also protect the reply direction. Conservative even for positive-priority policies.
            let inbound = matches "ingress-zone" [ zoneName; "ANY" ] && matches "egress-zone" [ "HOST" ]
            let outbound = matches "ingress-zone" [ "HOST" ] && matches "egress-zone" [ zoneName; "ANY" ]
            if inbound || outbound then
                if List.contains (defaultArg (attr "target" policy) "CONTINUE") [ "DROP"; "REJECT" ]
                   || (policy.Elements(xn "rule") |> Seq.exists richRuleMayBlockSsh) then
                    fail "A host policy may block the current SSH connection; refusing mutation."

    let private validateRuntimeBinding context defaultZone runtimeZone zones policies serviceXml =
        validateSshGuard context defaultZone zones policies serviceXml
        if not (Map.containsKey runtimeZone zones) then
            fail "SSH runtime zone is absent from final permanent configuration; reconcile the runtime binding before applying."
        // Reload can retain runtime/NM bindings. Check that outcome too, without changing it.
        let runtimeBound =
            zones |> Map.map (fun name xml ->
                let root = parseXml "zone" xml
                root.Elements(xn "interface")
                |> Seq.filter (fun element -> required "name" element = context.Interface)
                |> Seq.toArray |> Array.iter (fun element -> element.Remove())
                if name = runtimeZone then
                    let element = XElement(xn "interface")
                    element.SetAttributeValue(xn "name", context.Interface)
                    root.Add element
                root.ToString(SaveOptions.DisableFormatting))
        validateSshGuard context defaultZone runtimeBound policies serviceXml

    let private diagnostic (text: string) =
        if isNull text then ""
        else
            text.Substring(0, min 2048 text.Length)
            |> String.map (fun c -> if Char.IsControl c then ' ' else c)

    let private mode644 = UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.GroupRead ||| UnixFileMode.OtherRead
    let private mode600 = UnixFileMode.UserRead ||| UnixFileMode.UserWrite
    let private mode700 = mode600 ||| UnixFileMode.UserExecute
    let private journalDirectory = "/var/lib/keroosha-iac/firewalld"
    let private lockPath = "/run/lock/keroosha-firewalld-backend.lock"
    let private path environment logical = HostEnvironment.path environment logical
    let private category kind = if kind = "zone" then "zones" elif kind = "policy" then "policies" else "services"
    let private objectPath prefix kind name = prefix + "/" + category kind + "/" + name + ".xml"

    let private checkedCommandResult executable arguments (result: CommandResult) =
        if result.ExitCode <> 0 then
            let detail = if String.IsNullOrWhiteSpace result.Stderr then result.Stdout else result.Stderr
            let commandLine = String.concat " " arguments
            fail ("firewalld command failed: " + executable + " " + commandLine + " (exit " + string result.ExitCode + "): " + diagnostic detail)
        result.Stdout.Trim()

    let private command (environment: HostEnvironment) executable arguments =
        environment.Run executable arguments None |> checkedCommandResult executable arguments

    let private runtimeZoneOfInterface (environment: HostEnvironment) defaultZone iface =
        let arguments = [ "--get-zone-of-interface=" + iface ]
        let result = environment.Run "firewall-cmd" arguments None
        let stdout, stderr = result.Stdout.Trim(), result.Stderr.Trim()
        let unbound =
            result.ExitCode = 2
            && ((stdout = "no zone" && (stderr = "" || stderr = "no zone"))
                || (stderr = "no zone" && stdout = ""))
        if unbound then defaultZone
        else
            let name = checkedCommandResult "firewall-cmd" arguments result
            FirewalldModel.token "runtime zone" 17 name

    let private firewall environment arguments = command environment "firewall-cmd" arguments

    let private regularPath environment logical =
        let physical = path environment logical
        let rec parents (item: string) =
            if item <> Path.GetPathRoot item then
                if File.GetAttributes(item).HasFlag FileAttributes.ReparsePoint then fail "Symlinks are not accepted for firewalld state paths."
                parents (Path.GetDirectoryName item)
        if File.Exists physical || Directory.Exists physical then parents physical
        else parents (Path.GetDirectoryName physical)
        physical

    let private readFile environment logical =
        let physical = path environment logical
        if File.Exists physical then
            regularPath environment logical |> ignore
            Some(File.ReadAllText physical)
        else
            if Directory.Exists physical then fail "Expected a regular firewalld configuration file."
            // Also reject dangling symlinks.
            if not (isNull (FileInfo(physical).LinkTarget)) then fail "Dangling firewalld state symlink."
            None

    let private effective environment kind name =
        match readFile environment (objectPath "/etc/firewalld" kind name) with
        | Some xml -> Some xml
        | None -> readFile environment (objectPath "/usr/lib/firewalld" kind name)

    let private inventory environment kind =
        [ "/usr/lib/firewalld"; "/etc/firewalld" ]
        |> List.fold (fun result prefix ->
            let directory = path environment (prefix + "/" + category kind)
            if not (Directory.Exists directory) then result
            else
                regularPath environment (prefix + "/" + category kind) |> ignore
                Directory.EnumerateFiles(directory, "*.xml")
                |> Seq.fold (fun state file ->
                    let name = Path.GetFileNameWithoutExtension file
                    FirewalldModel.token kind (if kind = "zone" then 17 else 128) name |> ignore
                    let logical = objectPath prefix kind name
                    match readFile environment logical with Some xml -> Map.add name xml state | None -> state) result) Map.empty

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
                if journal.Count <> 5 || journal["version"].GetValue<int>() <> 1
                   || getString journal "ownerId" <> owner then fail "Firewalld object is owned by another resource or its journal is invalid."
                optionalString journal "baseline" |> ignore
                optionalString journal "managed" |> ignore
                if not (journal.ContainsKey "pending") then fail "Firewalld journal has no transaction state."
                Some journal

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

    let private writeOverride environment (c: FirewalldModel.Configuration) contents =
        let logical = objectPath "/etc/firewalld" c.Kind c.Name
        let parent = Path.GetDirectoryName(path environment logical)
        if not (Directory.Exists parent) then
            regularPath environment "/etc/firewalld" |> ignore
            Directory.CreateDirectory parent |> ignore
        let physical = regularPath environment logical
        match contents with
        | Some text -> HostFiles.atomicWrite physical (Encoding.UTF8.GetBytes(text: string)) mode644
        | None -> File.Delete physical

    let private finalInventory environment (c: FirewalldModel.Configuration) proposed =
        let zones, policies = inventory environment "zone", inventory environment "policy"
        let final =
            match proposed with
            | Some xml -> Some xml
            | None -> readFile environment (objectPath "/usr/lib/firewalld" c.Kind c.Name)
        let update values = match final with Some xml -> Map.add c.Name xml values | None -> Map.remove c.Name values
        if c.Kind = "zone" then update zones, policies else zones, update policies

    let private guardMutation environment c proposed =
        let connection = Environment.GetEnvironmentVariable "SSH_CONNECTION"
        let fields = if isNull connection then [||] else connection.Split(' ', StringSplitOptions.RemoveEmptyEntries)
        if fields.Length <> 4 then fail "SSH_CONNECTION is required before any firewalld mutation."
        // Validate addresses before passing them as separate argv tokens.
        for index in [ 0; 2 ] do
            match IPAddress.TryParse fields[index] with true, _ -> () | _ -> fail "Invalid SSH_CONNECTION address."
        let route = command environment "ip" [ "-j"; "route"; "get"; fields[0]; "from"; fields[2] ]
        let context = parseSshContext connection route
        let defaultZone = firewall environment [ "--get-default-zone" ]
        let zones, policies = finalInventory environment c proposed
        let runtimeZone = runtimeZoneOfInterface environment defaultZone context.Interface
        validateRuntimeBinding context defaultZone runtimeZone zones policies (effective environment "service")

    /// APT may start firewalld from its maintainer script, before any zone resource runs.
    /// Validate that first-start permanent configuration without writing an unowned zone.
    let validatePackageInstall (environment: HostEnvironment) =
        let connection = Environment.GetEnvironmentVariable "SSH_CONNECTION"
        let fields = if isNull connection then [||] else connection.Split(' ', StringSplitOptions.RemoveEmptyEntries)
        if fields.Length <> 4 then fail "Installing firewalld requires SSH_CONNECTION to guard package-triggered startup."
        for index in [ 0; 2 ] do
            match IPAddress.TryParse fields[index] with true, _ -> () | _ -> fail "Invalid SSH_CONNECTION address."
        let route = command environment "ip" [ "-j"; "route"; "get"; fields[0]; "from"; fields[2] ]
        let context = parseSshContext connection route
        let defaults =
            readFile environment "/etc/firewalld/firewalld.conf"
            |> Option.map (fun text ->
                text.Split('\n')
                |> Array.map (fun line -> line.Trim())
                |> Array.filter (fun line -> line.StartsWith("DefaultZone=", StringComparison.Ordinal))
                |> Array.map (fun line -> line.Substring("DefaultZone=".Length).Trim()))
            |> Option.defaultValue [||]
        let defaultZone =
            match defaults with
            | [||] -> "public"
            | [| name |] -> FirewalldModel.token "default zone" 17 name
            | _ -> fail "Ambiguous DefaultZone in firewalld bootstrap configuration."
        // Debian 13's package default permits SSH on 22, not the provider's configured port.
        let stockSsh = "<service><port port=\"22\" protocol=\"tcp\"/></service>"
        let zones = inventory environment "zone"
        let zones =
            if Map.containsKey "public" zones then zones
            else Map.add "public" "<zone><port port=\"22\" protocol=\"tcp\"/></zone>" zones
        let services name =
            match effective environment "service" name with
            | None when name = "ssh" -> Some stockSsh
            | value -> value
        try validateSshGuard context defaultZone zones (inventory environment "policy") services
        with :? BackendError as error ->
            fail ("Refusing firewalld package startup before zone resources: " + error.Message
                  + " Pre-seed the permanent default/interface zone to permit the actual SSH server port before installing firewalld.")

    let private ensurePrerequisites environment (c: FirewalldModel.Configuration) =
        firewall environment [ "--state" ] |> ignore
        for service in c.Services do
            if effective environment "service" service |> Option.isNone then fail ("Missing firewalld service prerequisite: " + service)
        if c.Kind = "policy" then
            for name in c.Ingress @ c.Egress do
                if name <> "ANY" && name <> "HOST" && (effective environment "zone" name |> Option.isNone) then
                    fail ("Missing firewalld zone prerequisite: " + name + "; provision its owner first (declare docker in the same host for DockerEngine ordering), or create the permanent zone before applying this policy.")
        else
            for KeyValue(name, xml) in inventory environment "zone" do
                if name <> c.Name then
                    let zone = parseXml "zone" xml
                    if zone.Elements(xn "interface") |> Seq.exists (fun e -> List.contains (required "name" e) c.Interfaces) then
                        fail ("An interface belongs to another permanent zone: " + name + "; remove that binding first.")

    let private snapshot environment (c: FirewalldModel.Configuration) journal =
        let actual = effective environment c.Kind c.Name
        let owned =
            match journal with
            | Some (value: JsonObject) -> isNull value["pending"] && optionalString value "managed" = readFile environment (objectPath "/etc/firewalld" c.Kind c.Name)
            | None -> false
        let matches =
            actual |> Option.exists (fun xml -> canonicalXml c.Kind xml = canonicalXml c.Kind (render c))
        let result = JsonObject()
        result["exists"] <- JsonValue.Create actual.IsSome
        result["actual"] <- JsonValue.Create(defaultArg actual "")
        result["inSync"] <- JsonValue.Create(owned && matches)
        result :> JsonNode

    let private recover environment (c: FirewalldModel.Configuration) (journal: JsonObject) =
        match journal["pending"] with
        | null -> ()
        | pending ->
            let pending = pending.AsObject()
            if pending.Count <> 2 then fail "Invalid firewalld pending transaction."
            let before, after = optionalString pending "before", optionalString pending "after"
            let current = readFile environment (objectPath "/etc/firewalld" c.Kind c.Name)
            if current <> before && current <> after then fail "Firewalld configuration changed during an interrupted transaction; refusing recovery."
            guardMutation environment c before
            writeOverride environment c before
            firewall environment [ "--check-config" ] |> ignore
            firewall environment [ "--reload" ] |> ignore
            setOptional journal "managed" before
            journal["pending"] <- null
            saveJournal environment c journal

    let private transact environment (c: FirewalldModel.Configuration) (journal: JsonObject) releaseOnRollback desired =
        let before = readFile environment (objectPath "/etc/firewalld" c.Kind c.Name)
        guardMutation environment c desired
        let pending = JsonObject()
        setOptional pending "before" before
        setOptional pending "after" desired
        journal["pending"] <- pending
        // Baseline and rollback material are durable before touching permanent state.
        saveJournal environment c journal
        try
            writeOverride environment c desired
            firewall environment [ "--check-config" ] |> ignore
            firewall environment [ "--reload" ] |> ignore
        with originalError ->
            try
                writeOverride environment c before
                firewall environment [ "--reload" ] |> ignore
                setOptional journal "managed" before
                journal["pending"] <- null
                saveJournal environment c journal
            with rollbackError ->
                fail ("Firewalld apply failed: " + diagnostic originalError.Message + "; rollback failed: " + diagnostic rollbackError.Message + "; journal retained for recovery.")
            if releaseOnRollback then File.Delete(path environment (journalPath c))
            fail ("Firewalld apply failed; original permanent configuration restored and reloaded: " + diagnostic originalError.Message)
        setOptional journal "managed" desired
        journal["pending"] <- null
        saveJournal environment c journal

    let handle (environment: HostEnvironment) (request: JsonElement) : JsonNode =
        let keys = request.EnumerateObject() |> Seq.map (fun p -> p.Name) |> Seq.toList
        if keys.Length <> 3 || Set.ofList keys <> set [ "operation"; "ownerId"; "configuration" ] then fail "Invalid firewalld request fields."
        let operation = request.GetProperty("operation").GetString()
        let owner = request.GetProperty("ownerId").GetString()
        if String.IsNullOrWhiteSpace owner || owner |> Seq.exists Char.IsControl then fail "Invalid firewalld owner identity."
        let c =
            try FirewalldModel.parse (request.GetProperty("configuration").GetString())
            with _ -> fail "Invalid firewalld configuration."
        let lockFile = path environment lockPath
        if operation = "read" then
            use _lock =
                if File.Exists lockFile then HostFiles.lockFile lockFile
                else { new IDisposable with member _.Dispose() = () }
            snapshot environment c (loadJournal environment c owner)
        elif operation = "apply" || operation = "delete" then
            use _lock = HostFiles.lockFile lockFile
            let existingJournal = loadJournal environment c owner
            if operation = "delete" && existingJournal.IsNone then
                // Never delete an unowned object, including a resource whose Create guard failed.
                JsonObject() :> JsonNode
            else
                ensurePrerequisites environment (if operation = "delete" then { c with Interfaces = []; Services = []; Ingress = []; Egress = [] } else c)
                let journal =
                    existingJournal
                    |> Option.defaultWith (fun () -> newJournal owner (readFile environment (objectPath "/etc/firewalld" c.Kind c.Name)))
                recover environment c journal
                if operation = "apply" then
                    transact environment c journal existingJournal.IsNone (Some(render c))
                    let result = snapshot environment c (Some journal)
                    if not (result["inSync"].GetValue<bool>()) then fail "Firewalld permanent configuration did not converge."
                    result
                else
                    let current = readFile environment (objectPath "/etc/firewalld" c.Kind c.Name)
                    if current <> optionalString journal "managed" then fail "Owned firewalld file changed independently; refusing Delete."
                    let baseline = optionalString journal "baseline"
                    let restored =
                        baseline |> Option.map (fun xml ->
                            if c.Kind <> "zone" then xml
                            else
                                let zone = parseXml "zone" xml
                                // Deleted resource no longer owns any interface: use default-zone fallback.
                                zone.Elements(xn "interface") |> Seq.toArray |> Array.iter (fun element -> element.Remove())
                                zone.ToString(SaveOptions.DisableFormatting) + "\n")
                    transact environment c journal false restored
                    File.Delete(path environment (journalPath c))
                    JsonObject() :> JsonNode
        else fail "Unsupported firewalld operation."
