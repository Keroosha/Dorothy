#if HOST_HELPER
namespace Dorothy.HostHelper
#else
namespace Dorothy.DSL
#endif

open System
open System.Globalization
open System.Net
open System.Text.Json
open System.Text.Json.Nodes

/// Shared, reflection-free wire contract used by the DSL, provider and native helper.
module FirewalldModel =
    type Element =
        { Name: string
          Attributes: Map<string, string>
          Text: string option
          Children: Element list }

    type Configuration =
        { Kind: string
          Name: string
          Target: string
          Interfaces: string list
          Services: string list
          Ports: string list
          Protocols: string list
          Masquerade: bool
          Forward: bool
          Ingress: string list
          Egress: string list
          Priority: int
          StrictForwardPorts: bool option
          Attributes: Map<string, string>
          Elements: Element list
          SettingValue: string option }

    let empty kind name =
        { Kind = kind; Name = name; Target = if kind = "zone" then "default" else "CONTINUE"
          Interfaces = []; Services = []; Ports = []; Protocols = []; Masquerade = false
          Forward = false; Ingress = []; Egress = []; Priority = -1; StrictForwardPorts = None
          Attributes = Map.empty; Elements = []; SettingValue = None }
    let helperNameForModule (moduleName: string) =
        if moduleName.StartsWith("nf_conntrack_", StringComparison.Ordinal) then
            moduleName.Substring("nf_conntrack_".Length).Replace('_', '-')
        else
            moduleName

    let token label maxLength (value: string) =
        if String.IsNullOrEmpty value || value.Length > maxLength
           || not (Char.IsAsciiLetterOrDigit value[0])
           || not (value |> Seq.forall (fun c -> Char.IsAsciiLetterOrDigit c || c = '_' || c = '-' || c = '.')) then
            invalidArg label (label + " must be a safe firewalld identifier.")
        value

    let port (value: string) =
        let parts = value.Split('/')
        if parts.Length <> 2 || not (List.contains parts[1] [ "tcp"; "udp"; "sctp"; "dccp" ]) then
            invalidArg "ports" "Ports require number[/range]/transport, e.g. 22/tcp or 8000-8010/tcp."
        let range = parts[0].Split('-')
        let number (text: string) =
            match Int32.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture) with
            | true, n when n >= 1 && n <= 65535 -> n
            | _ -> invalidArg "ports" "Port numbers must be between 1 and 65535."
        if range.Length < 1 || range.Length > 2 then invalidArg "ports" "Invalid port range."
        let first = number range[0]
        let last = number range[range.Length - 1]
        if last < first then invalidArg "ports" "Reversed port range."
        (if first = last then string first else string first + "-" + string last) + "/" + parts[1]

    let private fail label message = invalidArg label message

    let private require condition label message =
        if not condition then fail label message

    let private safeXmlString label (value: string) =
        require (not (isNull value)) label (label + " cannot be null.")
        require
            (value
             |> Seq.forall (fun c ->
                 (not (Char.IsControl c) || c = '\t' || c = '\n' || c = '\r')
                 && c <> '\uFFFE' && c <> '\uFFFF'))
            label
            (label + " contains a character that cannot be represented safely in XML.")
        value
    let private safeXmlAttribute label value =
        safeXmlString label value |> ignore
        require (value |> Seq.forall (Char.IsControl >> not)) label (label + " attributes cannot contain control characters.")
        value

    let private nativeName label allowed maxLength (value: string) =
        require (not (String.IsNullOrEmpty value) && value.Length <= maxLength) label (label + " is empty or too long.")
        require
            (Char.IsAsciiLetterOrDigit value[0]
             && (value |> Seq.forall (fun c -> Char.IsAsciiLetterOrDigit c || List.contains c allowed)))
            label
            (label + " must be a safe firewalld identifier.")
        value

    /// References and read-only inventory entries need not satisfy Dorothy's
    /// narrower owned-resource convention. Native IO_Object checks *each*
    /// character, including the first, against its kind's alnum alphabet.
    /// The .xml path component is still a single filename; split zones are separate.
    let nativeReference kind label (value: string) =
        let allowed, maxLength =
            match kind with
            | "zone" -> "_-", 17
            | "policy" -> "_-", 18
            | "service" | "icmptype" -> "_-", Int32.MaxValue
            | "helper" -> "-.", Int32.MaxValue
            | "ipset" -> "_-:.", 32
            | _ -> fail label "Unknown firewalld definition kind."
        require (not (String.IsNullOrEmpty value) && System.Text.Encoding.UTF8.GetByteCount(value) <= 251) label "Invalid native definition filename."
        let mutable count = 0
        for scalar in value.EnumerateRunes() do
            count <- count + 1
            require (System.Text.Rune.IsLetter(scalar) || System.Text.Rune.IsNumber(scalar)
                     || (scalar.IsAscii && allowed.IndexOf(char scalar.Value) >= 0)) label "Invalid native definition name."
        require (count <= maxLength) label "Native definition name exceeds the target limit."
        value

    let private normalizedReferences kind values =
        values |> List.map (nativeReference kind kind) |> List.distinct |> List.sort

    let private checkObjectName kind name =
        match kind with
        | "zone" ->
            token "name" 17 name |> ignore
            require (not (name.Contains('.'))) "name" "Zone names cannot contain dots."
        | "policy" ->
            token "name" 18 name |> ignore
            require (not (name.Contains('.'))) "name" "Policy names cannot contain dots."
        | "service" -> nativeName "name" [ '_'; '-' ] 128 name |> ignore
        | "ipset" -> nativeName "name" [ '_'; '-'; ':'; '.' ] 32 name |> ignore
        | "icmptype" -> nativeName "name" [ '_'; '-' ] 128 name |> ignore
        | "helper" -> nativeName "name" [ '-'; '.' ] 128 name |> ignore
        | _ -> fail "name" "Unsupported firewalld object kind."

    let private parseInt label (value: string) =
        match Int32.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture) with
        | true, number -> number
        | _ -> fail label (label + " must be an integer.")

    let private parseNonnegative label (value: string) =
        let parsed = parseInt label value
        require (parsed >= 0) label (label + " cannot be negative.")
        parsed

    let private parseUnsigned label maxValue (value: string) =
        let raw = if isNull value then "" else value.Trim()
        let parsed =
            if raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
                match UInt64.TryParse(raw.Substring(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture) with
                | true, number -> Some number
                | _ -> None
            else
                match UInt64.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture) with
                | true, number -> Some number
                | _ -> None
        match parsed with
        | Some number when number <= maxValue -> number
        | _ -> fail label (label + " must be an unsigned integer in range.")

    let private isIpv4 (value: string) =
        let parts = value.Split('.')
        parts.Length = 4
        && (parts
            |> Array.forall (fun part ->
                match Byte.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture) with
                | true, number -> part.Length > 0 && string number = part
                | _ -> false))

    let private isIpv6 (value: string) =
        let raw =
            if value.StartsWith("[", StringComparison.Ordinal) && value.EndsWith("]", StringComparison.Ordinal) then
                value.Substring(1, value.Length - 2)
            else value
        match IPAddress.TryParse raw with
        | true, address -> address.AddressFamily = System.Net.Sockets.AddressFamily.InterNetworkV6
        | _ -> false

    let private addressFamily value =
        if isIpv4 value then Some "ipv4"
        elif isIpv6 value then Some "ipv6"
        else None

    let private isMac (value: string) =
        if isNull value || value.Length <> 17 then false
        else
            ([ 2; 5; 8; 11; 14 ] |> List.forall (fun i -> value[i] = ':'))
            && ([ 0; 1; 3; 4; 6; 7; 9; 10; 12; 13; 15; 16 ] |> List.forall (fun i -> Uri.IsHexDigit value[i]))

    let private checkAddress family label (value: string) =
        let parts = value.Split('/')
        require (parts.Length <= 2 && parts[0] <> "") label "Invalid address or network."
        match addressFamily parts[0] with
        | Some actual ->
            family |> Option.iter (fun expected -> require (actual = expected) label "Address family does not match.")
            if parts.Length = 2 then
                let mask = parts[1]
                if actual = "ipv4" && isIpv4 mask then ()
                else
                    let maxPrefix = if actual = "ipv4" then 32 else 128
                    let prefix = parseInt label mask
                    require (prefix >= 0 && prefix <= maxPrefix) label "Invalid network prefix."
        | None -> fail label "Invalid IP address."

    let private checkAddressOrMac label value =
        if (addressFamily value |> Option.isSome) then ()
        elif value.Contains('/') then checkAddress None label value
        elif isMac value then ()
        else fail label "Expected an IP address, network, or MAC address."

    let private checkInterface label (value: string) =
        require (not (String.IsNullOrEmpty value) && value.Length <= 16) label "Invalid interface name."
        let wildcard = value = "+" || (value.EndsWith("+", StringComparison.Ordinal) && value.Length > 1)
        let baseName = if value = "+" then "" elif wildcard then value.Substring(0, value.Length - 1) else value
        let safeCharacter c = Char.IsAsciiLetterOrDigit c || List.contains c [ '_'; '-'; '.'; ':'; '@' ]
        require
            (not (baseName.Contains('+')) && (baseName |> Seq.forall safeCharacter))
            label
            "Interfaces must use safe native name characters; only a trailing '+' wildcard is accepted."
        value

    // Protocol aliases are resolved by the target firewalld parser, not this host.
    let private checkProtocol label (value: string) =
        require (not (String.IsNullOrEmpty value)) label "Protocol cannot be empty."
        match Int32.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture) with
        | true, number -> require (number >= 0 && number <= 255) label "Protocol number must be 0..255."
        | _ -> nativeName label [ '-'; '_'; '.' ] 64 value |> ignore


    let private checkTransport label value =
        require (List.contains value [ "tcp"; "udp"; "sctp"; "dccp" ]) label "Transport must be tcp, udp, sctp, or dccp."

    let private checkNativePort label (value: string) =
        require (not (String.IsNullOrEmpty value)) label "Port cannot be empty."
        let number (part: string) =
            match Int32.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture) with
            | true, n when n >= 0 && n <= 65535 -> Some n
            | _ -> None
        let digits (part: string) =
            not (String.IsNullOrEmpty part) && (part |> Seq.forall Char.IsAsciiDigit)
        let serviceName (name: string) =
            nativeName label [ '_'; '-' ] 64 name |> ignore
            require (not (name.EndsWith("-", StringComparison.Ordinal))) label "Invalid service port name."
        match value.Split('-') with
        | [| single |] ->
            match number single with
            | Some _ -> ()
            | None when digits single -> fail label "Port number must be 0..65535."
            | None -> serviceName single
        | [| first; last |] ->
            match number first, number last with
            | Some firstPort, Some lastPort ->
                require (firstPort <= lastPort) label "Reversed port range."
            | _ ->
                require (not (digits first && (number first |> Option.isNone)) && not (digits last && (number last |> Option.isNone))) label "Port range endpoint is out of range."
                serviceName value
        | parts ->
            require (not (parts |> Array.forall digits)) label "Invalid numeric port range."

    let private checkPortAndTransport (label: string) (attrs: Map<string, string>) =
        checkNativePort label (Map.find "port" attrs)
        checkTransport label (Map.find "protocol" attrs)

    let private checkNativeAttrs (label: string) (allowed: string list) (required: string list) (attrs: Map<string, string>) =
        require (not (isNull (box attrs))) label "Attribute map cannot be null."
        for KeyValue(key, value) in attrs do
            require (List.contains key allowed) label (label + " has an unsupported attribute '" + key + "'.")
            safeXmlAttribute (label + "." + key) value |> ignore
        for key in required do
            require (Map.containsKey key attrs) label (label + " requires attribute '" + key + "'.")

    let private attr (key: string) (attrs: Map<string, string>) = Map.tryFind key attrs

    let private requiredAttr (label: string) (key: string) (attrs: Map<string, string>) =
        match attr key attrs with
        | Some value -> value
        | None -> fail label (label + " requires attribute '" + key + "'.")

    let private checkEmptyNode (label: string) (node: Element) =
        require node.Text.IsNone label (label + " cannot contain text.")
        require node.Children.IsEmpty label (label + " cannot contain child elements.")

    let private checkMetadataNode (label: string) (node: Element) =
        checkNativeAttrs label [] [] node.Attributes
        require node.Children.IsEmpty label (label + " cannot contain child elements.")
        node.Text |> Option.iter (safeXmlString label >> ignore)

    let private checkServiceName label value = nativeReference "service" label value |> ignore
    let private checkIpSetName label value = nativeReference "ipset" label value |> ignore
    let private checkHelperName label value = nativeReference "helper" label value |> ignore
    let private checkIcmpName label value = nativeReference "icmptype" label value |> ignore

    let private parseBoolean label (value: string) =
        match value.ToLowerInvariant() with
        | "yes" | "true" -> true
        | "no" | "false" -> false
        | _ -> fail label "Boolean value must be yes, no, true, or false."

    let private checkRate label (value: string) =
        let parts = value.Split('/')
        require (parts.Length = 2) label "Rate limits use count/second, minute, hour, or day."
        let rate = parseInt label parts[0]
        let duration =
            match parts[1].Trim() with
            | "s" | "second" -> 1L
            | "m" | "minute" -> 60L
            | "h" | "hour" -> 3600L
            | "d" | "day" -> 86400L
            | _ -> fail label "Invalid rate limit duration."
        require (rate >= 1) label "Rate must be positive."
        require (not (rate = 1 && duration = 86400L)) label "A rate of 1/day is unsupported."
        require (10000L * duration / int64 rate > 0L) label "Rate is too fast."

    let private checkLimit (node: Element) =
        checkNativeAttrs "limit" [ "value"; "burst" ] [ "value" ] node.Attributes
        checkRate "limit" (requiredAttr "limit" "value" node.Attributes)
        attr "burst" node.Attributes
        |> Option.iter (fun value ->
            let burst = parseInt "limit" value
            require (burst >= 0 && burst <= 10000000) "limit" "Limit burst must be 0..10000000.")
        checkEmptyNode "limit" node

    let private checkRichSource (label: string) (family: string option) (destination: bool) (node: Element) =
        let allowed = if destination then [ "address"; "ipset"; "invert" ] else [ "address"; "mac"; "ipset"; "invert" ]
        checkNativeAttrs label allowed [] node.Attributes
        checkEmptyNode label node
        let address, mac, ipset = attr "address" node.Attributes, attr "mac" node.Attributes, attr "ipset" node.Attributes
        let count = [ address.IsSome; mac.IsSome; ipset.IsSome ] |> List.filter id |> List.length
        require (count = 1) label "Source and destination require exactly one selector."
        if destination then require family.IsSome label "An explicit rule family is required for a destination."
        match address with
        | Some value ->
            require family.IsSome label "An explicit rule family is required for an IP address."
            checkAddress family label value
        | None -> ()
        mac |> Option.iter (fun value -> require (not destination && isMac value) label "Invalid source MAC address.")
        ipset |> Option.iter (checkIpSetName label)
        attr "invert" node.Attributes |> Option.iter (parseBoolean label >> ignore)

    let private checkRichPort (label: string) (node: Element) =
        checkNativeAttrs label [ "port"; "protocol" ] [ "port"; "protocol" ] node.Attributes
        checkPortAndTransport label node.Attributes
        checkEmptyNode label node

    let private checkRichForwardPort (label: string) (family: string option) (node: Element) =
        checkNativeAttrs label [ "port"; "protocol"; "to-port"; "to-addr" ] [ "port"; "protocol" ] node.Attributes
        checkPortAndTransport label node.Attributes
        let toPort, toAddress = attr "to-port" node.Attributes, attr "to-addr" node.Attributes
        require (toPort.IsSome || toAddress.IsSome) label "Forward-port requires to-port or to-addr."
        require family.IsSome label "An explicit rule family is required for every rich forward-port."
        toPort |> Option.iter (checkNativePort label)
        toAddress
        |> Option.iter (fun value ->
            checkAddress family label value
            require (not (value.Contains('/'))) label "Forward-port destination must be a single address.")
        checkEmptyNode label node

    let private checkRichLimitChildren (label: string) (node: Element) =
        require (node.Children |> List.forall (fun child -> child.Name = "limit")) label (label + " only accepts a limit child.")
        require (node.Children.Length <= 1) label (label + " accepts at most one limit.")
        node.Children |> List.iter checkLimit
        node.Text |> Option.iter (fun _ -> fail label (label + " cannot contain text."))

    let private checkRichLog (node: Element) =
        let nflog = node.Name = "nflog"
        checkNativeAttrs node.Name (if nflog then [ "group"; "prefix"; "queue-size" ] else [ "prefix"; "level" ]) [] node.Attributes
        checkRichLimitChildren node.Name node
        attr "prefix" node.Attributes
        |> Option.iter (fun prefix -> require (prefix.Length <= 127) node.Name "Log prefix cannot exceed 127 characters.")
        if nflog then
            attr "group" node.Attributes |> Option.iter (parseUnsigned "nflog" 65535UL >> ignore)
            attr "queue-size" node.Attributes |> Option.iter (parseUnsigned "nflog" 65535UL >> ignore)
        else
            attr "level" node.Attributes
            |> Option.iter (fun level ->
                require (List.contains level [ "emerg"; "alert"; "crit"; "error"; "warning"; "notice"; "info"; "debug" ]) "log" "Invalid log level.")

    let private checkRichAction (family: string option) (node: Element) =
        let allowed, required =
            match node.Name with
            | "reject" -> [ "type" ], []
            | "mark" -> [ "set" ], [ "set" ]
            | _ -> [], []
        checkNativeAttrs node.Name allowed required node.Attributes
        checkRichLimitChildren node.Name node
        match attr "type" node.Attributes with
        | Some rejectType ->
            let valid =
                match family with
                | Some "ipv4" -> [ "icmp-host-prohibited"; "host-prohib"; "icmp-net-unreachable"; "net-unreach"; "icmp-host-unreachable"; "host-unreach"; "icmp-port-unreachable"; "port-unreach"; "icmp-proto-unreachable"; "proto-unreach"; "icmp-net-prohibited"; "net-prohib"; "tcp-reset"; "tcp-rst"; "icmp-admin-prohibited"; "admin-prohib" ]
                | Some "ipv6" -> [ "icmp6-adm-prohibited"; "adm-prohibited"; "icmp6-no-route"; "no-route"; "icmp6-addr-unreachable"; "addr-unreach"; "icmp6-port-unreachable"; "port-unreach"; "tcp-reset" ]
                | _ -> []
            require (List.contains rejectType valid) "reject" "Reject type requires a matching ipv4 or ipv6 family."
        | None -> ()
        attr "set" node.Attributes
        |> Option.iter (fun mark ->
            let parts = mark.Split('/')
            require (parts.Length <= 2) "mark" "Mark must be a value or value/mask."
            parts |> Array.iter (parseUnsigned "mark" 4294967295UL >> ignore))

    let private checkRichRule (node: Element) =
        checkNativeAttrs "rule" [ "family"; "priority" ] [] node.Attributes
        require node.Text.IsNone "rule" "Rich rules cannot contain text."
        let family = attr "family" node.Attributes
        family |> Option.iter (fun value -> require (value = "ipv4" || value = "ipv6") "rule" "Family must be ipv4 or ipv6.")
        let priority = attr "priority" node.Attributes |> Option.map (parseInt "rule") |> Option.defaultValue 0
        require (priority >= -32768 && priority <= 32767) "rule" "Rich-rule priority must be -32768..32767."
        let source = node.Children |> List.filter (fun child -> child.Name = "source")
        let destination = node.Children |> List.filter (fun child -> child.Name = "destination")
        let elementNames = [ "service"; "port"; "protocol"; "tcp-mss-clamp"; "icmp-block"; "icmp-type"; "masquerade"; "forward-port"; "source-port" ]
        let elements = node.Children |> List.filter (fun child -> List.contains child.Name elementNames)
        let logs = node.Children |> List.filter (fun child -> child.Name = "log" || child.Name = "nflog")
        let audits = node.Children |> List.filter (fun child -> child.Name = "audit")
        let actions = node.Children |> List.filter (fun child -> List.contains child.Name [ "accept"; "reject"; "drop"; "mark" ])
        require (source.Length <= 1 && destination.Length <= 1 && elements.Length <= 1 && logs.Length <= 1 && audits.Length <= 1 && actions.Length <= 1) "rule" "Rich-rule source, destination, element, log, audit, and action are singletons."
        let known = [ "source"; "destination"; "log"; "nflog"; "audit"; "accept"; "reject"; "drop"; "mark" ] @ elementNames
        require (node.Children |> List.forall (fun child -> List.contains child.Name known)) "rule" "Unsupported rich-rule child."
        source |> List.iter (checkRichSource "source" family false)
        destination |> List.iter (checkRichSource "destination" family true)
        for child in elements do
            match child.Name with
            | "service" ->
                checkNativeAttrs "service" [ "name" ] [ "name" ] child.Attributes
                checkServiceName "service" (requiredAttr "service" "name" child.Attributes)
                checkEmptyNode "service" child
            | "port" | "source-port" -> checkRichPort child.Name child
            | "protocol" ->
                checkNativeAttrs "protocol" [ "value" ] [ "value" ] child.Attributes
                checkProtocol "protocol" (requiredAttr "protocol" "value" child.Attributes)
                checkEmptyNode "protocol" child
            | "tcp-mss-clamp" ->
                checkNativeAttrs "tcp-mss-clamp" [ "value" ] [] child.Attributes
                attr "value" child.Attributes
                |> Option.iter (fun value ->
                    if value <> "None" && value <> "pmtu" then
                        let size = parseInt "tcp-mss-clamp" value
                        require (size >= 536) "tcp-mss-clamp" "TCP MSS clamp value must be at least 536.")
                checkEmptyNode "tcp-mss-clamp" child
            | "icmp-block" | "icmp-type" ->
                checkNativeAttrs child.Name [ "name" ] [ "name" ] child.Attributes
                checkIcmpName child.Name (requiredAttr child.Name "name" child.Attributes)
                checkEmptyNode child.Name child
            | "masquerade" ->
                checkNativeAttrs "masquerade" [] [] child.Attributes
                checkEmptyNode "masquerade" child
            | "forward-port" -> checkRichForwardPort "forward-port" family child
            | _ -> fail "rule" "Unsupported rich-rule element."
        logs |> List.iter checkRichLog
        for audit in audits do
            checkNativeAttrs "audit" [] [] audit.Attributes
            checkRichLimitChildren "audit" audit
        actions |> List.iter (checkRichAction family)
        let elementName = elements |> List.tryHead |> Option.map (fun child -> child.Name)
        let actionName = actions |> List.tryHead |> Option.map (fun child -> child.Name)
        if elementName.IsNone && (logs.IsEmpty || priority = 0) then
            require actionName.IsSome "rule" "Rich rule requires an action in this form."
            require (not (source.IsEmpty && destination.IsEmpty) || priority <> 0) "rule" "A priority-zero action-only rule needs a source or destination."
        let actionRequired = elementName |> Option.exists (fun name -> not (List.contains name [ "icmp-block"; "forward-port"; "masquerade"; "tcp-mss-clamp" ]))
        if actionRequired && logs.IsEmpty && audits.IsEmpty && actionName.IsNone then
            fail "rule" "Rich-rule element requires an action, log, or audit."
        match elementName, actionName with
        | Some ("masquerade" | "icmp-block" | "forward-port" | "tcp-mss-clamp"), Some _ ->
            fail "rule" "This rich-rule element cannot be combined with an action."
        | _ -> ()
        if not audits.IsEmpty then
            require (actionName |> Option.exists (fun name -> List.contains name [ "accept"; "reject"; "drop" ])) "rule" "Audit requires accept, reject, or drop."
        if elementName = Some "masquerade" then
            require (source |> List.forall (fun item -> not (Map.containsKey "mac" item.Attributes))) "rule" "Masquerade cannot use a MAC source."

    let private validateZonePolicyElement (kind: string) (node: Element) =
        match node.Name with
        | "short" | "description" -> checkMetadataNode node.Name node
        | "service" ->
            checkNativeAttrs "service" [ "name" ] [ "name" ] node.Attributes
            checkServiceName "service" (requiredAttr "service" "name" node.Attributes)
            checkEmptyNode "service" node
        | "port" | "source-port" ->
            checkNativeAttrs node.Name [ "port"; "protocol" ] [ "port"; "protocol" ] node.Attributes
            checkPortAndTransport node.Name node.Attributes
            checkEmptyNode node.Name node
        | "protocol" ->
            checkNativeAttrs "protocol" [ "value" ] [ "value" ] node.Attributes
            checkProtocol "protocol" (requiredAttr "protocol" "value" node.Attributes)
            checkEmptyNode "protocol" node
        | "icmp-block" ->
            checkNativeAttrs "icmp-block" [ "name" ] [ "name" ] node.Attributes
            checkIcmpName "icmp-block" (requiredAttr "icmp-block" "name" node.Attributes)
            checkEmptyNode "icmp-block" node
        | "masquerade" ->
            checkNativeAttrs "masquerade" (if kind = "zone" then [ "enabled" ] else []) [] node.Attributes
            attr "enabled" node.Attributes
            |> Option.iter (fun value -> require (parseBoolean "masquerade" value) "masquerade" "A disabled masquerade element is not supported.")
            checkEmptyNode "masquerade" node
        | "forward-port" ->
            checkNativeAttrs "forward-port" [ "port"; "protocol"; "to-port"; "to-addr" ] [ "port"; "protocol" ] node.Attributes
            checkPortAndTransport "forward-port" node.Attributes
            let toPort, toAddr = attr "to-port" node.Attributes, attr "to-addr" node.Attributes
            require (toPort.IsSome || toAddr.IsSome) "forward-port" "Forward-port requires to-port or to-addr."
            toPort |> Option.iter (checkNativePort "forward-port")
            toAddr |> Option.iter (fun value -> checkAddress None "forward-port" value; require (not (value.Contains('/'))) "forward-port" "Destination must be a single address.")
            checkEmptyNode "forward-port" node
        | "rule" -> checkRichRule node
        | "interface" when kind = "zone" ->
            checkNativeAttrs "interface" [ "name" ] [ "name" ] node.Attributes
            checkInterface "interface" (requiredAttr "interface" "name" node.Attributes) |> ignore
            checkEmptyNode "interface" node
        | "source" when kind = "zone" ->
            checkNativeAttrs "source" [ "address"; "ipset" ] [] node.Attributes
            let address, ipset = attr "address" node.Attributes, attr "ipset" node.Attributes
            require (address.IsSome <> ipset.IsSome) "source" "Zone source requires exactly one address or ipset."
            address |> Option.iter (checkAddressOrMac "source")
            ipset |> Option.iter (checkIpSetName "source")
            checkEmptyNode "source" node
        | "icmp-block-inversion" when kind = "zone" ->
            checkNativeAttrs "icmp-block-inversion" [] [] node.Attributes
            checkEmptyNode "icmp-block-inversion" node
        | "forward" when kind = "zone" ->
            checkNativeAttrs "forward" [] [] node.Attributes
            checkEmptyNode "forward" node
        | "ingress-zone" | "egress-zone" when kind = "policy" ->
            checkNativeAttrs node.Name [ "name" ] [ "name" ] node.Attributes
            let name = requiredAttr node.Name "name" node.Attributes
            nativeReference "zone" node.Name name |> ignore
            checkEmptyNode node.Name node
        | _ -> fail "elements" ("Unsupported " + kind + " element '" + node.Name + "'.")

    let private validIpSetTypes =
        [ "hash:ip"; "hash:ip,port"; "hash:ip,port,ip"; "hash:ip,port,net"; "hash:ip,mark"
          "hash:net"; "hash:net,net"; "hash:net,port"; "hash:net,port,net"; "hash:net,iface"; "hash:mac" ]

    let private icmpTypes =
        [ "0/0"; "3/0"; "3/1"; "3/2"; "3/3"; "3/4"; "3/5"; "3/6"; "3/7"; "3/9"; "3/10"; "3/11"; "3/12"; "3/13"; "3/14"; "3/15"; "4/0"; "5/0"; "5/1"; "5/2"; "5/3"; "8/0"; "9/0"; "10/0"; "11/0"; "11/1"; "12/0"; "12/1"; "13/0"; "14/0"; "17/0"; "18/0"
          "echo-reply"; "pong"; "network-unreachable"; "host-unreachable"; "protocol-unreachable"; "port-unreachable"; "fragmentation-needed"; "source-route-failed"; "network-unknown"; "host-unknown"; "network-prohibited"; "host-prohibited"; "TOS-network-unreachable"; "TOS-host-unreachable"; "communication-prohibited"; "host-precedence-violation"; "precedence-cutoff"; "source-quench"; "network-redirect"; "host-redirect"; "TOS-network-redirect"; "TOS-host-redirect"; "echo-request"; "ping"; "router-advertisement"; "router-solicitation"; "ttl-zero-during-transit"; "ttl-zero-during-reassembly"; "ip-header-bad"; "required-option-missing"; "timestamp-request"; "timestamp-reply"; "address-mask-request"; "address-mask-reply" ]

    let private icmpv6Types =
        [ "1/0"; "1/1"; "1/3"; "1/4"; "2/0"; "3/0"; "3/1"; "4/0"; "4/1"; "4/2"; "128/0"; "129/0"; "133/0"; "134/0"; "135/0"; "136/0"; "137/0"
          "no-route"; "communication-prohibited"; "address-unreachable"; "port-unreachable"; "packet-too-big"; "ttl-zero-during-transit"; "ttl-zero-during-reassembly"; "bad-header"; "unknown-header-type"; "unknown-option"; "echo-request"; "ping"; "echo-reply"; "pong"; "router-solicitation"; "router-advertisement"; "neighbour-solicitation"; "neigbour-solicitation"; "neighbour-advertisement"; "neigbour-advertisement"; "redirect" ]

    let private checkIpSetPort (family: string) (value: string) =
        match value.Split(':') with
        | [| protocol; item |] ->
            if protocol = "icmp" then
                require (family = "inet" && List.contains item icmpTypes) "entry" "Invalid IPv4 ICMP ipset entry."
            elif protocol = "icmpv6" || protocol = "ipv6-icmp" then
                require (family = "inet6" && List.contains item icmpv6Types) "entry" "Invalid IPv6 ICMP ipset entry."
            else
                checkProtocol "entry" protocol
                checkNativePort "entry" item
        | [| single |] -> checkNativePort "entry" single
        | _ -> fail "entry" "Invalid ipset port entry."

    let private checkIpSetAddress (family: string) (flag: string) (index: int) (typeName: string) (item: string) =
        let ipv4 = family <> "inet6"
        let plain (address: string) = if ipv4 then isIpv4 address else isIpv6 address
        let network (address: string) =
            let parts = address.Split('/')
            if parts.Length = 1 then plain address
            elif parts.Length = 2 && plain parts[0] then
                if ipv4 && isIpv4 parts[1] then true
                else
                    match Int32.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture) with
                    | true, prefix -> prefix >= 0 && prefix <= (if ipv4 then 32 else 128)
                    | _ -> false
            else false
        if flag = "ip" then
            if item.Contains("-") && ipv4 then
                let range = item.Split('-')
                require (index <= 1 && range.Length = 2 && plain range[0] && plain range[1]) "entry" "Invalid ipset address range."
            else
                require
                    (if ipv4 then item <> "0.0.0.0" && (if index = 0 then network item else plain item)
                     else plain item)
                    "entry"
                    "Invalid ipset address."
        else
            if item.Contains("-") then
                let range = item.Split('-')
                require (range.Length = 2 && plain range[0] && network range[1]) "entry" "Invalid ipset network range."
            else
                require (not (item.EndsWith("/0", StringComparison.Ordinal)) || (not ipv4 && index = 0 && typeName = "hash:net,iface")) "entry" "A /0 ipset network is not valid here."
                require (network item) "entry" "Invalid ipset network."

    let private checkIpSetEntry (typeName: string) (family: string) (entry: string) =
        let flags, values = typeName.Substring(5).Split(','), entry.Split(',')
        require (flags.Length = values.Length && flags.Length > 0) "entry" "Entry fields do not match the ipset type."
        for index in 0 .. flags.Length - 1 do
            let flag, item = flags[index], values[index]
            match flag with
            | "ip" | "net" -> checkIpSetAddress family flag index typeName item
            | "mac" -> require (isMac item && item <> "00:00:00:00:00:00") "entry" "Invalid ipset MAC address."
            | "port" -> checkIpSetPort family item
            | "mark" -> parseUnsigned "entry" 4294967295UL item |> ignore
            | "iface" ->
                checkInterface "entry" item |> ignore
                if typeName = "hash:net,iface" then
                    require (item.Length <= 15) "entry" "Interface names in hash:net,iface entries cannot exceed 15 characters."
            | _ -> fail "entry" "Unsupported ipset field."

    let rec private guardElement (node: Element) =
        require (not (isNull (box node))) "elements" "Native element cannot be null."
        require (not (String.IsNullOrEmpty node.Name)) "elements" "Native element name cannot be empty."
        require (not (isNull (box node.Attributes)) && not (isNull (box node.Children))) "elements" "Native element attributes and children cannot be null."
        node.Children |> List.iter guardElement

    let private validateNativeDefinition (kind: string) (c: Configuration) =
        let rootAttrs, rootRequired =
            match kind with
            | "zone" -> [ "target"; "version"; "ingress-priority"; "egress-priority" ], []
            | "policy" -> [ "target"; "version"; "priority" ], []
            | "service" | "icmptype" -> [ "version" ], []
            | "ipset" -> [ "type"; "version" ], [ "type" ]
            | "helper" -> [ "module"; "version"; "family" ], [ "module" ]
            | _ -> [], []
        checkNativeAttrs kind rootAttrs rootRequired c.Attributes
        attr "version" c.Attributes |> Option.iter (safeXmlString (kind + ".version") >> ignore)
        match kind, attr "target" c.Attributes with
        | "zone", Some target -> require (List.contains target [ "default"; "ACCEPT"; "DROP"; "%%REJECT%%" ]) "target" "Invalid zone target."
        | "policy", Some target -> require (List.contains target [ "CONTINUE"; "ACCEPT"; "DROP"; "REJECT" ]) "target" "Invalid policy target."
        | _ -> ()
        if kind = "zone" then
            for key in [ "ingress-priority"; "egress-priority" ] do
                attr key c.Attributes
                |> Option.iter (fun value ->
                    let priority = parseInt key value
                    require (priority >= -32768 && priority <= 32767) key "Zone priority must be -32768..32767.")
        if kind = "policy" then
            attr "priority" c.Attributes
            |> Option.iter (fun value ->
                let priority = parseInt "priority" value
                require (priority >= -32768 && priority <= 32767 && priority <> 0) "priority" "Policy priority must be -32768..32767, excluding zero.")
        match kind with
        | "service" ->
            let seenMetadata, seenFamilies, seenPorts, seenProtocols, seenSourcePorts, seenNames =
                ref Set.empty, ref Set.empty, ref Set.empty, ref Set.empty, ref Set.empty, ref Set.empty
            for node in c.Elements do
                match node.Name with
                | "short" | "description" ->
                    require (not ((!seenMetadata).Contains node.Name)) node.Name ("Duplicate " + node.Name + " element.")
                    seenMetadata := (!seenMetadata).Add node.Name
                    checkMetadataNode node.Name node
                | "port" ->
                    checkNativeAttrs "port" [ "port"; "protocol" ] [ "port"; "protocol" ] node.Attributes
                    let p, proto = requiredAttr "port" "port" node.Attributes, requiredAttr "port" "protocol" node.Attributes
                    if p = "" then
                        checkProtocol "port" proto
                        require (not ((!seenProtocols).Contains proto)) "port" "Duplicate service protocol."
                        seenProtocols := (!seenProtocols).Add proto
                    else
                        checkNativePort "port" p
                        checkTransport "port" proto
                        let key = p + "/" + proto
                        require (not ((!seenPorts).Contains key)) "port" "Duplicate service port."
                        seenPorts := (!seenPorts).Add key
                    checkEmptyNode "port" node
                | "protocol" ->
                    checkNativeAttrs "protocol" [ "value" ] [ "value" ] node.Attributes
                    let value = requiredAttr "protocol" "value" node.Attributes
                    checkProtocol "protocol" value
                    require (not ((!seenProtocols).Contains value)) "protocol" "Duplicate service protocol."
                    seenProtocols := (!seenProtocols).Add value
                    checkEmptyNode "protocol" node
                | "source-port" ->
                    checkNativeAttrs "source-port" [ "port"; "protocol" ] [ "port"; "protocol" ] node.Attributes
                    checkPortAndTransport "source-port" node.Attributes
                    let key = requiredAttr "source-port" "port" node.Attributes + "/" + requiredAttr "source-port" "protocol" node.Attributes
                    require (not ((!seenSourcePorts).Contains key)) "source-port" "Duplicate service source port."
                    seenSourcePorts := (!seenSourcePorts).Add key
                    checkEmptyNode "source-port" node
                | "destination" ->
                    checkNativeAttrs "destination" [ "ipv4"; "ipv6" ] [] node.Attributes
                    require (not node.Attributes.IsEmpty) "destination" "Destination requires an ipv4 or ipv6 address."
                    for KeyValue(family, value) in node.Attributes do
                        require (family = "ipv4" || family = "ipv6") "destination" "Invalid destination family."
                        checkAddress (Some family) "destination" value
                        require (not ((!seenFamilies).Contains family)) "destination" "Duplicate destination family."
                        seenFamilies := (!seenFamilies).Add family
                    checkEmptyNode "destination" node
                | "module" ->
                    checkNativeAttrs "module" [ "name" ] [ "name" ] node.Attributes
                    let value = requiredAttr "module" "name" node.Attributes
                    nativeName "module" [ '_'; '-' ] 128 value |> ignore
                    let moduleForUse = helperNameForModule value
                    require (moduleForUse.Length >= 2) "module" "Module name is too short."
                    require (not ((!seenNames).Contains ("module:" + value))) "module" "Duplicate service module."
                    seenNames := (!seenNames).Add("module:" + value)
                    checkEmptyNode "module" node
                | "include" ->
                    checkNativeAttrs "include" [ "service" ] [ "service" ] node.Attributes
                    let value = requiredAttr "include" "service" node.Attributes
                    checkServiceName "include" value
                    require (value <> c.Name) "include" "A service cannot include itself."
                    require (not ((!seenNames).Contains ("include:" + value))) "include" "Duplicate included service."
                    seenNames := (!seenNames).Add("include:" + value)
                    checkEmptyNode "include" node
                | "helper" ->
                    checkNativeAttrs "helper" [ "name" ] [ "name" ] node.Attributes
                    let value = requiredAttr "helper" "name" node.Attributes
                    checkHelperName "helper" value
                    require (not ((!seenNames).Contains ("helper:" + value))) "helper" "Duplicate service helper."
                    seenNames := (!seenNames).Add("helper:" + value)
                    checkEmptyNode "helper" node
                | _ -> fail "elements" ("Unsupported service element '" + node.Name + "'.")
        | "ipset" ->
            let typeName = requiredAttr "ipset" "type" c.Attributes
            require (List.contains typeName validIpSetTypes) "type" "Unsupported ipset type."
            let options = ref Map.empty<string, string>
            let entries = ResizeArray<string>()
            let seenMetadata = ref Set.empty<string>
            for node in c.Elements do
                match node.Name with
                | "short" | "description" ->
                    require (not ((!seenMetadata).Contains node.Name)) node.Name ("Duplicate " + node.Name + " element.")
                    seenMetadata := (!seenMetadata).Add node.Name
                    checkMetadataNode node.Name node
                | "option" ->
                    checkNativeAttrs "option" [ "name"; "value" ] [ "name" ] node.Attributes
                    let name = requiredAttr "option" "name" node.Attributes
                    let value = attr "value" node.Attributes |> Option.defaultValue ""
                    require (List.contains name [ "family"; "timeout"; "hashsize"; "maxelem" ]) "option" "Unsupported ipset option."
                    require (not (Map.containsKey name !options)) "option" "Duplicate ipset option."
                    require (value <> "") "option" "IpSet options require an explicit value."
                    if name = "family" then
                        require (value = "inet" || value = "inet6") "option" "IpSet family must be inet or inet6."
                        require (typeName <> "hash:mac") "option" "hash:mac does not support a family option."
                    else parseNonnegative "option" value |> ignore
                    options := Map.add name value !options
                    checkEmptyNode "option" node
                | "entry" ->
                    checkNativeAttrs "entry" [] [] node.Attributes
                    require node.Children.IsEmpty "entry" "IpSet entries cannot contain child elements."
                    let value = node.Text |> Option.defaultValue ""
                    require (value <> "") "entry" "IpSet entries cannot be empty."
                    safeXmlString "entry" value |> ignore
                    entries.Add value
                | _ -> fail "elements" ("Unsupported ipset element '" + node.Name + "'.")
            let family = Map.tryFind "family" !options |> Option.defaultValue "inet"
            let timeout = Map.tryFind "timeout" !options |> Option.defaultValue "0"
            require (timeout = "0" || entries.Count = 0) "entries" "IpSet entries cannot be declared with a nonzero timeout."
            Map.tryFind "maxelem" !options
            |> Option.iter (fun maxelem -> require (entries.Count <= parseNonnegative "maxelem" maxelem) "entries" "Entry count exceeds maxelem.")
            require (entries.Count = (entries |> Seq.distinct |> Seq.length)) "entries" "Duplicate ipset entry."
            for entry in entries do checkIpSetEntry typeName family entry
        | "icmptype" ->
            let seenMetadata, seenFamilies = ref Set.empty, ref Set.empty
            for node in c.Elements do
                match node.Name with
                | "short" | "description" ->
                    require (not ((!seenMetadata).Contains node.Name)) node.Name ("Duplicate " + node.Name + " element.")
                    seenMetadata := (!seenMetadata).Add node.Name
                    checkMetadataNode node.Name node
                | "destination" ->
                    checkNativeAttrs "destination" [ "ipv4"; "ipv6" ] [] node.Attributes
                    require (not node.Attributes.IsEmpty) "destination" "ICMP destination requires ipv4 or ipv6."
                    for KeyValue(family, value) in node.Attributes do
                        require (family = "ipv4" || family = "ipv6") "destination" "Invalid ICMP destination family."
                        require (List.contains (value.ToLowerInvariant()) [ "yes"; "true"; "no"; "false" ]) "destination" "ICMP destinations use yes/no or true/false."
                        require (not ((!seenFamilies).Contains family)) "destination" "Duplicate ICMP destination family."
                        seenFamilies := (!seenFamilies).Add family
                    checkEmptyNode "destination" node
                | _ -> fail "elements" ("Unsupported icmptype element '" + node.Name + "'.")
        | "helper" ->
            let moduleName = requiredAttr "helper" "module" c.Attributes
            require (moduleName.StartsWith("nf_conntrack_", StringComparison.Ordinal) && moduleName.Length > "nf_conntrack_".Length) "module" "Helper module must start with nf_conntrack_ and include a module name."
            nativeName "module" [ '_'; '-' ] 128 moduleName |> ignore
            attr "family" c.Attributes |> Option.iter (fun family -> require (family = "ipv4" || family = "ipv6") "family" "Helper family must be ipv4 or ipv6.")
            let seenMetadata, seenPorts = ref Set.empty, ref Set.empty
            for node in c.Elements do
                match node.Name with
                | "short" | "description" ->
                    require (not ((!seenMetadata).Contains node.Name)) node.Name ("Duplicate " + node.Name + " element.")
                    seenMetadata := (!seenMetadata).Add node.Name
                    checkMetadataNode node.Name node
                | "port" ->
                    checkNativeAttrs "port" [ "port"; "protocol" ] [ "port"; "protocol" ] node.Attributes
                    checkPortAndTransport "port" node.Attributes
                    let key = requiredAttr "port" "port" node.Attributes + "/" + requiredAttr "port" "protocol" node.Attributes
                    require (not ((!seenPorts).Contains key)) "port" "Duplicate helper port."
                    seenPorts := (!seenPorts).Add key
                    checkEmptyNode "port" node
                | _ -> fail "elements" ("Unsupported helper element '" + node.Name + "'.")
        | "zone" | "policy" ->
            let seenSingleton, seenKeys = ref Set.empty, ref Set.empty
            for node in c.Elements do
                validateZonePolicyElement kind node
                match node.Name with
                | "short" | "description" | "forward" | "icmp-block-inversion" | "masquerade" ->
                    require (not ((!seenSingleton).Contains node.Name)) node.Name ("Duplicate " + node.Name + " element.")
                    seenSingleton := (!seenSingleton).Add node.Name
                | "interface" | "source" | "service" | "port" | "protocol" | "icmp-block" | "source-port" | "ingress-zone" | "egress-zone" ->
                    let key = node.Name + ":" + (node.Attributes |> Map.toList |> List.map (fun (k, v) -> k + "=" + v) |> String.concat ";")
                    require (not ((!seenKeys).Contains key)) node.Name ("Duplicate " + node.Name + " element.")
                    seenKeys := (!seenKeys).Add key
                | _ -> ()
            let rules = c.Elements |> List.filter (fun node -> node.Name = "rule")
            require (rules.Length = (rules |> List.distinct |> List.length)) "rule" "Duplicate rich rule."
        | _ -> ()

    let private settingKeys =
        [ "DefaultZone"; "LogDenied"; "MinimalMark"; "CleanupOnExit"; "CleanupModulesOnExit"; "IPv6_rpfilter"; "IndividualCalls"
          "AutomaticHelpers"; "FirewallBackend"; "FlushAllOnReload"; "ReloadPolicy"; "RFC3964_IPv4"; "AllowZoneDrifting"
          "NftablesFlowtable"; "NftablesCounters"; "NftablesTableOwner"; "Lockdown" ]

    let private validateReloadPolicy (value: string) =
        let raw = value.Trim()
        if List.contains (raw.ToUpperInvariant()) [ "ACCEPT"; "REJECT"; "DROP" ] then ()
        else
            let entries = raw.Replace(';', ',').Split(',') |> Array.map (fun item -> item.Trim()) |> Array.filter (fun item -> item <> "")
            require (entries.Length > 0) "ReloadPolicy" "ReloadPolicy must contain a policy."
            let seen = ref Set.empty<string>
            for entry in entries do
                let parts = if entry.Contains('=') then entry.Split('=') else entry.Split(':')
                require (parts.Length = 2) "ReloadPolicy" "Invalid ReloadPolicy entry."
                let table, action = parts[0].Trim().ToUpperInvariant(), parts[1].Trim().ToUpperInvariant()
                require (List.contains table [ "INPUT"; "FORWARD"; "OUTPUT" ]) "ReloadPolicy" "Unknown ReloadPolicy table."
                require (List.contains action [ "ACCEPT"; "REJECT"; "DROP" ]) "ReloadPolicy" "Invalid ReloadPolicy action."
                require (not ((!seen).Contains table)) "ReloadPolicy" "Duplicate ReloadPolicy table."
                seen := (!seen).Add table

    let private validateSetting (key: string) (value: string) =
        safeXmlString key value |> ignore
        require (value <> "" && not (value.Contains('=')) && (value |> Seq.forall (Char.IsControl >> not))) key (key + " requires a nonempty line-safe value.")
        match key with
        | "DefaultZone" -> nativeReference "zone" key value |> ignore
        | "MinimalMark" -> parseInt key value |> ignore
        | "CleanupOnExit" | "CleanupModulesOnExit" | "IndividualCalls" | "FlushAllOnReload" | "RFC3964_IPv4"
        | "NftablesCounters" | "NftablesTableOwner" | "AllowZoneDrifting" | "Lockdown" -> parseBoolean key value |> ignore
        | "IPv6_rpfilter" ->
            require
                (List.contains (value.ToLowerInvariant()) [ "yes"; "true"; "no"; "false"; "strict"; "loose"; "strict-forward"; "loose-forward" ])
                key
                "Invalid IPv6_rpfilter value."
        | "LogDenied" -> require (List.contains value [ "all"; "unicast"; "broadcast"; "multicast"; "off" ]) key "Invalid LogDenied value."
        | "AutomaticHelpers" -> require (List.contains (value.ToLowerInvariant()) [ "yes"; "no"; "system" ]) key "Invalid AutomaticHelpers value."
        | "FirewallBackend" -> require (List.contains (value.ToLowerInvariant()) [ "nftables"; "iptables" ]) key "Invalid FirewallBackend value."
        | "ReloadPolicy" -> validateReloadPolicy value
        | "NftablesFlowtable" ->
            if value <> "off" then
                let interfaces = value.Split([| ' ' |], StringSplitOptions.RemoveEmptyEntries)
                require (interfaces.Length > 0 && not (interfaces |> Array.contains "off")) key "Flowtable requires off or an interface list."
                interfaces |> Array.iter (checkInterface key >> ignore)
                require (interfaces.Length = (interfaces |> Array.distinct |> Array.length)) key "Flowtable interface list cannot contain duplicates."
        | _ -> fail "settings" "Unsupported firewalld setting."

    let private legacyDefaults (c: Configuration) =
        c.Target = "CONTINUE" && c.Interfaces.IsEmpty && c.Services.IsEmpty && c.Ports.IsEmpty && c.Protocols.IsEmpty
        && not c.Masquerade && not c.Forward && c.Ingress.IsEmpty && c.Egress.IsEmpty && c.Priority = -1
        && c.StrictForwardPorts.IsNone

    let private validateLegacyFields (kind: string) (c: Configuration) =
        match kind with
        | "zone" | "policy" -> ()
        | "service" ->
            require (c.Target = "CONTINUE" && c.Interfaces.IsEmpty && c.Services.IsEmpty && not c.Masquerade && not c.Forward
                     && c.Ingress.IsEmpty && c.Egress.IsEmpty && c.Priority = -1 && c.StrictForwardPorts.IsNone) kind "Service objects cannot include zone, policy, or settings fields."
        | "helper" ->
            require (c.Target = "CONTINUE" && c.Interfaces.IsEmpty && c.Services.IsEmpty && c.Protocols.IsEmpty && not c.Masquerade
                     && not c.Forward && c.Ingress.IsEmpty && c.Egress.IsEmpty && c.Priority = -1 && c.StrictForwardPorts.IsNone) kind "Helper objects cannot include unrelated fields."
        | _ -> require (legacyDefaults c) kind "This native definition cannot include legacy zone or policy fields."
    let private legacyPortValue (value: string) (transport: string) =
        if not (List.contains transport [ "tcp"; "udp"; "sctp"; "dccp" ]) then None
        else
            let number (text: string) =
                match Int32.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture) with
                | true, portNumber when portNumber >= 1 && portNumber <= 65535 -> Some portNumber
                | _ -> None
            match value.Split('-') with
            | [| single |] ->
                match number single with
                | Some _ -> Some(port (value + "/" + transport))
                | None -> None
            | [| first; last |] ->
                match number first, number last with
                | Some firstPort, Some lastPort when lastPort >= firstPort -> Some(port (value + "/" + transport))
                | _ -> None
            | _ -> None

    let private canonicalizeLegacyFields (c: Configuration) =
        if c.Kind = "zone" || c.Kind = "policy" then
            let nativeInterfaces = c.Elements |> List.choose (fun node -> if node.Name = "interface" then Some(Map.find "name" node.Attributes) else None)
            let nativeServices = c.Elements |> List.choose (fun node -> if node.Name = "service" then Some(Map.find "name" node.Attributes) else None)
            let nativeProtocols = c.Elements |> List.choose (fun node -> if node.Name = "protocol" then Some(Map.find "value" node.Attributes) else None)
            let nativeIngress = c.Elements |> List.choose (fun node -> if node.Name = "ingress-zone" then Some(Map.find "name" node.Attributes) else None)
            let nativeEgress = c.Elements |> List.choose (fun node -> if node.Name = "egress-zone" then Some(Map.find "name" node.Attributes) else None)
            let nativePorts = c.Elements |> List.filter (fun node -> node.Name = "port")
            let portsConvertible =
                nativePorts
                |> List.forall (fun node -> legacyPortValue (Map.find "port" node.Attributes) (Map.find "protocol" node.Attributes) |> Option.isSome)
            let nativePortValues =
                if portsConvertible then
                    nativePorts |> List.choose (fun node -> legacyPortValue (Map.find "port" node.Attributes) (Map.find "protocol" node.Attributes))
                else []
            let target = Map.tryFind "target" c.Attributes |> Option.defaultValue c.Target
            let priority =
                if c.Kind = "policy" then Map.tryFind "priority" c.Attributes |> Option.map (parseInt "priority") |> Option.defaultValue c.Priority
                else c.Priority
            let attributes =
                let withoutTarget = Map.remove "target" c.Attributes
                if c.Kind = "policy" then Map.remove "priority" withoutTarget else withoutTarget
            let elements =
                c.Elements
                |> List.filter (fun node ->
                    match node.Name with
                    | "interface" | "service" | "protocol" | "masquerade" -> false
                    | "forward" when c.Kind = "zone" -> false
                    | "ingress-zone" | "egress-zone" when c.Kind = "policy" -> false
                    | "port" when portsConvertible -> false
                    | _ -> true)
            { c with
                Target = target
                Interfaces = (c.Interfaces @ nativeInterfaces) |> List.distinct |> List.sort
                Services = (c.Services @ nativeServices) |> List.distinct |> List.sort
                Ports = if portsConvertible then (c.Ports @ nativePortValues) |> List.distinct |> List.sort else c.Ports
                Protocols = (c.Protocols @ nativeProtocols) |> List.distinct |> List.sort
                Masquerade = c.Masquerade || (c.Elements |> List.exists (fun node -> node.Name = "masquerade"))
                Forward = c.Forward || (c.Kind = "zone" && (c.Elements |> List.exists (fun node -> node.Name = "forward")))
                Ingress = (c.Ingress @ nativeIngress) |> List.distinct |> List.sort
                Egress = (c.Egress @ nativeEgress) |> List.distinct |> List.sort
                Priority = priority
                Attributes = attributes
                Elements = elements }
        elif c.Kind = "service" then
            let protocolNodes = c.Elements |> List.choose (fun node -> if node.Name = "protocol" then Some(Map.find "value" node.Attributes) else None)
            let emptyPortProtocols =
                c.Elements
                |> List.choose (fun node ->
                    if node.Name = "port" && Map.find "port" node.Attributes = "" then Some(Map.find "protocol" node.Attributes)
                    else None)
            let nativePorts = c.Elements |> List.filter (fun node -> node.Name = "port" && Map.find "port" node.Attributes <> "")
            let portsConvertible =
                nativePorts
                |> List.forall (fun node -> legacyPortValue (Map.find "port" node.Attributes) (Map.find "protocol" node.Attributes) |> Option.isSome)
            let nativePortValues =
                if portsConvertible then
                    nativePorts |> List.choose (fun node -> legacyPortValue (Map.find "port" node.Attributes) (Map.find "protocol" node.Attributes))
                else []
            let elements =
                c.Elements
                |> List.filter (fun node ->
                    node.Name <> "protocol"
                    && not (node.Name = "port" && Map.find "port" node.Attributes = "")
                    && not (node.Name = "port" && portsConvertible))
            { c with
                Ports = if portsConvertible then (c.Ports @ nativePortValues) |> List.distinct |> List.sort else c.Ports
                Protocols = (c.Protocols @ protocolNodes @ emptyPortProtocols) |> List.distinct |> List.sort
                Elements = elements }
        elif c.Kind = "helper" then
            let nativePorts = c.Elements |> List.filter (fun node -> node.Name = "port")
            let portsConvertible =
                nativePorts
                |> List.forall (fun node -> legacyPortValue (Map.find "port" node.Attributes) (Map.find "protocol" node.Attributes) |> Option.isSome)
            let nativePortValues =
                if portsConvertible then
                    nativePorts |> List.choose (fun node -> legacyPortValue (Map.find "port" node.Attributes) (Map.find "protocol" node.Attributes))
                else []
            { c with
                Ports = if portsConvertible then (c.Ports @ nativePortValues) |> List.distinct |> List.sort else c.Ports
                Elements = if portsConvertible then c.Elements |> List.filter (fun node -> node.Name <> "port") else c.Elements }
        else c


    let validate (configuration: Configuration) =
        require (not (isNull (box configuration))) "configuration" "Configuration cannot be null."
        let c = configuration
        require (List.contains c.Kind [ "zone"; "policy"; "service"; "ipset"; "icmptype"; "helper"; "settings" ]) "kind" "Unsupported firewalld configuration kind."
        require (not (isNull (box c.Attributes)) && not (isNull (box c.Elements))) "configuration" "Native attributes and elements cannot be null."
        c.Elements |> List.iter guardElement
        if c.Kind = "settings" then
            require (c.Target = "CONTINUE" && c.Interfaces.IsEmpty && c.Services.IsEmpty && c.Ports.IsEmpty && c.Protocols.IsEmpty
                     && not c.Masquerade && not c.Forward && c.Ingress.IsEmpty && c.Egress.IsEmpty && c.Priority = -1) "settings" "Global settings cannot include zone or policy fields."
            require (c.Attributes.IsEmpty && c.Elements.IsEmpty) "settings" "Global settings cannot include native object attributes or elements."
            if c.Name = "strict-forward-ports" then
                require c.StrictForwardPorts.IsSome "settings" "StrictForwardPorts requires an explicit value."
                require c.SettingValue.IsNone "settings" "StrictForwardPorts is owned by the legacy setting resource."
            else
                require (List.contains c.Name settingKeys) "settings" "Unknown or separately-owned firewalld setting."
                require c.StrictForwardPorts.IsNone "settings" "StrictForwardPorts is owned by the legacy setting resource."
                require c.SettingValue.IsSome "settings" "Native settings require an explicit string value."
                c.SettingValue |> Option.iter (validateSetting c.Name)
            c
        else
            require c.StrictForwardPorts.IsNone "strictForwardPorts" "StrictForwardPorts is a global setting, not an object field."
            require c.SettingValue.IsNone "settingValue" "Only settings resources may include SettingValue."
            checkObjectName c.Kind c.Name
            validateLegacyFields c.Kind c
            if c.Kind = "zone" || c.Kind = "policy" then
                let targets = if c.Kind = "zone" then [ "default"; "ACCEPT"; "DROP"; "%%REJECT%%" ] else [ "CONTINUE"; "ACCEPT"; "DROP"; "REJECT" ]
                require (List.contains c.Target targets) "target" "Invalid firewalld target."
                let normalized label length values = values |> List.map (token label length) |> List.distinct |> List.sort
                let interfaces = c.Interfaces |> List.map (checkInterface "interface") |> List.distinct |> List.sort
                let services, protocols = normalizedReferences "service" c.Services, normalized "protocol" 128 c.Protocols
                protocols |> List.iter (checkProtocol "protocol")
                let ingress, egress = normalizedReferences "zone" c.Ingress, normalizedReferences "zone" c.Egress
                let nativeIngress = c.Elements |> List.filter (fun e -> e.Name = "ingress-zone") |> List.map (fun e -> Map.tryFind "name" e.Attributes |> Option.defaultValue "")
                let nativeEgress = c.Elements |> List.filter (fun e -> e.Name = "egress-zone") |> List.map (fun e -> Map.tryFind "name" e.Attributes |> Option.defaultValue "")
                if c.Kind = "zone" then
                    require (ingress.IsEmpty && egress.IsEmpty && c.Priority = -1) "zone" "Ingress, egress and priority belong to policies."
                    require (interfaces.IsEmpty || (c.Elements |> List.forall (fun e -> e.Name <> "interface"))) "interface" "Legacy and native interfaces cannot be combined."
                    require (services.IsEmpty || (c.Elements |> List.forall (fun e -> e.Name <> "service"))) "service" "Legacy and native services cannot be combined."
                    require (c.Ports.IsEmpty || (c.Elements |> List.forall (fun e -> e.Name <> "port"))) "port" "Legacy and native ports cannot be combined."
                    require (protocols.IsEmpty || (c.Elements |> List.forall (fun e -> e.Name <> "protocol"))) "protocol" "Legacy and native protocols cannot be combined."
                    require (not c.Masquerade || (c.Elements |> List.forall (fun e -> e.Name <> "masquerade"))) "masquerade" "Legacy and native masquerade cannot be combined."
                    require (not c.Forward || (c.Elements |> List.forall (fun e -> e.Name <> "forward"))) "forward" "Legacy and native forwarding cannot be combined."
                else
                    require (interfaces.IsEmpty && not c.Forward) "policy" "Policy does not support interfaces or zone forwarding."
                    require (services.IsEmpty || (c.Elements |> List.forall (fun e -> e.Name <> "service"))) "service" "Legacy and native services cannot be combined."
                    require (c.Ports.IsEmpty || (c.Elements |> List.forall (fun e -> e.Name <> "port"))) "port" "Legacy and native ports cannot be combined."
                    require (protocols.IsEmpty || (c.Elements |> List.forall (fun e -> e.Name <> "protocol"))) "protocol" "Legacy and native protocols cannot be combined."
                    require (not c.Masquerade || (c.Elements |> List.forall (fun e -> e.Name <> "masquerade"))) "masquerade" "Legacy and native masquerade cannot be combined."
                    require (ingress.IsEmpty || nativeIngress.IsEmpty) "ingress" "Legacy and native ingress zones cannot be combined."
                    require (egress.IsEmpty || nativeEgress.IsEmpty) "egress" "Legacy and native egress zones cannot be combined."
                    let effectiveIngress = if nativeIngress.IsEmpty then ingress else nativeIngress
                    let effectiveEgress = if nativeEgress.IsEmpty then egress else nativeEgress
                    let policyZones (values: string list) =
                        require (values.Length <= 1 || not (List.contains "ANY" values || List.contains "HOST" values)) "policy" "ANY and HOST cannot be combined with other zones."
                    policyZones effectiveIngress
                    policyZones effectiveEgress
                    require (not (effectiveIngress = [ "HOST" ] && effectiveEgress = [ "HOST" ])) "policy" "Both policy sides cannot be HOST."
                    require (c.Priority <> 0 && c.Priority >= -32768 && c.Priority <= 32767) "priority" "Policy priority must be -32768..32767, excluding zero."
                match Map.tryFind "target" c.Attributes with
                | Some _ -> require (c.Target = (if c.Kind = "zone" then "default" else "CONTINUE")) "target" "Legacy and native targets cannot be combined."
                | None -> ()
                if c.Kind = "policy" then
                    match Map.tryFind "priority" c.Attributes with
                    | Some _ -> require (c.Priority = -1) "priority" "Legacy and native priorities cannot be combined."
                    | None -> ()
                validateNativeDefinition c.Kind c
                if c.Kind = "policy" then
                    let ingress = if nativeIngress.IsEmpty then ingress else nativeIngress
                    let egress = if nativeEgress.IsEmpty then egress else nativeEgress
                    let richMasquerade =
                        c.Elements
                        |> List.exists (fun element -> element.Name = "rule" && (element.Children |> List.exists (fun child -> child.Name = "masquerade")))
                    let masquerade = c.Masquerade || (c.Elements |> List.exists (fun e -> e.Name = "masquerade")) || richMasquerade
                    require (not masquerade || not (List.contains "HOST" ingress || List.contains "HOST" egress)) "policy" "Masquerade cannot be used with HOST."
                    let forwardPorts =
                        c.Elements
                        |> List.collect (fun element ->
                            if element.Name = "forward-port" then [ element ]
                            elif element.Name = "rule" then element.Children |> List.filter (fun child -> child.Name = "forward-port")
                            else [])
                    let addressRequired = not egress.IsEmpty && not (List.contains "HOST" egress)
                    for forwardPort in forwardPorts do
                        require (not addressRequired || Map.containsKey "to-addr" forwardPort.Attributes) "forward-port" "Policy forward-ports need to-addr unless egress is HOST."
            else
                if c.Kind = "service" then
                    let ports = c.Ports |> List.map port |> List.distinct |> List.sort
                    let protocols = c.Protocols |> List.map (token "protocol" 128) |> List.distinct |> List.sort
                    protocols |> List.iter (checkProtocol "protocol")
                    let hasNativePorts =
                        c.Elements
                        |> List.exists (fun node -> node.Name = "port" && Map.tryFind "port" node.Attributes <> Some "")
                    require (ports.IsEmpty || not hasNativePorts) "port" "Legacy and native service ports cannot be combined."
                    let nativeProtocols =
                        c.Elements
                        |> List.exists (fun e -> e.Name = "protocol" || (e.Name = "port" && Map.tryFind "port" e.Attributes = Some ""))
                    require (protocols.IsEmpty || not nativeProtocols) "protocol" "Legacy and native service protocols cannot be combined."
                    validateNativeDefinition c.Kind c
                elif c.Kind = "helper" then
                    let ports = c.Ports |> List.map port |> List.distinct |> List.sort
                    require (ports.IsEmpty || (c.Elements |> List.forall (fun e -> e.Name <> "port"))) "port" "Legacy and native helper ports cannot be combined."
                    validateNativeDefinition c.Kind c
                else
                    require (c.Target = "CONTINUE" && c.Interfaces.IsEmpty && c.Services.IsEmpty && c.Ports.IsEmpty
                             && c.Protocols.IsEmpty && not c.Masquerade && not c.Forward && c.Ingress.IsEmpty
                             && c.Egress.IsEmpty && c.Priority = -1) c.Kind "This native definition cannot include legacy zone or policy fields."
                    validateNativeDefinition c.Kind c
            let normalized =
                if c.Kind = "zone" || c.Kind = "policy" then
                    let normalizedList label length values = values |> List.map (token label length) |> List.distinct |> List.sort
                    { c with Interfaces = c.Interfaces |> List.map (checkInterface "interface") |> List.distinct |> List.sort
                             Services = normalizedReferences "service" c.Services
                             Ports = c.Ports |> List.map port |> List.distinct |> List.sort
                             Protocols = normalizedList "protocol" 128 c.Protocols
                             Ingress = normalizedReferences "zone" c.Ingress
                             Egress = normalizedReferences "zone" c.Egress }
                elif c.Kind = "service" then
                    { c with Ports = c.Ports |> List.map port |> List.distinct |> List.sort
                             Protocols = c.Protocols |> List.map (token "protocol" 128) |> List.distinct |> List.sort }
                elif c.Kind = "helper" then
                    { c with Ports = c.Ports |> List.map port |> List.distinct |> List.sort }
                else c
            canonicalizeLegacyFields normalized

    let settingKey (configuration: Configuration) =
        let c = validate configuration
        require (c.Kind = "settings") "settings" "settingKey requires a settings resource."
        if c.Name = "strict-forward-ports" then "StrictForwardPorts" else c.Name

    let references (configuration: Configuration) =
        let c = validate configuration
        let refs = ResizeArray<string * string>()
        let add kind name = refs.Add((kind, name))
        if c.Kind = "zone" || c.Kind = "policy" then
            c.Services |> List.iter (add "service")
            for zone in c.Ingress @ c.Egress do
                if zone <> "HOST" && zone <> "ANY" then add "zone" zone
        if c.Kind = "settings" && c.Name = "DefaultZone" then
            c.SettingValue |> Option.iter (add "zone")
        let rec visit (node: Element) =
            match node.Name with
            | "service" -> attr "name" node.Attributes |> Option.iter (add "service")
            | "include" -> attr "service" node.Attributes |> Option.iter (add "service")
            | "helper" when c.Kind = "service" -> attr "name" node.Attributes |> Option.iter (add "helper")
            | "module" when c.Kind = "service" ->
                attr "name" node.Attributes
                |> Option.iter (helperNameForModule >> add "helper")
            | "icmp-block" | "icmp-type" -> attr "name" node.Attributes |> Option.iter (add "icmptype")
            | "source" | "destination" -> attr "ipset" node.Attributes |> Option.iter (add "ipset")
            | "ingress-zone" | "egress-zone" ->
                attr "name" node.Attributes |> Option.iter (fun name -> if name <> "HOST" && name <> "ANY" then add "zone" name)
            | _ -> ()
            node.Children |> List.iter visit
        c.Elements |> List.iter visit
        refs |> Seq.distinct |> Seq.sort |> Seq.toList

    let rec private elementToJson (element: Element) : JsonObject =
        let result = JsonObject()
        result["name"] <- JsonValue.Create element.Name
        let attributes = JsonObject()
        for KeyValue(key, value) in element.Attributes do attributes[key] <- JsonValue.Create value
        result["attributes"] <- attributes
        match element.Text with
        | Some value -> result["text"] <- JsonValue.Create value
        | None -> result["text"] <- null
        let children = JsonArray()
        for child in element.Children do children.Add(elementToJson child)
        result["children"] <- children
        result

    let toJson (configuration: Configuration) =
        let c = validate configuration
        let result = JsonObject()
        for name, value in [ "kind", c.Kind; "name", c.Name; "target", c.Target ] do
            result[name] <- JsonValue.Create value
        for name, values in [ "interfaces", c.Interfaces; "services", c.Services; "ports", c.Ports; "protocols", c.Protocols; "ingress", c.Ingress; "egress", c.Egress ] do
            let array = JsonArray()
            for value in values do array.Add(JsonValue.Create value)
            result[name] <- array
        result["masquerade"] <- JsonValue.Create c.Masquerade
        result["forward"] <- JsonValue.Create c.Forward
        c.StrictForwardPorts |> Option.iter (fun value -> result["strictForwardPorts"] <- JsonValue.Create value)
        result["priority"] <- JsonValue.Create c.Priority
        if not c.Attributes.IsEmpty then
            let attributes = JsonObject()
            for KeyValue(key, value) in c.Attributes do attributes[key] <- JsonValue.Create value
            result["attributes"] <- attributes
        if not c.Elements.IsEmpty then
            let elements = JsonArray()
            for element in c.Elements do elements.Add(elementToJson element)
            result["elements"] <- elements
        c.SettingValue |> Option.iter (fun value -> result["settingValue"] <- JsonValue.Create value)
        result.ToJsonString()

    let private jsonString label (value: JsonElement) =
        require (value.ValueKind = JsonValueKind.String) label (label + " must be a string.")
        let result = value.GetString()
        require (not (isNull result)) label (label + " cannot be null.")
        result

    let private jsonStrings label (value: JsonElement) =
        require (value.ValueKind = JsonValueKind.Array) label (label + " must be an array.")
        value.EnumerateArray() |> Seq.map (jsonString label) |> Seq.toList

    let private jsonMap label (value: JsonElement) =
        require (value.ValueKind = JsonValueKind.Object) label (label + " must be an object.")
        let pairs, seen = ResizeArray<string * string>(), ref Set.empty<string>
        for property in value.EnumerateObject() do
            require (not ((!seen).Contains property.Name)) label (label + " contains a duplicate key.")
            seen := (!seen).Add property.Name
            pairs.Add((property.Name, jsonString label property.Value))
        Map.ofSeq pairs

    let private elementFromJson (value: JsonElement) : Element =
        let rec parseElement (node: JsonElement) : Element =
            require (node.ValueKind = JsonValueKind.Object) "elements" "Every element must be an object."
            let expected = set [ "name"; "attributes"; "text"; "children" ]
            let properties = node.EnumerateObject() |> Seq.map (fun property -> property.Name) |> Seq.toList
            require (properties.Length = (properties |> List.distinct |> List.length)) "elements" "An element contains duplicate fields."
            require (Set.ofList properties = expected) "elements" "Every element requires exactly name, attributes, text, and children."
            let textValue = node.GetProperty("text")
            let text = if textValue.ValueKind = JsonValueKind.Null then None else Some(jsonString "elements.text" textValue)
            let children = node.GetProperty("children")
            require (children.ValueKind = JsonValueKind.Array) "elements.children" "Element children must be an array."
            { Name = jsonString "elements.name" (node.GetProperty("name"))
              Attributes = jsonMap "elements.attributes" (node.GetProperty("attributes"))
              Text = text
              Children = children.EnumerateArray() |> Seq.map parseElement |> Seq.toList }
        parseElement value

    let parse (text: string) =
        use document = JsonDocument.Parse text
        let root = document.RootElement
        require (root.ValueKind = JsonValueKind.Object) "configuration" "Firewalld configuration must be an object."
        let expected = set [ "kind"; "name"; "target"; "interfaces"; "services"; "ports"; "protocols"; "ingress"; "egress"; "masquerade"; "forward"; "priority" ]
        let optional = set [ "strictForwardPorts"; "attributes"; "elements"; "settingValue" ]
        let allProperties = root.EnumerateObject() |> Seq.map (fun property -> property.Name) |> Seq.toList
        require (allProperties.Length = (allProperties |> List.distinct |> List.length)) "configuration" "Firewalld configuration contains duplicate fields."
        let properties = Set.ofList allProperties
        require (Set.isSubset expected properties && Set.isSubset properties (Set.union expected optional)) "configuration" "Firewalld configuration requires exactly the documented fields."
        let str (name: string) = jsonString name (root.GetProperty name)
        let bool (name: string) =
            let value = root.GetProperty name
            require (value.ValueKind = JsonValueKind.True || value.ValueKind = JsonValueKind.False) name (name + " must be a boolean.")
            value.GetBoolean()
        let int (name: string) =
            let value = root.GetProperty name
            let mutable number = 0
            require (value.ValueKind = JsonValueKind.Number && value.TryGetInt32(&number)) name (name + " must be a 32-bit integer.")
            number
        let strings (name: string) = jsonStrings name (root.GetProperty name)
        let strictForwardPorts = if properties.Contains "strictForwardPorts" then Some(bool "strictForwardPorts") else None
        let attributes = if properties.Contains "attributes" then jsonMap "attributes" (root.GetProperty "attributes") else Map.empty
        let elements =
            if properties.Contains "elements" then
                let value = root.GetProperty "elements"
                require (value.ValueKind = JsonValueKind.Array) "elements" "Elements must be an array."
                value.EnumerateArray() |> Seq.map elementFromJson |> Seq.toList
            else []
        let settingValue = if properties.Contains "settingValue" then Some(str "settingValue") else None
        validate
            { Kind = str "kind"; Name = str "name"; Target = str "target"
              Interfaces = strings "interfaces"; Services = strings "services"; Ports = strings "ports"; Protocols = strings "protocols"
              Ingress = strings "ingress"; Egress = strings "egress"
              Masquerade = bool "masquerade"; Forward = bool "forward"
              Priority = int "priority"; StrictForwardPorts = strictForwardPorts
              Attributes = attributes; Elements = elements; SettingValue = settingValue }
