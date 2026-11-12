#if HOST_HELPER
namespace Dorothy.HostHelper
#else
namespace Dorothy.DSL
#endif

open System
open System.Globalization
open System.Text.Json
open System.Text.Json.Nodes

/// Shared, reflection-free wire contract used by the DSL, provider and native helper.
module FirewalldModel =
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
          Priority: int }

    let empty kind name =
        { Kind = kind; Name = name; Target = if kind = "zone" then "default" else "CONTINUE"
          Interfaces = []; Services = []; Ports = []; Protocols = []; Masquerade = false
          Forward = false; Ingress = []; Egress = []; Priority = -1 }

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
        (if first = last then string first else sprintf "%d-%d" first last) + "/" + parts[1]

    let validate (c: Configuration) =
        if c.Kind <> "zone" && c.Kind <> "policy" then invalidArg "kind" "Expected zone or policy."
        token "name" (if c.Kind = "zone" then 17 else 128) c.Name |> ignore
        if c.Name.Contains('.') then invalidArg "name" "Zone and policy names cannot contain dots."
        let targets = if c.Kind = "zone" then [ "default"; "ACCEPT"; "DROP"; "%%REJECT%%" ] else [ "CONTINUE"; "ACCEPT"; "DROP"; "REJECT" ]
        if not (List.contains c.Target targets) then invalidArg "target" "Invalid firewalld target."
        let normalized label length values = values |> List.map (token label length) |> List.distinct |> List.sort
        let interfaces = normalized "interface" 15 c.Interfaces
        let services = normalized "service" 128 c.Services
        let protocols = normalized "protocol" 128 c.Protocols
        let zones values =
            values |> List.map (fun value -> if value = "ANY" || value = "HOST" then value else token "zone" 17 value)
            |> List.distinct |> List.sort
        let ingress, egress = zones c.Ingress, zones c.Egress
        if c.Kind = "zone" && (not ingress.IsEmpty || not egress.IsEmpty || c.Priority <> -1) then
            invalidArg "zone" "Ingress, egress and priority belong to policies."
        if c.Kind = "policy" then
            if not interfaces.IsEmpty || not services.IsEmpty || not c.Ports.IsEmpty || not protocols.IsEmpty || c.Forward then
                invalidArg "policy" "Policy supports only ingress, egress, target, priority and masquerade."
            if ingress.IsEmpty || egress.IsEmpty then invalidArg "policy" "Policy requires ingress and egress zones."
            for values in [ ingress; egress ] do
                if values.Length > 1 && (List.contains "ANY" values || List.contains "HOST" values) then
                    invalidArg "policy" "ANY and HOST cannot be combined with other zones."
            if ingress = [ "HOST" ] && egress = [ "HOST" ] then invalidArg "policy" "Both policy sides cannot be HOST."
            if c.Priority = 0 || c.Priority < -32768 || c.Priority > 32767 then
                invalidArg "priority" "Policy priority must be -32768..32767, excluding zero."
        { c with Interfaces = interfaces; Services = services; Ports = c.Ports |> List.map port |> List.distinct |> List.sort
                 Protocols = protocols; Ingress = ingress; Egress = egress }

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
        result["priority"] <- JsonValue.Create c.Priority
        result.ToJsonString()

    let parse (text: string) =
        use document = JsonDocument.Parse text
        let root = document.RootElement
        let expected = set [ "kind"; "name"; "target"; "interfaces"; "services"; "ports"; "protocols"; "ingress"; "egress"; "masquerade"; "forward"; "priority" ]
        let properties = root.EnumerateObject() |> Seq.toArray
        if properties.Length <> expected.Count || (properties |> Seq.map (fun p -> p.Name) |> Set.ofSeq) <> expected then
            invalidArg "configuration" "Firewalld configuration requires exactly the documented fields."
        let str name = root.GetProperty(name: string).GetString()
        let strings name = root.GetProperty(name: string).EnumerateArray() |> Seq.map (fun v -> v.GetString()) |> Seq.toList
        validate
            { Kind = str "kind"; Name = str "name"; Target = str "target"
              Interfaces = strings "interfaces"; Services = strings "services"; Ports = strings "ports"; Protocols = strings "protocols"
              Ingress = strings "ingress"; Egress = strings "egress"
              Masquerade = root.GetProperty("masquerade").GetBoolean(); Forward = root.GetProperty("forward").GetBoolean()
              Priority = root.GetProperty("priority").GetInt32() }
