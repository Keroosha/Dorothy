namespace Dorothy.DSL.Provider

open System
open System.Collections.Generic
open System.Globalization
open System.IO
open System.Net
open System.Net.Sockets
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks

type Fail2BanConfig =
    { Enabled: bool
      MaxRetry: int
      FindTimeSeconds: int
      BanTimeSeconds: int
      IgnoreIps: string list
      Ports: int list }

type Fail2BanSnapshot =
    { Owned: bool
      Active: bool
      ActualPorts: int list
      ActualMaxRetry: int
      ActualFindTimeSeconds: int
      ActualBanTimeSeconds: int
      ActualIgnoreIps: string list
      InSync: bool }

module Fail2BanBackend =
    let tryCanonicalIgnoreIp (value: string) =
        if String.IsNullOrWhiteSpace(value) || value <> value.Trim() || value.Contains('%') then
            None
        else
            let parts = value.Split('/')
            if parts.Length < 1 || parts.Length > 2 then
                None
            else
                let mutable address = Unchecked.defaultof<IPAddress>
                if not (IPAddress.TryParse(parts[0], &address)) then
                    None
                else
                    let prefixMaximum =
                        match address.AddressFamily with
                        | AddressFamily.InterNetwork -> 32
                        | AddressFamily.InterNetworkV6 -> 128
                        | _ -> -1
                    if prefixMaximum < 0 then
                        None
                    elif parts.Length = 1 then
                        let canonicalAddress =
                            if address.IsIPv4MappedToIPv6 then address.MapToIPv4()
                            else address
                        if canonicalAddress.Equals(IPAddress.Any) || canonicalAddress.Equals(IPAddress.IPv6Any) then
                            None
                        else
                            Some(canonicalAddress.ToString().ToLowerInvariant())
                    elif address.IsIPv4MappedToIPv6 then
                        None
                    else
                        let mutable prefix = 0
                        if not (Int32.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, &prefix))
                           || prefix < 1
                           || prefix > prefixMaximum then
                            None
                        else
                            let bytes = address.GetAddressBytes()
                            let mutable remaining = prefix
                            for index in 0 .. bytes.Length - 1 do
                                let mask =
                                    if remaining >= 8 then 255
                                    elif remaining <= 0 then 0
                                    else (255 <<< (8 - remaining)) &&& 255
                                bytes[index] <- bytes[index] &&& byte mask
                                remaining <- max 0 (remaining - 8)
                            let networkAddress = IPAddress(bytes)
                            if (prefix = prefixMaximum)
                               && (networkAddress.Equals(IPAddress.Any) || networkAddress.Equals(IPAddress.IPv6Any)) then
                                None
                            else
                                Some(networkAddress.ToString().ToLowerInvariant() + "/" + prefix.ToString(CultureInfo.InvariantCulture))

    let tryCanonicalIgnoreIps (values: string list) =
        let result = ResizeArray<string>()
        let seen = HashSet<string>(StringComparer.Ordinal)
        let mutable valid = true
        for value in values do
            match tryCanonicalIgnoreIp value with
            | Some canonical when seen.Add(canonical) -> result.Add(canonical)
            | _ -> valid <- false
        if valid then Some(List.ofSeq result) else None

    let private serializePayload (operation: string) (ownerId: string) (config: Fail2BanConfig) (ports: int list) =
        use stream = new MemoryStream()
        use writer = new Utf8JsonWriter(stream)
        writer.WriteStartObject()
        writer.WriteString("operation", operation)
        writer.WriteString("ownerId", ownerId)
        writer.WriteBoolean("enabled", config.Enabled)
        writer.WriteNumber("maxRetry", config.MaxRetry)
        writer.WriteNumber("findTimeSeconds", config.FindTimeSeconds)
        writer.WriteNumber("banTimeSeconds", config.BanTimeSeconds)
        writer.WriteStartArray("ignoreIps")
        for ignoreIp in config.IgnoreIps do
            writer.WriteStringValue(ignoreIp)
        writer.WriteEndArray()
        writer.WriteStartArray("ports")
        for port in ports do
            writer.WriteNumberValue(port)
        writer.WriteEndArray()
        writer.WriteEndObject()
        writer.Flush()
        Encoding.UTF8.GetString(stream.GetBuffer(), 0, int stream.Length)

    let parseSnapshot (output: string) =
        try
            use document = JsonDocument.Parse(output)
            let root = document.RootElement
            if root.ValueKind <> JsonValueKind.Object then
                raise (FormatException("Remote Fail2Ban result must be a JSON object."))

            let properties = root.EnumerateObject() |> Seq.toArray
            let expectedProperties =
                Set.ofList
                    [ "owned"
                      "active"
                      "actualPorts"
                      "actualMaxRetry"
                      "actualFindTimeSeconds"
                      "actualBanTimeSeconds"
                      "actualIgnoreIps"
                      "inSync" ]
            let propertyNames = properties |> Array.map (fun property -> property.Name) |> Set.ofArray
            if properties.Length <> expectedProperties.Count || propertyNames <> expectedProperties then
                raise (FormatException("Remote Fail2Ban result must contain only the ownership and synchronization snapshot fields."))

            let readBoolean (name: string) =
                let value = root.GetProperty(name)
                if value.ValueKind <> JsonValueKind.True && value.ValueKind <> JsonValueKind.False then
                    raise (FormatException("Remote Fail2Ban " + name + " must be a boolean."))
                value.GetBoolean()

            let readInt (name: string) =
                let value = root.GetProperty(name)
                let mutable number = 0
                if value.ValueKind <> JsonValueKind.Number || not (value.TryGetInt32(&number)) then
                    raise (FormatException("Remote Fail2Ban " + name + " must be a 32-bit integer."))
                number

            let actualPortsElement = root.GetProperty("actualPorts")
            if actualPortsElement.ValueKind <> JsonValueKind.Array then
                raise (FormatException("Remote Fail2Ban actualPorts must be a JSON array."))
            let actualPorts = ResizeArray<int>()
            let seenPorts = HashSet<int>()
            for item in actualPortsElement.EnumerateArray() do
                let mutable port = 0
                if item.ValueKind <> JsonValueKind.Number || not (item.TryGetInt32(&port)) || port < 1 || port > 65535 then
                    raise (FormatException("Remote Fail2Ban actualPorts must contain integers from 1 through 65535."))
                if not (seenPorts.Add(port)) then
                    raise (FormatException("Remote Fail2Ban actualPorts contains a duplicate port."))
                actualPorts.Add(port)
 

            let actualIgnoreIpsElement = root.GetProperty("actualIgnoreIps")
            if actualIgnoreIpsElement.ValueKind <> JsonValueKind.Array then
                raise (FormatException("Remote Fail2Ban actualIgnoreIps must be a JSON array."))
            let rawIgnoreIps = ResizeArray<string>()
            for item in actualIgnoreIpsElement.EnumerateArray() do
                if item.ValueKind <> JsonValueKind.String then
                    raise (FormatException("Remote Fail2Ban actualIgnoreIps entries must be strings."))
                match item.GetString() with
                | null -> raise (FormatException("Remote Fail2Ban actualIgnoreIps entries must not be null."))
                | value when String.IsNullOrWhiteSpace(value) || (value |> Seq.exists (fun character -> Char.IsControl(character) || Char.IsWhiteSpace(character))) ->
                    raise (FormatException("Remote Fail2Ban actualIgnoreIps entries must be non-empty tokens."))
                | value -> rawIgnoreIps.Add(value)

            let actualIgnoreIps = List.ofSeq rawIgnoreIps

            let owned = readBoolean "owned"
            let active = readBoolean "active"
            let actualMaxRetry = readInt "actualMaxRetry"
            let actualFindTimeSeconds = readInt "actualFindTimeSeconds"
            let actualBanTimeSeconds = readInt "actualBanTimeSeconds"
            let inSync = readBoolean "inSync"

            { Owned = owned
              Active = active
              ActualPorts = List.ofSeq actualPorts
              ActualMaxRetry = actualMaxRetry
              ActualFindTimeSeconds = actualFindTimeSeconds
              ActualBanTimeSeconds = actualBanTimeSeconds
              ActualIgnoreIps = actualIgnoreIps
              InSync = inSync }
        with
        | :? JsonException as error ->
            raise (InvalidOperationException("Remote Fail2Ban helper returned invalid JSON.", error))
        | :? FormatException as error ->
            raise (InvalidOperationException("Remote Fail2Ban helper returned an invalid snapshot.", error))

    let private parseDeleteResult (output: string) =
        try
            use document = JsonDocument.Parse(output)
            let root = document.RootElement
            if root.ValueKind <> JsonValueKind.Object || not (root.EnumerateObject() |> Seq.isEmpty) then
                raise (FormatException("Remote Fail2Ban delete result must be an empty JSON object."))
        with
        | :? JsonException as error ->
            raise (InvalidOperationException("Remote Fail2Ban helper returned invalid delete JSON.", error))
        | :? FormatException as error ->
            raise (InvalidOperationException("Remote Fail2Ban helper returned an invalid delete result.", error))

    let private invoke (connection: SshConnection) (operation: string) (ownerId: string) (config: Fail2BanConfig) (ports: int list) (cancellationToken: CancellationToken) =
        task {
            let payload = serializePayload operation ownerId config ports
            let! output = SshTransport.runHelper connection "fail2ban" "Fail2Ban" payload cancellationToken
            return parseSnapshot output
        }

    let read
        (connection: SshConnection)
        (ownerId: string)
        (config: Fail2BanConfig)
        (cancellationToken: CancellationToken)
        : Task<Fail2BanSnapshot> =
        invoke connection "read" ownerId config [] cancellationToken

    let apply
        (connection: SshConnection)
        (ownerId: string)
        (config: Fail2BanConfig)
        (cancellationToken: CancellationToken)
        : Task<Fail2BanSnapshot> =
        invoke connection "apply" ownerId config config.Ports cancellationToken

    let delete
        (connection: SshConnection)
        (ownerId: string)
        (config: Fail2BanConfig)
        (cancellationToken: CancellationToken)
        : Task<unit> =
        task {
            let payload = serializePayload "delete" ownerId config []
            let! output = SshTransport.runHelper connection "fail2ban" "Fail2Ban" payload cancellationToken
            parseDeleteResult output
        }
