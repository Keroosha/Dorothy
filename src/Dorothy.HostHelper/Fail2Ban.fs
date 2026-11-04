namespace Dorothy.HostHelper

open System
open System.Collections.Generic
open System.Globalization
open System.IO
open System.Net
open System.Runtime.InteropServices
open System.Security.Cryptography
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open System.Text.RegularExpressions

module Fail2Ban =
    type BackendError(message: string) =
        inherit InvalidOperationException(message)

    [<Struct>]
    type private Desired =
        { OwnerId: string
          Enabled: bool
          MaxRetry: int
          FindTimeSeconds: int
          BanTimeSeconds: int
          IgnoreIps: string array
          RequestedPorts: int array }

    type private PendingMutation =
        { Operation: string
          PriorContent: string option
          TargetContent: string option }

    type private Journal =
        { OwnerId: string
          ManagedContent: string option
          Pending: PendingMutation option }

    type private ParsedFile =
        { Enabled: bool option
          MaxRetry: int option
          FindTimeSeconds: int option
          BanTimeSeconds: int option
          Ports: int array option
          IgnoreIps: string array option
          Filter: string option
          Backend: string option
          UseDns: string option
          Banaction: string option }

    type private DumpPolicy =
        { Enabled: bool
          MaxRetry: int
          FindTimeSeconds: int
          BanTimeSeconds: int
          Ports: int array
          IgnoreIps: string array
          Backend: string
          ActionNames: string array
          ActionName: string
          Banaction: string
          ActionType: string
          ActionProtocol: string
          ActionStart: string
          ActionStop: string
          ActionCheck: string
          ActionBan: string
          ActionUnban: string
          UseDns: string
          JournalMatchesSshd: bool
          FilterIsNormal: bool
          IgnoreRegexEmpty: bool }

    type private RuntimePolicy =
        { MaxRetry: int
          FindTimeSeconds: int
          BanTimeSeconds: int
          Ports: int array
          IgnoreIps: string array
          ActionNames: string array
          UseDns: string
          ActionProtocol: string
          ActionStart: string
          ActionStop: string
          ActionCheck: string
          ActionBan: string
          ActionUnban: string
          JournalMatchesSshd: bool
          FilterIsNormal: bool
          IgnoreRegexEmpty: bool }

    type private ServiceState =
        { Enabled: bool
          Active: bool }

    let private jailPath = "/etc/fail2ban/jail.d/90-dorothy-sshd.local"
    let private journalDirectory = "/var/lib/keroosha-iac/fail2ban"
    let private journalPath = "/var/lib/keroosha-iac/fail2ban/sshd.json"
    let private lockPath = "/run/lock/keroosha-fail2ban-backend.lock"
    let private utf8Strict = UTF8Encoding(false, true)
    let private systemdUnit = "fail2ban.service"
    let private defaults = [| "127.0.0.0/8"; "::1" |]

    [<DllImport("libc", EntryPoint = "open", SetLastError = true)>]
    extern int private nativeOpenDirectory (string path, int flags)

    [<DllImport("libc", EntryPoint = "fsync", SetLastError = true)>]
    extern int private nativeFsync (int descriptor)

    [<DllImport("libc", EntryPoint = "close", SetLastError = true)>]
    extern int private nativeClose (int descriptor)

    let private fail (message: string) = raise (BackendError(message))

    let private hasControl (value: string) =
        value |> Seq.exists (fun character -> int character < 32 || int character = 127)

    let private validateOwnerId (ownerId: string) =
        if String.IsNullOrWhiteSpace ownerId then fail "ownerId must be a non-empty Pulumi resource ID"
        if hasControl ownerId then fail "ownerId must not contain control characters"
        try utf8Strict.GetBytes ownerId |> ignore
        with :? EncoderFallbackException -> fail "ownerId is not valid UTF-8"

    let private mappedPath (environment: HostEnvironment) (logicalPath: string) =
        HostEnvironment.path environment logicalPath

    let private isMissingPathException (error: exn) =
        error :? FileNotFoundException || error :? DirectoryNotFoundException

    let private readOptionalText (path: string) (description: string) =
        try
            let attributes = File.GetAttributes path
            if (attributes &&& FileAttributes.Directory) <> enum<FileAttributes> 0
               || (attributes &&& FileAttributes.ReparsePoint) <> enum<FileAttributes> 0 then
                fail (description + " must be a regular file")
            try Some(File.ReadAllText(path, utf8Strict))
            with error -> fail ("cannot read " + description + ": " + error.Message)
        with
        | :? BackendError -> reraise ()
        | error when isMissingPathException error -> None
        | error -> fail ("cannot inspect " + description + ": " + error.Message)

    let private ensureSafeDirectory (path: string) (mode: UnixFileMode option) =
        let fullPath = Path.GetFullPath path
        let root = Path.GetPathRoot fullPath
        let relative = fullPath.Substring(root.Length)
        let components = relative.Split([| Path.DirectorySeparatorChar; Path.AltDirectorySeparatorChar |], StringSplitOptions.RemoveEmptyEntries)
        let mutable current = root
        for directoryComponent in components do
            current <- Path.Combine(current, directoryComponent)
            try
                let attributes = File.GetAttributes current
                if (attributes &&& FileAttributes.Directory) = enum<FileAttributes> 0
                   || (attributes &&& FileAttributes.ReparsePoint) <> enum<FileAttributes> 0 then
                    fail ("refusing to use a non-directory or symbolic-link path: " + current)
            with
            | :? BackendError -> reraise ()
            | error when isMissingPathException error ->
                Directory.CreateDirectory current |> ignore
                let attributes = File.GetAttributes current
                if (attributes &&& FileAttributes.Directory) = enum<FileAttributes> 0
                   || (attributes &&& FileAttributes.ReparsePoint) <> enum<FileAttributes> 0 then
                    fail ("refusing to use a non-directory or symbolic-link path: " + current)
            | error -> fail ("cannot inspect directory " + current + ": " + error.Message)
        match mode with
        | Some expected ->
            try
                File.SetUnixFileMode(fullPath, expected)
                let actual = File.GetUnixFileMode fullPath
                if actual <> expected then fail "Fail2Ban ownership journal directory has insecure permissions"
            with
            | :? BackendError -> reraise ()
            | error -> fail ("cannot secure Fail2Ban ownership journal directory: " + error.Message)
        | None -> ()

    let private syncDirectory (path: string) =
        let descriptor = nativeOpenDirectory(path, 0x10000 ||| 0x80000)
        if descriptor < 0 then fail "cannot open Fail2Ban state directory for synchronization"
        try
            if nativeFsync descriptor <> 0 then fail "cannot synchronize Fail2Ban state directory"
        finally
            nativeClose descriptor |> ignore

    let private writeJournalFile (environment: HostEnvironment) (journal: JsonObject) =
        let directory = mappedPath environment journalDirectory
        ensureSafeDirectory directory (Some(UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute))
        let path = mappedPath environment journalPath
        HostFiles.atomicWrite path (Encoding.UTF8.GetBytes(journal.ToJsonString() + "\n")) (UnixFileMode.UserRead ||| UnixFileMode.UserWrite)

    let private deleteJournalFile (environment: HostEnvironment) =
        let directory = mappedPath environment journalDirectory
        let path = mappedPath environment journalPath
        match readOptionalText path "Fail2Ban ownership journal" with
        | None -> ()
        | Some _ ->
            File.Delete path
            syncDirectory directory

    let private ensureExactProperties (element: JsonElement) (expected: Set<string>) (description: string) =
        if element.ValueKind <> JsonValueKind.Object then fail (description + " must be a JSON object")
        let properties = element.EnumerateObject() |> Seq.toArray
        let names = properties |> Array.map (fun property -> property.Name) |> Set.ofArray
        if properties.Length <> names.Count || names <> expected then
            fail (description + " contains missing, duplicate, or unsupported fields")

    let private hasDuplicateProperties (element: JsonElement) =
        let rec visit (value: JsonElement) =
            match value.ValueKind with
            | JsonValueKind.Object ->
                let names = HashSet<string>(StringComparer.Ordinal)
                let mutable duplicate = false
                for property in value.EnumerateObject() do
                    if not (names.Add property.Name) then duplicate <- true
                    if visit property.Value then duplicate <- true
                duplicate
            | JsonValueKind.Array -> value.EnumerateArray() |> Seq.exists visit
            | _ -> false
        visit element

    let private requiredString (element: JsonElement) (field: string) =
        let value = element.GetProperty field
        if value.ValueKind <> JsonValueKind.String then fail (field + " must be a string")
        let text = value.GetString()
        if isNull text then fail (field + " must not be null")
        text

    let private positiveInteger (element: JsonElement) (field: string) =
        let value = element.GetProperty field
        if value.ValueKind <> JsonValueKind.Number || not (value.TryGetInt32() |> fst) then
            fail (field + " must be a positive Int32")
        let number = value.GetInt32()
        if number <= 0 then fail (field + " must be a positive Int32")
        number

    let private normalizeIpOrNetworkCore (field: string) (rejectMappedCidr: bool) (rejectAmbiguous: bool) (raw: string) =
        if String.IsNullOrWhiteSpace raw || raw <> raw.Trim() || hasControl raw then
            fail (field + " must be an IP address or CIDR network")
        let parts = raw.Split('/')
        if parts.Length > 2 then fail (field + " must be an IP address or CIDR network")
        let parsedAddress =
            match IPAddress.TryParse parts.[0] with
            | true, value -> value
            | _ -> fail (field + " must be an IP address or CIDR network")
        if rejectMappedCidr && parsedAddress.IsIPv4MappedToIPv6 && parts.Length > 1 then
            fail (field + " must not use an IPv4-mapped IPv6 CIDR")
        let address = if parsedAddress.IsIPv4MappedToIPv6 && parts.Length = 1 then parsedAddress.MapToIPv4() else parsedAddress
        if address.AddressFamily = System.Net.Sockets.AddressFamily.InterNetworkV6 && address.ScopeId <> 0L then
            fail (field + " must not contain an IPv6 scope identifier")
        let bytes = address.GetAddressBytes()
        let maxPrefix = bytes.Length * 8
        let prefix =
            if parts.Length = 1 then maxPrefix
            else
                match Int32.TryParse(parts.[1], NumberStyles.None, CultureInfo.InvariantCulture) with
                | true, value when value >= 0 && value <= maxPrefix -> value
                | _ -> fail (field + " has an invalid CIDR prefix")
        if rejectAmbiguous && parts.Length > 1 && prefix = 0 then
            fail (field + " must not use a /0 network; use enabled = false or a narrower administrative CIDR")
        if rejectAmbiguous
           && (bytes |> Array.forall ((=) 0uy))
           && (parts.Length = 1 || prefix = maxPrefix) then
            fail (field + " must not be an unspecified host address; use enabled = false or a narrower administrative CIDR")
        if parts.Length = 2 then
            let mutable remaining = prefix
            for index in 0 .. bytes.Length - 1 do
                if remaining >= 8 then remaining <- remaining - 8
                elif remaining <= 0 then bytes.[index] <- 0uy
                else
                    bytes.[index] <- bytes.[index] &&& byte ((0xff <<< (8 - remaining)) &&& 0xff)
                    remaining <- 0
        let canonicalAddress = IPAddress(bytes).ToString().ToLowerInvariant()
        if parts.Length = 1 then canonicalAddress
        else canonicalAddress + "/" + prefix.ToString(CultureInfo.InvariantCulture)

    let private normalizeIpOrNetwork (field: string) (raw: string) =
        normalizeIpOrNetworkCore field true true raw

    let private normalizeObservedIpOrNetwork (field: string) (raw: string) =
        let parts = raw.Split('/')
        if parts.Length = 2 then
            match IPAddress.TryParse parts.[0] with
            | true, address when address.IsIPv4MappedToIPv6 ->
                match Int32.TryParse(parts.[1], NumberStyles.None, CultureInfo.InvariantCulture) with
                | true, prefix when prefix >= 0 && prefix <= 128 -> raw
                | _ -> fail (field + " has an invalid CIDR prefix")
            | _ ->
                let normalized = normalizeIpOrNetworkCore field false false raw
                let normalizedParts = normalized.Split('/')
                let address = IPAddress.Parse normalizedParts.[0]
                let prefix = Int32.Parse(normalizedParts.[1], NumberStyles.None, CultureInfo.InvariantCulture)
                let fullLength = address.GetAddressBytes().Length * 8
                if prefix = 0 || prefix = fullLength then normalizedParts.[0] else normalized
        else normalizeIpOrNetworkCore field false false raw


    let private normalizeIgnoreIps (values: string array) =
        let normalized = ResizeArray<string>()
        let seen = HashSet<string>(StringComparer.OrdinalIgnoreCase)
        for value in Array.append defaults values do
            let ip = normalizeIpOrNetwork "ignoreIps entry" value
            if seen.Add ip then normalized.Add ip
        normalized |> Seq.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right)) |> Seq.toArray
    let private observedIgnoreIps (values: string array) =
        values
        |> Array.map (normalizeObservedIpOrNetwork "observed ignoreip")
        |> Array.distinct
        |> Array.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right))

    let private parseRequest (request: JsonElement) =
        if request.ValueKind <> JsonValueKind.Object || hasDuplicateProperties request then
            fail "Fail2Ban request must be an object without duplicate properties"
        let names = request.EnumerateObject() |> Seq.map (fun property -> property.Name) |> Set.ofSeq
        let baseFields = set [ "operation"; "ownerId"; "enabled"; "maxRetry"; "findTimeSeconds"; "banTimeSeconds"; "ignoreIps" ]
        if names <> baseFields && names <> Set.add "ports" baseFields then
            fail "Fail2Ban request contains missing or unsupported fields"
        let operation = requiredString request "operation"
        if not (Set.contains operation (set [ "read"; "apply"; "delete" ])) then
            fail ("unsupported Fail2Ban operation '" + operation + "'")
        let ownerId = requiredString request "ownerId"
        validateOwnerId ownerId
        let enabledElement = request.GetProperty "enabled"
        if enabledElement.ValueKind <> JsonValueKind.True && enabledElement.ValueKind <> JsonValueKind.False then
            fail "enabled must be a Boolean"
        let maxRetry = positiveInteger request "maxRetry"
        let findTimeSeconds = positiveInteger request "findTimeSeconds"
        let banTimeSeconds = positiveInteger request "banTimeSeconds"
        let ignoreIpsElement = request.GetProperty "ignoreIps"
        if ignoreIpsElement.ValueKind <> JsonValueKind.Array then fail "ignoreIps must be an array of IP addresses or CIDR networks"
        let ignoreIps =
            ignoreIpsElement.EnumerateArray()
            |> Seq.map (fun value ->
                if value.ValueKind <> JsonValueKind.String then fail "ignoreIps entries must be strings"
                let text = value.GetString()
                if isNull text then fail "ignoreIps entries must not be null"
                text)
            |> Seq.toArray
            |> normalizeIgnoreIps
        let requestedPorts =
            if names.Contains "ports" then
                let portsElement = request.GetProperty "ports"
                if portsElement.ValueKind <> JsonValueKind.Array then fail "ports must be an array of TCP port numbers"
                let ports =
                    portsElement.EnumerateArray()
                    |> Seq.map (fun value ->
                        if value.ValueKind <> JsonValueKind.Number || not (value.TryGetInt32() |> fst) then
                            fail "ports entries must be integers from 1 through 65535"
                        let port = value.GetInt32()
                        if port < 1 || port > 65535 then fail "ports entries must be integers from 1 through 65535"
                        port)
                    |> Seq.toArray
                if ports.Length <> (ports |> Array.distinct).Length then fail "ports must not contain duplicates"
                ports |> Array.sort
            else [||]
        operation,
        { OwnerId = ownerId
          Enabled = enabledElement.GetBoolean()
          MaxRetry = maxRetry
          FindTimeSeconds = findTimeSeconds
          BanTimeSeconds = banTimeSeconds
          IgnoreIps = ignoreIps
          RequestedPorts = requestedPorts }


    let private renderJail (desired: Desired) (ports: int array) =
        let boolText = if desired.Enabled then "true" else "false"
        String.concat "\n" [
            "# Managed by Dorothy. Changes are reverted when the resource is deleted."
            "[sshd]"
            "enabled = " + boolText
            "filter = sshd[mode=normal]"
            "backend = systemd"
            "usedns = no"
            "banaction = nftables[type=multiport]"
            "port = " + (ports |> Array.map (fun port -> port.ToString(CultureInfo.InvariantCulture)) |> String.concat ",")
            "maxretry = " + desired.MaxRetry.ToString(CultureInfo.InvariantCulture)
            "findtime = " + desired.FindTimeSeconds.ToString(CultureInfo.InvariantCulture)
            "bantime = " + desired.BanTimeSeconds.ToString(CultureInfo.InvariantCulture)
            "ignoreip = " + String.concat " " desired.IgnoreIps
            ""
        ]

    let private parseObservedInt (field: string) (text: string) =
        match Int32.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture) with
        | true, value -> value
        | _ -> fail ("Fail2Ban observed " + field + " value is not an Int32")
    let private parseObservedDuration (environment: HostEnvironment) (field: string) (text: string) =
        match Int32.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture) with
        | true, seconds -> seconds
        | _ ->
            let result =
                try environment.Run "fail2ban-client" [ "--str2sec"; text ] None
                with error -> fail ("cannot convert observed Fail2Ban " + field + " duration: " + error.Message)
            if result.ExitCode <> 0 then fail ("Fail2Ban cannot convert observed " + field + " duration")
            parseObservedInt field (result.Stdout.Trim())
    let private servicePort (environment: HostEnvironment) (name: string) =
        let services = readOptionalText (mappedPath environment "/etc/services") "/etc/services" |> Option.defaultValue ""
        let matches = ResizeArray<int>()
        for line in services.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries) do
            let commentStart = line.IndexOf('#')
            let content = (if commentStart < 0 then line else line.Substring(0, commentStart)).Trim()
            let fields: string array = content.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
            let matchesName =
                fields.Length >= 2
                && (String.Equals(fields.[0], name, StringComparison.OrdinalIgnoreCase)
                    || (fields.Length > 2
                        && (fields |> Array.skip 2 |> Array.exists (fun alias -> String.Equals(alias, name, StringComparison.OrdinalIgnoreCase)))))
            if matchesName then
                let portSeparator = fields.[1].IndexOf('/')
                if portSeparator > 0
                   && fields.[1].Substring(portSeparator + 1).Equals("tcp", StringComparison.OrdinalIgnoreCase) then
                    let portText = fields.[1].Substring(0, portSeparator)
                    match Int32.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture) with
                    | true, port when port > 0 && port <= 65535 -> matches.Add port
                    | _ -> ()
        let ports = matches |> Seq.distinct |> Seq.sort |> Seq.toArray
        if ports.Length <> 1 then fail ("Fail2Ban action port service '" + name + "' does not resolve to exactly one TCP port")
        ports.[0]

    let private parsePortSetting (environment: HostEnvironment) (field: string) (text: string) =
        let ports =
            text.Split([| ','; ' '; '\t'; '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
            |> Array.map (fun raw ->
                match Int32.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture) with
                | true, value when value >= 1 && value <= 65535 -> value
                | true, _ -> fail ("Fail2Ban " + field + " contains an invalid TCP port")
                | _ -> servicePort environment raw)
            |> Array.distinct
            |> Array.sort
        if ports.Length = 0 then fail ("Fail2Ban " + field + " contains no TCP ports")
        ports


    let private parseFile (environment: HostEnvironment) (text: string) =
        let values = Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        let mutable inSshd = false
        let mutable foundSshd = false
        for rawLine in text.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries) do
            let line = rawLine.Trim()
            if line.StartsWith("[", StringComparison.Ordinal) && line.EndsWith("]", StringComparison.Ordinal) then
                let section = line.Substring(1, line.Length - 2).Trim()
                inSshd <- section.Equals("sshd", StringComparison.OrdinalIgnoreCase)
                if inSshd then
                    if foundSshd then fail "Fail2Ban jail override contains a duplicate sshd section"
                    foundSshd <- true
            elif inSshd && line.Length > 0 && not (line.StartsWith("#", StringComparison.Ordinal) || line.StartsWith(";", StringComparison.Ordinal)) then
                let separator = line.IndexOf('=')
                if separator <= 0 then fail "Fail2Ban sshd jail override contains a malformed setting"
                let name = line.Substring(0, separator).Trim()
                let value = line.Substring(separator + 1).Trim()
                if values.ContainsKey name then fail ("Fail2Ban sshd jail override duplicates " + name)
                values.Add(name, value)
        if not foundSshd then fail "Fail2Ban sshd jail override has no [sshd] section"
        let tryValue name = match values.TryGetValue name with true, value -> Some value | _ -> None
        let boolValue name =
            match tryValue name with
            | None -> None
            | Some("true")
            | Some("yes") -> Some true
            | Some("false")
            | Some("no") -> Some false
            | Some _ -> fail ("Fail2Ban sshd jail override has an invalid " + name + " value")
        let intValue name = tryValue name |> Option.map (parseObservedInt name)
        let durationValue name = tryValue name |> Option.map (parseObservedDuration environment name)
        let ports = tryValue "port" |> Option.map (parsePortSetting environment "observed jail port")
        let ips =
            tryValue "ignoreip"
            |> Option.map (fun value -> value.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries) |> Array.map (normalizeObservedIpOrNetwork "ignoreip"))
        { Enabled = boolValue "enabled"
          MaxRetry = intValue "maxretry"
          FindTimeSeconds = durationValue "findtime"
          BanTimeSeconds = durationValue "bantime"
          Ports = ports
          IgnoreIps = ips
          Filter = tryValue "filter"
          Backend = tryValue "backend"
          UseDns = tryValue "usedns"
          Banaction = tryValue "banaction" }

    let private parseSshdPorts (output: string) =
        let ports = ResizeArray<int>()
        for line in output.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries) do
            let fields = line.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
            if fields.Length > 0 && fields.[0].Equals("listenaddress", StringComparison.OrdinalIgnoreCase) then
                if fields.Length <> 2 then fail "sshd -T returned a malformed listenaddress setting"
                let address = fields.[1]
                let portSeparator =
                    if address.StartsWith("[", StringComparison.Ordinal) then
                        let closingBracket = address.IndexOf(']')
                        if closingBracket <= 1 || closingBracket + 1 >= address.Length || address.[closingBracket + 1] <> ':' then
                            fail "sshd -T returned a malformed bracketed listenaddress"
                        closingBracket + 1
                    else
                        address.LastIndexOf(':')
                if portSeparator <= 0 || portSeparator + 1 >= address.Length then
                    fail "sshd -T returned a listenaddress without an explicit port"
                let portText = address.Substring(portSeparator + 1)
                match Int32.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture) with
                | true, port when port >= 1 && port <= 65535 -> ports.Add port
                | _ -> fail "sshd -T returned an invalid listening TCP port"
        let result = ports |> Seq.distinct |> Seq.sort |> Seq.toArray
        if result.Length = 0 then fail "sshd -T did not report any resolved listenaddress ports"
        result

    let private run (environment: HostEnvironment) (executable: string) (arguments: string list) =
        let result =
            try environment.Run executable arguments None
            with error -> fail ("could not execute " + executable + ": " + error.Message)
        if result.ExitCode <> 0 then
            let diagnostic = if String.IsNullOrWhiteSpace result.Stderr then result.Stdout.Trim() else result.Stderr.Trim()
            let safeDiagnostic = diagnostic |> Seq.map (fun character -> if Char.IsControl character then ' ' else character) |> Array.ofSeq |> fun chars -> String(chars)
            let detail = if String.IsNullOrWhiteSpace safeDiagnostic then "exit code " + result.ExitCode.ToString(CultureInfo.InvariantCulture) else safeDiagnostic
            fail (executable + " failed: " + detail)
        result.Stdout

    let private readSshdPorts (environment: HostEnvironment) =
        run environment "/usr/sbin/sshd" [ "-T" ] |> parseSshdPorts

    let private parseSystemdProperties (output: string) =
        let collected = Dictionary<string, ResizeArray<string>>(StringComparer.Ordinal)
        for line in output.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries) do
            let separator = line.IndexOf('=')
            if separator <= 0 then fail "systemd returned malformed unit properties"
            let name = line.Substring(0, separator)
            match collected.TryGetValue name with
            | true, values when name = "ExecReload" -> values.Add(line.Substring(separator + 1))
            | true, _ -> fail "systemd returned duplicate unit properties"
            | _ ->
                let values = ResizeArray<string>()
                values.Add(line.Substring(separator + 1))
                collected.Add(name, values)
        let properties = Dictionary<string, string array>(StringComparer.Ordinal)
        for KeyValue(name, values) in collected do properties.Add(name, values.ToArray())
        properties

    let private systemdCommandField (property: string) (description: string) (field: string) =
        let marker = field + "="
        let start = property.IndexOf(marker, StringComparison.Ordinal)
        if start < 0 || property.IndexOf(marker, start + marker.Length, StringComparison.Ordinal) >= 0 then
            fail ("systemd " + description + " does not expose exactly one " + field)
        let valueStart = start + marker.Length
        let semicolon = property.IndexOf(';', valueStart)
        let closingBrace = property.IndexOf('}', valueStart)
        let finish =
            match semicolon, closingBrace with
            | -1, -1 -> -1
            | -1, value -> value
            | value, -1 -> value
            | left, right -> min left right
        if finish < valueStart then fail ("systemd " + description + " is malformed")
        property.Substring(valueStart, finish - valueStart).Trim()

    let private sshdCommand (property: string) (description: string) =
        let path = systemdCommandField property description "path"
        let argv = systemdCommandField property description "argv[]"
        let ignoreErrors = systemdCommandField property description "ignore_errors"
        path, Regex.Replace(argv, @"\s+", " ", RegexOptions.CultureInvariant), ignoreErrors


    let private isEmptySshdOptions (text: string) =
        let matches = Regex.Matches(text, @"(?:^|\s)SSHD_OPTS=(?:""([^""]*)""|'([^']*)'|([^\s]*))", RegexOptions.CultureInvariant)
        matches
        |> Seq.cast<Match>
        |> Seq.forall (fun matched ->
            let value =
                [ 1; 2; 3 ]
                |> List.tryPick (fun index ->
                    let group = matched.Groups.[index]
                    if group.Success then Some group.Value else None)
                |> Option.defaultValue ""
            String.IsNullOrEmpty value)

    let private verifySshdService (environment: HostEnvironment) =
        let output =
            run environment "systemctl"
                [ "show"; "--no-pager"; "--property=LoadState"; "--property=ActiveState"; "--property=ExecStart"; "--property=ExecReload"; "--property=Environment"; "--property=EnvironmentFiles"; "ssh.service" ]
        let properties = parseSystemdProperties output
        let get name =
            match properties.TryGetValue name with
            | true, [| value |] -> value
            | true, _ -> fail ("ssh.service returned duplicate systemd property " + name)
            | _ -> fail ("ssh.service omitted systemd property " + name)
        let getMany name =
            match properties.TryGetValue name with
            | true, values -> values
            | _ -> fail ("ssh.service omitted systemd property " + name)
        if get "LoadState" <> "loaded" || get "ActiveState" <> "active" then
            fail "ssh.service must be loaded and active to establish the local SSH listener configuration"
        let startPath, startArgv, startIgnoreErrors = sshdCommand (get "ExecStart") "ssh.service ExecStart"
        if startPath <> "/usr/sbin/sshd"
           || (startArgv <> "/usr/sbin/sshd -D" && startArgv <> "/usr/sbin/sshd -D $SSHD_OPTS")
           || startIgnoreErrors <> "no" then
            fail "ssh.service ExecStart is not the supported Debian OpenSSH command; effective SSH ports cannot be established"
        let reload = getMany "ExecReload" |> Array.map (fun property -> sshdCommand property "ssh.service ExecReload")
        let stockReload =
            [| ("/usr/sbin/sshd", "/usr/sbin/sshd -t", "no")
               ("/bin/kill", "/bin/kill -HUP $MAINPID", "no") |]
        let hupOnlyReload = [| ("/bin/kill", "/bin/kill -HUP $MAINPID", "no") |]
        let usrBinHupOnlyReload = [| ("/usr/bin/kill", "/usr/bin/kill -HUP $MAINPID", "no") |]
        if reload <> stockReload && reload <> hupOnlyReload && reload <> usrBinHupOnlyReload then
            fail "ssh.service ExecReload is not the supported Debian validation and HUP-only sequence"
        if not (isEmptySshdOptions (get "Environment")) then
            fail "ssh.service defines non-empty SSHD_OPTS; effective SSH ports cannot be established"
        let environmentFiles = get "EnvironmentFiles"
        let files = Regex.Matches(environmentFiles, @"/[^\s()]+", RegexOptions.CultureInvariant)
        for path in files |> Seq.cast<Match> |> Seq.map (fun matched -> matched.Value) do
            if path <> "/etc/default/ssh" then
                fail ("ssh.service uses unsupported EnvironmentFile " + path)
        match readOptionalText (mappedPath environment "/etc/default/ssh") "/etc/default/ssh" with
        | None -> ()
        | Some text ->
            for line in text.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries) do
                let value = line.Trim()
                if value.StartsWith("SSHD_OPTS=", StringComparison.Ordinal) && not (isEmptySshdOptions value) then
                    fail "/etc/default/ssh defines non-empty SSHD_OPTS; effective SSH ports cannot be established"
        let socketResult =
            try
                environment.Run "systemctl" [ "show"; "--no-pager"; "--property=LoadState"; "--property=UnitFileState"; "--property=ActiveState"; "ssh.socket" ] None
            with error -> fail ("could not inspect ssh.socket: " + error.Message)
        if socketResult.ExitCode <> 0 then
            let diagnostic = (socketResult.Stderr + " " + socketResult.Stdout).ToLowerInvariant()
            if not (diagnostic.Contains("could not be found", StringComparison.Ordinal) || diagnostic.Contains("not found", StringComparison.Ordinal)) then
                fail "could not establish whether SSH socket activation is enabled"
        else
            let socket = parseSystemdProperties socketResult.Stdout
            let socketValue name fallback =
                match socket.TryGetValue name with
                | true, [| value |] -> value
                | true, _ -> fail ("ssh.socket returned duplicate systemd property " + name)
                | _ -> fallback
            let loadState = socketValue "LoadState" "not-found"
            let unitFileState = socketValue "UnitFileState" "disabled"
            let activeState = socketValue "ActiveState" "inactive"
            if loadState <> "not-found"
               && (activeState = "active" || unitFileState = "enabled" || unitFileState = "enabled-runtime" || unitFileState = "linked") then
                fail "ssh.socket activation is unsupported; effective local SSH ports cannot be established"

    let private stockConffiles =
        [ "/etc/fail2ban/filter.d/sshd.conf"
          "/etc/fail2ban/filter.d/common.conf"
          "/etc/fail2ban/action.d/nftables.conf" ]

    let private localOverrideFiles =
        [ "/etc/fail2ban/filter.d/sshd.local"
          "/etc/fail2ban/filter.d/common.local"
          "/etc/fail2ban/action.d/nftables.local"
          "/etc/fail2ban/action.d/nftables-common.local" ]

    let private verifyStockDefinitions (environment: HostEnvironment) =
        for logicalPath in localOverrideFiles do
            match readOptionalText (mappedPath environment logicalPath) logicalPath with
            | Some _ -> fail (logicalPath + " is an unsupported local override")
            | None -> ()
        let packageConffiles = run environment "dpkg-query" [ "-W"; "-f=${Conffiles}"; "fail2ban" ]
        let expectedDigests = Dictionary<string, string>(StringComparer.Ordinal)
        for line in packageConffiles.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries) do
            let fields = line.Trim().Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
            if fields.Length >= 2 && fields.[0].StartsWith("/etc/fail2ban/", StringComparison.Ordinal) then
                expectedDigests[fields.[0]] <- fields.[1].ToLowerInvariant()
        for logicalPath in stockConffiles do
            let expected =
                match expectedDigests.TryGetValue logicalPath with
                | true, value when value.Length = 32 -> value
                | _ -> fail ("dpkg-query did not provide a stock checksum for " + logicalPath)
            let path = mappedPath environment logicalPath
            match readOptionalText path logicalPath with
            | Some _ -> ()
            | None -> fail (logicalPath + " is missing")
            let actual =
                try MD5.HashData(File.ReadAllBytes path) |> Convert.ToHexString |> fun value -> value.ToLowerInvariant()
                with error -> fail ("cannot checksum " + logicalPath + ": " + error.Message)
            if actual <> expected then
                fail (logicalPath + " differs from the Debian package definition; refusing to claim stock sshd filtering/action")

    let private tupleArguments (operation: string) (line: string) =
        let pattern = "^\\s*\\[\\s*['\"]" + Regex.Escape(operation) + "['\"]\\s*,\\s*['\"]sshd['\"](?:\\s*,\\s*(.*?))?\\s*\\]\\s*$"
        let matched = Regex.Match(line, pattern, RegexOptions.CultureInvariant)
        if matched.Success then Some(matched.Groups[1].Value.Trim()) else None

    let private commandArgument (command: string) (line: string) =
        let pattern = "^\\s*\\[\\s*['\"]set['\"]\\s*,\\s*['\"]sshd['\"]\\s*,\\s*['\"]" + Regex.Escape(command) + "['\"]\\s*,\\s*(.*?)\\s*\\]\\s*$"
        let matched = Regex.Match(line, pattern, RegexOptions.CultureInvariant)
        if matched.Success then Some(matched.Groups[1].Value.Trim()) else None

    let private quotedStrings (text: string) =
        let values = ResizeArray<string>()
        let mutable index = 0
        while index < text.Length do
            let delimiter = text.[index]
            if delimiter = '\'' || delimiter = '"' then
                index <- index + 1
                let value = StringBuilder()
                let mutable closed = false
                while index < text.Length && not closed do
                    let character = text.[index]
                    if character = delimiter then
                        closed <- true
                        index <- index + 1
                    elif character = '\\' && index + 1 < text.Length then
                        let escaped = text.[index + 1]
                        match escaped with
                        | 'n' -> value.Append('\n') |> ignore
                        | 'r' -> value.Append('\r') |> ignore
                        | 't' -> value.Append('\t') |> ignore
                        | '\\' -> value.Append('\\') |> ignore
                        | '\'' -> value.Append('\'') |> ignore
                        | '"' -> value.Append('"') |> ignore
                        | other -> value.Append('\\').Append(other) |> ignore
                        index <- index + 2
                    else
                        value.Append(character) |> ignore
                        index <- index + 1
                if closed then values.Add(value.ToString())
            else
                index <- index + 1
        values.ToArray()

    let private isSshdNormalFilter (regexText: string) =
        let value = regexText.ToLowerInvariant()
        value.Contains("failed", StringComparison.Ordinal)
        && value.Contains("invalid user", StringComparison.Ordinal)
        && value.Contains("too many authentication failures", StringComparison.Ordinal)
        && not (value.Contains("kex_exchange_identification", StringComparison.Ordinal))
        && not (value.Contains("did not receive identification string", StringComparison.Ordinal))
        && not (value.Contains("bad protocol version identification", StringComparison.Ordinal))
        && not (value.Contains("unable to negotiate", StringComparison.Ordinal))

    let private hasEmptyIgnoreRegex (text: string) =
        let entries =
            text.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
            |> Array.map (fun line -> line.Trim())
            |> Array.filter (fun line ->
                let lower = line.ToLowerInvariant()
                not (String.IsNullOrEmpty lower)
                && not (lower.StartsWith("current ignoreregex", StringComparison.Ordinal))
                && not (lower.StartsWith("no ignoreregex", StringComparison.Ordinal))
                && not (lower.StartsWith("no regex", StringComparison.Ordinal))
                && not (lower.StartsWith("no regular expression", StringComparison.Ordinal))
                && not (lower.StartsWith("there are no", StringComparison.Ordinal)))
        entries.Length = 0

    let private normalizedActionCommand (text: string) =
        Regex.Replace(text.Trim(), @"\s+", " ", RegexOptions.CultureInvariant)

    let private nftActionMatches (actionName: string) (actionType: string) (protocol: string) (portText: string) (actionStart: string) (actionStop: string) (actionCheck: string) (actionBan: string) (actionUnban: string) =
        let start = normalizedActionCommand actionStart
        let stop = normalizedActionCommand actionStop
        let check = normalizedActionCommand actionCheck
        let ban = normalizedActionCommand actionBan
        let unban = normalizedActionCommand actionUnban
        actionName = "nftables"
        && actionType = "multiport"
        && protocol = "tcp"
        && ban = "nft add element inet f2b-table <addr_set> \\{ <ip> \\}"
        && unban = "nft delete element inet f2b-table <addr_set> \\{ <ip> \\}"
        && start.Contains("nft add table inet f2b-table", StringComparison.Ordinal)
        && start.Contains("nft -- add chain inet f2b-table f2b-chain", StringComparison.Ordinal)
        && start.Contains("nft add set inet f2b-table <addr_set>", StringComparison.Ordinal)
        && start.Contains("dport", StringComparison.Ordinal)
        && start.Contains("<addr_family> saddr @<addr_set>", StringComparison.Ordinal)
        && start.Contains("echo '" + portText + "'", StringComparison.Ordinal)
        && stop.Contains("nft delete set inet f2b-table <addr_set>", StringComparison.Ordinal)
        && stop.Contains("nft delete table inet f2b-table", StringComparison.Ordinal)
        && check.Contains("nft list chain inet f2b-table f2b-chain", StringComparison.Ordinal)
        && check.Contains("@<addr_set>", StringComparison.Ordinal)

    let private parseDumpPolicy (environment: HostEnvironment) (text: string) =
        let lines = text.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
        let isSshdLine (line: string) =
            line.Contains("'sshd'", StringComparison.Ordinal) || line.Contains("\"sshd\"", StringComparison.Ordinal)
        let hasSshdStart = lines |> Array.exists (fun line -> tupleArguments "start" line |> Option.isSome)
        let sshdLines = lines |> Array.filter isSshdLine
        if not hasSshdStart && sshdLines.Length = 0 then None
        else
            let requiredInteger command field =
                let matches = lines |> Array.choose (commandArgument command)
                if matches.Length <> 1 then fail ("Fail2Ban effective sshd policy omitted or duplicated " + field)
                let value =
                    match quotedStrings matches[0] with
                    | [| single |] -> single
                    | _ -> matches[0].Trim()
                parseObservedInt field value
            let requiredString command field =
                let matches = lines |> Array.choose (commandArgument command)
                if matches.Length <> 1 then fail ("Fail2Ban effective sshd policy omitted or duplicated " + field)
                match quotedStrings matches[0] with
                | [| value |] -> value
                | _ -> fail ("Fail2Ban effective sshd policy has an invalid " + field)
            let requiredDuration command field =
                requiredString command field |> parseObservedDuration environment field
            let backend =
                match lines |> Array.tryPick (tupleArguments "add") with
                | Some value ->
                    match quotedStrings value with
                    | [| backendName |] -> backendName
                    | _ -> fail "Fail2Ban effective sshd policy omitted its backend"
                | None -> fail "Fail2Ban effective sshd policy omitted its backend"
            let actionNames = lines |> Array.choose (commandArgument "addaction") |> Array.collect quotedStrings
            let actionName = Array.tryHead actionNames |> Option.defaultValue ""
            let actionProperty (name: string) =
                if String.IsNullOrEmpty actionName then None
                else
                    lines
                    |> Array.filter (fun line ->
                        isSshdLine line
                        && line.Contains(actionName, StringComparison.Ordinal)
                        && line.Contains("action", StringComparison.Ordinal))
                    |> Array.tryPick (fun line ->
                        let values = quotedStrings line
                        values
                        |> Array.pairwise
                        |> Array.tryPick (fun (key, value) -> if key = name then Some value else None))
            let actionType = actionProperty "type" |> Option.defaultValue ""
            let actionTypeMatches = actionName = "nftables" && actionType = "multiport"
            let actionString name = actionProperty name |> Option.defaultValue ""
            let action = if actionTypeMatches then "nftables[type=multiport]" else String.concat "," actionNames
            let actionProtocol = actionString "protocol"
            let actionStart = actionString "actionstart"
            let actionStop = actionString "actionstop"
            let actionCheck = actionString "actioncheck"
            let actionBan = actionString "actionban"
            let actionUnban = actionString "actionunban"
            let ignoreIps =
                lines
                |> Array.choose (commandArgument "addignoreip")
                |> Array.collect quotedStrings
                |> Array.map (normalizeObservedIpOrNetwork "Fail2Ban effective ignoreip")
                |> Array.distinct
                |> Array.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right))
            let actionPortText =
                actionProperty "port"
                |> Option.defaultWith (fun () -> fail "Fail2Ban effective sshd policy omitted the action port")
            let ports = parsePortSetting environment "effective action port" actionPortText
            let usedns = requiredString "usedns" "usedns"
            let failRegexes =
                lines
                |> Array.filter (fun line -> isSshdLine line && line.Contains("addfailregex", StringComparison.Ordinal))
                |> String.concat "\n"
            let ignoreRegexEmpty =
                not (lines |> Array.exists (fun line -> isSshdLine line && line.Contains("addignoreregex", StringComparison.Ordinal)))
            let journalMatches =
                lines
                |> Array.choose (commandArgument "addjournalmatch")
                |> Array.collect quotedStrings
            let journalMatchesSshd =
                (journalMatches |> Array.exists (fun value -> value.Contains("_COMM=sshd", StringComparison.Ordinal)))
                && (journalMatches |> Array.exists (fun value -> value.Contains("_SYSTEMD_UNIT=ssh.service", StringComparison.Ordinal) || value.Contains("_SYSTEMD_UNIT=sshd.service", StringComparison.Ordinal)))
            Some
                { Enabled = hasSshdStart
                  MaxRetry = requiredInteger "maxretry" "maxretry"
                  FindTimeSeconds = requiredDuration "findtime" "findtime"
                  BanTimeSeconds = requiredDuration "bantime" "bantime"
                  Ports = ports
                  IgnoreIps = ignoreIps
                  Backend = backend
                  ActionNames = actionNames
                  ActionName = actionName
                  Banaction = action
                  ActionType = actionType
                  ActionProtocol = actionProtocol
                  ActionStart = actionStart
                  ActionStop = actionStop
                  ActionCheck = actionCheck
                  ActionBan = actionBan
                  ActionUnban = actionUnban
                  UseDns = usedns
                  JournalMatchesSshd = journalMatchesSshd
                  IgnoreRegexEmpty = ignoreRegexEmpty
                  FilterIsNormal = isSshdNormalFilter failRegexes }

    let private readSystemdState (environment: HostEnvironment) =
        let output = run environment "systemctl" [ "show"; "--no-pager"; "--property=LoadState"; "--property=UnitFileState"; "--property=ActiveState"; systemdUnit ]
        let values = Dictionary<string, string>(StringComparer.Ordinal)
        for line in output.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries) do
            let separator = line.IndexOf('=')
            if separator <= 0 then fail "Fail2Ban systemd status is malformed"
            let name = line.Substring(0, separator)
            if name <> "LoadState" && name <> "UnitFileState" && name <> "ActiveState" then fail "Fail2Ban systemd status contains an unsupported property"
            if values.ContainsKey name then fail "Fail2Ban systemd status contains duplicate properties"
            values.Add(name, line.Substring(separator + 1))
        if values.Count <> 3 then fail "Fail2Ban systemd status omitted required properties"
        if values["LoadState"] <> "loaded" && values["LoadState"] <> "masked" then
            fail "fail2ban.service is not installed or systemd could not load it"
        { Enabled = values["UnitFileState"] = "enabled"
          Active = values["ActiveState"] = "active" }

    let private getJailActive (environment: HostEnvironment) (service: ServiceState) =
        if not service.Active then false
        else
            let output = run environment "fail2ban-client" [ "status" ]
            let line = output.Split([| '\r'; '\n' |], StringSplitOptions.None) |> Array.tryFind (fun value -> value.Contains("Jail list:", StringComparison.Ordinal))
            match line with
            | None -> fail "fail2ban-client status omitted the jail list"
            | Some value ->
                let separator = value.IndexOf("Jail list:", StringComparison.Ordinal)
                let listing = value.Substring(separator + "Jail list:".Length).Trim().TrimStart('|', '`', '-', ' ')
                listing.Split([| ','; ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
                |> Array.exists (fun name -> name.Equals("sshd", StringComparison.OrdinalIgnoreCase))

    let private parseRuntimeActions (text: string) =
        let lines = text.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries) |> Array.map (fun line -> line.Trim())
        let header = "The jail sshd has the following actions:"
        if lines.Length = 0 || not (lines.[0].Equals(header, StringComparison.Ordinal)) then
            fail "Fail2Ban runtime action listing is malformed"
        lines |> Array.skip 1 |> Array.filter (String.IsNullOrWhiteSpace >> not)


    let private parseRuntimeInt (environment: HostEnvironment) (field: string) =
        let text = run environment "fail2ban-client" [ "get"; "sshd"; field ] |> fun value -> value.Trim()
        parseObservedInt ("runtime " + field) text
    let private parseRuntimeDuration (environment: HostEnvironment) (field: string) =
        let text = run environment "fail2ban-client" [ "get"; "sshd"; field ] |> fun value -> value.Trim()
        parseObservedDuration environment ("runtime " + field) text


    let private parseRuntimePorts (environment: HostEnvironment) (actionName: string) =
        let text = run environment "fail2ban-client" [ "get"; "sshd"; "action"; actionName; "port" ] |> fun value -> value.Trim()
        parsePortSetting environment "runtime action port" text

    let private parseRuntimeIgnoreIps (environment: HostEnvironment) =
        let output = run environment "fail2ban-client" [ "get"; "sshd"; "ignoreip" ]
        let found = ResizeArray<string>()
        for line in output.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries) do
            for token in line.Split([| ' '; '\t'; ','; '|'; '`'; '-' |], StringSplitOptions.RemoveEmptyEntries) do
                match IPAddress.TryParse(token.Split('/')[0]) with
                | true, _ ->
                    let normalized = normalizeObservedIpOrNetwork "Fail2Ban runtime ignoreip" token
                    if not (found.Contains normalized) then found.Add normalized
                | _ -> ()
        found
        |> Seq.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right))
        |> Seq.toArray

    let private matchesSshdJournal (text: string) =
        text.Contains("_COMM=sshd", StringComparison.Ordinal)
        && (text.Contains("_SYSTEMD_UNIT=ssh.service", StringComparison.Ordinal)
            || text.Contains("_SYSTEMD_UNIT=sshd.service", StringComparison.Ordinal))

    let private readRuntimePolicy (environment: HostEnvironment) (actionName: string) =
        let query (arguments: string list) = run environment "fail2ban-client" arguments |> fun value -> value.Trim()
        let actionQuery (property: string) =
            if actionName = "nftables" then query [ "get"; "sshd"; "action"; actionName; property ]
            else ""
        let failRegexes = query [ "get"; "sshd"; "failregex" ]
        let ignoreRegexes = query [ "get"; "sshd"; "ignoreregex" ]
        { MaxRetry = parseRuntimeInt environment "maxretry"
          FindTimeSeconds = parseRuntimeDuration environment "findtime"
          BanTimeSeconds = parseRuntimeDuration environment "bantime"
          Ports = parseRuntimePorts environment actionName
          IgnoreIps = parseRuntimeIgnoreIps environment
          ActionNames = query [ "get"; "sshd"; "actions" ] |> parseRuntimeActions
          UseDns = query [ "get"; "sshd"; "usedns" ]
          ActionProtocol = actionQuery "protocol"
          ActionStart = actionQuery "actionstart"
          ActionStop = actionQuery "actionstop"
          ActionCheck = actionQuery "actioncheck"
          ActionBan = actionQuery "actionban"
          ActionUnban = actionQuery "actionunban"
          JournalMatchesSshd = query [ "get"; "sshd"; "journalmatch" ] |> matchesSshdJournal
          FilterIsNormal = isSshdNormalFilter failRegexes
          IgnoreRegexEmpty = hasEmptyIgnoreRegex ignoreRegexes }

    let private sshdOverrideFile (environment: HostEnvironment) =
        mappedPath environment jailPath |> fun path -> readOptionalText path "Fail2Ban sshd jail override"

    let private readJournal (environment: HostEnvironment) (ownerId: string) =
        let directory = mappedPath environment journalDirectory
        let directoryExists =
            try
                let attributes = File.GetAttributes directory
                if (attributes &&& FileAttributes.Directory) = enum<FileAttributes> 0
                   || (attributes &&& FileAttributes.ReparsePoint) <> enum<FileAttributes> 0 then
                    fail "Fail2Ban ownership journal directory is not a real directory"
                let mode = File.GetUnixFileMode directory
                if mode <> (UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute) then
                    fail "Fail2Ban ownership journal directory has insecure permissions"
                true
            with
            | :? BackendError -> reraise ()
            | error when isMissingPathException error -> false
            | error -> fail ("cannot inspect Fail2Ban ownership journal directory: " + error.Message)
        if not directoryExists then None
        else
            let path = mappedPath environment journalPath
            match readOptionalText path "Fail2Ban ownership journal" with
            | None -> None
            | Some text ->
                try
                    let mode = File.GetUnixFileMode path
                    if mode <> (UnixFileMode.UserRead ||| UnixFileMode.UserWrite) then
                        fail "Fail2Ban ownership journal has insecure permissions"
                    use document = JsonDocument.Parse text
                    if hasDuplicateProperties document.RootElement then fail "Fail2Ban ownership journal contains duplicate JSON properties"
                    let root = document.RootElement
                    ensureExactProperties root (set [ "version"; "ownerId"; "managedContent"; "pending" ]) "Fail2Ban ownership journal"
                    if root.GetProperty("version").ValueKind <> JsonValueKind.Number || root.GetProperty("version").GetInt32() <> 1 then
                        fail "Fail2Ban ownership journal has an unsupported version"
                    let storedOwner = requiredString root "ownerId"
                    validateOwnerId storedOwner
                    if storedOwner <> ownerId then fail "Fail2Ban sshd jail is already owned by another Pulumi resource"
                    let managedElement = root.GetProperty "managedContent"
                    let managedContent =
                        match managedElement.ValueKind with
                        | JsonValueKind.Null -> None
                        | JsonValueKind.String -> Some(requiredString root "managedContent")
                        | _ -> fail "Fail2Ban ownership journal has an invalid managedContent"
                    let pendingElement = root.GetProperty "pending"
                    let pending =
                        match pendingElement.ValueKind with
                        | JsonValueKind.Null -> None
                        | JsonValueKind.Object ->
                            ensureExactProperties pendingElement (set [ "operation"; "priorContent"; "targetContent" ]) "Fail2Ban pending mutation"
                            let operation = requiredString pendingElement "operation"
                            if operation <> "apply" && operation <> "delete" then fail "Fail2Ban ownership journal has an invalid pending operation"
                            let readNullable (field: string) : string option =
                                let value = pendingElement.GetProperty(field)
                                match value.ValueKind with
                                | JsonValueKind.Null -> None
                                | JsonValueKind.String ->
                                    let valueText = value.GetString()
                                    if isNull valueText then fail ("Fail2Ban ownership journal has an invalid " + field)
                                    Some valueText
                                | _ -> fail ("Fail2Ban ownership journal has an invalid " + field)
                            let priorContent = readNullable "priorContent"
                            let targetContent = readNullable "targetContent"
                            if operation = "apply" && targetContent.IsNone then fail "Fail2Ban apply journal has no target content"
                            if operation = "delete" && (priorContent.IsNone || targetContent.IsSome) then fail "Fail2Ban delete journal is malformed"
                            if managedContent <> priorContent then fail "Fail2Ban pending journal does not match its prior managed content"
                            Some { Operation = operation; PriorContent = priorContent; TargetContent = targetContent }
                        | _ -> fail "Fail2Ban ownership journal has an invalid pending mutation"
                    if pending.IsNone && managedContent.IsNone then fail "Fail2Ban ownership journal has no managed content"
                    Some { OwnerId = storedOwner; ManagedContent = managedContent; Pending = pending }
                with
                | :? BackendError -> reraise ()
                | error -> fail ("Fail2Ban ownership journal is malformed: " + error.Message)

    let private journalNode (journal: Journal) =
        let root = JsonObject()
        root["version"] <- JsonValue.Create 1
        root["ownerId"] <- JsonValue.Create journal.OwnerId
        root["managedContent"] <- (match journal.ManagedContent with Some text -> JsonValue.Create text :> JsonNode | None -> null)
        root["pending"] <-
            match journal.Pending with
            | None -> null
            | Some pending ->
                let value = JsonObject()
                value["operation"] <- JsonValue.Create pending.Operation
                value["priorContent"] <- (match pending.PriorContent with Some text -> JsonValue.Create text :> JsonNode | None -> null)
                value["targetContent"] <- (match pending.TargetContent with Some text -> JsonValue.Create text :> JsonNode | None -> null)
                value :> JsonNode
        root

    let private saveJournal (environment: HostEnvironment) (journal: Journal) =
        writeJournalFile environment (journalNode journal)

    let private writeJailFile (environment: HostEnvironment) (expected: string option) (contents: string) =
        let path = mappedPath environment jailPath
        let parent = Path.GetDirectoryName path
        try
            let attributes = File.GetAttributes parent
            if (attributes &&& FileAttributes.Directory) = enum<FileAttributes> 0
               || (attributes &&& FileAttributes.ReparsePoint) <> enum<FileAttributes> 0 then
                fail "Fail2Ban jail.d directory is not a real directory"
        with
        | :? BackendError -> reraise ()
        | error -> fail ("cannot inspect Fail2Ban jail.d directory: " + error.Message)
        let current = readOptionalText path "Fail2Ban sshd jail override"
        if current <> expected then fail "Fail2Ban sshd jail override changed concurrently; refusing to overwrite it"
        match current with
        | Some value when value = contents -> ()
        | _ ->
            try HostFiles.atomicWrite path (utf8Strict.GetBytes contents) (UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.GroupRead ||| UnixFileMode.OtherRead)
            with error -> fail ("cannot atomically update Fail2Ban sshd jail override: " + error.Message)

    let private removeJailFile (environment: HostEnvironment) (expected: string) =
        let path = mappedPath environment jailPath
        let current = readOptionalText path "Fail2Ban sshd jail override"
        if current <> Some expected then fail "Fail2Ban sshd jail override changed concurrently; refusing to delete it"
        try
            File.Delete path
            syncDirectory (Path.GetDirectoryName path)
        with error -> fail ("cannot remove Fail2Ban sshd jail override: " + error.Message)

    let private validateConfig (environment: HostEnvironment) =
        run environment "fail2ban-client" [ "-t" ] |> ignore

    let private effectiveDump (environment: HostEnvironment) =
        run environment "fail2ban-client" [ "-d" ] |> parseDumpPolicy environment

    let private reloadIfActive (environment: HostEnvironment) =
        let service = readSystemdState environment
        if service.Active then run environment "fail2ban-client" [ "reload" ] |> ignore

    let private recoverPending (environment: HostEnvironment) (journal: Journal) =
        match journal.Pending with
        | None -> Some journal
        | Some pending ->
            let path = mappedPath environment jailPath
            let current = readOptionalText path "Fail2Ban sshd jail override"
            if current <> pending.PriorContent && current <> pending.TargetContent then
                fail "Fail2Ban sshd jail override changed outside the journaled mutation; refusing recovery"
            match pending.PriorContent, current with
            | Some prior, Some actual when prior = actual -> ()
            | Some prior, _ -> writeJailFile environment current prior
            | None, Some _ -> removeJailFile environment (current.Value)
            | None, None -> ()
            validateConfig environment
            effectiveDump environment |> ignore
            reloadIfActive environment
            match pending.PriorContent with
            | None ->
                deleteJournalFile environment
                None
            | Some prior ->
                let recovered = { journal with ManagedContent = Some prior; Pending = None }
                saveJournal environment recovered
                Some recovered

    let private dumpMatchesDesired (desired: Desired) (sshdPorts: int array) (dump: DumpPolicy option) =
        let desiredObservedIgnoreIps = observedIgnoreIps desired.IgnoreIps
        let expectedPortText = sshdPorts |> Array.map (fun port -> port.ToString(CultureInfo.InvariantCulture)) |> String.concat ","
        match desired.Enabled, dump with
        | false, None -> true
        | true, Some policy ->
            policy.Enabled
            && policy.MaxRetry = desired.MaxRetry
            && policy.FindTimeSeconds = desired.FindTimeSeconds
            && policy.BanTimeSeconds = desired.BanTimeSeconds
            && policy.Ports = sshdPorts
            && policy.IgnoreIps = desiredObservedIgnoreIps
            && policy.Backend.Equals("systemd", StringComparison.OrdinalIgnoreCase)
            && policy.ActionNames = [| "nftables" |]
            && policy.Banaction.Equals("nftables[type=multiport]", StringComparison.OrdinalIgnoreCase)
            && policy.UseDns.Equals("no", StringComparison.OrdinalIgnoreCase)
            && policy.JournalMatchesSshd
            && policy.FilterIsNormal
            && policy.IgnoreRegexEmpty
            && nftActionMatches
                policy.ActionName
                policy.ActionType
                policy.ActionProtocol
                expectedPortText
                policy.ActionStart
                policy.ActionStop
                policy.ActionCheck
                policy.ActionBan
                policy.ActionUnban
        | _ -> false

    let private readNativeSnapshot (environment: HostEnvironment) (desired: Desired) (journal: Journal option) =
        verifyStockDefinitions environment
        verifySshdService environment
        let sshdPorts = readSshdPorts environment
        let requestedPortsMatch = desired.RequestedPorts.Length = 0 || desired.RequestedPorts = sshdPorts
        validateConfig environment
        let dump = effectiveDump environment
        let service = readSystemdState environment
        let active = getJailActive environment service
        let runtime =
            match active, dump with
            | true, Some policy -> Some(readRuntimePolicy environment policy.ActionName)
            | true, None -> fail "Fail2Ban runtime has an active sshd jail absent from its effective configuration"
            | false, _ -> None
        let fileContent = sshdOverrideFile environment
        let filePolicy = fileContent |> Option.map (parseFile environment)
        match dump, filePolicy with
        | None, Some policy when policy.Enabled = Some true ->
            fail "Fail2Ban effective dump omitted an enabled sshd jail"
        | _ -> ()
        let fallback =
            match filePolicy with
            | Some policy -> policy
            | None ->
                { Enabled = None
                  MaxRetry = None
                  FindTimeSeconds = None
                  BanTimeSeconds = None
                  Ports = None
                  IgnoreIps = None
                  Filter = None
                  Backend = None
                  UseDns = None
                  Banaction = None }
        let actualMaxRetry, actualFindTime, actualBanTime, actualPorts, actualIgnoreIps =
            match runtime, dump with
            | Some running, _ -> running.MaxRetry, running.FindTimeSeconds, running.BanTimeSeconds, running.Ports, running.IgnoreIps
            | None, Some policy -> policy.MaxRetry, policy.FindTimeSeconds, policy.BanTimeSeconds, policy.Ports, policy.IgnoreIps
            | None, None ->
                Option.defaultValue 0 fallback.MaxRetry,
                Option.defaultValue 0 fallback.FindTimeSeconds,
                Option.defaultValue 0 fallback.BanTimeSeconds,
                Option.defaultValue [||] fallback.Ports,
                Option.defaultValue [||] fallback.IgnoreIps
        let expectedContent = renderJail desired sshdPorts
        let owned = journal.IsSome
        let fileOwnedContentMatches =
            match journal with
            | Some state -> state.ManagedContent = fileContent
            | None -> false
        let effectiveConfigMatches = dumpMatchesDesired desired sshdPorts dump
        let desiredRuntimeIgnoreIps = observedIgnoreIps desired.IgnoreIps
        let runtimeMatches =
            match runtime, dump with
            | Some value, Some policy ->
                let expectedPortText = sshdPorts |> Array.map (fun port -> port.ToString(CultureInfo.InvariantCulture)) |> String.concat ","
                value.MaxRetry = desired.MaxRetry
                && value.ActionNames = [| "nftables" |]
                && value.FindTimeSeconds = desired.FindTimeSeconds
                && value.BanTimeSeconds = desired.BanTimeSeconds
                && value.Ports = sshdPorts
                && value.IgnoreIps = desiredRuntimeIgnoreIps
                && value.UseDns.Equals("no", StringComparison.OrdinalIgnoreCase)
                && value.ActionProtocol.Equals(policy.ActionProtocol, StringComparison.OrdinalIgnoreCase)
                && value.JournalMatchesSshd
                && value.FilterIsNormal
                && value.IgnoreRegexEmpty
                && nftActionMatches policy.ActionName policy.ActionType value.ActionProtocol expectedPortText value.ActionStart value.ActionStop value.ActionCheck value.ActionBan value.ActionUnban
                && normalizedActionCommand value.ActionStart = normalizedActionCommand policy.ActionStart
                && normalizedActionCommand value.ActionStop = normalizedActionCommand policy.ActionStop
                && normalizedActionCommand value.ActionCheck = normalizedActionCommand policy.ActionCheck
                && normalizedActionCommand value.ActionBan = normalizedActionCommand policy.ActionBan
                && normalizedActionCommand value.ActionUnban = normalizedActionCommand policy.ActionUnban
            | None, _ -> not desired.Enabled && not active
            | _ -> false
        let fileMatches = fileContent = Some expectedContent
        let inSync =
            owned
            && (journal |> Option.exists (fun state -> state.Pending.IsNone))
            && fileOwnedContentMatches
            && fileMatches
            && requestedPortsMatch
            && effectiveConfigMatches
            && runtimeMatches
            && service.Enabled
            && service.Active
            && active = desired.Enabled
        let response = JsonObject()
        response["owned"] <- JsonValue.Create owned
        response["active"] <- JsonValue.Create active
        let portsNode = JsonArray()
        for port in actualPorts do portsNode.Add(JsonValue.Create port)
        response["actualPorts"] <- portsNode
        response["actualMaxRetry"] <- JsonValue.Create actualMaxRetry
        response["actualFindTimeSeconds"] <- JsonValue.Create actualFindTime
        response["actualBanTimeSeconds"] <- JsonValue.Create actualBanTime
        let ipsNode = JsonArray()
        for ip in actualIgnoreIps do ipsNode.Add(JsonValue.Create ip)
        response["actualIgnoreIps"] <- ipsNode
        response["inSync"] <- JsonValue.Create inSync
        response

    let private runSnapshot (environment: HostEnvironment) (desired: Desired) =
        use _lock = HostFiles.lockFile (mappedPath environment lockPath)
        let state = readJournal environment desired.OwnerId
        readNativeSnapshot environment desired state

    let private fail2banServiceApply (environment: HostEnvironment) =
        run environment "systemctl" [ "enable"; systemdUnit ] |> ignore
        run environment "systemctl" [ "start"; systemdUnit ] |> ignore
        run environment "fail2ban-client" [ "reload" ] |> ignore
        let state = readSystemdState environment
        if not state.Enabled || not state.Active then
            fail "fail2ban.service did not become enabled and active"

    let private restoreMutation (environment: HostEnvironment) (journal: Journal) (pending: PendingMutation) =
        let current = readOptionalText (mappedPath environment jailPath) "Fail2Ban sshd jail override"
        if current <> pending.PriorContent && current <> pending.TargetContent then
            fail "Fail2Ban sshd jail override changed during rollback; refusing to overwrite it"
        match pending.PriorContent, current with
        | Some prior, Some actual when prior = actual -> ()
        | Some prior, _ -> writeJailFile environment current prior
        | None, Some actual -> removeJailFile environment actual
        | None, None -> ()
        validateConfig environment
        effectiveDump environment |> ignore
        reloadIfActive environment
        match pending.PriorContent with
        | None -> deleteJournalFile environment
        | Some prior -> saveJournal environment { journal with ManagedContent = Some prior; Pending = None }

    let private apply (environment: HostEnvironment) (desired: Desired) =
        use _lock = HostFiles.lockFile (mappedPath environment lockPath)
        let loaded = readJournal environment desired.OwnerId |> Option.bind (recoverPending environment)
        let current = sshdOverrideFile environment
        let prior =
            match loaded with
            | None ->
                if current.IsSome then fail "Fail2Ban sshd jail override already exists without Dorothy ownership; refusing to overwrite it"
                None
            | Some state ->
                match state.ManagedContent with
                | Some managed when current = Some managed -> Some managed
                | Some _ -> fail "Fail2Ban sshd jail override drifted from its owner journal; refusing to overwrite it"
                | None -> fail "Fail2Ban ownership journal has no managed sshd jail override"
        let sshdPorts = readSshdPorts environment
        if desired.RequestedPorts.Length > 0 && desired.RequestedPorts <> sshdPorts then
            fail "Fail2Ban ports input does not match the ports reported by local sshd -T"
        let target = renderJail desired sshdPorts
        let currentSnapshot = readNativeSnapshot environment desired loaded
        if loaded.IsSome && currentSnapshot["inSync"].GetValue<bool>() then
            currentSnapshot
        else
            let pending = { Operation = "apply"; PriorContent = prior; TargetContent = Some target }
            let initial =
                match loaded with
                | Some state -> { state with Pending = Some pending }
                | None -> { OwnerId = desired.OwnerId; ManagedContent = None; Pending = Some pending }
            saveJournal environment initial
            try
                writeJailFile environment prior target
                validateConfig environment
                let dump = effectiveDump environment
                if not (dumpMatchesDesired desired sshdPorts dump) then
                    fail "Fail2Ban effective sshd policy conflicts with the requested jail"
                fail2banServiceApply environment
                let snapshot = readNativeSnapshot environment desired (Some { initial with ManagedContent = Some target; Pending = None })
                if not (snapshot["inSync"].GetValue<bool>()) then
                    fail "Fail2Ban effective sshd jail or runtime state does not match the requested policy"
                saveJournal environment { initial with ManagedContent = Some target; Pending = None }
                snapshot
            with error ->
                try restoreMutation environment initial pending
                with rollbackError ->
                    fail ("Fail2Ban apply failed: " + error.Message + "; rollback also failed: " + rollbackError.Message)
                match error with
                | :? BackendError -> reraise ()
                | _ -> fail ("Fail2Ban apply failed: " + error.Message)

    let private delete (environment: HostEnvironment) (desired: Desired) =
        use _lock = HostFiles.lockFile (mappedPath environment lockPath)
        let loaded = readJournal environment desired.OwnerId |> Option.bind (recoverPending environment)
        let current = sshdOverrideFile environment
        match loaded, current with
        | None, None -> JsonObject() :> JsonNode
        | None, Some _ -> fail "Fail2Ban sshd jail override exists without Dorothy ownership; refusing to delete it"
        | Some state, Some actual ->
            match state.ManagedContent with
            | Some managed when actual = managed ->
                let pending = { Operation = "delete"; PriorContent = Some managed; TargetContent = None }
                let inProgress = { state with Pending = Some pending }
                saveJournal environment inProgress
                try
                    removeJailFile environment managed
                    validateConfig environment
                    effectiveDump environment |> ignore
                    reloadIfActive environment
                    deleteJournalFile environment
                    JsonObject() :> JsonNode
                with error ->
                    try restoreMutation environment inProgress pending
                    with rollbackError ->
                        fail ("Fail2Ban delete failed: " + error.Message + "; rollback also failed: " + rollbackError.Message)
                    match error with
                    | :? BackendError -> reraise ()
                    | _ -> fail ("Fail2Ban delete failed: " + error.Message)
            | Some _ -> fail "Fail2Ban sshd jail override drifted from its owner journal; refusing to delete it"
            | None -> fail "Fail2Ban ownership journal has no managed sshd jail override"
        | Some _, None -> fail "Fail2Ban sshd jail override is missing while its owner journal remains; refusing to delete"

    let handle (environment: HostEnvironment) (request: JsonElement) : JsonNode =
        let operation, desired = parseRequest request
        match operation with
        | "read" -> runSnapshot environment desired :> JsonNode
        | "apply" -> apply environment desired :> JsonNode
        | "delete" -> delete environment desired
        | _ -> fail "unsupported Fail2Ban operation"
