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

[<Struct>]
type UfwRuleBlock =
    { Family: string
      Marker: string option
      Tuple: string
      Canonical: string
      Commands: string array
      Lines: string array }

type UfwRuntimeTable =
    { Family: string
      Active: bool
      Partial: bool
      Related: bool
      ReachableChains: Set<string>
      Rules: Map<string, string array array>
      AllRules: Map<string, string array array>
      Policies: Map<string, string>
      Chains: Set<string> }

type UfwSettings =
    { Enabled: bool
      DefaultIn: string
      DefaultOut: string
      RuntimeEnabled: bool }
type UfwRuntimeAction =
    | StartRuntime
    | StopRuntime
    | RestartRuntime
    | ReloadRuntime
    | KeepRuntime

module Ufw =
    let private lockPath = "/run/lock/keroosha-ufw-backend.lock"
    let private journalDirectory = "/var/lib/keroosha-iac/ufw"
    let private journalPath = "/var/lib/keroosha-iac/ufw/global.json"
    let private policies = set [ "allow"; "deny"; "reject" ]
    let private actions = set [ "allow"; "limit"; "deny"; "reject" ]
    let private ipv4OnlyProtocols = set [ "ipv6"; "igmp" ]
    let private utf8Strict = UTF8Encoding(false, true)
    type BackendError(message: string) =
        inherit InvalidOperationException(message)
    [<DllImport("libc", EntryPoint = "open", SetLastError = true)>]
    extern int private nativeOpenDirectory (string path, int flags)

    [<DllImport("libc", EntryPoint = "fsync", SetLastError = true)>]
    extern int private nativeFsync (int descriptor)

    [<DllImport("libc", EntryPoint = "close", SetLastError = true)>]
    extern int private nativeClose (int descriptor)

    [<DllImport("libc", EntryPoint = "geteuid")>]
    extern uint32 private getEffectiveUserId ()
    let private fail (message: string) = raise (BackendError(message))

    let private hasControl (value: string) =
        value |> Seq.exists (fun c -> int c < 32 || int c = 127)

    let private sha256 (value: byte array) =
        SHA256.HashData(value) |> Convert.ToHexString |> fun value -> value.ToLowerInvariant()

    let private ownerDigest (ownerId: string) =
        if String.IsNullOrEmpty ownerId then fail "ownerId must be a non-empty Pulumi resource ID"
        if hasControl ownerId then fail "ownerId must not contain control characters"
        try sha256 (utf8Strict.GetBytes ownerId)
        with :? EncoderFallbackException -> fail "ownerId is not valid UTF-8"

    let ownerMarkerPrefix (ownerId: string) = "keroosha-iac:" + ownerDigest ownerId + ":"

    let private isShellOperator (value: string) =
        value |> Seq.exists (fun character -> ";|&<>`$".Contains(character))

    let validateRuleTokens (index: int) (tokens: string list) =
        if List.isEmpty tokens then fail ("rules[" + index.ToString(CultureInfo.InvariantCulture) + "] must be a non-empty array of argument strings")
        tokens
        |> List.iteri (fun tokenIndex token ->
            if String.IsNullOrEmpty token then
                fail ("rules[" + index.ToString(CultureInfo.InvariantCulture) + "][" + tokenIndex.ToString(CultureInfo.InvariantCulture) + "] must be a non-empty string")
            if hasControl token then fail ("rules[" + index.ToString(CultureInfo.InvariantCulture) + "] contains a control character")
            if isShellOperator token then fail ("rules[" + index.ToString(CultureInfo.InvariantCulture) + "] contains a shell operator")
            if String.Equals(token, "comment", StringComparison.OrdinalIgnoreCase) then
                fail "rule comments are reserved for deterministic UFW ownership markers"
            if token.StartsWith("-", StringComparison.Ordinal) then
                fail ("UFW command options are not permitted in rules[" + index.ToString(CultureInfo.InvariantCulture) + "]"))
        let actionIndex = if String.Equals(tokens.Head, "route", StringComparison.OrdinalIgnoreCase) then 1 else 0
        if actionIndex = 1 && tokens.Length < 2 then fail ("rules[" + index.ToString(CultureInfo.InvariantCulture) + "] has an incomplete route command")
        let action = tokens |> List.tryItem actionIndex |> Option.defaultValue "" |> fun value -> value.ToLowerInvariant()
        if not (Set.contains action actions) then
            fail ("rules[" + index.ToString(CultureInfo.InvariantCulture) + "] must start with a native UFW rule action (allow, limit, deny, reject)")
        tokens

    let private pyJsonString (value: string) =
        let builder = StringBuilder(value.Length + 2)
        builder.Append('"') |> ignore
        for character in value do
            match character with
            | '"' -> builder.Append("\\\"") |> ignore
            | '\\' -> builder.Append("\\\\") |> ignore
            | '\b' -> builder.Append("\\b") |> ignore
            | '\f' -> builder.Append("\\f") |> ignore
            | '\n' -> builder.Append("\\n") |> ignore
            | '\r' -> builder.Append("\\r") |> ignore
            | '\t' -> builder.Append("\\t") |> ignore
            | c when int c < 32 || int c >= 127 -> builder.Append("\\u").Append(int c |> fun number -> number.ToString("x4", CultureInfo.InvariantCulture)) |> ignore
            | c -> builder.Append(c) |> ignore
        builder.Append('"').ToString()

    let private digestSource (ipType: string) (canonical: string) =
        "{\"ipType\":" + pyJsonString ipType + ",\"rule\":" + pyJsonString canonical + "}"

    let makeOwnerMarker (ownerId: string) (index: int) (ipType: string) (canonical: string) : string =
        ownerMarkerPrefix ownerId
        + "r"
        + index.ToString("D8", CultureInfo.InvariantCulture)
        + ":"
        + sha256 (Encoding.UTF8.GetBytes(digestSource ipType canonical))

    let private splitLines (text: string) = text.Split([| "\n" |], StringSplitOptions.None)

    let ruleSection (lines: string array) =
        let tableIndexes = lines |> Array.mapi (fun index line -> index, line.Trim()) |> Array.choose (fun (index, line) -> if line.StartsWith("*", StringComparison.Ordinal) then Some(index, line) else None)
        let commits = lines |> Array.mapi (fun index line -> index, line.Trim()) |> Array.choose (fun (index, line) -> if line = "COMMIT" then Some index else None)
        let starts = lines |> Array.mapi (fun index line -> index, line.Trim()) |> Array.choose (fun (index, line) -> if line = "### RULES ###" then Some index else None)
        let ends = lines |> Array.mapi (fun index line -> index, line.Trim()) |> Array.choose (fun (index, line) -> if line = "### END RULES ###" then Some index else None)
        if tableIndexes.Length <> 1 || snd tableIndexes[0] <> "*filter" || commits.Length <> 1 || starts.Length <> 1 || ends.Length > 1 then
            fail "UFW user rule file has a malformed RULES section"
        let table, start, commit = fst tableIndexes[0], starts[0], commits[0]
        if not (table < start && start < commit) then fail "UFW user rule file has a malformed RULES section"
        let finish =
            if ends.Length = 0 then commit
            else
                let closingIndex = ends[0]
                if closingIndex <= start || closingIndex >= commit then fail "UFW user rule file has a malformed RULES section"
                closingIndex
        start, finish

    let private userChains = set [ "ufw-user-input"; "ufw-user-output"; "ufw-user-forward"; "ufw6-user-input"; "ufw6-user-output"; "ufw6-user-forward" ]

    let private isAuxiliaryRule (line: string) =
        let fields = line.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
        if fields.Length < 2 || (fields[0] <> "-A" && fields[0] <> "-I") then false
        else
            let chain = fields[1]
            (chain.StartsWith("ufw-", StringComparison.Ordinal) || chain.StartsWith("ufw6-", StringComparison.Ordinal))
            && not (Set.contains chain userChains)

    let private tupleMarker (line: string) =
        if not (line.StartsWith("### tuple ###", StringComparison.Ordinal)) then None
        else
            let markerAt = line.LastIndexOf(" comment=", StringComparison.Ordinal)
            if markerAt < 0 then None
            else
                let encoded = line.Substring(markerAt + 9).Trim()
                if encoded.Length = 0 then None
                else
                    try Some(utf8Strict.GetString(Convert.FromHexString encoded))
                    with _ -> None

    let ruleBlocks (lines: string array) (start: int) (finish: int) =
        if start < 0 || finish <= start || finish > lines.Length then invalidArg "section" "Invalid UFW RULES section bounds."
        let body = lines[(start + 1) .. (finish - 1)]
        let blocks = ResizeArray<int * int * string option>()
        let mutable index = 0
        while index < body.Length do
            if body[index].StartsWith("### tuple ###", StringComparison.Ordinal) then
                let mutable next = index + 1
                while next < body.Length && not (body[next].StartsWith("### tuple ###", StringComparison.Ordinal)) && not (isAuxiliaryRule body[next]) do
                    next <- next + 1
                blocks.Add(index, next, tupleMarker body[index])
                index <- next
            else index <- index + 1
        body, blocks.ToArray()

    let private posixSplit (text: string) =
        let values = ResizeArray<string>()
        let current = StringBuilder()
        let mutable quote = '\000'
        let mutable escaped = false
        let mutable started = false
        let flush () =
            if started then
                values.Add(current.ToString())
                current.Clear() |> ignore
                started <- false
        for character in text do
            if escaped then
                current.Append(character) |> ignore
                escaped <- false
                started <- true
            elif quote = '\'' then
                if character = '\'' then quote <- '\000' else current.Append(character) |> ignore
                started <- true
            elif quote = '"' then
                if character = '"' then quote <- '\000'
                elif character = '\\' then escaped <- true
                else current.Append(character) |> ignore
                started <- true
            else
                match character with
                | '\\' -> escaped <- true; started <- true
                | '\'' | '"' as delimiter -> quote <- delimiter; started <- true
                | ' ' | '\t' | '\r' | '\n' -> flush ()
                | _ -> current.Append(character) |> ignore; started <- true
        if escaped || quote <> '\000' then fail "iptables rule contains invalid quoting"
        flush ()
        values.ToArray()

    let private normalizedNetwork (text: string) =
        try
            let addressText, prefixText =
                match text.Split('/') with
                | [| address |] -> address, None
                | [| address; prefix |] -> address, Some(int (Int32.Parse(prefix, CultureInfo.InvariantCulture)))
                | _ -> text, None
            let address = IPAddress.Parse addressText
            let bytes = address.GetAddressBytes()
            let prefix = defaultArg prefixText (bytes.Length * 8)
            if prefix < 0 || prefix > bytes.Length * 8 then text
            else
                let mutable remaining = prefix
                for index in 0 .. bytes.Length - 1 do
                    if remaining >= 8 then remaining <- remaining - 8
                    elif remaining <= 0 then bytes[index] <- 0uy
                    else
                        let mask = byte (0xff <<< (8 - remaining))
                        bytes[index] <- bytes[index] &&& mask
                        remaining <- 0
                IPAddress(bytes).ToString().ToLowerInvariant() + "/" + prefix.ToString(CultureInfo.InvariantCulture)
        with _ -> text

    let normalizeIptablesTokens (line: string) =
        let tokens = posixSplit line
        for index in 0 .. tokens.Length - 2 do
            if tokens[index] = "--limit" then
                let value = tokens[index + 1]
                let slash = value.IndexOf('/')
                if slash > 0 && slash + 1 < value.Length then
                    let unit = value.Substring(slash + 1).ToLowerInvariant()
                    let normalizedUnit =
                        match unit with
                        | "second"
                        | "seconds" -> "sec"
                        | "minute"
                        | "minutes" -> "min"
                        | _ -> unit
                    tokens[index + 1] <- value.Substring(0, slash + 1) + normalizedUnit
        if tokens.Length < 3 then tokens
        else
            let aliases = dict [ "--protocol", "-p"; "--source", "-s"; "--destination", "-d"; "--in-interface", "-i"; "--out-interface", "-o"; "--source-port", "--sport"; "--destination-port", "--dport" ]
            let resolve token = match aliases.TryGetValue token with true, value -> value | _ -> token
            let valueOptions = set [ "-p"; "-s"; "-d"; "-i"; "-o"; "--sport"; "--dport"; "--sports"; "--dports" ]
            let ranks = dict [ "-i", 0; "-o", 1; "-s", 2; "-d", 3; "-p", 4; "--sport", 6; "--sports", 6; "--dport", 7; "--dports", 7 ]
            let protocol =
                tokens |> Array.pairwise |> Array.tryPick (fun (option, value) -> if resolve option = "-p" then Some(value.ToLowerInvariant()) else None)
            let segments = ResizeArray<int * int * string array>()
            let result = ResizeArray<string>()
            result.Add(tokens[0]); result.Add(tokens[1])
            let flushMatches () =
                segments |> Seq.sortBy (fun (rank, order, _) -> rank, order) |> Seq.iter (fun (_, _, clause) -> result.AddRange clause)
                segments.Clear()
            let target = ResizeArray<string>()
            let mutable index = 2
            let mutable sequence = 0
            while index < tokens.Length do
                let mutable inverted = false
                let mutable optionIndex = index
                if tokens[index] = "!" && index + 1 < tokens.Length && Set.contains (resolve tokens[index + 1]) valueOptions then
                    inverted <- true
                    optionIndex <- index + 1
                let option = resolve tokens[optionIndex]
                if Set.contains option valueOptions then
                    let mutable valueIndex = optionIndex + 1
                    if valueIndex >= tokens.Length then
                        flushMatches ()
                        result.AddRange(tokens[index .. optionIndex])
                        index <- optionIndex + 1
                    else
                        if tokens[valueIndex] = "!" && valueIndex + 1 < tokens.Length then
                            inverted <- true
                            valueIndex <- valueIndex + 1
                        let mutable value = tokens[valueIndex]
                        if option = "-s" || option = "-d" then value <- normalizedNetwork value
                        elif option = "-p" && (value.Equals("tcp", StringComparison.OrdinalIgnoreCase) || value.Equals("udp", StringComparison.OrdinalIgnoreCase)) then value <- value.ToLowerInvariant()
                        let clause = if inverted then [| "!"; option; value |] else [| option; value |]
                        segments.Add(ranks[option], sequence, clause)
                        sequence <- sequence + 1
                        index <- valueIndex + 1
                elif tokens[index] = "-m" && index + 1 < tokens.Length then
                    let marker = tokens[index + 1]
                    if (marker = "tcp" || marker = "udp") && Some marker = protocol then index <- index + 2
                    elif marker = "multiport" then segments.Add(5, sequence, [| "-m"; marker |]); sequence <- sequence + 1; index <- index + 2
                    elif marker = "comment" && index + 3 < tokens.Length && tokens[index + 2] = "--comment" then index <- index + 4
                    elif marker = "recent" then
                        let family6 = tokens[1].StartsWith("ufw6-", StringComparison.Ordinal)
                        let defaultMask = if family6 then "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" else "255.255.255.255"
                        let mutable finish = index + 2
                        let recentTerminators = set [ "-m"; "-j"; "--jump"; "-g"; "--goto" ]
                        while finish < tokens.Length && not (Set.contains tokens[finish] recentTerminators) do finish <- finish + 1
                        let recent = tokens[(index + 2) .. (finish - 1)]
                        let hasDestination = Array.contains "--rdest" recent
                        let normalized = ResizeArray<string>()
                        normalized.Add("-m"); normalized.Add("recent")
                        let mutable part = 0
                        while part < recent.Length do
                            if recent[part] = "--name" && part + 1 < recent.Length && recent[part + 1] = "DEFAULT" then part <- part + 2
                            elif recent[part] = "--mask" && part + 1 < recent.Length && recent[part + 1].Equals(defaultMask, StringComparison.OrdinalIgnoreCase) then part <- part + 2
                            elif recent[part] = "--rsource" && not hasDestination then part <- part + 1
                            else normalized.Add(recent[part]); part <- part + 1
                        flushMatches ()
                        result.AddRange normalized
                        index <- finish
                    else
                        flushMatches ()
                        result.AddRange(tokens[index .. index + 1])
                        index <- index + 2
                elif (tokens[index] = "-j" || tokens[index] = "--jump" || tokens[index] = "-g" || tokens[index] = "--goto") && index + 1 < tokens.Length then
                    let jump = if tokens[index] = "-g" || tokens[index] = "--goto" then "-g" else "-j"
                    target.Add(jump); target.Add(tokens[index + 1]); index <- index + 2
                    while index + 1 < tokens.Length && tokens[index] = "--reject-with" do target.Add(tokens[index]); target.Add(tokens[index + 1]); index <- index + 2
                else
                    flushMatches ()
                    result.Add tokens[index]
                    index <- index + 1
            flushMatches ()
            if target.Count >= 2 && target[0] = "-j" && target[1] = "REJECT" && not (target.Contains "--reject-with") then
                target.Add("--reject-with")
                target.Add(if tokens[1].StartsWith("ufw6-", StringComparison.Ordinal) then "icmp6-port-unreachable" else "icmp-port-unreachable")
            result.AddRange target
            result.ToArray()

    let rec private blockFromTuple (lines: string array) (start: int) (finish: int) =
        let header = lines[start]
        let body = lines[(start + 1) .. (finish - 1)]
        let family = if body |> Array.exists (fun line -> line.Contains("ufw6-", StringComparison.Ordinal)) || header.Contains("::/", StringComparison.Ordinal) then "6" else "4"
        let tupleEnd = header.LastIndexOf(" comment=", StringComparison.Ordinal)
        let tuple = if tupleEnd < 0 then header.Substring("### tuple ###".Length).Trim() else header.Substring("### tuple ###".Length, tupleEnd - "### tuple ###".Length).Trim()
        let marker = tupleMarker header
        let commands = body |> Array.filter (fun line -> line.TrimStart().StartsWith("-A ", StringComparison.Ordinal) || line.TrimStart().StartsWith("-I ", StringComparison.Ordinal))
        let canonical = canonicalRule tuple commands
        { Family = family; Marker = marker; Tuple = tuple; Canonical = canonical; Commands = commands; Lines = lines[start .. (finish - 1)] }

    and private canonicalRule (tuple: string) (_commands: string array) =
        let fields = tuple.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
        if fields.Length < 7 then fail "native UFW returned an unsupported tuple record"
        let isForward = fields[0].StartsWith("route:", StringComparison.Ordinal)
        let rawAction = if isForward then fields[0].Substring("route:".Length) else fields[0]
        let actionParts = rawAction.Split([| '_' |], 2, StringSplitOptions.None)
        let action = actionParts[0]
        let logtype = if actionParts.Length = 2 then actionParts[1] else ""
        let protocol, dport, destination, sport, source = fields[1], fields[2], fields[3], fields[4], fields[5]
        let applicationRule = fields.Length >= 9
        let appValue index =
            if not applicationRule || fields[index] = "-" then ""
            else fields[index].Replace("%20", " ")
        let dapp = appValue 6
        let sapp = appValue 7
        let interfaceToken = if applicationRule then fields[8] else fields[6]
        let direction = interfaceToken.Split([| '_' |], 2, StringSplitOptions.None)[0]
        let mutable interfaceIn = ""
        let mutable interfaceOut = ""
        for interfacePart in interfaceToken.Split('!') do
            if interfacePart.StartsWith("in_", StringComparison.Ordinal) then interfaceIn <- interfacePart.Substring(3)
            elif interfacePart.StartsWith("out_", StringComparison.Ordinal) then interfaceOut <- interfacePart.Substring(4)
        let any address = address = "any" || address = "0.0.0.0/0" || address = "::/0"
        let builder = StringBuilder()
        if isForward then builder.Append("route ") |> ignore
        builder.Append(action) |> ignore
        let shortForm = any destination && any source && sport = "any" && sapp = "" && interfaceIn = "" && interfaceOut = "" && dport <> "any"
        if shortForm then
            if direction = "out" then builder.Append(" out") |> ignore
            if logtype <> "" then builder.Append(' ').Append(logtype) |> ignore
            if dapp <> "" then
                let renderedApp: string = if dapp.Contains(' ') then "'" + dapp + "'" else dapp
                builder.Append(' ').Append(renderedApp) |> ignore
            else
                builder.Append(' ').Append(dport) |> ignore
                if protocol <> "any" then builder.Append('/').Append(protocol) |> ignore
        else
            if interfaceIn <> "" then builder.Append(" in on ").Append(interfaceIn) |> ignore
            if interfaceOut <> "" then builder.Append(" out on ").Append(interfaceOut) |> ignore
            elif direction = "out" then builder.Append(" out") |> ignore
            if logtype <> "" then builder.Append(' ').Append(logtype) |> ignore
            let appendEndpoint (directionName: string) (address: string) (port: string) (app: string) =
                let location = if any address then "any" else address
                if location <> "any" || port <> "any" || app <> "" then
                    builder.Append(' ').Append(directionName).Append(' ').Append(location) |> ignore
                    if app <> "" then
                        let renderedApp: string = if app.Contains(' ') then "'" + app + "'" else app
                        builder.Append(" app ").Append(renderedApp) |> ignore
                    elif port <> "any" then builder.Append(" port ").Append(port) |> ignore
            appendEndpoint "from" source sport sapp
            appendEndpoint "to" destination dport dapp
            if not (builder.ToString().Contains(" to ", StringComparison.Ordinal) || builder.ToString().Contains(" from ", StringComparison.Ordinal)) && interfaceIn = "" && interfaceOut = "" then builder.Append(" to any") |> ignore
            if protocol <> "any" && dapp = "" && sapp = "" then builder.Append(" proto ").Append(protocol) |> ignore
        builder.ToString()

    let private parseRecords (text: string) =
        let lines = splitLines text
        let start, finish = ruleSection lines
        let body, ranges = ruleBlocks lines start finish
        ranges |> Array.map (fun (left, right, _) -> blockFromTuple body (left) (right))

    let private blockInBody (body: string array) (left: int) (right: int) = blockFromTuple body left right

    let private extractNativeBlocks (stdout: string) (marker: string) =
        let lines = splitLines stdout
        let matching = ResizeArray<UfwRuleBlock>()
        let tupleIndexes = lines |> Array.mapi (fun index line -> index, line) |> Array.choose (fun (index, line) -> if line.StartsWith("### tuple ###", StringComparison.Ordinal) then Some index else None)
        for position in 0 .. tupleIndexes.Length - 1 do
            let left = tupleIndexes[position]
            let mutable right = if position + 1 < tupleIndexes.Length then tupleIndexes[position + 1] else lines.Length
            let mutable stop = left + 1
            while stop < right && lines[stop] <> "### END RULES ###" && lines[stop] <> "COMMIT" && not (isAuxiliaryRule lines[stop]) do stop <- stop + 1
            right <- min right stop
            if tupleMarker lines[left] = Some marker then
                matching.Add(blockFromTuple lines left right)
        if matching.Count = 0 then fail "native UFW dry-run did not emit the requested ownership tuple"
        matching.ToArray()

    let ensureNativeUfw (environment: HostEnvironment) =
        try
            let result = environment.Run "ufw" [ "--version" ] None
            if result.ExitCode <> 0 then fail "UFW is not installed"
        with
        | :? BackendError -> reraise ()
        | _ -> fail "UFW is not installed"

    let enableAndReload (environment: HostEnvironment) =
        let started = environment.Run "ufw" [ "--force"; "enable" ] None
        if started.ExitCode <> 0 then fail "native UFW could not enable the firewall"
        let reloaded = environment.Run "ufw" [ "reload" ] None
        if reloaded.ExitCode <> 0 then fail "native UFW did not reload user rules after startup"
    let private nativeRun (environment: HostEnvironment) (arguments: string list) =
        let result = environment.Run "ufw" arguments None
        if result.ExitCode <> 0 then
            let detail = if String.IsNullOrWhiteSpace result.Stderr then result.Stdout.Trim() else result.Stderr.Trim()
            fail (if String.IsNullOrWhiteSpace detail then "native UFW rejected the requested rule" else "native UFW rejected the requested rule: " + detail)
        result.Stdout

    let private renderRule (environment: HostEnvironment) (tokens: string list) (marker: string) =
        let stdout = nativeRun environment ([ "--dry-run" ] @ tokens @ [ "comment"; marker ])
        extractNativeBlocks stdout marker

    let private deriveIpType (blocks: UfwRuleBlock array) =
        let families = blocks |> Array.map (fun block -> block.Family) |> Set.ofArray
        if Set.contains "4" families && Set.contains "6" families then "both"
        elif Set.contains "6" families then "v6"
        elif Set.contains "4" families then "v4"
        else fail "native UFW did not identify an IP family"

    let private addressFamily (value: string) : string option =
        let slash = value.IndexOf('/')
        let addressText = if slash < 0 then value else value.Substring(0, slash)
        let mutable address = Unchecked.defaultof<IPAddress>
        if IPAddress.TryParse(addressText, &address) then
            match address.GetAddressBytes().Length with
            | 4 -> Some "4"
            | 16 -> Some "6"
            | _ -> None
        else None

    let private intendedIpType (tokens: string list) : string =
        let rec visit (remaining: string list) (families: Set<string>) (ipv4Only: bool) =
            match remaining with
            | key :: value :: tail when key.Equals("from", StringComparison.OrdinalIgnoreCase) || key.Equals("to", StringComparison.OrdinalIgnoreCase) ->
                let restricted =
                    match addressFamily value with
                    | Some family -> Set.intersect families (Set.singleton family)
                    | None -> families
                visit tail restricted ipv4Only
            | key :: value :: tail when key.Equals("proto", StringComparison.OrdinalIgnoreCase) ->
                visit tail families (ipv4Only || Set.contains (value.ToLowerInvariant()) ipv4OnlyProtocols)
            | _ :: tail -> visit tail families ipv4Only
            | [] ->
                let intended = if ipv4Only then Set.intersect families (Set.singleton "4") else families
                if Set.isEmpty intended then fail "UFW rule arguments select incompatible address families"
                elif Set.contains "4" intended && Set.contains "6" intended then "both"
                elif Set.contains "4" intended then "v4"
                else "v6"
        visit tokens (set [ "4"; "6" ]) false

    let private rewriteBlockMarker (marker: string) (block: UfwRuleBlock) =
        let encoded = Convert.ToHexString(utf8Strict.GetBytes marker).ToLowerInvariant()
        let lines =
            block.Lines
            |> Array.mapi (fun index line ->
                if index <> 0 then line
                else
                    let markerAt = line.LastIndexOf(" comment=", StringComparison.Ordinal)
                    if markerAt < 0 then fail "native UFW dry-run omitted the tuple marker"
                    line.Substring(0, markerAt + 9) + encoded)
        { block with Marker = Some marker; Lines = lines }

    let private makeDesiredRules (environment: HostEnvironment) (ownerId: string) (rules: string list list) =
        rules
        |> List.mapi (fun index rawTokens ->
            let tokens = validateRuleTokens index rawTokens
            let probe = "keroosha-iac:probe:" + Guid.NewGuid().ToString("N") + ":" + index.ToString("D8", CultureInfo.InvariantCulture)
            let parsed = renderRule environment tokens probe
            let nativeIpType = deriveIpType parsed
            let ipType = intendedIpType tokens
            if nativeIpType <> ipType then
                fail ("native UFW dry-run did not emit all requested address families for rules[" + index.ToString(CultureInfo.InvariantCulture) + "]")
            let canonical = parsed[0].Canonical
            let marker = makeOwnerMarker ownerId index ipType canonical
            { Marker = Some marker; Family = ""; Tuple = ""; Canonical = canonical; Commands = [||]; Lines = [||] },
            (parsed |> Array.map (rewriteBlockMarker marker)))

    let private containsPrefix prefix (marker: string option) =
        match marker with Some value -> value.StartsWith(prefix, StringComparison.Ordinal) | None -> false
    let private markerMatches (markerPrefix: string) (block: UfwRuleBlock) = containsPrefix markerPrefix block.Marker

    let private filePath (environment: HostEnvironment) (logicalPath: string) = HostEnvironment.path environment logicalPath

    let private readRegularFile environment logicalPath description =
        let path = filePath environment logicalPath
        try
            let attributes = File.GetAttributes path
            if (attributes &&& FileAttributes.Directory) <> enum<FileAttributes> 0
               || (attributes &&& FileAttributes.ReparsePoint) <> enum<FileAttributes> 0 then
                fail (description + " must be a regular file")
            File.ReadAllText(path, utf8Strict), File.GetUnixFileMode path
        with
        | :? BackendError -> reraise ()
        | error -> fail ("cannot read " + description + ": " + error.Message)

    let private writeAtomic environment logicalPath contents expectedText mode description =
        let path = filePath environment logicalPath
        try
            let old = if File.Exists path then Some(File.ReadAllText(path, utf8Strict)) else None
            if old <> Some expectedText then
                fail "UFW user rule file changed concurrently; refusing to overwrite it"
            elif old = Some contents then false
            else
                HostFiles.atomicWrite path (utf8Strict.GetBytes contents) mode
                true
        with
        | :? BackendError -> reraise ()
        | error -> fail ("cannot atomically update " + description + ": " + error.Message)

    let private syncDirectory (path: string) =
        let descriptor = nativeOpenDirectory(path, 0x10000 ||| 0x80000)
        if descriptor < 0 then fail "cannot open UFW journal directory for synchronization"
        try
            if nativeFsync descriptor <> 0 then fail "cannot synchronize the UFW journal directory"
        finally
            if nativeClose descriptor <> 0 then ()
    let private writeJournal (environment: HostEnvironment) (journal: JsonObject) =
        let directory = filePath environment journalDirectory
        if not (Directory.Exists directory) then
            let parent = Path.GetDirectoryName directory
            let parentExisted = Directory.Exists parent
            let grandParent = Path.GetDirectoryName parent
            let grandParentExisted = Directory.Exists grandParent
            Directory.CreateDirectory directory |> ignore
            File.SetUnixFileMode(directory, UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute)
            if not parentExisted then
                syncDirectory parent
                if not grandParentExisted then syncDirectory grandParent
        let journalFile = filePath environment journalPath
        HostFiles.atomicWrite journalFile (Encoding.UTF8.GetBytes(journal.ToJsonString() + "\n")) (UnixFileMode.UserRead ||| UnixFileMode.UserWrite)

    let private hasDuplicateJsonProperties (element: JsonElement) =
        let rec visit (node: JsonElement) : bool =
            match node.ValueKind with
            | JsonValueKind.Object ->
                let seen = HashSet<string>(StringComparer.Ordinal)
                let mutable duplicate = false
                for property in node.EnumerateObject() do
                    if not (seen.Add property.Name) then duplicate <- true
                    if visit property.Value then duplicate <- true
                duplicate
            | JsonValueKind.Array -> node.EnumerateArray() |> Seq.exists visit
            | _ -> false
        visit element

    let private nodeObj (node: JsonNode) (name: string) : JsonObject =
        match node with
        | :? JsonObject as value -> value
        | _ -> fail ("UFW settings journal " + name + " is malformed")

    let private nodeString (node: JsonNode) (field: string) =
        try
            let value = node.GetValue<string>()
            if isNull value then fail ("UFW settings journal contains an invalid " + field + " value")
            value
        with _ -> fail ("UFW settings journal contains an invalid " + field + " value")

    let private nodeBool (node: JsonNode) (field: string) =
        try node.GetValue<bool>()
        with _ -> fail ("UFW settings journal contains an invalid " + field + " value")

    let private prop (objectNode: JsonObject) (field: string) : JsonNode =
        let mutable value: JsonNode = null
        if objectNode.TryGetPropertyValue(field, &value) then
            if isNull value then fail ("UFW settings journal property " + field + " is null")
            value
        else
            fail ("UFW settings journal property " + field + " is missing")

    let private requireExactKeys (objectNode: JsonObject) (expected: Set<string>) (message: string) =
        let actual = objectNode |> Seq.map (fun pair -> pair.Key) |> Set.ofSeq
        if actual <> expected then fail message

    let private digestValue (value: string) =
        Regex.IsMatch(value, "\\A[0-9a-f]{64}\\z", RegexOptions.CultureInvariant)

    let private validateSettingsNode (section: string) (node: JsonNode) =
        let values = nodeObj node section
        let keys = set [ "enabled"; "defaultIn"; "defaultOut"; "runtimeEnabled" ]
        requireExactKeys values keys ("UFW settings journal " + section + " settings are malformed")
        let enabled = nodeBool (prop values "enabled") "enabled"
        let runtimeEnabled = nodeBool (prop values "runtimeEnabled") "runtimeEnabled"
        let defaultIn = nodeString (prop values "defaultIn") "defaultIn"
        let defaultOut = nodeString (prop values "defaultOut") "defaultOut"
        if not (Set.contains defaultIn policies) then fail "UFW settings journal contains an invalid defaultIn value"
        if not (Set.contains defaultOut policies) then fail "UFW settings journal contains an invalid defaultOut value"
        { Enabled = enabled; DefaultIn = defaultIn; DefaultOut = defaultOut; RuntimeEnabled = runtimeEnabled }

    let validateJournal (journal: JsonObject) (ownerId: string) =
        let exact =
            set
                [ "schemaVersion"
                  "ownerId"
                  "baseline"
                  "managed"
                  "pending"
                  "pendingRules"
                  "baselineRuntimeDigest"
                  "baselineStoppedRuntimeDigest" ]
        requireExactKeys journal exact "UFW settings journal has an unsupported format"
        let version =
            try (prop journal "schemaVersion").GetValue<int>()
            with _ -> -1
        if version <> 1 then fail "UFW settings journal has an unsupported schema version"
        if nodeString (prop journal "ownerId") "ownerId" <> ownerId then
            fail "UFW firewall-global settings are already owned by another Pulumi resource"
        validateSettingsNode "baseline" (prop journal "baseline") |> ignore
        validateSettingsNode "managed" (prop journal "managed") |> ignore
        for field in [ "baselineRuntimeDigest"; "baselineStoppedRuntimeDigest" ] do
            if not (digestValue (nodeString (prop journal field) field)) then
                fail ("UFW settings journal contains an invalid " + field)
        match journal["pending"] with
        | null -> ()
        | :? JsonObject as pending ->
            requireExactKeys
                pending
                (set [ "setting"; "prior"; "target"; "runtimePrior"; "runtimeTarget"; "runtimeIntermediate" ])
                "UFW settings journal pending mutation is malformed"
            let setting = nodeString (prop pending "setting") "setting"
            let validSettings = set [ "enabled"; "defaultIn"; "defaultOut"; "runtimeEnabled" ]
            if not (Set.contains setting validSettings) then
                fail "UFW settings journal pending mutation names an invalid setting"
            let validSettingValue (name: string) (node: JsonNode) =
                if name = "enabled" || name = "runtimeEnabled" then
                    try node.GetValue<bool>() |> ignore; true with _ -> false
                else
                    try policies |> Set.contains (node.GetValue<string>()) with _ -> false
            if not (validSettingValue setting (prop pending "prior")) then
                fail "UFW settings journal pending prior value is invalid"
            if not (validSettingValue setting (prop pending "target")) then
                fail "UFW settings journal pending target value is invalid"
            for field in [ "runtimePrior"; "runtimeTarget"; "runtimeIntermediate" ] do
                nodeBool (prop pending field) field |> ignore
        | _ -> fail "UFW settings journal pending mutation is malformed"
        match journal["pendingRules"] with
        | null -> ()
        | :? JsonObject as pending ->
            requireExactKeys
                pending
                (set [ "operation"; "beforeFiles"; "afterFiles"; "runtimeBefore"; "runtimeAfter"; "runtimeStopped" ])
                "UFW settings journal pending rule mutation is malformed"
            if nodeString (prop pending "operation") "operation" <> "delete" then
                fail "UFW settings journal pending rule operation is unsupported"
            for field in [ "beforeFiles"; "afterFiles" ] do
                let files = nodeObj (prop pending field) field
                requireExactKeys files (set [ "4"; "6" ]) "UFW settings journal pending file digests are malformed"
                for family in [ "4"; "6" ] do
                    if not (digestValue (nodeString (prop files family) field)) then
                        fail "UFW settings journal pending file digest is invalid"
            for field in [ "runtimeBefore"; "runtimeAfter"; "runtimeStopped" ] do
                if not (digestValue (nodeString (prop pending field) field)) then
                    fail "UFW settings journal pending runtime digest is invalid"
        | _ -> fail "UFW settings journal pending rule mutation is malformed"
        journal

    let private validateRequest
        (request: JsonElement)
        : string * string * int * string list list * bool * string * string =
        if request.ValueKind <> JsonValueKind.Object then fail "request must be a JSON object"
        let get (name: string) =
            let mutable value = Unchecked.defaultof<JsonElement>
            if request.TryGetProperty(name, &value) then Some value else None
        let getRequired (name: string) =
            get name |> Option.defaultWith (fun () -> fail ("request is missing " + name))
        let operation =
            match getRequired "operation" with
            | value when value.ValueKind = JsonValueKind.String -> value.GetString()
            | _ -> fail "operation must be a string"
        if operation <> "read" && operation <> "apply" && operation <> "delete" then
            fail ("unsupported helper operation " + pyJsonString operation)
        let ownerId =
            match getRequired "ownerId" with
            | value when value.ValueKind = JsonValueKind.String -> value.GetString()
            | _ -> fail "ownerId must be a non-empty Pulumi resource ID"
        ownerDigest ownerId |> ignore
        if operation = "delete" then operation, ownerId, 22, [], false, "deny", "allow"
        else
            let port =
                match getRequired "sshPort" with
                | value when value.ValueKind = JsonValueKind.Number ->
                    let mutable parsed = 0
                    if value.TryGetInt32(&parsed) && parsed >= 1 && parsed <= 65535 then parsed
                    else fail "sshPort must be an integer between 1 and 65535"
                | _ -> fail "sshPort must be an integer between 1 and 65535"
            let enabled =
                match getRequired "enabled" with
                | value when value.ValueKind = JsonValueKind.True -> true
                | value when value.ValueKind = JsonValueKind.False -> false
                | _ -> fail "enabled must be a boolean"
            let policy (field: string) =
                match getRequired field with
                | value when value.ValueKind = JsonValueKind.String ->
                    let result = value.GetString()
                    if Set.contains result policies then result
                    else fail (field + " must be one of allow, deny, or reject")
                | _ -> fail (field + " must be one of allow, deny, or reject")
            let rulesElement = getRequired "rules"
            if rulesElement.ValueKind <> JsonValueKind.Array then fail "rules must be an array"
            let rules =
                rulesElement.EnumerateArray()
                |> Seq.mapi (fun index rule ->
                    if rule.ValueKind <> JsonValueKind.Array then
                        fail ("rules[" + index.ToString(CultureInfo.InvariantCulture) + "] must be a non-empty array of argument strings")
                    rule.EnumerateArray()
                    |> Seq.map (fun token ->
                        if token.ValueKind = JsonValueKind.String then token.GetString()
                        else "")
                    |> Seq.toList
                    |> validateRuleTokens index)
                |> Seq.toList
            operation, ownerId, port, rules, enabled, policy "defaultIn", policy "defaultOut"

    let private parseConfig (environment: HostEnvironment) =
        let defaults, _ = readRegularFile environment "/etc/default/ufw" "UFW defaults file"
        let config, _ = readRegularFile environment "/etc/ufw/ufw.conf" "UFW configuration file"
        let readValue (text: string) (key: string) =
            let pattern = "(?m)^\\s*" + Regex.Escape(key) + "\\s*=\\s*\"?([A-Za-z]+)\"?\\s*(?:#.*)?$"
            let matched = Regex.Match(text, pattern, RegexOptions.CultureInvariant)
            if matched.Success then Some(matched.Groups[1].Value.ToLowerInvariant()) else None
        let policy name =
            match readValue defaults name with
            | Some "accept" -> "allow"
            | Some "drop" -> "deny"
            | Some "reject" -> "reject"
            | Some _ -> fail ("native UFW reports an unsupported " + name + " policy")
            | None -> fail ("native UFW is missing " + name)
        let enabled = readValue config "ENABLED" = Some "yes"
        let ipv6 = readValue defaults "IPV6" = Some "yes" && Directory.Exists(filePath environment "/proc/sys/net/ipv6")
        { Enabled = enabled; DefaultIn = policy "DEFAULT_INPUT_POLICY"; DefaultOut = policy "DEFAULT_OUTPUT_POLICY"; RuntimeEnabled = false }, ipv6

    let private readRulesFiles (environment: HostEnvironment) =
        let text4, mode4 = readRegularFile environment "/etc/ufw/user.rules" "UFW user rule file"
        let text6, mode6 = readRegularFile environment "/etc/ufw/user6.rules" "UFW user rule file"
        (text4, mode4), (text6, mode6)

    // A mapped temporary root is an isolated filesystem seam; production uses "/" and requires effective UID 0.
    let private enforceRoot (environment: HostEnvironment) =
        let root = Path.TrimEndingDirectorySeparator(Path.GetFullPath environment.Root)
        let isHostRoot = root = Path.GetPathRoot root
        if isHostRoot && getEffectiveUserId() <> 0u then fail "the UFW backend requires root privileges"

    let private statPath (environment: HostEnvironment) (path: string) (description: string) (expectedType: string) (expectedMode: int) =
        let absolute = filePath environment path
        let result = environment.Run "stat" [ "-c"; "%F:%u:%a"; "--"; absolute ] None
        if result.ExitCode <> 0 then fail ("cannot inspect " + description)
        let fields = result.Stdout.Trim().Split(':')
        if fields.Length <> 3 || fields[0] <> expectedType || fields[1] <> "0" then fail (description + " must be a root-owned real " + expectedType)
        let mode = Convert.ToInt32(fields[2], 8)
        if (mode &&& 0o777) <> expectedMode then fail (description + " has insecure permissions")

    let private loadJournal (environment: HostEnvironment) (ownerId: string) (createDirectory: bool) : JsonObject option =
        let directory = filePath environment journalDirectory
        if not (Directory.Exists directory) then
            if not createDirectory then None
            else
                Directory.CreateDirectory directory |> ignore
                File.SetUnixFileMode(directory, UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute)
                statPath environment journalDirectory "UFW settings journal directory" "directory" 0o700
                None
        else
            statPath environment journalDirectory "UFW settings journal directory" "directory" 0o700
            let path = filePath environment journalPath
            if not (File.Exists path) then None
            else
                statPath environment journalPath "UFW settings journal" "regular file" 0o600
                let text, _ = readRegularFile environment journalPath "UFW settings journal"
                use document = JsonDocument.Parse text
                if hasDuplicateJsonProperties document.RootElement then fail "UFW settings journal contains duplicate JSON properties"
                let journal = JsonNode.Parse(text) :?> JsonObject
                Some(validateJournal journal ownerId)

    let private saveJournal (environment: HostEnvironment) (journal: JsonObject) = writeJournal environment journal


    let private removeJournal (environment: HostEnvironment) (ownerId: string) =
        match loadJournal environment ownerId false with
        | None -> ()
        | Some _ ->
            File.Delete(filePath environment journalPath)
            syncDirectory (filePath environment journalDirectory)
    let private nodeForSetting (setting: string) (value: obj) : JsonNode =
        match value with
        | :? JsonNode as existing -> existing.DeepClone()
        | :? bool as boolean when setting = "enabled" || setting = "runtimeEnabled" -> JsonValue.Create(boolean) :> JsonNode
        | :? string as text when setting = "defaultIn" || setting = "defaultOut" -> JsonValue.Create(text) :> JsonNode
        | _ -> fail ("UFW setting " + setting + " has an invalid journal value")


    let private newJournal (ownerId: string) (settings: UfwSettings) (runtimeDigest: string) (stoppedDigest: string) =
        let settingsNode (value: UfwSettings) =
            let result = JsonObject()
            result["enabled"] <- JsonValue.Create value.Enabled
            result["defaultIn"] <- JsonValue.Create value.DefaultIn
            result["defaultOut"] <- JsonValue.Create value.DefaultOut
            result["runtimeEnabled"] <- JsonValue.Create value.RuntimeEnabled
            result
        let journal = JsonObject()
        journal["schemaVersion"] <- JsonValue.Create 1
        journal["ownerId"] <- JsonValue.Create ownerId
        journal["baseline"] <- settingsNode settings
        journal["managed"] <- settingsNode settings
        journal["pending"] <- null
        journal["pendingRules"] <- null
        journal["baselineRuntimeDigest"] <- JsonValue.Create runtimeDigest
        journal["baselineStoppedRuntimeDigest"] <- JsonValue.Create stoppedDigest
        journal

    let private settingsFromJournal (journal: JsonObject) (key: string) = validateSettingsNode key (prop (nodeObj journal "journal") key)

    let private updateManaged (journal: JsonObject) (settings: UfwSettings) =
        let managed = nodeObj (prop journal "managed") "managed"
        managed["enabled"] <- JsonValue.Create settings.Enabled
        managed["defaultIn"] <- JsonValue.Create settings.DefaultIn
        managed["defaultOut"] <- JsonValue.Create settings.DefaultOut
        managed["runtimeEnabled"] <- JsonValue.Create settings.RuntimeEnabled

    let private setPending (journal: JsonObject) (setting: string) (prior: obj) (target: obj) (runtimePrior: bool) (runtimeTarget: bool) (intermediate: bool) =
        let managed = nodeObj (prop journal "managed") "managed"
        managed[setting] <- nodeForSetting setting (box prior)
        managed["runtimeEnabled"] <- JsonValue.Create runtimePrior
        let pending = JsonObject()
        pending["setting"] <- JsonValue.Create setting
        pending["prior"] <- nodeForSetting setting (box prior)
        pending["target"] <- nodeForSetting setting (box target)
        pending["runtimePrior"] <- JsonValue.Create runtimePrior
        pending["runtimeTarget"] <- JsonValue.Create runtimeTarget
        pending["runtimeIntermediate"] <- JsonValue.Create intermediate
        journal["pending"] <- pending

    let private finishPending (journal: JsonObject) (setting: string) (target: obj) (runtimeEnabled: bool) =
        let managed = nodeObj (prop journal "managed") "managed"
        managed[setting] <- nodeForSetting setting (box target)
        managed["runtimeEnabled"] <- JsonValue.Create runtimeEnabled
        journal["pending"] <- null

    let private recoverPending (environment: HostEnvironment) (journal: JsonObject) (current: UfwSettings) =
        match journal["pending"] with
        | null -> ()
        | :? JsonObject as pending ->
            let setting = nodeString (prop pending "setting") "setting"
            let prior, target = prop pending "prior", prop pending "target"
            let actual =
                match setting with
                | "enabled" -> nodeForSetting setting (box current.Enabled)
                | "defaultIn" -> nodeForSetting setting (box current.DefaultIn)
                | "defaultOut" -> nodeForSetting setting (box current.DefaultOut)
                | _ -> nodeForSetting setting (box current.RuntimeEnabled)
            let runtimeIntermediate = nodeBool (prop pending "runtimeIntermediate") "runtimeIntermediate"
            let runtimeAccepted =
                current.RuntimeEnabled = nodeBool (prop pending "runtimePrior") "runtimePrior"
                || current.RuntimeEnabled = nodeBool (prop pending "runtimeTarget") "runtimeTarget"
                || (runtimeIntermediate && not current.RuntimeEnabled)
            let settingMatches = actual.ToJsonString() = prior.ToJsonString() || actual.ToJsonString() = target.ToJsonString()
            let settingAccepted = settingMatches || (setting = "runtimeEnabled" && runtimeIntermediate && not current.RuntimeEnabled)
            if not (runtimeAccepted && settingAccepted) then
                fail "UFW settings changed independently while a journaled mutation was incomplete"
            let resolved =
                if settingMatches then
                    if actual.ToJsonString() = prior.ToJsonString() then prior else target
                else actual
            finishPending journal setting resolved current.RuntimeEnabled
            saveJournal environment journal
        | _ -> fail "UFW settings journal pending mutation is malformed"

    let private parsePolicy (value: string) : string = match value with "allow" -> "ACCEPT" | "deny" -> "DROP" | "reject" -> "REJECT" | _ -> fail "invalid default policy"

    let runtimeUfwReachableChains (prefix: string) (jumpEdges: Map<string, Set<string>>) =
        let pending = Stack<string>([ "INPUT"; "OUTPUT"; "FORWARD" ])
        let visited = HashSet<string>([ "INPUT"; "OUTPUT"; "FORWARD" ], StringComparer.Ordinal)
        while pending.Count > 0 do
            let source = pending.Pop()
            match jumpEdges.TryFind source with
            | Some targets -> for target in targets do if visited.Add target then pending.Push target
            | None -> ()
        visited |> Seq.filter (fun chain -> chain.StartsWith(prefix + "-", StringComparison.Ordinal)) |> Set.ofSeq

    let runtimeFamilyIsActive (prefix: string) (chains: Set<string>) (hooks: Set<string * string>) (dispatchHooks: Set<string * string>) =
        let before = set [ prefix + "-before-input"; prefix + "-before-output"; prefix + "-before-forward" ]
        let user = set [ prefix + "-user-input"; prefix + "-user-output"; prefix + "-user-forward" ]
        let builtin = set [ "INPUT", prefix + "-before-input"; "OUTPUT", prefix + "-before-output"; "FORWARD", prefix + "-before-forward" ]
        let dispatch = set [ prefix + "-before-input", prefix + "-user-input"; prefix + "-before-output", prefix + "-user-output"; prefix + "-before-forward", prefix + "-user-forward" ]
        Set.isSubset before chains && Set.isSubset user chains && Set.isSubset builtin hooks && Set.isSubset dispatch dispatchHooks

    let runtimeIsPartial (prefix: string) (active: bool) (reachableChains: Set<string>) (chains: Set<string>) (allRules: Map<string, string array array>) (policies: Map<string, string>) =
        if active || Set.isEmpty reachableChains then false
        else
            let userChains = set [ prefix + "-user-input"; prefix + "-user-output"; prefix + "-user-forward" ]
            let hasReachableRules = reachableChains |> Seq.exists (fun chain -> allRules.TryFind chain |> Option.exists (fun rules -> rules.Length > 0))
            let hasUserTopology = not (Set.isEmpty (Set.intersect userChains chains))
            let hasRestrictiveBuiltin = [ "INPUT"; "OUTPUT"; "FORWARD" ] |> List.exists (fun chain -> policies.TryFind chain <> Some "ACCEPT")
            hasReachableRules || hasUserTopology || hasRestrictiveBuiltin

    let parseRuntimeTable (family: string) (stdout: string) =
        let prefix = if family = "4" then "ufw" else "ufw6"
        let chains = HashSet<string>(StringComparer.Ordinal)
        let policies = Dictionary<string, string>(StringComparer.Ordinal)
        let allRules = Dictionary<string, ResizeArray<string array>>(StringComparer.Ordinal)
        let rules = Dictionary<string, ResizeArray<string array>>(StringComparer.Ordinal)
        let jumpEdges = Dictionary<string, HashSet<string>>(StringComparer.Ordinal)
        let hooks = HashSet<string * string>()
        let dispatch = HashSet<string * string>()
        let builtin = set [ "INPUT"; "OUTPUT"; "FORWARD" ]
        let expectedHooks = dict [ "INPUT", prefix + "-before-input"; "OUTPUT", prefix + "-before-output"; "FORWARD", prefix + "-before-forward" ]
        let expectedDispatch = dict [ prefix + "-before-input", prefix + "-user-input"; prefix + "-before-output", prefix + "-user-output"; prefix + "-before-forward", prefix + "-user-forward" ]
        for name in [ prefix + "-user-input"; prefix + "-user-output"; prefix + "-user-forward" ] do rules[name] <- ResizeArray()
        let mutable related = false
        for line in stdout.Split([| '\n' |], StringSplitOptions.RemoveEmptyEntries) do
            if line.StartsWith(":", StringComparison.Ordinal) then
                let fields = line.Substring(1).Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
                if fields.Length > 0 then
                    let chain = fields[0]
                    chains.Add chain |> ignore
                    if Set.contains chain builtin && fields.Length > 1 then policies[chain] <- fields[1]
                    if chain.StartsWith(prefix + "-", StringComparison.Ordinal) then
                        related <- true
                        if not (allRules.ContainsKey chain) then allRules[chain] <- ResizeArray()
            elif line.StartsWith("-P ", StringComparison.Ordinal) then
                let fields = line.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
                if fields.Length = 3 && Set.contains fields[1] builtin then policies[fields[1]] <- fields[2]
            elif line.StartsWith("-A ", StringComparison.Ordinal) then
                let tokens = posixSplit line
                if tokens.Length >= 3 then
                    let source = tokens[1]
                    let jumpIndex = tokens |> Array.tryFindIndex (fun token -> token = "-j" || token = "--jump" || token = "-g" || token = "--goto")
                    match jumpIndex with
                    | Some index when index + 1 < tokens.Length ->
                        let target = tokens[index + 1]
                        let targets =
                            match jumpEdges.TryGetValue source with
                            | true, current -> current
                            | _ ->
                                let current = HashSet<string>(StringComparer.Ordinal)
                                jumpEdges[source] <- current
                                current
                        targets.Add target |> ignore
                        if expectedHooks.ContainsKey source && expectedHooks[source] = target then
                            hooks.Add(source, target) |> ignore
                            related <- true
                        if expectedDispatch.ContainsKey source && expectedDispatch[source] = target then
                            dispatch.Add(source, target) |> ignore
                            related <- true
                    | _ -> ()
                    if source.StartsWith(prefix + "-", StringComparison.Ordinal) then
                        related <- true
                        if not (allRules.ContainsKey source) then allRules[source] <- ResizeArray()
                        allRules[source].Add(normalizeIptablesTokens line)
                    if rules.ContainsKey source then rules[source].Add(normalizeIptablesTokens line)
        let chainSet = chains |> Seq.toList |> Set.ofList
        let hooksSet = hooks |> Seq.toList |> Set.ofList
        let dispatchSet = dispatch |> Seq.toList |> Set.ofList
        let edges = jumpEdges |> Seq.map (fun pair -> pair.Key, pair.Value |> Seq.toList |> Set.ofList) |> Map.ofSeq
        let active = runtimeFamilyIsActive prefix chainSet hooksSet dispatchSet
        let reachable = runtimeUfwReachableChains prefix edges
        let allMap = allRules |> Seq.map (fun pair -> pair.Key, pair.Value.ToArray()) |> Map.ofSeq
        let rulesMap = rules |> Seq.map (fun pair -> pair.Key, pair.Value.ToArray()) |> Map.ofSeq
        let policiesMap = policies |> Seq.map (fun pair -> pair.Key, pair.Value) |> Map.ofSeq
        let partial = runtimeIsPartial prefix active reachable chainSet allMap policiesMap
        { Family = family; Active = active; Partial = partial; Related = related; ReachableChains = reachable; Rules = rulesMap; AllRules = allMap; Policies = policiesMap; Chains = chainSet }

    let private runtimeTable (environment: HostEnvironment) (family: string) (required: bool) =
        let executable = if family = "4" then "iptables-save" else "ip6tables-save"
        let result =
            try Some(environment.Run executable [ "-t"; "filter" ] None)
            with _ -> None
        match result with
        | None ->
            if required then fail ("cannot inspect UFW runtime: " + executable + " is unavailable")
            else None
        | Some command when command.ExitCode <> 0 ->
            if required then
                let detail = if String.IsNullOrWhiteSpace command.Stderr then command.Stdout.Trim() else command.Stderr.Trim()
                fail ("cannot inspect UFW runtime with " + executable + ": " + detail)
            else None
        | Some command -> Some(parseRuntimeTable family command.Stdout)

    let private chainJumpTargets (table: UfwRuntimeTable) chain =
        table.AllRules.TryFind chain
        |> Option.defaultValue [||]
        |> Array.choose (fun tokens ->
            let index = tokens |> Array.tryFindIndex ((=) "-j")
            match index with Some value when value + 1 < tokens.Length -> Some tokens[value + 1] | _ -> None)

    let runtimePolicyDetails (table: UfwRuntimeTable) (direction: string) =
        let prefix = if table.Family = "4" then "ufw" else "ufw6"
        let builtin = if direction = "input" then "INPUT" else "OUTPUT"
        let builtinPolicy = table.Policies.TryFind builtin
        let skipTargets = chainJumpTargets table (prefix + "-skip-to-policy-" + direction)
        let skipTarget = if skipTargets.Length = 1 then Some skipTargets[0] else None
        let rejectReady = chainJumpTargets table (prefix + "-reject-" + direction) = [| "REJECT" |]
        let actual =
            if builtinPolicy = Some "ACCEPT" || skipTarget = Some "ACCEPT" then Some "allow"
            elif skipTarget = Some "REJECT" && rejectReady then Some "reject"
            elif builtinPolicy = Some "DROP" || skipTarget = Some "DROP" then Some "deny"
            else None
        actual, builtinPolicy, skipTarget, rejectReady

    let runtimePoliciesMatch (useIpv6: bool) (enabled: bool) (defaultIn: string) (defaultOut: string) (v4: UfwRuntimeTable) (v6: UfwRuntimeTable option) =
        let active = ResizeArray<UfwRuntimeTable>()
        if v4.Active then active.Add v4
        if useIpv6 then
            match v6 with
            | Some table when table.Active -> active.Add table
            | _ -> ()
        if active.Count = 0 then not enabled && not v4.Partial && (v6 |> Option.forall (fun table -> not table.Partial))
        elif enabled && not v4.Active then false
        elif enabled && useIpv6 && (v6 |> Option.forall (fun table -> not table.Active)) then false
        else
            active
            |> Seq.forall (fun table ->
                [ "input", defaultIn; "output", defaultOut ]
                |> List.forall (fun (direction, expected) ->
                    let actual, builtin, target, rejectReady = runtimePolicyDetails table direction
                    actual = Some expected
                    && builtin = Some(if expected = "allow" then "ACCEPT" else "DROP")
                    && target = Some(parsePolicy expected)
                    && (expected <> "reject" || rejectReady)))
            && (useIpv6 || v6 |> Option.forall (fun table -> not table.Active && not table.Partial))
    let private tupleFields (block: UfwRuleBlock) = block.Tuple.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
    let private unrestrictedSsh (port: int) (block: UfwRuleBlock) =
        let fields = tupleFields block
        fields.Length = 7
        && fields[0] = "allow"
        && fields[1] = "tcp"
        && fields[2] = port.ToString(CultureInfo.InvariantCulture)
        && (fields[3] = "0.0.0.0/0" || fields[3] = "::/0")
        && fields[4] = "any"
        && fields[5] = fields[3]
        && fields[6] = "in"
        && (block.Family = "4" || block.Family = "6")
        && not (block.Commands |> Array.exists (fun line -> line.Contains(" -i ", StringComparison.Ordinal) || line.Contains(" -o ", StringComparison.Ordinal) || line.Contains("_log", StringComparison.Ordinal) || line.Contains("dapp_", StringComparison.Ordinal) || line.Contains("sapp_", StringComparison.Ordinal)))
        && not (block.Commands |> Array.exists (fun line -> line.Contains("ufw-user-forward", StringComparison.Ordinal) || line.Contains("ufw6-user-forward", StringComparison.Ordinal)))

    let validateEnableGuard (desired: (UfwRuleBlock * UfwRuleBlock array) list) (port: int) (enabled: bool) (defaultOut: string) =
        if enabled then
            if defaultOut <> "allow" then fail "enabling UFW requires defaultOut to be allow"
            if List.isEmpty desired then
                fail "enabling UFW requires the first rule to allow unrestricted incoming TCP on sshPort for IPv4 and IPv6"
            let _, firstBlocks = desired.Head
            let v4 = firstBlocks |> Array.filter (fun block -> block.Family = "4")
            let v6 = firstBlocks |> Array.filter (fun block -> block.Family = "6")
            if v4.Length <> 1 || v6.Length <> 1 then
                fail "enabling UFW requires the first rule to allow unrestricted incoming TCP on sshPort for IPv4 and IPv6"
            if not (unrestrictedSsh port v4[0] && unrestrictedSsh port v6[0]) then
                fail "enabling UFW requires the first rule to allow unrestricted incoming TCP on sshPort"

    let private readRuntime (environment: HostEnvironment) (useIpv6: bool) (settings: UfwSettings) =
        let v4 = runtimeTable environment "4" true |> Option.get
        let ipv6Available = Directory.Exists(filePath environment "/proc/sys/net/ipv6")
        let v6 = if useIpv6 || ipv6Available then runtimeTable environment "6" useIpv6 else None
        let enabled = (v4.Active || (v6 |> Option.exists (fun table -> table.Active)))
        let shape =
            not v4.Partial && (v6 |> Option.forall (fun table -> not table.Partial))
            && (not settings.Enabled || v4.Active)
            && (not (settings.Enabled && useIpv6) || (v6 |> Option.exists (fun table -> table.Active)))
            && (useIpv6 || v6 |> Option.forall (fun table -> not table.Active))
            && (settings.Enabled || (not v4.Active && not v4.Partial && (v6 |> Option.forall (fun table -> not table.Active && not table.Partial))))
        let policyMatch = runtimePoliciesMatch useIpv6 settings.Enabled settings.DefaultIn settings.DefaultOut v4 v6
        enabled, shape && policyMatch, policyMatch, v4, v6

    let private userChainRulesFromLines (lines: string array) (family: string) =
        let names = if family = "4" then set [ "ufw-user-input"; "ufw-user-output"; "ufw-user-forward" ] else set [ "ufw6-user-input"; "ufw6-user-output"; "ufw6-user-forward" ]
        let results = Dictionary<string, ResizeArray<string array>>(StringComparer.Ordinal)
        for name in names do results[name] <- ResizeArray()
        for line in lines do
            let tokens = posixSplit line
            if tokens.Length >= 3 && tokens[0] = "-A" && Set.contains tokens[1] names then results[tokens[1]].Add(normalizeIptablesTokens line)
        results |> Seq.map (fun item -> item.Key, item.Value.ToArray()) |> Map.ofSeq

    let private persistentUfwUserChains (lines: string array) (family: string) =
        let prefix = if family = "4" then "ufw" else "ufw6"
        let results = Dictionary<string, ResizeArray<string array>>(StringComparer.Ordinal)
        for line in lines do
            if line.StartsWith(":", StringComparison.Ordinal) then
                let fields = line.Substring(1).Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
                if fields.Length > 0 && fields[0].StartsWith(prefix + "-user-", StringComparison.Ordinal) && not (results.ContainsKey fields[0]) then results[fields[0]] <- ResizeArray()
            else
                let tokens = posixSplit line
                if tokens.Length >= 3 && tokens[0] = "-A" && tokens[1].StartsWith(prefix + "-user-", StringComparison.Ordinal) then
                    if not (results.ContainsKey tokens[1]) then results[tokens[1]] <- ResizeArray()
                    results[tokens[1]].Add(normalizeIptablesTokens line)
        results |> Seq.map (fun item -> item.Key, item.Value.ToArray()) |> Map.ofSeq

    let runtimeRulesMatch (useIpv6: bool) (enabled: bool) (v4: UfwRuntimeTable) (v6: UfwRuntimeTable option) (userRules4: string) (userRules6: string) =
        if not v4.Active then
            not enabled && not v4.Partial && (v6 |> Option.forall (fun table -> not table.Active && not table.Partial))
        else
            let expected4 = persistentUfwUserChains (splitLines userRules4) "4"
            let actual4 = v4.AllRules |> Map.filter (fun name _ -> name.StartsWith("ufw-user-", StringComparison.Ordinal))
            if expected4 <> actual4 then false
            elif useIpv6 then
                match v6 with
                | None -> false
                | Some table -> table.Active && persistentUfwUserChains (splitLines userRules6) "6" = (table.AllRules |> Map.filter (fun name _ -> name.StartsWith("ufw6-user-", StringComparison.Ordinal)))
            else v6 |> Option.forall (fun table -> not table.Active && not table.Partial)

    let private jsonArray (writer: Utf8JsonWriter) (values: seq<'T>) (writeValue: Utf8JsonWriter -> 'T -> unit) =
        writer.WriteStartArray()
        for value in values do writeValue writer value
        writer.WriteEndArray()

    let runtimeDigest (v4: UfwRuntimeTable) (v6: UfwRuntimeTable option) =
        let encodeFamily (writer: Utf8JsonWriter) (family: string) (table: UfwRuntimeTable option) =
            writer.WritePropertyName family
            match table with
            | None -> writer.WriteNullValue()
            | Some item ->
                let effective = item.Active || item.Partial
                writer.WriteStartObject()
                writer.WriteBoolean("active", item.Active)
                writer.WritePropertyName("policy")
                if not effective then writer.WriteNullValue()
                else
                    writer.WriteStartObject()
                    writer.WritePropertyName("builtin")
                    writer.WriteStartObject()
                    for chain in [ "INPUT"; "OUTPUT" ] do
                        writer.WritePropertyName chain
                        match item.Policies.TryFind chain with Some policy -> writer.WriteRawValue(pyJsonString policy, true) | None -> writer.WriteNullValue()
                    writer.WriteEndObject()
                    writer.WritePropertyName("chains")
                    writer.WriteStartObject()
                    for suffix in [ "-reject-input"; "-reject-output"; "-skip-to-policy-input"; "-skip-to-policy-output" ] do
                        writer.WritePropertyName suffix
                        let chain = (if family = "4" then "ufw" else "ufw6") + suffix
                        let values = item.AllRules.TryFind chain |> Option.defaultValue [||]
                        jsonArray writer values (fun w tokens -> jsonArray w tokens (fun tokenWriter token -> tokenWriter.WriteRawValue(pyJsonString token, true)))
                    writer.WriteEndObject()
                    writer.WriteEndObject()
                writer.WritePropertyName("rules")
                writer.WriteStartObject()
                for (name, rules) in item.Rules |> Map.toSeq |> Seq.sortBy fst do
                    writer.WritePropertyName name
                    jsonArray writer (if effective then rules else [||]) (fun w tokens -> jsonArray w tokens (fun tokenWriter token -> tokenWriter.WriteRawValue(pyJsonString token, true)))
                writer.WriteEndObject()
                writer.WriteEndObject()
        use stream = new MemoryStream()
        use writer = new Utf8JsonWriter(stream)
        writer.WriteStartObject()
        encodeFamily writer "4" (Some v4)
        encodeFamily writer "6" v6
        writer.WriteEndObject()
        writer.Flush()
        sha256 (stream.ToArray())
    let validatePendingDelete
        (pending: JsonObject)
        (currentFiles: Map<string, string>)
        (targetFiles: Map<string, string>)
        (actualRuntime: string)
        (expectedAfter: string)
        (expectedStopped: string)
        =
        let fileDigests (files: Map<string, string>) = files |> Map.map (fun _ text -> sha256 (Encoding.UTF8.GetBytes text))
        let beforeHashes = fileDigests currentFiles
        let afterHashes = fileDigests targetFiles
        let storedBefore = nodeObj (prop pending "beforeFiles") "beforeFiles"
        let storedAfter = nodeObj (prop pending "afterFiles") "afterFiles"
        let storedHash (files: JsonObject) family = nodeString (prop files family) family
        let storedBeforeHashes = Map.ofList [ "4", storedHash storedBefore "4"; "6", storedHash storedBefore "6" ]
        let storedAfterHashes = Map.ofList [ "4", storedHash storedAfter "4"; "6", storedHash storedAfter "6" ]
        if afterHashes <> storedAfterHashes
           || (beforeHashes["4"] <> storedBeforeHashes["4"] && beforeHashes["4"] <> storedAfterHashes["4"])
           || (beforeHashes["6"] <> storedBeforeHashes["6"] && beforeHashes["6"] <> storedAfterHashes["6"]) then
            fail "UFW rule files changed outside the journaled Delete; refusing recovery"
        let storedRuntimeBefore = nodeString (prop pending "runtimeBefore") "runtimeBefore"
        let storedRuntimeAfter = nodeString (prop pending "runtimeAfter") "runtimeAfter"
        let storedRuntimeStopped = nodeString (prop pending "runtimeStopped") "runtimeStopped"
        if expectedAfter <> storedRuntimeAfter
           || expectedStopped <> storedRuntimeStopped
           || (actualRuntime <> storedRuntimeBefore && actualRuntime <> storedRuntimeAfter && actualRuntime <> storedRuntimeStopped) then
            fail "UFW runtime changed outside the journaled Delete; refusing recovery"
        pending

    let private expectedPolicyChains (defaultIn: string) (defaultOut: string) (family: string) =
        let prefix = if family = "4" then "ufw" else "ufw6"
        let builtin =
            Map.ofList
                [ "INPUT", (if defaultIn = "allow" then "ACCEPT" else "DROP")
                  "OUTPUT", (if defaultOut = "allow" then "ACCEPT" else "DROP") ]
        let chain direction policy =
            let target = parsePolicy policy
            let skip = [| [| "-A"; prefix + "-skip-to-policy-" + direction; "-j"; target |] |]
            let reject =
                if policy = "reject" then
                    [| [| "-A"; prefix + "-reject-" + direction; "-j"; "REJECT"; "--reject-with"; (if family = "6" then "icmp6-port-unreachable" else "icmp-port-unreachable") |] |]
                else [||]
            skip, reject
        let inSkip, inReject = chain "input" defaultIn
        let outSkip, outReject = chain "output" defaultOut
        builtin, Map.ofList [ "-skip-to-policy-input", inSkip; "-skip-to-policy-output", outSkip; "-reject-input", inReject; "-reject-output", outReject ]

    let expectedRuntimeDigest (useIpv6: bool) (contents: Map<string, string>) (settings: UfwSettings) (v4: UfwRuntimeTable) (v6: UfwRuntimeTable option) =
        let encodeFamily (writer: Utf8JsonWriter) (family: string) (table: UfwRuntimeTable option) =
            writer.WritePropertyName family
            match table with
            | None -> writer.WriteNullValue()
            | Some actual ->
                let active = settings.RuntimeEnabled && (family = "4" || useIpv6)
                let rules = if active then userChainRulesFromLines (splitLines contents[family]) family else actual.Rules |> Map.map (fun _ _ -> [||])
                writer.WriteStartObject()
                writer.WriteBoolean("active", active)
                writer.WritePropertyName("policy")
                if active then
                    let builtin, chains = expectedPolicyChains settings.DefaultIn settings.DefaultOut family
                    writer.WriteStartObject()
                    writer.WritePropertyName("builtin")
                    writer.WriteStartObject()
                    for (name, value) in builtin |> Map.toSeq |> Seq.sortBy fst do
                        writer.WritePropertyName name
                        writer.WriteRawValue(pyJsonString value, true)
                    writer.WriteEndObject()
                    writer.WritePropertyName("chains")
                    writer.WriteStartObject()
                    for (name, values) in chains |> Map.toSeq |> Seq.sortBy fst do
                        writer.WritePropertyName name
                        jsonArray writer values (fun w tokens -> jsonArray w tokens (fun tokenWriter token -> tokenWriter.WriteRawValue(pyJsonString token, true)))
                    writer.WriteEndObject()
                    writer.WriteEndObject()
                else writer.WriteNullValue()
                writer.WritePropertyName("rules")
                writer.WriteStartObject()
                for (name, entries) in rules |> Map.toSeq |> Seq.sortBy fst do
                    writer.WritePropertyName name
                    jsonArray writer entries (fun w tokens -> jsonArray w tokens (fun tokenWriter token -> tokenWriter.WriteRawValue(pyJsonString token, true)))
                writer.WriteEndObject()
                writer.WriteEndObject()
        use stream = new MemoryStream()
        use writer = new Utf8JsonWriter(stream)
        writer.WriteStartObject()
        encodeFamily writer "4" (Some v4)
        encodeFamily writer "6" v6
        writer.WriteEndObject()
        writer.Flush()
        sha256 (stream.ToArray())

    let private observedPolicy (tables: UfwRuntimeTable option list) direction fallback =
        tables
        |> List.tryPick (function
            | Some table when table.Active -> let actual, _, _, _ = runtimePolicyDetails table direction in actual
            | _ -> None)
        |> Option.defaultValue fallback

    let private actualRules (blocks: UfwRuleBlock array) (ownerPrefix: string) =
        blocks
        |> Array.filter (fun block -> containsPrefix ownerPrefix block.Marker)
        |> Array.sortBy (fun block -> if block.Family = "4" then 0 else 1)
        |> Array.map (fun block -> "[IPv" + block.Family + "] " + block.Canonical)


    let private commandPorts (singular: string) (plural: string) (commands: string array) (fallback: string) =
        let ports = ResizeArray<string>()
        for command in commands do
            let tokens = normalizeIptablesTokens command
            for index in 0 .. tokens.Length - 2 do
                if tokens[index] = singular || tokens[index] = plural then ports.Add tokens[index + 1]
        if ports.Count = 0 then [| fallback |] else ports |> Seq.distinct |> Seq.toArray

    let private semanticKeys (block: UfwRuleBlock) =
        let fields = tupleFields block
        if fields.Length < 7 then fail "native UFW returned an unsupported tuple record"
        let applicationRule = fields.Length >= 9
        let destinationApplication = applicationRule && fields[6] <> "-"
        let sourceApplication = applicationRule && fields[7] <> "-"
        let destinationPorts =
            if destinationApplication then commandPorts "--dport" "--dports" block.Commands fields[2]
            else [| fields[2] |]
        let sourcePorts =
            if sourceApplication then commandPorts "--sport" "--sports" block.Commands fields[4]
            else [| fields[4] |]
        let interfaceToken = if applicationRule then fields[8] else fields[6]
        let direction = interfaceToken.Split([| '_' |], 2, StringSplitOptions.None)[0]
        let mutable interfaceIn = ""
        let mutable interfaceOut = ""
        for interfacePart in interfaceToken.Split('!') do
            if interfacePart.StartsWith("in_", StringComparison.Ordinal) then interfaceIn <- interfacePart.Substring(3)
            elif interfacePart.StartsWith("out_", StringComparison.Ordinal) then interfaceOut <- interfacePart.Substring(4)
        let forward = fields[0].StartsWith("route:", StringComparison.Ordinal)
        [| for destinationPort in destinationPorts do
               for sourcePort in sourcePorts do
                   yield
                       String.concat
                           "\u001f"
                           [ fields[1]
                             destinationPort
                             normalizedNetwork fields[3]
                             sourcePort
                             normalizedNetwork fields[5]
                             block.Family
                             direction
                             (if forward then "1" else "0")
                             interfaceIn
                             interfaceOut ] |]

    let semanticKey (block: UfwRuleBlock) =
        semanticKeys block |> Array.sort |> String.concat "\u001e"

    let hasUnmanagedSemanticCollision (desired: UfwRuleBlock array) (current: UfwRuleBlock array) (ownerPrefix: string) =
        desired
        |> Array.exists (fun wanted ->
            let wantedKeys = semanticKeys wanted |> Set.ofArray
            current
            |> Array.exists (fun observed ->
                observed.Family = wanted.Family
                && not (markerMatches ownerPrefix observed)
                && (semanticKeys observed |> Array.exists (fun key -> Set.contains key wantedKeys))))


    let private readFileRecords (text: string) =
        let lines = splitLines text
        let start, finish = ruleSection lines
        let body, ranges = ruleBlocks lines start finish
        body, ranges |> Array.map (fun (left, right, _) -> blockInBody body left right)

    let ownerRuleBlocksMatch (ownerPrefix: string) (actual: UfwRuleBlock array) (expected: UfwRuleBlock array) =
        let owned = actual |> Array.filter (markerMatches ownerPrefix)
        let expectedMarkers = expected |> Array.choose (fun block -> block.Marker)
        let actualMarkers = owned |> Array.choose (fun block -> block.Marker)
        let positions =
            actual
            |> Array.mapi (fun index block -> index, block)
            |> Array.choose (fun (index, block) -> if markerMatches ownerPrefix block then Some index else None)
        let contiguous = positions = [| actual.Length - positions.Length .. actual.Length - 1 |]
        owned.Length = expected.Length
        && actualMarkers = expectedMarkers
        && contiguous
        && (Array.zip owned expected
            |> Array.forall (fun (observed, wanted) ->
                observed.Family = wanted.Family
                && observed.Tuple = wanted.Tuple
                && (observed.Commands |> Array.map normalizeIptablesTokens)
                   = (wanted.Commands |> Array.map normalizeIptablesTokens)))


    let private verifyNativeGroups (environment: HostEnvironment) (blocks: UfwRuleBlock array) =
        let key (block: UfwRuleBlock) =
            let identity = block.Marker |> Option.defaultValue block.Canonical
            block.Family + "\u001f" + identity
        let commandCounts (records: UfwRuleBlock array) =
            records
            |> Array.collect (fun record -> record.Commands)
            |> Array.map normalizeIptablesTokens
            |> Array.map (String.concat "\u001f")
            |> Array.toList
            |> List.countBy id
            |> Map.ofList
        for _, group in blocks |> Array.groupBy key do
            let first = group[0]
            let probe = "keroosha-iac:verify:" + Guid.NewGuid().ToString("N")
            let tokens = posixSplit first.Canonical |> Array.toList
            let generated = renderRule environment tokens probe |> Array.filter (fun record -> record.Family = first.Family)
            if commandCounts generated <> commandCounts group then
                fail "UFW user rule file contains raw or modified commands that cannot be attributed to native rule metadata"
    let private expectedOwnedCommands (environment: HostEnvironment) ownerPrefix family (text: string) =
        let _, records = readFileRecords text
        let owned = records |> Array.filter (fun block -> block.Family = family && markerMatches ownerPrefix block)
        if owned |> Array.exists (fun block -> Option.isNone block.Marker) then
            fail "owned UFW rule marker is not parseable by the native backend; refusing to remove an unknown record"
        verifyNativeGroups environment owned
        owned
        |> Array.groupBy (fun block -> Option.get block.Marker)
        |> Array.map (fun (marker, group) -> marker, group |> Array.collect (fun block -> block.Commands))
        |> Map.ofArray

    let removeOwnedBlocksFromText (ownerPrefix: string) (family: string) (expectedByMarker: Map<string, string array>) (text: string) =
        let lines = splitLines text
        let start, finish = ruleSection lines
        let body, ranges = ruleBlocks lines start finish
        let output = ResizeArray<string>()
        let remaining = Dictionary<string, ResizeArray<string array>>(StringComparer.Ordinal)
        for KeyValue(marker, commands) in expectedByMarker do
            remaining[marker] <- ResizeArray(commands |> Array.map normalizeIptablesTokens)
        let mutable cursor = 0
        let mutable changed = false
        for left, right, _ in ranges do
            let block = blockInBody body left right
            if block.Family = family && markerMatches ownerPrefix block then
                let marker = block.Marker |> Option.defaultWith (fun () -> fail "owned UFW rule marker is not parseable by the native backend; refusing to remove an unknown record")
                if not (remaining.ContainsKey marker) then
                    fail "owned UFW rule marker has no verified native command block"
                for index in cursor .. left - 1 do output.Add body[index]
                cursor <- right
                changed <- true
                for line in block.Lines do
                    if line.StartsWith("### tuple ###", StringComparison.Ordinal) then ()
                    elif line.TrimStart().StartsWith("-A ", StringComparison.Ordinal) then
                        let normalized = normalizeIptablesTokens line
                        let commands = remaining[marker]
                        let index = commands |> Seq.tryFindIndex ((=) normalized)
                        match index with
                        | Some found -> commands.RemoveAt found
                        | None -> fail "owned UFW rule block contains an unattributable raw record; remove or repair it before Delete/apply"
                    elif line.TrimStart().StartsWith("-I ", StringComparison.Ordinal) then
                        fail "owned UFW rule block contains an unattributable raw record; remove or repair it before Delete/apply"
                    elif not (String.IsNullOrWhiteSpace line) then output.Add line
        for commands in remaining.Values do
            if commands.Count > 0 then fail "native UFW reports an owned rule without a matching marker record; refusing to rewrite it"
        for index in cursor .. body.Length - 1 do output.Add body[index]
        if not changed then text, false
        else String.concat "\n" (Array.append lines[0 .. start] (Array.append (output.ToArray()) lines[finish ..])), true
    let insertNativeBlocks (family: string) (blocks: UfwRuleBlock array) (text: string) =
        let additionsForFamily = blocks |> Array.filter (fun block -> block.Family = family)
        if additionsForFamily.Length = 0 then text, false
        else
            let lines = splitLines text
            let start, finish = ruleSection lines
            let body, existing = ruleBlocks lines start finish
            let firstHelper = body |> Array.tryFindIndex isAuxiliaryRule
            let lastTupleEnd = existing |> Array.map (fun (left, right, _) -> right) |> Array.fold max 0
            let insertAt = match firstHelper with Some helper when lastTupleEnd <= helper -> helper | _ -> body.Length
            let additions =
                additionsForFamily
                |> Array.collect (fun block -> block.Lines |> Array.filter (fun line -> line <> "COMMIT" && line <> "### END RULES ###"))
                |> Array.rev
                |> Array.skipWhile String.IsNullOrWhiteSpace
                |> Array.rev
            let updatedBody = Array.concat [ body[0 .. insertAt - 1]; additions; body[insertAt ..] ]
            let output = Array.concat [ lines[0 .. start]; updatedBody; lines[finish ..] ]
            let updated = String.concat "\n" output
            updated, updated <> text

    let reconcileOwnedRuleBlocks (ownerPrefix: string) (family: string) (expectedByMarker: Map<string, string array>) (desired: UfwRuleBlock array) (text: string) =
        let withoutOwned, _ = removeOwnedBlocksFromText ownerPrefix family expectedByMarker text
        let updated, _ = insertNativeBlocks family desired withoutOwned
        updated, updated <> text

    let private removeOwnedFromText (environment: HostEnvironment) (ownerPrefix: string) (family: string) (text: string) =
        let _, records = readFileRecords text
        let owned = records |> Array.filter (fun block -> block.Family = family && markerMatches ownerPrefix block)
        if owned |> Array.exists (fun block -> block.Marker.IsNone) then
            fail "owned UFW rule marker is not parseable by the native backend; refusing to remove an unknown record"
        verifyNativeGroups environment owned
        let expected =
            owned
            |> Array.groupBy (fun block -> block.Marker.Value)
            |> Array.map (fun (marker, blocks) -> marker, blocks |> Array.collect (fun block -> block.Commands))
            |> Map.ofArray
        removeOwnedBlocksFromText ownerPrefix family expected text

    let private applyDesiredToText (environment: HostEnvironment) (ownerPrefix: string) (family: string) (desired: UfwRuleBlock array) (text: string) =
        let expected = expectedOwnedCommands environment ownerPrefix family text
        reconcileOwnedRuleBlocks ownerPrefix family expected desired text

    let private validateNativeUserFile (environment: HostEnvironment) (family: string) (text: string) =
        let lines = splitLines text
        let start, finish = ruleSection lines
        let body, ranges = ruleBlocks lines start finish
        let records = ranges |> Array.map (fun (left, right, _) -> blockInBody body left right)
        verifyNativeGroups environment records
        let covered = HashSet<int>()
        for left, right, _ in ranges do for index in left .. right - 1 do covered.Add index |> ignore
        let prefix = if family = "4" then "ufw-user-" else "ufw6-user-"
        for index in 0 .. body.Length - 1 do
            let tokens = if String.IsNullOrWhiteSpace body[index] then [||] else posixSplit body[index]
            if tokens.Length >= 3 && (tokens[0] = "-A" || tokens[0] = "-I") && tokens[1].StartsWith(prefix, StringComparison.Ordinal) && Set.contains tokens[1] userChains && not (covered.Contains index) then
                fail ("UFW IPv" + family + " user rules contain unmanaged raw entries or disagree with native rule metadata; refusing an unverifiable semantic collision")

    let private checkCollisions (desired: UfwRuleBlock array) (current4: UfwRuleBlock array) (current6: UfwRuleBlock array) (ownerPrefix: string) =
        let current = Array.append current4 current6
        if hasUnmanagedSemanticCollision desired current ownerPrefix then
            let wanted =
                desired
                |> Array.find (fun rule ->
                    current
                    |> Array.exists (fun observed ->
                        observed.Family = rule.Family
                        && not (markerMatches ownerPrefix observed)
                        && semanticKey observed = semanticKey rule))
            fail ("desired UFW rule " + pyJsonString wanted.Canonical + " collides with an unmanaged rule; refusing to let UFW replace its comment")

    let private getOwned (blocks: UfwRuleBlock array) (prefix: string) = blocks |> Array.filter (markerMatches prefix)

    let private requestSettings (enabled: bool) (defaultIn: string) (defaultOut: string) (runtimeEnabled: bool) =
        { Enabled = enabled; DefaultIn = defaultIn; DefaultOut = defaultOut; RuntimeEnabled = runtimeEnabled }
    let runtimeConvergenceAction (runtimeEnabled: bool) (requestedEnabled: bool) (defaultsChanged: bool) (rulesChanged: bool) (runtimeNeedsRepair: bool) (runtimeNeedsRestart: bool) : UfwRuntimeAction =
        if runtimeEnabled && requestedEnabled && (defaultsChanged || runtimeNeedsRestart) then UfwRuntimeAction.RestartRuntime
        elif not runtimeEnabled && requestedEnabled then UfwRuntimeAction.StartRuntime
        elif runtimeEnabled && not requestedEnabled then UfwRuntimeAction.StopRuntime
        elif runtimeEnabled && requestedEnabled && (rulesChanged || runtimeNeedsRepair) then UfwRuntimeAction.ReloadRuntime
        else UfwRuntimeAction.KeepRuntime

    let private setDefault (environment: HostEnvironment) (policy: string) (direction: string) =
        let result = environment.Run "ufw" [ "default"; policy; direction ] None
        if result.ExitCode <> 0 then fail ("native UFW could not persist the requested default " + direction + " policy")

    let private setEnabledConfig (environment: HostEnvironment) enabled =
        let contents, mode = readRegularFile environment "/etc/ufw/ufw.conf" "UFW configuration file"
        let pattern = "(?m)^([ \\t]*ENABLED[ \\t]*=[ \\t]*)\"?[A-Za-z]+\"?([ \\t]*(?:#.*)?\\r?)$"
        let matches = Regex.Matches(contents, pattern, RegexOptions.CultureInvariant)
        if matches.Count <> 1 then fail "UFW configuration does not contain one unambiguous ENABLED setting"
        let value = if enabled then "yes" else "no"
        let updated = Regex.Replace(contents, pattern, MatchEvaluator(fun matched -> matched.Groups[1].Value + value + matched.Groups[2].Value), RegexOptions.CultureInvariant)
        writeAtomic environment "/etc/ufw/ufw.conf" updated contents mode "UFW configuration file" |> ignore

    let private setEnabledRuntime (environment: HostEnvironment) (enabled: bool) =
        if enabled then enableAndReload environment
        else
            let result = environment.Run "ufw" [ "--force"; "disable" ] None
            if result.ExitCode <> 0 then fail "native UFW could not disable the firewall"

    let private reload environment =
        let result = environment.Run "ufw" [ "reload" ] None
        if result.ExitCode <> 0 then fail "native UFW could not reload user rules"
    let private reloadAndSynchronize (environment: HostEnvironment) =
        // Native start rewrites user.rules after its first kernel load.
        reload environment
        reload environment

    let private configSettings (environment: HostEnvironment) (runtimeEnabled: bool) =
        let settings, ipv6 = parseConfig environment
        { settings with RuntimeEnabled = runtimeEnabled }, ipv6

    let private snapshot (environment: HostEnvironment) (ownerId: string) (requestRules: string list list) (sshPort: int) (enabled: bool) (defaultIn: string) (defaultOut: string) (journal: JsonObject option) =
        let settings, useIpv6 = configSettings environment false
        let actualEnabled, shapeOk, policyMatch, v4, v6 = readRuntime environment useIpv6 settings
        let current4, current6 = readRulesFiles environment
        let records4 = parseRecords (fst current4)
        let records6 = parseRecords (fst current6)
        let prefix = ownerMarkerPrefix ownerId
        let desired = makeDesiredRules environment ownerId requestRules
        validateEnableGuard desired sshPort enabled defaultOut
        let desiredBlocks = desired |> List.collect (fun (_, blocks) -> Array.toList blocks) |> List.toArray
        let actualOwned4 = getOwned records4 prefix
        let actualOwned6 = getOwned records6 prefix
        let expected4 = desiredBlocks |> Array.filter (fun block -> block.Family = "4")
        let expected6 = desiredBlocks |> Array.filter (fun block -> block.Family = "6")
        let fileMatch =
            (fst current4 |> fun text -> validateNativeUserFile environment "4" text; true)
            && (fst current6 |> fun text -> validateNativeUserFile environment "6" text; true)
        let ownerMatch =
            ownerRuleBlocksMatch prefix records4 expected4
            && ownerRuleBlocksMatch prefix records6 expected6
        let runtimeRules = runtimeRulesMatch useIpv6 settings.Enabled v4 v6 (fst current4) (fst current6)
        let settingsCurrent = { settings with RuntimeEnabled = actualEnabled }
        let journalMatches =
            match journal with
            | Some value ->
                let managed = settingsFromJournal value "managed"
                managed = settingsCurrent && isNull value["pending"] && isNull value["pendingRules"]
            | None -> false
        let actualDefaultIn = observedPolicy [ Some v4; v6 ] "input" settings.DefaultIn
        let actualDefaultOut = observedPolicy [ Some v4; v6 ] "output" settings.DefaultOut
        let inSync = ownerMatch && fileMatch && runtimeRules && policyMatch && shapeOk && settings.Enabled = enabled && actualEnabled = enabled && actualDefaultIn = defaultIn && actualDefaultOut = defaultOut && journalMatches
        let response = JsonObject()
        let rulesNode = JsonArray()
        for rule in actualRules (Array.append records4 records6) prefix do rulesNode.Add(JsonValue.Create rule)
        response["actualRules"] <- rulesNode
        response["actualEnabled"] <- JsonValue.Create actualEnabled
        response["actualDefaultIn"] <- JsonValue.Create actualDefaultIn
        response["actualDefaultOut"] <- JsonValue.Create actualDefaultOut
        response["inSync"] <- JsonValue.Create inSync
        response :> JsonNode

    let private mutateSettings (environment: HostEnvironment) (journal: JsonObject) (current: UfwSettings) (requested: UfwSettings) (rulesChanged: bool) (runtimeNeedsRepair: bool) (runtimeNeedsRestart: bool) =
        let mutable currentSettings = current
        let mutable defaultsChanged = false
        let changePolicy setting direction target prior =
            if prior <> target then
                setPending journal setting prior target currentSettings.RuntimeEnabled currentSettings.RuntimeEnabled currentSettings.RuntimeEnabled
                saveJournal environment journal
                setDefault environment target direction
                let observed, _ = parseConfig environment
                let actual = if setting = "defaultIn" then observed.DefaultIn else observed.DefaultOut
                if actual <> target then fail ("native UFW did not persist the requested " + setting + " setting")
                finishPending journal setting target currentSettings.RuntimeEnabled
                saveJournal environment journal
                defaultsChanged <- true
                currentSettings <-
                    if setting = "defaultIn" then { currentSettings with DefaultIn = target }
                    else { currentSettings with DefaultOut = target }
        changePolicy "defaultIn" "incoming" requested.DefaultIn currentSettings.DefaultIn
        changePolicy "defaultOut" "outgoing" requested.DefaultOut currentSettings.DefaultOut
        if currentSettings.Enabled <> requested.Enabled then
            setPending journal "enabled" currentSettings.Enabled requested.Enabled currentSettings.RuntimeEnabled currentSettings.RuntimeEnabled false
            saveJournal environment journal
            setEnabledConfig environment requested.Enabled
            let observed, _ = parseConfig environment
            if observed.Enabled <> requested.Enabled then fail "native UFW did not persist the requested enabled setting"
            finishPending journal "enabled" requested.Enabled currentSettings.RuntimeEnabled
            saveJournal environment journal
            currentSettings <- { currentSettings with Enabled = requested.Enabled }
        let action =
            runtimeConvergenceAction
                currentSettings.RuntimeEnabled
                requested.Enabled
                defaultsChanged
                rulesChanged
                runtimeNeedsRepair
                runtimeNeedsRestart
        match action with
        | RestartRuntime ->
            setPending journal "runtimeEnabled" true true true true true
            saveJournal environment journal
            if defaultsChanged && current.Enabled then reload environment
            else reloadAndSynchronize environment
            finishPending journal "runtimeEnabled" true true
            saveJournal environment journal
            currentSettings <- { currentSettings with RuntimeEnabled = true }
        | StartRuntime ->
            setPending journal "runtimeEnabled" false true false true false
            saveJournal environment journal
            setEnabledRuntime environment true
            finishPending journal "runtimeEnabled" true true
            saveJournal environment journal
            currentSettings <- { currentSettings with RuntimeEnabled = true }
        | StopRuntime ->
            setPending journal "runtimeEnabled" true false true false false
            saveJournal environment journal
            setEnabledRuntime environment false
            finishPending journal "runtimeEnabled" false false
            saveJournal environment journal
            currentSettings <- { currentSettings with RuntimeEnabled = false }
        | ReloadRuntime ->
            setPending journal "runtimeEnabled" true true true true false
            saveJournal environment journal
            reloadAndSynchronize environment
            finishPending journal "runtimeEnabled" true true
            saveJournal environment journal
        | KeepRuntime -> ()
        let updated = { requested with RuntimeEnabled = currentSettings.RuntimeEnabled }
        updateManaged journal updated
        journal["pending"] <- null
        saveJournal environment journal
        updated

    let private apply (environment: HostEnvironment) (ownerId: string) (sshPort: int) (rules: string list list) (enabled: bool) (defaultIn: string) (defaultOut: string) =
        enforceRoot environment
        ensureNativeUfw environment
        use _lock = HostFiles.lockFile(filePath environment lockPath)
        let config, useIpv6 = parseConfig environment
        let runtime, shape, _policyMatch, v4, v6 = readRuntime environment useIpv6 config
        let current = { config with RuntimeEnabled = runtime }
        let journalOpt = loadJournal environment ownerId false
        let first = Option.isNone journalOpt
        let journal =
            match journalOpt with
            | Some value -> value
            | None ->
                newJournal
                    ownerId
                    current
                    (runtimeDigest v4 v6)
                    (expectedRuntimeDigest useIpv6 (Map.ofList [ "4", ""; "6", "" ]) { current with RuntimeEnabled = false } v4 v6)
        if not (isNull journal["pendingRules"]) then fail "a prior UFW Delete is incomplete; retry Delete before Apply"
        let desired = makeDesiredRules environment ownerId rules
        validateEnableGuard desired sshPort enabled defaultOut
        let desiredBlocks = desired |> List.collect (fun (_, blocks) -> Array.toList blocks) |> List.toArray
        let (text4, mode4), (text6, mode6) = readRulesFiles environment
        let records4, records6 = parseRecords text4, parseRecords text6
        checkCollisions desiredBlocks records4 records6 (ownerMarkerPrefix ownerId)
        validateNativeUserFile environment "4" text4
        validateNativeUserFile environment "6" text6
        if desiredBlocks |> Array.exists (fun block -> block.Family = "6") && not useIpv6 then
            fail "UFW IPv6 rules are requested but IPv6 is disabled in /etc/default/ufw"
        let runtimeRulesCurrentlyMatch = runtimeRulesMatch useIpv6 config.Enabled v4 v6 text4 text6
        if first && (config.Enabled <> runtime || not shape || not runtimeRulesCurrentlyMatch) then
            fail "UFW has inconsistent persisted and kernel state before first ownership; reconcile it before applying this resource"
        let next4, changed4 = applyDesiredToText environment (ownerMarkerPrefix ownerId) "4" desiredBlocks text4
        let next6, changed6 = applyDesiredToText environment (ownerMarkerPrefix ownerId) "6" desiredBlocks text6
        if first then saveJournal environment journal
        match journal["pending"] with
        | :? JsonObject -> recoverPending environment journal current
        | _ -> ()
        let changed4OnDisk = writeAtomic environment "/etc/ufw/user.rules" next4 text4 mode4 "UFW user rule file"
        let changed6OnDisk = writeAtomic environment "/etc/ufw/user6.rules" next6 text6 mode6 "UFW user rule file"
        let rulesChanged = changed4 || changed6 || changed4OnDisk || changed6OnDisk
        let requested = requestSettings enabled defaultIn defaultOut runtime
        mutateSettings environment journal current requested rulesChanged (not runtimeRulesCurrentlyMatch) (not shape) |> ignore
        let finalJournal = loadJournal environment ownerId false
        let response = snapshot environment ownerId rules sshPort enabled defaultIn defaultOut finalJournal
        if not ((response.AsObject()["inSync"]).GetValue<bool>()) then
            fail "UFW changes were applied but the observed firewall did not converge to the requested state"
        response

    let private delete (environment: HostEnvironment) (ownerId: string) =
        enforceRoot environment
        ensureNativeUfw environment
        use _lock = HostFiles.lockFile(filePath environment lockPath)
        let config, useIpv6 = parseConfig environment
        let runtime, shape, policyMatch, v4, v6 = readRuntime environment useIpv6 config
        let current = { config with RuntimeEnabled = runtime }
        let hadJournal = loadJournal environment ownerId false
        match hadJournal with
        | Some journal ->
            recoverPending environment journal current
            if settingsFromJournal journal "managed" <> current then
                fail "UFW settings changed independently; refusing to overwrite them during Delete"
        | None -> ()
        let prefix = ownerMarkerPrefix ownerId
        let (text4, mode4), (text6, mode6) = readRulesFiles environment
        let records4, records6 = parseRecords text4, parseRecords text6
        let ownerExists = not (Array.isEmpty (getOwned records4 prefix)) || not (Array.isEmpty (getOwned records6 prefix))
        if Option.isNone hadJournal && not ownerExists then JsonObject() :> JsonNode
        else
            let journal =
                hadJournal
                |> Option.defaultWith (fun () ->
                    newJournal
                        ownerId
                        current
                        (runtimeDigest v4 v6)
                        (expectedRuntimeDigest useIpv6 (Map.ofList [ "4", ""; "6", "" ]) { current with RuntimeEnabled = false } v4 v6))
            let after4, _ = removeOwnedFromText environment prefix "4" text4
            let after6, _ = removeOwnedFromText environment prefix "6" text6
            let beforeHashes = Map.ofList [ "4", sha256 (Encoding.UTF8.GetBytes text4); "6", sha256 (Encoding.UTF8.GetBytes text6) ]
            let afterHashes = Map.ofList [ "4", sha256 (Encoding.UTF8.GetBytes after4); "6", sha256 (Encoding.UTF8.GetBytes after6) ]
            let contentsAfter = Map.ofList [ "4", after4; "6", after6 ]
            let runtimeBefore = runtimeDigest v4 v6
            let baseline = settingsFromJournal journal "baseline"
            let stoppedBaseline = { baseline with RuntimeEnabled = false }
            let expectedAfter = expectedRuntimeDigest useIpv6 contentsAfter baseline v4 v6
            let expectedStopped = expectedRuntimeDigest useIpv6 contentsAfter stoppedBaseline v4 v6
            let pendingRules =
                match journal["pendingRules"] with
                | null ->
                    let normalRuntime =
                        config.Enabled = runtime
                        && shape
                        && policyMatch
                        && runtimeRulesMatch useIpv6 config.Enabled v4 v6 text4 text6
                    let knownRecoveryState =
                        match hadJournal with
                        | Some existing ->
                            runtimeBefore = nodeString (prop existing "baselineRuntimeDigest") "baselineRuntimeDigest"
                            || runtimeBefore = nodeString (prop existing "baselineStoppedRuntimeDigest") "baselineStoppedRuntimeDigest"
                        | None -> false
                    if not normalRuntime && not knownRecoveryState then
                        fail "UFW runtime changed independently; refusing to overwrite it during Delete"
                    let pending = JsonObject()
                    pending["operation"] <- JsonValue.Create "delete"
                    let before = JsonObject()
                    before["4"] <- JsonValue.Create beforeHashes["4"]
                    before["6"] <- JsonValue.Create beforeHashes["6"]
                    let after = JsonObject()
                    after["4"] <- JsonValue.Create afterHashes["4"]
                    after["6"] <- JsonValue.Create afterHashes["6"]
                    pending["beforeFiles"] <- before
                    pending["afterFiles"] <- after
                    pending["runtimeBefore"] <- JsonValue.Create runtimeBefore
                    pending["runtimeAfter"] <- JsonValue.Create expectedAfter
                    pending["runtimeStopped"] <- JsonValue.Create expectedStopped
                    journal["pendingRules"] <- pending
                    saveJournal environment journal
                    pending
                | :? JsonObject as pending ->
                    validatePendingDelete
                        pending
                        (Map.ofList [ "4", text4; "6", text6 ])
                        contentsAfter
                        runtimeBefore
                        expectedAfter
                        expectedStopped
                | _ -> fail "UFW settings journal pending rule mutation is malformed"
            let changed4 = writeAtomic environment "/etc/ufw/user.rules" after4 text4 mode4 "UFW user rule file"
            let changed6 = writeAtomic environment "/etc/ufw/user6.rules" after6 text6 mode6 "UFW user rule file"
            mutateSettings
                environment
                journal
                current
                baseline
                (changed4 || changed6)
                (runtimeBefore <> expectedAfter)
                false
            |> ignore
            let finalConfig, finalIpv6 = parseConfig environment
            let finalEnabled, finalShape, finalPolicyMatch, final4, final6 = readRuntime environment finalIpv6 finalConfig
            let finalCurrent = { finalConfig with RuntimeEnabled = finalEnabled }
            let finalText4, _ = readRegularFile environment "/etc/ufw/user.rules" "UFW user rule file"
            let finalText6, _ = readRegularFile environment "/etc/ufw/user6.rules" "UFW user rule file"
            validateNativeUserFile environment "4" finalText4
            validateNativeUserFile environment "6" finalText6
            let finalRecords = Array.append (parseRecords finalText4) (parseRecords finalText6)
            let afterFiles = nodeObj (prop pendingRules "afterFiles") "afterFiles"
            let filesMatch =
                sha256 (Encoding.UTF8.GetBytes finalText4) = nodeString (prop afterFiles "4") "4"
                && sha256 (Encoding.UTF8.GetBytes finalText6) = nodeString (prop afterFiles "6") "6"
            let finalRulesMatch =
                runtimeRulesMatch finalIpv6 baseline.Enabled final4 final6 finalText4 finalText6
            let finalRuntime = runtimeDigest final4 final6
            let expectedRuntimeAfter = nodeString (prop pendingRules "runtimeAfter") "runtimeAfter"
            if finalCurrent <> baseline
               || finalEnabled <> baseline.RuntimeEnabled
               || not finalShape
               || not finalPolicyMatch
               || not finalRulesMatch
               || not (Array.isEmpty (getOwned finalRecords prefix))
               || not filesMatch
               || finalRuntime <> expectedRuntimeAfter then
                fail "UFW Delete did not restore the observed baseline; ownership journal retained for recovery"
            updateManaged journal baseline
            journal["pending"] <- null
            journal["pendingRules"] <- null
            saveJournal environment journal
            removeJournal environment ownerId
            JsonObject() :> JsonNode

    let private readLock (environment: HostEnvironment) : IDisposable =
        let path = filePath environment lockPath
        if File.Exists path then HostFiles.lockFile path
        else
            { new IDisposable with
                member _.Dispose() = () }

    let handle (environment: HostEnvironment) (request: JsonElement) : JsonNode =
        let operation, ownerId, sshPort, rules, enabled, defaultIn, defaultOut = validateRequest request
        match operation with
        | "apply" -> apply environment ownerId sshPort rules enabled defaultIn defaultOut
        | "delete" -> delete environment ownerId
        | "read" ->
            enforceRoot environment
            ensureNativeUfw environment
            use _lock = readLock environment
            let journal = loadJournal environment ownerId false
            snapshot environment ownerId rules sshPort enabled defaultIn defaultOut journal
        | _ -> fail "unsupported helper operation"
