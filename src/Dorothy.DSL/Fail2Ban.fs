namespace Dorothy.DSL

open System
open System.Collections.Generic
open System.Globalization
open System.Text

[<RequireQualifiedAccess>]
type internal Fail2BanOptionMergeBehavior =
    | Scalar
    | Append

[<Sealed>]
type Fail2BanOption
    internal (name: string, value: string, mergeBehavior: Fail2BanOptionMergeBehavior, appendValues: string list) =
    member _.Name = name
    member _.Value = value
    member internal _.MergeBehavior = mergeBehavior
    member internal _.AppendValues = appendValues

[<Sealed>]
type Fail2BanSectionSpec internal (path: string, name: string, options: Fail2BanOption list) =
    member _.Path = path
    member _.Name = name
    member _.Options = options

[<Sealed>]
type Fail2BanInputSpec internal (parts: Fail2BanPart list, manageSshdPorts: bool option) =
    member _.Parts = parts
    member _.ManageSshdPorts = manageSshdPorts

and Fail2BanPart =
    | Option of Fail2BanOption
    | Section of Fail2BanSectionSpec
    | File of path: string * contents: string
    | PythonAction of name: string * source: string
    | ManageSshdPorts of bool

[<Sealed>]
type Fail2BanSpec internal (files: Map<string, string>, manageSshdPorts: bool) =
    member _.Files = files
    member _.ManageSshdPorts = manageSshdPorts

module private Fail2BanValidation =
    let optionName (name: string) =
        if
            String.IsNullOrWhiteSpace name
            || (name
                |> Seq.exists (fun character ->
                    Char.IsWhiteSpace character
                    || character = '='
                    || character = '['
                    || character = ']'
                    || character = '\r'
                    || character = '\n'
                    || character = '\u0000'))
        then
            invalidArg "name" "A Fail2Ban option name must be one non-empty native INI key."

        name

    let sectionName (name: string) =
        if
            String.IsNullOrWhiteSpace name
            || name.IndexOfAny([| '['; ']'; '\r'; '\n'; '\u0000' |]) >= 0
        then
            invalidArg
                "name"
                "A Fail2Ban section name must be non-empty and cannot contain INI delimiters or line breaks."

        name

    let filePath (path: string) =
        if
            String.IsNullOrWhiteSpace path
            || path.StartsWith("/", StringComparison.Ordinal)
            || path.Contains('\\')
            || path.Contains(':')
            || path.IndexOfAny([| '\r'; '\n'; '\u0000' |]) >= 0
        then
            invalidArg
                "path"
                "A Fail2Ban config path must be a relative path beneath /etc/fail2ban using '/' separators."

        let segments = path.Split('/')

        if
            segments
            |> Array.exists (fun segment -> segment.Length = 0 || segment = "." || segment = "..")
        then
            invalidArg "path" "A Fail2Ban config path cannot contain empty, '.' or '..' path segments."

        path

    let nonNull parameterName (value: string) =
        if isNull value then
            invalidArg parameterName "A native Fail2Ban configuration value cannot be null."

        value

    let reservedPortPath = "jail.d/99-dorothy-sshd-ports.local"
    let jailPath = "jail.d/90-dorothy.local"

    let renderOption (option: Fail2BanOption) =
        let continuation =
            option.Value
                .Replace("\r\n", "\n", StringComparison.Ordinal)
                .Replace('\r', '\n')
                .Replace("\n", "\n    ", StringComparison.Ordinal)

        option.Name + " = " + continuation + "\n"

    let renderSection (sectionName: string) (options: Fail2BanOption list) =
        let builder = StringBuilder()
        builder.Append('[').Append(sectionName).Append("]\n") |> ignore

        for option in options do
            builder.Append(renderOption option) |> ignore

        builder.ToString()

    let appendPiece (builder: StringBuilder) (piece: string) =
        if piece.Length > 0 then
            if builder.Length > 0 && builder[builder.Length - 1] <> '\n' then
                builder.Append('\n') |> ignore

            builder.Append(piece) |> ignore

            if builder.Length > 0 && builder[builder.Length - 1] <> '\n' then
                builder.Append('\n') |> ignore

    let sectionOptions (parts: Fail2BanPart list) (directSection: string) =
        let entries = ResizeArray<string * string * Fail2BanOption>()

        for part in parts do
            match part with
            | Fail2BanPart.Option option -> entries.Add(jailPath, directSection, option)
            | Fail2BanPart.Section section ->
                for option in section.Options do
                    entries.Add(section.Path, section.Name, option)
            | _ -> ()

        entries |> Seq.toList

    let hasExplicitSshdPort (parts: Fail2BanPart list) =
        let isJailConfigurationPath (path: string) =
            path.StartsWith("jail.d/", StringComparison.Ordinal)
            || path.Equals("jail.local", StringComparison.Ordinal)
            || path.Equals("jail.conf", StringComparison.Ordinal)

        let structured =
            parts
            |> List.exists (function
                | Fail2BanPart.Option option -> option.Name.Equals("port", StringComparison.OrdinalIgnoreCase)
                | Fail2BanPart.Section section ->
                    isJailConfigurationPath section.Path
                    && (section.Name.Equals("DEFAULT", StringComparison.Ordinal)
                        || section.Name.Equals("sshd", StringComparison.Ordinal))
                    && (section.Options
                        |> List.exists (fun option -> option.Name.Equals("port", StringComparison.OrdinalIgnoreCase)))
                | _ -> false)

        let raw =
            parts
            |> List.exists (function
                | Fail2BanPart.File(path, contents) when isJailConfigurationPath path ->
                    let mutable section = ""
                    let mutable currentOptionIndent = None

                    contents.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
                    |> Array.exists (fun line ->
                        let trimmed = line.Trim()
                        let indentation = line.Length - line.TrimStart().Length

                        if
                            trimmed.Length = 0
                            || trimmed.StartsWith("#", StringComparison.Ordinal)
                            || trimmed.StartsWith(";", StringComparison.Ordinal)
                        then
                            false
                        else
                            let isContinuation =
                                match currentOptionIndent with
                                | Some previousIndent -> indentation > previousIndent
                                | None -> false

                            if isContinuation then
                                false
                            elif trimmed.StartsWith("[", StringComparison.Ordinal) then
                                let closingBracket = trimmed.IndexOf(']')

                                if closingBracket > 0 then
                                    section <- trimmed.Substring(1, closingBracket - 1)
                                    currentOptionIndent <- None

                                false
                            else
                                let separator = trimmed.IndexOfAny([| '='; ':' |])

                                if separator <= 0 then
                                    false
                                else
                                    currentOptionIndent <- Some indentation

                                    trimmed
                                        .Substring(0, separator)
                                        .Trim()
                                        .Equals("port", StringComparison.OrdinalIgnoreCase)
                                    && (section.Equals("DEFAULT", StringComparison.Ordinal)
                                        || section.Equals("sshd", StringComparison.Ordinal)))
                | _ -> false)

        structured || raw

    let detectConflicts (declarations: (Fail2BanInputSpec * bool) list) =
        let values =
            declarations
            |> List.mapi (fun declarationIndex (spec, isNested) ->
                sectionOptions spec.Parts (if isNested then "sshd" else "DEFAULT")
                |> List.map (fun (path, name, option) -> declarationIndex, path, name, option))
            |> List.concat
            |> List.toArray

        for leftIndex = 0 to values.Length - 1 do
            let leftDeclaration, leftPath, leftSection, leftOption = values[leftIndex]

            for rightIndex = leftIndex + 1 to values.Length - 1 do
                let rightDeclaration, rightPath, rightSection, rightOption = values[rightIndex]

                if
                    leftDeclaration <> rightDeclaration
                    && leftPath = rightPath
                    && leftSection.Equals(rightSection, StringComparison.Ordinal)
                    && leftOption.Name.Equals(rightOption.Name, StringComparison.OrdinalIgnoreCase)
                    && leftOption.Value <> rightOption.Value
                    && not (
                        leftOption.MergeBehavior = Fail2BanOptionMergeBehavior.Append
                        && rightOption.MergeBehavior = Fail2BanOptionMergeBehavior.Append
                    )
                then
                    invalidArg
                        "fail2ban"
                        (sprintf "Conflicting Fail2Ban declarations for [%s] %s." leftSection leftOption.Name)

    let addFile (files: Dictionary<string, string>) (path: string) (contents: string) =
        let path = filePath path
        let contents = nonNull "contents" contents

        if path = reservedPortPath then
            invalidArg
                "path"
                (sprintf "The Fail2Ban path '%s' is reserved for automatic sshd port synchronization." reservedPortPath)

        match files.TryGetValue(path) with
        | false, _ -> files.Add(path, contents)
        | true, previous when previous = contents -> ()
        | true, _ -> invalidArg "path" (sprintf "The Fail2Ban file '%s' was declared with conflicting contents." path)

    let addSection
        (files: Dictionary<string, ResizeArray<string * ResizeArray<Fail2BanOption>>>)
        (path: string)
        (section: string)
        (options: Fail2BanOption list)
        =
        let path = filePath path

        if path = reservedPortPath then
            invalidArg
                "path"
                (sprintf "The Fail2Ban path '%s' is reserved for automatic sshd port synchronization." reservedPortPath)

        let validatedSectionName = sectionName section

        let groups =
            match files.TryGetValue(path) with
            | true, value -> value
            | false, _ ->
                let value = ResizeArray<string * ResizeArray<Fail2BanOption>>()
                files.Add(path, value)
                value

        let mutable targetOptions = None

        for name, sectionOptions in groups do
            if name.Equals(validatedSectionName, StringComparison.Ordinal) then
                targetOptions <- Some sectionOptions

        let targetOptions =
            match targetOptions with
            | Some value -> value
            | None ->
                let value = ResizeArray<Fail2BanOption>()
                groups.Add(validatedSectionName, value)
                value

        for option in options do
            let mutable existingIndex = None

            for index = 0 to targetOptions.Count - 1 do
                if targetOptions[index].Name.Equals(option.Name, StringComparison.OrdinalIgnoreCase) then
                    existingIndex <- Some index

            match existingIndex with
            | None -> targetOptions.Add option
            | Some index ->
                let existing = targetOptions[index]

                if existing.Value = option.Value then
                    ()
                elif
                    existing.MergeBehavior = Fail2BanOptionMergeBehavior.Append
                    && option.MergeBehavior = Fail2BanOptionMergeBehavior.Append
                then
                    let appendValues = existing.AppendValues @ option.AppendValues |> List.distinct

                    targetOptions[index] <-
                        Fail2BanOption(
                            existing.Name,
                            String.concat "\n" appendValues,
                            Fail2BanOptionMergeBehavior.Append,
                            appendValues
                        )
                else
                    invalidArg
                        "fail2ban"
                        (sprintf "Conflicting Fail2Ban options for [%s] %s." validatedSectionName option.Name)

    let build (declarations: (Fail2BanInputSpec * bool) list) =
        detectConflicts declarations
        let hasNested = declarations |> List.exists snd

        let explicitPort =
            declarations |> List.exists (fun (spec, _) -> hasExplicitSshdPort spec.Parts)

        let requestedLink =
            declarations
            |> List.choose (fun (spec, _) -> spec.ManageSshdPorts)
            |> List.distinct
            |> function
                | [] -> None
                | [ value ] -> Some value
                | _ -> invalidArg "fail2ban" "Fail2Ban declarations contain conflicting manageSshdPorts settings."

        if explicitPort && requestedLink = Some true then
            invalidArg
                "fail2ban"
                "manageSshdPorts cannot be enabled when a Fail2Ban sshd port is explicitly configured."

        let manageSshdPorts = defaultArg requestedLink (hasNested && not explicitPort)
        let rawFiles = Dictionary<string, string>(StringComparer.Ordinal)

        let sectionGroups =
            Dictionary<string, ResizeArray<string * ResizeArray<Fail2BanOption>>>(StringComparer.Ordinal)

        for spec, isNested in declarations do
            let directSection = if isNested then "sshd" else "DEFAULT"
            let mutable directOptions = ResizeArray<Fail2BanOption>()

            let flushDirect () =
                if directOptions.Count > 0 then
                    addSection sectionGroups jailPath directSection (List.ofSeq directOptions)
                    directOptions <- ResizeArray<Fail2BanOption>()

            for part in spec.Parts do
                match part with
                | Fail2BanPart.Option option -> directOptions.Add option
                | Fail2BanPart.Section section ->
                    flushDirect ()
                    addSection sectionGroups section.Path section.Name section.Options
                | Fail2BanPart.File(path, contents) ->
                    flushDirect ()
                    let path = filePath path

                    if sectionGroups.ContainsKey(path) then
                        invalidArg
                            "path"
                            (sprintf
                                "The Fail2Ban path '%s' is declared both as a native file and as structured sections."
                                path)

                    addFile rawFiles path contents
                | Fail2BanPart.PythonAction(name, source) ->
                    flushDirect ()
                    let path = "action.d/" + name + ".py" |> filePath

                    if sectionGroups.ContainsKey(path) then
                        invalidArg
                            "path"
                            (sprintf
                                "The Fail2Ban path '%s' is declared both as a Python action and as structured sections."
                                path)

                    addFile rawFiles path source
                | Fail2BanPart.ManageSshdPorts _ -> ()

            flushDirect ()

        let renderedFiles = Dictionary<string, string>(StringComparer.Ordinal)

        for KeyValue(path, groups) in sectionGroups do
            if rawFiles.ContainsKey(path) then
                invalidArg
                    "path"
                    (sprintf "The Fail2Ban path '%s' is declared as both a native file and structured sections." path)

            let builder = StringBuilder()

            for sectionName, options in groups do
                appendPiece builder (renderSection sectionName (List.ofSeq options))

            renderedFiles.Add(path, builder.ToString())

        let files =
            rawFiles
            |> Seq.map (fun entry -> entry.Key, entry.Value)
            |> Map.ofSeq
            |> fun result ->
                renderedFiles
                |> Seq.fold (fun merged entry -> Map.add entry.Key entry.Value merged) result

        Fail2BanSpec(files, manageSshdPorts)

[<RequireQualifiedAccess>]
module Fail2BanOptions =
    let option (name: string) (value: string) =
        Fail2BanOption(
            Fail2BanValidation.optionName name,
            Fail2BanValidation.nonNull "value" value,
            Fail2BanOptionMergeBehavior.Scalar,
            []
        )

    let private appendableOption name (values: seq<string>) =
        let values = values |> Seq.map (Fail2BanValidation.nonNull "value") |> Seq.toList

        Fail2BanOption(
            Fail2BanValidation.optionName name,
            String.concat "\n" values,
            Fail2BanOptionMergeBehavior.Append,
            values
        )

    let private boolOption name value =
        option name (if value then "true" else "false")

    let private valuesOption name (values: seq<string>) = option name (String.concat " " values)

    let enabled value = boolOption "enabled" value
    let bantime value = option "bantime" value
    let findtime value = option "findtime" value

    let maxretry (value: int) =
        option "maxretry" (value.ToString(CultureInfo.InvariantCulture))

    let maxmatches (value: int) =
        option "maxmatches" (value.ToString(CultureInfo.InvariantCulture))

    let bantimeIncrement value = boolOption "bantime.increment" value
    let bantimeFactor value = option "bantime.factor" value
    let bantimeFormula value = option "bantime.formula" value
    let bantimeMultipliers value = option "bantime.multipliers" value
    let bantimeMaxtime value = option "bantime.maxtime" value
    let bantimeRndtime value = option "bantime.rndtime" value
    let bantimeOveralljails value = boolOption "bantime.overalljails" value
    let ignoreself value = boolOption "ignoreself" value
    let ignoreip value = option "ignoreip" value
    let ignoreipList values = valuesOption "ignoreip" values
    let ignorecommand value = option "ignorecommand" value
    let ignorecache value = option "ignorecache" value
    let usedns value = option "usedns" value
    let filter value = option "filter" value
    let backend value = option "backend" value
    let logpath value = option "logpath" value

    let logpathList values =
        option "logpath" (String.concat "\n" values)

    let logencoding value = option "logencoding" value
    let logtimezone value = option "logtimezone" value
    let destemail value = option "destemail" value
    let sender value = option "sender" value
    let mta value = option "mta" value
    let protocol value = option "protocol" value
    let chain value = option "chain" value
    let port value = option "port" value
    let fail2banAgent value = option "fail2ban_agent" value
    let banaction value = option "banaction" value
    let banactionAllports value = option "banaction_allports" value
    let action value = appendableOption "action" [ value ]
    let actionList values = appendableOption "action" values
    let actionShortcut name value = option ("action_" + name) value
    let actionMw value = option "action_mw" value
    let actionMwl value = option "action_mwl" value
    let actionXarf value = option "action_xarf" value
    let actionCfMwl value = option "action_cf_mwl" value
    let actionBlocklistDe value = option "action_blocklist_de" value
    let actionAbuseipdb value = option "action_abuseipdb" value

    /// An open-ended key/value entry for native options and installation-specific extensions.
    let custom name value = option name value

[<RequireQualifiedAccess>]
module Fail2BanDaemonOptions =
    let private option = Fail2BanOptions.option
    let loglevel value = option "loglevel" value
    let logtarget value = option "logtarget" value
    let syslogsocket value = option "syslogsocket" value
    let socket value = option "socket" value
    let pidfile value = option "pidfile" value
    let allowipv6 value = option "allowipv6" value
    let dbfile value = option "dbfile" value
    let dbmaxmatches value = option "dbmaxmatches" value
    let dbpurgeage value = option "dbpurgeage" value
    let stacksize value = option "stacksize" value
    let custom name value = option name value

[<RequireQualifiedAccess>]
module Fail2BanFilterOptions =
    let private option = Fail2BanOptions.option
    let prefregex value = option "prefregex" value
    let failregex value = option "failregex" value

    let failregexList values =
        option "failregex" (String.concat "\n" values)

    let ignoreregex value = option "ignoreregex" value

    let ignoreregexList values =
        option "ignoreregex" (String.concat "\n" values)

    let maxlines (value: int) =
        option "maxlines" (Convert.ToString(value, CultureInfo.InvariantCulture))

    let datepattern value = option "datepattern" value
    let journalmatch value = option "journalmatch" value
    let custom name value = option name value

[<RequireQualifiedAccess>]
module Fail2BanActionOptions =
    let private option = Fail2BanOptions.option
    let actionstart value = option "actionstart" value
    let actionstop value = option "actionstop" value
    let actioncheck value = option "actioncheck" value
    let actionban value = option "actionban" value
    let actionunban value = option "actionunban" value
    let actionflush value = option "actionflush" value
    let actionrepair value = option "actionrepair" value
    let actionreload value = option "actionreload" value
    let actionreban value = option "actionreban" value
    let actionprolong value = option "actionprolong" value
    let timeout value = option "timeout" value
    let actionstartOnDemand value = option "actionstart_on_demand" value
    let actionrepairOnUnban value = option "actionrepair_on_unban" value
    let families value = option "families" value
    let norestored value = option "norestored" value
    let init name value = option name value
    let definition name value = option name value
    let custom name value = option name value

[<RequireQualifiedAccess>]
module Fail2BanIncludeOptions =
    let private option = Fail2BanOptions.option
    let before value = option "before" value
    let after value = option "after" value

[<Sealed>]
type Fail2BanSectionBuilder internal (path: string, sectionName: string) =
    member _.Yield(option: Fail2BanOption) = [ option ]
    member _.YieldFrom(options: seq<Fail2BanOption>) = Seq.toList options
    member _.Zero() = []
    member _.Combine(left: Fail2BanOption list, right: Fail2BanOption list) = left @ right
    member _.Delay(generator: unit -> Fail2BanOption list) = generator ()

    member _.For(values: seq<'T>, body: 'T -> Fail2BanOption list) =
        values |> Seq.collect body |> Seq.toList

    member _.Run(options: Fail2BanOption list) =
        Fail2BanSectionSpec(path, sectionName, options)

[<Sealed>]
type Fail2BanBuilder() =
    member _.Yield(option: Fail2BanOption) = [ Fail2BanPart.Option option ]
    member _.Yield(section: Fail2BanSectionSpec) = [ Fail2BanPart.Section section ]
    member _.Yield(file: Fail2BanPart) = [ file ]
    member _.YieldFrom(parts: seq<Fail2BanPart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: Fail2BanPart list, right: Fail2BanPart list) = left @ right
    member _.Delay(generator: unit -> Fail2BanPart list) = generator ()

    member _.For(values: seq<'T>, body: 'T -> Fail2BanPart list) =
        values |> Seq.collect body |> Seq.toList

    member _.Run(parts: Fail2BanPart list) =
        let mutable autoLink = None
        let declarations = ResizeArray<Fail2BanPart>()

        for part in parts do
            match part with
            | Fail2BanPart.ManageSshdPorts value ->
                match autoLink with
                | None -> autoLink <- Some value
                | Some previous when previous = value -> ()
                | Some _ -> invalidArg "fail2ban" "manageSshdPorts may only be declared once with a consistent value."
            | _ -> declarations.Add part

        Fail2BanInputSpec(List.ofSeq declarations, autoLink)

module Fail2BanSections =
    let private builder path name =
        Fail2BanSectionBuilder(Fail2BanValidation.filePath path, Fail2BanValidation.sectionName name)

    /// Native [DEFAULT] section in jail.d/90-dorothy.local.
    let defaults = builder Fail2BanValidation.jailPath "DEFAULT"
    /// Native daemon [Definition] section in fail2ban.d/90-dorothy.local.
    let daemon = builder "fail2ban.d/90-dorothy.local" "Definition"
    /// Native daemon [Thread] section in fail2ban.d/90-dorothy.local.
    let thread = builder "fail2ban.d/90-dorothy.local" "Thread"

    /// A named native jail in jail.d/90-dorothy.local.
    let jail name =
        builder Fail2BanValidation.jailPath name

    /// A native filter's standard sections in filter.d/<name>.local.
    let filter name =
        builder ("filter.d/" + name + ".local") "Definition"

    let filterDefaults name =
        builder ("filter.d/" + name + ".local") "DEFAULT"

    let filterInit name =
        builder ("filter.d/" + name + ".local") "Init"

    let filterIncludes name =
        builder ("filter.d/" + name + ".local") "INCLUDES"

    /// A native command action's standard sections in action.d/<name>.local.
    let action name =
        builder ("action.d/" + name + ".local") "Definition"

    let actionInit name =
        builder ("action.d/" + name + ".local") "Init"

    let actionIncludes name =
        builder ("action.d/" + name + ".local") "INCLUDES"

    /// A section in a caller-selected native config file beneath /etc/fail2ban.
    let nativeSection path name = builder path name

module Fail2BanFiles =
    /// Adds a caller-owned native configuration file below /etc/fail2ban.
    let file path contents =
        Fail2BanValidation.filePath path |> ignore
        Fail2BanValidation.nonNull "contents" contents |> ignore
        Fail2BanPart.File(path, contents)

    /// Adds an executable Python action module; Fail2Ban supplies the native Action interface.
    let pythonAction name source =
        if
            String.IsNullOrWhiteSpace name
            || name.Contains('/')
            || name.Contains('\\')
            || name = "."
            || name = ".."
        then
            invalidArg "name" "A Python action name must be one relative filename stem."

        Fail2BanValidation.nonNull "source" source |> ignore
        Fail2BanPart.PythonAction(name, source)

    /// Selects whether the managed sshd jail receives listener ports from Dorothy's sshd resource.
    let manageSshdPorts value = Fail2BanPart.ManageSshdPorts value

[<AutoOpen>]
module Fail2BanBuilders =
    let fail2ban = Fail2BanBuilder()

module internal Fail2BanConfigurationMerge =
    let combine (declarations: (Fail2BanInputSpec * bool) list) = Fail2BanValidation.build declarations
