namespace Dorothy.DSL

open System
open System.IO
open System.Collections.Generic
open System.Globalization
open Pulumi

[<RequireQualifiedAccess>]
type ContentOwnership = Managed | CreateOnly

type ArchiveFormat = Zip | TarGz | TarZst

[<RequireQualifiedAccess>]
type ServiceRestart = No | Always | OnFailure | OnAbnormal | OnAbort | OnWatchdog

type ContentMetadata = Owner of string | Group of string | Mode of int

type ContentTarget =
    { Path: string; Source: string; Owner: string option; Group: string option; Mode: int }

module internal HostContentValidation =
    let line field (value: string) =
        if String.IsNullOrWhiteSpace value || value |> Seq.exists Char.IsControl then
            invalidArg field "A non-empty single-line value is required."
        value
    let path value =
        line "path" value |> ignore
        if not (value.StartsWith('/')) || value = "/" || Path.GetFullPath value <> value
           || value.EndsWith('/') || value.Split('/') |> Array.exists (fun part -> part = "." || part = ".." || (part = "" && value <> "/" && value.Contains("//"))) then
            invalidArg "path" "Content destinations must be canonical absolute paths."
        value
    let name value =
        line "name" value |> ignore
        if value.StartsWith('-') || value.Length > 240 || value |> Seq.exists (fun c -> not (Char.IsAsciiLetterOrDigit c || "_.@:-\\".Contains c)) then
            invalidArg "name" "Invalid content or service name."
        value
    let unique field values =
        if (Set.ofList values).Count <> List.length values then invalidArg field "Duplicate declaration."
    let metadata defaultMode (parts: ContentMetadata list) =
        let mutable owner = None
        let mutable group = None
        let mutable mode = None
        for part in parts do
            match part with
            | Owner value ->
                if owner.IsSome then invalidArg "owner" "Owner may be declared once."
                owner <- Some(line "owner" value)
            | Group value ->
                if group.IsSome then invalidArg "group" "Group may be declared once."
                group <- Some(line "group" value)
            | Mode value ->
                if mode.IsSome || value < 0 || value > 0o7777 then invalidArg "mode" "Declare one valid Unix mode."
                mode <- Some value
        owner, group, defaultArg mode defaultMode

[<Sealed>]
type ContentTargetBuilder internal (source: string, path: string) =
    member _.Yield(part: ContentMetadata) = [ part ]
    member _.YieldFrom(parts: seq<ContentMetadata>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(a: ContentMetadata list, b) = a @ b
    member _.Delay(body: unit -> ContentMetadata list) = body()
    member _.For(values: seq<'T>, body: 'T -> ContentMetadata list) = values |> Seq.collect body |> Seq.toList
    member _.Run(parts: ContentMetadata list) =
        let owner, group, mode = HostContentValidation.metadata 0o644 parts
        { Path = HostContentValidation.path path; Source = source; Owner = owner; Group = group; Mode = mode }

type ContentPart =
    | ContentUrl of string
    | ContentSha256 of string
    | ContentFormat of ArchiveFormat
    | ContentHeader of string * DockerStringInput
    | ContentSource of string
    | ContentValue of DockerStringInput
    | ContentTarget of ContentTarget
    | ContentOwnership of ContentOwnership
    | ContentDirectoryPath of string
    | ContentDirectoryMetadata of ContentMetadata

[<Sealed>]
type HostContentItem internal (name: string, kind: string, url: string option, digest: string option, format: ArchiveFormat option,
                               headers: (string * DockerStringInput) list, source: string option, value: DockerStringInput option,
                               targets: ContentTarget list, ownership: ContentOwnership) =
    member _.Name = name
    member _.Kind = kind
    member _.Url = url
    member _.Sha256 = digest
    member _.Format = format
    member _.Headers = headers
    member _.Source = source
    member _.Value = value
    member _.Targets = targets
    member _.Ownership = ownership

[<Sealed>]
type ContentItemBuilder internal (name: string, kind: string) =
    member _.Yield(part: ContentPart) = [ part ]
    member _.Yield(target: ContentTarget) = [ ContentTarget target ]
    member _.Yield(target: ContentTargetBuilder) = [ ContentTarget(target.Run []) ]
    member _.Yield(metadata: ContentMetadata) = [ ContentDirectoryMetadata metadata ]
    member _.YieldFrom(parts: seq<ContentPart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(a: ContentPart list, b) = a @ b
    member _.Delay(body: unit -> ContentPart list) = body()
    member _.For(values: seq<'T>, body: 'T -> ContentPart list) = values |> Seq.collect body |> Seq.toList
    member _.Run(parts: ContentPart list) =
        HostContentValidation.name name |> ignore
        let singleton field chooser =
            match List.choose chooser parts with
            | [] -> None
            | [ value ] -> Some value
            | _ -> invalidArg field "This field may be declared only once."
        let url = singleton "url" (function ContentUrl v -> Some v | _ -> None)
        let digest = singleton "sha256" (function ContentSha256 v -> Some v | _ -> None)
        let format = singleton "format" (function ContentFormat v -> Some v | _ -> None)
        let source = singleton "source" (function ContentSource v -> Some v | _ -> None)
        let value = singleton "value" (function ContentValue v -> Some v | _ -> None)
        let ownership = singleton "ownership" (function ContentOwnership v -> Some v | _ -> None) |> Option.defaultValue ContentOwnership.Managed
        let path = singleton "path" (function ContentDirectoryPath v -> Some v | _ -> None)
        let headers = parts |> List.choose (function ContentHeader(k, v) -> Some(k, v) | _ -> None)
        let targets = parts |> List.choose (function ContentTarget v -> Some v | _ -> None)
        let metadata = parts |> List.choose (function ContentDirectoryMetadata v -> Some v | _ -> None)
        let remote = kind = "archive" || kind = "download"
        if remote then
            match url, digest with
            | Some uri, Some hash when hash.Length = 64 && hash |> Seq.forall Uri.IsHexDigit ->
                let parsed = Uri uri
                if (parsed.Scheme <> "http" && parsed.Scheme <> "https") || parsed.UserInfo <> "" then invalidArg "url" "Use HTTP(S) without URL credentials."
            | _ -> invalidArg "content" "URL artifacts require url and sha256."
        elif url.IsSome || digest.IsSome || not headers.IsEmpty then invalidArg "content" "Only downloads and archives accept URL, sha256 and headers."
        if (kind = "file") <> source.IsSome then invalidArg "source" "Only file requires a local source."
        if (kind = "text") <> value.IsSome then invalidArg "value" "Only text requires a value."
        if kind <> "archive" && format.IsSome then invalidArg "format" "Only archives accept format."
        let format =
            if kind <> "archive" then None
            else
                match format with
                | Some value -> Some value
                | None ->
                    let path = (Uri url.Value).AbsolutePath.ToLowerInvariant()
                    if path.EndsWith ".zip" then Some Zip
                    elif path.EndsWith ".tar.gz" || path.EndsWith ".tgz" then Some TarGz
                    elif path.EndsWith ".tar.zst" then Some TarZst
                    else invalidArg "format" "Archive format is required when URL extension is ambiguous."
        let targets =
            if kind = "directory" then
                if not targets.IsEmpty then invalidArg "directory" "Use path for a directory."
                let owner, group, mode = HostContentValidation.metadata 0o755 metadata
                [ { Path = HostContentValidation.path (path |> Option.defaultWith (fun () -> invalidArg "path" "Directory path is required.")); Source = ""; Owner = owner; Group = group; Mode = mode } ]
            else
                if path.IsSome || not metadata.IsEmpty then invalidArg "content" "Place file metadata inside installTo or extract."
                if targets.IsEmpty || (kind <> "archive" && targets.Length <> 1) then invalidArg "content" "Declare the destination with installTo or extract."
                targets
        for target in targets do
            if kind = "archive" then
                let src = target.Source
                if String.IsNullOrWhiteSpace src || src.StartsWith('/') || src.Contains('\\') || src |> Seq.exists Char.IsControl
                   || src.Split('/') |> Array.exists (fun part -> part = "" || part = "." || part = "..") then
                    invalidArg "extract" "Selected archive members must be canonical relative paths."
            elif target.Source <> "" then invalidArg "extract" "Only archives accept extract."
        HostContentValidation.unique "targets" (targets |> List.map _.Path)
        HostContentValidation.unique "headers" (headers |> List.map (fun (name, _) -> name.ToLowerInvariant()))
        for name, _ in headers do
            if String.IsNullOrEmpty name || name |> Seq.exists (fun c -> not (Char.IsAsciiLetterOrDigit c || "!#$%&'*+-.^_`|~".Contains c)) then invalidArg "header" "Invalid HTTP header name."
        HostContentItem(name, kind, url, digest |> Option.map _.ToLowerInvariant(), format, headers, source, value, targets, ownership)

[<Sealed>]
type HostContentSpec internal (items: HostContentItem list) =
    member _.Items = items

[<Sealed>]
type HostContentBuilder() =
    member _.Yield(item: HostContentItem) = [ item ]
    member _.YieldFrom(items: seq<HostContentItem>) = Seq.toList items
    member _.Zero() = []
    member _.Combine(a: HostContentItem list, b) = a @ b
    member _.Delay(body: unit -> HostContentItem list) = body()
    member _.For(values: seq<'T>, body: 'T -> HostContentItem list) = values |> Seq.collect body |> Seq.toList
    member _.Run(items: HostContentItem list) =
        HostContentValidation.unique "content" (items |> List.map _.Name)
        HostContentValidation.unique "content target paths" (items |> List.collect (fun item -> item.Targets |> List.map _.Path))
        HostContentSpec items

type HostServicePart =
    | ServiceUses of HostContentItem list
    | ServiceRestartOnChange of bool
    | ServiceLine of section: string * key: string * value: string

[<Sealed>]
type HostServiceSpec internal (name: string, managed: bool, configuration: string, uses: HostContentItem list, restartOnChange: bool) =
    member _.Name = name
    member _.Managed = managed
    member _.Configuration = configuration
    member _.Uses = uses
    member _.RestartOnChange = restartOnChange

[<Sealed>]
type HostServiceBuilder internal (name: string, managed: bool) =
    member _.Yield(part: HostServicePart) = [ part ]
    member _.YieldFrom(parts: seq<HostServicePart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(a: HostServicePart list, b) = a @ b
    member _.Delay(body: unit -> HostServicePart list) = body()
    member _.For(values: seq<'T>, body: 'T -> HostServicePart list) = values |> Seq.collect body |> Seq.toList
    member _.Run(parts: HostServicePart list) =
        let name = HostContentValidation.name name
        let name = if name.EndsWith ".service" then name else name + ".service"
        let uses = parts |> List.choose (function ServiceUses v -> Some v | _ -> None)
        let changes = parts |> List.choose (function ServiceRestartOnChange v -> Some v | _ -> None)
        if uses.Length > 1 || changes.Length > 1 then invalidArg "service" "uses and restartOnChange may be declared once."
        let lines = parts |> List.choose (function ServiceLine(s, k, v) -> Some(s, k, v) | _ -> None)
        if not managed && not lines.IsEmpty then invalidArg "systemdUnit" "Package units accept only uses and restartOnChange."
        for _, key, value in lines do
            HostContentValidation.line "unit value" value |> ignore
            if String.IsNullOrWhiteSpace key || key |> Seq.exists (fun c -> not (Char.IsAsciiLetterOrDigit c)) then invalidArg "raw" "Use a systemd Key=Value directive."
        if managed && not (lines |> List.exists (fun (s, k, _) -> s = "Service" && k = "ExecStart")) then invalidArg "service" "A service requires exec."
        let lines =
            if managed && not (lines |> List.exists (fun (s, k, _) -> s = "Install" && k = "WantedBy")) then lines @ [ "Install", "WantedBy", "multi-user.target" ]
            else lines
        let configuration =
            if not managed then ""
            else
                [ "Unit"; "Service"; "Install" ]
                |> List.map (fun section ->
                    "[" + section + "]\n" + (lines |> List.choose (fun (s, k, v) -> if s = section then Some(k + "=" + v + "\n") else None) |> String.concat ""))
                |> String.concat "\n"
        HostServiceSpec(name, managed, configuration, uses |> List.tryHead |> Option.defaultValue [], changes |> List.tryHead |> Option.defaultValue true)

[<AbstractClass; Sealed>]
type HostContentFields private () =
    static member Value(value: string) = ContentValue(LiteralDockerString value)
    static member Value(value: Output<string>) = ContentValue(OutputDockerString value)
    static member Header(name: string, value: string) = ContentHeader(name, LiteralDockerString value)
    static member Header(name: string, value: Output<string>) = ContentHeader(name, OutputDockerString value)

/// Explicitly opened to avoid changing existing Docker content/source/env/restart functions.
module HostContent =
    let content = HostContentBuilder()
    let archive name = ContentItemBuilder(name, "archive")
    let download name = ContentItemBuilder(name, "download")
    let file name = ContentItemBuilder(name, "file")
    let text name = ContentItemBuilder(name, "text")
    let directory name = ContentItemBuilder(name, "directory")
    let installTo path = ContentTargetBuilder("", path)
    let extract source path = ContentTargetBuilder(source, path)
    let owner value = Owner value
    let group value = Group value
    let mode value = Mode value
    let path value = ContentDirectoryPath value
    let source value = ContentSource value
    let url value = ContentUrl value
    let sha256 value = ContentSha256 value
    let format value = ContentFormat value
    let ownership value = ContentOwnership value
    let inline value (value: ^T) : ContentPart = ((^T or HostContentFields) : (static member Value: ^T -> ContentPart) value)
    let inline header name (value: ^T) : ContentPart = ((^T or HostContentFields) : (static member Header: string * ^T -> ContentPart) (name, value))
    let service name = HostServiceBuilder(name, true)
    let systemdUnit name = HostServiceBuilder(name, false)
    let uses values = ServiceUses values
    let restartOnChange value = ServiceRestartOnChange value
    let exec value = ServiceLine("Service", "ExecStart", value)
    let runAs value = ServiceLine("Service", "User", value)
    let runAsGroup value = ServiceLine("Service", "Group", value)
    let supplementaryGroups values = ServiceLine("Service", "SupplementaryGroups", String.concat " " values)
    let workingDirectory value = ServiceLine("Service", "WorkingDirectory", value)
    let restart value =
        let token = match value with ServiceRestart.No -> "no" | ServiceRestart.Always -> "always" | ServiceRestart.OnFailure -> "on-failure" | ServiceRestart.OnAbnormal -> "on-abnormal" | ServiceRestart.OnAbort -> "on-abort" | ServiceRestart.OnWatchdog -> "on-watchdog"
        ServiceLine("Service", "Restart", token)
    let restartSec (seconds: float) =
        if Double.IsNaN seconds || Double.IsInfinity seconds || seconds < 0. then invalidArg "seconds" "Expected nonnegative seconds."
        ServiceLine("Service", "RestartSec", seconds.ToString(CultureInfo.InvariantCulture))
    let limitNoFile (value: int) =
        if value <= 0 then invalidArg "limitNoFile" "A positive file descriptor limit is required."
        ServiceLine("Service", "LimitNOFILE", string value)
    let env name value =
        if String.IsNullOrEmpty name || name |> Seq.exists (fun c -> not (Char.IsAsciiLetterOrDigit c || c = '_')) then invalidArg "name" "Invalid environment variable name."
        HostContentValidation.line "env" value |> ignore
        let escaped = value.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("%", "%%")
        ServiceLine("Service", "Environment", "\"" + name + "=" + escaped + "\"")
    let after values = ServiceLine("Unit", "After", String.concat " " values)
    let requires values = ServiceLine("Unit", "Requires", String.concat " " values)
    let wants values = ServiceLine("Unit", "Wants", String.concat " " values)
    let wantedBy values = ServiceLine("Install", "WantedBy", String.concat " " values)
    let raw (value: string) =
        let parts = value.Split('=', 2)
        if parts.Length <> 2 then invalidArg "raw" "Expected Key=Value."
        ServiceLine("Service", parts[0], parts[1])
