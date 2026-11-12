namespace Dorothy.HostHelper

open System
open System.IO
open System.IO.Compression
open System.Formats.Tar
open System.Net.Http
open System.Security.Cryptography
open System.Text.Json
open System.Text.Json.Nodes
open System.Collections.Generic
open System.Runtime.InteropServices
open System.Threading
open System.Runtime.CompilerServices

[<assembly: InternalsVisibleTo("Dorothy.Tests")>]
do ()

[<Struct; StructLayout(LayoutKind.Sequential, Size = 256)>]
type private ContentStatx =
    val mutable Mask: uint32
    val mutable BlockSize: uint32
    val mutable Attributes: uint64
    val mutable LinkCount: uint32
    val mutable UserId: uint32
    val mutable GroupId: uint32
    val mutable Mode: uint16

/// Content operations never return source bytes, URLs, or header values.
module Content =
    type BackendError(message: string) =
        inherit InvalidOperationException(message)

    type Target =
        { Path: string
          Source: string
          Mode: int option
          Owner: string option
          Group: string option }

    let private fail message = raise (BackendError message)
    [<DllImport("libc", EntryPoint = "statx", SetLastError = true)>]
    extern int private nativeStatx(int directoryFileDescriptor, string path, int flags, uint32 mask, ContentStatx& result)
    [<DllImport("libc", EntryPoint = "fchown", SetLastError = true)>]
    extern int private nativeFchown(int fileDescriptor, uint32 owner, uint32 group)
    let private text (node: JsonElement) (name: string) = node.GetProperty(name).GetString()
    let private optionalText (node: JsonElement) (name: string) =
        match node.TryGetProperty name with
        | true, value when value.ValueKind = JsonValueKind.String -> Some(value.GetString())
        | false, _ -> None
        | _ -> fail "Invalid content string property."

    let validatePath (path: string) =
        if String.IsNullOrWhiteSpace path || not (path.StartsWith('/')) || path = "/"
           || Path.GetFullPath(path) <> path || path.EndsWith('/')
           || path.Split('/') |> Array.exists (fun part -> part = "." || part = "..")
           || path |> Seq.exists Char.IsControl then
            fail "Content targets must be canonical absolute paths without control characters."
        path

    let private validateSource (path: string) =
        if String.IsNullOrWhiteSpace path || path.StartsWith('/') || path.Contains('\\')
           || path.Split('/') |> Array.exists (fun part -> part = "." || part = ".." || part = "")
           || path |> Seq.exists Char.IsControl then
            fail "Archive members must be canonical relative regular-file paths."
        path

    let private validHash (value: string) =
        not (isNull value) && value.Length = 64 && value |> Seq.forall Uri.IsHexDigit

    let hashFile path =
        use input = File.OpenRead path
        SHA256.HashData(input) |> Convert.ToHexString |> fun value -> value.ToLowerInvariant()

    let private targets (request: JsonElement) =
        let result =
            request.GetProperty("targets").EnumerateArray()
            |> Seq.map (fun node ->
                let mode =
                    match node.TryGetProperty "mode" with
                    | true, value ->
                        let mode = value.GetInt32()
                        if mode < 0 || mode > 0o7777 then fail "Content mode is outside the Unix permission range."
                        Some mode
                    | _ -> None
                let identity name =
                    optionalText node name |> Option.map (fun value ->
                        if String.IsNullOrWhiteSpace value || value.StartsWith('-')
                           || value |> Seq.exists (fun c -> Char.IsWhiteSpace c || Char.IsControl c || c = ':' || c = '/') then
                            fail "Invalid content owner or group."
                        value)
                { Path = validatePath (text node "path")
                  Source = optionalText node "source" |> Option.defaultValue ""
                  Mode = mode; Owner = identity "owner"; Group = identity "group" })
            |> Seq.toList
        if result.IsEmpty || (result |> List.map _.Path |> Set.ofList).Count <> result.Length then
            fail "Content requires distinct destination paths."
        result

    /// Reject symlinks in all existing path components, including dangling final links.
    let ensureSafePath path =
        let mutable current = Path.GetFullPath path
        while not (String.IsNullOrEmpty current) do
            let mutable stat = Unchecked.defaultof<ContentStatx>
            if nativeStatx(-100, current, 0x100, 0x1u, &stat) = 0 then
                let kind = stat.Mode &&& 0xF000us
                if kind <> 0x8000us && kind <> 0x4000us then
                    fail "Content paths must be regular files or real directories, never links or special files."
            elif Marshal.GetLastWin32Error() <> 2 then
                fail "Unable to inspect content path."
            current <- Path.GetDirectoryName current

    let private run (environment: HostEnvironment) command args =
        let result = environment.Run command args None
        if result.ExitCode <> 0 then fail "A content filesystem operation failed."
        result.Stdout.Trim()

    let private setMetadata environment (target: Target) (path: string) =
        let mode =
            target.Mode
            |> Option.orElseWith (fun () ->
                if target.Owner.IsSome || target.Group.IsSome then Some(int (File.GetUnixFileMode path))
                else None)
        match target.Owner, target.Group with
        | None, None -> ()
        | owner, group ->
            let identity = defaultArg owner "" + (group |> Option.map ((+) ":") |> Option.defaultValue "")
            run environment "/usr/bin/chown" [ "--"; identity; path ] |> ignore
        // chown can clear set-id bits, so chmod follows it and both precede rename.
        mode |> Option.iter (fun mode -> File.SetUnixFileMode(path, enum<UnixFileMode> mode))

    let private metadataMatches environment (target: Target) (path: string) =
        let identityMatches numeric named value =
            let format = if value |> Seq.forall Char.IsAsciiDigit then numeric else named
            run environment "/usr/bin/stat" [ "-c"; format; "--"; path ] = value
        (target.Mode |> Option.forall (fun mode -> int (File.GetUnixFileMode path) = mode))
        && (target.Owner |> Option.forall (identityMatches "%u" "%U"))
        && (target.Group |> Option.forall (identityMatches "%g" "%G"))

    /// Stage in the destination filesystem, apply metadata, then publish with one rename.
    let stageFile environment target (source: Stream) =
        let destination = HostEnvironment.path environment target.Path
        ensureSafePath destination
        Directory.CreateDirectory(Path.GetDirectoryName destination) |> ignore
        let temporary = Path.Combine(Path.GetDirectoryName destination, ".keroosha-content-" + Guid.NewGuid().ToString("N"))
        try
            let options = FileStreamOptions(Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None)
            options.UnixCreateMode <- Nullable(enum<UnixFileMode> 0o600)
            use output = new FileStream(temporary, options)
            source.CopyTo output
            output.Flush(true)
            if File.Exists destination && (target.Owner.IsNone || target.Group.IsNone) then
                let mutable previous = Unchecked.defaultof<ContentStatx>
                if nativeStatx(-100, destination, 0x100, 0x1u, &previous) <> 0 || previous.Mode &&& 0xF000us <> 0x8000us then
                    fail "Unable to preserve existing content ownership."
                let uid = if target.Owner.IsNone then previous.UserId else UInt32.MaxValue
                let gid = if target.Group.IsNone then previous.GroupId else UInt32.MaxValue
                if nativeFchown(int (output.SafeFileHandle.DangerousGetHandle()), uid, gid) <> 0 then
                    fail "Unable to preserve existing content ownership."
            setMetadata environment target temporary
            output.Flush(true)
            temporary, destination
        with _ ->
            File.Delete temporary
            reraise ()

    let private publish createOnly (temporary, destination) =
        ensureSafePath destination
        if createOnly && File.Exists destination then File.Delete temporary
        else
            File.Move(temporary, destination, not createOnly)
            HostFiles.syncDirectory (Path.GetDirectoryName destination)

    let private cacheFile environment digest = HostEnvironment.path environment ("/var/cache/keroosha-iac/content/" + digest)

    /// One deadline covers every redirect, response headers and the complete streamed body.
    let internal download (client: HttpClient) (timeout: TimeSpan) (request: JsonElement) (destinationPath: string) =
        task {
            use deadline = new CancellationTokenSource(timeout)
            let ct = deadline.Token
            try
                let uri = Uri(text request "url")
                if uri.Scheme <> "https" && uri.Scheme <> "http" then fail "Content downloads require HTTP or HTTPS."
                if uri.UserInfo <> "" then fail "Content URL credentials must be supplied through headers."
                use message = new HttpRequestMessage(HttpMethod.Get, uri)
                match request.TryGetProperty "headers" with
                | true, headers ->
                    for header in headers.EnumerateObject() do
                        let value = header.Value.GetString()
                        if String.IsNullOrEmpty header.Name || header.Name |> Seq.exists (fun c -> not (Char.IsAsciiLetterOrDigit c || "!#$%&'*+-.^_`|~".Contains c))
                           || value |> Seq.exists (fun c -> c = '\r' || c = '\n' || c = '\000') then
                            fail "Invalid download header."
                        if not (message.Headers.TryAddWithoutValidation(header.Name, value)) then fail "Invalid download header."
                | _ -> ()
                let! initial = client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, ct)
                let mutable response = initial
                let mutable currentUri = uri
                try
                    let mutable redirects = 0
                    while int response.StatusCode >= 300 && int response.StatusCode < 400 && redirects < 10 do
                        let location = response.Headers.Location
                        if isNull location then fail "Download redirect has no location."
                        let destination = if location.IsAbsoluteUri then location else Uri(currentUri, location)
                        if (destination.Scheme <> "https" && destination.Scheme <> "http") || destination.UserInfo <> "" then fail "Invalid download redirect."
                        if currentUri.Scheme = "https" && destination.Scheme <> "https" then fail "Refusing download TLS downgrade."
                        response.Dispose()
                        use redirected = new HttpRequestMessage(HttpMethod.Get, destination)
                        if destination.GetLeftPart(UriPartial.Authority) = uri.GetLeftPart(UriPartial.Authority) then
                            for header in message.Headers do redirected.Headers.TryAddWithoutValidation(header.Key, header.Value) |> ignore
                        let! next = client.SendAsync(redirected, HttpCompletionOption.ResponseHeadersRead, ct)
                        response <- next
                        currentUri <- destination
                        redirects <- redirects + 1
                    if not response.IsSuccessStatusCode then fail "Content download failed."
                    use! input = response.Content.ReadAsStreamAsync(ct)
                    let options = FileStreamOptions(Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, Options = FileOptions.Asynchronous)
                    options.UnixCreateMode <- Nullable(enum<UnixFileMode> 0o600)
                    use output = new FileStream(destinationPath, options)
                    do! input.CopyToAsync(output, 65536, ct)
                    output.Flush(true)
                finally
                    response.Dispose()
            with :? OperationCanceledException ->
                fail "Content download exceeded its connection or total transfer timeout."
        }

    let private acquire environment (request: JsonElement) digest =
        let cached = cacheFile environment digest
        ensureSafePath cached
        if File.Exists cached && hashFile cached = digest then cached
        else
            Directory.CreateDirectory(Path.GetDirectoryName cached) |> ignore
            let temporary = cached + "." + Guid.NewGuid().ToString("N")
            try
                use handler = new SocketsHttpHandler(AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds 30.)
                use client = new HttpClient(handler, Timeout = Timeout.InfiniteTimeSpan)
                download client (TimeSpan.FromMinutes 15.) request temporary |> fun operation -> operation.GetAwaiter().GetResult()
                if hashFile temporary <> digest then fail "Content SHA-256 verification failed."
                File.Move(temporary, cached, true)
                HostFiles.syncDirectory (Path.GetDirectoryName cached)
                cached
            finally
                File.Delete temporary

    let private stageArchive environment format cached (items: Target list) =
        let staged = ResizeArray<string * string>()
        let found = HashSet<string>(StringComparer.Ordinal)
        let selected = items |> List.groupBy _.Source |> Map.ofList
        let accept name regular (stream: Stream) =
            match selected.TryFind name with
            | None -> ()
            | Some targets ->
                if not regular || isNull stream || not (found.Add name) then fail "Archive selected member is duplicated or not a regular file."
                // A selected member can be installed at multiple destinations without buffering it in memory.
                let first = stageFile environment targets.Head stream
                staged.Add first
                for target in targets.Tail do
                    use copy = File.OpenRead(fst first)
                    staged.Add(stageFile environment target copy)
        let mutable decompressed = None
        try
            try
                match format with
                | "zip" ->
                    use archive = ZipFile.OpenRead cached
                    for entry in archive.Entries do
                        if selected.ContainsKey entry.FullName then
                            let fileType = (entry.ExternalAttributes >>> 16) &&& 0xF000
                            use input = entry.Open()
                            accept entry.FullName (not (entry.FullName.EndsWith('/')) && (fileType = 0 || fileType = 0x8000)) input
                | "tarGz" | "tarZst" ->
                    let tarPath =
                        if format = "tarZst" then
                            let output = cached + ".tar-" + Guid.NewGuid().ToString("N")
                            decompressed <- Some output
                            let options = FileStreamOptions(Mode = FileMode.CreateNew, Access = FileAccess.Write)
                            options.UnixCreateMode <- Nullable(enum<UnixFileMode> 0o600)
                            use placeholder = new FileStream(output, options)
                            placeholder.Dispose()
                            run environment "/usr/bin/zstd" [ "-q"; "-d"; "-f"; "-o"; output; "--"; cached ] |> ignore
                            output
                        else cached
                    use source = File.OpenRead tarPath
                    use input: Stream = if format = "tarGz" then new GZipStream(source, CompressionMode.Decompress) else source
                    use reader = new TarReader(input)
                    let mutable entry = reader.GetNextEntry()
                    while not (isNull entry) do
                        accept entry.Name (entry.EntryType = TarEntryType.RegularFile || entry.EntryType = TarEntryType.V7RegularFile) entry.DataStream
                        entry <- reader.GetNextEntry()
                | _ -> fail "Unsupported archive format."
                if found.Count <> selected.Count then fail "Archive does not contain every selected member."
                List.ofSeq staged
            with _ ->
                for temporary, _ in staged do File.Delete temporary
                reraise ()
        finally
            decompressed |> Option.iter File.Delete

    let handle (environment: HostEnvironment) (request: JsonElement) : JsonNode =
        let operation = text request "operation"
        if not ([ "read"; "apply"; "delete" ] |> List.contains operation) then fail "Unsupported content operation."
        let kind = text request "kind"
        if not ([ "archive"; "download"; "file"; "text"; "directory" ] |> List.contains kind) then fail "Unsupported content kind."
        let ownership = text request "ownership"
        if ownership <> "managed" && ownership <> "createOnly" then fail "Unsupported content ownership."
        let createOnly = ownership = "createOnly"
        let items = targets request
        if kind <> "archive" && items.Length <> 1 then fail "Only archives support multiple targets."
        if kind <> "directory" && items |> List.exists (fun target -> target.Mode.IsNone) then fail "File content requires a mode."
        if kind = "archive" then items |> List.iter (fun target -> validateSource target.Source |> ignore)
        let digest = optionalText request "sha256" |> Option.defaultValue ""
        if kind <> "directory" && not (validHash digest) then fail "Content requires SHA-256."
        let digest = digest.ToLowerInvariant()
        let paths = items |> List.map (fun target -> target, HostEnvironment.path environment target.Path)
        for _, path in paths do ensureSafePath path
        let present path = if kind = "directory" then Directory.Exists path else File.Exists path
        let lockPath = HostEnvironment.path environment "/run/lock/keroosha-iac-content.lock"
        Directory.CreateDirectory(Path.GetDirectoryName lockPath) |> ignore
        use held = HostFiles.lockFile lockPath
        let expected = JsonObject()
        match request.TryGetProperty "hashes" with
        | true, hashes -> for property in hashes.EnumerateObject() do expected[property.Name] <- JsonValue.Create(property.Value.GetString())
        | _ -> ()
        if kind <> "archive" && kind <> "directory" then expected[items.Head.Path] <- JsonValue.Create digest
        if operation = "apply" then
            let pending = paths |> List.filter (fun (_, path) -> not createOnly || not (present path))
            if not pending.IsEmpty then
                if kind = "directory" then
                    for target, path in pending do
                        if Directory.Exists path then setMetadata environment target path
                        else
                            Directory.CreateDirectory(Path.GetDirectoryName path) |> ignore
                            let temporary = path + "." + Guid.NewGuid().ToString("N")
                            try
                                Directory.CreateDirectory(temporary, enum<UnixFileMode> 0o700) |> ignore
                                setMetadata environment { target with Mode = Some(defaultArg target.Mode 0o755) } temporary
                                Directory.Move(temporary, path)
                                HostFiles.syncDirectory (Path.GetDirectoryName path)
                            finally
                                if Directory.Exists temporary then Directory.Delete temporary
                else
                    let staged =
                        if kind = "archive" || kind = "download" then
                            let cached = acquire environment request digest
                            if kind = "archive" then stageArchive environment (text request "format") cached (pending |> List.map fst)
                            else
                                use source = File.OpenRead cached
                                [ stageFile environment (fst pending.Head) source ]
                        else
                            let bytes = Convert.FromBase64String(text request "data")
                            if (SHA256.HashData bytes |> Convert.ToHexString).ToLowerInvariant() <> digest then fail "Content SHA-256 verification failed."
                            use source = new MemoryStream(bytes, false)
                            [ stageFile environment (fst pending.Head) source ]
                    try
                        for temporary, destination in staged do
                            let target = pending |> List.find (fun (_, path) -> path = destination) |> fst
                            expected[target.Path] <- JsonValue.Create(hashFile temporary)
                        for item in staged do publish createOnly item
                    finally
                        for temporary, _ in staged do File.Delete temporary
        elif operation = "delete" && not createOnly then
            for _, path in paths do
                if kind = "directory" then
                    if Directory.Exists path && Seq.isEmpty (Directory.EnumerateFileSystemEntries path) then Directory.Delete path
                else File.Delete path
        let hashes = JsonObject()
        let mutable exists = true
        let mutable inSync = true
        for target, path in paths do
            let found = present path
            exists <- exists && found
            if not found then inSync <- false
            elif not createOnly then
                inSync <- inSync && metadataMatches environment target path
                if kind <> "directory" then
                    let actual = hashFile path
                    hashes[target.Path] <- JsonValue.Create actual
                    let desired = expected[target.Path]
                    inSync <- inSync && not (isNull desired) && desired.GetValue<string>() = actual
        let result = JsonObject()
        result["exists"] <- JsonValue.Create exists
        result["inSync"] <- JsonValue.Create inSync
        result["hashes"] <- hashes
        result :> JsonNode
