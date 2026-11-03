namespace Dorothy.HostHelper

open System
open System.Globalization
open System.Collections.Generic
open System.IO
open System.Runtime.InteropServices
open System.Security.Cryptography
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open Microsoft.Win32.SafeHandles

[<Struct; StructLayout(LayoutKind.Sequential, Size = 256)>]
type private SwapfileStatx =
    val mutable Mask: uint32
    val mutable BlockSize: uint32
    val mutable Attributes: uint64
    val mutable LinkCount: uint32
    val mutable UserId: uint32
    val mutable GroupId: uint32
    val mutable Mode: uint16
    val mutable Spare0: uint16
    val mutable Inode: uint64
    val mutable Size: uint64
    val mutable Blocks: uint64
    val mutable AttributesMask: uint64
    val mutable AtimeSeconds: int64
    val mutable AtimeNanoseconds: uint32
    val mutable AtimeReserved: int32
    val mutable BtimeSeconds: int64
    val mutable BtimeNanoseconds: uint32
    val mutable BtimeReserved: int32
    val mutable CtimeSeconds: int64
    val mutable CtimeNanoseconds: uint32
    val mutable CtimeReserved: int32
    val mutable MtimeSeconds: int64
    val mutable MtimeNanoseconds: uint32
    val mutable MtimeReserved: int32
    val mutable RdevMajor: uint32
    val mutable RdevMinor: uint32
    val mutable DeviceMajor: uint32
    val mutable DeviceMinor: uint32

type private SwapfileIdentity =
    { DeviceMajor: uint32
      DeviceMinor: uint32
      Inode: uint64 }

type private SwapfileRecord =
    { Path: string
      UnitPath: string
      UnitName: string
      SizeBytes: int64
      Identity: SwapfileIdentity }

type private SwapfileState =
    { OwnerId: string
      Primary: SwapfileRecord
      Retired: SwapfileRecord list }

type private SwapfileMetadata =
    { Identity: SwapfileIdentity
      SizeBytes: int64
      Mode: int
      UserId: uint32
      FileType: int }

module Swapfile =
    type BackendError(message: string) =
        inherit InvalidOperationException(message)

    [<Literal>]
    let private StateDirectory = "/var/lib/keroosha-iac/swapfiles"

    [<Literal>]
    let private UnitDirectory = "/etc/systemd/system"

    [<Literal>]
    let private Mebibyte = 1048576L

    let private stateMode = UnixFileMode.UserRead ||| UnixFileMode.UserWrite
    let private directoryMode = UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute
    let private unitMode = UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.GroupRead ||| UnixFileMode.OtherRead
    let private strictUtf8 = UTF8Encoding(false, true)

    [<DllImport("libc", EntryPoint = "statx", SetLastError = true)>]
    extern int private nativeStatx (int directoryFileDescriptor, string path, int flags, uint32 mask, SwapfileStatx& result)

    [<DllImport("libc", EntryPoint = "open", SetLastError = true)>]
    extern int private nativeOpen (string path, int flags, int mode)
    [<DllImport("libc", EntryPoint = "openat", SetLastError = true)>]
    extern int private nativeOpenAt (int directoryFileDescriptor, string path, int flags, int mode)
    [<DllImport("libc", EntryPoint = "linkat", SetLastError = true)>]
    extern int private nativeLinkAt (int oldDirectoryFileDescriptor, string oldPath, int newDirectoryFileDescriptor, string newPath, int flags)

    [<DllImport("libc", EntryPoint = "fchmod", SetLastError = true)>]
    extern int private nativeFchmod (int fileDescriptor, int mode)

    [<DllImport("libc", EntryPoint = "fsync", SetLastError = true)>]
    extern int private nativeFsync (int fileDescriptor)
    [<DllImport("libc", EntryPoint = "ftruncate", SetLastError = true)>]
    extern int private nativeFtruncate (int fileDescriptor, int64 length)
    [<DllImport("libc", EntryPoint = "geteuid")>]
    extern uint32 private nativeGetEffectiveUserId ()
    let private fail message = raise (BackendError(message))

    let private isProductionRoot (environment: HostEnvironment) = Path.GetFullPath environment.Root = "/"

    let private requireProductionRoot (environment: HostEnvironment) =
        if isProductionRoot environment && nativeGetEffectiveUserId() <> 0u then
            fail "The swapfile helper must run as root."

    let private requireRootOwned (environment: HostEnvironment) (metadata: SwapfileMetadata) description =
        if isProductionRoot environment && metadata.UserId <> 0u then
            fail ("The " + description + " is not root-owned.")

    let private isControl (value: string) =
        value |> Seq.exists (fun character -> int character < 32 || int character = 127)

    let private ownerDigest (ownerId: string) =
        if String.IsNullOrEmpty ownerId || ownerId.Length > 4096 then
            fail "Swapfile ownerId must be a non-empty string of at most 4096 characters."
        if isControl ownerId then fail "Swapfile ownerId must not contain control characters."
        let bytes =
            try strictUtf8.GetBytes ownerId
            with :? EncoderFallbackException -> fail "Swapfile ownerId is not valid UTF-8."
        SHA256.HashData(bytes) |> Convert.ToHexString |> fun value -> value.ToLowerInvariant()

    let private validatePath (path: string) =
        let validCharacter (character: char) =
            (character >= 'a' && character <= 'z')
            || (character >= 'A' && character <= 'Z')
            || (character >= '0' && character <= '9')
            || character = '_'
            || character = '-'
            || character = '.'
            || character = '+'

        let validSegment (segment: string) =
            segment.Length > 0
            && segment <> "."
            && segment <> ".."
            && (segment |> Seq.forall validCharacter)

        if String.IsNullOrWhiteSpace path || path[0] <> '/' || isControl path then
            fail "Swapfile path must be an absolute path without control characters."
        let normalized =
            try Path.GetFullPath path
            with _ -> fail "Swapfile path is invalid."
        if normalized <> path
           || normalized = Path.GetPathRoot normalized
           || String.IsNullOrEmpty(Path.GetFileName normalized)
           || not (path.Substring(1).Split('/') |> Array.forall validSegment) then
            fail "Swapfile path must be a canonical absolute path with safe path components."
        normalized

    let private validateSize (sizeBytes: int64) =
        if sizeBytes <= 0L || sizeBytes % Mebibyte <> 0L then
            fail "Swapfile sizeBytes must be positive and MiB-aligned."

    let private parseRequest (request: JsonElement) =
        if request.ValueKind <> JsonValueKind.Object then fail "The swapfile request must be a JSON object."
        let properties = request.EnumerateObject() |> Seq.toArray
        let names = properties |> Array.map (fun property -> property.Name) |> Set.ofArray
        if properties.Length <> 4 || names <> Set.ofList [ "operation"; "ownerId"; "path"; "sizeBytes" ] then
            fail "The swapfile request must contain only operation, ownerId, path, and sizeBytes."

        let readString (name: string) =
            let value = request.GetProperty(name)
            if value.ValueKind <> JsonValueKind.String then fail ("Swapfile " + name + " must be a string.")
            match value.GetString() with
            | null -> fail ("Swapfile " + name + " must not be null.")
            | text -> text

        let operation = readString "operation"
        if operation <> "read" && operation <> "apply" && operation <> "delete" then fail "Unsupported swapfile operation."
        let ownerId = readString "ownerId"
        let digest = ownerDigest ownerId
        let path = validatePath (readString "path")
        let sizeElement = request.GetProperty("sizeBytes")
        if sizeElement.ValueKind <> JsonValueKind.Number then fail "Swapfile sizeBytes must be a signed 64-bit integer."
        let mutable sizeBytes = 0L
        if not (sizeElement.TryGetInt64(&sizeBytes)) then fail "Swapfile sizeBytes must be a signed 64-bit integer."
        validateSize sizeBytes
        operation, ownerId, digest, path, sizeBytes

    let private pathError (path: string) =
        let code = Marshal.GetLastPInvokeError()
        if code = 2 then None
        else raise (IOException("Could not safely inspect filesystem path '" + path + "'.", System.ComponentModel.Win32Exception(code)))

    let private inspectNoFollow (path: string) =
        let mutable metadata = Unchecked.defaultof<SwapfileStatx>
        if nativeStatx(-100, path, 0x100, 0x7FFu, &metadata) = 0 then
            Some {
                Identity = { DeviceMajor = metadata.DeviceMajor; DeviceMinor = metadata.DeviceMinor; Inode = metadata.Inode }
                SizeBytes = if metadata.Size > uint64 Int64.MaxValue then Int64.MaxValue else int64 metadata.Size
                Mode = int (metadata.Mode &&& 0x0FFFus)
                UserId = metadata.UserId
                FileType = int (metadata.Mode &&& 0xF000us)
            }
        else pathError path

    let private inspectDescriptor (fileDescriptor: int) =
        let mutable metadata = Unchecked.defaultof<SwapfileStatx>
        if nativeStatx(fileDescriptor, "", 0x1000, 0x7FFu, &metadata) <> 0 then
            let code = Marshal.GetLastPInvokeError()
            raise (IOException("Could not safely inspect the open swapfile.", System.ComponentModel.Win32Exception(code)))
        { Identity = { DeviceMajor = metadata.DeviceMajor; DeviceMinor = metadata.DeviceMinor; Inode = metadata.Inode }
          SizeBytes = if metadata.Size > uint64 Int64.MaxValue then Int64.MaxValue else int64 metadata.Size
          Mode = int (metadata.Mode &&& 0x0FFFus)
          UserId = metadata.UserId
          FileType = int (metadata.Mode &&& 0xF000us) }

    let private sameIdentity left right =
        left.DeviceMajor = right.DeviceMajor && left.DeviceMinor = right.DeviceMinor && left.Inode = right.Inode

    let private actualPath (environment: HostEnvironment) logicalPath = HostEnvironment.path environment logicalPath

    let private fullDirectoryChainExists (path: string) (create: bool) (finalMode: UnixFileMode) =
        let fullPath = Path.GetFullPath path
        let root = Path.GetPathRoot fullPath
        if String.IsNullOrEmpty root then fail "A host directory path must be absolute."
        match inspectNoFollow root with
        | Some metadata when metadata.FileType = 0x4000 -> ()
        | _ -> fail "A host path has no real filesystem root directory."
        let components =
            fullPath.Substring(root.Length).Split([| Path.DirectorySeparatorChar; Path.AltDirectorySeparatorChar |], StringSplitOptions.RemoveEmptyEntries)
        let mutable current = root
        let mutable exists = true
        for index in 0 .. components.Length - 1 do
            current <- Path.Combine(current, components[index])
            if exists then
                match inspectNoFollow current with
                | Some metadata when metadata.FileType = 0x4000 -> ()
                | Some _ -> fail ("Filesystem parent '" + current + "' is not a real directory.")
                | None when create ->
                    try Directory.CreateDirectory(current) |> ignore
                    with _ -> fail ("Could not create required filesystem directory '" + current + "'.")
                    match inspectNoFollow current with
                    | Some metadata when metadata.FileType = 0x4000 ->
                        let mode = if index = components.Length - 1 then finalMode else directoryMode
                        try File.SetUnixFileMode(current, mode)
                        with _ -> fail ("Could not set safe permissions on filesystem directory '" + current + "'.")
                    | _ -> fail ("Filesystem path '" + current + "' is not a real directory.")
                | None -> exists <- false
        exists
    let private requireSafeDirectoryChain (environment: HostEnvironment) (directory: string) =
        let fullPath = Path.GetFullPath directory
        let boundary =
            if isProductionRoot environment then
                Path.GetPathRoot fullPath
            else
                Path.TrimEndingDirectorySeparator(Path.GetFullPath environment.Root)
        if String.IsNullOrEmpty boundary then fail "A filesystem parent path must be absolute."
        let relative = Path.GetRelativePath(boundary, fullPath)
        if Path.IsPathRooted relative
           || relative = ".."
           || relative.StartsWith(".." + string Path.DirectorySeparatorChar, StringComparison.Ordinal) then
            fail "A filesystem parent path escapes the managed host root."
        let components =
            if relative = "." then [||]
            else relative.Split([| Path.DirectorySeparatorChar; Path.AltDirectorySeparatorChar |], StringSplitOptions.RemoveEmptyEntries)
        let inspectDirectory path =
            match inspectNoFollow path with
            | Some metadata when metadata.FileType = 0x4000 ->
                requireRootOwned environment metadata "swapfile parent directory"
                if (metadata.Mode &&& 0o022) <> 0 then
                    fail ("Swapfile parent directory '" + path + "' is group- or world-writable.")
                metadata.UserId
            | _ -> fail ("Filesystem parent '" + path + "' is not a real directory.")
        let boundaryOwner = inspectDirectory boundary
        let mutable current = boundary
        for pathComponent in components do
            current <- Path.Combine(current, pathComponent)
            if inspectDirectory current <> boundaryOwner then
                fail ("Swapfile parent directory '" + current + "' has an unexpected owner.")

    let private ensureDirectory (environment: HostEnvironment) (logicalDirectory: string) (create: bool) (finalMode: UnixFileMode) =
        let directory = actualPath environment logicalDirectory
        if fullDirectoryChainExists directory create finalMode then
            requireSafeDirectoryChain environment directory
            let metadata = inspectNoFollow directory |> Option.get
            requireRootOwned environment metadata "swapfile state directory"
            Some directory
        else None

    let private inspectManagedPath (environment: HostEnvironment) (logicalPath: string) =
        let path = actualPath environment logicalPath
        let parent = Path.GetDirectoryName path
        if String.IsNullOrEmpty parent || not (fullDirectoryChainExists parent false directoryMode) then None
        else
            requireSafeDirectoryChain environment parent
            match inspectNoFollow path with
            | None -> None
            | Some metadata when metadata.FileType = 0x8000 ->
                requireRootOwned environment metadata "swapfile"
                Some metadata
            | Some _ -> fail ("Refusing to follow or replace non-regular filesystem object '" + logicalPath + "'.")

    let private statePath (environment: HostEnvironment) (digest: string) = actualPath environment (StateDirectory + "/" + digest + ".json")

    let private pathUnitName (environment: HostEnvironment) (logicalPath: string) =
        let result = environment.Run "systemd-escape" [ "--path"; "--suffix=swap"; logicalPath ] None
        if result.ExitCode <> 0 then fail "Could not derive the systemd swap unit name."
        let output = result.Stdout.Trim()
        if String.IsNullOrWhiteSpace output || not (output.EndsWith(".swap", StringComparison.Ordinal)) || isControl output || output.Contains('/') then
            fail "systemd-escape returned an invalid swap unit name."
        output

    let private unitPath (environment: HostEnvironment) (name: string) = actualPath environment (UnitDirectory + "/" + name)

    let private safeReadRegularFile (environment: HostEnvironment) (path: string) =
        let parent = Path.GetDirectoryName path
        if String.IsNullOrEmpty parent || not (fullDirectoryChainExists parent false directoryMode) then None
        else
            requireSafeDirectoryChain environment parent
            match inspectNoFollow path with
            | None -> None
            | Some initial when initial.FileType <> 0x8000 -> fail ("Refusing to read non-regular filesystem object '" + path + "'.")
            | Some initial ->
                requireRootOwned environment initial "swapfile state or systemd unit file"
                // Linux: O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW.
                let descriptor = nativeOpen(path, 0x800 ||| 0x80000 ||| 0x20000, 0)
                if descriptor < 0 then
                    let code = Marshal.GetLastPInvokeError()
                    raise (IOException("Could not safely open filesystem file '" + path + "'.", System.ComponentModel.Win32Exception(code)))
                use handle = new SafeFileHandle(nativeint descriptor, true)
                let opened = inspectDescriptor descriptor
                if opened.FileType <> 0x8000 || not (sameIdentity initial.Identity opened.Identity) then
                    fail ("Filesystem file changed while it was being opened: '" + path + "'.")
                use stream = new FileStream(handle, FileAccess.Read, 4096, false)
                use buffer = new MemoryStream()
                stream.CopyTo(buffer)
                match inspectNoFollow path with
                | Some current when sameIdentity opened.Identity current.Identity -> Some(strictUtf8.GetString(buffer.ToArray()), current)
                | _ -> fail ("Filesystem file changed while it was being read: '" + path + "'.")

    let private jsonObjectProperties (element: JsonElement) (expected: Set<string>) =
        if element.ValueKind <> JsonValueKind.Object then fail "The swapfile state is malformed."
        let properties = element.EnumerateObject() |> Seq.toArray
        let names = properties |> Array.map (fun property -> property.Name) |> Set.ofArray
        if properties.Length <> expected.Count || names <> expected then fail "The swapfile state is malformed."

    let private readInt64 (element: JsonElement) (name: string) =
        let value = element.GetProperty(name)
        let mutable number = 0L
        if value.ValueKind <> JsonValueKind.Number || not (value.TryGetInt64(&number)) then fail "The swapfile state is malformed."
        number

    let private readUInt32 (element: JsonElement) (name: string) =
        let value = element.GetProperty(name)
        let mutable number = 0u
        if value.ValueKind <> JsonValueKind.Number || not (value.TryGetUInt32(&number)) then fail "The swapfile state is malformed."
        number

    let private readUInt64 (element: JsonElement) (name: string) =
        let value = element.GetProperty(name)
        let mutable number = 0UL
        if value.ValueKind <> JsonValueKind.Number || not (value.TryGetUInt64(&number)) then fail "The swapfile state is malformed."
        number

    let private readRecordPath (element: JsonElement) (name: string) =
        let value = element.GetProperty(name)
        if value.ValueKind <> JsonValueKind.String then fail "The swapfile state is malformed."
        match value.GetString() with
        | null -> fail "The swapfile state is malformed."
        | path -> validatePath path

    let private parseRecord (environment: HostEnvironment) (element: JsonElement) =
        jsonObjectProperties element (set [ "path"; "unitPath"; "unitName"; "sizeBytes"; "deviceMajor"; "deviceMinor"; "inode" ])
        let path = readRecordPath element "path"
        let unitPath = readRecordPath element "unitPath"
        let nameElement = element.GetProperty("unitName")
        if nameElement.ValueKind <> JsonValueKind.String then fail "The swapfile state is malformed."
        let unitName =
            match nameElement.GetString() with
            | null -> fail "The swapfile state is malformed."
            | name -> name
        if pathUnitName environment unitPath <> unitName then fail "The swapfile state contains a non-canonical systemd unit name."
        let sizeBytes = readInt64 element "sizeBytes"
        validateSize sizeBytes
        let identity =
            { DeviceMajor = readUInt32 element "deviceMajor"
              DeviceMinor = readUInt32 element "deviceMinor"
              Inode = readUInt64 element "inode" }
        if identity.Inode = 0UL then fail "The swapfile state is malformed."
        { Path = path; UnitPath = unitPath; UnitName = unitName; SizeBytes = sizeBytes; Identity = identity }

    let private encodeRecord (record: SwapfileRecord) =
        let node = JsonObject()
        node["path"] <- JsonValue.Create(record.Path)
        node["unitPath"] <- JsonValue.Create(record.UnitPath)
        node["unitName"] <- JsonValue.Create(record.UnitName)
        node["sizeBytes"] <- JsonValue.Create(record.SizeBytes)
        node["deviceMajor"] <- JsonValue.Create(record.Identity.DeviceMajor)
        node["deviceMinor"] <- JsonValue.Create(record.Identity.DeviceMinor)
        node["inode"] <- JsonValue.Create(record.Identity.Inode)
        node

    let private stateNode (state: SwapfileState) =
        let root = JsonObject()
        root["version"] <- JsonValue.Create(1)
        root["ownerId"] <- JsonValue.Create(state.OwnerId)
        root["primary"] <- encodeRecord state.Primary
        let retired = JsonArray()
        for record in state.Retired do retired.Add(encodeRecord record)
        root["retired"] <- retired
        root

    let private loadState (environment: HostEnvironment) (ownerId: string) (digest: string) (createDirectory: bool) =
        let directory = ensureDirectory environment StateDirectory createDirectory directoryMode
        match directory with
        | None -> None, 0
        | Some _ ->
            let path = statePath environment digest
            match safeReadRegularFile environment path with
            | None -> None, 0
            | Some (text, metadata) ->
                try
                    use document = JsonDocument.Parse(text)
                    let element = document.RootElement
                    jsonObjectProperties element (set [ "version"; "ownerId"; "primary"; "retired" ])
                    let version = element.GetProperty("version")
                    if version.ValueKind <> JsonValueKind.Number || version.GetInt32() <> 1 then fail "The swapfile state is malformed."
                    let storedOwner = element.GetProperty("ownerId")
                    if storedOwner.ValueKind <> JsonValueKind.String || storedOwner.GetString() <> ownerId then
                        fail "A pre-existing swapfile state file is not owned by this resource."
                    let primary = parseRecord environment (element.GetProperty("primary"))
                    if primary.UnitPath <> primary.Path then fail "The swapfile state is malformed."
                    let retiredElement = element.GetProperty("retired")
                    if retiredElement.ValueKind <> JsonValueKind.Array then fail "The swapfile state is malformed."
                    let retired = retiredElement.EnumerateArray() |> Seq.map (parseRecord environment) |> Seq.toList
                    if retired |> List.exists (fun record -> record.Path = primary.Path && sameIdentity record.Identity primary.Identity) then
                        fail "The swapfile state is malformed."
                    Some { OwnerId = ownerId; Primary = primary; Retired = retired }, metadata.Mode
                with
                | :? BackendError -> reraise ()
                | _ -> fail "The swapfile state is malformed."

    let private writeState (environment: HostEnvironment) (digest: string) (state: SwapfileState) =
        let directory = ensureDirectory environment StateDirectory true directoryMode |> Option.get
        let path = statePath environment digest
        loadState environment state.OwnerId digest false |> ignore
        HostFiles.atomicWrite path (stateNode state |> fun node -> node.ToJsonString() |> strictUtf8.GetBytes) stateMode
        if not (fullDirectoryChainExists directory false directoryMode) then fail "The swapfile state directory is unavailable."

    let private escapeUnitValue (value: string) =
        value.Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace(" ", "\\x20", StringComparison.Ordinal)

    let private unitText (digest: string) (logicalPath: string) =
        String.concat "\n" [
            "# Dorothy owner-sha256=" + digest
            "# Dorothy path=" + logicalPath
            "[Unit]"
            "Description=Dorothy managed swapfile " + digest
            "Before=swap.target"
            "[Swap]"
            "What=" + escapeUnitValue logicalPath
            "[Install]"
            "WantedBy=swap.target"
            ""
        ]

    let private readUnitFile (environment: HostEnvironment) (name: string) =
        let path = unitPath environment name
        if not (fullDirectoryChainExists (Path.GetDirectoryName path) false directoryMode) then None
        else safeReadRegularFile environment path |> Option.map fst

    let private writeUnitFile (environment: HostEnvironment) (name: string) (currentText: string option) (desiredText: string) =
        let path = unitPath environment name
        if not (fullDirectoryChainExists (Path.GetDirectoryName path) false directoryMode) then
            fail "The systemd unit directory is unavailable."
        match safeReadRegularFile environment path with
        | None ->
            if currentText.IsSome then fail "The owned swapfile systemd unit disappeared unexpectedly."
            HostFiles.atomicWrite path (strictUtf8.GetBytes desiredText) unitMode
        | Some (existingText, _) ->
            match currentText with
            | Some expected when existingText = expected ->
                if existingText <> desiredText then HostFiles.atomicWrite path (strictUtf8.GetBytes desiredText) unitMode
            | _ -> fail "Refusing to replace a pre-existing unowned swapfile systemd unit."

    let private removeUnitFile (environment: HostEnvironment) (name: string) (expectedText: string) =
        let path = unitPath environment name
        match safeReadRegularFile environment path with
        | None -> ()
        | Some (contents, _) when contents = expectedText -> File.Delete path
        | Some _ -> fail "Refusing to remove a swapfile systemd unit that is no longer owned."

    let private run (environment: HostEnvironment) (executable: string) (arguments: string list) =
        let result = environment.Run executable arguments None
        if result.ExitCode <> 0 then
            let diagnostic = if String.IsNullOrWhiteSpace result.Stderr then result.Stdout.Trim() else result.Stderr.Trim()
            let safeDiagnostic =
                diagnostic
                |> Seq.map (fun character -> if Char.IsControl character then ' ' else character)
                |> Array.ofSeq
                |> fun characters -> String(characters)
            if String.IsNullOrWhiteSpace safeDiagnostic then fail ("Swapfile host command '" + executable + "' failed.")
            fail ("Swapfile host command '" + executable + "' failed: " + safeDiagnostic)
        result.Stdout

    type private UnitStatus =
        { Exists: bool
          Enabled: bool
          UnitActive: bool }

    let private readUnitStatus (environment: HostEnvironment) (name: string) =
        let output =
            run environment "systemctl" [ "show"; "--no-pager"; "--property=LoadState"; "--property=UnitFileState"; "--property=ActiveState"; name ]
        let values = Dictionary<string, string>(StringComparer.Ordinal)
        for line in output.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries) do
            let separator = line.IndexOf('=')
            if separator <= 0 then fail "Swapfile systemd status is malformed."
            let key = line.Substring(0, separator)
            if key <> "LoadState" && key <> "UnitFileState" && key <> "ActiveState" then fail "Swapfile systemd status contains an unexpected property."
            if values.ContainsKey key then fail "Swapfile systemd status contains duplicate properties."
            values.Add(key, line.Substring(separator + 1))
        if values.Count <> 3 then fail "Swapfile systemd status omitted required properties."
        let loadState = values["LoadState"]
        if loadState = "not-found" then { Exists = false; Enabled = false; UnitActive = false }
        elif loadState = "loaded" || loadState = "masked" then
            { Exists = true
              Enabled = values["UnitFileState"] = "enabled"
              UnitActive = values["ActiveState"] = "active" }
        else fail "Swapfile systemd status contains an unknown load state."

    let private readActivePaths (environment: HostEnvironment) =
        let output = run environment "swapon" [ "--show=NAME"; "--noheadings"; "--raw" ]
        output.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
        |> Array.map (fun path -> path.TrimEnd())
        |> Set.ofArray

    let private pathIsActive (environment: HostEnvironment) (logicalPath: string) =
        (readActivePaths environment).Contains(actualPath environment logicalPath)

    let private recordIsActive (environment: HostEnvironment) (record: SwapfileRecord) = pathIsActive environment record.Path

    let private currentRecordMetadata (environment: HostEnvironment) (record: SwapfileRecord) =
        match inspectManagedPath environment record.Path with
        | None -> None
        | Some metadata when sameIdentity metadata.Identity record.Identity -> Some metadata
        | Some _ -> fail ("The swapfile at '" + record.Path + "' no longer has its recorded file identity.")

    let private openOwnedFile (environment: HostEnvironment) (record: SwapfileRecord) =
        let path = actualPath environment record.Path
        match currentRecordMetadata environment record with
        | None -> fail "The owned swapfile is missing."
        | Some _ ->
            // Linux: O_RDWR | O_CLOEXEC | O_NOFOLLOW.
            let descriptor = nativeOpen(path, 0x2 ||| 0x80000 ||| 0x20000, 0)
            if descriptor < 0 then
                let code = Marshal.GetLastPInvokeError()
                raise (IOException("Could not safely open owned swapfile '" + record.Path + "'.", System.ComponentModel.Win32Exception(code)))
            let handle = new SafeFileHandle(nativeint descriptor, true)
            let metadata = inspectDescriptor descriptor
            if metadata.FileType <> 0x8000 || not (sameIdentity metadata.Identity record.Identity) then
                handle.Dispose()
                fail "The owned swapfile changed while it was being opened."
            handle, metadata

    let private repairMode (environment: HostEnvironment) (record: SwapfileRecord) =
        let handle, metadata = openOwnedFile environment record
        use handle = handle
        if metadata.Mode <> 0o600 then
            let descriptor = handle.DangerousGetHandle().ToInt32()
            if nativeFchmod(descriptor, 0o600) <> 0 then
                let code = Marshal.GetLastPInvokeError()
                raise (IOException("Could not repair swapfile mode.", System.ComponentModel.Win32Exception(code)))
        let after = inspectDescriptor (handle.DangerousGetHandle().ToInt32())
        if after.Mode <> 0o600 || not (sameIdentity after.Identity record.Identity) then fail "Could not verify repaired swapfile mode."


    let private createSwapfile
        (environment: HostEnvironment)
        (logicalPath: string)
        (unitPath: string)
        (unitName: string)
        (sizeBytes: int64)
        (persist: SwapfileRecord -> SwapfileState)
        =
        let path = actualPath environment logicalPath
        let parent = Path.GetDirectoryName path
        if String.IsNullOrEmpty parent || not (fullDirectoryChainExists parent false directoryMode) then
            fail ("Swapfile parent directory for '" + logicalPath + "' does not exist or is not a real directory.")
        requireSafeDirectoryChain environment parent
        match inspectNoFollow path with
        | Some _ -> fail ("Refusing to overwrite pre-existing swapfile path '" + logicalPath + "'.")
        | None -> ()

        // Hold the validated directory open so preparation and publication use the same directory.
        let parentDescriptor = nativeOpen(parent, 0x80000 ||| 0x20000 ||| 0x10000, 0)
        if parentDescriptor < 0 then
            let code = Marshal.GetLastPInvokeError()
            raise (IOException("Could not safely open the swapfile parent directory.", System.ComponentModel.Win32Exception(code)))
        use parentHandle = new SafeFileHandle(nativeint parentDescriptor, true)
        let parentMetadata = inspectDescriptor parentDescriptor
        if parentMetadata.FileType <> 0x4000 then fail "The swapfile parent is not a real directory."
        requireRootOwned environment parentMetadata "swapfile parent directory"
        if (parentMetadata.Mode &&& 0o022) <> 0 then fail "The swapfile parent directory is group- or world-writable."
        requireSafeDirectoryChain environment parent
        match inspectNoFollow parent with
        | Some current when current.FileType = 0x4000 && sameIdentity parentMetadata.Identity current.Identity -> ()
        | _ -> fail "The swapfile parent directory changed while it was being opened."

        // Linux O_TMPFILE: keep the inode anonymous until its ownership record is durable.
        let descriptor = nativeOpenAt(parentDescriptor, ".", 0x2 ||| 0x410000 ||| 0x80000, 0o600)
        if descriptor < 0 then
            let code = Marshal.GetLastPInvokeError()
            if code = 22 || code = 38 || code = 95 then
                fail "The swapfile parent filesystem or kernel does not support O_TMPFILE anonymous creation."
            raise (IOException("Could not safely prepare an anonymous swapfile.", System.ComponentModel.Win32Exception(code)))
        use handle = new SafeFileHandle(nativeint descriptor, true)
        let initial = inspectDescriptor descriptor
        if initial.FileType <> 0x8000 then fail "The anonymous swapfile is not a regular file."
        let identity = initial.Identity

        let preparationPath =
            "/proc/"
            + Environment.ProcessId.ToString(CultureInfo.InvariantCulture)
            + "/fd/"
            + descriptor.ToString(CultureInfo.InvariantCulture)
        run environment "fallocate" [ "-l"; sizeBytes.ToString(CultureInfo.InvariantCulture); "--"; preparationPath ] |> ignore
        run environment "mkswap" [ "--"; preparationPath ] |> ignore
        if nativeFchmod(descriptor, 0o600) <> 0 then
            let code = Marshal.GetLastPInvokeError()
            raise (IOException("Could not set swapfile mode to 0600.", System.ComponentModel.Win32Exception(code)))
        if nativeFsync descriptor <> 0 then
            let code = Marshal.GetLastPInvokeError()
            raise (IOException("Could not synchronize the prepared swapfile.", System.ComponentModel.Win32Exception(code)))
        let metadata = inspectDescriptor descriptor
        requireRootOwned environment metadata "swapfile"
        if not (sameIdentity identity metadata.Identity)
           || metadata.SizeBytes <> sizeBytes
           || metadata.Mode <> 0o600 then
            fail "The prepared swapfile has unexpected filesystem metadata."
        match inspectNoFollow path with
        | None -> ()
        | Some _ -> fail ("Refusing to overwrite pre-existing swapfile path '" + logicalPath + "'.")
        match inspectNoFollow parent with
        | Some current when current.FileType = 0x4000 && sameIdentity parentMetadata.Identity current.Identity -> ()
        | _ -> fail "The swapfile parent directory changed while it was being prepared."

        let record =
            { Path = logicalPath; UnitPath = unitPath; UnitName = unitName; SizeBytes = sizeBytes; Identity = identity }
        let persistedState = persist record

        // AT_SYMLINK_FOLLOW links the proc fd reference to the anonymous inode without replacing a name.
        let linkPath = "/proc/self/fd/" + descriptor.ToString(CultureInfo.InvariantCulture)
        let fileName = Path.GetFileName path
        if nativeLinkAt(-100, linkPath, parentDescriptor, fileName, 0x400) <> 0 then
            let code = Marshal.GetLastPInvokeError()
            if code = 17 then fail ("Refusing to overwrite pre-existing swapfile path '" + logicalPath + "'.")
            if code = 22 || code = 38 || code = 95 then
                fail "The swapfile filesystem cannot safely publish the anonymous inode with linkat."
            raise (IOException("Could not safely publish the prepared swapfile '" + logicalPath + "'.", System.ComponentModel.Win32Exception(code)))
        if nativeFsync parentDescriptor <> 0 then
            let code = Marshal.GetLastPInvokeError()
            raise (IOException("Could not synchronize the swapfile parent directory.", System.ComponentModel.Win32Exception(code)))
        match inspectNoFollow path with
        | Some current when current.FileType = 0x8000 && sameIdentity identity current.Identity -> ()
        | _ -> fail "The published swapfile path does not refer to the prepared inode."
        record, persistedState

    let private removeOwnedFile (environment: HostEnvironment) (record: SwapfileRecord) =
        match currentRecordMetadata environment record with
        | None -> ()
        | Some _ ->
            if recordIsActive environment record then
                run environment "swapoff" [ "--"; actualPath environment record.Path ] |> ignore
                if recordIsActive environment record then fail ("Owned swapfile remains active and will not be removed: '" + record.Path + "'.")
            match inspectManagedPath environment record.Path with
            | Some metadata when sameIdentity metadata.Identity record.Identity -> File.Delete(actualPath environment record.Path)
            | None -> ()
            | Some _ -> fail ("The swapfile at '" + record.Path + "' changed before removal.")

    let private decodeFstabField (value: string) =
        let builder = StringBuilder(value.Length)
        let mutable index = 0
        while index < value.Length do
            if value[index] = '\\' && index + 3 < value.Length
               && value[index + 1] >= '0' && value[index + 1] <= '7'
               && value[index + 2] >= '0' && value[index + 2] <= '7'
               && value[index + 3] >= '0' && value[index + 3] <= '7' then
                let decoded = (int value[index + 1] - int '0') * 64 + (int value[index + 2] - int '0') * 8 + int value[index + 3] - int '0'
                builder.Append(char decoded) |> ignore
                index <- index + 4
            else
                builder.Append(value[index]) |> ignore
                index <- index + 1
        builder.ToString()

    let private fstabClaimsPath (environment: HostEnvironment) (logicalPath: string) =
        let fstabPath = actualPath environment "/etc/fstab"
        match safeReadRegularFile environment fstabPath with
        | None -> false
        | Some (contents, _) ->
            contents.Split([| '\n'; '\r' |], StringSplitOptions.RemoveEmptyEntries)
            |> Array.exists (fun line ->
                let trimmed = line.TrimStart()
                if trimmed.StartsWith("#", StringComparison.Ordinal) then false
                else
                    let fields = trimmed.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
                    fields.Length >= 3 && fields[2] = "swap" && decodeFstabField fields[0] = logicalPath)

    let private writeResponse (owned: bool) (path: string) (sizeBytes: int64) (mode: int) (enabled: bool) (active: bool) (inSync: bool) =
        let response = JsonObject()
        response["owned"] <- JsonValue.Create(owned)
        response["actualPath"] <- JsonValue.Create(path)
        response["actualSizeBytes"] <- JsonValue.Create(sizeBytes)
        response["mode"] <- JsonValue.Create(mode)
        response["enabled"] <- JsonValue.Create(enabled)
        response["active"] <- JsonValue.Create(active)
        response["inSync"] <- JsonValue.Create(inSync)
        response

    let private snapshot (environment: HostEnvironment) (ownerId: string) (digest: string) (desiredPath: string) (desiredSize: int64) (desiredUnitName: string) =
        let state, stateMode = loadState environment ownerId digest false
        match state with
        | None ->
            writeResponse false String.Empty 0L 0 false false false :> JsonNode
        | Some managed ->
            let expectedUnit = unitText digest managed.Primary.UnitPath
            let unitFileMatches = readUnitFile environment managed.Primary.UnitName |> Option.exists ((=) expectedUnit)
            let status = readUnitStatus environment managed.Primary.UnitName
            let activePaths = readActivePaths environment
            let metadata = currentRecordMetadata environment managed.Primary
            let actualSize, mode =
                match metadata with
                | None -> 0L, 0
                | Some value -> value.SizeBytes, value.Mode
            let active = status.UnitActive && activePaths.Contains(actualPath environment managed.Primary.Path)
            let inSync =
                managed.Primary.Path = desiredPath
                && managed.Primary.UnitName = desiredUnitName
                && not (fstabClaimsPath environment managed.Primary.Path)
                && managed.Primary.SizeBytes = desiredSize
                && metadata.IsSome
                && actualSize = desiredSize
                && mode = 0o600
                && stateMode = 0o600
                && managed.Retired.IsEmpty
                && unitFileMatches
                && status.Enabled
                && active
            writeResponse true managed.Primary.Path actualSize mode status.Enabled active inSync :> JsonNode

    let private disableOwnedUnit (environment: HostEnvironment) (digest: string) (record: SwapfileRecord) =
        let expected = unitText digest record.UnitPath
        match readUnitFile environment record.UnitName with
        | Some contents when contents <> expected -> fail "Refusing to disable a pre-existing unowned swapfile systemd unit."
        | _ -> ()
        let status = readUnitStatus environment record.UnitName
        if status.Exists || (readUnitFile environment record.UnitName |> Option.isSome) then
            run environment "systemctl" [ "disable"; "--now"; record.UnitName ] |> ignore

    let private cleanupRetired (environment: HostEnvironment) (digest: string) (state: SwapfileState) =
        if state.Retired.IsEmpty then
            state
        else
            if state.Retired |> List.exists (fun record -> fstabClaimsPath environment record.Path) then
                fail "Refusing to remove a retired swapfile path claimed by /etc/fstab."
            let primaryStatus = readUnitStatus environment state.Primary.UnitName
            let activePaths = readActivePaths environment
            let primaryActive =
                primaryStatus.Enabled
                && primaryStatus.UnitActive
                && activePaths.Contains(actualPath environment state.Primary.Path)
            if not primaryActive then
                state
            else
                let mutable remaining = state.Retired
                for record in state.Retired do
                    if record.UnitName <> state.Primary.UnitName then
                        disableOwnedUnit environment digest record
                        if readUnitFile environment record.UnitName |> Option.isSome then
                            removeUnitFile environment record.UnitName (unitText digest record.UnitPath)
                            run environment "systemctl" [ "daemon-reload" ] |> ignore
                    removeOwnedFile environment record
                    remaining <- remaining |> List.filter (fun candidate -> not (candidate.Path = record.Path && sameIdentity candidate.Identity record.Identity))
                    writeState environment digest { state with Retired = remaining }
                { state with Retired = remaining }

    let private restoreOldActivation
        (environment: HostEnvironment)
        (oldRecord: SwapfileRecord option)
        (oldUnitText: string option)
        (wasEnabled: bool)
        (wasActive: bool)
        =
        match oldRecord with
        | None -> ()
        | Some record ->
            try
                let current = readUnitFile environment record.UnitName
                match oldUnitText, current with
                | Some expected, Some existing when existing = expected -> ()
                | Some expected, None -> HostFiles.atomicWrite (unitPath environment record.UnitName) (strictUtf8.GetBytes expected) unitMode
                | _ -> ()
                run environment "systemctl" [ "daemon-reload" ] |> ignore
                if wasEnabled then run environment "systemctl" [ "enable"; record.UnitName ] |> ignore
                else run environment "systemctl" [ "disable"; record.UnitName ] |> ignore
                if wasActive then run environment "systemctl" [ "start"; record.UnitName ] |> ignore
                else run environment "systemctl" [ "stop"; record.UnitName ] |> ignore
            with _ -> ()

    let private rollbackApply
        (environment: HostEnvironment)
        (oldRecord: SwapfileRecord option)
        (oldUnitText: string option)
        (desiredUnitName: string)
        (desiredUnitText: string)
        (wasEnabled: bool)
        (wasActive: bool)
        (createdRecord: SwapfileRecord)
        =
        try run environment "systemctl" [ "disable"; "--now"; desiredUnitName ] |> ignore with _ -> ()
        try removeOwnedFile environment createdRecord with _ -> ()
        match oldRecord with
        | Some old when old.UnitName = desiredUnitName -> restoreOldActivation environment (Some old) oldUnitText wasEnabled wasActive
        | _ ->
            try
                removeUnitFile environment desiredUnitName desiredUnitText
                run environment "systemctl" [ "daemon-reload" ] |> ignore
            with _ -> ()

    let private resizeOwnedSwapfile (environment: HostEnvironment) (record: SwapfileRecord) (sizeBytes: int64) =
        let handle, _ = openOwnedFile environment record
        use handle = handle
        let descriptor = handle.DangerousGetHandle().ToInt32()
        let path = actualPath environment record.Path
        if recordIsActive environment record then fail "Refusing to resize an active swapfile."
        if nativeFtruncate(descriptor, sizeBytes) <> 0 then
            let code = Marshal.GetLastPInvokeError()
            raise (IOException("Could not set exact swapfile length.", System.ComponentModel.Win32Exception(code)))
        run environment "fallocate" [ "-l"; sizeBytes.ToString(CultureInfo.InvariantCulture); "--"; path ] |> ignore
        run environment "mkswap" [ "--"; path ] |> ignore
        if nativeFchmod(descriptor, 0o600) <> 0 then
            let code = Marshal.GetLastPInvokeError()
            raise (IOException("Could not set swapfile mode to 0600.", System.ComponentModel.Win32Exception(code)))
        if nativeFsync descriptor <> 0 then
            let code = Marshal.GetLastPInvokeError()
            raise (IOException("Could not synchronize the resized swapfile.", System.ComponentModel.Win32Exception(code)))
        let metadata = inspectDescriptor descriptor
        if not (sameIdentity metadata.Identity record.Identity) || metadata.SizeBytes <> sizeBytes || metadata.Mode <> 0o600 then
            fail "The resized swapfile has unexpected filesystem metadata."
        { record with SizeBytes = sizeBytes }

    let private verifyActive (environment: HostEnvironment) (record: SwapfileRecord) =
        let status = readUnitStatus environment record.UnitName
        let activePaths = readActivePaths environment
        status.Enabled && status.UnitActive && activePaths.Contains(actualPath environment record.Path)

    let private apply (environment: HostEnvironment) (ownerId: string) (digest: string) (desiredPath: string) (desiredSize: int64) (desiredUnitName: string) =
        let stateOption, stateMode = loadState environment ownerId digest false
        if fstabClaimsPath environment desiredPath then
            fail "Refusing to manage a swapfile path already claimed by /etc/fstab."
        stateOption
        |> Option.iter (fun existing ->
            for record in existing.Primary :: existing.Retired do
                if fstabClaimsPath environment record.Path then
                    fail "Refusing to manage a swapfile path already claimed by /etc/fstab.")
        let stateOption =
            match stateOption with
            | Some existing when existing.Primary.Path <> desiredPath ->
                match existing.Retired |> List.tryFind (fun record -> record.Path = desiredPath) with
                | Some retired ->
                    let promote () =
                        let remaining =
                            existing.Retired
                            |> List.filter (fun record -> record.Path <> retired.Path || not (sameIdentity record.Identity retired.Identity))
                        Some { existing with Primary = retired; Retired = existing.Primary :: remaining }
                    match inspectManagedPath environment retired.Path with
                    | Some metadata when sameIdentity metadata.Identity retired.Identity -> promote ()
                    | None -> promote ()
                    | Some _ -> fail "A retired swapfile path no longer has its recorded file identity."
                | None -> Some existing
            | _ -> stateOption
        if fstabClaimsPath environment desiredPath then
            fail "Refusing to manage a swapfile path already claimed by /etc/fstab."
        stateOption
        |> Option.iter (fun existing ->
            for record in existing.Primary :: existing.Retired do
                if fstabClaimsPath environment record.Path then
                    fail "Refusing to manage a swapfile path already claimed by /etc/fstab.")
        let initialRecord = stateOption |> Option.map (fun state -> state.Primary)
        let initialUnitText = initialRecord |> Option.bind (fun record -> readUnitFile environment record.UnitName)
        match stateOption, initialUnitText with
        | Some managed, Some contents when contents <> unitText digest managed.Primary.UnitPath ->
            fail "Refusing to replace a pre-existing unowned swapfile systemd unit."
        | _ -> ()
        let state =
            match stateOption with
            | Some managed -> cleanupRetired environment digest managed
            | None -> { OwnerId = ownerId; Primary = Unchecked.defaultof<SwapfileRecord>; Retired = [] }
        let managedState = stateOption |> Option.map (fun _ -> state)
        let oldRecord = managedState |> Option.map (fun managed -> managed.Primary)
        let oldUnitText = oldRecord |> Option.bind (fun record -> readUnitFile environment record.UnitName)
        let oldStatus = oldRecord |> Option.map (fun record -> readUnitStatus environment record.UnitName)
        let activePaths = readActivePaths environment
        let wasEnabled = oldStatus |> Option.exists (fun status -> status.Enabled)
        let oldMetadata = oldRecord |> Option.bind (currentRecordMetadata environment)
        let wasActive = oldRecord |> Option.exists (fun record -> oldMetadata.IsSome && activePaths.Contains(actualPath environment record.Path))
        let samePath = oldRecord |> Option.exists (fun record -> record.Path = desiredPath)
        let targetMetadata = inspectManagedPath environment desiredPath
        match oldRecord, samePath, targetMetadata with
        | Some record, true, Some metadata when not (sameIdentity record.Identity metadata.Identity) ->
            fail "The configured swapfile path no longer has its recorded file identity."
        | Some _, false, Some _ -> fail ("Refusing to overwrite pre-existing swapfile path '" + desiredPath + "'.")
        | None, _, Some _ -> fail ("Refusing to overwrite pre-existing swapfile path '" + desiredPath + "'.")
        | _ -> ()
        let oldPathListedActive = oldRecord |> Option.exists (fun record -> activePaths.Contains(actualPath environment record.Path))
        if samePath && oldRecord.IsSome && oldMetadata.IsNone && ((oldStatus |> Option.exists (fun status -> status.UnitActive)) || oldPathListedActive) then
            fail "The recorded swapfile is missing while its systemd unit or swap is active; refusing to replace the active resource."

        let desiredUnitContents = readUnitFile environment desiredUnitName
        let desiredUnitStatus = readUnitStatus environment desiredUnitName
        let desiredUnitRecorded = oldRecord |> Option.exists (fun record -> record.UnitName = desiredUnitName)
        let desiredUnitOwned =
            match oldRecord with
            | Some record when record.UnitName = desiredUnitName -> desiredUnitContents = Some(unitText digest record.UnitPath)
            | _ -> false
        if desiredUnitContents.IsSome && not desiredUnitOwned then
            fail "Refusing to replace a pre-existing path-based swapfile systemd unit."
        if desiredUnitContents.IsNone && desiredUnitStatus.Exists && not desiredUnitRecorded then
            fail "Refusing to use a pre-existing path-based swapfile systemd unit."
        if fstabClaimsPath environment desiredPath then
            fail "Refusing to manage a swapfile path already claimed by /etc/fstab."
        oldRecord
        |> Option.iter (fun record ->
            if fstabClaimsPath environment record.Path then
                fail "Refusing to change a swapfile path claimed by /etc/fstab.")
        ensureDirectory environment StateDirectory true directoryMode |> ignore

        let needsStorageRepair =
            match oldRecord, oldMetadata with
            | Some record, Some metadata when samePath && metadata.SizeBytes = desiredSize && record.SizeBytes = desiredSize -> false
            | _ -> true

        if not needsStorageRepair then
            let record = oldRecord.Value
            let status = oldStatus.Value
            let active = status.UnitActive && activePaths.Contains(actualPath environment desiredPath)
            let alreadyInSync =
                stateMode = 0o600
                && record.SizeBytes = desiredSize
                && oldMetadata.Value.Mode = 0o600
                && record.UnitName = desiredUnitName
                && desiredUnitContents = Some(unitText digest desiredPath)
                && status.Enabled
                && active
                && state.Retired.IsEmpty
            if alreadyInSync then snapshot environment ownerId digest desiredPath desiredSize desiredUnitName
            else
                repairMode environment record
                if desiredUnitContents.IsNone then
                    writeUnitFile environment desiredUnitName None (unitText digest desiredPath)
                    run environment "systemctl" [ "daemon-reload" ] |> ignore
                if status.UnitActive && not (activePaths.Contains(actualPath environment desiredPath)) then
                    run environment "systemctl" [ "enable"; desiredUnitName ] |> ignore
                    run environment "systemctl" [ "restart"; desiredUnitName ] |> ignore
                else
                    run environment "systemctl" [ "enable"; "--now"; desiredUnitName ] |> ignore
                let repairedRecord = { record with SizeBytes = desiredSize }
                if not (verifyActive environment repairedRecord) then fail "Swapfile apply did not reach the requested active state."
                let repairedState = { state with Primary = repairedRecord }
                if stateMode <> 0o600 then writeState environment digest repairedState
                let clean = cleanupRetired environment digest repairedState
                if not clean.Retired.IsEmpty then fail "An old owned swapfile could not be safely removed."
                let verified = snapshot environment ownerId digest desiredPath desiredSize desiredUnitName
                if not (verified["inSync"].GetValue<bool>()) then fail "Swapfile apply did not reach the requested active state."
                verified
        else
            match oldRecord, oldMetadata, samePath with
            | Some record, Some _, true ->
                let unitIsActive = oldStatus |> Option.exists (fun status -> status.UnitActive)
                if unitIsActive then run environment "systemctl" [ "stop"; desiredUnitName ] |> ignore
                if pathIsActive environment desiredPath then
                    run environment "swapoff" [ "--"; actualPath environment desiredPath ] |> ignore
                if pathIsActive environment desiredPath then fail "The old swapfile remained active during resize."

                let restoreOldSize () =
                    let status = readUnitStatus environment desiredUnitName
                    if status.UnitActive then run environment "systemctl" [ "stop"; desiredUnitName ] |> ignore
                    if pathIsActive environment desiredPath then
                        run environment "swapoff" [ "--"; actualPath environment desiredPath ] |> ignore
                    if pathIsActive environment desiredPath then fail "The swapfile remained active during resize rollback."
                    let restored = resizeOwnedSwapfile environment record record.SizeBytes
                    writeState environment digest { state with Primary = restored }
                    if desiredUnitContents.IsNone then
                        writeUnitFile environment desiredUnitName None (unitText digest desiredPath)
                        run environment "systemctl" [ "daemon-reload" ] |> ignore
                    run environment "systemctl" [ "enable"; "--now"; desiredUnitName ] |> ignore
                    if not (verifyActive environment restored) then fail "Could not restore the previous active swapfile after resize failure."

                try
                    let resized = resizeOwnedSwapfile environment record desiredSize
                    let resizedState = { state with Primary = resized }
                    writeState environment digest resizedState
                    if desiredUnitContents.IsNone then
                        writeUnitFile environment desiredUnitName None (unitText digest desiredPath)
                        run environment "systemctl" [ "daemon-reload" ] |> ignore
                    run environment "systemctl" [ "enable"; "--now"; desiredUnitName ] |> ignore
                    if not (verifyActive environment resized) then fail "Swapfile resize did not reach the requested active state."
                    let clean = cleanupRetired environment digest resizedState
                    if not clean.Retired.IsEmpty then fail "An old owned swapfile could not be safely removed."
                    let verified = snapshot environment ownerId digest desiredPath desiredSize desiredUnitName
                    if not (verified["inSync"].GetValue<bool>()) then fail "Swapfile resize did not reach the requested active state."
                    verified
                with _ ->
                    try restoreOldSize () with _ -> ()
                    reraise ()
            | _ ->
                let mutable committed = false
                let mutable preparedRecord: SwapfileRecord option = None
                try
                    let createdRecord, updated =
                        createSwapfile environment desiredPath desiredPath desiredUnitName desiredSize (fun primary ->
                            preparedRecord <- Some primary
                            let retired =
                                state.Retired
                                @ (oldRecord |> Option.filter (fun old -> not samePath) |> Option.toList)
                                |> List.distinctBy (fun record -> record.Path, record.Identity)
                            let updated = { OwnerId = ownerId; Primary = primary; Retired = retired }
                            writeState environment digest updated
                            committed <- true
                            updated)
                    let metadata = inspectManagedPath environment desiredPath
                    let primary =
                        match metadata with
                        | Some value when value.Identity = createdRecord.Identity && value.SizeBytes = desiredSize && value.Mode = 0o600 -> createdRecord
                        | _ -> fail "The created swapfile has unexpected filesystem metadata."
                    if desiredUnitContents.IsNone then
                        writeUnitFile environment desiredUnitName None (unitText digest desiredPath)
                        run environment "systemctl" [ "daemon-reload" ] |> ignore
                    run environment "systemctl" [ "enable"; "--now"; desiredUnitName ] |> ignore
                    if not (verifyActive environment primary) then
                        fail "Swapfile activation did not match the requested path and persistence state."
                    let clean = cleanupRetired environment digest updated
                    if not clean.Retired.IsEmpty then fail "An old owned swapfile could not be safely removed."
                    let verified = snapshot environment ownerId digest desiredPath desiredSize desiredUnitName
                    if not (verified["inSync"].GetValue<bool>()) then
                        fail "Swapfile apply did not reach the requested active state."
                    verified
                with _ ->
                    let stateWasCommitted =
                        try
                            let current, _ = loadState environment ownerId digest false
                            current
                            |> Option.exists (fun saved ->
                                preparedRecord
                                |> Option.exists (fun primary ->
                                    saved.Primary.Path = desiredPath
                                    && saved.Primary.SizeBytes = desiredSize
                                    && sameIdentity saved.Primary.Identity primary.Identity))
                        with _ -> false
                    if committed || stateWasCommitted then reraise ()
                    match preparedRecord with
                    | Some createdRecord ->
                        rollbackApply
                            environment
                            oldRecord
                            oldUnitText
                            desiredUnitName
                            (unitText digest desiredPath)
                            wasEnabled
                            wasActive
                            createdRecord
                    | None -> ()
                    reraise ()
    let private readStateOwner (environment: HostEnvironment) (path: string) =
        match safeReadRegularFile environment path with
        | None -> None
        | Some (text, metadata) ->
            use document = JsonDocument.Parse(text)
            let root = document.RootElement
            jsonObjectProperties root (set [ "version"; "ownerId"; "primary"; "retired" ])
            let owner = root.GetProperty("ownerId")
            if owner.ValueKind <> JsonValueKind.String then fail "The swapfile state is malformed."
            Some(owner.GetString(), metadata)

    let private delete (environment: HostEnvironment) (ownerId: string) (digest: string) (desiredUnitName: string) =
        let stateOption, _ = loadState environment ownerId digest false
        match stateOption with
        | None ->
            if readUnitFile environment desiredUnitName |> Option.isSome then
                fail "Refusing to delete a path-based swapfile unit without matching owner state."
            JsonObject() :> JsonNode
        | Some state ->
            let allRecords = state.Primary :: state.Retired
            for record in allRecords do
                if fstabClaimsPath environment record.Path then
                    fail "Refusing to delete a swapfile path claimed by /etc/fstab."
            let uniqueUnits = allRecords |> List.map (fun record -> record.UnitName) |> List.distinct
            for record in allRecords do
                match currentRecordMetadata environment record with
                | None -> ()
                | Some _ -> ()
            for name in uniqueUnits do
                let unitRecord = allRecords |> List.find (fun record -> record.UnitName = name)
                let expectedPath = if name = state.Primary.UnitName then state.Primary.UnitPath else unitRecord.UnitPath
                match readUnitFile environment name with
                | Some contents when contents <> unitText digest expectedPath ->
                    fail "Refusing to disable or remove a pre-existing unowned swapfile systemd unit."
                | _ -> ()
            try
                for name in uniqueUnits do
                    let status = readUnitStatus environment name
                    if status.Exists || readUnitFile environment name |> Option.isSome then
                        run environment "systemctl" [ "disable"; "--now"; name ] |> ignore
                for record in allRecords do
                    if recordIsActive environment record then run environment "swapoff" [ "--"; actualPath environment record.Path ] |> ignore
                    if recordIsActive environment record then fail ("Owned swapfile remains active and will not be removed: '" + record.Path + "'.")
                for record in allRecords do removeOwnedFile environment record
                for name in uniqueUnits do
                    let unitRecord = allRecords |> List.find (fun record -> record.UnitName = name)
                    let expectedPath = if name = state.Primary.UnitName then state.Primary.UnitPath else unitRecord.UnitPath
                    removeUnitFile environment name (unitText digest expectedPath)
                run environment "systemctl" [ "daemon-reload" ] |> ignore
                let path = statePath environment digest
                match readStateOwner environment path with
                | None -> ()
                | Some (storedOwner, oldMetadata) when storedOwner = ownerId ->
                    match inspectNoFollow path with
                    | Some current when current.FileType = 0x8000 && sameIdentity current.Identity oldMetadata.Identity -> File.Delete path
                    | None -> ()
                    | _ -> fail "The swapfile state file changed before removal."
                | Some _ -> fail "Refusing to remove a swapfile state file that is no longer owned."
                JsonObject() :> JsonNode
            with error ->
                try
                    let primary = state.Primary
                    if readUnitFile environment primary.UnitName |> Option.exists ((=) (unitText digest primary.UnitPath)) then
                        run environment "systemctl" [ "enable"; primary.UnitName ] |> ignore
                        run environment "systemctl" [ "start"; primary.UnitName ] |> ignore
                with _ -> ()
                raise error

    let handle (environment: HostEnvironment) (request: JsonElement) : JsonNode =
        if not (OperatingSystem.IsLinux()) then raise (PlatformNotSupportedException("Swapfile management requires Linux."))
        requireProductionRoot environment
        let operation, ownerId, digest, path, sizeBytes = parseRequest request
        let desiredUnitName = pathUnitName environment path
        match operation with
        | "read" -> snapshot environment ownerId digest path sizeBytes desiredUnitName
        | "apply" -> apply environment ownerId digest path sizeBytes desiredUnitName
        | "delete" -> delete environment ownerId digest desiredUnitName
        | _ -> fail "Unsupported swapfile operation."
