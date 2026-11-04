namespace Dorothy.HostHelper

open System
open System.Collections.Generic
open System.ComponentModel
open System.Globalization
open System.IO
open System.Net
open System.Runtime.InteropServices
open System.Security.Cryptography
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open System.Text.RegularExpressions
open Microsoft.Win32.SafeHandles

module Sshd =
    type BackendError(message: string) =
        inherit InvalidOperationException(message)

    [<Struct; StructLayout(LayoutKind.Sequential, Size = 256)>]
    type private LinuxStatx =
        val mutable Mask: uint32
        val mutable BlockSize: uint32
        val mutable Attributes: uint64
        val mutable LinkCount: uint32
        val mutable UserId: uint32
        val mutable GroupId: uint32
        val mutable Mode: uint16

    [<DllImport("libc", EntryPoint = "statx", SetLastError = true)>]
    extern int private nativeStatx (int directoryFileDescriptor, string path, int flags, uint32 mask, LinuxStatx& result)

    [<DllImport("libc", EntryPoint = "open", SetLastError = true)>]
    extern int private nativeOpen (string path, int flags, int mode)

    [<DllImport("libc", EntryPoint = "fsync", SetLastError = true)>]
    extern int private nativeFsync (int fileDescriptor)

    [<DllImport("libc", EntryPoint = "close", SetLastError = true)>]
    extern int private nativeClose (int fileDescriptor)

    [<DllImport("libc", EntryPoint = "geteuid")>]
    extern uint32 private nativeGetEffectiveUserId ()

    type private FileMetadata =
        { Kind: uint16
          Mode: int
          UserId: uint32
          GroupId: uint32 }

    type private ConnectionContext =
        { User: string option
          Host: string option
          Address: string option
          LocalAddress: string option
          LocalPort: int option }

    type private Request =
        { Operation: string
          OwnerId: string
          OwnerDigest: string
          Settings: Map<string, string>
          TransactionToken: string option
          Context: ConnectionContext }

    type private OwnerState =
        { OwnerDigest: string
          Settings: Map<string, string> }

    type private Transaction =
        { OwnerId: string
          OwnerDigest: string
          Action: string
          Token: string
          Status: string
          OldConfig: byte[] option
          NewConfig: byte[] option
          OldState: byte[] option
          NewState: byte[] option
          HelperPath: string
          Context: ConnectionContext
          BaselineSettings: Map<string, string>
          BaselineGlobalSettings: Map<string, string>
          BaselinePorts: int list
          BaselineContextPorts: int list
          ReloadCompleted: bool }

    type private ParsedSshdConfiguration =
        { Settings: Map<string, string>
          Ports: int list }

    type private EffectiveConfiguration =
        { Settings: Map<string, string>
          GlobalSettings: Map<string, string>
          Ports: int list
          ContextPorts: int list }

    let private mainConfiguration = "/etc/ssh/sshd_config"
    let private configurationDirectory = "/etc/ssh/sshd_config.d"
    let private configurationPath = configurationDirectory + "/00-dorothy.conf"
    let private stateDirectory = "/var/lib/keroosha-iac/sshd"
    let private ownerStatePath = stateDirectory + "/owner.json"
    let private transactionPath = stateDirectory + "/rollback.json"
    let private rollbackRequestPath = stateDirectory + "/rollback-request.json"
    let private lockDirectory = "/run/keroosha-iac"
    let private lockPath = lockDirectory + "/sshd.lock"
    let private servicePath = "/etc/systemd/system/keroosha-iac-sshd-rollback.service"
    let private timerPath = "/etc/systemd/system/keroosha-iac-sshd-rollback.timer"
    let private rollbackServiceName = "keroosha-iac-sshd-rollback.service"
    let private rollbackTimerName = "keroosha-iac-sshd-rollback.timer"
    let private sshdExecutable = "/usr/sbin/sshd"
    let private supportedSettings =
        [ "PasswordAuthentication"
          "KbdInteractiveAuthentication"
          "PubkeyAuthentication"
          "PermitRootLogin"
          "Port"
          "MaxAuthTries" ]
    let private settingNames = supportedSettings |> Set.ofList
    let private strictUtf8 = UTF8Encoding(false, true)
    let private tokenPattern = Regex("^[0-9a-f]{32}$", RegexOptions.CultureInvariant)
    let private helperPathPattern = Regex("^/var/cache/keroosha-iac/helper/(?:linux-x64|linux-arm64)/([0-9a-f]{64})$", RegexOptions.CultureInvariant)
    let private ownerMarkerPrefix = "# Dorothy sshd owner-sha256="
    let private fileMode = UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.GroupRead ||| UnixFileMode.OtherRead
    let private privateFileMode = UnixFileMode.UserRead ||| UnixFileMode.UserWrite
    let private directoryMode = UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute
    let private statxMask = 0xBu
    let private openReadFlags = 0x800 ||| 0x80000 ||| 0x20000
    let private openDirectoryFlags = 0x10000 ||| 0x80000 ||| 0x20000
    let private atFdcwd = -100
    let private atEmptyPath = 0x1000
    let private atSymlinkNoFollow = 0x100
    let private fileTypeMask = 0xF000us
    let private regularFileType = 0x8000us
    let private directoryFileType = 0x4000us
    let private symlinkFileType = 0xA000us
    let private maxManagedFileBytes = 1024 * 1024
    let private maxTransactionFileBytes = 4 * 1024 * 1024

    let private fail (message: string) = raise (BackendError(message))

    let private productionRoot (environment: HostEnvironment) = Path.GetFullPath(environment.Root) = Path.GetPathRoot(Path.GetFullPath(environment.Root))

    let private requireRoot (environment: HostEnvironment) =
        if productionRoot environment && nativeGetEffectiveUserId() <> 0u then
            fail "The SSHD helper must run as root."

    let private containsControl (value: string) =
        value |> Seq.exists (fun character -> int character < 32 || int character = 127)

    let private sha256 (bytes: byte array) =
        SHA256.HashData(bytes) |> Convert.ToHexString |> fun value -> value.ToLowerInvariant()

    let private ownerDigest (ownerId: string) =
        if String.IsNullOrEmpty ownerId || ownerId.Length > 4096 || containsControl ownerId then
            fail "SSHD ownerId must be a non-empty string of at most 4096 characters without control characters."
        try SHA256.HashData(strictUtf8.GetBytes(ownerId)) |> Convert.ToHexString |> fun value -> value.ToLowerInvariant()
        with :? EncoderFallbackException -> fail "SSHD ownerId is not valid UTF-8."

    let private modeBits (mode: UnixFileMode) = int mode &&& 0o777

    let private metadataAt (path: string) =
        let mutable stat = Unchecked.defaultof<LinuxStatx>
        if nativeStatx(atFdcwd, path, atSymlinkNoFollow, statxMask, &stat) = 0 then
            Some {
                Kind = stat.Mode &&& fileTypeMask
                Mode = int (stat.Mode &&& 0x1FFus)
                UserId = stat.UserId
                GroupId = stat.GroupId
            }
        else
            let errorCode = Marshal.GetLastWin32Error()
            if errorCode = 2 || errorCode = 20 then None
            else raise (Win32Exception(errorCode, "Could not safely inspect SSHD path."))

    let private metadataForDescriptor descriptor =
        let mutable stat = Unchecked.defaultof<LinuxStatx>
        if nativeStatx(descriptor, "", atEmptyPath, statxMask, &stat) <> 0 then
            let errorCode = Marshal.GetLastWin32Error()
            raise (Win32Exception(errorCode, "Could not safely inspect an opened SSHD file."))
        { Kind = stat.Mode &&& fileTypeMask
          Mode = int (stat.Mode &&& 0x1FFus)
          UserId = stat.UserId
          GroupId = stat.GroupId }

    let private requireRootOwned (environment: HostEnvironment) (metadata: FileMetadata) description =
        if productionRoot environment && metadata.UserId <> 0u then
            fail (description + " must be root-owned.")

    let private checkMetadata (environment: HostEnvironment) (path: string) expectedKind description =
        let actualPath = HostEnvironment.path environment path
        match metadataAt actualPath with
        | None -> None
        | Some metadata ->
            if metadata.Kind = symlinkFileType then fail (description + " must not be a symbolic link.")
            if metadata.Kind <> expectedKind then fail (description + " has an unexpected filesystem type.")
            requireRootOwned environment metadata description
            Some metadata

    let private ensureSafeDirectoryChain (environment: HostEnvironment) (logicalPath: string) (create: bool) =
        let rootPath = HostEnvironment.path environment "/"
        let target = HostEnvironment.path environment logicalPath
        let relative = Path.GetRelativePath(rootPath, target)
        if relative = ".." || relative.StartsWith(".." + string Path.DirectorySeparatorChar, StringComparison.Ordinal) then
            fail "An SSHD managed path escapes the host root."
        let checkOne path description =
            match metadataAt path with
            | None -> fail (description + " is unavailable.")
            | Some metadata ->
                if metadata.Kind <> directoryFileType then fail (description + " must be a real directory.")
                requireRootOwned environment metadata description
                if productionRoot environment && (metadata.Mode &&& 0o022) <> 0 then
                    fail (description + " must not be group- or world-writable.")
        checkOne rootPath "host root directory"
        if relative <> "." then
            let segments = relative.Split([| Path.DirectorySeparatorChar; Path.AltDirectorySeparatorChar |], StringSplitOptions.RemoveEmptyEntries)
            let mutable current = rootPath
            for index = 0 to segments.Length - 1 do
                current <- Path.Combine(current, segments[index])
                match metadataAt current with
                | Some metadata ->
                    if metadata.Kind <> directoryFileType then fail "An SSHD managed path contains a non-directory or symbolic-link parent."
                    requireRootOwned environment metadata "SSHD managed parent directory"
                    if productionRoot environment && (metadata.Mode &&& 0o022) <> 0 then
                        fail "An SSHD managed parent directory is group- or world-writable."
                | None when create ->
                    try
                        Directory.CreateDirectory(current) |> ignore
                        File.SetUnixFileMode(current, directoryMode)
                    with error -> fail ("Could not create the SSHD state directory: " + error.Message)
                    match metadataAt current with
                    | Some metadata when metadata.Kind = directoryFileType -> requireRootOwned environment metadata "SSHD managed directory"
                    | _ -> fail "The SSHD managed directory could not be created safely."
                | None -> fail "An SSHD managed parent directory is unavailable."
        if relative <> "." then
            match metadataAt target with
            | Some metadata when metadata.Kind = directoryFileType ->
                requireRootOwned environment metadata "SSHD managed directory"
                if productionRoot environment && logicalPath = stateDirectory && metadata.Mode <> modeBits directoryMode then
                    fail "The SSHD transaction directory must have mode 0700."
                if productionRoot environment && logicalPath = lockDirectory && metadata.Mode <> modeBits directoryMode then
                    fail "The SSHD runtime lock directory must have mode 0700."
            | Some _ -> fail "An SSHD managed path is not a real directory."
            | None -> fail "An SSHD managed directory is unavailable."
    let private safeDirectoryChainExists (environment: HostEnvironment) (logicalPath: string) =
        let rec inspect current =
            let actualPath = HostEnvironment.path environment current
            match metadataAt actualPath with
            | Some _ ->
                ensureSafeDirectoryChain environment current false
                current = logicalPath
            | None ->
                if current = "/" then false
                else
                    let parent = Path.GetDirectoryName current
                    if String.IsNullOrEmpty parent then false else inspect parent
        inspect logicalPath


    let private readDescriptorBytes (descriptor: int) (limit: int) =
        let handle = new SafeFileHandle(nativeint descriptor, false)
        use input = new FileStream(handle, FileAccess.Read, 65536, false)
        use output = new MemoryStream()
        let buffer = Array.zeroCreate<byte> 65536
        let mutable finished = false
        while not finished do
            let count = input.Read(buffer, 0, buffer.Length)
            if count = 0 then finished <- true
            else
                if output.Length + int64 count > int64 limit then fail "An SSHD managed file is too large."
                output.Write(buffer, 0, count)
        output.ToArray()

    let private safeReadFile (environment: HostEnvironment) (logicalPath: string) (limit: int) (description: string) : byte[] option =
        let path = HostEnvironment.path environment logicalPath
        let parent = Path.GetDirectoryName logicalPath
        if String.IsNullOrEmpty parent || not (safeDirectoryChainExists environment parent) then None
        else
            match checkMetadata environment logicalPath regularFileType description with
            | None -> None
            | Some initial ->
                if productionRoot environment && (initial.Mode &&& 0o022) <> 0 then
                    fail (description + " must not be group- or world-writable.")
                let descriptor = nativeOpen(path, openReadFlags, 0)
                if descriptor < 0 then
                    let errorCode = Marshal.GetLastWin32Error()
                    raise (Win32Exception(errorCode, "Could not safely open an SSHD managed file."))
                try
                    let opened = metadataForDescriptor descriptor
                    if opened.Kind <> regularFileType || opened.UserId <> initial.UserId then
                        fail (description + " changed while it was being opened.")
                    requireRootOwned environment opened description
                    Some(readDescriptorBytes descriptor limit)
                finally
                    nativeClose descriptor |> ignore

    let private syncDirectory (path: string) =
        let descriptor = nativeOpen(path, openDirectoryFlags, 0)
        if descriptor < 0 then
            let errorCode = Marshal.GetLastWin32Error()
            raise (Win32Exception(errorCode, "Could not open an SSHD directory for synchronization."))
        try
            if nativeFsync descriptor <> 0 then
                let errorCode = Marshal.GetLastWin32Error()
                raise (Win32Exception(errorCode, "Could not synchronize an SSHD directory."))
        finally nativeClose descriptor |> ignore

    let private writeFile (environment: HostEnvironment) (logicalPath: string) (bytes: byte array) (mode: UnixFileMode) (description: string) =
        let path = HostEnvironment.path environment logicalPath
        ensureSafeDirectoryChain environment (Path.GetDirectoryName logicalPath) false
        checkMetadata environment logicalPath regularFileType description |> ignore
        try HostFiles.atomicWrite path bytes mode
        with error -> fail ("Could not atomically write " + description + ": " + error.Message)
        let metadata = checkMetadata environment logicalPath regularFileType description |> Option.defaultWith (fun () -> fail (description + " disappeared after writing."))
        if productionRoot environment && metadata.Mode <> modeBits mode then
            fail (description + " has unexpected permissions after writing.")

    let private deleteFile (environment: HostEnvironment) (logicalPath: string) description =
        let path = HostEnvironment.path environment logicalPath
        match safeReadFile environment logicalPath maxManagedFileBytes description with
        | None -> false
        | Some _ ->
            try
                File.Delete(path)
                syncDirectory(Path.GetDirectoryName(path))
                true
            with error -> fail ("Could not safely remove " + description + ": " + error.Message)

    let private withLock (environment: HostEnvironment) operation =
        requireRoot environment
        ensureSafeDirectoryChain environment lockDirectory true
        let actualLockPath = HostEnvironment.path environment lockPath
        try
            use held = HostFiles.lockFile actualLockPath
            match checkMetadata environment lockPath regularFileType "SSHD serialization lock" with
            | Some metadata when productionRoot environment && metadata.Mode <> 0o600 -> fail "SSHD serialization lock has insecure permissions."
            | None -> fail "SSHD serialization lock disappeared."
            | _ -> operation ()
        with
        | :? BackendError -> reraise ()
        | :? TimeoutException -> fail "Timed out waiting for the SSHD serialization lock."
        | error -> fail ("Could not acquire the SSHD serialization lock: " + error.Message)

    let private commandDiagnostic (result: CommandResult) =
        let text = if String.IsNullOrWhiteSpace result.Stderr then result.Stdout.Trim() else result.Stderr.Trim()
        text
        |> Seq.map (fun character -> if Char.IsControl character then ' ' else character)
        |> Array.ofSeq
        |> fun characters -> String(characters)

    let private runRaw (environment: HostEnvironment) executable arguments =
        try environment.Run executable arguments None
        with error -> fail ("Could not execute SSHD host command " + executable + ": " + error.Message)

    let private runOk (environment: HostEnvironment) executable arguments description =
        let result = runRaw environment executable arguments
        if result.ExitCode <> 0 then
            let diagnostic = commandDiagnostic result
            if String.IsNullOrWhiteSpace diagnostic then fail (description + " failed.")
            fail (description + " failed: " + diagnostic)
        result.Stdout

    let private statusCommand (environment: HostEnvironment) arguments acceptedCodes description =
        let result = runRaw environment "/usr/bin/systemctl" arguments
        if not (Set.contains result.ExitCode acceptedCodes) then
            let diagnostic = commandDiagnostic result
            if String.IsNullOrWhiteSpace diagnostic then fail (description + " could not be determined.")
            fail (description + " could not be determined: " + diagnostic)
        result

    let private validateSocketMode (environment: HostEnvironment) =
        let active = statusCommand environment [ "is-active"; "ssh.socket" ] (set [ 0; 3; 4 ]) "SSH socket activation state"
        if active.ExitCode = 0 then fail "OpenSSH socket activation is not supported by the SSHD helper."
        let enabled = statusCommand environment [ "is-enabled"; "ssh.socket" ] (set [ 0; 1; 4 ]) "SSH socket activation state"
        if enabled.ExitCode = 0 then fail "OpenSSH socket activation is not supported by the SSHD helper."

    let private requireSshServiceActive (environment: HostEnvironment) =
        let result = statusCommand environment [ "is-active"; "ssh.service" ] (set [ 0; 3; 4 ]) "OpenSSH service state"
        if result.ExitCode <> 0 || result.Stdout.Trim() <> "active" then
            fail "The Debian ssh.service must be active to manage SSHD configuration."

    let private reloadSshService (environment: HostEnvironment) =
        validateSocketMode environment
        requireSshServiceActive environment
        runOk environment "/usr/bin/systemctl" [ "reload"; "ssh.service" ] "Reloading ssh.service" |> ignore
        requireSshServiceActive environment

    let private restoreSshService (environment: HostEnvironment) =
        validateSocketMode environment
        let state = statusCommand environment [ "is-active"; "ssh.service" ] (set [ 0; 3; 4 ]) "OpenSSH service state"
        if state.ExitCode = 0 && state.Stdout.Trim() = "active" then
            runOk environment "/usr/bin/systemctl" [ "reload"; "ssh.service" ] "Reloading restored ssh.service configuration" |> ignore
        else
            runOk environment "/usr/bin/systemctl" [ "start"; "ssh.service" ] "Starting restored ssh.service configuration" |> ignore
        requireSshServiceActive environment

    let private jsonProperties (element: JsonElement) description =
        if element.ValueKind <> JsonValueKind.Object then fail (description + " must be an object.")
        let properties = element.EnumerateObject() |> Seq.toArray
        let names = properties |> Array.map (fun property -> property.Name)
        if names.Length <> (names |> Set.ofArray |> Set.count) then fail (description + " must not contain duplicate properties.")
        properties

    let private readString (element: JsonElement) description =
        if element.ValueKind <> JsonValueKind.String then fail (description + " must be a string.")
        match element.GetString() with
        | null -> fail (description + " must not be null.")
        | value -> value

    let private validateSetting name value =
        if not (Set.contains name settingNames) then fail ("Unsupported SSHD setting '" + name + "'.")
        if String.IsNullOrEmpty value || containsControl value then fail ("SSHD setting '" + name + "' has an invalid value.")
        let valid =
            match name with
            | "PasswordAuthentication"
            | "KbdInteractiveAuthentication"
            | "PubkeyAuthentication" -> value = "yes" || value = "no"
            | "PermitRootLogin" -> Set.contains value (set [ "yes"; "no"; "prohibit-password"; "forced-commands-only" ])
            | "Port" ->
                let mutable parsed = 0
                Int32.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, &parsed)
                && parsed >= 1 && parsed <= 65535
                && parsed.ToString(CultureInfo.InvariantCulture) = value
            | "MaxAuthTries" ->
                let mutable parsed = 0
                Int32.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, &parsed)
                && parsed > 0
                && parsed.ToString(CultureInfo.InvariantCulture) = value
            | _ -> false
        if not valid then fail ("SSHD setting '" + name + "' has an invalid canonical value.")

    let private validateObservedSetting (name: string) (value: string) =
        if name = "MaxAuthTries" then
            let mutable parsed = 0
            if String.IsNullOrEmpty value
               || containsControl value
               || not (Int32.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, &parsed))
               || parsed < 0
               || parsed.ToString(CultureInfo.InvariantCulture) <> value then
                fail "sshd -T returned an invalid MaxAuthTries value."
        elif name = "Port" then
            let values = value.Split([| ',' |], StringSplitOptions.None)
            let parsed =
                values
                |> Array.map (fun portText ->
                    let mutable port = 0
                    if not (Int32.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, &port))
                       || port < 1
                       || port > 65535
                       || port.ToString(CultureInfo.InvariantCulture) <> portText then
                        fail "sshd -T returned an invalid Port list."
                    port)
            if parsed.Length = 0 || parsed.Length <> (parsed |> Set.ofArray |> Set.count) || parsed <> Array.sort parsed then
                fail "sshd -T returned a non-canonical Port list."
        else
            validateSetting name value


    let private parseSettings (element: JsonElement) =
        let properties = jsonProperties element "SSHD settings"
        properties
        |> Array.map (fun property ->
            if property.Value.ValueKind <> JsonValueKind.String then fail ("SSHD setting '" + property.Name + "' must be a string.")
            let value = readString property.Value ("SSHD setting '" + property.Name + "'")
            validateSetting property.Name value
            property.Name, value)
        |> Map.ofArray

    let private parseObservedSettings (element: JsonElement) =
        let properties = jsonProperties element "SSHD effective settings"
        properties
        |> Array.map (fun property ->
            if not (Set.contains property.Name settingNames) then fail ("SSHD effective setting '" + property.Name + "' is unsupported.")
            let value = readString property.Value ("SSHD effective setting '" + property.Name + "'")
            validateObservedSetting property.Name value
            property.Name, value)
        |> Map.ofArray

    let private safeContextValue (description: string) (value: string) =
        if String.IsNullOrWhiteSpace value || value.Length > 255 || containsControl value || value.Contains(',') || value.Contains('=') then
            fail (description + " is invalid for an OpenSSH Match context.")
        value

    let private validateUser value =
        let value = safeContextValue "SSHD connection user" value
        if not (Regex.IsMatch(value, "^[A-Za-z0-9_.-]+$", RegexOptions.CultureInvariant)) then
            fail "SSHD connection user is invalid for an OpenSSH Match context."
        value

    let private validateAddress description value =
        let value = safeContextValue description value
        let mutable address = Unchecked.defaultof<IPAddress>
        if not (IPAddress.TryParse(value, &address)) then fail (description + " must be an IP address.")
        address.ToString()

    let private validateHost value =
        let value = safeContextValue "SSHD connection host" value
        if not (Regex.IsMatch(value, "^[A-Za-z0-9_.:-]+$", RegexOptions.CultureInvariant)) then
            fail "SSHD connection host is invalid for an OpenSSH Match context."
        value

    let private parseContextElement (element: JsonElement) =
        let properties = jsonProperties element "SSHD connectionContext"
        let allowed = set [ "user"; "host"; "addr"; "laddr"; "lport" ]
        if properties |> Array.exists (fun property -> not (Set.contains property.Name allowed)) then
            fail "SSHD connectionContext contains an unsupported property."
        let tryField name transform =
            match properties |> Array.tryFind (fun property -> property.Name = name) with
            | None -> None
            | Some property ->
                if property.Value.ValueKind = JsonValueKind.Null then None
                else Some(transform(readString property.Value ("SSHD connectionContext." + name)))
        let localPort =
            match properties |> Array.tryFind (fun property -> property.Name = "lport") with
            | None -> None
            | Some property when property.Value.ValueKind = JsonValueKind.Null -> None
            | Some property ->
                if property.Value.ValueKind <> JsonValueKind.Number then fail "SSHD connectionContext.lport must be an integer."
                let mutable port = 0
                if not (property.Value.TryGetInt32(&port)) || port < 1 || port > 65535 then
                    fail "SSHD connectionContext.lport must be from 1 through 65535."
                Some port
        { User = tryField "user" validateUser
          Host = tryField "host" validateHost
          Address = tryField "addr" (validateAddress "SSHD client address")
          LocalAddress = tryField "laddr" (validateAddress "SSHD local address")
          LocalPort = localPort }

    let private environmentContext () =
        let environmentUser =
            let sudoUser = Environment.GetEnvironmentVariable("SUDO_USER")
            let user = if String.IsNullOrWhiteSpace sudoUser then Environment.UserName else sudoUser
            if String.IsNullOrWhiteSpace user then None else Some(validateUser user)
        let sshConnection = Environment.GetEnvironmentVariable("SSH_CONNECTION")
        let connectionFields =
            if String.IsNullOrWhiteSpace sshConnection then Array.empty
            else sshConnection.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
        let parsedAddress, parsedLocalAddress, parsedLocalPort =
            if connectionFields.Length = 4 then
                let address = try Some(validateAddress "SSHD client address" connectionFields[0]) with _ -> None
                let localAddress = try Some(validateAddress "SSHD local address" connectionFields[2]) with _ -> None
                let mutable localPort = 0
                let port = if Int32.TryParse(connectionFields[3], NumberStyles.None, CultureInfo.InvariantCulture, &localPort) && localPort >= 1 && localPort <= 65535 then Some localPort else None
                address, localAddress, port
            else None, None, None
        { User = environmentUser
          Host = None
          Address = parsedAddress
          LocalAddress = parsedLocalAddress
          LocalPort = parsedLocalPort }


    let private contextNode (context: ConnectionContext) =
        let node = JsonObject()
        let writeOptional (key: string) (value: string option) =
            match value with
            | Some item -> node[key] <- JsonValue.Create(item)
            | None -> node[key] <- (null: JsonNode)
        writeOptional "user" context.User
        writeOptional "host" context.Host
        writeOptional "addr" context.Address
        writeOptional "laddr" context.LocalAddress
        match context.LocalPort with
        | Some value -> node["lport"] <- JsonValue.Create(value)
        | None -> node["lport"] <- (null: JsonNode)
        node

    let private parseRequest (element: JsonElement) =
        let properties = jsonProperties element "The SSHD request"
        let names = properties |> Array.map (fun property -> property.Name) |> Set.ofArray
        let required = set [ "operation"; "ownerId"; "settings" ]
        let allowed = set [ "operation"; "ownerId"; "settings"; "transactionToken" ]
        if not (Set.isSubset required names) || not (Set.isSubset names allowed) then
            fail "The SSHD request must contain only operation, ownerId, settings, and optional transactionToken."
        let get (name: string) = properties |> Array.find (fun property -> property.Name = name) |> fun property -> property.Value
        let operation = readString (get "operation") "SSHD operation"
        if not (Set.contains operation (set [ "read"; "apply"; "delete"; "confirm"; "rollback" ])) then
            fail "Unsupported SSHD operation."
        let ownerId = readString (get "ownerId") "SSHD ownerId"
        let digest = ownerDigest ownerId
        let settings = parseSettings (get "settings")
        let token =
            match properties |> Array.tryFind (fun property -> property.Name = "transactionToken") with
            | None -> None
            | Some property when property.Value.ValueKind = JsonValueKind.Null -> None
            | Some property ->
                let value = readString property.Value "SSHD transactionToken"
                if not (tokenPattern.IsMatch value) then fail "SSHD transactionToken is invalid."
                Some value
        if (operation = "confirm" || operation = "rollback") && token.IsNone then
            fail "SSHD confirm and rollback operations require transactionToken."
        if operation <> "confirm" && operation <> "rollback" && token.IsSome then
            fail "SSHD transactionToken is only valid for confirm and rollback operations."
        { Operation = operation
          OwnerId = ownerId
          OwnerDigest = digest
          Settings = settings
          TransactionToken = token
          Context = environmentContext () }

    let private renderConfig (digest: string) (settings: Map<string, string>) =
        let lines = ResizeArray<string>()
        lines.Add(ownerMarkerPrefix + digest)
        for name in supportedSettings do
            match Map.tryFind name settings with
            | Some value -> lines.Add(name + " " + value)
            | None -> ()
        lines.Add("")
        strictUtf8.GetBytes(String.concat "\n" lines)

    let private renderOwnerState (state: OwnerState) =
        let root = JsonObject()
        root["version"] <- JsonValue.Create(1)
        root["owner"] <- JsonValue.Create(state.OwnerDigest)
        let settings = JsonObject()
        for name, value in state.Settings |> Map.toSeq |> Seq.sortBy fst do
            settings[name] <- JsonValue.Create(value)
        root["settings"] <- settings
        strictUtf8.GetBytes(root.ToJsonString())

    let private parseBase64Snapshot (element: JsonElement) (description: string) : byte[] option =
        if element.ValueKind = JsonValueKind.Null then None
        elif element.ValueKind <> JsonValueKind.String then fail (description + " is invalid.")
        else
            try
                let raw = element.GetString()
                let bytes = Convert.FromBase64String(raw)
                if Convert.ToBase64String(bytes) <> raw then fail (description + " is invalid.")
                Some bytes
            with
            | :? BackendError -> reraise ()
            | _ -> fail (description + " is invalid.")

    let private parseOptionalSettings (element: JsonElement) (description: string) : byte[] option =
        parseBase64Snapshot element description

    let private encodeSnapshot (bytes: byte[] option) : JsonNode =
        match bytes with
        | None -> null
        | Some value -> JsonValue.Create(Convert.ToBase64String(value)) :> JsonNode

    let private jsonObject (bytes: byte[]) description =
        try
            let text = strictUtf8.GetString(bytes)
            use document = JsonDocument.Parse(text, JsonDocumentOptions(MaxDepth = 16))
            let properties = jsonProperties document.RootElement description
            properties, document.RootElement.Clone()
        with
        | :? BackendError -> reraise ()
        | _ -> fail (description + " is malformed.")

    let private loadOwnerState (environment: HostEnvironment) =
        match safeReadFile environment ownerStatePath maxManagedFileBytes "SSHD ownership state" with
        | None -> None, None
        | Some bytes ->
            let _, node = jsonObject bytes "SSHD ownership state"
            let names = node.EnumerateObject() |> Seq.map (fun property -> property.Name) |> Set.ofSeq
            if names <> set [ "version"; "owner"; "settings" ] then fail "SSHD ownership state is malformed."
            let version = node.GetProperty("version")
            let owner = node.GetProperty("owner")
            let settingsElement = node.GetProperty("settings")
            if version.ValueKind <> JsonValueKind.Number || version.GetInt32() <> 1 || owner.ValueKind <> JsonValueKind.String then
                fail "SSHD ownership state is malformed."
            let digest = owner.GetString()
            if isNull digest || not (Regex.IsMatch(digest, "^[0-9a-f]{64}$", RegexOptions.CultureInvariant)) then
                fail "SSHD ownership state is malformed."
            let settings = parseSettings settingsElement
            Some { OwnerDigest = digest; Settings = settings }, Some bytes

    let private jsonBool (element: JsonElement) description =
        if element.ValueKind = JsonValueKind.True then true
        elif element.ValueKind = JsonValueKind.False then false
        else fail (description + " is invalid.")

    let private jsonInt (element: JsonElement) description =
        let mutable value = 0
        if element.ValueKind = JsonValueKind.Number && element.TryGetInt32(&value) then value
        else fail (description + " is invalid.")


    let private parseContextFromJournal (element: JsonElement) =
        if element.ValueKind <> JsonValueKind.Object then fail "SSHD rollback journal is malformed."
        let properties = jsonProperties element "SSHD rollback context"
        if (properties |> Array.map (fun property -> property.Name) |> Set.ofArray) <> set [ "user"; "host"; "addr"; "laddr"; "lport" ] then
            fail "SSHD rollback journal is malformed."
        parseContextElement element

    let private renderTransaction (transaction: Transaction) =
        let root = JsonObject()
        root["version"] <- JsonValue.Create(1)
        root["owner"] <- JsonValue.Create(transaction.OwnerDigest)
        root["ownerId"] <- JsonValue.Create(transaction.OwnerId)
        root["action"] <- JsonValue.Create(transaction.Action)
        root["token"] <- JsonValue.Create(transaction.Token)
        root["status"] <- JsonValue.Create(transaction.Status)
        root["oldConfig"] <- encodeSnapshot transaction.OldConfig
        root["newConfig"] <- encodeSnapshot transaction.NewConfig
        root["oldState"] <- encodeSnapshot transaction.OldState
        root["newState"] <- encodeSnapshot transaction.NewState
        root["helperPath"] <- JsonValue.Create(transaction.HelperPath)
        root["context"] <- contextNode transaction.Context
        let settingsNode (values: Map<string, string>) =
            let node = JsonObject()
            for name, value in values |> Map.toSeq |> Seq.sortBy fst do
                node[name] <- JsonValue.Create(value)
            node
        root["baselineSettings"] <- settingsNode transaction.BaselineSettings
        root["baselineGlobalSettings"] <- settingsNode transaction.BaselineGlobalSettings
        let portsNode (values: int list) =
            let node = JsonArray()
            for port in values do node.Add(JsonValue.Create(port))
            node
        root["baselinePorts"] <- portsNode transaction.BaselinePorts
        root["baselineContextPorts"] <- portsNode transaction.BaselineContextPorts
        root["reloadCompleted"] <- JsonValue.Create(transaction.ReloadCompleted)
        strictUtf8.GetBytes(root.ToJsonString())

    let private writeTransaction (environment: HostEnvironment) (transaction: Transaction) =
        writeFile environment transactionPath (renderTransaction transaction) privateFileMode "SSHD rollback journal"

    let private loadTransaction (environment: HostEnvironment) =
        match safeReadFile environment transactionPath maxTransactionFileBytes "SSHD rollback journal" with
        | None -> None
        | Some bytes ->
            try
                let _, node = jsonObject bytes "SSHD rollback journal"
                let names = node.EnumerateObject() |> Seq.map (fun property -> property.Name) |> Set.ofSeq
                let expected = set [ "version"; "owner"; "ownerId"; "action"; "token"; "status"; "oldConfig"; "newConfig"; "oldState"; "newState"; "helperPath"; "context"; "baselineSettings"; "baselineGlobalSettings"; "baselinePorts"; "baselineContextPorts"; "reloadCompleted" ]
                if names <> expected then fail "SSHD rollback journal is malformed."
                let get (name: string) = node.GetProperty(name)
                let version = jsonInt (get "version") "SSHD rollback journal version"
                let digest = readString (get "owner") "SSHD rollback journal owner"
                let ownerId = readString (get "ownerId") "SSHD rollback journal ownerId"
                let action = readString (get "action") "SSHD rollback journal action"
                let token = readString (get "token") "SSHD rollback journal token"
                let status = readString (get "status") "SSHD rollback journal status"
                let helperPath = readString (get "helperPath") "SSHD rollback journal helper path"
                if version <> 1 || digest <> ownerDigest ownerId || not (tokenPattern.IsMatch token)
                   || not (Set.contains action (set [ "apply"; "delete" ]))
                   || not (Set.contains status (set [ "pending"; "confirmed"; "rolledBack" ])) then
                    fail "SSHD rollback journal is malformed."
                let helperMatch = helperPathPattern.Match(helperPath)
                if not helperMatch.Success then fail "SSHD rollback journal helper path is malformed."
                let oldConfig = parseOptionalSettings (get "oldConfig") "SSHD old configuration snapshot"
                let newConfig = parseOptionalSettings (get "newConfig") "SSHD candidate configuration snapshot"
                let oldState = parseOptionalSettings (get "oldState") "SSHD old ownership snapshot"
                let newState = parseOptionalSettings (get "newState") "SSHD candidate ownership snapshot"
                let context = parseContextFromJournal (get "context")
                let baselineSettings = parseObservedSettings (get "baselineSettings")
                let baselineGlobalSettings = parseObservedSettings (get "baselineGlobalSettings")
                let expectedSettingNames = settingNames
                if (baselineSettings |> Map.toSeq |> Seq.map fst |> Set.ofSeq) <> expectedSettingNames
                   || (baselineGlobalSettings |> Map.toSeq |> Seq.map fst |> Set.ofSeq) <> expectedSettingNames then
                    fail "SSHD rollback journal baseline settings are malformed."
                let parsePorts (description: string) (element: JsonElement) =
                    if element.ValueKind <> JsonValueKind.Array then fail "SSHD rollback journal is malformed."
                    let ports =
                        element.EnumerateArray()
                        |> Seq.map (fun item ->
                            let port = jsonInt item description
                            if port < 1 || port > 65535 then fail "SSHD rollback journal is malformed."
                            port)
                        |> Seq.toList
                    if ports.IsEmpty || ports.Length <> (ports |> Set.ofList |> Set.count) || ports <> List.sort ports then
                        fail "SSHD rollback journal is malformed."
                    ports
                let baselinePorts = parsePorts "SSHD rollback journal port" (get "baselinePorts")
                let baselineContextPorts = parsePorts "SSHD rollback context port" (get "baselineContextPorts")
                let reloadCompleted = jsonBool (get "reloadCompleted") "SSHD rollback reload state"
                Some {
                    OwnerId = ownerId
                    OwnerDigest = digest
                    Action = action
                    Token = token
                    Status = status
                    OldConfig = oldConfig
                    NewConfig = newConfig
                    OldState = oldState
                    NewState = newState
                    HelperPath = helperPath
                    Context = context
                    BaselineSettings = baselineSettings
                    BaselineGlobalSettings = baselineGlobalSettings
                    BaselinePorts = baselinePorts
                    BaselineContextPorts = baselineContextPorts
                    ReloadCompleted = reloadCompleted
                }
            with
            | :? BackendError -> reraise ()
            | _ -> fail "SSHD rollback journal is malformed."

    let private saveOwnerState (environment: HostEnvironment) (state: OwnerState option) =
        match state with
        | None -> deleteFile environment ownerStatePath "SSHD ownership state" |> ignore
        | Some value -> writeFile environment ownerStatePath (renderOwnerState value) privateFileMode "SSHD ownership state"

    let private listenAddressPort (endpoint: string) =
        let portText =
            if endpoint.StartsWith("[", StringComparison.Ordinal) then
                let closing = endpoint.IndexOf(']')
                if closing < 0 || closing + 1 >= endpoint.Length || endpoint[closing + 1] <> ':' then
                    fail "sshd -T returned an invalid ListenAddress endpoint."
                endpoint.Substring(closing + 2)
            else
                let separator = endpoint.LastIndexOf(':')
                if separator <= 0 || separator = endpoint.Length - 1 then
                    fail "sshd -T returned an invalid ListenAddress endpoint."
                endpoint.Substring(separator + 1)
        validateObservedSetting "Port" portText
        Int32.Parse(portText, NumberStyles.None, CultureInfo.InvariantCulture)

    let private parseEffective (text: string) =
        let mutable settings = Map.empty
        let configuredPorts = ResizeArray<int>()
        let listenerPorts = ResizeArray<int>()
        for rawLine in text.Split([| '\n'; '\r' |], StringSplitOptions.RemoveEmptyEntries) do
            let fields = rawLine.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
            if fields.Length >= 2 then
                let value = String.Join(" ", fields, 1, fields.Length - 1)
                match fields[0].ToLowerInvariant() with
                | "port" ->
                    validateObservedSetting "Port" value
                    configuredPorts.Add(Int32.Parse(value, NumberStyles.None, CultureInfo.InvariantCulture))
                | "listenaddress" -> listenerPorts.Add(listenAddressPort value)
                | "passwordauthentication" ->
                    validateObservedSetting "PasswordAuthentication" value
                    settings <- Map.add "PasswordAuthentication" value settings
                | "kbdinteractiveauthentication" ->
                    validateObservedSetting "KbdInteractiveAuthentication" value
                    settings <- Map.add "KbdInteractiveAuthentication" value settings
                | "pubkeyauthentication" ->
                    validateObservedSetting "PubkeyAuthentication" value
                    settings <- Map.add "PubkeyAuthentication" value settings
                | "permitrootlogin" ->
                    let canonical = if value = "without-password" then "prohibit-password" else value
                    validateObservedSetting "PermitRootLogin" canonical
                    settings <- Map.add "PermitRootLogin" canonical settings
                | "maxauthtries" ->
                    validateObservedSetting "MaxAuthTries" value
                    settings <- Map.add "MaxAuthTries" value settings
                | _ -> ()
        if configuredPorts.Count = 0 then fail "sshd -T did not report an effective Port."
        if listenerPorts.Count = 0 then fail "sshd -T did not report an effective ListenAddress."
        for name in supportedSettings do
            if name <> "Port" && not (Map.containsKey name settings) then
                fail ("sshd -T did not report effective " + name + ".")
        let configured = configuredPorts |> Seq.distinct |> Seq.sort |> Seq.toList
        let listeners = listenerPorts |> Seq.distinct |> Seq.sort |> Seq.toList
        { Settings =
            settings
            |> Map.add "Port" (configured |> List.map (fun port -> port.ToString(CultureInfo.InvariantCulture)) |> String.concat ",")
          Ports = listeners }

    let private contextArguments (context: ConnectionContext) =
        let parts = ResizeArray<string>()
        match context.User with Some value -> parts.Add("user=" + value) | None -> ()
        match context.Host with Some value -> parts.Add("host=" + value) | None -> ()
        match context.Address with Some value -> parts.Add("addr=" + value) | None -> ()
        match context.LocalAddress with Some value -> parts.Add("laddr=" + value) | None -> ()
        match context.LocalPort with Some value -> parts.Add("lport=" + value.ToString(CultureInfo.InvariantCulture)) | None -> ()
        if parts.Count = 0 then [] else [ "-C"; String.Join(",", parts) ]

    let private verifySshConfigurationPaths (environment: HostEnvironment) =
        ensureSafeDirectoryChain environment "/etc/ssh" false
        ensureSafeDirectoryChain environment configurationDirectory false
        let metadata = checkMetadata environment mainConfiguration regularFileType "sshd_config" |> Option.defaultWith (fun () -> fail "sshd_config is unavailable.")
        if productionRoot environment && (metadata.Mode &&& 0o022) <> 0 then
            fail "sshd_config must not be group- or world-writable."

    let private systemdProperty (environment: HostEnvironment) (property: string) =
        runOk environment "/usr/bin/systemctl" [ "show"; "--no-pager"; "--property=" + property; "--value"; "ssh.service" ] ("Inspecting ssh.service " + property)

    let private systemdCommands (environment: HostEnvironment) (property: string) =
        let output = systemdProperty environment property
        let expectedCount = Regex.Matches(output, @"\{\s*path=").Count
        let matches =
            Regex.Matches(output, @"\{\s*path=([^;]+)\s*;\s*argv\[\]=([^;]*)\s*;\s*ignore_errors=[^;]+")
        if expectedCount = 0 || matches.Count <> expectedCount then
            fail ("ssh.service " + property + " is not in Debian's supported form.")
        matches
        |> Seq.cast<Match>
        |> Seq.map (fun item -> item.Groups[1].Value.Trim(), item.Groups[2].Value.Trim())
        |> Seq.toList

    let private requireSystemdCommand
        (environment: HostEnvironment)
        (property: string)
        (allowed: (string * string) list list)
        =
        let actual = systemdCommands environment property
        if not (List.contains actual allowed) then
            fail ("ssh.service " + property + " uses unsupported OpenSSH options.")

    let private verifySshdOptionsFile (environment: HostEnvironment) =
        let environmentText = systemdProperty environment "Environment"
        let optionAssignments =
            environmentText.Split([| ' '; '\t'; '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
            |> Array.choose (fun item ->
                let prefix = "SSHD_OPTS="
                if item.StartsWith(prefix, StringComparison.Ordinal) then Some(item.Substring(prefix.Length)) else None)
        if optionAssignments |> Array.exists (fun value -> value <> "" && value <> "''" && value <> "\"\"") then
            fail "ssh.service has non-empty SSHD_OPTS."
        let environmentFiles = systemdProperty environment "EnvironmentFiles"
        let filePaths =
            Regex.Matches(environmentFiles, @"/[^\s()]+")
            |> Seq.cast<Match>
            |> Seq.map (fun item -> item.Value)
            |> Seq.toArray
        if not (String.IsNullOrWhiteSpace environmentFiles) && filePaths.Length = 0 then
            fail "ssh.service EnvironmentFiles cannot be verified."
        if filePaths.Length > 1 || filePaths |> Array.exists (fun path -> path <> "/etc/default/ssh") then
            fail "ssh.service uses an unsupported EnvironmentFile."
        if filePaths |> Array.contains "/etc/default/ssh" then
            match safeReadFile environment "/etc/default/ssh" maxManagedFileBytes "OpenSSH defaults file" with
            | None -> ()
            | Some bytes ->
                let text = strictUtf8.GetString(bytes)
                for rawLine in text.Split([| '\n'; '\r' |], StringSplitOptions.RemoveEmptyEntries) do
                    let line = rawLine.Trim()
                    let assignment =
                        if line.StartsWith("export ", StringComparison.Ordinal) then line.Substring(7).Trim()
                        else line
                    if assignment.StartsWith("SSHD_OPTS", StringComparison.Ordinal) then
                        let equals = assignment.IndexOf('=')
                        if equals < 0 || assignment.Substring(0, equals).Trim() <> "SSHD_OPTS" then
                            fail "/etc/default/ssh contains an unsupported SSHD_OPTS assignment."
                        let rawValue = assignment.Substring(equals + 1).Trim()
                        let comment = rawValue.IndexOf('#')
                        let value = if comment < 0 then rawValue else rawValue.Substring(0, comment).Trim()
                        if value <> "" && value <> "''" && value <> "\"\"" then
                            fail "/etc/default/ssh contains non-empty SSHD_OPTS."

    let private verifySshServiceCommand (environment: HostEnvironment) =
        requireSystemdCommand
            environment
            "ExecStart"
            [
                [ "/usr/sbin/sshd", "/usr/sbin/sshd -D" ]
                [ "/usr/sbin/sshd", "/usr/sbin/sshd -D $SSHD_OPTS" ]
            ]
        requireSystemdCommand
            environment
            "ExecReload"
            [
                [ "/usr/sbin/sshd", "/usr/sbin/sshd -t"; "/bin/kill", "/bin/kill -HUP $MAINPID" ]
                [ "/usr/sbin/sshd", "/usr/sbin/sshd -t"; "/usr/bin/kill", "/usr/bin/kill -HUP $MAINPID" ]
            ]
        verifySshdOptionsFile environment

    let private effectiveConfiguration (environment: HostEnvironment) (context: ConnectionContext) =
        verifySshConfigurationPaths environment
        verifySshServiceCommand environment
        let mainPath = HostEnvironment.path environment mainConfiguration
        let read (contextArgs: string list) =
            runOk environment sshdExecutable ([ "-T"; "-f"; mainPath ] @ contextArgs) "Evaluating effective sshd configuration"
            |> parseEffective
        let globalConfig = read []
        let contextArgs = contextArguments context
        let contextual = if List.isEmpty contextArgs then globalConfig else read contextArgs
        { Settings = contextual.Settings
          GlobalSettings = globalConfig.Settings
          Ports = globalConfig.Ports
          ContextPorts = contextual.Ports }

    let private validateSshdConfiguration (environment: HostEnvironment) =
        verifySshConfigurationPaths environment
        let mainPath = HostEnvironment.path environment mainConfiguration
        runOk environment sshdExecutable [ "-t"; "-f"; mainPath ] "Validating sshd configuration" |> ignore

    let private verifyRequestedSettings (settings: Map<string, string>) (effective: EffectiveConfiguration) =
        for KeyValue(name, expected) in settings do
            let globalValue = Map.tryFind name effective.GlobalSettings
            let contextualValue = Map.tryFind name effective.Settings
            if name = "Port" then
                let expectedPort = Int32.Parse(expected, CultureInfo.InvariantCulture)
                if globalValue <> Some expected
                   || contextualValue <> Some expected
                   || effective.Ports <> [ expectedPort ]
                   || effective.ContextPorts <> [ expectedPort ] then
                    fail "Effective sshd Port directives or ListenAddress listeners conflict with Dorothy's scalar Port override."
            elif globalValue <> Some expected || contextualValue <> Some expected then
                fail "An earlier global or Match sshd directive takes precedence over a requested Dorothy setting."

    let private verifyBaseline (transaction: Transaction) (effective: EffectiveConfiguration) =
        if transaction.BaselinePorts <> effective.Ports || transaction.BaselineContextPorts <> effective.ContextPorts then
            fail "The previous effective SSHD listener ports were not restored."
        for name in supportedSettings do
            if Map.tryFind name transaction.BaselineSettings <> Map.tryFind name effective.Settings
               || Map.tryFind name transaction.BaselineGlobalSettings <> Map.tryFind name effective.GlobalSettings then
                fail "The previous effective SSHD configuration was not restored."

    let private hashFile (environment: HostEnvironment) (logicalPath: string) (description: string) =
        let path = HostEnvironment.path environment logicalPath
        let parent = Path.GetDirectoryName logicalPath
        if String.IsNullOrEmpty parent then fail (description + " has no safe parent directory.")
        ensureSafeDirectoryChain environment parent false
        let initial = checkMetadata environment logicalPath regularFileType description |> Option.defaultWith (fun () -> fail (description + " is unavailable."))
        let descriptor = nativeOpen(path, openReadFlags, 0)
        if descriptor < 0 then
            let errorCode = Marshal.GetLastWin32Error()
            raise (Win32Exception(errorCode, "Could not safely open an SSHD executable."))
        try
            let opened = metadataForDescriptor descriptor
            if opened.Kind <> regularFileType || opened.UserId <> initial.UserId then
                fail (description + " changed while it was being opened.")
            requireRootOwned environment opened description
            use handle = new SafeFileHandle(nativeint descriptor, false)
            use stream = new FileStream(handle, FileAccess.Read, 65536, false)
            SHA256.HashData(stream) |> Convert.ToHexString |> fun value -> value.ToLowerInvariant()
        finally
            nativeClose descriptor |> ignore


    let private readHelperPath (environment: HostEnvironment) =
        let helperPath =
            if productionRoot environment then
                try
                    let executable = File.ResolveLinkTarget("/proc/self/exe", true)
                    if isNull executable then fail "The running SSHD helper path is unavailable."
                    Path.GetFullPath executable.FullName
                with
                | :? BackendError -> reraise ()
                | error -> fail ("Could not resolve the running SSHD helper path: " + error.Message)
            else
                runOk environment "/usr/bin/readlink" [ "-f"; "/proc/self/exe" ] "Resolving immutable SSHD helper path"
                |> fun output -> output.Trim()
        let matchResult = helperPathPattern.Match(helperPath)
        if not matchResult.Success then fail "The SSHD rollback helper must run from the immutable native helper cache."
        let logicalPath = helperPath
        let metadata = checkMetadata environment logicalPath regularFileType "immutable SSHD helper executable" |> Option.defaultWith (fun () -> fail "The immutable SSHD rollback helper executable is unavailable.")
        if productionRoot environment && metadata.Mode <> 0o755 then fail "The immutable SSHD rollback helper executable has insecure permissions."
        if hashFile environment logicalPath "immutable SSHD helper executable" <> matchResult.Groups[1].Value then
            fail "The immutable SSHD rollback helper executable digest does not match its cache path."
        helperPath

    let private jsonText (node: JsonNode) = node.ToJsonString(JsonSerializerOptions(WriteIndented = false))

    let private rollbackRequestBytes (transaction: Transaction) =
        let node = JsonObject()
        node["operation"] <- JsonValue.Create("rollback")
        node["ownerId"] <- JsonValue.Create(transaction.OwnerId)
        node["settings"] <- JsonObject()
        node["transactionToken"] <- JsonValue.Create(transaction.Token)
        strictUtf8.GetBytes(jsonText node)

    let private serviceUnitText (transaction: Transaction) =
        String.concat "\n" [
            ownerMarkerPrefix + transaction.OwnerDigest
            "[Unit]"
            "Description=Dorothy SSHD configuration rollback"
            "After=network.target"
            "[Service]"
            "Type=oneshot"
            "ExecStart=" + transaction.HelperPath + " sshd"
            "StandardInput=file:" + rollbackRequestPath
            ""
        ]

    let private timerUnitText (transaction: Transaction) =
        String.concat "\n" [
            ownerMarkerPrefix + transaction.OwnerDigest
            "[Unit]"
            "Description=Dorothy SSHD rollback watchdog"
            "[Timer]"
            "OnActiveSec=2min"
            "OnUnitInactiveSec=2min"
            "AccuracySec=1s"
            "Unit=" + rollbackServiceName
            "[Install]"
            "WantedBy=timers.target"
            ""
        ]

    let private hasOwnerMarker digest (bytes: byte array) =
        try
            let text = strictUtf8.GetString(bytes)
            text.StartsWith(ownerMarkerPrefix + digest + "\n", StringComparison.Ordinal)
        with _ -> false


    let private unitSlot (environment: HostEnvironment) (logicalPath: string) (digest: string) (expected: byte[]) (description: string) =
        match safeReadFile environment logicalPath maxManagedFileBytes description with
        | None -> ()
        | Some current when current = expected -> ()
        | Some current when hasOwnerMarker digest current -> fail (description + " has drifted from the active SSHD transaction.")
        | Some _ -> fail (description + " collides with an unowned systemd unit.")

    let private writeOwnedUnit (environment: HostEnvironment) (logicalPath: string) (digest: string) (bytes: byte[]) (description: string) =
        ensureSafeDirectoryChain environment (Path.GetDirectoryName logicalPath) false
        unitSlot environment logicalPath digest bytes description
        match safeReadFile environment logicalPath maxManagedFileBytes description with
        | None -> writeFile environment logicalPath bytes fileMode description
        | Some _ -> ()

    let private validateUnitPathOwner (environment: HostEnvironment) (logicalPath: string) (digest: string) (expected: byte[]) (description: string) =
        match safeReadFile environment logicalPath maxManagedFileBytes description with
        | None -> false
        | Some bytes when bytes = expected -> true
        | Some bytes when hasOwnerMarker digest bytes -> fail (description + " drifted during the SSHD transaction.")
        | Some _ -> fail (description + " is not owned by this SSHD transaction.")

    let private validateRequestFile (environment: HostEnvironment) (transaction: Transaction) =
        match safeReadFile environment rollbackRequestPath maxManagedFileBytes "SSHD rollback request" with
        | None -> false
        | Some bytes when bytes = rollbackRequestBytes transaction -> true
        | Some _ -> fail "SSHD rollback request drifted during the transaction."

    let private deleteExpectedFile (environment: HostEnvironment) logicalPath expected description =
        match safeReadFile environment logicalPath maxManagedFileBytes description with
        | None -> ()
        | Some bytes when bytes = expected -> deleteFile environment logicalPath description |> ignore
        | Some _ -> fail (description + " drifted; refusing to remove it.")

    let private assertRollbackSlotsAvailable (environment: HostEnvironment) =
        ensureSafeDirectoryChain environment (Path.GetDirectoryName servicePath) false
        ensureSafeDirectoryChain environment (Path.GetDirectoryName timerPath) false
        ensureSafeDirectoryChain environment stateDirectory true
        let requireAbsent logicalPath description =
            match safeReadFile environment logicalPath maxManagedFileBytes description with
            | None -> ()
            | Some _ -> fail (description + " already exists without a recoverable SSHD transaction.")
        requireAbsent servicePath "SSHD rollback service unit"
        requireAbsent timerPath "SSHD rollback timer unit"
        requireAbsent rollbackRequestPath "SSHD rollback request"

    let private armRollbackTimer (environment: HostEnvironment) (transaction: Transaction) =
        ensureSafeDirectoryChain environment (Path.GetDirectoryName servicePath) false
        ensureSafeDirectoryChain environment (Path.GetDirectoryName timerPath) false
        ensureSafeDirectoryChain environment stateDirectory true
        writeFile environment rollbackRequestPath (rollbackRequestBytes transaction) privateFileMode "SSHD rollback request"
        writeOwnedUnit environment servicePath transaction.OwnerDigest (strictUtf8.GetBytes(serviceUnitText transaction)) "SSHD rollback service unit"
        writeOwnedUnit environment timerPath transaction.OwnerDigest (strictUtf8.GetBytes(timerUnitText transaction)) "SSHD rollback timer unit"
        runOk environment "/usr/bin/systemctl" [ "daemon-reload" ] "Reloading systemd units for SSHD rollback" |> ignore
        runOk environment "/usr/bin/systemctl" [ "enable"; "--now"; rollbackTimerName ] "Arming the independent SSHD rollback timer" |> ignore

    let private disarmRollbackTimer (environment: HostEnvironment) (transaction: Transaction) =
        let serviceBytes = strictUtf8.GetBytes(serviceUnitText transaction)
        let timerBytes = strictUtf8.GetBytes(timerUnitText transaction)
        let serviceOwned = validateUnitPathOwner environment servicePath transaction.OwnerDigest serviceBytes "SSHD rollback service unit"
        let timerOwned = validateUnitPathOwner environment timerPath transaction.OwnerDigest timerBytes "SSHD rollback timer unit"
        let requestOwned = validateRequestFile environment transaction
        if timerOwned || serviceOwned then
            runOk environment "/usr/bin/systemctl" [ "disable"; "--now"; rollbackTimerName ] "Disarming the SSHD rollback timer" |> ignore
        if serviceOwned then deleteExpectedFile environment servicePath serviceBytes "SSHD rollback service unit"
        if timerOwned then deleteExpectedFile environment timerPath timerBytes "SSHD rollback timer unit"
        if requestOwned then deleteExpectedFile environment rollbackRequestPath (rollbackRequestBytes transaction) "SSHD rollback request"
        if timerOwned || serviceOwned then
            runOk environment "/usr/bin/systemctl" [ "daemon-reload" ] "Reloading systemd units after SSHD rollback" |> ignore
    let private optionBytesEqual (left: byte[] option) (right: byte[] option) =
        match left, right with
        | None, None -> true
        | Some a, Some b -> a.Length = b.Length && Array.forall2 (=) a b
        | _ -> false

    let private currentManagedBytes (environment: HostEnvironment) =
        safeReadFile environment configurationPath maxManagedFileBytes "Dorothy SSHD configuration"

    let private configIsRecognizablyOwned (digest: string) (bytes: byte[]) =
        try
            let text = strictUtf8.GetString(bytes)
            let lines = text.Split([| '\n' |], StringSplitOptions.RemoveEmptyEntries)
            if lines.Length = 0 || lines[0] <> ownerMarkerPrefix + digest then false
            else
                let seen = HashSet<string>(StringComparer.Ordinal)
                lines
                |> Array.skip 1
                |> Array.forall (fun line ->
                    let fields = line.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
                    if fields.Length <> 2 || not (Set.contains fields[0] settingNames) || not (seen.Add(fields[0])) then false
                    else
                        try validateSetting fields[0] fields[1]; true
                        with _ -> false)
        with _ -> false

    let private safeDeleteCurrentConfig (environment: HostEnvironment) (expected: byte[] option) =
        match currentManagedBytes environment with
        | None -> false
        | Some current ->
            match expected with
            | Some bytes when current = bytes -> deleteFile environment configurationPath "Dorothy SSHD configuration"
            | _ -> fail "The Dorothy SSHD configuration changed during deletion; refusing to remove drifted content."

    let private restoreSnapshot (environment: HostEnvironment) logicalPath snapshot mode description =
        match snapshot with
        | None -> deleteFile environment logicalPath description |> ignore
        | Some bytes -> writeFile environment logicalPath bytes mode description

    let private saveStatus (environment: HostEnvironment) (transaction: Transaction) status =
        let updated = { transaction with Status = status }
        writeTransaction environment updated
        updated

    let private cleanupTerminalTransaction (environment: HostEnvironment) (transaction: Transaction) =
        if transaction.Status <> "pending" then
            disarmRollbackTimer environment transaction

    let private transactionRequestMatches (request: Request) (transaction: Transaction) =
        request.OwnerDigest = transaction.OwnerDigest && request.OwnerId = transaction.OwnerId

    let private assertTransactionOwner (request: Request) (transaction: Transaction) =
        if not (transactionRequestMatches request transaction) then fail "A different SSHD resource owns the pending transaction."

    let private assertCurrentCandidate (environment: HostEnvironment) (transaction: Transaction) =
        let currentConfig = currentManagedBytes environment
        let _, currentState = loadOwnerState environment
        let configKnown = optionBytesEqual currentConfig transaction.NewConfig || optionBytesEqual currentConfig transaction.OldConfig
        let stateKnown = optionBytesEqual currentState transaction.NewState || optionBytesEqual currentState transaction.OldState
        if not configKnown || not stateKnown then
            fail "SSHD configuration drifted during a pending transaction; refusing to overwrite it."
        let candidateMatches = optionBytesEqual currentConfig transaction.NewConfig && optionBytesEqual currentState transaction.NewState
        let originalMatches = optionBytesEqual currentConfig transaction.OldConfig && optionBytesEqual currentState transaction.OldState
        candidateMatches, originalMatches

    let private rollbackPending (environment: HostEnvironment) (transaction: Transaction) =
        if transaction.Status = "confirmed" then transaction
        elif transaction.Status = "rolledBack" then transaction
        else
            let _, originalMatches = assertCurrentCandidate environment transaction
            if not originalMatches then
                restoreSnapshot environment configurationPath transaction.OldConfig fileMode "Dorothy SSHD configuration"
                match transaction.OldState with
                | None -> deleteFile environment ownerStatePath "SSHD ownership state" |> ignore
                | Some bytes ->
                    let _, element = jsonObject bytes "SSHD ownership snapshot"
                    let names = element.EnumerateObject() |> Seq.map (fun property -> property.Name) |> Set.ofSeq
                    if names <> set [ "version"; "owner"; "settings" ] then fail "SSHD ownership snapshot is malformed."
                    let version = jsonInt (element.GetProperty("version")) "SSHD ownership snapshot version"
                    let digest = readString (element.GetProperty("owner")) "SSHD ownership snapshot owner"
                    parseSettings (element.GetProperty("settings")) |> ignore
                    if version <> 1 || digest <> transaction.OwnerDigest then fail "SSHD ownership snapshot is malformed."
                    writeFile environment ownerStatePath bytes privateFileMode "SSHD ownership state"
            validateSshdConfiguration environment
            let restored = effectiveConfiguration environment transaction.Context
            verifyBaseline transaction restored
            restoreSshService environment
            saveStatus environment transaction "rolledBack"

    let private cleanPendingAfterError (environment: HostEnvironment) (transaction: Transaction) =
        let rolledBack = rollbackPending environment transaction
        cleanupTerminalTransaction environment rolledBack

    let private transactionDesiredSettings (transaction: Transaction) =
        match transaction.Action, transaction.NewConfig, transaction.NewState with
        | "apply", Some expectedConfig, Some stateBytes ->
            let _, state = jsonObject stateBytes "SSHD candidate ownership snapshot"
            let names = state.EnumerateObject() |> Seq.map (fun property -> property.Name) |> Set.ofSeq
            if names <> set [ "version"; "owner"; "settings" ] then fail "SSHD candidate ownership snapshot is malformed."
            let version = jsonInt (state.GetProperty("version")) "SSHD candidate ownership snapshot version"
            let owner = readString (state.GetProperty("owner")) "SSHD candidate ownership snapshot owner"
            let settings = parseSettings (state.GetProperty("settings"))
            if version <> 1 || owner <> transaction.OwnerDigest || renderConfig owner settings <> expectedConfig then
                fail "SSHD candidate ownership snapshot is malformed."
            Some settings
        | "delete", None, None -> None
        | _ -> fail "SSHD rollback journal candidate is malformed."

    let private validatePendingCandidate (environment: HostEnvironment) (transaction: Transaction) =
        validateSshdConfiguration environment
        let effective = effectiveConfiguration environment transaction.Context
        match transactionDesiredSettings transaction with
        | Some settings -> verifyRequestedSettings settings effective
        | None -> ()

    let private resumePendingTransaction (environment: HostEnvironment) (transaction: Transaction) =
        validatePendingCandidate environment transaction
        if transaction.ReloadCompleted then transaction
        else
            reloadSshService environment
            let completed = { transaction with ReloadCompleted = true }
            writeTransaction environment completed
            completed
    let private resultSnapshot (environment: HostEnvironment) (request: Request) =
        let transaction = loadTransaction environment
        match transaction with
        | Some pending when pending.Status = "pending" && not (transactionRequestMatches request pending) ->
            fail "A different SSHD resource has a pending configuration transaction."
        | _ -> ()
        validateSocketMode environment
        requireSshServiceActive environment
        let state, _ = loadOwnerState environment
        let effective = effectiveConfiguration environment request.Context
        let actualSettings = JsonObject()
        for KeyValue(name, _) in request.Settings do
            match Map.tryFind name effective.Settings with
            | Some value -> actualSettings[name] <- JsonValue.Create(value)
            | None -> fail ("sshd -T did not report effective " + name + ".")
        let pendingToken =
            match loadTransaction environment with
            | Some current when current.Status = "pending" && transactionRequestMatches request current -> current.Token
            | _ -> ""
        let fileContents = currentManagedBytes environment
        let ownedByRequest = state |> Option.exists (fun value -> value.OwnerDigest = request.OwnerDigest)
        let pendingOwned = pendingToken <> ""
        let owned = ownedByRequest || pendingOwned
        let fileMatchesState =
            match state with
            | Some value when value.OwnerDigest = request.OwnerDigest ->
                match fileContents with
                | Some bytes -> bytes = renderConfig value.OwnerDigest value.Settings
                | None -> false
            | _ -> false
        let stateMatchesRequest =
            state
            |> Option.exists (fun value -> value.OwnerDigest = request.OwnerDigest && value.Settings = request.Settings)
        let requestedSettingsMatch =
            request.Settings
            |> Map.forall (fun name expected ->
                if name = "Port" then
                    let mutable port = 0
                    Int32.TryParse(expected, NumberStyles.None, CultureInfo.InvariantCulture, &port)
                    && Map.tryFind name effective.GlobalSettings = Some expected
                    && Map.tryFind name effective.Settings = Some expected
                    && effective.Ports = [ port ]
                    && effective.ContextPorts = [ port ]
                else
                    Map.tryFind name effective.GlobalSettings = Some expected
                    && Map.tryFind name effective.Settings = Some expected)
        let noPending = pendingToken = ""
        let inSync = ownedByRequest && stateMatchesRequest && fileMatchesState && requestedSettingsMatch && noPending
        let response = JsonObject()
        response["owned"] <- JsonValue.Create(owned)
        response["actualSettings"] <- actualSettings
        let ports = JsonArray()
        for port in effective.Ports do ports.Add(JsonValue.Create(port))
        response["ports"] <- ports
        response["inSync"] <- JsonValue.Create(inSync)
        response["pendingToken"] <- JsonValue.Create(pendingToken)
        response
    let private resumePendingWithRollback (environment: HostEnvironment) (transaction: Transaction) =
        try resumePendingTransaction environment transaction
        with error ->
            try cleanPendingAfterError environment transaction
            with rollbackError ->
                fail ("SSHD pending activation failed and rollback remains armed: " + rollbackError.Message)
            match error with
            | :? BackendError -> reraise ()
            | _ -> fail ("SSHD pending activation failed: " + error.Message)

    let private loadTransactionForMutation (environment: HostEnvironment) (request: Request) =
        match loadTransaction environment with
        | None -> None
        | Some transaction when transaction.Status = "pending" ->
            assertTransactionOwner request transaction
            Some transaction
        | Some transaction ->
            cleanupTerminalTransaction environment transaction
            deleteFile environment transactionPath "SSHD rollback journal" |> ignore
            None

    let private ensureNoForeignOwner (request: Request) (state: OwnerState option) =
        match state with
        | Some existing when existing.OwnerDigest <> request.OwnerDigest ->
            fail "The SSHD configuration is already owned by another Pulumi resource."
        | _ -> ()

    let private currentEffective (environment: HostEnvironment) (request: Request) =
        validateSshdConfiguration environment
        effectiveConfiguration environment request.Context

    let private beginTransaction (environment: HostEnvironment) (request: Request) (action: string) oldConfig newConfig oldState newState baseline =
        let helperPath = readHelperPath environment
        let transaction = {
            OwnerId = request.OwnerId
            OwnerDigest = request.OwnerDigest
            Action = action
            Token = Guid.NewGuid().ToString("N")
            Status = "pending"
            OldConfig = oldConfig
            NewConfig = newConfig
            OldState = oldState
            NewState = newState
            HelperPath = helperPath
            Context = request.Context
            BaselineSettings = baseline.Settings
            BaselineGlobalSettings = baseline.GlobalSettings
            BaselinePorts = baseline.Ports
            BaselineContextPorts = baseline.ContextPorts
            ReloadCompleted = false
        }
        assertRollbackSlotsAvailable environment
        writeTransaction environment transaction
        transaction

    let private apply (environment: HostEnvironment) (request: Request) =
        ensureSafeDirectoryChain environment configurationDirectory false
        let pending = loadTransactionForMutation environment request
        let reusable =
            match pending with
            | Some transaction when transaction.Action = "apply" && optionBytesEqual transaction.NewConfig (Some(renderConfig request.OwnerDigest request.Settings)) ->
                let candidateMatches, _ = assertCurrentCandidate environment transaction
                if candidateMatches then
                    resumePendingWithRollback environment transaction |> ignore
                    Some(resultSnapshot environment request)
                else
                    let rolledBack = rollbackPending environment transaction
                    cleanupTerminalTransaction environment rolledBack
                    None
            | Some transaction ->
                let rolledBack = rollbackPending environment transaction
                cleanupTerminalTransaction environment rolledBack
                None
            | None -> None
        match reusable with
        | Some response -> response
        | None ->
            let owner, ownerBytes = loadOwnerState environment
            ensureNoForeignOwner request owner
            let currentConfig = currentManagedBytes environment
            match currentConfig, owner with
            | Some _, None ->
                fail "Refusing to manage an existing SSHD configuration without Dorothy ownership state."
            | Some current, Some existing when existing.OwnerDigest = request.OwnerDigest && not (configIsRecognizablyOwned request.OwnerDigest current) ->
                fail "The Dorothy SSHD configuration has drifted into an unowned format."
            | _ -> ()
            let baseline = currentEffective environment request
            let candidate = renderConfig request.OwnerDigest request.Settings
            let candidateOwner = { OwnerDigest = request.OwnerDigest; Settings = request.Settings }
            let nextState = renderOwnerState candidateOwner
            if optionBytesEqual currentConfig (Some candidate) then
                verifyRequestedSettings request.Settings baseline
                if not (optionBytesEqual ownerBytes (Some nextState)) then saveOwnerState environment (Some candidateOwner)
                resultSnapshot environment request
            else
                validateSocketMode environment
                requireSshServiceActive environment
                let transaction = beginTransaction environment request "apply" currentConfig (Some candidate) ownerBytes (Some nextState) baseline
                let mutable activeTransaction = transaction
                try
                    armRollbackTimer environment transaction
                    writeFile environment configurationPath candidate fileMode "Dorothy SSHD configuration"
                    saveOwnerState environment (Some candidateOwner)
                    activeTransaction <- resumePendingTransaction environment activeTransaction
                    resultSnapshot environment request
                with error ->
                    try cleanPendingAfterError environment activeTransaction
                    with rollbackError ->
                        fail ("SSHD configuration apply failed and rollback remains armed: " + rollbackError.Message)
                    match error with
                    | :? BackendError -> reraise ()
                    | _ -> fail ("SSHD configuration apply failed: " + error.Message)

    let rec private delete (environment: HostEnvironment) (request: Request) =
        ensureSafeDirectoryChain environment configurationDirectory false
        let pending = loadTransactionForMutation environment request
        match pending with
        | Some transaction when transaction.Action = "delete" ->
            let candidateMatches, _ = assertCurrentCandidate environment transaction
            if candidateMatches then
                resumePendingWithRollback environment transaction |> ignore
                let response = JsonObject()
                response["pendingToken"] <- JsonValue.Create(transaction.Token)
                response
            else
                let rolledBack = rollbackPending environment transaction
                cleanupTerminalTransaction environment rolledBack
                deleteFile environment transactionPath "SSHD rollback journal" |> ignore
                deleteAfterPending environment request
        | Some transaction ->
            let rolledBack = rollbackPending environment transaction
            cleanupTerminalTransaction environment rolledBack
            deleteFile environment transactionPath "SSHD rollback journal" |> ignore
            deleteAfterPending environment request
        | None -> deleteAfterPending environment request

    and private deleteAfterPending (environment: HostEnvironment) (request: Request) =
        let owner, ownerBytes = loadOwnerState environment
        ensureNoForeignOwner request owner
        match owner with
        | None ->
            match currentManagedBytes environment with
            | Some _ -> fail "Refusing to remove an SSHD configuration without Dorothy ownership state."
            | None ->
                let response = JsonObject()
                response["pendingToken"] <- JsonValue.Create("")
                response
        | Some existing ->
            let currentConfig = currentManagedBytes environment
            match currentConfig with
            | Some current when current <> renderConfig request.OwnerDigest existing.Settings ->
                fail "Refusing to remove a drifted Dorothy SSHD configuration."
            | _ -> ()
            match currentConfig with
            | None ->
                saveOwnerState environment None
                let response = JsonObject()
                response["pendingToken"] <- JsonValue.Create("")
                response
            | Some _ ->
                validateSocketMode environment
                requireSshServiceActive environment
                let baseline = currentEffective environment request
                let transaction = beginTransaction environment request "delete" currentConfig None ownerBytes None baseline
                let mutable activeTransaction = transaction
                try
                    armRollbackTimer environment transaction
                    safeDeleteCurrentConfig environment currentConfig |> ignore
                    saveOwnerState environment None
                    activeTransaction <- resumePendingTransaction environment activeTransaction
                    let response = JsonObject()
                    response["pendingToken"] <- JsonValue.Create(transaction.Token)
                    response
                with error ->
                    try cleanPendingAfterError environment activeTransaction
                    with rollbackError ->
                        fail ("SSHD configuration delete failed and rollback remains armed: " + rollbackError.Message)
                    match error with
                    | :? BackendError -> reraise ()
                    | _ -> fail ("SSHD configuration delete failed: " + error.Message)

    let private confirm (environment: HostEnvironment) (request: Request) =
        match loadTransaction environment with
        | None -> fail "The SSHD transaction to confirm is unavailable."
        | Some transaction ->
            assertTransactionOwner request transaction
            if request.TransactionToken <> Some transaction.Token then fail "SSHD transactionToken does not match the pending transaction."
            match transaction.Status with
            | "confirmed" ->
                cleanupTerminalTransaction environment transaction
                JsonObject()
            | "rolledBack" -> fail "The SSHD transaction was already rolled back."
            | "pending" ->
                if not transaction.ReloadCompleted then
                    fail "The SSHD candidate was not successfully reloaded before confirmation."
                let candidateMatches, _ = assertCurrentCandidate environment transaction
                if not candidateMatches then fail "The SSHD candidate configuration is not active for confirmation."
                validateSocketMode environment
                requireSshServiceActive environment
                validatePendingCandidate environment transaction
                match transactionDesiredSettings transaction with
                | Some expectedSettings when request.Settings <> expectedSettings ->
                    fail "SSHD confirm settings do not match the pending apply transaction."
                | _ -> ()
                let confirmed = saveStatus environment transaction "confirmed"
                cleanupTerminalTransaction environment confirmed
                JsonObject()
            | _ -> fail "SSHD rollback journal is malformed."

    let private rollback (environment: HostEnvironment) (request: Request) =
        match loadTransaction environment with
        | None -> fail "The SSHD transaction to roll back is unavailable."
        | Some transaction ->
            assertTransactionOwner request transaction
            if request.TransactionToken <> Some transaction.Token then fail "SSHD transactionToken does not match the pending transaction."
            let rolledBack = rollbackPending environment transaction
            cleanupTerminalTransaction environment rolledBack
            JsonObject()

    let private handleRequest (environment: HostEnvironment) (request: Request) =
        withLock environment (fun () ->
            match request.Operation with
            | "read" -> resultSnapshot environment request
            | "apply" -> apply environment request
            | "delete" -> delete environment request
            | "confirm" -> confirm environment request
            | "rollback" -> rollback environment request
            | _ -> fail "Unsupported SSHD operation.")

    let handle (environment: HostEnvironment) (element: JsonElement) : JsonNode =
        try
            let request = parseRequest element
            handleRequest environment request
        with
        | :? BackendError -> reraise ()
        | :? JsonException -> fail "The SSHD request is malformed."
        | :? PlatformNotSupportedException -> fail "The SSHD helper requires Linux filesystem primitives."
        | error -> fail ("SSHD operation failed: " + error.Message)

    let execute (environment: HostEnvironment) (requestText: string) : string =
        try
            use document = JsonDocument.Parse(requestText, JsonDocumentOptions(MaxDepth = 16))
            if document.RootElement.ValueKind <> JsonValueKind.Object then fail "The SSHD request must be a JSON object."
            handle environment document.RootElement |> fun response -> response.ToJsonString()
        with
        | :? BackendError -> reraise ()
        | :? JsonException -> fail "The SSHD request is malformed."
