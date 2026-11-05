namespace Dorothy.HostHelper

open System
open System.Collections.Generic
open System.Globalization
open System.IO
open System.Diagnostics
open System.Runtime.InteropServices
open System.Threading
open System.Text
open System.Text.Json
open System.Text.Json.Nodes

module Fail2Ban =
    type BackendError(message: string) =
        inherit InvalidOperationException(message)

    type private FileMutation =
        {
            Path: string
            Prior: string option
            Target: string option
        }

    type private PendingMutation =
        {
            Operation: string
            PriorOwned: bool
            PriorActive: bool
            PriorEnabled: bool
            StartupChanged: bool
            PythonChanged: bool
            TargetFiles: Map<string, string>
            Mutations: FileMutation list
        }

    type private Journal =
        {
            OwnerId: string
            Files: Map<string, string>
            RuntimeBaseline: Fail2BanNative.RuntimeBaseline option
            Pending: PendingMutation option
        }

    type private Desired =
        {
            OwnerId: string
            Files: Map<string, string>
            ManageSshdPorts: bool
            SshdPorts: int array
        }

    type private ServiceState =
        {
            Enabled: bool
            Active: bool
            Failed: bool
        }

    [<DllImport("libc", EntryPoint = "open", SetLastError = true)>]
    extern int private nativeOpenDirectory(string path, int flags)

    [<DllImport("libc", EntryPoint = "fsync", SetLastError = true)>]
    extern int private nativeFsync(int descriptor)

    [<DllImport("libc", EntryPoint = "close", SetLastError = true)>]
    extern int private nativeClose(int descriptor)

    let private configRoot = "/etc/fail2ban"
    let private stateDirectory = "/var/lib/keroosha-iac/fail2ban"
    let private journalPath = "/var/lib/keroosha-iac/fail2ban/configuration.json"
    let private lockPath = "/run/lock/keroosha-fail2ban-backend.lock"
    let private stagingDirectory = "/var/lib/keroosha-iac/fail2ban/staging"
    let private systemdUnit = "fail2ban.service"
    let private readinessTimeout = TimeSpan.FromSeconds 30.0
    let private sshdPortsPath = "jail.d/99-dorothy-sshd-ports.local"
    let private strictUtf8 = UTF8Encoding(false, true)

    let private journalDirectoryMode =
        UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute

    let private journalFileMode = UnixFileMode.UserRead ||| UnixFileMode.UserWrite
    let private managedFileMode = UnixFileMode.UserRead ||| UnixFileMode.UserWrite

    let private fail (message: string) = raise (BackendError(message))

    let private isMissingPathException (error: exn) =
        error :? FileNotFoundException || error :? DirectoryNotFoundException

    let private hasControl (value: string) =
        value |> Seq.exists (fun character -> Char.IsControl character)

    let private validateOwnerId (ownerId: string) =
        if String.IsNullOrWhiteSpace ownerId || hasControl ownerId then
            fail "ownerId must be a non-empty Pulumi resource ID without control characters"

        try
            strictUtf8.GetBytes ownerId |> ignore
        with :? EncoderFallbackException ->
            fail "ownerId is not valid UTF-8"

    let private validateRelativePath (relativePath: string) =
        if
            String.IsNullOrWhiteSpace relativePath
            || relativePath.StartsWith("/", StringComparison.Ordinal)
            || relativePath.Contains('\\')
            || hasControl relativePath
        then
            fail "Fail2Ban file paths must be safe relative paths beneath /etc/fail2ban"

        try
            strictUtf8.GetBytes relativePath |> ignore
        with :? EncoderFallbackException ->
            fail "Fail2Ban file path is not valid UTF-8"

        let components = relativePath.Split('/')

        if
            components
            |> Array.exists (fun segment -> segment = "" || segment = "." || segment = "..")
        then
            fail "Fail2Ban file paths must be safe relative paths beneath /etc/fail2ban"

        let normalized = Path.GetFullPath(Path.Combine(configRoot, relativePath))

        let prefix =
            Path.TrimEndingDirectorySeparator(Path.GetFullPath configRoot)
            + string Path.DirectorySeparatorChar

        if not (normalized.StartsWith(prefix, StringComparison.Ordinal)) then
            fail "Fail2Ban file paths must remain beneath /etc/fail2ban"

        relativePath

    let private mappedPath (environment: HostEnvironment) (logicalPath: string) =
        HostEnvironment.path environment logicalPath

    let private tryAttributes (path: string) =
        try
            Some(File.GetAttributes path)
        with
        | error when isMissingPathException error -> None
        | error -> fail ("cannot inspect Fail2Ban filesystem path: " + error.GetType().Name)

    let private ensureSafeDirectoryPath (path: string) (mode: UnixFileMode option) =
        let fullPath = Path.GetFullPath path
        let root = Path.GetPathRoot fullPath

        let segments =
            fullPath
                .Substring(root.Length)
                .Split(
                    [| Path.DirectorySeparatorChar; Path.AltDirectorySeparatorChar |],
                    StringSplitOptions.RemoveEmptyEntries
                )

        let mutable current = root

        for segment in segments do
            current <- Path.Combine(current, segment)

            match tryAttributes current with
            | None ->
                try
                    Directory.CreateDirectory current |> ignore
                with _ ->
                    fail "cannot create a Fail2Ban directory"

                match tryAttributes current with
                | Some attributes when
                    (attributes &&& FileAttributes.Directory) <> enum<FileAttributes> 0
                    && (attributes &&& FileAttributes.ReparsePoint) = enum<FileAttributes> 0
                    ->
                    ()
                | _ -> fail "refusing to use a non-directory or symbolic-link Fail2Ban path"
            | Some attributes when
                (attributes &&& FileAttributes.Directory) <> enum<FileAttributes> 0
                && (attributes &&& FileAttributes.ReparsePoint) = enum<FileAttributes> 0
                ->
                ()
            | Some _ -> fail "refusing to use a non-directory or symbolic-link Fail2Ban path"

        match mode with
        | None -> ()
        | Some expected ->
            try
                File.SetUnixFileMode(fullPath, expected)

                if File.GetUnixFileMode(fullPath) <> expected then
                    fail "Fail2Ban ownership state has insecure permissions"
            with
            | :? BackendError -> reraise ()
            | _ -> fail "cannot secure Fail2Ban ownership state"

    let private requireExistingDirectoryPath (path: string) =
        let fullPath = Path.GetFullPath path
        let root = Path.GetPathRoot fullPath

        let segments =
            fullPath
                .Substring(root.Length)
                .Split(
                    [| Path.DirectorySeparatorChar; Path.AltDirectorySeparatorChar |],
                    StringSplitOptions.RemoveEmptyEntries
                )

        let mutable current = root
        let mutable exists = true

        for segment in segments do
            current <- Path.Combine(current, segment)

            if exists then
                match tryAttributes current with
                | None -> exists <- false
                | Some attributes when
                    (attributes &&& FileAttributes.Directory) <> enum<FileAttributes> 0
                    && (attributes &&& FileAttributes.ReparsePoint) = enum<FileAttributes> 0
                    ->
                    ()
                | Some _ -> fail "refusing to inspect a non-directory or symbolic-link Fail2Ban path"

        exists

    let private ensureFileParent (path: string) =
        let parent = Path.GetDirectoryName path

        if String.IsNullOrEmpty parent then
            fail "Fail2Ban file path has no parent directory"

        ensureSafeDirectoryPath parent None

    let private syncDirectory (path: string) =
        let descriptor = nativeOpenDirectory (path, 0x10000 ||| 0x80000 ||| 0x20000)

        if descriptor < 0 then
            fail "cannot open a Fail2Ban directory for synchronization"

        try
            if nativeFsync descriptor <> 0 then
                fail "cannot synchronize a Fail2Ban directory"
        finally
            nativeClose descriptor |> ignore

    let private configFilePath (environment: HostEnvironment) (relativePath: string) =
        let valid = validateRelativePath relativePath
        mappedPath environment (configRoot + "/" + valid)

    let private readFileAtPath (path: string) =
        let parent = Path.GetDirectoryName path

        if not (requireExistingDirectoryPath parent) then
            None
        else
            match tryAttributes path with
            | None -> None
            | Some attributes when
                (attributes
                 &&& (FileAttributes.Directory
                      ||| FileAttributes.ReparsePoint
                      ||| FileAttributes.Device))
                <> enum<FileAttributes> 0
                ->
                fail "Fail2Ban configuration files must be regular files, not directories or symbolic links"
            | Some _ ->
                try
                    Some(strictUtf8.GetString(File.ReadAllBytes path))
                with
                | :? BackendError -> reraise ()
                | _ -> fail "cannot read a Fail2Ban configuration file as UTF-8"

    let private readConfigFile (environment: HostEnvironment) (relativePath: string) =
        readFileAtPath (configFilePath environment relativePath)

    let private hasManagedFileMode (environment: HostEnvironment) (relativePath: string) =
        let path = configFilePath environment relativePath

        match tryAttributes path with
        | None -> false
        | Some attributes when
            (attributes
             &&& (FileAttributes.Directory
                  ||| FileAttributes.ReparsePoint
                  ||| FileAttributes.Device))
                =
                enum<FileAttributes> 0
            ->
            try
                File.GetUnixFileMode path = managedFileMode
            with _ ->
                fail "cannot inspect Fail2Ban configuration file permissions"
        | Some _ -> false

    let private writeConfigFile
        (environment: HostEnvironment)
        (relativePath: string)
        (expected: string option)
        (target: string option)
        =
        let path = configFilePath environment relativePath
        let current = readFileAtPath path

        if current <> expected then
            fail "a Fail2Ban configuration file changed during the journaled transaction"

        if current <> target then
            match target with
            | Some text ->
                ensureFileParent path

                try
                    HostFiles.atomicWrite path (strictUtf8.GetBytes text) managedFileMode
                with
                | :? BackendError -> reraise ()
                | _ -> fail "cannot atomically update a Fail2Ban configuration file"
            | None ->
                match current with
                | None -> ()
                | Some _ ->
                    try
                        File.Delete path
                        syncDirectory (Path.GetDirectoryName path)
                    with
                    | :? BackendError -> reraise ()
                    | _ -> fail "cannot remove a Fail2Ban configuration file"

    let private syncStateDirectory (environment: HostEnvironment) =
        syncDirectory (mappedPath environment stateDirectory)

    let private ensureStateDirectory (environment: HostEnvironment) =
        ensureSafeDirectoryPath (mappedPath environment stateDirectory) (Some journalDirectoryMode)

    let private checkDuplicateProperties (element: JsonElement) =
        let rec visit (value: JsonElement) =
            match value.ValueKind with
            | JsonValueKind.Object ->
                let names = HashSet<string>(StringComparer.Ordinal)
                let mutable duplicate = false

                for property in value.EnumerateObject() do
                    if not (names.Add property.Name) then
                        duplicate <- true

                    if visit property.Value then
                        duplicate <- true

                duplicate
            | JsonValueKind.Array -> value.EnumerateArray() |> Seq.exists visit
            | _ -> false

        visit element

    let private ensureExactProperties (element: JsonElement) (expected: Set<string>) (description: string) =
        if element.ValueKind <> JsonValueKind.Object then
            fail (description + " must be a JSON object")

        let properties = element.EnumerateObject() |> Seq.toArray
        let names = properties |> Array.map (fun property -> property.Name) |> Set.ofArray

        if properties.Length <> names.Count || names <> expected then
            fail (description + " contains missing, duplicate, or unsupported fields")

    let private requiredString (element: JsonElement) (field: string) =
        let value = element.GetProperty field

        if value.ValueKind <> JsonValueKind.String then
            fail (field + " must be a string")

        match value.GetString() with
        | null -> fail (field + " must not be null")
        | text -> text

    let private requiredBoolean (element: JsonElement) (field: string) =
        let value = element.GetProperty field

        if value.ValueKind <> JsonValueKind.True && value.ValueKind <> JsonValueKind.False then
            fail (field + " must be a Boolean")

        value.GetBoolean()

    let private readStringMap (element: JsonElement) (description: string) =
        if element.ValueKind <> JsonValueKind.Object then
            fail (description + " must be a JSON object")

        let values = ResizeArray<string * string>()
        let names = HashSet<string>(StringComparer.Ordinal)

        for property in element.EnumerateObject() do
            let path = validateRelativePath property.Name

            if not (names.Add path) then
                fail (description + " contains duplicate paths")

            if property.Value.ValueKind <> JsonValueKind.String then
                fail (description + " values must be strings")

            match property.Value.GetString() with
            | null -> fail (description + " values must not be null")
            | text ->
                try
                    strictUtf8.GetBytes text |> ignore
                with :? EncoderFallbackException ->
                    fail (description + " contains text that is not valid UTF-8")

                values.Add(path, text)

        values |> Seq.toList |> Map.ofList

    let private readPorts (element: JsonElement) =
        if element.ValueKind <> JsonValueKind.Array then
            fail "sshdPorts must be an array of integers"

        element.EnumerateArray()
        |> Seq.map (fun value ->
            if value.ValueKind <> JsonValueKind.Number || not (value.TryGetInt32() |> fst) then
                fail "sshdPorts entries must be integers"

            value.GetInt32())
        |> Seq.toArray

    let private parseRequest (request: JsonElement) =
        if request.ValueKind <> JsonValueKind.Object || checkDuplicateProperties request then
            fail "Fail2Ban request must be an object without duplicate properties"

        ensureExactProperties
            request
            (set [ "operation"; "ownerId"; "files"; "manageSshdPorts"; "sshdPorts" ])
            "Fail2Ban request"

        let operation = requiredString request "operation"

        if operation <> "read" && operation <> "apply" && operation <> "delete" then
            fail "unsupported Fail2Ban operation"

        let ownerId = requiredString request "ownerId"
        validateOwnerId ownerId
        let files = readStringMap (request.GetProperty "files") "files"

        if files.ContainsKey sshdPortsPath then
            fail "the SSH port drop-in path is reserved for automatic SSH port linking"

        let manageSshdPorts = requiredBoolean request "manageSshdPorts"
        let sshdPorts = readPorts (request.GetProperty "sshdPorts")

        if manageSshdPorts then
            if sshdPorts |> Array.exists (fun port -> port < 1 || port > 65535) then
                fail "sshdPorts entries must be between 1 and 65535"

            if sshdPorts.Length <> (sshdPorts |> Array.distinct).Length then
                fail "sshdPorts must not contain duplicates"

        operation,
        {
            OwnerId = ownerId
            Files = files
            ManageSshdPorts = manageSshdPorts
            SshdPorts = sshdPorts
        }

    let private discoverSshdPorts (environment: HostEnvironment) =
        let result =
            try
                environment.Run "/usr/sbin/sshd" [ "-T" ] None
            with _ ->
                fail "could not read resolved local SSH listener ports"

        if result.ExitCode <> 0 then
            fail "sshd could not report resolved local listener ports"

        let ports = ResizeArray<int>()

        for rawLine in result.Stdout.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries) do
            let fields = rawLine.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)

            if
                fields.Length > 0
                && fields.[0].Equals("listenaddress", StringComparison.OrdinalIgnoreCase)
            then
                if fields.Length <> 2 then
                    fail "sshd returned a malformed listenaddress"

                let address = fields.[1]

                let separator =
                    if address.StartsWith("[", StringComparison.Ordinal) then
                        let closing = address.IndexOf(']')

                        if closing <= 1 || closing + 1 >= address.Length || address.[closing + 1] <> ':' then
                            fail "sshd returned a malformed bracketed listenaddress"

                        closing + 1
                    else
                        address.LastIndexOf(':')

                if separator <= 0 || separator + 1 >= address.Length then
                    fail "sshd returned a listenaddress without an explicit port"

                match
                    Int32.TryParse(address.Substring(separator + 1), NumberStyles.None, CultureInfo.InvariantCulture)
                with
                | true, port when port >= 1 && port <= 65535 -> ports.Add port
                | _ -> fail "sshd returned an invalid listener port"

        let result = ports |> Seq.distinct |> Seq.sort |> Seq.toArray

        if result.Length = 0 then
            fail "sshd did not report any resolved listening ports"

        result

    let private effectiveFiles (environment: HostEnvironment) (desired: Desired) =
        if not desired.ManageSshdPorts then
            desired.Files
        else
            let ports =
                if desired.SshdPorts.Length = 0 then
                    discoverSshdPorts environment
                else
                    desired.SshdPorts

            if ports.Length = 0 then
                fail "automatic SSH port linking requires at least one resolved SSH listener"

            let normalized = ports |> Array.distinct |> Array.sort

            let portText =
                normalized
                |> Array.map (fun port -> port.ToString(CultureInfo.InvariantCulture))
                |> String.concat ","

            let content =
                "# Managed by Dorothy for the linked sshd configuration.\n[sshd]\nport = "
                + portText
                + "\n"

            desired.Files.Add(sshdPortsPath, content)

    let private run (environment: HostEnvironment) (executable: string) (arguments: string list) =
        let result =
            try
                environment.Run executable arguments None
            with _ ->
                fail ("could not execute " + executable)

        if result.ExitCode <> 0 then
            fail (
                executable
                + " failed with exit code "
                + result.ExitCode.ToString(CultureInfo.InvariantCulture)
            )

        result.Stdout

    let private parseSystemdProperties (output: string) =
        let values = Dictionary<string, string>(StringComparer.Ordinal)

        for line in output.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries) do
            let separator = line.IndexOf('=')

            if separator <= 0 then
                fail "systemd returned malformed Fail2Ban service state"

            let name = line.Substring(0, separator)

            if
                name <> "LoadState"
                && name <> "UnitFileState"
                && name <> "ActiveState"
                && name <> "SubState"
                && name <> "Result"
            then
                fail "systemd returned unsupported Fail2Ban service state"

            if values.ContainsKey name then
                fail "systemd returned duplicate Fail2Ban service properties"

            values.Add(name, line.Substring(separator + 1))

        if values.Count <> 5 then
            fail "systemd omitted Fail2Ban service properties"

        values

    let private readServiceState (environment: HostEnvironment) =
        let output =
            run
                environment
                "systemctl"
                [
                    "show"
                    "--no-pager"
                    "--property=LoadState"
                    "--property=UnitFileState"
                    "--property=ActiveState"
                    "--property=SubState"
                    "--property=Result"
                    systemdUnit
                ]

        let values = parseSystemdProperties output

        if values["LoadState"] <> "loaded" then
            fail "fail2ban.service is not loaded"

        let enabled =
            match values["UnitFileState"] with
            | "enabled"
            | "enabled-runtime"
            | "linked"
            | "linked-runtime"
            | "alias" -> true
            | _ -> false

        {
            Enabled = enabled
            Active = values["ActiveState"] = "active"
            Failed =
                values["ActiveState"] = "failed"
                || values["SubState"] = "failed"
                || (values["Result"].Length > 0
                    && values["Result"] <> "success"
                    && values["Result"] <> "none")
        }

    let private setServiceEnabled (environment: HostEnvironment) (enabled: bool) =
        run environment "systemctl" [ (if enabled then "enable" else "disable"); systemdUnit ]
        |> ignore

    let private changeServiceState (environment: HostEnvironment) (operation: string) =
        run environment "systemctl" [ operation; systemdUnit ] |> ignore

    let private nativeValidate (environment: HostEnvironment) (root: string) =
        try
            Fail2BanNative.validate environment root
        with
        | :? BackendError -> reraise ()
        | :? Fail2BanNative.BackendError -> fail "Fail2Ban native configuration validation failed"
        | _ -> fail "Fail2Ban native configuration validation failed"

    let private nativeInspect (environment: HostEnvironment) (root: string) =
        try
            Fail2BanNative.inspect environment root
        with
        | :? BackendError -> reraise ()
        | :? Fail2BanNative.BackendError -> fail "Fail2Ban native configuration inspection failed"
        | _ -> fail "Fail2Ban native configuration inspection failed"

    let private nativeObserve
        (environment: HostEnvironment)
        (root: string)
        (configuration: Fail2BanNative.Configuration)
        (baseline: Fail2BanNative.RuntimeBaseline option)
        =
        try
            Fail2BanNative.observeWithBaseline environment root configuration baseline
        with
        | :? BackendError -> reraise ()
        | :? Fail2BanNative.BackendError -> fail "Fail2Ban runtime observation failed"
        | _ -> fail "Fail2Ban runtime observation failed"

    let private nativeReload (environment: HostEnvironment) (configuration: Fail2BanNative.Configuration) =
        try
            Fail2BanNative.reload environment configuration
        with
        | :? BackendError -> reraise ()
        | :? Fail2BanNative.BackendError -> fail "Fail2Ban native reload failed"
        | _ -> fail "Fail2Ban native reload failed"

    let private createStage (environment: HostEnvironment) (files: Map<string, string>) (removePaths: Set<string>) =
        let configPath = mappedPath environment configRoot

        if not (requireExistingDirectoryPath configPath) then
            fail "the Fail2Ban configuration directory does not exist"

        let stageName = Guid.NewGuid().ToString("N")
        let logicalStage = stagingDirectory + "/" + stageName
        let physicalStage = mappedPath environment logicalStage
        ensureSafeDirectoryPath (mappedPath environment stateDirectory) (Some journalDirectoryMode)
        ensureSafeDirectoryPath (Path.GetDirectoryName physicalStage) (Some journalDirectoryMode)

        try
            Directory.CreateDirectory physicalStage |> ignore
            File.SetUnixFileMode(physicalStage, journalDirectoryMode)
        with _ ->
            fail "cannot create a private Fail2Ban validation tree"

        let sourceRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath configPath)
        let sourcePrefix = sourceRoot + string Path.DirectorySeparatorChar

        let stagedLinkTarget (sourcePath: string) (linkTarget: string) =
            let resolvedTarget =
                if Path.IsPathRooted linkTarget then
                    Path.GetFullPath linkTarget
                else
                    Path.GetFullPath(Path.Combine(Path.GetDirectoryName sourcePath, linkTarget))

            if resolvedTarget = sourceRoot then
                Path.GetFullPath physicalStage
            elif resolvedTarget.StartsWith(sourcePrefix, StringComparison.Ordinal) then
                Path.Combine(physicalStage, Path.GetRelativePath(sourceRoot, resolvedTarget))
            else
                linkTarget

        let rec copyDirectory (source: string) (destination: string) =
            for entry in Directory.EnumerateFileSystemEntries source do
                let name = Path.GetFileName entry
                let target = Path.Combine(destination, name)

                let attributes =
                    match tryAttributes entry with
                    | Some value -> value
                    | None -> fail "Fail2Ban configuration changed while staging validation"

                let isDirectory =
                    (attributes &&& FileAttributes.Directory) <> enum<FileAttributes> 0

                if (attributes &&& FileAttributes.ReparsePoint) <> enum<FileAttributes> 0 then
                    let info =
                        if isDirectory then
                            DirectoryInfo(entry) :> FileSystemInfo
                        else
                            FileInfo(entry) :> FileSystemInfo

                    match info.LinkTarget with
                    | null -> fail "cannot preserve a Fail2Ban configuration symbolic link in the validation tree"
                    | linkTarget ->
                        let stagedTarget = stagedLinkTarget entry linkTarget

                        try
                            if isDirectory then
                                Directory.CreateSymbolicLink(target, stagedTarget) |> ignore
                            else
                                File.CreateSymbolicLink(target, stagedTarget) |> ignore
                        with _ ->
                            fail "cannot preserve a Fail2Ban configuration symbolic link in the validation tree"
                elif isDirectory then
                    Directory.CreateDirectory target |> ignore
                    File.SetUnixFileMode(target, journalDirectoryMode)
                    copyDirectory entry target
                elif (attributes &&& FileAttributes.Device) = enum<FileAttributes> 0 then
                    try
                        File.Copy(entry, target, false)
                        File.SetUnixFileMode(target, managedFileMode)
                    with _ ->
                        fail "cannot copy a Fail2Ban file into the validation tree"
                else
                    fail "unsupported filesystem object in the Fail2Ban configuration tree"

        try
            copyDirectory configPath physicalStage

            for relativePath in removePaths do
                let target =
                    Path.Combine(
                        physicalStage,
                        (validateRelativePath relativePath).Replace('/', Path.DirectorySeparatorChar)
                    )

                if requireExistingDirectoryPath (Path.GetDirectoryName target) then
                    match tryAttributes target with
                    | None -> ()
                    | Some attributes when
                        (attributes
                         &&& (FileAttributes.Directory
                              ||| FileAttributes.ReparsePoint
                              ||| FileAttributes.Device))
                            =
                            enum<FileAttributes> 0
                        ->
                        try
                            File.Delete target
                        with _ ->
                            fail "cannot remove a file from the Fail2Ban validation tree"
                    | Some _ -> fail "a staged Fail2Ban removal is not a regular file"

            for KeyValue(relativePath, content) in files do
                let target =
                    Path.Combine(physicalStage, relativePath.Replace('/', Path.DirectorySeparatorChar))

                ensureSafeDirectoryPath (Path.GetDirectoryName target) None

                match tryAttributes target with
                | Some attributes when
                    (attributes
                     &&& (FileAttributes.Directory
                          ||| FileAttributes.ReparsePoint
                          ||| FileAttributes.Device))
                    <> enum<FileAttributes> 0
                    ->
                    fail "a staged Fail2Ban target is not a regular file"
                | _ -> ()

                File.WriteAllBytes(target, strictUtf8.GetBytes content)
                File.SetUnixFileMode(target, managedFileMode)

            logicalStage, physicalStage
        with error ->
            try
                Directory.Delete(physicalStage, true)
            with _ ->
                ()

            match error with
            | :? BackendError -> reraise ()
            | _ -> fail "cannot stage the complete Fail2Ban configuration tree"

    let private withStagedConfiguration
        (environment: HostEnvironment)
        (files: Map<string, string>)
        (removePaths: Set<string>)
        (action: string -> Fail2BanNative.Configuration -> 'T)
        =
        let logicalStage, physicalStage = createStage environment files removePaths

        try
            nativeValidate environment logicalStage
            let configuration = nativeInspect environment logicalStage
            action logicalStage configuration
        finally
            try
                Directory.Delete(physicalStage, true)
            with _ ->
                ()

    let private computeMutations (priorFiles: Map<string, string>) (targetFiles: Map<string, string>) =
        let paths =
            Set.union (priorFiles |> Map.keys |> Set.ofSeq) (targetFiles |> Map.keys |> Set.ofSeq)

        paths
        |> Seq.choose (fun path ->
            let prior = priorFiles.TryFind path
            let target = targetFiles.TryFind path

            if prior = target then
                None
            else
                Some
                    {
                        Path = path
                        Prior = prior
                        Target = target
                    })
        |> Seq.toList

    let private serializeMap (values: Map<string, string>) =
        let node = JsonObject()

        for KeyValue(key, value) in values do
            node[key] <- JsonValue.Create value

        node

    let private serializeNullableString (value: string option) : JsonNode =
        match value with
        | Some text -> JsonValue.Create text :> JsonNode
        | None -> null

    let private serializeRuntimeBaseline (baseline: Fail2BanNative.RuntimeBaseline option) : JsonNode =
        match baseline with
        | None -> null
        | Some value ->
            let node = JsonObject()
            node["fingerprint"] <- JsonValue.Create value.Fingerprint
            node["startupFingerprint"] <- JsonValue.Create value.StartupFingerprint
            node["observationFingerprint"] <- JsonValue.Create value.ObservationFingerprint
            node :> JsonNode

    let private journalNode (journal: Journal) =
        let root = JsonObject()
        root["version"] <- JsonValue.Create 3
        root["ownerId"] <- JsonValue.Create journal.OwnerId
        root["files"] <- serializeMap journal.Files
        root["runtimeBaseline"] <- serializeRuntimeBaseline journal.RuntimeBaseline

        root["pending"] <-
            match journal.Pending with
            | None -> null
            | Some pending ->
                let value = JsonObject()
                value["operation"] <- JsonValue.Create pending.Operation
                value["priorOwned"] <- JsonValue.Create pending.PriorOwned
                value["priorActive"] <- JsonValue.Create pending.PriorActive
                value["priorEnabled"] <- JsonValue.Create pending.PriorEnabled
                value["startupChanged"] <- JsonValue.Create pending.StartupChanged
                value["pythonChanged"] <- JsonValue.Create pending.PythonChanged
                value["targetFiles"] <- serializeMap pending.TargetFiles
                let mutations = JsonArray()

                for mutation in pending.Mutations do
                    let item = JsonObject()
                    item["path"] <- JsonValue.Create mutation.Path
                    item["prior"] <- serializeNullableString mutation.Prior
                    item["target"] <- serializeNullableString mutation.Target
                    mutations.Add item

                value["mutations"] <- mutations
                value :> JsonNode

        root

    let private saveJournal (environment: HostEnvironment) (journal: Journal) =
        ensureStateDirectory environment
        let path = mappedPath environment journalPath

        try
            HostFiles.atomicWrite
                path
                (strictUtf8.GetBytes((journalNode journal).ToJsonString() + "\n"))
                journalFileMode
        with
        | :? BackendError -> reraise ()
        | _ -> fail "cannot durably write the Fail2Ban ownership journal"

    let private deleteJournal (environment: HostEnvironment) =
        let path = mappedPath environment journalPath

        match tryAttributes path with
        | None -> ()
        | Some attributes when
            (attributes
             &&& (FileAttributes.Directory
                  ||| FileAttributes.ReparsePoint
                  ||| FileAttributes.Device))
            <> enum<FileAttributes> 0
            ->
            fail "Fail2Ban ownership journal must be a regular file"
        | Some _ ->
            try
                File.Delete path
                syncStateDirectory environment
            with
            | :? BackendError -> reraise ()
            | _ -> fail "cannot remove the Fail2Ban ownership journal"

    let private expectObjectStringMap (element: JsonElement) (description: string) =
        if element.ValueKind <> JsonValueKind.Object then
            fail (description + " must be a JSON object")

        let values = ResizeArray<string * string>()

        for property in element.EnumerateObject() do
            let path = validateRelativePath property.Name

            if property.Value.ValueKind <> JsonValueKind.String then
                fail (description + " contains a non-string value")

            match property.Value.GetString() with
            | null -> fail (description + " contains a null value")
            | text -> values.Add(path, text)

        let entries = values |> Seq.toList

        if entries.Length <> (entries |> List.map fst |> List.distinct |> List.length) then
            fail (description + " contains duplicate paths")

        Map.ofList entries

    let private readBooleanProperty (element: JsonElement) (field: string) =
        let value = element.GetProperty field

        if value.ValueKind <> JsonValueKind.True && value.ValueKind <> JsonValueKind.False then
            fail ("Fail2Ban ownership journal has an invalid " + field)

        value.GetBoolean()

    let private readNullableString (element: JsonElement) (field: string) =
        match element.GetProperty(field).ValueKind with
        | JsonValueKind.Null -> None
        | JsonValueKind.String ->
            match element.GetProperty(field).GetString() with
            | null -> fail ("Fail2Ban ownership journal has an invalid " + field)
            | text -> Some text
        | _ -> fail ("Fail2Ban ownership journal has an invalid " + field)


    let private isSha256Digest (value: string) =
        value.Length = 64
        && (value
            |> Seq.forall (fun character ->
                (character >= '0' && character <= '9')
                || (character >= 'a' && character <= 'f')))

    let private readRuntimeBaseline (element: JsonElement) : Fail2BanNative.RuntimeBaseline option =
        match element.ValueKind with
        | JsonValueKind.Null -> None
        | JsonValueKind.Object ->
            ensureExactProperties
                element
                (set [ "fingerprint"; "startupFingerprint"; "observationFingerprint" ])
                "Fail2Ban runtime baseline"

            let fingerprint = requiredString element "fingerprint"
            let startupFingerprint = requiredString element "startupFingerprint"
            let observationFingerprint = requiredString element "observationFingerprint"

            if
                not (isSha256Digest fingerprint)
                || not (isSha256Digest startupFingerprint)
                || not (isSha256Digest observationFingerprint)
            then
                fail "Fail2Ban runtime baseline has an invalid digest"

            Some
                {
                    Fingerprint = fingerprint
                    StartupFingerprint = startupFingerprint
                    ObservationFingerprint = observationFingerprint
                }
        | _ -> fail "Fail2Ban ownership journal has an invalid runtime baseline"
    let private readJournal (environment: HostEnvironment) (ownerId: string) =
        let directory = mappedPath environment stateDirectory

        if not (requireExistingDirectoryPath directory) then
            None
        else
            let mode =
                try
                    File.GetUnixFileMode directory
                with _ ->
                    fail "cannot inspect Fail2Ban ownership state permissions"

            if mode <> journalDirectoryMode then
                fail "Fail2Ban ownership state has insecure permissions"

            let path = mappedPath environment journalPath

            match readFileAtPath path with
            | None -> None
            | Some text ->
                let fileMode =
                    try
                        File.GetUnixFileMode path
                    with _ ->
                        fail "cannot inspect Fail2Ban journal permissions"

                if fileMode <> journalFileMode then
                    fail "Fail2Ban ownership journal has insecure permissions"

                try
                    use document = JsonDocument.Parse text
                    let root = document.RootElement

                    if checkDuplicateProperties root then
                        fail "Fail2Ban ownership journal contains duplicate JSON properties"

                    let versionElement = root.GetProperty "version"

                    let version =
                        if versionElement.ValueKind = JsonValueKind.Number then
                            versionElement.GetInt32()
                        else
                            -1

                    if version <> 2 && version <> 3 then
                        fail "Fail2Ban ownership journal has an unsupported version"

                    let journalProperties =
                        if version = 2 then
                            set [ "version"; "ownerId"; "files"; "pending" ]
                        else
                            set [ "version"; "ownerId"; "files"; "runtimeBaseline"; "pending" ]

                    ensureExactProperties root journalProperties "Fail2Ban ownership journal"

                    let storedOwner = requiredString root "ownerId"
                    validateOwnerId storedOwner

                    if storedOwner <> ownerId then
                        fail "Fail2Ban configuration is already owned by another Pulumi resource"

                    let files =
                        expectObjectStringMap (root.GetProperty "files") "Fail2Ban journal files"

                    let runtimeBaseline =
                        if version = 2 then
                            None
                        else
                            readRuntimeBaseline (root.GetProperty "runtimeBaseline")

                    let pendingElement = root.GetProperty "pending"

                    let pending =
                        match pendingElement.ValueKind with
                        | JsonValueKind.Null -> None
                        | JsonValueKind.Object ->
                            ensureExactProperties
                                pendingElement
                                (set
                                    [
                                        "operation"
                                        "priorOwned"
                                        "priorActive"
                                        "priorEnabled"
                                        "startupChanged"
                                        "pythonChanged"
                                        "targetFiles"
                                        "mutations"
                                    ])
                                "Fail2Ban pending mutation"

                            let operation = requiredString pendingElement "operation"

                            if operation <> "apply" && operation <> "delete" then
                                fail "Fail2Ban ownership journal has an invalid operation"

                            let priorOwned = readBooleanProperty pendingElement "priorOwned"

                            let targetFiles =
                                expectObjectStringMap
                                    (pendingElement.GetProperty "targetFiles")
                                    "Fail2Ban pending target files"

                            let mutationsElement = pendingElement.GetProperty "mutations"

                            if mutationsElement.ValueKind <> JsonValueKind.Array then
                                fail "Fail2Ban pending mutations must be an array"

                            let mutations =
                                mutationsElement.EnumerateArray()
                                |> Seq.map (fun item ->
                                    ensureExactProperties
                                        item
                                        (set [ "path"; "prior"; "target" ])
                                        "Fail2Ban file mutation"

                                    {
                                        Path = validateRelativePath (requiredString item "path")
                                        Prior = readNullableString item "prior"
                                        Target = readNullableString item "target"
                                    })
                                |> Seq.toList

                            if
                                mutations.Length
                                <> (mutations
                                    |> List.map (fun mutation -> mutation.Path)
                                    |> List.distinct
                                    |> List.length)
                            then
                                fail "Fail2Ban pending mutations contain duplicate paths"

                            if not priorOwned && not (Map.isEmpty files) then
                                fail "Fail2Ban pending journal has inconsistent prior ownership"

                            if operation = "delete" && not (Map.isEmpty targetFiles) then
                                fail "Fail2Ban delete journal has target files"

                            let expectedMutations = computeMutations files targetFiles

                            if mutations <> expectedMutations then
                                fail "Fail2Ban pending journal mutations do not match their file snapshots"

                            Some
                                {
                                    Operation = operation
                                    PriorOwned = priorOwned
                                    PriorActive = readBooleanProperty pendingElement "priorActive"
                                    PriorEnabled = readBooleanProperty pendingElement "priorEnabled"
                                    StartupChanged = readBooleanProperty pendingElement "startupChanged"
                                    PythonChanged = readBooleanProperty pendingElement "pythonChanged"
                                    TargetFiles = targetFiles
                                    Mutations = mutations
                                }
                        | _ -> fail "Fail2Ban ownership journal has an invalid pending mutation"

                    match pending with
                    | Some state when state.Operation = "delete" && not state.PriorOwned ->
                        fail "Fail2Ban delete journal has no prior owner"
                    | _ -> ()

                    Some
                        {
                            OwnerId = storedOwner
                            Files = files
                            RuntimeBaseline = runtimeBaseline
                            Pending = pending
                        }
                with
                | :? BackendError -> reraise ()
                | _ -> fail "Fail2Ban ownership journal is malformed"

    let private writeJournalIfOwned (environment: HostEnvironment) (priorOwned: bool) (journal: Journal) =
        if priorOwned then
            saveJournal environment { journal with Pending = None }
        else
            deleteJournal environment

    let private verifyTrackedFiles (environment: HostEnvironment) (files: Map<string, string>) =
        for KeyValue(path, expected) in files do
            if
                readConfigFile environment path <> Some expected
                || not (hasManagedFileMode environment path)
            then
                fail "a Dorothy-owned Fail2Ban configuration file drifted; refusing to overwrite or delete it"

    let private verifyNewPathsAbsent
        (environment: HostEnvironment)
        (priorFiles: Map<string, string>)
        (targetFiles: Map<string, string>)
        =
        for KeyValue(path, _) in targetFiles do
            if
                not (priorFiles.ContainsKey path)
                && (readConfigFile environment path |> Option.isSome)
            then
                fail "a Fail2Ban target file already exists without Dorothy ownership; refusing takeover"

    let private currentFilesForJournal (environment: HostEnvironment) (journal: Journal option) =
        match journal with
        | None -> Map.empty
        | Some state ->
            let paths =
                match state.Pending with
                | None -> state.Files |> Map.toSeq |> Seq.map fst
                | Some pending ->
                    Seq.append
                        (state.Files |> Map.toSeq |> Seq.map fst)
                        (pending.Mutations |> Seq.map (fun mutation -> mutation.Path))

            paths
            |> Seq.distinct
            |> Seq.choose (fun path -> readConfigFile environment path |> Option.map (fun contents -> path, contents))
            |> Map.ofSeq

    let private ownedInJournal (journal: Journal option) =
        match journal with
        | None -> false
        | Some state ->
            state.Pending
            |> Option.map (fun pending -> pending.PriorOwned || pending.TargetFiles.Count > 0)
            |> Option.defaultValue true


    let private applyMutation (environment: HostEnvironment) (mutation: FileMutation) =
        writeConfigFile environment mutation.Path mutation.Prior mutation.Target

    let private restoreMutations (environment: HostEnvironment) (mutations: FileMutation list) =
        for mutation in mutations do
            let current = readConfigFile environment mutation.Path

            if current <> mutation.Prior && current <> mutation.Target then
                fail "a Fail2Ban file changed outside the journaled transaction; refusing recovery"

            if current.IsSome && not (hasManagedFileMode environment mutation.Path) then
                fail "a Fail2Ban file changed outside the journaled transaction; refusing recovery"

        for mutation in mutations do
            let current = readConfigFile environment mutation.Path

            if current <> mutation.Prior then
                writeConfigFile environment mutation.Path current mutation.Prior

    let private pythonFilesChanged (mutations: FileMutation list) =
        mutations
        |> List.exists (fun mutation ->
            mutation.Path.StartsWith("action.d/", StringComparison.Ordinal)
            && mutation.Path.EndsWith(".py", StringComparison.Ordinal)
            && mutation.Prior <> mutation.Target)

    let private ensureServiceState (environment: HostEnvironment) (expectedActive: bool) (expectedEnabled: bool) =
        let state = readServiceState environment

        if state.Active <> expectedActive then
            fail "Fail2Ban service did not reach its expected active state"

        if expectedActive && state.Failed then
            fail "Fail2Ban service entered a failed state"

        if state.Enabled <> expectedEnabled then
            fail "Fail2Ban service did not reach its expected enablement state"

        state

    let private waitForReadiness
        (environment: HostEnvironment)
        (expectedEnabled: bool)
        (configuration: Fail2BanNative.Configuration)
        (baseline: Fail2BanNative.RuntimeBaseline option)
        =
        let timer = Stopwatch.StartNew()
        let mutable delayMilliseconds = 100
        let mutable observation:
            (ServiceState * Fail2BanNative.Runtime * Fail2BanNative.RuntimeBaseline) option =
            None

        while observation.IsNone && timer.Elapsed < readinessTimeout do
            let state = readServiceState environment

            if state.Failed then
                fail "Fail2Ban service failed before native configuration became ready"

            if state.Enabled = expectedEnabled && state.Active then
                let runtime, capturedBaseline =
                    nativeObserve environment configRoot configuration baseline

                match capturedBaseline with
                | Some value when runtime.InSync -> observation <- Some(state, runtime, value)
                | _ -> ()

            if observation.IsNone && timer.Elapsed < readinessTimeout then
                let remaining = (readinessTimeout - timer.Elapsed).TotalMilliseconds

                if remaining > 0.0 then
                    Thread.Sleep(min delayMilliseconds (max 1 (int (Math.Ceiling remaining))))

                delayMilliseconds <- min 1000 (delayMilliseconds * 2)

        match observation with
        | Some result -> result
        | None -> fail "Fail2Ban service did not reach native readiness before the bounded deadline"


    let private recoverPending (environment: HostEnvironment) (journal: Journal) =
        match journal.Pending with
        | None -> Some journal
        | Some pending ->
            if pending.Operation = "delete" && not pending.PriorOwned then
                fail "Fail2Ban pending delete has no attributable prior owner"

            let changedPaths =
                pending.Mutations |> Seq.map (fun mutation -> mutation.Path) |> Set.ofSeq

            for KeyValue(path, expected) in journal.Files do
                if
                    not (changedPaths.Contains path)
                    && (readConfigFile environment path <> Some expected
                        || not (hasManagedFileMode environment path))
                then
                    fail "a Dorothy-owned Fail2Ban configuration file drifted; refusing recovery"

            let currentService = readServiceState environment

            let shouldStop =
                currentService.Active
                && (pending.StartupChanged || pending.PythonChanged || not pending.PriorActive)

            if shouldStop then
                changeServiceState environment "stop"

            restoreMutations environment pending.Mutations
            nativeValidate environment configRoot
            let restoredConfiguration = nativeInspect environment configRoot
            let afterRestore = readServiceState environment

            if pending.PriorActive then
                if pending.StartupChanged || pending.PythonChanged || not afterRestore.Active then
                    changeServiceState environment "start"
                elif pending.Mutations.Length > 0 then
                    nativeReload environment restoredConfiguration
            elif afterRestore.Active then
                changeServiceState environment "stop"

            let afterControl = readServiceState environment

            if afterControl.Enabled <> pending.PriorEnabled then
                setServiceEnabled environment pending.PriorEnabled

            if pending.PriorActive then
                waitForReadiness environment pending.PriorEnabled restoredConfiguration journal.RuntimeBaseline
                |> ignore
            else
                ensureServiceState environment false pending.PriorEnabled |> ignore

            match writeJournalIfOwned environment pending.PriorOwned journal with
            | _ when pending.PriorOwned -> Some { journal with Pending = None }
            | _ -> None

    let private jsonStringArray (values: string list) =
        let result = JsonArray()

        for value in values do
            result.Add(JsonValue.Create value)

        result

    let private snapshotNode
        (owned: bool)
        (actualFiles: Map<string, string>)
        (active: bool)
        (activeJails: string list)
        (socket: string)
        (inSync: bool)
        =
        let result = JsonObject()
        result["owned"] <- JsonValue.Create owned
        result["actualFiles"] <- serializeMap actualFiles
        result["active"] <- JsonValue.Create active
        result["activeJails"] <- jsonStringArray activeJails
        result["socket"] <- JsonValue.Create socket
        result["inSync"] <- JsonValue.Create inSync
        result

    let private observeCurrent
        (environment: HostEnvironment)
        (service: ServiceState)
        (configuration: Fail2BanNative.Configuration)
        (baseline: Fail2BanNative.RuntimeBaseline option)
        =
        if service.Active then
            Some(nativeObserve environment configRoot configuration baseline)
        else
            None

    let private readSnapshot (environment: HostEnvironment) (desired: Desired) =
        use _lock = HostFiles.lockFile (mappedPath environment lockPath)
        let journal = readJournal environment desired.OwnerId
        let targetFiles = effectiveFiles environment desired
        let pending = journal |> Option.exists (fun state -> state.Pending.IsSome)
        let actualFiles = currentFilesForJournal environment journal

        let configuration =
            if pending then
                try
                    Some(nativeInspect environment configRoot)
                with :? BackendError ->
                    None
            else
                nativeValidate environment configRoot
                Some(nativeInspect environment configRoot)

        let service = readServiceState environment
        let baseline = journal |> Option.bind (fun state -> state.RuntimeBaseline)

        let runtime =
            match configuration, service.Active with
            | Some config, true when pending ->
                try
                    let value, _ = nativeObserve environment configRoot config baseline
                    Some value
                with :? BackendError ->
                    None
            | Some config, true ->
                let value, _ = nativeObserve environment configRoot config baseline
                Some value
            | _ -> None

        let filesMatch =
            match journal with
            | Some state when state.Pending.IsNone && state.Files = targetFiles ->
                targetFiles
                |> Map.forall (fun path expected ->
                    readConfigFile environment path = Some expected
                    && hasManagedFileMode environment path)
            | _ -> false

        let owned = ownedInJournal journal
        let noPending = not pending
        let runtimeMatches =
            baseline.IsSome
            && (runtime |> Option.exists (fun value -> value.InSync))

        let inSync =
            owned
            && noPending
            && filesMatch
            && service.Active
            && service.Enabled
            && runtimeMatches

        let activeJails =
            runtime |> Option.map (fun value -> value.ActiveJails) |> Option.defaultValue []

        let socket =
            configuration
            |> Option.map (fun value -> value.Socket)
            |> Option.defaultValue ""

        snapshotNode owned actualFiles service.Active activeJails socket inSync :> JsonNode


    let private completeApply (environment: HostEnvironment) (desired: Desired) =
        use _lock = HostFiles.lockFile (mappedPath environment lockPath)

        let loaded =
            readJournal environment desired.OwnerId
            |> Option.bind (recoverPending environment)

        let targetFiles = effectiveFiles environment desired

        let priorFiles =
            loaded |> Option.map (fun state -> state.Files) |> Option.defaultValue Map.empty

        match loaded with
        | Some state -> verifyTrackedFiles environment state.Files
        | None -> ()

        verifyNewPathsAbsent environment priorFiles targetFiles
        let mutations = computeMutations priorFiles targetFiles

        let removals =
            mutations
            |> Seq.choose (fun mutation -> if mutation.Target.IsNone then Some mutation.Path else None)
            |> Set.ofSeq

        let serviceBefore = readServiceState environment
        nativeValidate environment configRoot
        let priorConfiguration = nativeInspect environment configRoot
        let priorBaseline = loaded |> Option.bind (fun state -> state.RuntimeBaseline)
        let runtimeBefore = observeCurrent environment serviceBefore priorConfiguration priorBaseline

        withStagedConfiguration environment targetFiles removals (fun _ targetConfiguration ->
            let startupChanged =
                priorConfiguration.StartupFingerprint <> targetConfiguration.StartupFingerprint

            let pythonChanged = pythonFilesChanged mutations
            let priorOwned = loaded.IsSome

            let pending =
                {
                    Operation = "apply"
                    PriorOwned = priorOwned
                    PriorActive = serviceBefore.Active
                    PriorEnabled = serviceBefore.Enabled
                    StartupChanged = startupChanged
                    PythonChanged = pythonChanged
                    TargetFiles = targetFiles
                    Mutations = mutations
                }

            let initial =
                {
                    OwnerId = desired.OwnerId
                    Files = priorFiles
                    RuntimeBaseline = priorBaseline
                    Pending = Some pending
                }

            saveJournal environment initial

            let mutable nativeAcknowledged = false

            try
                if (startupChanged || pythonChanged) && serviceBefore.Active then
                    changeServiceState environment "stop"

                if not serviceBefore.Enabled then
                    setServiceEnabled environment true

                for mutation in mutations do
                    applyMutation environment mutation

                nativeValidate environment configRoot
                let installedConfiguration = nativeInspect environment configRoot

                if
                    installedConfiguration.Fingerprint <> targetConfiguration.Fingerprint
                    || installedConfiguration.StartupFingerprint
                       <> targetConfiguration.StartupFingerprint
                then
                    fail "installed Fail2Ban configuration differs from its validated staged tree"

                if startupChanged || pythonChanged then
                    changeServiceState environment "start"
                    nativeAcknowledged <- true
                elif serviceBefore.Active then
                    let needsReload =
                        mutations.Length > 0
                        || priorBaseline.IsNone
                        || (runtimeBefore |> Option.exists (fun (runtime, _) -> not runtime.InSync))

                    if needsReload then
                        nativeReload environment installedConfiguration
                        nativeAcknowledged <- true
                else
                    changeServiceState environment "start"
                    nativeAcknowledged <- true

                let readinessBaseline = if nativeAcknowledged then None else priorBaseline

                let finalService, finalRuntime, capturedBaseline =
                    waitForReadiness environment true installedConfiguration readinessBaseline

                let finalBaseline =
                    if nativeAcknowledged then
                        capturedBaseline
                    else
                        match priorBaseline with
                        | Some value -> value
                        | None -> fail "Fail2Ban runtime baseline is unavailable after no-op apply"

                let currentOwnedFiles =
                    currentFilesForJournal
                        environment
                        (Some
                            { initial with
                                Files = targetFiles
                                Pending = None
                            })

                if currentOwnedFiles <> targetFiles then
                    fail "Fail2Ban owned files do not match the requested map"

                let response =
                    snapshotNode
                        true
                        currentOwnedFiles
                        finalService.Active
                        finalRuntime.ActiveJails
                        installedConfiguration.Socket
                        true

                saveJournal
                    environment
                    { initial with
                        Files = targetFiles
                        RuntimeBaseline = Some finalBaseline
                        Pending = None
                    }

                response :> JsonNode
            with error ->
                try
                    recoverPending environment initial |> ignore
                with _ ->
                    fail "Fail2Ban apply failed and attributable rollback is pending"

                match error with
                | :? BackendError as backendError ->
                    fail ("Fail2Ban apply failed; previous state was restored: " + backendError.Message)
                | _ -> fail "Fail2Ban apply failed; previous state was restored")

    let private completeDelete (environment: HostEnvironment) (desired: Desired) =
        use _lock = HostFiles.lockFile (mappedPath environment lockPath)

        let loaded =
            readJournal environment desired.OwnerId
            |> Option.bind (recoverPending environment)

        match loaded with
        | None -> JsonObject() :> JsonNode
        | Some state ->
            verifyTrackedFiles environment state.Files
            let targetFiles = Map.empty<string, string>
            let mutations = computeMutations state.Files targetFiles

            let removals =
                mutations
                |> Seq.choose (fun mutation -> if mutation.Target.IsNone then Some mutation.Path else None)
                |> Set.ofSeq

            let serviceBefore = readServiceState environment
            nativeValidate environment configRoot
            let priorConfiguration = nativeInspect environment configRoot
            let priorBaseline = state.RuntimeBaseline
            let runtimeBefore = observeCurrent environment serviceBefore priorConfiguration priorBaseline

            withStagedConfiguration environment targetFiles removals (fun _ targetConfiguration ->
                let startupChanged =
                    priorConfiguration.StartupFingerprint <> targetConfiguration.StartupFingerprint

                let pythonChanged = pythonFilesChanged mutations

                let pending =
                    {
                        Operation = "delete"
                        PriorOwned = true
                        PriorActive = serviceBefore.Active
                        PriorEnabled = serviceBefore.Enabled
                        StartupChanged = startupChanged
                        PythonChanged = pythonChanged
                        TargetFiles = targetFiles
                        Mutations = mutations
                    }

                let initial = { state with Pending = Some pending }
                saveJournal environment initial

                try
                    if (startupChanged || pythonChanged) && serviceBefore.Active then
                        changeServiceState environment "stop"

                    for mutation in mutations do
                        applyMutation environment mutation

                    nativeValidate environment configRoot
                    let installedConfiguration = nativeInspect environment configRoot

                    if
                        installedConfiguration.Fingerprint <> targetConfiguration.Fingerprint
                        || installedConfiguration.StartupFingerprint
                           <> targetConfiguration.StartupFingerprint
                    then
                        fail "installed Fail2Ban configuration differs from its validated staged tree"

                    if startupChanged || pythonChanged then
                        if serviceBefore.Active then
                            changeServiceState environment "start"
                    elif
                        serviceBefore.Active
                        && (mutations.Length > 0
                            || (runtimeBefore |> Option.exists (fun (runtime, _) -> not runtime.InSync)))
                    then
                        nativeReload environment installedConfiguration

                    if serviceBefore.Active then
                        waitForReadiness environment serviceBefore.Enabled installedConfiguration None
                        |> ignore
                    else
                        ensureServiceState environment false serviceBefore.Enabled |> ignore

                    for mutation in mutations do
                        if readConfigFile environment mutation.Path <> mutation.Target then
                            fail "Fail2Ban deletion left a Dorothy-owned configuration file behind"

                    deleteJournal environment
                    JsonObject() :> JsonNode
                with error ->
                    try
                        recoverPending environment initial |> ignore
                    with _ ->
                        fail "Fail2Ban deletion failed and attributable rollback is pending"

                    match error with
                    | :? BackendError as backendError ->
                        fail ("Fail2Ban deletion failed; previous state was restored: " + backendError.Message)
                    | _ -> fail "Fail2Ban deletion failed; previous state was restored")

    let handle (environment: HostEnvironment) (request: JsonElement) : JsonNode =
        try
            let operation, desired = parseRequest request

            match operation with
            | "read" -> readSnapshot environment desired
            | "apply" -> completeApply environment desired
            | "delete" -> completeDelete environment desired
            | _ -> fail "unsupported Fail2Ban operation"
        with
        | :? BackendError -> reraise ()
        | :? Fail2BanNative.BackendError -> fail "Fail2Ban native operation failed"
        | _ -> fail "Fail2Ban helper operation failed"
