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
open System.Text.RegularExpressions

type BackendError(message: string) =
    inherit Exception(message)

type PackageRecord =
    { BinaryName: string
      Name: string
      Architecture: string
      Status: string
      Version: string
      Essential: bool
      Protected: bool }

type PackageState =
    { NativeArchitecture: string
      Records: Map<string, PackageRecord>
      ByName: Map<string, PackageRecord list> }

type AptPlan =
    { Installs: (string * string option) list
      Removals: string list
      Arguments: string list }
type AptSnapshot =
    { InstalledVersions: Map<string, string>
      ManagedPackages: string list }

module Apt =
    [<Literal>]
    let private AptLockTimeoutSeconds = 120

    [<Literal>]
    let private HostLockPath = "/run/lock/keroosha-apt-backend.lock"

    [<Literal>]
    let private JournalDirectory = "/var/lib/keroosha-iac/apt"

    let private packageNamePattern = Regex("\\A[a-z0-9][a-z0-9+.-]{1,254}\\z", RegexOptions.CultureInvariant)
    let private debianVersionPattern = Regex("\\A(?:[0-9]+:)?[0-9][A-Za-z0-9.+~-]*(?:-[A-Za-z0-9+.~]+)?\\z", RegexOptions.CultureInvariant)
    let private strictUtf8 = UTF8Encoding(false, true)

    module private Unix =
        [<Struct; StructLayout(LayoutKind.Sequential, Size = 256)>]
        type private AptStatx =
            val mutable Mask: uint32
            val mutable BlockSize: uint32
            val mutable Attributes: uint64
            val mutable LinkCount: uint32
            val mutable UserId: uint32
            val mutable GroupId: uint32
            val mutable Mode: uint16

        [<DllImport("libc", EntryPoint = "statx", SetLastError = true)>]
        extern int private nativeStatx (int directoryFileDescriptor, string path, int flags, uint32 mask, AptStatx& result)

        let private inspectPath path =
            let mutable status = Unchecked.defaultof<AptStatx>
            let result = nativeStatx(-100, path, 0x100, 0x9u, &status)

            if result <> 0 then
                let code = Marshal.GetLastPInvokeError()
                raise (IOException("cannot inspect filesystem path " + path + " (errno " + code.ToString(CultureInfo.InvariantCulture) + ")"))

            status

        let fileType path = inspectPath path |> fun status -> status.Mode &&& 0xF000us
        let userId path = inspectPath path |> fun status -> status.UserId

        [<DllImport("libc", EntryPoint = "geteuid")>]
        extern uint32 getEffectiveUserId()

        [<DllImport("libc", EntryPoint = "open", SetLastError = true)>]
        extern int openDirectory(string path, int flags)

        [<DllImport("libc", EntryPoint = "fsync", SetLastError = true)>]
        extern int synchronize(int descriptor)

        [<DllImport("libc", EntryPoint = "close", SetLastError = true)>]
        extern int closeDescriptor(int descriptor)

    let private fail message = raise (BackendError message)

    let validatePackageName (name: string) =
        if isNull name then
            fail "package name must be a string"

        if name.Contains(':') then
            fail "multiarch package names are unsupported"

        if not (packageNamePattern.IsMatch(name)) then
            fail "unsafe or unsupported Debian package name; use a concrete unqualified package name"

        name

    let validateVersion (version: string) =
        if isNull version || not (debianVersionPattern.IsMatch(version)) then
            fail "unsafe or invalid Debian version"

        version

    let private runCommand (environment: HostEnvironment) (program: string) (arguments: string list) (allowFailure: bool) (aptCommand: bool) =
        let actualArguments =
            if aptCommand then
                [ "-o"
                  "DPkg::Lock::Timeout=" + AptLockTimeoutSeconds.ToString(CultureInfo.InvariantCulture)
                  "-o"
                  "APT::Get::Lock-Timeout=" + AptLockTimeoutSeconds.ToString(CultureInfo.InvariantCulture) ]
                @ arguments
            else
                arguments

        let result =
            try
                environment.Run program actualArguments None
            with
            | _ -> fail ("cannot run " + program)

        if result.ExitCode <> 0 && not allowFailure then
            let commandName =
                match actualArguments with
                | first :: _ -> program + " " + first
                | [] -> program

            fail (commandName + " failed (exit status " + result.ExitCode.ToString(CultureInfo.InvariantCulture) + ")")

        result

    let private mappedPath (environment: HostEnvironment) (logicalPath: string) =
        HostEnvironment.path environment logicalPath

    let private isProductionRoot (environment: HostEnvironment) =
        Path.GetFullPath(environment.Root) = Path.DirectorySeparatorChar.ToString()

    let private requireRootIfProduction (environment: HostEnvironment) =
        if isProductionRoot environment && Unix.getEffectiveUserId() <> 0u then
            fail "the APT ownership journal requires root privileges"

    let private requireDebian (environment: HostEnvironment) =
        let releasePath = mappedPath environment "/etc/os-release"

        let lines =
            try
                File.ReadAllLines(releasePath)
            with error ->
                fail ("cannot read /etc/os-release to verify Debian: " + error.Message)

        let mutable found = "unknown"

        for line in lines do
            if line.StartsWith("ID=", StringComparison.Ordinal) then
                let raw = line.Substring(3).Trim()

                let value =
                    if raw.Length >= 2
                       && ((raw[0] = '"' && raw[raw.Length - 1] = '"')
                           || (raw[0] = '\'' && raw[raw.Length - 1] = '\'')) then
                        raw.Substring(1, raw.Length - 2)
                    else
                        let commentIndex = raw.IndexOf('#')

                        if commentIndex >= 0 then
                            raw.Substring(0, commentIndex).Trim()
                        else
                            raw.Trim()

                found <- value
                ()

        if not (String.Equals(found.Trim(), "debian", StringComparison.OrdinalIgnoreCase)) then
            fail ("APT backend requires Debian (detected ID=" + found + ")")

    let private checkNativeArchitecture (environment: HostEnvironment) =
        let result = runCommand environment "dpkg" [ "--print-architecture" ] false false
        let architecture = result.Stdout.Trim()

        if String.IsNullOrWhiteSpace(architecture) then
            fail "dpkg did not report the native architecture"

        architecture

    let private isYes (value: string) =
        String.Equals(value.Trim(), "yes", StringComparison.OrdinalIgnoreCase)

    let readPackageState (environment: HostEnvironment) =
        let nativeArchitecture = checkNativeArchitecture environment

        let formatString =
            "${binary:Package}\\t${Architecture}\\t${db:Status-Abbrev}\\t${Version}\\t${Essential}\\t${Protected}\\n"

        let result = runCommand environment "dpkg-query" [ "-W"; "-f=" + formatString ] false false
        let mutable records = Map.empty
        let mutable byName = Map.empty

        for line in result.Stdout.Split([| '\n'; '\r' |], StringSplitOptions.RemoveEmptyEntries) do
            let fields = line.Split('\t')

            if fields.Length <> 6 then
                fail "dpkg-query returned an unparseable package record"

            let binaryName, architecture, status, version, essential, protectedFlag =
                fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]

            if String.IsNullOrEmpty(binaryName) then
                fail "dpkg-query returned a package without a name"

            let suffix = ":" + architecture

            let packageName =
                if not (String.IsNullOrEmpty(architecture)) && binaryName.EndsWith(suffix, StringComparison.Ordinal) then
                    binaryName.Substring(0, binaryName.Length - suffix.Length)
                else
                    binaryName

            let record =
                { BinaryName = binaryName
                  Name = packageName
                  Architecture = architecture
                  Status = status
                  Version = version
                  Essential = isYes essential
                  Protected = isYes protectedFlag }

            records <- Map.add binaryName record records
            let previous = Map.tryFind packageName byName |> Option.defaultValue []
            byName <- Map.add packageName (previous @ [ record ]) byName

        { NativeArchitecture = nativeArchitecture
          Records = records
          ByName = byName }

    let isHealthyInstalledStatus (status: string) =
        if isNull status || status.Length <> 3 then
            fail "dpkg reports incomplete package status"

        if status[1] = 'n' || status[1] = 'c' then
            if status[2] = ' ' then
                false
            else
                fail "dpkg reports incomplete package status"
        elif status[1] = 'i' && status[2] = ' ' then
            true
        else
            fail "dpkg reports incomplete package status"

    let isDpkgPresentStatus (status: string) =
        if isNull status || status.Length <> 3 || (status[2] <> ' ' && status[2] <> 'R') then
            fail "dpkg reports incomplete package status"

        if status[1] = 'n' || status[1] = 'c' then
            if status[2] = ' ' then
                false
            else
                fail "dpkg reports incomplete package status"
        elif status[1] = 'i' || status[1] = 'H' || status[1] = 'U' || status[1] = 'F' || status[1] = 'W' || status[1] = 't' then
            true
        else
            fail "dpkg reports incomplete package status"

    let private requireSingleArchitecture (matches: PackageRecord list) =
        if matches.Length > 1 then
            fail "multiarch package management is unsupported"

    let packageRecord (state: PackageState) name =
        let matches = Map.tryFind name state.ByName |> Option.defaultValue []
        requireSingleArchitecture matches

        match matches with
        | [] -> None
        | [ record ] ->
            if not (isHealthyInstalledStatus record.Status) then
                None
            elif record.Architecture <> state.NativeArchitecture && record.Architecture <> "all" then
                fail "package is installed for a non-native architecture"
            elif String.IsNullOrEmpty(record.Version) then
                fail "dpkg reports no installed version for a package"
            else
                Some record
        | _ -> None

    let removableRecord (state: PackageState) name =
        let matches = Map.tryFind name state.ByName |> Option.defaultValue []
        requireSingleArchitecture matches

        match matches with
        | [] -> None
        | [ record ] ->
            if not (isDpkgPresentStatus record.Status) then
                None
            elif record.Architecture <> state.NativeArchitecture && record.Architecture <> "all" then
                fail "package is present for a non-native architecture"
            else
                Some record
        | _ -> None

    let installedMap (state: PackageState) (names: string list) =
        names
        |> List.choose (fun name -> packageRecord state name |> Option.map (fun record -> name, record.Version))
        |> Map.ofList

    let planTransaction (previousNames: string list) (desiredVersions: Map<string, string option>) (state: PackageState) =
        let desiredNames = desiredVersions |> Map.toSeq |> Seq.map fst |> Set.ofSeq
        let removeNames = Set.difference (Set.ofList previousNames) desiredNames |> Set.toList |> List.sort

        let installs =
            desiredVersions
            |> Map.toList
            |> List.choose (fun (name, desiredVersion) ->
                let record = packageRecord state name

                match record, desiredVersion with
                | None, _ -> Some(name, desiredVersion)
                | Some installed, Some exactVersion when installed.Version <> exactVersion -> Some(name, desiredVersion)
                | _ -> None)

        let actualRemovals =
            removeNames
            |> List.choose (fun name -> removableRecord state name |> Option.map (fun _ -> name))

        for name in actualRemovals do
            let record = removableRecord state name |> Option.get

            if record.Essential || record.Protected then
                fail "refusing to remove an essential or protected package"

        let installArguments =
            installs
            |> List.map (fun (name, version) ->
                match version with
                | Some exactVersion -> name + "=" + exactVersion
                | None -> name)

        let arguments = installArguments @ (actualRemovals |> List.map (fun name -> name + "-"))

        { Installs = installs
          Removals = actualRemovals
          Arguments = arguments }

    let private canonicalSimulatedName (name: string) = name.Split(':')[0]

    let validateSimulation
        (versionIsLess: string -> string -> bool)
        (output: string)
        (allowedRemovals: string list)
        (desiredVersions: Map<string, string option>)
        =
        let allowed = Set.ofList allowedRemovals
        let mutable allowDowngrades = false

        for line in output.Split('\n') do
            let fields =
                Regex.Split(line.Trim(), "\\s+")
                |> Array.filter (fun field -> not (String.IsNullOrEmpty(field)))

            if fields.Length >= 2 && fields[0] = "Remv" then
                let name = canonicalSimulatedName fields[1]

                if not (Set.contains name allowed) then
                    fail "APT simulation would remove an unmanaged package"

            if fields.Length >= 4 && fields[0] = "Inst" && fields[2].StartsWith("[", StringComparison.Ordinal) then
                let name = canonicalSimulatedName fields[1]
                let oldVersion = fields[2].Trim([| '['; ']' |])
                let newVersion = fields[3].Trim([| '('; ')' |])
                let requestedVersion = Map.tryFind name desiredVersions |> Option.flatten

                if oldVersion <> newVersion && requestedVersion <> Some newVersion then
                    fail "APT simulation would change an existing package without an exact requested version"

                if oldVersion <> newVersion && versionIsLess newVersion oldVersion then
                    if requestedVersion <> Some newVersion then
                        fail "APT simulation would downgrade a package without the exact requested version"

                    allowDowngrades <- true

        allowDowngrades

    let validateSimulatedProtection (output: string) (state: PackageState) =
        for line in output.Split('\n') do
            let fields =
                Regex.Split(line.Trim(), "\\s+")
                |> Array.filter (fun field -> not (String.IsNullOrEmpty(field)))

            if fields.Length >= 2 && fields[0] = "Remv" then
                let name = canonicalSimulatedName fields[1]

                for record in Map.tryFind name state.ByName |> Option.defaultValue [] do
                    if record.Essential || record.Protected then
                        fail "APT simulation would remove an essential or protected package"

    let verifyTransaction
        (before: PackageState)
        (after: PackageState)
        (desiredVersions: Map<string, string option>)
        (removeNames: string list)
        =
        for name in removeNames do
            if packageRecord after name |> Option.isSome then
                fail "APT transaction did not remove a previously managed package"

        for KeyValue(name, desiredVersion) in desiredVersions do
            match packageRecord after name with
            | None -> fail "APT transaction did not install a requested package"
            | Some record ->
                match desiredVersion with
                | Some exactVersion when record.Version <> exactVersion ->
                    fail "APT installed a package version different from the exact requested version"
                | _ -> ()

        let allowed = Set.ofList removeNames

        for KeyValue(binaryName, record) in before.Records do
            let wasPresent = isDpkgPresentStatus record.Status

            let remainsPresent =
                match Map.tryFind binaryName after.Records with
                | Some afterRecord -> isDpkgPresentStatus afterRecord.Status
                | None -> false

            if wasPresent && not remainsPresent then
                if not (Set.contains record.Name allowed) then
                    fail "APT transaction removed an unmanaged package"

                if record.Essential || record.Protected then
                    fail "APT transaction removed an essential or protected package"

    let private pathExists (path: string) : bool =
        try
            File.GetAttributes(path) |> ignore
            true
        with
        | :? FileNotFoundException
        | :? DirectoryNotFoundException -> false

    let private syncDirectory (path: string) =
        let descriptor = Unix.openDirectory(path, 0x10000)

        if descriptor < 0 then
            let code = Marshal.GetLastPInvokeError()
            raise (IOException("cannot open directory " + path + " for synchronization (errno " + code.ToString(CultureInfo.InvariantCulture) + ")"))

        try
            if Unix.synchronize descriptor <> 0 then
                let code = Marshal.GetLastPInvokeError()
                raise (IOException("cannot synchronize directory " + path + " (errno " + code.ToString(CultureInfo.InvariantCulture) + ")"))
        finally
            Unix.closeDescriptor descriptor |> ignore

    let private requireRootOwnedPath (environment: HostEnvironment) path =
        if isProductionRoot environment && Unix.userId path <> 0u then
            fail ("APT ownership journal path " + path + " must be root-owned")

    let private secureDirectory (environment: HostEnvironment) (directory: string) (repairPermissions: bool) =
        let fileType =
            try
                Unix.fileType directory
            with error ->
                fail ("cannot inspect the APT journal directory: " + error.Message)

        if fileType <> 0x4000us then
            fail "APT journal path must be a root-owned real directory"

        requireRootOwnedPath environment directory

        let mutable mode =
            try
                File.GetUnixFileMode(directory)
            with error ->
                fail ("cannot inspect the APT journal directory permissions: " + error.Message)

        let groupOrOther =
            UnixFileMode.GroupRead
            ||| UnixFileMode.GroupWrite
            ||| UnixFileMode.GroupExecute
            ||| UnixFileMode.OtherRead
            ||| UnixFileMode.OtherWrite
            ||| UnixFileMode.OtherExecute

        if repairPermissions && (mode &&& groupOrOther) <> enum<UnixFileMode> 0 then
            try
                File.SetUnixFileMode(directory, UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute)
                mode <- File.GetUnixFileMode(directory)
            with error ->
                fail ("cannot secure the APT journal directory: " + error.Message)

        if (mode &&& groupOrOther) <> enum<UnixFileMode> 0 then
            fail "APT journal directory permissions must be root-only (0700)"

    let private secureJournalFile (environment: HostEnvironment) (path: string) (repairPermissions: bool) =
        let fileType =
            try
                Unix.fileType path
            with error ->
                fail ("cannot inspect APT ownership journal: " + error.Message)

        if fileType <> 0x8000us then
            fail "APT ownership journal must be a root-owned regular file"

        requireRootOwnedPath environment path

        let mutable mode =
            try
                File.GetUnixFileMode(path)
            with error ->
                fail ("cannot inspect APT ownership journal permissions: " + error.Message)

        let groupOrOther =
            UnixFileMode.GroupRead
            ||| UnixFileMode.GroupWrite
            ||| UnixFileMode.GroupExecute
            ||| UnixFileMode.OtherRead
            ||| UnixFileMode.OtherWrite
            ||| UnixFileMode.OtherExecute

        if repairPermissions && (mode &&& groupOrOther) <> enum<UnixFileMode> 0 then
            try
                File.SetUnixFileMode(path, UnixFileMode.UserRead ||| UnixFileMode.UserWrite)
                mode <- File.GetUnixFileMode(path)
            with error ->
                fail ("cannot secure APT ownership journal: " + error.Message)

        if (mode &&& groupOrOther) <> enum<UnixFileMode> 0 then
            fail "APT ownership journal permissions must be root-only (0600)"

    let private ensureJournalDirectory (environment: HostEnvironment) (create: bool) =
        requireRootIfProduction environment
        let directory = mappedPath environment JournalDirectory

        if not (pathExists directory) then
            if not create then
                None
            else
                let parentDirectory = Path.GetDirectoryName(directory)
                let parentExisted = pathExists parentDirectory

                try
                    Directory.CreateDirectory(directory) |> ignore
                    File.SetUnixFileMode(directory, UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute)

                    try
                        syncDirectory parentDirectory

                        if not parentExisted then
                            let grandparent = Path.GetDirectoryName(parentDirectory)
                            syncDirectory grandparent
                    with error ->
                        raise (IOException("cannot sync created APT journal directory hierarchy: " + error.Message))
                with error ->
                    fail ("cannot create or sync the root-only APT journal directory: " + error.Message)

                secureDirectory environment directory true
                Some directory
        else
            secureDirectory environment directory create
            Some directory

    let private journalPath (environment: HostEnvironment) ownerId =
        if String.IsNullOrEmpty(ownerId) then
            fail "ownerId must be a non-empty Pulumi resource ID"

        let digest =
            try
                SHA256.HashData(strictUtf8.GetBytes(ownerId)) |> Convert.ToHexString |> fun value -> value.ToLowerInvariant()
            with
            | :? EncoderFallbackException -> fail "ownerId is not valid UTF-8"

        mappedPath environment (JournalDirectory + "/" + digest + ".json")

    let private validateJournalPackages (packages: string list) =
        let validated = packages |> List.map validatePackageName

        if validated.Length <> (validated |> Set.ofList |> Set.count)
           || validated <> List.sort validated then
            fail "APT ownership journal managedPackages must be sorted and unique"

        validated

    let private loadJournal (environment: HostEnvironment) ownerId (createDirectory: bool) =
        let path = journalPath environment ownerId

        match ensureJournalDirectory environment createDirectory with
        | None -> []
        | Some _ when not (pathExists path) -> []
        | Some _ ->
            secureJournalFile environment path createDirectory

            let text =
                try
                    File.ReadAllText(path, strictUtf8)
                with error ->
                    fail ("cannot read APT ownership journal: " + error.Message)

            try
                use document = JsonDocument.Parse(text)
                let root = document.RootElement

                if root.ValueKind <> JsonValueKind.Object then
                    fail "APT ownership journal has an unsupported format"

                let properties = HashSet<string>(StringComparer.Ordinal)

                for property in root.EnumerateObject() do
                    if not (properties.Add(property.Name)) then
                        fail ("APT ownership journal contains duplicate JSON property " + property.Name)

                let expected = Set.ofList [ "schemaVersion"; "ownerId"; "managedPackages" ]

                if Set.ofSeq properties <> expected then
                    fail "APT ownership journal has an unsupported format"

                let schemaVersion = root.GetProperty("schemaVersion")
                let mutable schemaNumber = 0

                if schemaVersion.ValueKind <> JsonValueKind.Number
                   || not (schemaVersion.TryGetInt32(&schemaNumber))
                   || schemaNumber <> 1 then
                    fail "APT ownership journal has an unsupported schema version"

                let recordedOwner = root.GetProperty("ownerId")

                if recordedOwner.ValueKind <> JsonValueKind.String || recordedOwner.GetString() <> ownerId then
                    fail "APT ownership journal ownerId does not match the Pulumi resource"

                let managedPackages = root.GetProperty("managedPackages")

                if managedPackages.ValueKind <> JsonValueKind.Array then
                    fail "APT ownership journal managedPackages must be an array"

                let packages =
                    managedPackages.EnumerateArray()
                    |> Seq.map (fun item ->
                        if item.ValueKind <> JsonValueKind.String then
                            fail "package name must be a string"

                        let name = item.GetString()

                        if isNull name then
                            fail "package name must be a string"

                        validatePackageName name)
                    |> Seq.toList

                validateJournalPackages packages
            with
            | :? BackendError -> reraise ()
            | :? JsonException as error -> fail ("cannot read APT ownership journal: " + error.Message)

    let private saveJournal (environment: HostEnvironment) ownerId (managedPackages: seq<string>) =
        let path = journalPath environment ownerId
        let directory = ensureJournalDirectory environment true |> Option.get
        let packages = managedPackages |> Seq.map validatePackageName |> Set.ofSeq |> Set.toList

        use stream = new MemoryStream()
        use writer = new Utf8JsonWriter(stream)
        writer.WriteStartObject()
        writer.WritePropertyName("managedPackages")
        writer.WriteStartArray()

        for package in packages do
            writer.WriteStringValue(package)

        writer.WriteEndArray()
        writer.WriteString("ownerId", ownerId)
        writer.WriteNumber("schemaVersion", 1)
        writer.WriteEndObject()
        writer.Flush()
        stream.WriteByte(byte '\n')
        let bytes = stream.ToArray()

        try
            HostFiles.atomicWrite path bytes (UnixFileMode.UserRead ||| UnixFileMode.UserWrite)
        with error ->
            fail ("cannot atomically persist APT ownership journal: " + error.Message)

        secureJournalFile environment path false
        secureDirectory environment directory false

    let private removeJournal (environment: HostEnvironment) ownerId =
        let path = journalPath environment ownerId

        match ensureJournalDirectory environment false with
        | None -> ()
        | Some _ when not (pathExists path) -> ()
        | Some directory ->
            secureJournalFile environment path false

            try
                File.Delete(path)
                syncDirectory directory
            with error ->
                fail ("cannot remove empty APT ownership journal: " + error.Message)

    let private commitJournal environment ownerId (managedPackages: seq<string>) =
        let packages = managedPackages |> Seq.distinct |> Seq.sort |> Seq.toList

        if List.isEmpty packages then
            removeJournal environment ownerId
        else
            saveJournal environment ownerId packages

    let private jsonPropertyOrUndefined (request: JsonElement) (name: string) =
        let mutable value = Unchecked.defaultof<JsonElement>
        if request.TryGetProperty(name, &value) then value else Unchecked.defaultof<JsonElement>

    let private ownerIdFromRequest (request: JsonElement) =
        let value = jsonPropertyOrUndefined request "ownerId"

        if value.ValueKind <> JsonValueKind.String then
            fail "ownerId must be a non-empty Pulumi resource ID"

        let ownerId = value.GetString()

        if String.IsNullOrEmpty(ownerId) then
            fail "ownerId must be a non-empty Pulumi resource ID"

        ownerId

    let private packageNamesFromRequest (request: JsonElement) propertyName errorMessage =
        let value = jsonPropertyOrUndefined request propertyName

        if value.ValueKind <> JsonValueKind.Array then
            fail errorMessage

        value.EnumerateArray()
        |> Seq.map (fun item ->
            if item.ValueKind <> JsonValueKind.String then
                fail "package name must be a string"

            let name = item.GetString()

            if isNull name then
                fail "package name must be a string"

            validatePackageName name)
        |> Seq.toList

    let private desiredVersionsFromRequest (request: JsonElement) =
        let value = jsonPropertyOrUndefined request "desiredVersions"

        if value.ValueKind <> JsonValueKind.Object then
            fail "apply request desiredVersions must be an object"

        value.EnumerateObject()
        |> Seq.fold (fun desired property ->
            let name = validatePackageName property.Name

            let version =
                match property.Value.ValueKind with
                | JsonValueKind.Null -> None
                | JsonValueKind.String ->
                    let exactVersion = property.Value.GetString()

                    if isNull exactVersion then
                        fail "unsafe or invalid Debian version"

                    Some(validateVersion exactVersion)
                | _ -> fail "unsafe or invalid Debian version"

            Map.add name version desired) Map.empty

    let private readRequest (environment: HostEnvironment) (request: JsonElement) =
        let ownerId = ownerIdFromRequest request
        let names = packageNamesFromRequest request "names" "read request names must be an array"
        requireDebian environment
        let journalNames = loadJournal environment ownerId false
        let managedPackages = Set.union (Set.ofList journalNames) (Set.ofList names) |> Set.toList
        let state = readPackageState environment

        { InstalledVersions = installedMap state managedPackages
          ManagedPackages = managedPackages }

    let private aptCacheVersions (environment: HostEnvironment) name =
        let result = runCommand environment "apt-cache" [ "show"; name ] true false
        let versions = ResizeArray<string>()

        for stanza in Regex.Split(result.Stdout, "\\n\\s*\\n") do
            let mutable package: string option = None
            let mutable version: string option = None

            for line in stanza.Split('\n') do
                if line.StartsWith("Package: ", StringComparison.Ordinal) then
                    package <- Some(line.Substring("Package: ".Length).Trim())
                elif line.StartsWith("Version: ", StringComparison.Ordinal) then
                    version <- Some(line.Substring("Version: ".Length).Trim())

            match package, version with
            | Some foundPackage, Some foundVersion when foundPackage = name && not (String.IsNullOrEmpty(foundVersion)) ->
                versions.Add(foundVersion)
            | _ -> ()

        Set.ofSeq versions

    let private updateIndexes environment =
        runCommand environment "apt-get" [ "update" ] false true |> ignore

    let private versionIsLess (environment: HostEnvironment) left right =
        let result = runCommand environment "dpkg" [ "--compare-versions"; left; "lt"; right ] true false

        match result.ExitCode with
        | 0 -> true
        | 1 -> false
        | code ->
            fail ("dpkg could not compare package versions (exit status " + code.ToString(CultureInfo.InvariantCulture) + ")")

    let private applyRequest (environment: HostEnvironment) (request: JsonElement) =
        let ownerId = ownerIdFromRequest request
        let previousNames = packageNamesFromRequest request "previousNames" "apply request previousNames must be an array"
        let desired = desiredVersionsFromRequest request
        requireDebian environment
        let logicalLockDirectory = Path.GetDirectoryName(HostLockPath)
        let lockDirectory = mappedPath environment logicalLockDirectory

        if not (Directory.Exists(lockDirectory)) then
            fail "required host lock directory /run/lock is unavailable"

        let lockPath = mappedPath environment HostLockPath

        use hostLock =
            try
                HostFiles.lockFile lockPath
            with
            | :? TimeoutException -> fail "timed out waiting for the Dorothy APT serialization lock"
            | error -> fail ("cannot open APT serialization lock " + HostLockPath + ": " + error.Message)

        let journalNames = loadJournal environment ownerId true
        let effectiveOwned = Set.union (Set.ofList journalNames) (Set.ofList previousNames) |> Set.toList
        let before = readPackageState environment
        let plan = planTransaction effectiveOwned desired before

        if not (List.isEmpty plan.Installs) then
            updateIndexes environment

            for name, version in plan.Installs do
                let available = aptCacheVersions environment name

                if Set.isEmpty available then
                    fail "package is not a concrete package in configured APT indexes; virtual packages and unavailable package names are unsupported"

                match version with
                | Some exactVersion when not (Set.contains exactVersion available) ->
                    fail "exact requested package version is not available in configured APT indexes"
                | _ -> ()

        let after =
            if List.isEmpty plan.Arguments then
                before
            else
                let simulationArguments = [ "-s"; "install" ] @ plan.Arguments
                let simulation = runCommand environment "apt-get" simulationArguments false true
                let allowDowngrades = validateSimulation (versionIsLess environment) simulation.Stdout plan.Removals desired
                validateSimulatedProtection simulation.Stdout before
                let attemptedOwnership =
                    Set.union (Set.ofList effectiveOwned) (desired |> Map.toSeq |> Seq.map fst |> Set.ofSeq)

                saveJournal environment ownerId attemptedOwnership

                let mutable realArguments = [ "-y" ]

                if allowDowngrades then
                    realArguments <- realArguments @ [ "--allow-downgrades" ]

                if List.isEmpty plan.Removals then
                    realArguments <- realArguments @ [ "--no-remove" ]

                realArguments <- realArguments @ [ "install" ] @ plan.Arguments
                runCommand environment "apt-get" realArguments false true |> ignore
                let resultingState = readPackageState environment
                verifyTransaction before resultingState desired plan.Removals
                resultingState

        let desiredNames = desired |> Map.toSeq |> Seq.map fst |> Seq.toList
        commitJournal environment ownerId desiredNames

        { InstalledVersions = installedMap after desiredNames
          ManagedPackages = desiredNames }

    let private toJsonNode (snapshot: AptSnapshot) =
        let installedVersions = JsonObject()

        for KeyValue(name, version) in snapshot.InstalledVersions do
            installedVersions.Add(name, JsonValue.Create(version))

        let managedPackages = JsonArray()

        for name in snapshot.ManagedPackages do
            managedPackages.Add(JsonValue.Create(name))

        let result = JsonObject()
        result.Add("installedVersions", installedVersions)
        result.Add("managedPackages", managedPackages)
        result :> JsonNode

    let handle (environment: HostEnvironment) (request: JsonElement) : JsonNode =
        if request.ValueKind <> JsonValueKind.Object then
            fail "request must be a JSON object"

        let operation = jsonPropertyOrUndefined request "operation"

        if operation.ValueKind <> JsonValueKind.String then
            fail "unsupported helper operation null"

        match operation.GetString() with
        | "read" -> readRequest environment request |> toJsonNode
        | "apply" -> applyRequest environment request |> toJsonNode
        | _ -> fail "unsupported helper operation"
