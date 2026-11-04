namespace Dorothy.HostHelper

open System
open System.Collections.Generic
open System.Globalization
open System.IO
open System.Runtime.InteropServices
open System.Security.Cryptography
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open Microsoft.Win32.SafeHandles

[<Struct; StructLayout(LayoutKind.Sequential, Size = 256)>]
type private SudoStatx =
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

type private SudoIdentity =
    { DeviceMajor: uint32
      DeviceMinor: uint32
      Inode: uint64 }

type private SudoMetadata =
    { Identity: SudoIdentity
      FileType: int
      Mode: int
      UserId: uint32
      GroupId: uint32 }

type private SudoSubject =
    { Kind: string
      Name: string }

type private SudoArguments =
    | NoArguments
    | ExactArguments of string
    | AnyArguments

type private SudoCommand =
    { Path: string
      Arguments: SudoArguments }

type private SudoRunAs =
    | AllUsersAndGroups
    | SpecificRunAs of string * string option

type private SudoGrant =
    { Name: string
      Subjects: SudoSubject list
      RunAs: SudoRunAs
      Authentication: string
      AllCommands: bool
      Commands: SudoCommand list }

type private SudoRequest =
    { Operation: string
      ResourceId: string
      ConnectionUser: string
      Grants: SudoGrant list }
type private SudoGrantPlan =
    { Grant: SudoGrant
      Principals: string list
      Coverage: string
      PrincipalsResolved: bool }

type private SudoJournal =
    { ResourceId: string
      Digest: string
      FilePath: string
      Content: string }

type private SudoPending =
    { ResourceId: string
      Digest: string
      FilePath: string
      Operation: string
      Content: string option
      PreviousPresent: bool
      PreviousContent: string option
      PreviousMode: int option
      PreviousGroupId: uint32 option }
type private SudoPolicyEntry =
    { Source: string
      RunAsUsers: string
      RunAsGroups: string
      Options: string
      Commands: string list
      Matched: string option }

module Sudo =
    type BackendError(message: string) =
        inherit InvalidOperationException(message)

    [<Literal>]
    let private StateDirectory = "/var/lib/keroosha-iac/sudoers"

    [<Literal>]
    let private PolicyDirectory = "/etc/sudoers.d"

    [<Literal>]
    let private PolicyFile = "/etc/sudoers"

    [<Literal>]
    let private PolicyMode = 0o440

    [<Literal>]
    let private JournalMode = 0o600

    [<Literal>]
    let private DirectoryMode = 0o700

    let private strictUtf8 = UTF8Encoding(false, true)

    [<DllImport("libc", EntryPoint = "statx", SetLastError = true)>]
    extern int private nativeStatx (int directoryFileDescriptor, string path, int flags, uint32 mask, SudoStatx& result)

    [<DllImport("libc", EntryPoint = "open", SetLastError = true)>]
    extern int private nativeOpen (string path, int flags, int mode)

    [<DllImport("libc", EntryPoint = "fsync", SetLastError = true)>]
    extern int private nativeFsync (int fileDescriptor)

    [<DllImport("libc", EntryPoint = "close", SetLastError = true)>]
    extern int private nativeClose (int fileDescriptor)

    [<DllImport("libc", EntryPoint = "geteuid")>]
    extern uint32 private nativeGetEffectiveUserId ()

    [<DllImport("libc", EntryPoint = "chown", SetLastError = true)>]
    extern int private nativeChown (string path, uint32 owner, uint32 group)

    let private fail message = raise (BackendError(message))

    let private isProductionRoot (environment: HostEnvironment) =
        try Path.GetFullPath(environment.Root) = Path.GetPathRoot(Path.GetFullPath environment.Root)
        with _ -> false

    let private requireLinuxAndRoot (environment: HostEnvironment) =
        if not (OperatingSystem.IsLinux()) then
            fail "Sudo management requires Linux."
        if isProductionRoot environment && nativeGetEffectiveUserId() <> 0u then
            fail "Sudo management must run as root."

    let private isControl (value: string) = value |> Seq.exists Char.IsControl

    let private ownerDigest (resourceId: string) =
        if String.IsNullOrWhiteSpace resourceId || resourceId.Length > 4096 || isControl resourceId then
            fail "Sudo resourceId must be a non-empty string of at most 4096 characters without control characters."
        let bytes =
            try strictUtf8.GetBytes resourceId
            with :? EncoderFallbackException -> fail "Sudo resourceId is not valid UTF-8."
        SHA256.HashData(bytes) |> Convert.ToHexString |> fun value -> value.ToLowerInvariant()

    let private actualPath (environment: HostEnvironment) (logicalPath: string) =
        try HostEnvironment.path environment logicalPath
        with _ -> fail "A sudo-managed host path is invalid."

    let private isValidName (name: string) =
        let validStart character =
            (character >= 'a' && character <= 'z')
            || (character >= 'A' && character <= 'Z')
            || character = '_'
        let validRest character =
            validStart character
            || (character >= '0' && character <= '9')
            || character = '-'
            || character = '.'
        not (String.IsNullOrEmpty name)
        && name.Length <= 32
        && validStart name[0]
        && (name |> Seq.forall validRest)

    let private validateName description name =
        if not (isValidName name) then
            fail (description + " must be a conservative system user or group name.")
        name

    let private validateCommandPath (path: string) =
        let validCharacter character =
            (character >= 'a' && character <= 'z')
            || (character >= 'A' && character <= 'Z')
            || (character >= '0' && character <= '9')
            || character = '/'
            || character = '_'
            || character = '-'
            || character = '.'
            || character = '+'
        if String.IsNullOrWhiteSpace path || path[0] <> '/' || isControl path then
            fail "Sudo command paths must be absolute paths without control characters."
        let normalized =
            try Path.GetFullPath path
            with _ -> fail "A sudo command path is invalid."
        let segments = path.Substring(1).Split('/', StringSplitOptions.None)
        if normalized <> path
           || path = "/"
           || segments.Length = 0
           || (segments |> Array.exists (fun segment -> String.IsNullOrEmpty segment || segment = "." || segment = ".." || not (segment |> Seq.forall validCharacter))) then
            fail "Sudo command paths must be canonical absolute paths without sudoers glob syntax."
        path

    let private validateExactArguments (value: string) =
        let allowedCharacter character =
            (character >= 'a' && character <= 'z')
            || (character >= 'A' && character <= 'Z')
            || (character >= '0' && character <= '9')
            || character = ' '
            || character = '_'
            || character = '-'
            || character = '.'
            || character = '/'
            || character = ':'
            || character = '='
            || character = '+'
            || character = '@'
            || character = '%'
            || character = ','
            || character = '*'
            || character = '?'
            || character = '['
            || character = ']'
            || character = '\\'
            || character = '^'
            || character = '$'
        if String.IsNullOrEmpty value
           || value[0] = ' '
           || value[value.Length - 1] = ' '
           || (value |> Seq.exists (allowedCharacter >> not)) then
            fail "Exact sudo arguments must use the supported ASCII sudoers-safe character set."
        value

    let private objectProperties (element: JsonElement) (required: Set<string>) (optional: Set<string>) (description: string) =
        if element.ValueKind <> JsonValueKind.Object then fail (description + " must be a JSON object.")
        let properties = element.EnumerateObject() |> Seq.toArray
        let names = properties |> Array.map (fun property -> property.Name) |> Set.ofArray
        if properties.Length <> names.Count
           || not (required.IsSubsetOf names)
           || not (names.IsSubsetOf(Set.union required optional)) then
            fail (description + " contains missing, duplicate, or unsupported properties.")
        names

    let private requiredString (element: JsonElement) (name: string) (description: string) =
        let property = element.GetProperty(name)
        if property.ValueKind <> JsonValueKind.String then fail (description + " must be a string.")
        match property.GetString() with
        | null -> fail (description + " must not be null.")
        | value -> value

    let private optionalString (element: JsonElement) (name: string) (description: string) =
        match element.TryGetProperty(name) with
        | true, property when property.ValueKind = JsonValueKind.String ->
            match property.GetString() with
            | null -> fail (description + " must not be null.")
            | value -> Some value
        | true, _ -> fail (description + " must be a string when supplied.")
        | false, _ -> None

    let private requiredBoolean (element: JsonElement) (name: string) (description: string) =
        let property = element.GetProperty(name)
        if property.ValueKind <> JsonValueKind.True && property.ValueKind <> JsonValueKind.False then
            fail (description + " must be a boolean.")
        property.GetBoolean()

    let private parseSubject (element: JsonElement) =
        objectProperties element (set [ "kind"; "name" ]) Set.empty "A sudo subject" |> ignore
        let kind = requiredString element "kind" "A sudo subject kind"
        if kind <> "user" && kind <> "group" then fail "Sudo subject kind must be user or group."
        let name = validateName "A sudo subject name" (requiredString element "name" "A sudo subject name")
        { Kind = kind; Name = name }

    let private parseRunAs (element: JsonElement) =
        if element.ValueKind <> JsonValueKind.Object then fail "Sudo runAs must be a JSON object."
        let names = element.EnumerateObject() |> Seq.map (fun property -> property.Name) |> Set.ofSeq
        if names.Contains "kind" |> not then fail "Sudo runAs must contain kind."
        let kind = requiredString element "kind" "Sudo runAs kind"
        match kind with
        | "all" ->
            objectProperties element (set [ "kind" ]) Set.empty "An all-user sudo runAs" |> ignore
            AllUsersAndGroups
        | "specific" ->
            objectProperties element (set [ "kind"; "user" ]) (set [ "group" ]) "A specific sudo runAs" |> ignore
            let user = validateName "A sudo run-as user" (requiredString element "user" "A sudo run-as user")
            let group = optionalString element "group" "A sudo run-as group" |> Option.map (validateName "A sudo run-as group")
            SpecificRunAs(user, group)
        | _ -> fail "Sudo runAs kind must be all or specific."

    let private parseArguments (element: JsonElement) =
        if element.ValueKind <> JsonValueKind.Object then fail "Sudo command arguments must be a JSON object."
        match element.TryGetProperty("kind") with
        | true, _ -> ()
        | false, _ -> fail "Sudo command arguments must contain kind."
        let kind = requiredString element "kind" "Sudo argument kind"
        match kind with
        | "none" ->
            objectProperties element (set [ "kind" ]) Set.empty "No-argument sudo command settings" |> ignore
            NoArguments
        | "any" ->
            objectProperties element (set [ "kind" ]) Set.empty "Any-argument sudo command settings" |> ignore
            AnyArguments
        | "exact" ->
            objectProperties element (set [ "kind"; "value" ]) Set.empty "Exact sudo command settings" |> ignore
            ExactArguments(requiredString element "value" "Exact sudo command arguments" |> validateExactArguments)
        | _ -> fail "Sudo command argument kind must be none, exact, or any."

    let private parseCommand (element: JsonElement) =
        objectProperties element (set [ "path"; "arguments" ]) Set.empty "A sudo command" |> ignore
        let path = requiredString element "path" "A sudo command path" |> validateCommandPath
        let arguments = parseArguments (element.GetProperty "arguments")
        { Path = path; Arguments = arguments }

    let private parseGrant (element: JsonElement) =
        objectProperties element (set [ "name"; "subjects"; "runAs"; "allCommands"; "commands" ]) (set [ "authentication" ]) "A sudo grant" |> ignore
        let name = validateName "A sudo grant name" (requiredString element "name" "A sudo grant name")
        let subjectsElement = element.GetProperty "subjects"
        if subjectsElement.ValueKind <> JsonValueKind.Array then fail "Sudo grant subjects must be an array."
        let subjects = subjectsElement.EnumerateArray() |> Seq.map parseSubject |> Seq.toList
        if List.isEmpty subjects then fail "A sudo grant must have at least one subject."
        if subjects |> List.distinctBy (fun subject -> subject.Kind, subject.Name) |> List.length <> subjects.Length then
            fail "A sudo grant must not repeat a subject."
        let runAs = parseRunAs (element.GetProperty "runAs")
        let authentication =
            match optionalString element "authentication" "Sudo authentication" with
            | None -> "required"
            | Some value when value = "required" || value = "passwordless" -> value
            | Some _ -> fail "Sudo authentication must be required or passwordless."
        let allCommands = requiredBoolean element "allCommands" "Sudo allCommands"
        let commandsElement = element.GetProperty "commands"
        if commandsElement.ValueKind <> JsonValueKind.Array then fail "Sudo grant commands must be an array."
        let commands = commandsElement.EnumerateArray() |> Seq.map parseCommand |> Seq.toList
        if allCommands && not commands.IsEmpty then fail "A sudo grant with allCommands must not also declare commands."
        if not allCommands && commands.IsEmpty then fail "A sudo grant must declare commands unless allCommands is true."
        if commands |> List.distinctBy (fun command -> command.Path, command.Arguments) |> List.length <> commands.Length then
            fail "A sudo grant must not repeat a command setting."
        { Name = name
          Subjects = subjects |> List.sortBy (fun subject -> subject.Kind, subject.Name)
          RunAs = runAs
          Authentication = authentication
          AllCommands = allCommands
          Commands = commands |> List.sortBy (fun command ->
              let arguments =
                  match command.Arguments with
                  | NoArguments -> "0"
                  | ExactArguments value -> "1" + value
                  | AnyArguments -> "2"
              command.Path, arguments) }

    let private checkConflictingCommands (grants: SudoGrant list) =
        let rules = ResizeArray<SudoSubject * SudoRunAs * SudoCommand option>()
        let runAsOverlaps left right =
            match left, right with
            | AllUsersAndGroups, _
            | _, AllUsersAndGroups -> true
            | SpecificRunAs(leftUser, leftGroup), SpecificRunAs(rightUser, rightGroup) ->
                leftUser = rightUser
                && (leftGroup.IsNone || rightGroup.IsNone || leftGroup = rightGroup)
        let argumentScopesOverlap left right =
            match left, right with
            | AnyArguments, _
            | _, AnyArguments -> true
            | NoArguments, NoArguments -> true
            | ExactArguments leftValue, ExactArguments rightValue -> leftValue = rightValue
            | NoArguments, ExactArguments value
            | ExactArguments value, NoArguments -> String.IsNullOrEmpty value
        let commandScopesOverlap left right =
            match left, right with
            | None, _
            | _, None -> true
            | Some leftCommand, Some rightCommand ->
                leftCommand.Path = rightCommand.Path
                && argumentScopesOverlap leftCommand.Arguments rightCommand.Arguments
        for grant in grants do
            let commands = if grant.AllCommands then [ None ] else grant.Commands |> List.map Some
            for subject in grant.Subjects do
                for command in commands do
                    if rules
                       |> Seq.exists (fun (existingSubject, existingRunAs, existingCommand) ->
                           existingSubject = subject
                           && runAsOverlaps existingRunAs grant.RunAs
                           && commandScopesOverlap existingCommand command) then
                        fail "Sudo grants contain duplicate or conflicting command settings for the same subject and overlapping run-as identities."
                    rules.Add((subject, grant.RunAs, command))
    let private parseRequest (request: JsonElement) =
        objectProperties request (set [ "operation"; "resourceId"; "connectionUser"; "grants" ]) Set.empty "The sudo request" |> ignore
        let operation = requiredString request "operation" "Sudo operation"
        if operation <> "read" && operation <> "apply" && operation <> "delete" then fail "Unsupported sudo operation."
        let resourceId = requiredString request "resourceId" "Sudo resourceId"
        ownerDigest resourceId |> ignore
        let connectionUser = validateName "Sudo connectionUser" (requiredString request "connectionUser" "Sudo connectionUser")
        let grantsElement = request.GetProperty "grants"
        if grantsElement.ValueKind <> JsonValueKind.Array then fail "Sudo grants must be an array."
        let grants = grantsElement.EnumerateArray() |> Seq.map parseGrant |> Seq.toList
        if grants |> List.distinctBy (fun grant -> grant.Name) |> List.length <> grants.Length then
            fail "Sudo grants must not repeat a rule name."
        checkConflictingCommands grants
        { Operation = operation
          ResourceId = resourceId
          ConnectionUser = connectionUser
          Grants = grants |> List.sortBy (fun grant -> grant.Name) }

    let private escapeExactArguments (value: string) =
        let builder = StringBuilder(value.Length + 16)
        for index in 0 .. value.Length - 1 do
            let character = value[index]
            if character = '\\' then
                builder.Append('\\') |> ignore
                builder.Append('\\') |> ignore
                builder.Append('\\') |> ignore
                builder.Append('\\') |> ignore
            else
                if character = ',' || character = ':' || character = '=' || character = '*' || character = '?' || character = '[' || character = ']' || (index = 0 && character = '^') then
                    builder.Append('\\') |> ignore
                builder.Append(character) |> ignore
        builder.ToString()

    let private renderCommand (command: SudoCommand) =
        match command.Arguments with
        | NoArguments -> command.Path + " \"\""
        | AnyArguments -> command.Path
        | ExactArguments value -> command.Path + " " + escapeExactArguments value

    let private renderGrant (grant: SudoGrant) =
        let subjects =
            grant.Subjects
            |> List.map (fun subject -> if subject.Kind = "group" then "%" + subject.Name else subject.Name)
            |> String.concat ", "
        let runAs =
            match grant.RunAs with
            | AllUsersAndGroups -> "ALL:ALL"
            | SpecificRunAs(user, None) -> user
            | SpecificRunAs(user, Some group) -> user + ":" + group
        let authentication = if grant.Authentication = "passwordless" then "NOPASSWD:" else "PASSWD:"
        let commands =
            if grant.AllCommands then "ALL"
            else grant.Commands |> List.map renderCommand |> String.concat ", "
        subjects + " ALL = (" + runAs + ") " + authentication + " NOSETENV: " + commands

    let private renderGrants (digest: string) (grants: SudoGrant list) =
        let lines =
            [ "# Dorothy managed sudo policy owner-sha256=" + digest
              yield! grants |> List.collect (fun grant -> grant.Subjects |> List.map (fun subject -> { grant with Subjects = [ subject ] })) |> List.map renderGrant |> List.sortWith (fun left right -> String.CompareOrdinal(left, right)) ]
        String.concat "\n" lines + "\n"

    let private readPasswdLine (line: string) =
        let fields = line.Split(':')
        if fields.Length < 7 then None
        else
            let mutable userId = 0u
            let mutable groupId = 0u
            if UInt32.TryParse(fields[2], NumberStyles.None, CultureInfo.InvariantCulture, &userId)
               && UInt32.TryParse(fields[3], NumberStyles.None, CultureInfo.InvariantCulture, &groupId) then
                Some(fields[0], userId, groupId, fields[5])
            else None

    let private tryGetent (environment: HostEnvironment) (arguments: string list) =
        let result = environment.Run "getent" arguments None
        if result.ExitCode = 0 then Some result.Stdout
        elif result.ExitCode = 2 then None
        else fail "The host could not query NSS for a sudo user or group."

    let private getent (environment: HostEnvironment) (arguments: string list) =
        tryGetent environment arguments
        |> Option.defaultWith (fun () -> fail "A sudo user or group could not be resolved through NSS.")

    let private resolveUser (environment: HostEnvironment) (name: string) =
        let lines = getent environment [ "passwd"; name ] |> fun output -> output.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
        match lines |> Array.choose readPasswdLine |> Array.filter (fun (resolved, _, _, _) -> resolved = name) with
        | [| (_, userId, groupId, home) |] when not (isControl home) -> userId, groupId, home
        | _ -> fail "A sudo user could not be resolved unambiguously through NSS."

    let private tryResolveGroup (environment: HostEnvironment) (name: string) =
        match tryGetent environment [ "group"; name ] with
        | None -> None
        | Some output ->
            let lines = output.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
            let matches =
                lines
                |> Array.choose (fun line ->
                    let fields = line.Split(':')
                    if fields.Length < 4 || fields[0] <> name then None
                    else
                        let mutable groupId = 0u
                        if UInt32.TryParse(fields[2], NumberStyles.None, CultureInfo.InvariantCulture, &groupId) then
                            Some(groupId, fields[3].Split(',', StringSplitOptions.RemoveEmptyEntries) |> Array.toList)
                        else None)
            match matches with
            | [| groupId, members |] -> Some(groupId, members)
            | _ -> fail "A sudo group could not be resolved unambiguously through NSS."

    let private resolveGroup (environment: HostEnvironment) (name: string) =
        tryResolveGroup environment name
        |> Option.defaultWith (fun () -> fail "A sudo group could not be resolved through NSS.")

    let private tryGroupMembers (environment: HostEnvironment) (name: string) =
        match tryResolveGroup environment name with
        | None -> None
        | Some(groupId, explicitMembers) ->
            let allUsers = getent environment [ "passwd" ]
            let primaryMembers =
                allUsers.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
                |> Array.choose readPasswdLine
                |> Array.choose (fun (user, _, primaryGroupId, _) -> if primaryGroupId = groupId then Some user else None)
            Some(
                Seq.append explicitMembers primaryMembers
                |> Seq.filter isValidName
                |> Seq.distinct
                |> Seq.sortWith (fun left right -> String.CompareOrdinal(left, right))
                |> Seq.toList
            )

    let private resolveRequestIdentities (environment: HostEnvironment) (request: SudoRequest) =
        let connectionIdentity = resolveUser environment request.ConnectionUser
        for grant in request.Grants do
            for subject in grant.Subjects do
                if subject.Kind = "user" then resolveUser environment subject.Name |> ignore
                else resolveGroup environment subject.Name |> ignore
            match grant.RunAs with
            | AllUsersAndGroups -> ()
            | SpecificRunAs(user, group) ->
                resolveUser environment user |> ignore
                group |> Option.iter (fun value -> resolveGroup environment value |> ignore)
        connectionIdentity

    let private expectedOwner (environment: HostEnvironment) =
        if isProductionRoot environment then 0u
        else
            let boundary = Path.TrimEndingDirectorySeparator(Path.GetFullPath environment.Root)
            let mutable stat = Unchecked.defaultof<SudoStatx>
            if nativeStatx(-100, boundary, 0x100, 0x7FFu, &stat) <> 0 then fail "The mapped sudo host root could not be inspected."
            stat.UserId

    let private expectedGroup (environment: HostEnvironment) =
        if isProductionRoot environment then 0u
        else
            let boundary = Path.TrimEndingDirectorySeparator(Path.GetFullPath environment.Root)
            let mutable stat = Unchecked.defaultof<SudoStatx>
            if nativeStatx(-100, boundary, 0x100, 0x7FFu, &stat) <> 0 then fail "The mapped sudo host root could not be inspected."
            stat.GroupId

    let private inspectNoFollow (path: string) =
        let mutable stat = Unchecked.defaultof<SudoStatx>
        if nativeStatx(-100, path, 0x100, 0x7FFu, &stat) = 0 then
            Some
                { Identity =
                    { DeviceMajor = stat.DeviceMajor
                      DeviceMinor = stat.DeviceMinor
                      Inode = stat.Inode }
                  FileType = int (stat.Mode &&& 0xF000us)
                  Mode = int (stat.Mode &&& 0x0FFFus)
                  UserId = stat.UserId
                  GroupId = stat.GroupId }
        else
            let errorCode = Marshal.GetLastWin32Error()
            if errorCode = 2 then None
            else raise (IOException("Could not safely inspect a sudo host path.", System.ComponentModel.Win32Exception(errorCode)))

    let private inspectDescriptor (descriptor: int) =
        let mutable stat = Unchecked.defaultof<SudoStatx>
        if nativeStatx(descriptor, "", 0x1000, 0x7FFu, &stat) <> 0 then
            let errorCode = Marshal.GetLastWin32Error()
            raise (IOException("Could not safely inspect an open sudo file.", System.ComponentModel.Win32Exception(errorCode)))
        { Identity =
            { DeviceMajor = stat.DeviceMajor
              DeviceMinor = stat.DeviceMinor
              Inode = stat.Inode }
          FileType = int (stat.Mode &&& 0xF000us)
          Mode = int (stat.Mode &&& 0x0FFFus)
          UserId = stat.UserId
          GroupId = stat.GroupId }

    let private sameIdentity left right =
        left.DeviceMajor = right.DeviceMajor
        && left.DeviceMinor = right.DeviceMinor
        && left.Inode = right.Inode

    let private syncDirectory (path: string) =
        let descriptor = nativeOpen(path, 0x10000 ||| 0x80000 ||| 0x20000, 0)
        if descriptor < 0 then
            let errorCode = Marshal.GetLastWin32Error()
            raise (IOException("Could not open a sudo ownership directory for synchronization.", System.ComponentModel.Win32Exception(errorCode)))
        try
            if nativeFsync descriptor <> 0 then
                let errorCode = Marshal.GetLastWin32Error()
                raise (IOException("Could not synchronize a sudo ownership directory.", System.ComponentModel.Win32Exception(errorCode)))
        finally
            nativeClose descriptor |> ignore


    let private ensureSafeDirectoryChain (environment: HostEnvironment) (path: string) (create: bool) (finalMode: int) =
        let fullPath = Path.GetFullPath path
        let boundary =
            if isProductionRoot environment then Path.GetPathRoot fullPath
            else Path.TrimEndingDirectorySeparator(Path.GetFullPath environment.Root)
        if String.IsNullOrEmpty boundary then fail "A sudo directory path must be absolute."
        let relative = Path.GetRelativePath(boundary, fullPath)
        if Path.IsPathRooted relative
           || relative = ".."
           || relative.StartsWith(".." + string Path.DirectorySeparatorChar, StringComparison.Ordinal) then
            fail "A sudo directory escaped the managed host root."
        let expectedUid = expectedOwner environment
        let expectedGid = expectedGroup environment
        let checkDirectory (directory: string) =
            match inspectNoFollow directory with
            | Some metadata when metadata.FileType = 0x4000 ->
                if metadata.UserId <> expectedUid || metadata.GroupId <> expectedGid || (metadata.Mode &&& 0o022) <> 0 then
                    fail "A sudo policy or ownership directory is not privately owned by the host administrator."
                metadata
            | Some _ -> fail "A sudo policy directory is not a real directory."
            | None -> fail "A required sudo policy directory does not exist."
        checkDirectory boundary |> ignore
        let components =
            if relative = "." then [||]
            else relative.Split([| Path.DirectorySeparatorChar; Path.AltDirectorySeparatorChar |], StringSplitOptions.RemoveEmptyEntries)
        let mutable current = boundary
        let mutable present = true
        for index in 0 .. components.Length - 1 do
            current <- Path.Combine(current, components[index])
            if present then
                match inspectNoFollow current with
                | Some metadata when metadata.FileType = 0x4000 ->
                    if metadata.UserId <> expectedUid || metadata.GroupId <> expectedGid || (metadata.Mode &&& 0o022) <> 0 then
                        fail "A sudo policy or ownership directory is not privately owned by the host administrator."
                    if create then
                        let parent = Path.GetDirectoryName current
                        if String.IsNullOrEmpty parent then fail "A sudo ownership directory has no parent."
                        syncDirectory current
                        syncDirectory parent
                | Some _ -> fail "A sudo policy path contains a non-directory component."
                | None when create ->
                    try
                        Directory.CreateDirectory current |> ignore
                        let mode = if index = components.Length - 1 then enum<UnixFileMode> finalMode else UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute
                        File.SetUnixFileMode(current, mode)
                        let parent = Path.GetDirectoryName current
                        if String.IsNullOrEmpty parent then fail "A sudo ownership directory has no parent."
                        syncDirectory current
                        syncDirectory parent
                    with _ -> fail "A required sudo ownership directory could not be created safely."
                    match inspectNoFollow current with
                    | Some metadata when metadata.FileType = 0x4000 && metadata.UserId = expectedUid && metadata.GroupId = expectedGid && (metadata.Mode &&& 0o022) = 0 -> ()
                    | _ -> fail "A newly created sudo ownership directory is not safe."
                | None -> present <- false
        present

    let private validateRootOwnedFile (environment: HostEnvironment) (metadata: SudoMetadata) description =
        if metadata.UserId <> expectedOwner environment then fail (description + " is not owned by the host administrator.")

    let private safeReadBytes (environment: HostEnvironment) (path: string) =
        let parent = Path.GetDirectoryName path
        if String.IsNullOrEmpty parent || not (ensureSafeDirectoryChain environment parent false DirectoryMode) then None
        else
            match inspectNoFollow path with
            | None -> None
            | Some initial when initial.FileType <> 0x8000 -> fail "A sudo-managed path is not a regular file."
            | Some initial ->
                validateRootOwnedFile environment initial "A sudo-managed file"
                let descriptor = nativeOpen(path, 0x800 ||| 0x80000 ||| 0x20000, 0)
                if descriptor < 0 then
                    let errorCode = Marshal.GetLastWin32Error()
                    raise (IOException("Could not safely open a sudo-managed file.", System.ComponentModel.Win32Exception(errorCode)))
                let handle = new SafeFileHandle(nativeint descriptor, true)
                use handle = handle
                let opened = inspectDescriptor descriptor
                if opened.FileType <> 0x8000 || not (sameIdentity initial.Identity opened.Identity) then
                    fail "A sudo-managed file changed while it was being opened."
                use stream = new FileStream(handle, FileAccess.Read, 4096, false)
                use buffer = new MemoryStream()
                stream.CopyTo buffer
                match inspectNoFollow path with
                | Some current when sameIdentity opened.Identity current.Identity -> Some(buffer.ToArray(), current)
                | _ -> fail "A sudo-managed file changed while it was being read."

    let private decodeUtf8 description (bytes: byte array) =
        try strictUtf8.GetString bytes
        with :? DecoderFallbackException -> fail (description + " is not valid UTF-8.")

    let private encodeUtf8 (value: string) =
        try strictUtf8.GetBytes value
        with :? EncoderFallbackException -> fail "A sudo policy value is not valid UTF-8."

    let private digestBytes (bytes: byte array) =
        SHA256.HashData bytes |> Convert.ToHexString |> fun value -> value.ToLowerInvariant()

    let private filePath (environment: HostEnvironment) digest =
        actualPath environment (PolicyDirectory + "/90-keroosha-iac-" + digest)

    let private journalPath (environment: HostEnvironment) digest =
        actualPath environment (StateDirectory + "/" + digest + ".json")

    let private pendingPath (environment: HostEnvironment) digest =
        actualPath environment (StateDirectory + "/" + digest + ".pending.json")

    let private stateDirectoryPath (environment: HostEnvironment) = actualPath environment StateDirectory

    let private requireJournalDirectory (environment: HostEnvironment) create =
        let path = stateDirectoryPath environment
        if not (ensureSafeDirectoryChain environment path create DirectoryMode) then
            if create then fail "The sudo journal directory is unavailable."
            else false
        else
            let metadata = inspectNoFollow path |> Option.defaultWith (fun () -> fail "The sudo journal directory disappeared.")
            if metadata.Mode <> DirectoryMode then fail "The sudo journal directory permissions are not 0700."
            true

    let private optionalJsonString (element: JsonElement) (name: string) =
        let value = element.GetProperty(name)
        match value.ValueKind with
        | JsonValueKind.Null -> None
        | JsonValueKind.String ->
            match value.GetString() with
            | null -> fail "A sudo journal is malformed."
            | text -> Some text
        | _ -> fail "A sudo journal is malformed."

    let private requiredUInt32 (element: JsonElement) (name: string) =
        let mutable value = 0u
        let property = element.GetProperty(name)
        if property.ValueKind <> JsonValueKind.Number || not (property.TryGetUInt32(&value)) then fail "A sudo journal is malformed."
        value

    let private requiredInt32 (element: JsonElement) (name: string) =
        let mutable value = 0
        let property = element.GetProperty(name)
        if property.ValueKind <> JsonValueKind.Number || not (property.TryGetInt32(&value)) then fail "A sudo journal is malformed."
        value

    let private readJournal (environment: HostEnvironment) (resourceId: string) digest =
        if not (requireJournalDirectory environment false) then None
        else
            let path = journalPath environment digest
            match safeReadBytes environment path with
            | None -> None
            | Some(bytes, metadata) ->
                if metadata.Mode <> JournalMode then fail "The sudo ownership journal permissions are not 0600."
                try
                    use document = JsonDocument.Parse(bytes)
                    let root = document.RootElement
                    objectProperties root (set [ "version"; "resourceId"; "digest"; "filePath"; "content" ]) Set.empty "A sudo ownership journal" |> ignore
                    if requiredInt32 root "version" <> 1
                       || requiredString root "resourceId" "A sudo journal resourceId" <> resourceId
                       || requiredString root "digest" "A sudo journal digest" <> digest
                       || requiredString root "filePath" "A sudo journal filePath" <> PolicyDirectory + "/90-keroosha-iac-" + digest then
                        fail "A sudo ownership journal does not belong to this resource."
                    Some
                        { ResourceId = resourceId
                          Digest = digest
                          FilePath = PolicyDirectory + "/90-keroosha-iac-" + digest
                          Content = requiredString root "content" "A sudo journal content" }
                with
                | :? BackendError -> reraise ()
                | _ -> fail "The sudo ownership journal is malformed."

    let private readPending (environment: HostEnvironment) (resourceId: string) digest =
        if not (requireJournalDirectory environment false) then None
        else
            let path = pendingPath environment digest
            match safeReadBytes environment path with
            | None -> None
            | Some(bytes, metadata) ->
                if metadata.Mode <> JournalMode then fail "The sudo pending journal permissions are not 0600."
                try
                    use document = JsonDocument.Parse(bytes)
                    let root = document.RootElement
                    objectProperties root (set [ "version"; "resourceId"; "digest"; "filePath"; "operation"; "content"; "previousPresent"; "previousContent"; "previousMode"; "previousGroupId" ]) Set.empty "A sudo pending journal" |> ignore
                    let operation = requiredString root "operation" "A sudo pending operation"
                    if operation <> "apply" && operation <> "delete" then fail "A sudo pending operation is malformed."
                    let content = optionalJsonString root "content"
                    let previousPresent = requiredBoolean root "previousPresent" "A sudo previousPresent value"
                    let previousContent = optionalJsonString root "previousContent"
                    let previousMode =
                        match root.GetProperty "previousMode" with
                        | value when value.ValueKind = JsonValueKind.Null -> None
                        | _ -> Some(requiredInt32 root "previousMode")
                    let previousGroupId =
                        match root.GetProperty "previousGroupId" with
                        | value when value.ValueKind = JsonValueKind.Null -> None
                        | _ -> Some(requiredUInt32 root "previousGroupId")
                    if requiredInt32 root "version" <> 1
                       || requiredString root "resourceId" "A sudo pending resourceId" <> resourceId
                       || requiredString root "digest" "A sudo pending digest" <> digest
                       || requiredString root "filePath" "A sudo pending filePath" <> PolicyDirectory + "/90-keroosha-iac-" + digest
                       || (operation = "apply") <> content.IsSome
                       || previousPresent <> previousContent.IsSome
                       || previousPresent <> previousMode.IsSome
                       || previousPresent <> previousGroupId.IsSome then
                        fail "A sudo pending journal does not belong to this resource."
                    Some
                        { ResourceId = resourceId
                          Digest = digest
                          FilePath = PolicyDirectory + "/90-keroosha-iac-" + digest
                          Operation = operation
                          Content = content
                          PreviousPresent = previousPresent
                          PreviousContent = previousContent
                          PreviousMode = previousMode
                          PreviousGroupId = previousGroupId }
                with
                | :? BackendError -> reraise ()
                | _ -> fail "The sudo pending journal is malformed."

    let private journalNode (journal: SudoJournal) =
        let node = JsonObject()
        node["version"] <- JsonValue.Create(1)
        node["resourceId"] <- JsonValue.Create(journal.ResourceId)
        node["digest"] <- JsonValue.Create(journal.Digest)
        node["filePath"] <- JsonValue.Create(journal.FilePath)
        node["content"] <- JsonValue.Create(journal.Content)
        node

    let private pendingNode (pending: SudoPending) =
        let node = JsonObject()
        node["version"] <- JsonValue.Create(1)
        node["resourceId"] <- JsonValue.Create(pending.ResourceId)
        node["digest"] <- JsonValue.Create(pending.Digest)
        node["filePath"] <- JsonValue.Create(pending.FilePath)
        node["operation"] <- JsonValue.Create(pending.Operation)
        match pending.Content with
        | Some value -> node["content"] <- JsonValue.Create(value)
        | None -> node["content"] <- null
        node["previousPresent"] <- JsonValue.Create(pending.PreviousPresent)
        match pending.PreviousContent with
        | Some value -> node["previousContent"] <- JsonValue.Create(value)
        | None -> node["previousContent"] <- null
        match pending.PreviousMode with
        | Some value -> node["previousMode"] <- JsonValue.Create(value)
        | None -> node["previousMode"] <- null
        match pending.PreviousGroupId with
        | Some value -> node["previousGroupId"] <- JsonValue.Create(value)
        | None -> node["previousGroupId"] <- null
        node

    let private writeRootOnly (environment: HostEnvironment) (path: string) (contents: byte array) (mode: UnixFileMode) =
        let parent = Path.GetDirectoryName path
        if String.IsNullOrEmpty parent || not (ensureSafeDirectoryChain environment parent true DirectoryMode) then
            fail "A sudo ownership journal parent directory is not safe."
        HostFiles.atomicWrite path contents mode
        match safeReadBytes environment path with
        | Some(_, metadata) when metadata.Mode = int mode && metadata.UserId = expectedOwner environment -> ()
        | _ -> fail "A sudo ownership journal could not be verified after writing."

    let private writeJournal (environment: HostEnvironment) (journal: SudoJournal) =
        let path = journalPath environment journal.Digest
        let bytes = journalNode journal |> fun node -> node.ToJsonString() |> encodeUtf8
        writeRootOnly environment path bytes (enum<UnixFileMode> JournalMode)

    let private writePending (environment: HostEnvironment) (pending: SudoPending) =
        let path = pendingPath environment pending.Digest
        let bytes = pendingNode pending |> fun node -> node.ToJsonString() |> encodeUtf8
        writeRootOnly environment path bytes (enum<UnixFileMode> JournalMode)

    let private deleteRootOnly (environment: HostEnvironment) (path: string) =
        match safeReadBytes environment path with
        | None -> ()
        | Some(_, before) ->
            match inspectNoFollow path with
            | Some current when current.FileType = 0x8000 && sameIdentity before.Identity current.Identity ->
                let parent = Path.GetDirectoryName path
                File.Delete path
                if String.IsNullOrEmpty parent then fail "A sudo ownership journal has no parent directory."
                syncDirectory parent
            | _ -> fail "A sudo ownership journal changed before removal."

    let private readTarget (environment: HostEnvironment) (digest: string) =
        let path = filePath environment digest
        safeReadBytes environment path
        |> Option.map (fun (bytes, metadata) -> decodeUtf8 "The sudo policy file" bytes, metadata)

    let private writeTarget (environment: HostEnvironment) (digest: string) (allowedContents: string list) allowMissing (content: string) =
        requireJournalDirectory environment true |> ignore
        let target = filePath environment digest
        if not (ensureSafeDirectoryChain environment (Path.GetDirectoryName target) false DirectoryMode) then
            fail "The sudoers include directory does not exist."
        match readTarget environment digest with
        | None when allowMissing -> ()
        | Some(current, _) when allowedContents |> List.contains current -> ()
        | _ -> fail "The sudo policy path changed outside its ownership journal."
        HostFiles.atomicWrite target (encodeUtf8 content) (enum<UnixFileMode> PolicyMode)
        match safeReadBytes environment target with
        | Some(bytes, metadata) when metadata.Mode = PolicyMode && metadata.UserId = expectedOwner environment && decodeUtf8 "The sudo policy file" bytes = content -> ()
        | _ -> fail "The sudo policy file could not be verified after writing."

    let private removeTarget (environment: HostEnvironment) (digest: string) (expectedContent: string option) =
        let target = filePath environment digest
        match readTarget environment digest with
        | None -> ()
        | Some(content, before) ->
            match expectedContent with
            | Some expected when content <> expected -> fail "Refusing to remove a sudo policy file that is no longer owned."
            | None -> fail "Refusing to remove an unowned sudo policy file."
            | _ ->
                match inspectNoFollow target with
                | Some metadata when metadata.FileType = 0x8000 && sameIdentity before.Identity metadata.Identity ->
                    File.Delete target
                    let parent = Path.GetDirectoryName target
                    if String.IsNullOrEmpty parent then fail "The sudo policy file has no parent directory."
                    syncDirectory parent
                | _ -> fail "The sudo policy file changed before removal."

    let private processResult (environment: HostEnvironment) executable arguments standardInput =
        environment.Run executable arguments standardInput

    let private policyViewScript =
        "mount --bind \"$1\" /etc/sudoers.d || exit 125; shift; exec \"$@\""

    let private runInPolicyView (environment: HostEnvironment) (stagedDirectory: string option) executable arguments standardInput =
        match stagedDirectory with
        | Some directory when isProductionRoot environment ->
            let namespaceArguments =
                [ "--mount"; "--propagation"; "private"; "--fork"; "--"; "/bin/sh"; "-c"; policyViewScript; "dorothy-sudo-policy"; directory ]
                @ (executable :: arguments)
            processResult environment "unshare" namespaceArguments standardInput
        | _ -> processResult environment executable arguments standardInput

    let private policyOutputHasPath (output: string) (path: string) =
        output.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
        |> Array.exists (fun line -> line.Trim() = path + ": parsed OK")

    let private validatePolicyGraph (environment: HostEnvironment) stagedDirectory expectedIncludedPath =
        let policyPath = actualPath environment PolicyFile
        match safeReadBytes environment policyPath with
        | None -> fail "The host sudoers policy file is missing."
        | Some(_, metadata) ->
            validateRootOwnedFile environment metadata "The host sudoers policy file"
            if (metadata.Mode &&& 0o022) <> 0 then fail "The host sudoers policy file is writable by an untrusted group."
        let includeDirectory = actualPath environment PolicyDirectory
        if not (ensureSafeDirectoryChain environment includeDirectory false DirectoryMode) then
            fail "The host sudoers include directory is missing or unsafe."
        let result = runInPolicyView environment stagedDirectory "visudo" [ "-c"; "-f"; policyPath ] None
        if result.ExitCode <> 0 then fail "visudo rejected the complete host sudoers policy."
        let sudoVersion = runInPolicyView environment stagedDirectory "sudo" [ "-V" ] None
        let sudoVersionOutput = sudoVersion.Stdout + "\n" + sudoVersion.Stderr
        if sudoVersion.ExitCode <> 0
           || not (sudoVersionOutput.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
                   |> Array.exists (fun line -> line.Trim() = "Sudoers path: /etc/sudoers")) then
            fail "The active sudo policy plugin does not use the confirmed /etc/sudoers policy graph."
        let output = result.Stdout + "\n" + result.Stderr
        match expectedIncludedPath with
        | Some path -> policyOutputHasPath output path
        | None -> true


    let private parseVerbosePolicyEntries (output: string) =
        let entries = ResizeArray<SudoPolicyEntry>()
        let mutable source: string option = None
        let mutable runAsUsers = ""
        let mutable runAsGroups = ""
        let mutable options = ""
        let mutable commands = ResizeArray<string>()
        let mutable matched: string option = None
        let mutable hasRunAsUsers = false
        let mutable hasRunAsGroups = false
        let mutable hasOptions = false
        let mutable hasCommands = false
        let mutable readingCommands = false
        let saveCurrent () =
            match source with
            | None -> ()
            | Some file ->
                if String.IsNullOrWhiteSpace file
                   || not hasRunAsUsers
                   || not hasCommands
                   || commands.Count = 0 then
                    fail "The verbose sudo policy listing is incomplete."
                entries.Add(
                    { Source = file
                      RunAsUsers = runAsUsers
                      RunAsGroups = runAsGroups
                      Options = options
                      Commands = List.ofSeq commands
                      Matched = matched }
                )
        for line in output.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries) do
            let text = line.Trim()
            if text.StartsWith("Sudoers entry:", StringComparison.Ordinal) then
                saveCurrent ()
                source <- Some(text.Substring("Sudoers entry:".Length).Trim())
                runAsUsers <- ""
                runAsGroups <- ""
                options <- ""
                commands <- ResizeArray<string>()
                matched <- None
                hasRunAsUsers <- false
                hasRunAsGroups <- false
                hasOptions <- false
                hasCommands <- false
                readingCommands <- false
            elif source.IsSome then
                if text.StartsWith("RunAsUsers:", StringComparison.Ordinal) then
                    if hasRunAsUsers then fail "The verbose sudo listing repeated RunAsUsers."
                    runAsUsers <- text.Substring("RunAsUsers:".Length).Trim()
                    hasRunAsUsers <- true
                    readingCommands <- false
                elif text.StartsWith("RunAsGroups:", StringComparison.Ordinal) then
                    if hasRunAsGroups then fail "The verbose sudo listing repeated RunAsGroups."
                    runAsGroups <- text.Substring("RunAsGroups:".Length).Trim()
                    hasRunAsGroups <- true
                    readingCommands <- false
                elif text.StartsWith("Options:", StringComparison.Ordinal) then
                    if hasOptions then fail "The verbose sudo listing repeated Options."
                    options <- text.Substring("Options:".Length).Trim()
                    hasOptions <- true
                    readingCommands <- false
                elif text = "Commands:" then
                    if hasCommands then fail "The verbose sudo listing repeated Commands."
                    hasCommands <- true
                    readingCommands <- true
                elif text.StartsWith("Matched:", StringComparison.Ordinal) then
                    if matched.IsSome then fail "The verbose sudo listing repeated Matched."
                    matched <- Some(text.Substring("Matched:".Length).Trim())
                    readingCommands <- false
                elif readingCommands && not (String.IsNullOrWhiteSpace text) then
                    commands.Add text
                else
                    fail "The verbose sudo policy listing contains an unsupported field."
        saveCurrent ()
        entries.ToArray()

    let private policyEntryHasOption (entry: SudoPolicyEntry) (optionName: string) =
        entry.Options.Split([| ','; ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
        |> Array.exists ((=) optionName)

    let private policyEntryAuthenticationMatches authentication (entry: SudoPolicyEntry) =
        let passwordless = policyEntryHasOption entry "!authenticate"
        let authenticationMatches =
            if authentication = "passwordless" then passwordless
            else not passwordless && policyEntryHasOption entry "authenticate"
        authenticationMatches && policyEntryHasOption entry "!setenv"

    let private policyEntryRunAsMatches (runAs: SudoRunAs) (entry: SudoPolicyEntry) =
        let containsUser value field =
            String.IsNullOrWhiteSpace field
            || (field.Split(',', StringSplitOptions.RemoveEmptyEntries)
                |> Array.exists (fun candidate -> candidate.Trim() = "ALL" || candidate.Trim() = value))
        match runAs with
        | AllUsersAndGroups ->
            containsUser "ALL" entry.RunAsUsers && containsUser "ALL" entry.RunAsGroups
        | SpecificRunAs(user, group) ->
            containsUser user entry.RunAsUsers
            && (group |> Option.forall (fun value -> containsUser value entry.RunAsGroups))

    let private policyEntryContainsCommand (grant: SudoGrant) (command: SudoCommand) (entry: SudoPolicyEntry) =
        entry.Commands
        |> List.exists (fun value ->
            if grant.AllCommands then value.Trim() = "ALL"
            else
                value.Trim().Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
                |> Array.tryHead
                |> Option.exists ((=) command.Path))

    let private checkOneEffectiveCommand (environment: HostEnvironment) stagedDirectory digest (subjectName: string) (runAs: SudoRunAs) (commandPath: string) (argument: string option) authentication =
        let runAsUser, runAsGroup =
            match runAs with
            | AllUsersAndGroups -> "root", Some "root"
            | SpecificRunAs(user, group) -> user, group
        let arguments = ResizeArray<string>()
        arguments.Add("-n")
        arguments.Add("-ll")
        arguments.Add("-U")
        arguments.Add(subjectName)
        arguments.Add("-u")
        arguments.Add(runAsUser)
        match runAsGroup with
        | Some group -> arguments.Add("-g"); arguments.Add(group)
        | None -> ()
        arguments.Add("--")
        arguments.Add(commandPath)
        argument |> Option.iter arguments.Add
        let result = runInPolicyView environment stagedDirectory "sudo" (List.ofSeq arguments) None
        if result.ExitCode <> 0 then false
        else
            let entries = parseVerbosePolicyEntries (result.Stdout + "\n" + result.Stderr)
            let matching =
                entries
                |> Array.filter (fun entry -> entry.Matched |> Option.exists (String.IsNullOrWhiteSpace >> not))
            match matching |> Array.tryLast with
            | Some entry when entry.Source = filePath environment digest && policyEntryRunAsMatches runAs entry ->
                policyEntryAuthenticationMatches authentication entry
            | _ -> false

    let private checkFullPolicyScope (environment: HostEnvironment) (entries: SudoPolicyEntry array) digest (runAs: SudoRunAs) (grant: SudoGrant) (command: SudoCommand) =
        let ownerFile = filePath environment digest
        let ownedIndex =
            entries
            |> Array.tryFindIndex (fun entry ->
                entry.Source = ownerFile
                && policyEntryRunAsMatches runAs entry
                && policyEntryContainsCommand grant command entry)
        match ownedIndex with
        | None -> false
        | Some index ->
            entries
            |> Array.skip (index + 1)
            |> Array.exists (fun entry -> entry.Source <> ownerFile)
            |> not
    let private resolveEffectivePrincipals (environment: HostEnvironment) (grant: SudoGrant) =
        let subjects = ResizeArray<string>()
        let seenSubjects = HashSet<string>(StringComparer.Ordinal)
        let mutable includesGroup = false
        let mutable hasUnprobedGroup = false
        let mutable hasUnresolvedPrincipal = false
        for subject in grant.Subjects do
            if subject.Kind = "user" then
                if seenSubjects.Add subject.Name then subjects.Add subject.Name
            else
                includesGroup <- true
                match tryGroupMembers environment subject.Name with
                | None -> hasUnresolvedPrincipal <- true
                | Some members ->
                    if List.isEmpty members then hasUnprobedGroup <- true
                    for memberName in members do
                        if seenSubjects.Add memberName then subjects.Add memberName
        let coverage =
            if hasUnresolvedPrincipal then "unresolved-principal"
            elif hasUnprobedGroup then "empty-group-structural"
            elif includesGroup then "nss-enumerated-group-members"
            else "direct-user"
        List.ofSeq subjects, coverage, not hasUnresolvedPrincipal

    let private runAsScopesOverlap left right =
        match left, right with
        | AllUsersAndGroups, _
        | _, AllUsersAndGroups -> true
        | SpecificRunAs(leftUser, leftGroup), SpecificRunAs(rightUser, rightGroup) ->
            leftUser = rightUser
            && (leftGroup.IsNone || rightGroup.IsNone || leftGroup = rightGroup)

    let private argumentScopesOverlap left right =
        match left, right with
        | AnyArguments, _
        | _, AnyArguments -> true
        | NoArguments, NoArguments -> true
        | ExactArguments leftValue, ExactArguments rightValue -> leftValue = rightValue
        | NoArguments, ExactArguments value
        | ExactArguments value, NoArguments -> String.IsNullOrEmpty value

    let private commandScopesOverlap (leftGrant: SudoGrant) (rightGrant: SudoGrant) =
        if leftGrant.AllCommands || rightGrant.AllCommands then true
        else
            leftGrant.Commands
            |> List.exists (fun leftCommand ->
                rightGrant.Commands
                |> List.exists (fun rightCommand ->
                    if leftCommand.Path = rightCommand.Path then
                        argumentScopesOverlap leftCommand.Arguments rightCommand.Arguments
                    else
                        match leftCommand.Arguments, rightCommand.Arguments with
                        | AnyArguments, _
                        | _, AnyArguments -> true
                        | _ -> false))

    let private effectiveGrantPlans (environment: HostEnvironment) (grants: SudoGrant list) =
        grants
        |> List.map (fun grant ->
            let principals, coverage, principalsResolved = resolveEffectivePrincipals environment grant
            { Grant = grant
              Principals = principals
              Coverage = coverage
              PrincipalsResolved = principalsResolved })

    let private checkGrantEffectiveForPrincipals
        (environment: HostEnvironment)
        stagedDirectory
        digest
        (plan: SudoGrantPlan)
        (plans: SudoGrantPlan list)
        =
        let grant = plan.Grant
        let subjects = plan.Principals
        let coverage = plan.Coverage
        let commands =
            if grant.AllCommands then [ { Path = "/usr/bin/true"; Arguments = AnyArguments } ]
            else grant.Commands
        let conflictingOwnedScope =
            plans
            |> List.exists (fun other ->
                other.Grant.Name <> grant.Name
                && other.Grant.Authentication <> grant.Authentication
                && runAsScopesOverlap grant.RunAs other.Grant.RunAs
                && commandScopesOverlap grant other.Grant
                && (subjects |> List.exists (fun subject -> other.Principals |> List.contains subject)))
        let mutable effective = plan.PrincipalsResolved && not (List.isEmpty subjects) && not conflictingOwnedScope
        for subjectName in subjects do
            let listing = runInPolicyView environment stagedDirectory "sudo" [ "-n"; "-ll"; "-U"; subjectName ] None
            if listing.ExitCode <> 0 then effective <- false
            else
                let entries = parseVerbosePolicyEntries (listing.Stdout + "\n" + listing.Stderr)
                for command in commands do
                    let argument =
                        match command.Arguments with
                        | NoArguments -> None
                        | ExactArguments value -> Some value
                        | AnyArguments -> Some("keroosha-iac-policy-probe-" + digest)
                    if not (checkOneEffectiveCommand environment stagedDirectory digest subjectName grant.RunAs command.Path argument grant.Authentication)
                       || not (checkFullPolicyScope environment entries digest grant.RunAs grant command) then
                        effective <- false
        effective, coverage

    let private clonePolicyDirectory (environment: HostEnvironment) (digest: string) (targetName: string) (content: string option) =
        let source = actualPath environment PolicyDirectory
        if not (ensureSafeDirectoryChain environment source false DirectoryMode) then
            fail "The host sudoers include directory is missing or unsafe."
        let sourceMetadata = inspectNoFollow source |> Option.defaultWith (fun () -> fail "The host sudoers include directory is missing.")
        let stagingParent = stateDirectoryPath environment
        requireJournalDirectory environment true |> ignore
        let stageRoot = Path.Combine(stagingParent, ".validation-" + digest + "-" + Guid.NewGuid().ToString("N"))
        let stagedDirectory = Path.Combine(stageRoot, "sudoers.d")
        Directory.CreateDirectory stageRoot |> ignore
        File.SetUnixFileMode(stageRoot, enum<UnixFileMode> DirectoryMode)
        try
            Directory.CreateDirectory stagedDirectory |> ignore
            File.SetUnixFileMode(stagedDirectory, enum<UnixFileMode> sourceMetadata.Mode)
            if nativeChown(stagedDirectory, sourceMetadata.UserId, sourceMetadata.GroupId) <> 0 then
                fail "The sudo policy staging directory could not preserve trusted ownership."
            for sourceEntry in Directory.EnumerateFileSystemEntries(source) do
                let name = Path.GetFileName sourceEntry
                if String.IsNullOrEmpty name || name = "." || name = ".." then fail "A sudo include entry has an invalid name."
                let targetEntry = Path.Combine(stagedDirectory, name)
                if name <> targetName then
                    match inspectNoFollow sourceEntry with
                    | Some metadata when metadata.FileType = 0x8000 ->
                        validateRootOwnedFile environment metadata "A foreign sudoers include"
                        if (metadata.Mode &&& 0o022) <> 0 then fail "A foreign sudoers include is writable by an untrusted group."
                        match safeReadBytes environment sourceEntry with
                        | Some(bytes, readMetadata) when sameIdentity metadata.Identity readMetadata.Identity ->
                            HostFiles.atomicWrite targetEntry bytes (enum<UnixFileMode> metadata.Mode)
                            if nativeChown(targetEntry, metadata.UserId, metadata.GroupId) <> 0 then
                                fail "A sudo policy include could not preserve trusted ownership."
                        | _ -> fail "A sudoers include changed while the validation policy was copied."
                    | Some _ -> fail "The sudoers include directory contains a non-regular policy entry."
                    | None -> fail "A sudoers include changed while the validation policy was copied."
            match content with
            | Some value ->
                let stagedTarget = Path.Combine(stagedDirectory, targetName)
                HostFiles.atomicWrite stagedTarget (encodeUtf8 value) (enum<UnixFileMode> PolicyMode)
                if nativeChown(stagedTarget, expectedOwner environment, expectedGroup environment) <> 0 then
                    fail "The candidate sudo policy could not be owned by root."
            | None -> ()
            Some stagedDirectory
        with _ ->
            if Directory.Exists stageRoot then Directory.Delete(stageRoot, true)
            reraise ()

    let private disposePolicyStage (stagedDirectory: string option) =
        match stagedDirectory with
        | None -> ()
        | Some directory ->
            match Directory.GetParent directory with
            | null -> fail "The sudo policy staging directory has no parent."
            | parent when Directory.Exists parent.FullName -> Directory.Delete(parent.FullName, true)
            | _ -> ()

    let private hashRegularFileNoFollow (path: string) =
        match inspectNoFollow path with
        | Some initial when initial.FileType = 0x8000 ->
            let descriptor = nativeOpen(path, 0x800 ||| 0x80000 ||| 0x20000, 0)
            if descriptor < 0 then fail "The immutable native helper could not be opened safely."
            let handle = new SafeFileHandle(nativeint descriptor, true)
            use handle = handle
            let opened = inspectDescriptor descriptor
            if not (sameIdentity initial.Identity opened.Identity) then
                fail "The immutable native helper changed while it was being opened."
            use stream = new FileStream(handle, FileAccess.Read, 65536, false)
            let digest = SHA256.HashData(stream) |> Convert.ToHexString |> fun value -> value.ToLowerInvariant()
            match inspectNoFollow path with
            | Some current when sameIdentity opened.Identity current.Identity -> digest
            | _ -> fail "The immutable native helper changed while it was being verified."
        | _ -> fail "The immutable native helper is not a regular file."
    let private helperPath (environment: HostEnvironment) =
        match Environment.ProcessPath with
        | null -> fail "The current native helper executable path is unavailable."
        | path when String.IsNullOrWhiteSpace path || not (Path.IsPathRooted path) -> fail "The current native helper executable path is invalid."
        | path ->
            if isProductionRoot environment then
                let prefix = "/var/cache/keroosha-iac/helper/"
                if not (path.StartsWith(prefix, StringComparison.Ordinal)) then fail "The native helper is not running from its immutable cache path."
                let parts = path.Substring(prefix.Length).Split('/')
                if parts.Length <> 2
                   || (parts[0] <> "linux-x64" && parts[0] <> "linux-arm64")
                   || parts[1].Length <> 64
                   || (parts[1] |> Seq.exists (fun character -> not ((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')))) then
                    fail "The native helper cache path is not immutable and content-addressed."
                let parent = Path.GetDirectoryName path
                if not (ensureSafeDirectoryChain environment parent false DirectoryMode) then fail "The native helper cache directory is unsafe."
                match inspectNoFollow path with
                | Some metadata when metadata.FileType = 0x8000 && metadata.UserId = 0u && (metadata.Mode &&& 0o022) = 0 && (metadata.Mode &&& 0o111) <> 0 ->
                    if hashRegularFileNoFollow path <> parts[1] then
                        fail "The immutable native helper content does not match its cache digest."
                | _ -> fail "The immutable native helper is not a root-owned executable."
            path

    let private buildReadRequest (request: SudoRequest) =
        let root = JsonObject()
        root["operation"] <- JsonValue.Create("read")
        root["resourceId"] <- JsonValue.Create(request.ResourceId)
        root["connectionUser"] <- JsonValue.Create(request.ConnectionUser)
        root["grants"] <- JsonArray()
        root.ToJsonString()

    let private runAsConnectionUser (environment: HostEnvironment) stagedDirectory (connectionUser: string) (home: string) arguments standardInput =
        let envArguments =
            [ "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
              "USER=" + connectionUser
              "LOGNAME=" + connectionUser
              "HOME=" + home
              "LC_ALL=C" ]
        let commandArguments =
            [ "--user"; connectionUser; "--"; "/usr/bin/env"; "-i" ]
            @ envArguments
            @ [ "/usr/bin/sudo"; "-k"; "-n"; "--" ]
            @ arguments
        runInPolicyView environment stagedDirectory "/usr/sbin/runuser" commandArguments standardInput

    let private requireSuccessfulProbe (result: CommandResult) message =
        if result.ExitCode <> 0 then fail message

    let private verifyTransport (environment: HostEnvironment) stagedDirectory (request: SudoRequest) connectionHome digest =
        let shellProbe =
            runAsConnectionUser environment stagedDirectory request.ConnectionUser connectionHome
                [ "sh"; "-c"; "test \"$(/usr/bin/id -u)\" = 0" ] None
        requireSuccessfulProbe shellProbe "The sudo candidate would remove fresh sudo -n sh -c access for the deployment user."
        let executable = helperPath environment
        let versionProbe =
            runAsConnectionUser environment stagedDirectory request.ConnectionUser connectionHome
                [ executable; "--version" ] None
        if versionProbe.ExitCode <> 0 || versionProbe.Stdout.Trim() <> "keroosha-iac-helper protocol 1" then
            fail "The sudo candidate would remove access to the immutable native helper protocol probe."
        let helperRequest = buildReadRequest request
        let helperProbe =
            runAsConnectionUser environment stagedDirectory request.ConnectionUser connectionHome
                [ executable; "sudo" ] (Some helperRequest)
        if helperProbe.ExitCode <> 0 then fail "The sudo candidate would remove access to the native sudo helper invocation."
        try
            use document = JsonDocument.Parse helperProbe.Stdout
            let root = document.RootElement
            if root.ValueKind <> JsonValueKind.Object
               || not (root.TryGetProperty("exists") |> fst)
               || not (root.TryGetProperty("inSync") |> fst)
               || not (root.TryGetProperty("actual") |> fst) then
                fail "The native sudo helper invocation returned an invalid protocol response."
        with
        | :? BackendError -> reraise ()
        | _ -> fail "The native sudo helper invocation returned an invalid protocol response."

    let private makeGrantActual (grant: SudoGrant) (effective: bool) (coverage: string) =
        let node = JsonObject()
        node["name"] <- JsonValue.Create(grant.Name)
        node["effectiveVerified"] <- JsonValue.Create(effective)
        node["coverage"] <- JsonValue.Create(coverage)
        node

    let private actualNode (digest: string) (target: (string * SudoMetadata) option) (grants: (SudoGrant * bool * string) list) =
        let actual = JsonObject()
        actual["filePath"] <- JsonValue.Create(PolicyDirectory + "/90-keroosha-iac-" + digest)
        match target with
        | None ->
            actual["filePresent"] <- JsonValue.Create(false)
            actual["fileSha256"] <- null
            actual["fileMode"] <- null
            actual["fileOwnerUid"] <- null
        | Some(content, metadata) ->
            actual["filePresent"] <- JsonValue.Create(true)
            actual["fileSha256"] <- JsonValue.Create(digestBytes (encodeUtf8 content))
            actual["fileMode"] <- JsonValue.Create(metadata.Mode)
            actual["fileOwnerUid"] <- JsonValue.Create(metadata.UserId)
        let grantNodes = JsonArray()
        for grant, effective, coverage in grants do grantNodes.Add(makeGrantActual grant effective coverage)
        actual["grants"] <- grantNodes
        actual :> JsonNode

    let private envelope (exists: bool) (inSync: bool) (actual: JsonNode) =
        let response = JsonObject()
        response["exists"] <- JsonValue.Create(exists)
        response["inSync"] <- JsonValue.Create(inSync)
        response["actual"] <- actual
        response :> JsonNode

    let private pendingMatchesTarget (pending: SudoPending) (target: (string * SudoMetadata) option) =
        match target with
        | None -> pending.Operation = "delete" || not pending.PreviousPresent
        | Some(content, _) ->
            [ pending.Content; pending.PreviousContent ]
            |> List.choose id
            |> List.contains content

    let private verifyObservedTarget (journal: SudoJournal option) (pending: SudoPending option) target =
        match target, journal, pending with
        | None, None, None -> ()
        | Some _, None, None -> fail "A foreign sudo policy file occupies the resource's deterministic path."
        | Some(content, _), Some state, None when content = state.Content -> ()
        | None, Some _, None -> ()
        | actual, _, Some intent ->
            if not (pendingMatchesTarget intent actual) then fail "The sudo policy file changed outside its ownership journal."
        | _ -> fail "The sudo policy file changed outside its ownership journal."

    let private observe (environment: HostEnvironment) (request: SudoRequest) digest =
        let journal = readJournal environment request.ResourceId digest
        let pending = readPending environment request.ResourceId digest
        let target = readTarget environment digest
        verifyObservedTarget journal pending target
        let exists = journal.IsSome || pending.IsSome
        let includePath = if target.IsSome then Some(filePath environment digest) else None
        let plans = effectiveGrantPlans environment request.Grants
        let includeReachable, grantResults =
            if exists then
                let included = validatePolicyGraph environment None includePath
                let effective =
                    plans
                    |> List.map (fun plan ->
                        let canObserve = target.IsSome && included
                        if canObserve then
                            let observed, coverage = checkGrantEffectiveForPrincipals environment None digest plan plans
                            plan.Grant, observed, coverage
                        else plan.Grant, false, plan.Coverage)
                included, effective
            else
                false,
                (plans |> List.map (fun plan -> plan.Grant, false, plan.Coverage))
        let exactDesired =
            match journal with
            | Some state when pending.IsNone -> state.Content = renderGrants digest request.Grants
            | _ -> false
        let fileMatches =
            match target with
            | Some(content, metadata) ->
                metadata.Mode = PolicyMode
                && metadata.UserId = expectedOwner environment
                && metadata.GroupId = expectedGroup environment
                && (journal |> Option.exists (fun state -> state.Content = content))
            | None -> false
        let grantsEffective = grantResults |> List.forall (fun (_, effective, coverage) -> effective || coverage = "empty-group-structural")
        let inSync = exists && pending.IsNone && exactDesired && fileMatches && includeReachable && grantsEffective
        envelope exists inSync (actualNode digest target grantResults)

    let private capturePrevious (journal: SudoJournal option) (target: (string * SudoMetadata) option) =
        match target, journal with
        | None, _ -> false, None, None, None
        | Some(content, metadata), Some state when content = state.Content ->
            true, Some content, Some metadata.Mode, Some metadata.GroupId
        | Some _, _ -> fail "A foreign sudo policy file occupies the resource's deterministic path."

    let private restorePreviousFile (environment: HostEnvironment) digest (pending: SudoPending) =
        let current = readTarget environment digest
        if not (pendingMatchesTarget pending current) then
            fail "The sudo policy file changed outside its pending ownership journal."
        if pending.PreviousPresent then
            match pending.PreviousContent, pending.PreviousMode, pending.PreviousGroupId with
            | Some value, Some fileMode, Some group ->
                let target = filePath environment digest
                HostFiles.atomicWrite target (encodeUtf8 value) (enum<UnixFileMode> fileMode)
                if nativeChown(target, expectedOwner environment, group) <> 0 then
                    fail "The previous sudo policy file ownership could not be restored."
                match readTarget environment digest with
                | Some(actual, metadata)
                    when actual = value
                         && metadata.Mode = fileMode
                         && metadata.UserId = expectedOwner environment
                         && metadata.GroupId = group -> ()
                | _ -> fail "The previous sudo policy file could not be verified after rollback."
            | _ -> fail "The sudo rollback journal is incomplete."
        else
            match current with
            | None -> ()
            | Some(content, _) -> removeTarget environment digest (Some content)

    let private validateCandidate (environment: HostEnvironment) (request: SudoRequest) digest connectionHome targetExpectedPath stagedDirectory =
        let included = validatePolicyGraph environment stagedDirectory targetExpectedPath
        if not included then fail "The sudo policy file is not reachable through the host's active include graph."
        let plans = effectiveGrantPlans environment request.Grants
        let grants =
            plans
            |> List.map (fun plan ->
                let effective, coverage = checkGrantEffectiveForPrincipals environment stagedDirectory digest plan plans
                plan.Grant, effective, coverage)
        if grants |> List.exists (fun (_, effective, coverage) -> not effective && coverage <> "empty-group-structural") then
            fail "The sudo candidate's grant could not be confirmed in the effective host policy."
        verifyTransport environment stagedDirectory request connectionHome digest
        grants

    let private stageCandidate (environment: HostEnvironment) request digest content connectionHome =
        if not (isProductionRoot environment) then None
        else
            let stage = clonePolicyDirectory environment digest (Path.GetFileName(filePath environment digest)) (Some content)
            try
                validateCandidate environment request digest connectionHome (Some(filePath environment digest)) stage |> ignore
                stage
            with _ ->
                disposePolicyStage stage
                reraise ()

    let private stageDeletion (environment: HostEnvironment) request digest connectionHome =
        if not (isProductionRoot environment) then None
        else
            let stage = clonePolicyDirectory environment digest (Path.GetFileName(filePath environment digest)) None
            try
                let included = validatePolicyGraph environment stage None
                if not included then fail "The host sudoers policy could not be confirmed after removing the owned grant file."
                verifyTransport environment stage request connectionHome digest
                stage
            with _ ->
                disposePolicyStage stage
                reraise ()

    let private restorePending (environment: HostEnvironment) (request: SudoRequest) digest (pending: SudoPending) (connectionHome: string) =
        let target = readTarget environment digest
        if not (pendingMatchesTarget pending target) then
            fail "A pending sudo transaction has been changed by a foreign writer."
        let journal = readJournal environment request.ResourceId digest
        let alreadyCommitted =
            match pending.Operation, pending.Content, journal, target with
            | "apply", Some expected, Some state, Some(actual, _) -> state.Content = expected && actual = expected
            | "delete", None, None, None -> true
            | _ -> false
        if alreadyCommitted then
            let included = validatePolicyGraph environment None (target |> Option.map (fun _ -> filePath environment digest))
            if target.IsSome && not included then fail "The committed sudo policy file is no longer reachable."
            verifyTransport environment None request connectionHome digest
            deleteRootOnly environment (pendingPath environment digest)
        else
            let preview =
                if isProductionRoot environment then
                    let previous = if pending.PreviousPresent then pending.PreviousContent else None
                    let stage = clonePolicyDirectory environment digest (Path.GetFileName(filePath environment digest)) previous
                    try
                        let included = validatePolicyGraph environment stage (if pending.PreviousPresent then Some(filePath environment digest) else None)
                        if pending.PreviousPresent && not included then fail "The previous sudo policy file is no longer reachable."
                        verifyTransport environment stage request connectionHome digest
                        stage
                    with _ ->
                        disposePolicyStage stage
                        reraise ()
                else None
            try
                restorePreviousFile environment digest pending
                let included = validatePolicyGraph environment None (if pending.PreviousPresent then Some(filePath environment digest) else None)
                if pending.PreviousPresent && not included then fail "The previous sudo policy file is no longer reachable."
                verifyTransport environment None request connectionHome digest
                deleteRootOnly environment (pendingPath environment digest)
            finally
                disposePolicyStage preview

    let private makePending (request: SudoRequest) digest operation content previousPresent previousContent previousMode previousGroup =
        { ResourceId = request.ResourceId
          Digest = digest
          FilePath = PolicyDirectory + "/90-keroosha-iac-" + digest
          Operation = operation
          Content = content
          PreviousPresent = previousPresent
          PreviousContent = previousContent
          PreviousMode = previousMode
          PreviousGroupId = previousGroup }

    let private apply (environment: HostEnvironment) (request: SudoRequest) digest connectionHome =
        if not (ensureSafeDirectoryChain environment (actualPath environment PolicyDirectory) false DirectoryMode) then
            fail "The host sudoers include directory is missing or unsafe."
        requireJournalDirectory environment true |> ignore
        use hostLock = HostFiles.lockFile (Path.Combine(stateDirectoryPath environment, ".lock"))
        match safeReadBytes environment (Path.Combine(stateDirectoryPath environment, ".lock")) with
        | Some(_, metadata) when metadata.Mode = JournalMode && metadata.UserId = expectedOwner environment -> ()
        | _ -> fail "The sudo host-wide ownership lock is not root-only."
        let content = renderGrants digest request.Grants
        let firstJournal = readJournal environment request.ResourceId digest
        let firstPending = readPending environment request.ResourceId digest
        let firstTarget = readTarget environment digest
        let alreadyApplied =
            match firstPending, firstJournal, firstTarget with
            | Some pending, Some journal, Some(actual, _) when pending.Operation = "apply" && pending.Content = Some content && journal.Content = content && actual = content ->
                let effective = validateCandidate environment request digest connectionHome (Some(filePath environment digest)) None
                deleteRootOnly environment (pendingPath environment digest)
                Some(envelope true true (actualNode digest firstTarget effective))
            | _ -> None
        match alreadyApplied with
        | Some response -> response
        | None ->
            let mutable activePending = firstPending
            match activePending with
            | Some pending when pending.Operation = "apply" && pending.Content = Some content ->
                if not (pendingMatchesTarget pending firstTarget) then
                    fail "The pending sudo candidate was edited outside its ownership journal."
            | Some pending ->
                restorePending environment request digest pending connectionHome
                activePending <- None
            | None -> ()
            let journal = readJournal environment request.ResourceId digest
            let existing = readTarget environment digest
            match activePending, journal, existing with
            | Some pending, _, _ when not (pendingMatchesTarget pending existing) ->
                fail "The pending sudo candidate was edited outside its ownership journal."
            | None, None, Some _ -> fail "A foreign sudo policy file occupies the resource's deterministic path."
            | None, Some state, Some(actual, _) when actual <> state.Content ->
                fail "The owned sudo policy file has been edited outside its ownership journal."
            | _ -> ()
            if activePending.IsNone then
                let baseIncluded = validatePolicyGraph environment None (existing |> Option.map (fun _ -> filePath environment digest))
                if existing.IsSome && not baseIncluded then
                    fail "The existing sudo policy file is no longer reachable through the host include graph."
            let intent, newlyPending =
                match activePending with
                | Some pending -> pending, false
                | None ->
                    let previousPresent, previousContent, previousMode, previousGroup = capturePrevious journal existing
                    let pending = makePending request digest "apply" (Some content) previousPresent previousContent previousMode previousGroup
                    writePending environment pending
                    pending, true
            let mutable stage = None
            let mutable targetMayHaveChanged = not newlyPending
            let mutable journalCommitted = false
            try
                try
                    stage <- stageCandidate environment request digest content connectionHome
                    match readTarget environment digest with
                    | Some(actual, metadata)
                        when actual = content
                             && metadata.Mode = PolicyMode
                             && metadata.UserId = expectedOwner environment
                             && metadata.GroupId = expectedGroup environment -> ()
                    | _ ->
                        targetMayHaveChanged <- true
                        let allowedContents = [ intent.Content; intent.PreviousContent ] |> List.choose id
                        writeTarget environment digest allowedContents (not intent.PreviousPresent) content
                    let effective = validateCandidate environment request digest connectionHome (Some(filePath environment digest)) None
                    let stored =
                        { ResourceId = request.ResourceId
                          Digest = digest
                          FilePath = PolicyDirectory + "/90-keroosha-iac-" + digest
                          Content = content }
                    writeJournal environment stored
                    journalCommitted <- true
                    deleteRootOnly environment (pendingPath environment digest)
                    let target = readTarget environment digest |> Option.defaultWith (fun () -> fail "The installed sudo policy file disappeared.")
                    envelope true true (actualNode digest (Some target) effective)
                with
                | error when journalCommitted -> raise error
                | error ->
                    if newlyPending && not targetMayHaveChanged then
                        deleteRootOnly environment (pendingPath environment digest)
                    else
                        try
                            restorePreviousFile environment digest intent
                            match journal with
                            | Some previous -> writeJournal environment previous
                            | None -> deleteRootOnly environment (journalPath environment digest)
                            let included = validatePolicyGraph environment None (if intent.PreviousPresent then Some(filePath environment digest) else None)
                            if intent.PreviousPresent && not included then
                                fail "The previous sudo policy file could not be confirmed during rollback."
                            verifyTransport environment None request connectionHome digest
                            deleteRootOnly environment (pendingPath environment digest)
                        with _ ->
                            fail "Sudo candidate application failed and the previous policy could not be confirmed; the pending ownership journal was retained."
                    raise error
            finally
                disposePolicyStage stage

    let private delete (environment: HostEnvironment) (request: SudoRequest) digest connectionHome =
        if not (ensureSafeDirectoryChain environment (actualPath environment PolicyDirectory) false DirectoryMode) then
            fail "The host sudoers include directory is missing or unsafe."
        if not (requireJournalDirectory environment false) then
            let target = readTarget environment digest
            if target.IsSome then fail "A foreign sudo policy file occupies the resource's deterministic path."
            envelope false true (actualNode digest None [])
        else
            if not (ensureSafeDirectoryChain environment (stateDirectoryPath environment) true DirectoryMode) then
                fail "The sudo journal directory is unavailable for mutation."
            use hostLock = HostFiles.lockFile (Path.Combine(stateDirectoryPath environment, ".lock"))
            match safeReadBytes environment (Path.Combine(stateDirectoryPath environment, ".lock")) with
            | Some(_, metadata) when metadata.Mode = JournalMode && metadata.UserId = expectedOwner environment -> ()
            | _ -> fail "The sudo host-wide ownership lock is not root-only."
            let firstJournal = readJournal environment request.ResourceId digest
            let firstPending = readPending environment request.ResourceId digest
            let firstTarget = readTarget environment digest
            let finishedDelete =
                match firstPending, firstJournal, firstTarget with
                | Some pending, None, None when pending.Operation = "delete" ->
                    let included = validatePolicyGraph environment None None
                    if not included then fail "The host sudoers policy could not be confirmed after deletion."
                    verifyTransport environment None request connectionHome digest
                    deleteRootOnly environment (pendingPath environment digest)
                    true
                | _ -> false
            if finishedDelete then envelope false true (actualNode digest None [])
            else
                let mutable activePending = firstPending
                match activePending with
                | Some pending when pending.Operation = "delete" ->
                    if not (pendingMatchesTarget pending firstTarget) then
                        fail "The pending sudo deletion was edited outside its ownership journal."
                | Some pending ->
                    restorePending environment request digest pending connectionHome
                    activePending <- None
                | None -> ()
                let journal = readJournal environment request.ResourceId digest
                let target = readTarget environment digest
                match activePending, journal, target with
                | Some pending, _, _ when not (pendingMatchesTarget pending target) ->
                    fail "The pending sudo deletion was edited outside its ownership journal."
                | None, None, Some _ -> fail "A foreign sudo policy file occupies the resource's deterministic path."
                | None, Some state, Some(actual, _) when actual <> state.Content ->
                    fail "The owned sudo policy file has been edited outside its ownership journal."
                | _ -> ()
                match journal with
                | None -> envelope false true (actualNode digest None [])
                | Some state ->
                    if activePending.IsNone then
                        let baseIncluded = validatePolicyGraph environment None (target |> Option.map (fun _ -> filePath environment digest))
                        if target.IsSome && not baseIncluded then
                            fail "The owned sudo policy file is no longer reachable through the host include graph."
                    let intent =
                        match activePending with
                        | Some pending -> pending
                        | None ->
                            let previousPresent, previousContent, previousMode, previousGroup = capturePrevious journal target
                            makePending request digest "delete" None previousPresent previousContent previousMode previousGroup
                    let stage = stageDeletion environment request digest connectionHome
                    try
                        if activePending.IsNone then writePending environment intent
                        let mutable journalRemoved = false
                        try
                            try
                                match readTarget environment digest with
                                | None -> ()
                                | Some _ -> removeTarget environment digest (Some state.Content)
                                let included = validatePolicyGraph environment None None
                                if not included then fail "The host sudoers policy could not be confirmed after deletion."
                                verifyTransport environment None request connectionHome digest
                                deleteRootOnly environment (journalPath environment digest)
                                journalRemoved <- true
                                deleteRootOnly environment (pendingPath environment digest)
                                envelope false true (actualNode digest None [])
                            with
                            | error when journalRemoved -> raise error
                            | error ->
                                try
                                    restorePreviousFile environment digest intent
                                    writeJournal environment state
                                    let included = validatePolicyGraph environment None (if intent.PreviousPresent then Some(filePath environment digest) else None)
                                    if intent.PreviousPresent && not included then
                                        fail "The previous sudo policy file could not be confirmed during rollback."
                                    verifyTransport environment None request connectionHome digest
                                    deleteRootOnly environment (pendingPath environment digest)
                                with _ ->
                                    fail "Sudo deletion failed and the previous policy could not be confirmed; the pending ownership journal was retained."
                                raise error
                        finally
                            ()
                    finally
                        disposePolicyStage stage

    let handle (environment: HostEnvironment) (requestElement: JsonElement) : JsonNode =
        requireLinuxAndRoot environment
        let request = parseRequest requestElement
        let digest = ownerDigest request.ResourceId
        let connectionHome =
            if request.Operation = "apply" then
                let _, _, home = resolveRequestIdentities environment request
                home
            else
                let _, _, home = resolveUser environment request.ConnectionUser
                home
        match request.Operation with
        | "read" -> observe environment request digest
        | "apply" -> apply environment request digest connectionHome
        | "delete" -> delete environment request digest connectionHome
        | _ -> fail "Unsupported sudo operation."
